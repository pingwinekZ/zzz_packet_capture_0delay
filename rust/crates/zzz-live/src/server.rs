//! The server itself, ported from `websocket::Server`.
//!
//! Loopback only: it binds `127.0.0.1` and is meant for the optimizer running on
//! the same machine.
//!
//! ## The threading model, and where it differs
//!
//! The reference runs one asio `io_context` thread that accepts connections and
//! serves *all* clients' reads, plus one sender thread per client, so
//! `broadcastText` — called from the capture thread — never touches a socket.
//! The same guarantee holds here with `std`, which has no async I/O: a client
//! gets a reader thread and a writer thread, and `broadcast_text` only pushes to
//! an outbox and signals a condvar.
//!
//! Four consequences worth stating plainly:
//!
//! * **Two threads per client** instead of one shared event loop. The reference
//!   is one io thread plus one sender per client; this is one reader plus one
//!   sender per client. For a handful of optimizer connections that is fine, and
//!   it is the only way to keep blocking reads from serializing clients.
//! * **The accept loop polls.** `std::net::TcpListener` has no way to be woken
//!   from another thread, so it is non-blocking and re-checked every
//!   [`ACCEPT_POLL`]. The cost is up to a few tens of milliseconds before a
//!   connection is noticed, and it makes `stop()` deterministic without the
//!   self-connect trick asio's `io_context::stop` avoids needing.
//! * **Client sockets have a read timeout, and the reader polls.** `shutdown`
//!   does not interrupt a `recv` that is already blocked — measured on Windows,
//!   for `Shutdown::Both`, `Shutdown::Read` and a dropped duplicate handle alike;
//!   only an incoming close from the peer completes it. asio cancels the
//!   operation instead. So the reader waits at most [`CLIENT_READ_POLL`] at a
//!   time and checks whether it has been asked to stop in between, which is what
//!   bounds `stop()`. Writes get [`CLIENT_WRITE_TIMEOUT`] for the same reason in
//!   the other direction: a client that stops reading must not park the sender
//!   forever. See `frame`'s module docs for the one behaviour this changes.
//! * **The handshake is bounded.** A client that never finishes its request head
//!   is dropped after [`MAX_HEADERS_BYTES`] bytes, or after
//!   [`HANDSHAKE_TIMEOUT`], where the reference would grow a buffer without limit
//!   and wait forever for the blank line.
//!
//! One place this is deliberately *more* correct than the reference: the
//! reference reads the request head with `async_read_until`, then drains the
//! whole buffer into a string to search it — discarding anything the read
//! happened to pull in past the blank line. A client that pipelines a frame
//! immediately after its handshake can lose that frame there. Here the handshake
//! is read line by line from a `BufReader`, so whatever follows stays buffered
//! and is parsed as frames.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::frame::{self, opcode, FrameRead};
use crate::sha1::sha1;

/// The reference's port, `23313`.
pub const DEFAULT_PORT: u16 = 23313;

/// The GUID RFC 6455 appends to the client's key.
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The largest request head accepted, counted from the first byte to the blank
/// line. The reference has no bound; a real handshake is a few hundred bytes.
pub const MAX_HEADERS_BYTES: usize = 16 * 1024;

/// How often the accept loop looks up to notice that it was asked to stop.
const ACCEPT_POLL: Duration = Duration::from_millis(25);

/// How long one client socket read may block before its reader looks at the stop
/// flag. See the module docs: on Windows nothing else can interrupt a blocked
/// `recv`, so this is also the ceiling on how long `stop()` can take to join a
/// reader.
const CLIENT_READ_POLL: Duration = Duration::from_millis(250);

/// How long one client socket write may stall before the client is dropped.
///
/// A snapshot is a few hundred kilobytes — more than a socket buffer — so a
/// client that stops reading will block the sender mid-frame. This is per write
/// call rather than per frame, so a slow-but-draining client is not affected.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a connection has to send its request head.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Why the server could not start.
#[derive(Debug)]
pub struct ServerError {
    pub addr: SocketAddr,
    pub source: io::Error,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot listen on {}: {}", self.addr, self.source)
    }
}

impl std::error::Error for ServerError {}

type SnapshotSource = Arc<dyn Fn() -> String + Send + Sync>;
type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// Configuration a caller sets before — or while — running. Shared with the
/// running server, so assigning a new one takes effect immediately, exactly as
/// writing to the reference's public `onSnapshotRequested` field does.
#[derive(Default)]
struct Config {
    snapshot_source: Mutex<Option<SnapshotSource>>,
    logger: Mutex<Option<Logger>>,
}

impl Config {
    fn log(&self, message: String) {
        let logger = self.logger.lock().unwrap().clone();
        if let Some(logger) = logger {
            logger(&message);
        }
    }

    /// The initial payload for a client that connects before anything has been
    /// broadcast.
    fn snapshot(&self) -> Option<String> {
        let source = self.snapshot_source.lock().unwrap().clone();
        source.map(|source| source())
    }
}

/// A client's pending write.
#[derive(Debug)]
enum Body {
    /// Text, to be framed when it is written.
    Text(String),
    /// A complete frame, already encoded — a pong.
    Raw(Vec<u8>),
}

struct Client {
    stream: TcpStream,
    registered: AtomicBool,
    open: AtomicBool,
    close_after_send: AtomicBool,
    outbox: Mutex<VecDeque<Body>>,
    filled: Condvar,
    reader: Mutex<Option<JoinHandle<()>>>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl Client {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            registered: AtomicBool::new(false),
            open: AtomicBool::new(false),
            close_after_send: AtomicBool::new(false),
            outbox: Mutex::new(VecDeque::new()),
            filled: Condvar::new(),
            reader: Mutex::new(None),
            writer: Mutex::new(None),
        }
    }

    /// Queues a write and wakes the sender. Never touches the socket, so the
    /// caller — often the capture thread — never blocks on I/O.
    fn push(&self, body: Body) {
        self.outbox.lock().unwrap().push_back(body);
        self.filled.notify_all();
    }

    /// Takes this thread's handles out of the client, so that exactly one thread
    /// can join each of them. A handle whose thread is the caller is skipped:
    /// a thread cannot join itself, and the two error paths below can each be the
    /// one that gets here.
    fn take_handles(&self) -> Vec<JoinHandle<()>> {
        let mut handles = Vec::new();
        for slot in [&self.reader, &self.writer] {
            if let Some(handle) = slot.lock().unwrap().take() {
                handles.push(handle);
            }
        }
        handles
    }
}

/// The state of a running server. Held behind an `Arc` by the threads that use
/// it, and dropped when the server stops.
struct Running {
    running: AtomicBool,
    clients: Mutex<Vec<Arc<Client>>>,
    latest_snapshot: Mutex<Option<Arc<str>>>,
    config: Arc<Config>,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

impl Running {
    /// Registers a client and hands it its initial payload.
    ///
    /// The order matters and matches the reference: the client joins the list
    /// first, so a broadcast that lands between here and the snapshot being
    /// queued is delivered *before* the snapshot. That is the reference's
    /// behaviour, not an accident to be smoothed over — the snapshot is a
    /// fallback for a client that connected before anything was broadcast, and
    /// the reference prefers the newest broadcast when it has one.
    fn announce(&self, client: &Arc<Client>) {
        client.registered.store(true, Ordering::SeqCst);
        let latest = self.latest_snapshot.lock().unwrap().clone();
        let initial = match latest {
            Some(snapshot) => Some(snapshot.to_string()),
            None => self.config.snapshot(),
        };
        if let Some(initial) = initial {
            if !initial.is_empty() {
                client.push(Body::Text(initial));
            }
        }
        self.config.log(format!(
            "ws: client connected ({} total)",
            self.client_count()
        ));
    }

    fn client_count(&self) -> usize {
        self.clients
            .lock()
            .unwrap()
            .iter()
            .filter(|client| client.registered.load(Ordering::SeqCst))
            .count()
    }

    fn broadcast(&self, text: &str) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }
        *self.latest_snapshot.lock().unwrap() = Some(Arc::from(text));
        let clients = self.clients.lock().unwrap().clone();
        for client in clients {
            // A client mid-handshake is in the list but must not be written to:
            // it has not been told about the upgrade yet, and the reference does
            // not have it in `clients` at all at that point.
            if client.registered.load(Ordering::SeqCst) {
                client.push(Body::Text(text.to_string()));
            }
        }
    }

    /// Retires a client: closes its socket, drops it from the list and joins the
    /// threads that drove it.
    ///
    /// Called from a client's own reader thread on a read failure and from its
    /// writer thread after the close handshake, so it has to be safe to reach
    /// twice and from either thread.
    fn close_client(self: &Arc<Self>, client: &Arc<Client>) {
        let _ = client.stream.shutdown(Shutdown::Both);
        client.open.store(false, Ordering::SeqCst);
        client.close_after_send.store(true, Ordering::SeqCst);
        client.filled.notify_all();
        self.clients
            .lock()
            .unwrap()
            .retain(|held| !Arc::ptr_eq(held, client));

        let current = thread::current().id();
        for handle in client.take_handles() {
            if handle.thread().id() != current {
                let _ = handle.join();
            }
        }
        self.config.log(format!(
            "ws: client disconnected ({} total)",
            self.client_count()
        ));
    }
}

/// A minimal RFC 6455 server: text frames out, ping and close understood in.
pub struct Server {
    state: Mutex<Option<Arc<Running>>>,
    config: Arc<Config>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Server {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
            config: Arc::new(Config::default()),
        }
    }

    /// Sets the callback that produces a client's first payload, used when
    /// nothing has been broadcast yet.
    pub fn on_snapshot_requested<F>(&self, source: F)
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        *self.config.snapshot_source.lock().unwrap() = Some(Arc::new(source));
    }

    /// Sets where the server's own progress lines go. Silent if it is never set:
    /// a library should not print, and the reference's `std::println`s are the
    /// caller's business here.
    pub fn on_log<F>(&self, logger: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        *self.config.logger.lock().unwrap() = Some(Arc::new(logger));
    }

    /// Starts listening on `127.0.0.1:port`.
    ///
    /// Starting an already-running server restarts it: the reference calls
    /// `stop()` first, which is also what makes its restart test pass.
    pub fn start(&self, port: u16) -> Result<(), ServerError> {
        self.stop();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = TcpListener::bind(addr).map_err(|source| ServerError { addr, source })?;
        // Non-blocking so the accept loop can notice `stop` without a second
        // socket to wake it; see the module docs.
        listener
            .set_nonblocking(true)
            .map_err(|source| ServerError { addr, source })?;

        let running = Arc::new(Running {
            running: AtomicBool::new(true),
            clients: Mutex::new(Vec::new()),
            latest_snapshot: Mutex::new(None),
            config: Arc::clone(&self.config),
            accept_thread: Mutex::new(None),
        });

        let accept_state = Arc::clone(&running);
        let accept_thread = thread::Builder::new()
            .name("zzz-live-accept".to_string())
            .spawn(move || accept_loop(&accept_state, listener))
            .map_err(|source| ServerError { addr, source })?;
        *running.accept_thread.lock().unwrap() = Some(accept_thread);

        *self.state.lock().unwrap() = Some(running);
        self.config
            .log(format!("ws: live export listening on 127.0.0.1:{port}"));
        Ok(())
    }

    /// Stops the server and disconnects every client, waiting for the threads to
    /// finish. Safe to call from any thread, and safe to call when not running.
    pub fn stop(&self) {
        let Some(running) = self.state.lock().unwrap().take() else {
            return;
        };
        running.running.store(false, Ordering::SeqCst);

        // Join the accept thread first, so the client list cannot grow while it
        // is being retired.
        if let Some(handle) = running.accept_thread.lock().unwrap().take() {
            if handle.thread().id() != thread::current().id() {
                let _ = handle.join();
            }
        }

        let clients = running.clients.lock().unwrap().clone();
        for client in &clients {
            // Closing the socket is what unblocks a reader parked in a blocking
            // read, and a writer parked in a write.
            let _ = client.stream.shutdown(Shutdown::Both);
            client.open.store(false, Ordering::SeqCst);
            client.close_after_send.store(true, Ordering::SeqCst);
            client.filled.notify_all();
        }

        let current = thread::current().id();
        for client in &clients {
            for handle in client.take_handles() {
                if handle.thread().id() != current {
                    let _ = handle.join();
                }
            }
        }
        running.clients.lock().unwrap().clear();
    }

    /// Queues a text frame for every connected client. Returns immediately, and
    /// does nothing when the server is not running — the reference checks the
    /// same flag, so a stopped server silently drops broadcasts.
    pub fn broadcast_text(&self, text: &str) {
        let state = self.state.lock().unwrap().clone();
        if let Some(running) = state {
            running.broadcast(text);
        }
    }

    /// How many clients have completed their handshake.
    pub fn client_count(&self) -> usize {
        let state = self.state.lock().unwrap().clone();
        state.map_or(0, |running| running.client_count())
    }

    pub fn is_running(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }
}

fn accept_loop(running: &Arc<Running>, listener: TcpListener) {
    while running.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => hand_off(Arc::clone(running), stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(_) => {
                // A transient accept failure: back off rather than spin.
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

/// Starts serving one accepted connection.
///
/// Only the reader thread is started here. The writer is started once the
/// handshake has completed, by [`client_loop`] — which is what the reference
/// does, and it is not a detail that can be moved: [`sender_loop`] treats "not
/// open" as "closed", so a writer started before the handshake would see a
/// client that has not opened yet, decide it was finished and tear the
/// connection down before the reply was even written.
fn hand_off(running: Arc<Running>, stream: TcpStream) {
    // The listener is non-blocking so the accept loop can notice `stop`, and on
    // Windows an accepted socket *inherits* that. Without this the client's reads
    // return `WouldBlock` the moment they would have waited, which looks exactly
    // like a client that vanished — the connection is retired a few milliseconds
    // after it is accepted. Linux and macOS do not propagate the flag; Windows
    // does.
    let _ = stream.set_nonblocking(false);
    // Nagle would hold a small broadcast back waiting for more; the reference
    // writes each frame as it is queued.
    let _ = stream.set_nodelay(true);
    // The reader's socket is given its own timeout below as well: on Windows
    // `try_clone` produces a second socket object, and its options are its own.
    let _ = stream.set_read_timeout(Some(CLIENT_READ_POLL));
    let _ = stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT));
    let client = Arc::new(Client::new(stream));
    // `clients` holds the connection from the moment it is accepted, so `stop`
    // can reach it even if it never finishes its handshake. It is not counted or
    // written to until it registers.
    running.clients.lock().unwrap().push(Arc::clone(&client));

    let reader_state = Arc::clone(&running);
    let reader_client = Arc::clone(&client);
    match thread::Builder::new()
        .name("zzz-live-client".to_string())
        .spawn(move || client_loop(&reader_state, &reader_client))
    {
        Ok(reader) => *client.reader.lock().unwrap() = Some(reader),
        Err(_) => running.close_client(&client),
    }
}

/// Completes the handshake, then reads frames until the client goes away.
fn client_loop(running: &Arc<Running>, client: &Arc<Client>) {
    let stream = match client.stream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return running.close_client(client),
    };
    let _ = stream.set_read_timeout(Some(CLIENT_READ_POLL));
    let mut reader = BufReader::new(stream);

    let key = match read_handshake(&mut reader, Instant::now() + HANDSHAKE_TIMEOUT) {
        // A present but empty key is a refusal, exactly as `key.empty()` is in
        // the reference — so are a missing one and a connection that ended.
        Ok(Some(key)) if !key.is_empty() => key,
        _ => return running.close_client(client),
    };

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    );
    // `&TcpStream` implements `Write`, which is what lets a socket shared
    // through an `Arc` be written from any thread without a lock.
    let mut stream = &client.stream;
    if stream.write_all(response.as_bytes()).is_err() {
        return running.close_client(client);
    }

    // The connection is open from here, so the sender can start: see the note in
    // `hand_off` about why it cannot start any earlier.
    client.open.store(true, Ordering::SeqCst);
    let writer_state = Arc::clone(running);
    let writer_client = Arc::clone(client);
    match thread::Builder::new()
        .name("zzz-live-sender".to_string())
        .spawn(move || sender_loop(&writer_state, &writer_client))
    {
        Ok(writer) => *client.writer.lock().unwrap() = Some(writer),
        Err(_) => return running.close_client(client),
    }

    running.announce(client);

    loop {
        match frame::read_frame(&mut reader) {
            Ok(FrameRead::Frame(frame)) if frame.opcode == opcode::CLOSE => {
                // The peer wants to close. The writer replies with an empty close
                // frame and retires the client; this thread stops reading.
                client.close_after_send.store(true, Ordering::SeqCst);
                client.filled.notify_all();
                return;
            }
            Ok(FrameRead::Frame(frame)) if frame.opcode == opcode::PING => {
                client.push(Body::Raw(frame::encode_pong(&frame.payload)));
            }
            // Text, binary, continuation and anything else a client sends are
            // read and discarded, as the reference does.
            Ok(FrameRead::Frame(_)) => {}
            // Nothing arrived. This is the reader's only chance to notice that it
            // has been asked to stop: see the module docs on why a parked `recv`
            // cannot be interrupted on Windows.
            Ok(FrameRead::Idle) => {
                if !client.open.load(Ordering::SeqCst) {
                    return running.close_client(client);
                }
            }
            Ok(FrameRead::Ended) | Err(_) => return running.close_client(client),
        }
    }
}

/// Drains one client's outbox until it is closed and empty.
fn sender_loop(running: &Arc<Running>, client: &Arc<Client>) {
    enum Action {
        Write(Body),
        /// Answer the peer's close request, then stop.
        CloseReply,
        /// Nothing left to do and the client is gone.
        Finish,
    }

    loop {
        let action = {
            let mut outbox = client.outbox.lock().unwrap();
            while client.open.load(Ordering::SeqCst)
                && !client.close_after_send.load(Ordering::SeqCst)
                && outbox.is_empty()
            {
                outbox = client.filled.wait(outbox).unwrap();
            }
            if client.close_after_send.load(Ordering::SeqCst) {
                Action::CloseReply
            } else if !client.open.load(Ordering::SeqCst) && outbox.is_empty() {
                return;
            } else {
                match outbox.pop_front() {
                    Some(body) => Action::Write(body),
                    // The predicate above rules this out; treating it as "done"
                    // is safer than looping.
                    None => Action::Finish,
                }
            }
        };

        match action {
            Action::CloseReply => {
                // Failure here is expected when the socket is already gone, which
                // is exactly the case where a read error sent us here.
                let mut stream = &client.stream;
                let _ = stream.write_all(&frame::encode_close());
                break;
            }
            Action::Write(body) => {
                let bytes = match &body {
                    Body::Text(text) => frame::encode_text(text),
                    Body::Raw(bytes) => bytes.clone(),
                };
                let mut stream = &client.stream;
                if stream.write_all(&bytes).is_err() {
                    break;
                }
            }
            Action::Finish => break,
        }
    }

    running.close_client(client);
}

/// The `Sec-WebSocket-Accept` value for a client's key: base64 of SHA-1 over the
/// key and the RFC 6455 GUID.
pub fn accept_key(key: &[u8]) -> String {
    let mut input = Vec::with_capacity(key.len() + WEBSOCKET_GUID.len());
    input.extend_from_slice(key);
    input.extend_from_slice(WEBSOCKET_GUID);
    zzz_crypto::b64_encode(&sha1(&input))
}

/// Reads the request head and returns the `Sec-WebSocket-Key`, if it has one.
///
/// The value stays bytes: the reference hashes whatever it read, so a key that is
/// not valid UTF-8 still has to produce the same accept value.
///
/// A socket read timeout is not a failure here — a client's request head can
/// arrive in pieces — so the read resumes until the head is complete, the
/// connection ends, the byte bound is passed, or `deadline` arrives. The partial
/// line is kept across a timeout for the same reason.
fn read_handshake<R: BufRead>(reader: &mut R, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    let mut consumed = 0usize;
    let mut key: Option<Vec<u8>> = None;
    let mut line = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => return Ok(None), // The connection ended before the blank line.
            Ok(_) => {}
            Err(error) if frame::is_timeout(&error) => {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                continue;
            }
            Err(error) => return Err(error),
        }
        consumed += line.len();
        if consumed > MAX_HEADERS_BYTES {
            return Ok(None);
        }
        if !line.ends_with(b"\n") {
            // The connection ended part-way through a line.
            return Ok(None);
        }
        let complete = trim_line_end(&line);
        if complete.is_empty() {
            return Ok(key);
        }
        if key.is_none() {
            if let Some(colon) = complete.iter().position(|byte| *byte == b':') {
                let (name, value) = complete.split_at(colon);
                if name.eq_ignore_ascii_case(b"sec-websocket-key") {
                    let value = &value[1..];
                    let start = value
                        .iter()
                        .position(|byte| *byte != b' ' && *byte != b'\t')
                        .unwrap_or(value.len());
                    key = Some(value[start..].to_vec());
                }
            }
        }
        line.clear();
    }
}

fn trim_line_end(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_the_rfc_6455_accept_value() {
        // RFC 6455 section 1.3, the same fixture `tools/ws_test.cpp` uses.
        assert_eq!(
            accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    fn request(headers: &[&str]) -> String {
        let mut request = String::from("GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\n");
        for header in headers {
            request.push_str(header);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request
    }

    fn handshake_of(request: &str) -> Option<Vec<u8>> {
        until_the(reader_of(request), Duration::from_secs(1))
    }

    fn reader_of(request: &str) -> BufReader<&[u8]> {
        BufReader::new(request.as_bytes())
    }

    /// Reads a handshake with a deadline `after` now.
    fn until_the<R: BufRead>(mut reader: R, after: Duration) -> Option<Vec<u8>> {
        read_handshake(&mut reader, Instant::now() + after).expect("no io error")
    }

    #[test]
    fn reads_the_key_whatever_its_case_or_spacing() {
        // The reference compares the header name case-insensitively and strips
        // leading spaces and tabs from the value.
        for header in [
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==",
            "SEC-WEBSOCKET-KEY:\t dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Key:dGhlIHNhbXBsZSBub25jZQ==",
        ] {
            assert_eq!(
                handshake_of(&request(&[header])).as_deref(),
                Some(b"dGhlIHNhbXBsZSBub25jZQ==".as_slice()),
                "{header}"
            );
        }

        // Other headers are ignored, and unrelated ones that merely start with
        // the same letters are not mistaken for it.
        assert_eq!(
            handshake_of(&request(&[
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Extensions: permessage-deflate",
                "Sec-WebSocket-Key2: nope",
                "Sec-WebSocket-Key: realkey",
            ])),
            Some(b"realkey".to_vec())
        );
    }

    #[test]
    fn refuses_a_request_without_a_key() {
        assert_eq!(handshake_of(&request(&["Host: 127.0.0.1"])), None);
        // An empty value strips down to an empty key, which the caller refuses
        // the same way the reference's `key.empty()` check does.
        assert_eq!(
            handshake_of(&request(&["Sec-WebSocket-Key:   "])),
            Some(Vec::new())
        );
    }

    #[test]
    fn the_first_key_wins_and_the_tail_is_not_read() {
        assert_eq!(
            handshake_of(&request(&[
                "Sec-WebSocket-Key: first",
                "Sec-WebSocket-Key: second",
            ])),
            Some(b"first".to_vec())
        );
    }

    #[test]
    fn accepts_lf_only_line_endings() {
        // RFC 7230 tolerates a bare LF; the reference splits on CRLF, so this is
        // a small liberty taken deliberately.
        let request = "GET /ws HTTP/1.1\nSec-WebSocket-Key: k\n\n";
        assert_eq!(handshake_of(request), Some(b"k".to_vec()));
    }

    #[test]
    fn leaves_whatever_follows_the_head_in_the_reader() {
        // This is the deviation the module docs describe: the reference drains
        // its whole buffer into the header string, so a frame pipelined behind
        // the handshake is lost there. Here it stays buffered and parses.
        let mut wire = request(&["Sec-WebSocket-Key: k"]).into_bytes();
        wire.extend(frame::encode_text("early"));
        let mut reader = BufReader::new(wire.as_slice());

        assert_eq!(
            read_handshake(&mut reader, Instant::now() + Duration::from_secs(1)).unwrap(),
            Some(b"k".to_vec())
        );
        let frame = match frame::read_frame(&mut reader) {
            Ok(FrameRead::Frame(frame)) => frame,
            other => panic!("expected the buffered frame, got {other:?}"),
        };
        assert_eq!(
            (frame.opcode, frame.payload.as_slice()),
            (opcode::TEXT, b"early".as_slice())
        );
    }

    #[test]
    fn gives_up_on_a_head_that_never_ends() {
        let request = "GET /ws HTTP/1.1\r\n".to_string() + &"X-Filler: y\r\n".repeat(2000);
        assert!(request.len() > MAX_HEADERS_BYTES);
        assert_eq!(handshake_of(&request), None);
    }

    #[test]
    fn an_ended_connection_is_not_an_error() {
        assert_eq!(
            until_the(&b""[..], Duration::from_secs(1)),
            None,
            "a client that connects and says nothing"
        );
        assert_eq!(
            until_the(&b"GET /ws HTTP/1.1\r\n"[..], Duration::from_secs(1)),
            None,
            "a head cut off mid-way"
        );
        // A line that ends without its newline, which is what a connection cut
        // in the middle of a header looks like.
        assert_eq!(
            until_the(
                &b"GET /ws HTTP/1.1\r\nSec-WebSocket-Key: abc"[..],
                Duration::from_secs(1)
            ),
            None
        );
    }

    /// A socket that is quiet `stalls` times before handing over `data`.
    struct Trickling {
        data: Vec<u8>,
        at: usize,
        stalls: usize,
    }

    impl io::Read for Trickling {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.stalls > 0 {
                self.stalls -= 1;
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "nothing yet"));
            }
            if self.at >= self.data.len() {
                return Ok(0);
            }
            let take = (self.data.len() - self.at).min(buffer.len());
            buffer[..take].copy_from_slice(&self.data[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    #[test]
    fn a_head_that_arrives_in_pieces_is_still_read() {
        // Each read times out first, which is what a client whose request is split
        // across packets looks like to a socket with a read timeout.
        let request = request(&["Sec-WebSocket-Key: realkey"]);
        let reader = BufReader::new(Trickling {
            data: request.into_bytes(),
            at: 0,
            stalls: 3,
        });
        assert_eq!(
            until_the(reader, Duration::from_secs(1)),
            Some(b"realkey".to_vec())
        );
    }

    #[test]
    fn a_client_that_never_sends_its_head_is_dropped_at_the_deadline() {
        // No deadline: an idle connection is refused rather than waited on. This
        // is the bound the reference does not have.
        let reader = BufReader::new(Trickling {
            data: Vec::new(),
            at: 0,
            stalls: usize::MAX,
        });
        assert_eq!(until_the(reader, Duration::ZERO), None);
    }

    #[test]
    fn a_key_that_is_not_utf8_still_produces_an_accept_value() {
        // The value is hashed as bytes, so the accept key is defined even for a
        // key bytes that are not text.
        let mut wire = b"GET /ws HTTP/1.1\r\nSec-WebSocket-Key: ".to_vec();
        wire.extend_from_slice(&[0xFF, 0xFE]);
        wire.extend_from_slice(b"\r\n\r\n");
        let key = until_the(wire.as_slice(), Duration::from_secs(1)).expect("a key");
        assert_eq!(key, vec![0xFF, 0xFE]);
        assert!(!accept_key(&key).is_empty());
    }
}
