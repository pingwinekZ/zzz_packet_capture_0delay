//! The reference's own checklist, walked against this port.
//!
//! `tools/ws_test.cpp` is the C++ self-test. Its case list is reproduced here in
//! order, with the same fixtures — the RFC 6455 example key, `example` payloads,
//! the ping/pong and close exchanges, `stop()` and a restart on the same port —
//! so that a difference in behaviour shows up as a failing test rather than as an
//! optimizer that silently receives nothing.
//!
//! Every server gets its own port. The tests run in parallel, and a shared port
//! would make them flaky for a reason that has nothing to do with the port.

use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use zzz_live::frame::{self, opcode, Frame, FrameRead};
use zzz_live::{Server, DEFAULT_PORT};

/// The example from RFC 6455 section 1.3, and the fixture `ws_test.cpp` uses.
const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const RFC_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

const SNAPSHOT: &str = "{\"format\":\"ZOD\",\"snapshot\":true}";

/// How long a client waits for a frame before calling it missing.
const PATIENCE: Duration = Duration::from_secs(5);

/// A client that speaks just enough of the protocol to test the server.
struct Client {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Client {
    fn connect(port: u16) -> Self {
        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .expect("connect to the server");
        stream
            .set_read_timeout(Some(PATIENCE))
            .expect("a read timeout");
        Self {
            reader: BufReader::new(stream.try_clone().expect("clone the socket")),
            stream,
        }
    }

    /// Sends a handshake and returns the response head.
    fn handshake(&mut self, key: &str) -> String {
        let request = format!(
            "GET /ws HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        self.stream.write_all(request.as_bytes()).expect("send");
        self.read_head()
    }

    fn read_head(&mut self) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if self.reader.read(&mut byte).expect("read") == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    /// A masked frame, as a client must send one.
    fn send_frame(&mut self, opcode: u8, payload: &[u8], masked: bool) {
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        let mut frame = vec![0x80 | opcode];
        let length = payload.len();
        let mask_bit = if masked { 0x80 } else { 0 };
        if length < 126 {
            frame.push(length as u8 | mask_bit);
        } else if length <= 0xFFFF {
            frame.push(126 | mask_bit);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            frame.push(127 | mask_bit);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
        if masked {
            frame.extend_from_slice(&mask);
            frame.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
        } else {
            frame.extend_from_slice(payload);
        }
        self.stream.write_all(&frame).expect("send frame");
    }

    /// The next frame, waiting up to `PATIENCE`. An idle socket is not a failure
    /// here, so it is retried until the deadline passes.
    fn read_frame(&mut self) -> Frame {
        let deadline = Instant::now() + PATIENCE;
        loop {
            match frame::read_frame(&mut self.reader) {
                Ok(FrameRead::Frame(frame)) => return frame,
                Ok(FrameRead::Idle) => {
                    assert!(
                        Instant::now() < deadline,
                        "the server sent no frame within {PATIENCE:?}"
                    );
                }
                Ok(FrameRead::Ended) => panic!("the server closed the connection"),
                Err(error) => panic!("unreadable frame: {error}"),
            }
        }
    }

    /// The next frame, or `None` if the server stayed quiet for `wait`.
    fn read_frame_or_none(&mut self, wait: Duration) -> Option<Frame> {
        self.stream
            .set_read_timeout(Some(wait))
            .expect("set the timeout");
        let outcome = frame::read_frame(&mut self.reader);
        self.stream
            .set_read_timeout(Some(PATIENCE))
            .expect("restore the timeout");
        match outcome {
            Ok(FrameRead::Frame(frame)) => Some(frame),
            _ => None,
        }
    }
}

/// A server that logs nothing and serves `SNAPSHOT` as its initial payload.
fn server_with_snapshot() -> Server {
    let server = Server::new();
    server.on_snapshot_requested(|| SNAPSHOT.to_string());
    server
}

/// Waits for a condition, the way the C++ test polls `clientCount`.
fn await_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

#[test]
fn handshake_uses_the_rfc_6455_example_key() {
    let server = server_with_snapshot();
    server.start(24101).expect("start");
    let mut client = Client::connect(24101);
    let head = client.handshake(RFC_KEY);

    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.contains("Upgrade: websocket"), "{head}");
    assert!(head.contains("Connection: Upgrade"), "{head}");
    assert!(
        head.contains(&format!("Sec-WebSocket-Accept: {RFC_ACCEPT}")),
        "unexpected accept value in {head}"
    );
    // The 101 is written before the client is registered, so the count has to be
    // polled rather than read: the reply can reach this thread first.
    assert!(await_until(|| server.client_count() == 1));
    server.stop();
}

#[test]
fn pushes_a_snapshot_on_connect_and_broadcasts_after_it() {
    let server = server_with_snapshot();
    server.start(24102).expect("start");
    assert_eq!(server.client_count(), 0, "no clients initially");

    let mut client = Client::connect(24102);
    client.handshake(RFC_KEY);
    assert!(
        await_until(|| server.client_count() == 1),
        "client registered"
    );

    let snapshot = client.read_frame();
    assert_eq!(snapshot.opcode, opcode::TEXT);
    assert_eq!(snapshot.payload, SNAPSHOT.as_bytes());

    server.broadcast_text("hello world");
    let broadcast = client.read_frame();
    assert_eq!(broadcast.opcode, opcode::TEXT);
    assert_eq!(broadcast.payload, b"hello world");

    // An empty payload is a valid frame, not a no-op: the caller decides what to
    // send, and the reference's writer encodes whatever is queued.
    server.broadcast_text("");
    let empty = client.read_frame();
    assert_eq!(empty.payload, Vec::<u8>::new());
    server.stop();
}

#[test]
fn survives_a_client_text_frame_and_answers_pings() {
    let server = server_with_snapshot();
    server.start(24103).expect("start");
    let mut client = Client::connect(24103);
    client.handshake(RFC_KEY);
    let _snapshot = client.read_frame();

    client.send_frame(opcode::TEXT, b"ignored text", true);
    client.send_frame(opcode::BINARY, b"\x00\x01", true);
    server.broadcast_text("after client text");
    let after = client.read_frame();
    assert_eq!(after.payload, b"after client text", "the server survived");

    // A masked ping is answered with a pong carrying the same payload.
    client.send_frame(opcode::PING, b"p", true);
    let pong = client.read_frame();
    assert_eq!(pong.opcode, opcode::PONG);
    assert_eq!(pong.payload, b"p");

    // An unmasked ping too, which the reference tolerates.
    client.send_frame(opcode::PING, b"q", false);
    let pong = client.read_frame();
    assert_eq!((pong.opcode, pong.payload), (opcode::PONG, b"q".to_vec()));
    server.stop();
}

#[test]
fn answers_a_close_and_deregisters() {
    let server = server_with_snapshot();
    server.start(24104).expect("start");
    let mut client = Client::connect(24104);
    client.handshake(RFC_KEY);
    let _snapshot = client.read_frame();

    client.send_frame(opcode::CLOSE, b"", true);
    let reply = client.read_frame();
    assert_eq!(reply.opcode, opcode::CLOSE);
    assert_eq!(
        reply.payload,
        Vec::<u8>::new(),
        "the reference replies with an empty close frame, not the peer's code"
    );

    assert!(
        await_until(|| server.client_count() == 0),
        "client deregistered after close"
    );
    server.stop();
}

#[test]
fn delivers_to_every_client() {
    let server = server_with_snapshot();
    server.start(24105).expect("start");

    let mut first = Client::connect(24105);
    first.handshake(RFC_KEY);
    let mut second = Client::connect(24105);
    second.handshake(RFC_KEY);
    assert!(
        await_until(|| server.client_count() == 2),
        "both registered"
    );
    // Each got the snapshot before anything was broadcast.
    assert_eq!(first.read_frame().payload, SNAPSHOT.as_bytes());
    assert_eq!(second.read_frame().payload, SNAPSHOT.as_bytes());

    server.broadcast_text("both");
    assert_eq!(first.read_frame().payload, b"both");
    assert_eq!(second.read_frame().payload, b"both");
    server.stop();
}

#[test]
fn a_late_client_gets_the_latest_broadcast_not_the_snapshot() {
    // The snapshot callback is the fallback for a client that connects before
    // anything has been broadcast; once something has, the reference prefers it.
    let server = server_with_snapshot();
    server.start(24106).expect("start");

    server.broadcast_text("live payload");
    let mut client = Client::connect(24106);
    client.handshake(RFC_KEY);
    assert_eq!(client.read_frame().payload, b"live payload");
    server.stop();
}

#[test]
fn an_empty_snapshot_sends_nothing() {
    // `makeLiveZodJson` returns an empty string when it has nothing to say, and
    // the reference's caller checks `if (!json.empty())` before broadcasting.
    let server = Server::new();
    server.on_snapshot_requested(String::new);
    server.start(24107).expect("start");

    let mut client = Client::connect(24107);
    client.handshake(RFC_KEY);
    assert!(
        client
            .read_frame_or_none(Duration::from_millis(300))
            .is_none(),
        "an empty payload must not become a frame"
    );

    // The next broadcast is therefore the client's first frame.
    server.broadcast_text("first");
    assert_eq!(client.read_frame().payload, b"first");
    server.stop();
}

#[test]
fn broadcasts_large_payloads_in_one_64_bit_length_frame() {
    // The export is hundreds of kilobytes, which is where the frame length form
    // changes. `ws_test.cpp` never reaches this.
    let server = server_with_snapshot();
    server.start(24108).expect("start");
    let mut client = Client::connect(24108);
    client.handshake(RFC_KEY);
    let _snapshot = client.read_frame();

    let payload = "x".repeat(300_000);
    server.broadcast_text(&payload);
    let frame = client.read_frame();
    assert_eq!(frame.opcode, opcode::TEXT);
    assert_eq!(frame.payload.len(), payload.len());
    assert_eq!(frame.payload, payload.as_bytes());
    server.stop();
}

#[test]
fn stop_disconnects_and_releases_the_port() {
    let server = server_with_snapshot();
    server.start(24109).expect("start");
    let mut client = Client::connect(24109);
    client.handshake(RFC_KEY);
    let _snapshot = client.read_frame();

    server.stop();
    assert_eq!(server.client_count(), 0, "stop() disconnects clients");
    assert!(!server.is_running());

    // The client's socket is closed: a read returns end-of-stream rather than
    // blocking until the timeout.
    client
        .stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buffer = [0u8; 16];
    let read = client.reader.read(&mut buffer);
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "the socket should be closed, got {read:?}"
    );

    // Restarting on the same port has to work: the reference sets
    // reuse_address and its self-test restarts.
    server.start(24109).expect("restart on the same port");
    let mut client = Client::connect(24109);
    client.handshake(RFC_KEY);
    assert_eq!(client.read_frame().payload, SNAPSHOT.as_bytes());
    server.stop();
}

#[test]
fn a_client_that_never_hands_shakes_is_hidden_and_cleaned_up() {
    let server = server_with_snapshot();
    server.start(24110).expect("start");

    // Connect and say nothing.
    let quiet =
        TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, 24110))).expect("connect");
    quiet
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    // Give the server a moment to accept it. The accept loop polls, so this is
    // the only way to let it happen before the assertion below.
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(
        server.client_count(),
        0,
        "a connection mid-handshake is not a client"
    );

    // A real client still connects and works while the quiet one sits there.
    let mut client = Client::connect(24110);
    client.handshake(RFC_KEY);
    assert_eq!(client.read_frame().payload, SNAPSHOT.as_bytes());

    // And a broadcast reaches it, with the unregistered connection in the list.
    server.broadcast_text("nobody is listening");
    assert_eq!(client.read_frame().payload, b"nobody is listening");

    // And `stop` reaches the quiet one too: its socket is closed even though it
    // never registered.
    server.stop();
    let mut buffer = [0u8; 16];
    let mut quiet_reader = BufReader::new(quiet);
    let read = quiet_reader.read(&mut buffer);
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "the unhandshaken socket should be closed, got {read:?}"
    );
}

#[test]
fn a_stopped_server_refuses_new_connections_and_drops_broadcasts() {
    let server = server_with_snapshot();
    server.start(24111).expect("start");
    server.broadcast_text("while running");
    server.stop();

    // No listener any more.
    assert!(
        TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, 24111))).is_err(),
        "nothing should be listening"
    );

    // A broadcast to a stopped server is dropped rather than panicking, and does
    // not resurrect the snapshot: restarting clears it, as the reference's
    // `start` does.
    server.broadcast_text("while stopped");
    server.start(24111).expect("start again");
    let mut client = Client::connect(24111);
    client.handshake(RFC_KEY);
    assert_eq!(
        client.read_frame().payload,
        SNAPSHOT.as_bytes(),
        "the snapshot from before the restart must not survive it"
    );
    server.stop();
}

#[test]
fn a_disconnected_client_is_cleaned_up_and_the_rest_keep_working() {
    let server = server_with_snapshot();
    server.start(24112).expect("start");

    let mut leaver = Client::connect(24112);
    leaver.handshake(RFC_KEY);
    let _ = leaver.read_frame();
    let mut stayer = Client::connect(24112);
    stayer.handshake(RFC_KEY);
    let _ = stayer.read_frame();
    assert!(await_until(|| server.client_count() == 2));

    // Drop the socket without a close handshake, which is how a browser tab
    // closing looks.
    leaver
        .stream
        .shutdown(Shutdown::Both)
        .expect("shut the socket down");
    drop(leaver);
    assert!(
        await_until(|| server.client_count() == 1),
        "the departed client must be retired"
    );

    server.broadcast_text("still here");
    assert_eq!(stayer.read_frame().payload, b"still here");
    server.stop();
}

#[test]
fn the_default_port_is_the_reference_port() {
    assert_eq!(DEFAULT_PORT, 23313);
}
