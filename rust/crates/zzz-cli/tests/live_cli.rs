//! The live server, driven through the real command line.
//!
//! `zzz-live`'s own tests check the protocol against a client written for them,
//! which cannot catch a mistake in how `zzzcap live` *wires* the pieces: the
//! region detection, the snapshot callback, the payload rules. So this runs the
//! built binary on the recorded login and speaks to it over a socket, which is
//! what the optimizer does.
//!
//! Dormant unless `rust/login_capture.json` is present, the same as
//! `login_capture.rs`: the dump is a real 16 MB session and is not committed.

use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Relative to this crate: `rust/crates/zzz-cli`.
const DUMP: &str = "../../login_capture.json";
const ASSETS: &str = "../../../assets";

/// Ports of our own, away from the reference's 23313 — a real session may be
/// using that one while this runs.
const PORT: u16 = 23413;
const OTHER_PORT: u16 = 23414;

/// How long a client waits for the server to answer, and for the payload that
/// proves the whole inventory arrived.
const PATIENCE: Duration = Duration::from_secs(30);

fn recorded_dump() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DUMP);
    path.exists().then_some(path)
}

fn assets() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(ASSETS)
}

/// Kills the server even when the assertions above it fail.
struct Serving(Child);

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve(dump: &Path, port: u16, extra: &[&str]) -> Serving {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zzzcap"));
    command
        .arg("live")
        .arg("--in")
        .arg(dump)
        .arg("--assets")
        .arg(assets())
        .arg("--ws-port")
        .arg(port.to_string())
        // The server's own lines are worth seeing when this fails, and a pipe
        // nobody reads would eventually block it.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for argument in extra {
        command.arg(argument);
    }
    Serving(command.spawn().expect("the zzzcap binary starts"))
}

/// A WebSocket client: the handshake, and the server's unmasked frames.
struct Client {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Client {
    fn connect(port: u16) -> std::io::Result<Self> {
        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        stream.set_read_timeout(Some(PATIENCE))?;
        Ok(Self {
            reader: BufReader::new(stream.try_clone()?),
            stream,
        })
    }

    /// Connects while the server is still starting up.
    fn wait_for(port: u16) -> Self {
        let deadline = Instant::now() + PATIENCE;
        loop {
            match Self::connect(port) {
                Ok(client) => return client,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("no server on port {port}: {error}"),
            }
        }
    }

    fn handshake(&mut self) -> String {
        self.stream
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("send the handshake");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if self.reader.read(&mut byte).expect("read the head") == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    fn read_frame(&mut self) -> Vec<u8> {
        let mut head = [0u8; 2];
        self.reader.read_exact(&mut head).expect("a frame header");
        assert_eq!(head[0] & 0x0F, 0x1, "the server sends text frames");
        assert_eq!(head[1] & 0x80, 0, "a server frame is never masked");
        let length = match head[1] & 0x7F {
            126 => {
                let mut extended = [0u8; 2];
                self.reader.read_exact(&mut extended).expect("a length");
                u16::from_be_bytes(extended) as usize
            }
            127 => {
                let mut extended = [0u8; 8];
                self.reader.read_exact(&mut extended).expect("a length");
                u64::from_be_bytes(extended) as usize
            }
            length => length as usize,
        };
        let mut payload = vec![0u8; length];
        self.reader.read_exact(&mut payload).expect("a payload");
        payload
    }

    /// Reads snapshots until one satisfies `wanted`, which is how a client that
    /// connects mid-capture sees the inventory grow.
    fn snapshot_where(&mut self, wanted: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = Instant::now() + PATIENCE;
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let frame = self.read_frame();
            let json: serde_json::Value =
                serde_json::from_slice(&frame).expect("a snapshot is JSON");
            if wanted(&json) {
                return json;
            }
            seen.push(json);
        }
        panic!(
            "no snapshot matched within {PATIENCE:?} ({} others arrived)",
            seen.len()
        );
    }
}

/// The account in the recorded login, as `login_capture.rs` pins it.
const DISCS: usize = 1393;
const ENGINES: usize = 342;
const AGENTS: usize = 48;

#[test]
fn the_recorded_login_is_served_as_a_zod_snapshot() {
    let Some(dump) = recorded_dump() else {
        return;
    };
    let _server = serve(&dump, PORT, &[]);

    let mut client = Client::wait_for(PORT);
    let head = client.handshake();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "{head}"
    );

    // The region is detected from the capture, so the payload arrives without any
    // region argument — and the account arrives whole: `for_live` zeroes the
    // floors a written export would apply. Snapshots arrive as the capture grows
    // (the load responses land in different messages), so this waits for the one
    // that has everything.
    let snapshot = client.snapshot_where(|json| {
        json["discs"]
            .as_array()
            .is_some_and(|discs| discs.len() == DISCS)
            && json["characters"]
                .as_array()
                .is_some_and(|characters| characters.len() == AGENTS)
    });
    assert_eq!(snapshot["format"], "ZOD");
    assert_eq!(snapshot["version"], 1);
    assert_eq!(snapshot["source"], "ZZZ Packet Capture");
    assert_eq!(snapshot["wengines"].as_array().unwrap().len(), ENGINES);
    assert_eq!(snapshot["characters"].as_array().unwrap().len(), AGENTS);

    // A disc as the optimizer reads it: the keys are the export's, not the
    // capture's field numbers.
    let disc = &snapshot["discs"][0];
    assert!(disc["setKey"].is_string(), "{disc}");
    assert_eq!(disc["rarity"], "S");
    assert_eq!(disc["substats"].as_array().unwrap().len(), 4);

    // And a w-engine the capture says is worn names the agent wearing it, which
    // is the one link between the two lists that the site relies on.
    let worn = snapshot["wengines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|engine| engine["location"].as_str().is_some_and(|l| !l.is_empty()))
        .count();
    assert_eq!(worn, 36);
}

#[test]
fn a_switched_off_category_is_absent_from_the_payload() {
    let Some(dump) = recorded_dump() else {
        return;
    };
    let _server = serve(&dump, OTHER_PORT, &["--no-engines"]);

    let mut client = Client::wait_for(OTHER_PORT);
    client.handshake();
    let snapshot = client.snapshot_where(|json| {
        json["characters"]
            .as_array()
            .is_some_and(|characters| characters.len() == AGENTS)
    });

    // Absent, not empty: the optimizer's import replaces what it has, so an empty
    // list would mean "this account owns no w-engines".
    assert!(
        snapshot.get("wengines").is_none(),
        "w-engines were switched off but arrived anyway"
    );
    // The per-agent fields go with it, as they do in the reference: without them
    // the site cannot update which agent wears what.
    let agent = &snapshot["characters"][0];
    assert!(agent.get("wengineKey").is_none(), "{agent}");
    assert!(agent.get("wenginePhase").is_none(), "{agent}");
    // The other categories are unaffected.
    assert_eq!(snapshot["discs"].as_array().unwrap().len(), DISCS);
}
