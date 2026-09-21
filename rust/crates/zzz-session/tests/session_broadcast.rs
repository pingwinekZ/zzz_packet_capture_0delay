//! The GUI's live-export wiring: a client connected *before* any snapshot must
//! still receive `ZOD` broadcasts pushed by `Session` (the page shows
//! "connected" on socket open, so silence means the push path is broken, not
//! the handshake).

use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use zzz_live::frame::{self, FrameRead};

const PORT: u16 = 23511;
const PATIENCE: Duration = Duration::from_secs(20);

/// The recorded login is a real 16 MB session and is not committed, so these
/// tests only run on the machine that recorded it — the same as
/// `zzz-cli/tests/login_capture.rs`.
fn recorded_dump() -> Option<zzz_capture::Dump> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../login_capture.json");
    if !path.exists() {
        return None;
    }
    Some(zzz_capture::Dump::load(&path).expect("the recorded dump loads"))
}

fn handshake(stream: &mut TcpStream) {
    stream
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(reader.read(&mut byte).unwrap(), 1, "handshake cut off");
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 101"), "no upgrade: {head}");
}

#[test]
fn session_broadcasts_snapshots_to_an_early_client() {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets");
    let data = zzz_gamedata::GameData::load(&assets).expect("committed assets load");
    let Some(dump) = recorded_dump() else {
        eprintln!("skipping: rust/login_capture.json is not present");
        return;
    };
    assert!(dump.len() > 600, "dump holds a full login");

    let server = zzz_live::Server::new();
    server.start(PORT).expect("listen");
    server.on_log(|line| eprintln!("  {line}"));

    let candidates = zzz_session::candidate_seeds(&data, None, None).unwrap();
    let mut session = zzz_session::Session::new(
        &data,
        candidates,
        zzz_export::ExportSettings::default(),
        Some(&server),
        zzz_session::Callbacks::default(),
    );
    let source = session.snapshot_source();
    server.on_snapshot_requested(move || source.lock().unwrap().clone());

    // The page connects first, long before the login completes.
    let stream =
        TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, PORT))).expect("connect");
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut handshake_stream = stream.try_clone().unwrap();
    handshake(&mut handshake_stream);
    let mut reader = BufReader::new(stream);

    for packet in dump.iter_packets() {
        session.feed(&packet).expect("feed decodes");
    }
    assert!(
        session.snapshots() > 0,
        "the login produced at least one snapshot"
    );

    let deadline = Instant::now() + PATIENCE;
    // Snapshots stream in as the login's load responses arrive, so early ones
    // may carry only some categories (the page leaves null categories
    // untouched). Wait for one with the full inventory.
    loop {
        match frame::read_frame(&mut reader) {
            Ok(FrameRead::Frame(frame)) => {
                let text = String::from_utf8_lossy(&frame.payload).into_owned();
                if text.contains("\"format\":\"ZOD\"")
                    && text.contains("\"discs\"")
                    && text.contains("\"characters\"")
                    && text.contains("\"wengines\"")
                {
                    server.stop();
                    return;
                }
            }
            Ok(FrameRead::Idle) => assert!(
                Instant::now() < deadline,
                "connected client received no ZOD broadcast"
            ),
            Ok(FrameRead::Ended) => panic!("server closed the connection"),
            Err(error) => panic!("unreadable frame: {error}"),
        }
    }
}

#[test]
fn sync_toggles_apply_without_restart() {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets");
    let data = zzz_gamedata::GameData::load(&assets).expect("committed assets load");
    let Some(dump) = recorded_dump() else {
        eprintln!("skipping: rust/login_capture.json is not present");
        return;
    };
    let packets: Vec<_> = dump.iter_packets().collect();

    let candidates = zzz_session::candidate_seeds(&data, None, None).unwrap();
    let mut session = zzz_session::Session::new(
        &data,
        candidates,
        zzz_export::ExportSettings::default(),
        None,
        zzz_session::Callbacks::default(),
    );
    let latest = session.snapshot_source();
    let current = || latest.lock().unwrap().clone();

    // Feed until a snapshot carries discs.
    let mut at = 0;
    while at < packets.len() && !current().contains("\"discs\"") {
        session.feed(&packets[at]).expect("feed decodes");
        at += 1;
    }
    assert!(
        current().contains("\"discs\""),
        "a snapshot with discs arrived"
    );
    let snapshots_before = session.snapshots();

    // Disable discs mid-stream, like unchecking the Sync box mid-capture.
    let toggled = zzz_export::ExportSettings {
        export_discs: false,
        ..Default::default()
    };
    session.set_settings(toggled);
    while at < packets.len() && session.snapshots() == snapshots_before {
        session.feed(&packets[at]).expect("feed decodes");
        at += 1;
    }
    assert!(
        session.snapshots() > snapshots_before,
        "a snapshot was served after the toggle"
    );
    let payload = current();
    assert!(
        !payload.contains("\"discs\""),
        "discs left the payload after the toggle"
    );
    assert!(
        payload.contains("\"characters\"") && payload.contains("\"wengines\""),
        "the other categories are still served"
    );
}

#[test]
fn the_login_baseline_is_not_logged_as_changes() {
    use std::sync::Mutex;
    use zzz_session::{Callbacks, LogEntry};

    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets");
    let data = zzz_gamedata::GameData::load(&assets).expect("committed assets load");
    let Some(dump) = recorded_dump() else {
        eprintln!("skipping: rust/login_capture.json is not present");
        return;
    };

    let forwarded = std::sync::Arc::new(Mutex::new(Vec::<LogEntry>::new()));
    let sink = std::sync::Arc::clone(&forwarded);
    let callbacks = Callbacks {
        changes: Some(std::sync::Arc::new(move |entries: Vec<LogEntry>| {
            sink.lock().unwrap().extend(entries);
        })),
        ..Callbacks::default()
    };

    let candidates = zzz_session::candidate_seeds(&data, None, None).unwrap();
    let mut session = zzz_session::Session::new(
        &data,
        candidates,
        zzz_export::ExportSettings::default(),
        None,
        callbacks,
    );
    for packet in dump.iter_packets() {
        session.feed(&packet).expect("feed decodes");
    }

    let summary = session.extract().expect("extraction ran");
    // The login really did carry the whole inventory through load responses.
    assert!(summary.disc_loads > 0, "disc load seen");
    assert!(summary.weapon_loads > 0, "weapon load seen");
    assert!(summary.avatar_loads > 0, "avatar load seen");

    let forwarded = forwarded.lock().unwrap();
    let added = forwarded
        .iter()
        .filter(|entry| {
            matches!(
                entry.change,
                zzz_scan::ItemChange::DiscAdded { .. }
                    | zzz_scan::ItemChange::EngineAdded { .. }
                    | zzz_scan::ItemChange::AgentAdded { .. }
            )
        })
        .count();
    eprintln!(
        "login forwarded {} change lines ({} added) of {} extracted records",
        forwarded.len(),
        added,
        summary.discs_added + summary.engines_added + summary.agents_added,
    );
    // The baseline is ~1.7k added records; only genuine post-load deltas may
    // be forwarded.
    assert!(
        forwarded.len() < 200,
        "baseline leaked into the change log: {} lines",
        forwarded.len()
    );
}
