//! Live export: the inventory served to the optimizer over a WebSocket, ported
//! from `src/websocket/websocketServer.hpp`.
//!
//! The C++ reaches for asio and OpenSSL here. Both are avoided: `std::net` plus
//! threads replaces the `io_context`, and [`sha1`] replaces OpenSSL's hash and
//! base64 — so this crate adds no dependencies beyond the base64 helper that is
//! already ported in `zzz-crypto`.
//!
//! # What the server does
//!
//! ```no_run
//! use zzz_live::Server;
//!
//! let server = Server::new();
//! server.on_log(|line| println!("{line}"));
//! server.on_snapshot_requested(|| String::from("{\"format\":\"ZOD\"}"));
//! server.start(zzz_live::DEFAULT_PORT).expect("bind 127.0.0.1:23313");
//! server.broadcast_text("{\"format\":\"ZOD\"}"); // never blocks
//! assert_eq!(server.client_count(), 0);
//! server.stop();
//! ```
//!
//! It is loopback-only, sends text frames, answers pings and understands close.
//! The payloads are the caller's business: `zzz-export` produces them, and the
//! rules for a *live* payload differ from a file one — see `Izod::for_live`.
//!
//! # Provenance
//!
//! `tools/ws_test.cpp` is the reference's own self-test, and
//! `rust/crates/zzz-live/tests/live_server.rs` walks the same checklist against
//! this port: the RFC 6455 example key, the initial snapshot, broadcasts, a
//! masked client frame, ping/pong, the close handshake, deregistration, `stop()`
//! closing clients and a restart on the same port. It then adds the cases the
//! reference's test does not reach — a second client, a 64 KiB payload, and a
//! broadcast winning over the snapshot callback.

pub mod frame;
pub mod server;
mod sha1;

pub use frame::{Frame, FrameError, MAX_INBOUND_PAYLOAD};
pub use server::{accept_key, Server, ServerError, DEFAULT_PORT, MAX_HEADERS_BYTES};
pub use sha1::sha1;
