//! Live packet capture and the recorded-dump format.
//!
//! The C++ build got this from PcapPlusPlus, which wrapped either WinDivert
//! (Windows) or libpcap (Linux) and pulled in a full packet dissector. We need
//! very little of that: copy UDP datagrams for one port, remember which direction
//! they went, and hand the payload to KCP. So the Windows backend talks to
//! `WinDivert.dll` through five functions, and [`packet`] walks the IP and UDP
//! headers itself. That leaves the crate with no platform-specific dependencies
//! at runtime beyond the DLL and its driver.

pub mod dump;
pub mod packet;

#[cfg(windows)]
pub mod windivert;

#[cfg(windows)]
pub use windivert::Capture;

use std::fmt;

pub use dump::{Dump, DumpPacket};
pub use packet::{parse_udp, UdpView};
pub use zzz_wire::kcp::Direction;

/// The port Zenless Zone Zero's KCP session uses.
pub const GAME_PORT: u16 = 20501;

/// One captured datagram: the UDP payload plus what we know about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub direction: Direction,
    /// Wall-clock seconds. WinDivert's address does not carry a capture
    /// timestamp, so this is taken when the packet is received; it only needs
    /// second resolution for KCP's gap policy.
    pub timestamp: i64,
    /// UDP payload, exactly as `pcap.hpp` stored it.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// `WinDivert.dll` was not found. It has to sit next to the executable.
    DllMissing,
    /// A function the DLL was supposed to export is not there.
    MissingFunction(&'static str),
    /// `WinDivertOpen` failed; `code` is the Win32 error.
    OpenFailed {
        filter: String,
        code: u32,
    },
    RecvFailed(u32),
    /// The packet was larger than the buffer we offered.
    BufferTooSmall,
    Unsupported(&'static str),
}

impl CaptureError {
    /// A hint for the errors that have an obvious cause.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::OpenFailed { code: 5, .. } => Some(
                "access denied: WinDivert has to load a kernel driver, so run this from an \
                 elevated terminal",
            ),
            Self::OpenFailed { code: 577, .. } | Self::OpenFailed { code: 1275, .. } => {
                Some("the WinDivert driver could not be loaded; check WinDivert64.sys sits next to the executable and that driver signature enforcement has not been changed")
            }
            Self::DllMissing => {
                Some("build with `cargo build -p zzz-cli` so the build script copies WinDivert.dll into the target directory")
            }
            _ => None,
        }
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DllMissing => write!(f, "WinDivert.dll not found"),
            Self::MissingFunction(name) => write!(f, "WinDivert.dll does not export {name}"),
            Self::OpenFailed { filter, code } => {
                write!(
                    f,
                    "WinDivertOpen({filter:?}) failed with Win32 error {code}"
                )
            }
            Self::RecvFailed(code) => write!(f, "WinDivertRecv failed with Win32 error {code}"),
            Self::BufferTooSmall => write!(f, "captured packet did not fit in the buffer"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for CaptureError {}
