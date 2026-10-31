//! Live packet capture and the recorded-dump format.
//!
//! The C++ build got this from PcapPlusPlus, which wrapped either WinDivert
//! (Windows) or libpcap (Linux) and pulled in a full packet dissector. We need
//! very little of that: copy UDP datagrams for one port, remember which direction
//! they went, and hand the payload to KCP.
//!
//! The two backends sit behind the same [`Capture`] type:
//!
//! * Windows talks to `WinDivert.dll` through five functions. WinDivert's
//!   network layer hands over IP packets with no link-layer header, so
//!   [`packet`] walks the IP and UDP headers directly.
//! * Linux uses libpcap through the `pcap` crate. libpcap hands over
//!   link-layer frames (Ethernet, or Linux cooked SLL/SLL2 on the `any`
//!   device), so [`link`] strips that header before [`packet`] sees the IP
//!   packet.

pub mod dump;
pub mod link;
pub mod packet;

#[cfg(windows)]
pub mod windivert;

#[cfg(windows)]
pub use windivert::Capture;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::Capture;

#[cfg(not(any(windows, target_os = "linux")))]
pub mod unsupported;

#[cfg(not(any(windows, target_os = "linux")))]
pub use unsupported::Capture;

use std::fmt;

pub use dump::{Dump, DumpPacket};
pub use link::parse_frame;
pub use packet::{parse_udp, UdpView};
pub use zzz_wire::kcp::Direction;

/// The port Zenless Zone Zero's KCP session uses.
pub const GAME_PORT: u16 = 20501;

/// One captured datagram: the UDP payload plus what we know about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub direction: Direction,
    /// Wall-clock seconds. WinDivert's address does not carry a capture
    /// timestamp, and libpcap's timestamp would make the two backends disagree,
    /// so this is taken when the packet is received; it only needs second
    /// resolution for KCP's gap policy.
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
    /// libpcap could not be used or the device could not be opened.
    #[cfg(target_os = "linux")]
    DeviceUnavailable {
        device: String,
        message: String,
    },
    /// libpcap refused raw-socket access; the process needs root or
    /// `CAP_NET_RAW`.
    #[cfg(target_os = "linux")]
    PermissionDenied {
        device: String,
    },
    /// libpcap rejected the BPF filter.
    #[cfg(target_os = "linux")]
    FilterRejected {
        filter: String,
        message: String,
    },
    /// libpcap failed while reading.
    #[cfg(target_os = "linux")]
    PcapRecvFailed(String),
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
            #[cfg(target_os = "linux")]
            Self::PermissionDenied { .. } => Some(
                "live capture needs raw-socket access: run as root, or grant it once with \
                 `sudo setcap cap_net_raw,cap_net_admin=eip <path to zzzcap>` (and to zzzgui \
                 if you use the window)",
            ),
            #[cfg(target_os = "linux")]
            Self::DeviceUnavailable { .. } => Some(
                "install libpcap (Debian/Ubuntu: `sudo apt install libpcap0.8`; Fedora: \
                 `sudo dnf install libpcap`; Arch: `sudo pacman -S libpcap`) and check the \
                 device name in ZZZ_CAPTURE_DEVICE",
            ),
            Self::Unsupported(_) => Some(
                "live capture is implemented on Windows and Linux; serve a recorded dump with \
                 `--in <dump>` instead",
            ),
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
            #[cfg(target_os = "linux")]
            Self::DeviceUnavailable { device, message } => {
                write!(f, "could not open capture device {device:?}: {message}")
            }
            #[cfg(target_os = "linux")]
            Self::PermissionDenied { device } => {
                write!(f, "permission denied opening capture device {device:?}")
            }
            #[cfg(target_os = "linux")]
            Self::FilterRejected { filter, message } => {
                write!(f, "libpcap rejected the filter {filter:?}: {message}")
            }
            #[cfg(target_os = "linux")]
            Self::PcapRecvFailed(message) => write!(f, "libpcap receive failed: {message}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for CaptureError {}
