//! Linux capture backend: libpcap through the `pcap` crate.
//!
//! libpcap is the Linux equivalent of WinDivert here. The `any` pseudo-device
//! captures every interface at once, which matters because the game's server
//! can move between interfaces (Wi-Fi, Ethernet, VPN) between sessions. The
//! BPF filter is pushed down to the kernel, so unrelated traffic never reaches
//! us.
//!
//! Stopping uses `pcap_breakloop` through `pcap::BreakLoop`, which is the
//! libpcap equivalent of `WinDivertShutdown`: it wakes a blocked
//! `next_packet()` from another thread. The read timeout is a second line of
//! defence for libpcap versions where breakloop cannot wake the read.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use pcap::{Active, Capture as PcapCapture, Error as PcapError};

use crate::{link::parse_frame, CaptureError, Direction, Packet};

/// libpcap's pseudo-device that captures every interface.
pub const DEFAULT_DEVICE: &str = "any";

/// `WINDIVERT_MTU_MAX` has the same value; this is the largest frame we ask
/// libpcap to copy.
const SNAPLEN: i32 = 0xFFFF;

/// Matching the WinDivert queue intent: a login burst is bigger than the
/// default libpcap ring, and a dropped datagram is never retransmitted to a
/// passive observer.
const BUFFER_SIZE: i32 = 64 * 1024 * 1024;

/// How long a read may block before `recv` re-checks the stop flag. libpcap
/// needs a non-zero timeout for `next_packet` to return at all on some
/// platforms; 100 ms is invisible next to KCP's own timers.
const READ_TIMEOUT_MS: i32 = 100;

struct Inner {
    // Declared before `capture` so the breakloop handle is dropped before the
    // pcap handle it points at.
    break_loop: pcap::BreakLoop,
    capture: Mutex<PcapCapture<Active>>,
    linktype: i32,
    stopped: AtomicBool,
    port: u16,
    packets: AtomicU64,
    skipped: AtomicU64,
}

/// A live libpcap capture.
///
/// Cloning hands out another handle for `stop()`; only the thread that owns
/// the receive loop should call `recv`.
#[derive(Clone)]
pub struct Capture {
    inner: Arc<Inner>,
}

impl Capture {
    /// `udp port {port}`, the BPF filter libpcap installs in the kernel.
    pub fn port_filter(port: u16) -> String {
        format!("udp port {port}")
    }

    /// Open the default device (`any`, or `ZZZ_CAPTURE_DEVICE` if set).
    pub fn open(port: u16) -> Result<Self, CaptureError> {
        let device = device();
        Self::open_on(&device, port)
    }

    /// Open `device` for `port`.
    pub fn open_on(device: &str, port: u16) -> Result<Self, CaptureError> {
        Self::open_on_filtered(device, &Self::port_filter(port), port)
    }

    /// As [`Capture::open`], but with an explicit BPF filter.
    pub fn open_filtered(filter: &str, port: u16) -> Result<Self, CaptureError> {
        let device = device();
        Self::open_on_filtered(&device, filter, port)
    }

    fn open_on_filtered(device: &str, filter: &str, port: u16) -> Result<Self, CaptureError> {
        let inactive = PcapCapture::from_device(device)
            .map_err(|error| open_error(device, error))?
            .snaplen(SNAPLEN)
            .promisc(false)
            .timeout(READ_TIMEOUT_MS)
            .immediate_mode(true)
            .buffer_size(BUFFER_SIZE);

        let mut capture = inactive.open().map_err(|error| open_error(device, error))?;
        capture
            .filter(filter, true)
            .map_err(|error| CaptureError::FilterRejected {
                filter: filter.to_string(),
                message: error.to_string(),
            })?;

        let linktype = capture.get_datalink().0;
        let break_loop = capture.breakloop_handle();

        Ok(Self {
            inner: Arc::new(Inner {
                break_loop,
                capture: Mutex::new(capture),
                linktype,
                stopped: AtomicBool::new(false),
                port,
                packets: AtomicU64::new(0),
                skipped: AtomicU64::new(0),
            }),
        })
    }

    /// Receive the next game datagram.
    ///
    /// Blocks until one arrives. Returns `Ok(None)` once the capture has been
    /// stopped. Frames that do not parse as UDP for our port are skipped
    /// internally, so the caller never sees them.
    ///
    /// `buffer` is kept for API parity with the Windows backend, which needs
    /// the caller to supply storage; libpcap owns its own buffer.
    pub fn recv(&self, _buffer: &mut [u8]) -> Result<Option<Packet>, CaptureError> {
        loop {
            if self.inner.stopped.load(Ordering::Acquire) {
                return Ok(None);
            }

            let mut guard = lock(&self.inner.capture);
            match guard.next_packet() {
                Ok(packet) => {
                    let Some(udp) = parse_frame(self.inner.linktype, packet.data) else {
                        self.inner.skipped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if udp.source_port != self.inner.port && udp.destination_port != self.inner.port
                    {
                        self.inner.skipped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Direction comes from the port, exactly as the C++ build
                    // decides it: the client sends to 20501, so a destination
                    // of 20501 means the packet is ours. Linux has no
                    // equivalent of WinDivert's Outbound bit to cross-check.
                    let outgoing = udp.destination_port == self.inner.port;
                    self.inner.packets.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some(Packet {
                        direction: if outgoing {
                            Direction::Outgoing
                        } else {
                            Direction::Incoming
                        },
                        timestamp: unix_seconds(),
                        data: udp.payload.to_vec(),
                    }));
                }
                Err(PcapError::TimeoutExpired) => continue,
                Err(PcapError::NoMorePackets) => return Ok(None),
                Err(error) => return Err(CaptureError::PcapRecvFailed(error.to_string())),
            }
        }
    }

    /// Ask the capture to finish. Safe to call from any thread; `recv` returns
    /// `Ok(None)` immediately, including when it is already blocked.
    pub fn stop(&self) {
        if self.inner.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.break_loop.breakloop();
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::Acquire)
    }

    /// Datagrams delivered to the caller.
    pub fn packets(&self) -> u64 {
        self.inner.packets.load(Ordering::Relaxed)
    }

    /// Frames libpcap handed over that were not usable game traffic.
    pub fn skipped(&self) -> u64 {
        self.inner.skipped.load(Ordering::Relaxed)
    }

    /// Always zero on Linux: libpcap does not report a per-packet direction,
    /// so there is nothing to disagree with the port. Kept so the CLI can
    /// print the same summary on both platforms.
    pub fn direction_conflicts(&self) -> u64 {
        0
    }
}

fn device() -> String {
    std::env::var("ZZZ_CAPTURE_DEVICE").unwrap_or_else(|_| DEFAULT_DEVICE.to_string())
}

/// Turn a libpcap open error into the variant that carries the useful hint.
fn open_error(device: &str, error: PcapError) -> CaptureError {
    let message = error.to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("permission")
        || lowered.contains("not permitted")
        || lowered.contains("access denied")
    {
        CaptureError::PermissionDenied {
            device: device.to_string(),
        }
    } else {
        CaptureError::DeviceUnavailable {
            device: device.to_string(),
            message,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_is_bpf_syntax() {
        assert_eq!(Capture::port_filter(20501), "udp port 20501");
    }

    /// The CLI and GUI clone the handle into a writer thread while the receive
    /// loop keeps the original, so both `Send` and `Sync` are load-bearing.
    #[test]
    fn capture_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Capture>();
    }

    #[test]
    fn permission_errors_get_the_raw_socket_hint() {
        let error = open_error(
            "any",
            PcapError::PcapError(
                "You don't have permission to capture on that device \
                 (socket: Operation not permitted)"
                    .to_string(),
            ),
        );
        assert!(matches!(error, CaptureError::PermissionDenied { .. }));
        assert!(error.hint().is_some());
    }

    #[test]
    fn other_open_errors_name_the_device() {
        let error = open_error("eth0", PcapError::PcapError("No such device".to_string()));
        assert!(matches!(
            &error,
            CaptureError::DeviceUnavailable { device, .. } if device == "eth0"
        ));
        assert!(error.to_string().contains("eth0"));
    }
}
