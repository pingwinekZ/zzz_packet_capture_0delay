//! Windows capture backend: `WinDivert.dll` through five functions.
//!
//! Why hand-rolled FFI instead of the `windivert` crate: the crate pulls in the
//! `windows` crate (ten features of it), `etherparse` and `thiserror` to expose an
//! API that is still pre-1.0, and it needs WinDivert's import library and headers
//! at build time. We need exactly five functions, all of which have been stable
//! since WinDivert 2.0, and loading the DLL dynamically means the only build-time
//! artefact is the DLL itself — which also keeps WinDivert's LGPL satisfied the
//! same way the C++ build does: dynamically linked, shipped as a separate file.
//!
//! Behaviour kept from `pcap.hpp`: the same filter string, the same queue
//! parameters, and the same port check in code. Behaviour deliberately changed:
//! stopping uses `WinDivertShutdown`, which wakes a blocked receive on the spot,
//! instead of the C++ dance of flipping a flag and closing the handle because
//! `stopReceive()` only flips a flag.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{parse_udp, CaptureError, Direction, Packet};

// WINDIVERT_LAYER_NETWORK
const LAYER_NETWORK: i32 = 0;
// WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY: copy packets, never intercept
// them, so the game's own traffic is untouched.
const FLAG_SNIFF: u64 = 0x0001;
const FLAG_RECV_ONLY: u64 = 0x0004;
// WINDIVERT_PARAM_*
const PARAM_QUEUE_LENGTH: i32 = 0;
const PARAM_QUEUE_TIME: i32 = 1;
const PARAM_QUEUE_SIZE: i32 = 2;
// WINDIVERT_SHUTDOWN_RECV
const SHUTDOWN_RECV: i32 = 1;

// WinDivertOpen reports failure as INVALID_HANDLE_VALUE, not NULL. Treating the
// failure value as a handle makes the first WinDivertRecv fail with
// ERROR_INVALID_HANDLE and hides the real error, so both are rejected.
const INVALID_HANDLE_VALUE: isize = -1;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_OPERATION_ABORTED: u32 = 995;

/// Queue parameters, matching `WinDivertDevice::setPacketQueueParams` in the C++
/// build. A login burst arrives faster than we drain, and a dropped segment is
/// never retransmitted to a passive observer, so the queue is deliberately big.
const QUEUE_LENGTH: u64 = 8192;
const QUEUE_TIME: u64 = 8192;
const QUEUE_SIZE: u64 = 64 * 1024 * 1024;

/// `sizeof(WINDIVERT_ADDRESS)`, straight from `windivert.h`:
///
/// ```c
/// typedef struct {
///     INT64  Timestamp;
///     UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, ... Reserved1:8;
///     UINT32 Reserved2;
///     union { WINDIVERT_DATA_NETWORK Network; ... UINT8 Reserved3[64]; };
/// } WINDIVERT_ADDRESS;
/// ```
///
/// `WINDIVERT_DATA_FLOW` (8 + 8 + 4 + 16 + 16 + 2 + 2 + 1, padded) makes the
/// union 64 bytes, so the struct is 8 + 4 + 4 + 64 = 80. Under-sizing this buffer
/// is not a compile error: `WinDivertRecv` writes all 80 bytes regardless and the
/// last 16 land on whatever is next on the stack.
const ADDRESS_SIZE: usize = 80;
/// `WINDIVERT_ADDRESS` starts with an `INT64 Timestamp`, so the 32-bit bitfield
/// word (`Layer:8`, `Event:8`, `Sniffed:1`, `Outbound:1`, ...) begins at byte 8.
const ADDRESS_FLAGS_OFFSET: usize = 8;
/// `Outbound` is bit 17 of that word: `Layer` and `Event` occupy bits 0..16 and
/// `Sniffed` takes bit 16, so `Outbound` is bit 1 of byte 10. Reading byte 11
/// instead lands on `Reserved1`, which is always zero — that mistake labels every
/// packet incoming, so it is worth stating the arithmetic here.
const ADDRESS_OUTBOUND_OFFSET: usize = ADDRESS_FLAGS_OFFSET + 2;
const ADDRESS_OUTBOUND_MASK: u8 = 0x02;

/// Whether WinDivert reported this packet as leaving the machine.
///
/// Split out and tested because the bit lives at a hand-computed offset: an
/// off-by-one here produces a plausible-looking capture with two directions
/// interleaved as one.
fn address_is_outbound(address: &[u8]) -> bool {
    address
        .get(ADDRESS_OUTBOUND_OFFSET)
        .is_some_and(|byte| byte & ADDRESS_OUTBOUND_MASK != 0)
}

/// Largest packet WinDivert can hand us (`WINDIVERT_MTU_MAX`).
pub const MAX_PACKET_SIZE: usize = 0xFFFF;

type Handle = *mut c_void;

type OpenFn =
    unsafe extern "system" fn(filter: *const i8, layer: i32, priority: i16, flags: u64) -> Handle;
type RecvFn = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut u8) -> i32;
type SetParamFn = unsafe extern "system" fn(Handle, i32, u64) -> i32;
type ShutdownFn = unsafe extern "system" fn(Handle, i32) -> i32;
type CloseFn = unsafe extern "system" fn(Handle) -> i32;

extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

struct Functions {
    module: *mut c_void,
    open: OpenFn,
    recv: RecvFn,
    set_param: SetParamFn,
    shutdown: ShutdownFn,
    close: CloseFn,
}

// The module handle is only ever passed back to the Win32 loader, and WinDivert
// itself is thread-safe: `WinDivertShutdown` exists precisely so another thread
// can unblock a pending `WinDivertRecv`.
unsafe impl Send for Functions {}
unsafe impl Sync for Functions {}

impl Drop for Functions {
    fn drop(&mut self) {
        if !self.module.is_null() {
            unsafe { FreeLibrary(self.module) };
        }
    }
}

fn load() -> Result<Functions, CaptureError> {
    let name: Vec<u16> = "WinDivert.dll\0".encode_utf16().collect();
    let module = unsafe { LoadLibraryW(name.as_ptr()) };
    if module.is_null() {
        return Err(CaptureError::DllMissing);
    }

    let symbol = |name: &'static str| -> Result<*mut c_void, CaptureError> {
        let c_name = CString::new(name).expect("no NUL in a literal");
        let address = unsafe { GetProcAddress(module, c_name.as_ptr() as *const u8) };
        if address.is_null() {
            Err(CaptureError::MissingFunction(name))
        } else {
            Ok(address)
        }
    };

    // SAFETY: each symbol is transmuted to the signature windivert.h declares.
    // The annotations are spelled out rather than inferred so a signature drift is
    // visible in the diff.
    Ok(Functions {
        module,
        open: unsafe { std::mem::transmute::<*mut c_void, OpenFn>(symbol("WinDivertOpen")?) },
        recv: unsafe { std::mem::transmute::<*mut c_void, RecvFn>(symbol("WinDivertRecv")?) },
        set_param: unsafe {
            std::mem::transmute::<*mut c_void, SetParamFn>(symbol("WinDivertSetParam")?)
        },
        shutdown: unsafe {
            std::mem::transmute::<*mut c_void, ShutdownFn>(symbol("WinDivertShutdown")?)
        },
        close: unsafe { std::mem::transmute::<*mut c_void, CloseFn>(symbol("WinDivertClose")?) },
    })
}

struct Inner {
    functions: Functions,
    handle: AtomicIsize,
    stopped: AtomicBool,
    port: u16,
    packets: AtomicU64,
    skipped: AtomicU64,
    direction_conflicts: AtomicU64,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let handle = self.handle.swap(0, Ordering::AcqRel) as Handle;
        if !handle.is_null() {
            unsafe { (self.functions.close)(handle) };
        }
    }
}

/// A live WinDivert capture.
///
/// Cloning hands out another handle for `stop()`; only the thread that owns the
/// receive loop should call `recv`.
#[derive(Clone)]
pub struct Capture {
    inner: Arc<Inner>,
}

impl Capture {
    /// `udp.DstPort == port or udp.SrcPort == port`, the filter the C++ build
    /// pushes down to the driver so unrelated traffic never reaches us.
    pub fn port_filter(port: u16) -> String {
        format!("udp.DstPort == {port} or udp.SrcPort == {port}")
    }

    pub fn open(port: u16) -> Result<Self, CaptureError> {
        Self::open_filtered(&Self::port_filter(port), port)
    }

    pub fn open_filtered(filter: &str, port: u16) -> Result<Self, CaptureError> {
        let functions = load()?;
        let filter_c = CString::new(filter)
            .map_err(|_| CaptureError::Unsupported("filter contains a NUL byte"))?;

        let handle = unsafe {
            (functions.open)(
                filter_c.as_ptr(),
                LAYER_NETWORK,
                0,
                FLAG_SNIFF | FLAG_RECV_ONLY,
            )
        };
        let raw = handle as isize;
        if handle.is_null() || raw == INVALID_HANDLE_VALUE {
            let code = unsafe { GetLastError() };
            return Err(CaptureError::OpenFailed {
                filter: filter.to_string(),
                code,
            });
        }

        // Best effort, exactly like the original: a smaller queue is still usable.
        for (param, value) in [
            (PARAM_QUEUE_LENGTH, QUEUE_LENGTH),
            (PARAM_QUEUE_TIME, QUEUE_TIME),
            (PARAM_QUEUE_SIZE, QUEUE_SIZE),
        ] {
            unsafe { (functions.set_param)(handle, param, value) };
        }

        Ok(Self {
            inner: Arc::new(Inner {
                functions,
                handle: AtomicIsize::new(handle as isize),
                stopped: AtomicBool::new(false),
                port,
                packets: AtomicU64::new(0),
                skipped: AtomicU64::new(0),
                direction_conflicts: AtomicU64::new(0),
            }),
        })
    }

    /// Receive the next game datagram.
    ///
    /// Blocks until one arrives. Returns `Ok(None)` once the capture has been
    /// stopped, which makes the usual shape `while let Some(packet) = capture.recv(&mut buf)?`.
    /// Datagrams that do not parse as UDP for our port are skipped internally, so
    /// the caller never sees them.
    pub fn recv(&self, buffer: &mut [u8]) -> Result<Option<Packet>, CaptureError> {
        let mut address = [0u8; ADDRESS_SIZE];
        loop {
            let handle = self.inner.handle.load(Ordering::Acquire) as Handle;
            if handle.is_null() {
                return Ok(None);
            }

            let mut received: u32 = 0;
            let ok = unsafe {
                (self.inner.functions.recv)(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut received,
                    address.as_mut_ptr(),
                )
            };

            if ok == 0 {
                let code = unsafe { GetLastError() };
                return match code {
                    // Both mean "this handle is finished": shutdown was requested,
                    // or the driver went away.
                    ERROR_NO_MORE_ITEMS | ERROR_OPERATION_ABORTED => Ok(None),
                    ERROR_INSUFFICIENT_BUFFER => Err(CaptureError::BufferTooSmall),
                    other => Err(CaptureError::RecvFailed(other)),
                };
            }

            let bytes = &buffer[..(received as usize).min(buffer.len())];
            match self.decode(bytes, &address) {
                Some(packet) => {
                    self.inner.packets.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some(packet));
                }
                None => {
                    self.inner.skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn decode(&self, bytes: &[u8], address: &[u8; ADDRESS_SIZE]) -> Option<Packet> {
        let udp = parse_udp(bytes)?;
        // The driver filter already restricts this, but the C++ version checks
        // again in code and so do we: a filter change should not silently feed
        // another port's traffic into the KCP parser.
        if udp.source_port != self.inner.port && udp.destination_port != self.inner.port {
            return None;
        }

        // Direction comes from the port, exactly as `processRawPacket` decides it:
        // the client sends from an ephemeral port to 20501, so a destination of
        // 20501 means the packet is ours. WinDivert also reports the direction in
        // the address and the two agree in practice; a disagreement is counted so
        // it shows up in the summary instead of quietly halving the KCP input.
        let outgoing = udp.destination_port == self.inner.port;
        if outgoing != address_is_outbound(address) {
            self.inner
                .direction_conflicts
                .fetch_add(1, Ordering::Relaxed);
        }

        let direction = if outgoing {
            Direction::Outgoing
        } else {
            Direction::Incoming
        };
        Some(Packet {
            direction,
            timestamp: unix_seconds(),
            data: udp.payload.to_vec(),
        })
    }

    /// Ask the capture to finish. Safe to call from any thread; `recv` returns
    /// `Ok(None)` immediately, including when it is already blocked.
    pub fn stop(&self) {
        if self.inner.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        let handle = self.inner.handle.load(Ordering::Acquire) as Handle;
        if !handle.is_null() {
            unsafe { (self.inner.functions.shutdown)(handle, SHUTDOWN_RECV) };
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::Acquire)
    }

    /// Datagrams delivered to the caller.
    pub fn packets(&self) -> u64 {
        self.inner.packets.load(Ordering::Relaxed)
    }

    /// Datagrams the driver handed over that were not usable game traffic.
    pub fn skipped(&self) -> u64 {
        self.inner.skipped.load(Ordering::Relaxed)
    }

    /// Packets where the port and WinDivert's address disagreed about the
    /// direction. Zero is what a healthy capture reports.
    pub fn direction_conflicts(&self) -> u64 {
        self.inner.direction_conflicts.load(Ordering::Relaxed)
    }
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
    use crate::packet::parse_udp;
    use crate::GAME_PORT;

    /// Build the `WINDIVERT_ADDRESS` an outbound network-layer packet gets.
    fn make_address(
        layer: u8,
        event: u8,
        sniffed: bool,
        outbound: bool,
        loopback: bool,
    ) -> [u8; ADDRESS_SIZE] {
        let mut flags: u32 = u32::from(layer) | (u32::from(event) << 8);
        flags |= u32::from(sniffed) << 16;
        flags |= u32::from(outbound) << 17;
        flags |= u32::from(loopback) << 18;
        let mut address = [0u8; ADDRESS_SIZE];
        address[ADDRESS_FLAGS_OFFSET..ADDRESS_FLAGS_OFFSET + 4]
            .copy_from_slice(&flags.to_le_bytes());
        address
    }

    #[test]
    fn reads_the_outbound_bit_from_the_bitfield_word() {
        // WINDIVERT_LAYER_NETWORK = 0, WINDIVERT_EVENT_NETWORK_PACKET = 0.
        assert!(!address_is_outbound(&make_address(
            0, 0, true, false, false
        )));
        assert!(address_is_outbound(&make_address(0, 0, true, true, false)));
        // The neighbouring bits must not leak into it.
        assert!(!address_is_outbound(&make_address(1, 7, true, false, true)));
        assert!(address_is_outbound(&make_address(1, 7, false, true, true)));
        // An undersized buffer is not outbound rather than a panic.
        assert!(!address_is_outbound(&[]));
    }

    #[test]
    fn the_address_layout_matches_the_vendor_header() {
        // INT64 Timestamp, the bitfield word, Reserved2, then the 64-byte union.
        assert_eq!(ADDRESS_SIZE, 8 + 4 + 4 + 64);
        assert_eq!(ADDRESS_FLAGS_OFFSET, 8);
        // Layer:8 and Event:8 fill bytes 8 and 9, Sniffed takes bit 16, so
        // Outbound is bit 17: byte 10, mask 0x02.
        assert_eq!(ADDRESS_OUTBOUND_OFFSET, 10);
        assert_eq!(ADDRESS_OUTBOUND_MASK, 0x02);
    }

    #[test]
    fn the_reserved_bytes_are_not_mistaken_for_the_bit() {
        // Regression: reading byte 11 read `Reserved1`, which is always zero, so
        // every packet of a real 5997-packet capture was labelled incoming and the
        // two KCP directions were merged into one unreassemblable stream.
        let mut inbound = make_address(0, 0, true, false, false);
        inbound[11] = 0xFF; // Reserved1
        inbound[12] = 0xFF; // Reserved2
        assert!(
            !address_is_outbound(&inbound),
            "the reserved bytes must not be read as the direction"
        );

        let mut outbound = make_address(0, 0, true, true, false);
        outbound[11] = 0x00;
        assert!(address_is_outbound(&outbound));
    }

    #[test]
    fn the_port_decides_the_direction_the_way_process_raw_packet_did() {
        // Mirrors the C++: `outgoing = udpLayer->getDstPort() == 20501`.
        let client_to_server = ipv4_udp(51000, GAME_PORT, b"request");
        let server_to_client = ipv4_udp(GAME_PORT, 51000, b"response");
        assert_eq!(
            parse_udp(&client_to_server).unwrap().destination_port,
            GAME_PORT
        );
        assert_eq!(parse_udp(&server_to_client).unwrap().source_port, GAME_PORT);
    }

    fn ipv4_udp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[9] = 17;
        packet.extend_from_slice(&source.to_be_bytes());
        packet.extend_from_slice(&destination.to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        packet
    }
}
