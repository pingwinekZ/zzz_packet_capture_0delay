//! Port of `src/kcp/*` — the game's KCP transport, as seen by a passive observer.
//!
//! This is not a full KCP implementation. We only ever *read* the stream, so
//! there is no ACK state, no retransmission and no congestion control. The one
//! interesting policy is what to do about a gap: the game never retransmits a
//! segment it already delivered, so a hole in our capture is lost forever and the
//! stream has to be nudged forward instead of stalling. That is the
//! `MAX_GAP_SECONDS` / `MAX_RCV_BUF` logic below, and it has to stay identical or
//! long captures silently stop producing data.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

pub const SEGMENT_HEADER_SIZE: usize = 28;
pub const MESSAGE_HEADER_SIZE: usize = 12;

pub const CMD_PUSH: u8 = 81;
pub const CMD_ACK: u8 = 82;
pub const CMD_WASK: u8 = 83;
pub const CMD_WINS: u8 = 84;

/// A gap that stays unfilled this long is treated as permanently lost.
const MAX_GAP_SECONDS: i64 = 2;
/// Hard cap on buffered out-of-order segments.
const MAX_RCV_BUF: usize = 512;

/// Which side of the connection a packet came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Incoming,
    Outgoing,
}

impl Direction {
    pub fn is_outgoing(self) -> bool {
        matches!(self, Self::Outgoing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcpError {
    ShortSegment(usize),
    ShortMessageHeader(usize),
}

impl fmt::Display for KcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortSegment(len) => {
                write!(f, "not enough data to read KCP header ({len} bytes)")
            }
            Self::ShortMessageHeader(len) => {
                write!(
                    f,
                    "not enough data to read KCP message header ({len} bytes)"
                )
            }
        }
    }
}

impl std::error::Error for KcpError {}

/// `KCP::Header` — 28 bytes, all multi-byte fields little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentHeader {
    pub conv: u32,
    pub token: u32,
    pub cmd: u8,
    pub frg: u8,
    pub wnd: u16,
    pub ts: u32,
    pub sn: u32,
    pub una: u32,
    pub len: u32,
}

impl SegmentHeader {
    pub fn decode(data: &[u8]) -> Result<Self, KcpError> {
        if data.len() < SEGMENT_HEADER_SIZE {
            return Err(KcpError::ShortSegment(data.len()));
        }
        let u32_at = |offset: usize| {
            u32::from_le_bytes(data[offset..offset + 4].try_into().expect("4 bytes"))
        };
        Ok(Self {
            conv: u32_at(0),
            token: u32_at(4),
            cmd: data[8],
            frg: data[9],
            wnd: u16::from_le_bytes(data[10..12].try_into().expect("2 bytes")),
            ts: u32_at(12),
            sn: u32_at(16),
            una: u32_at(20),
            len: u32_at(24),
        })
    }

    pub fn encode(&self) -> [u8; SEGMENT_HEADER_SIZE] {
        let mut out = [0u8; SEGMENT_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.conv.to_le_bytes());
        out[4..8].copy_from_slice(&self.token.to_le_bytes());
        out[8] = self.cmd;
        out[9] = self.frg;
        out[10..12].copy_from_slice(&self.wnd.to_le_bytes());
        out[12..16].copy_from_slice(&self.ts.to_le_bytes());
        out[16..20].copy_from_slice(&self.sn.to_le_bytes());
        out[20..24].copy_from_slice(&self.una.to_le_bytes());
        out[24..28].copy_from_slice(&self.len.to_le_bytes());
        out
    }
}

/// `KCP::MessageHeader` — 12 bytes. Unlike the segment header, the numeric fields
/// here are *big*-endian (`util::reversedInteger`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MessageHeader {
    pub magic: [u8; 4],
    pub command_id: u16,
    pub head_length: u16,
    pub body_length: u32,
}

impl MessageHeader {
    pub fn decode(data: &[u8]) -> Result<Self, KcpError> {
        if data.len() < MESSAGE_HEADER_SIZE {
            return Err(KcpError::ShortMessageHeader(data.len()));
        }
        Ok(Self {
            magic: data[0..4].try_into().expect("4 bytes"),
            command_id: u16::from_be_bytes(data[4..6].try_into().expect("2 bytes")),
            head_length: u16::from_be_bytes(data[6..8].try_into().expect("2 bytes")),
            body_length: u32::from_be_bytes(data[8..12].try_into().expect("4 bytes")),
        })
    }

    pub fn encode(&self) -> [u8; MESSAGE_HEADER_SIZE] {
        let mut out = [0u8; MESSAGE_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.magic);
        out[4..6].copy_from_slice(&self.command_id.to_be_bytes());
        out[6..8].copy_from_slice(&self.head_length.to_be_bytes());
        out[8..12].copy_from_slice(&self.body_length.to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    sn: u32,
    frg: u8,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct Stream {
    rcv_buf: BTreeMap<u32, Segment>,
    rcv_queue: VecDeque<Segment>,
    rcv_nxt: u32,
    rcv_nxt_known: bool,
    conv: u32,
    conv_known: bool,
    last_progress_sec: i64,
}

/// Counters for the flows that used to produce diagnostic log lines. The library
/// does not print; the caller decides what to do with these.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KcpStats {
    /// The game reconnected and the stream was reset.
    pub conv_resets: u64,
    /// More than [`MAX_RCV_BUF`] segments were buffered and the stream skipped ahead.
    pub backlog_overflows: u64,
    /// A gap went unfilled past [`MAX_GAP_SECONDS`] and the stream skipped ahead.
    pub gaps_skipped: u64,
}

/// `KCP::KCP` — one reassembler per direction.
#[derive(Debug, Default)]
pub struct Kcp {
    incoming: Stream,
    outgoing: Stream,
    stats: KcpStats,
}

impl Kcp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &KcpStats {
        &self.stats
    }

    /// `KCP::KCP::receive` — feed one UDP payload, get back the complete messages
    /// it carried (usually zero or one).
    pub fn receive(
        &mut self,
        data: &[u8],
        direction: Direction,
        unix_seconds: i64,
    ) -> Vec<Vec<u8>> {
        let (stream, stats) = match direction {
            Direction::Incoming => (&mut self.incoming, &mut self.stats),
            Direction::Outgoing => (&mut self.outgoing, &mut self.stats),
        };

        let mut offset = 0usize;
        while data.len().saturating_sub(offset) >= SEGMENT_HEADER_SIZE {
            let header = SegmentHeader::decode(&data[offset..]).expect("length was checked");

            let remaining = data.len() - offset - SEGMENT_HEADER_SIZE;
            let payload_len = (header.len as usize).min(remaining);
            // A segment whose payload runs past the end of the datagram is
            // truncated by the capture; stop rather than resync on garbage.
            if header.len as usize > remaining {
                break;
            }

            if header.cmd == CMD_PUSH && header.len > 0 {
                if stream.conv_known && stream.conv != header.conv {
                    // New connection: everything buffered belongs to the old one.
                    stream.rcv_buf.clear();
                    stream.rcv_queue.clear();
                    stream.rcv_nxt_known = false;
                    stream.conv = header.conv;
                    stats.conv_resets += 1;
                }
                if !stream.conv_known {
                    stream.conv = header.conv;
                    stream.conv_known = true;
                }

                let payload = data
                    [offset + SEGMENT_HEADER_SIZE..offset + SEGMENT_HEADER_SIZE + payload_len]
                    .to_vec();

                if !stream.rcv_nxt_known {
                    stream.rcv_nxt = header.sn;
                    stream.rcv_nxt_known = true;
                    stream.last_progress_sec = unix_seconds;
                }

                // Segments older than the next expected one are duplicates of
                // something we already delivered; the C++ version drops them.
                let diff = header.sn.wrapping_sub(stream.rcv_nxt) as i32;
                if diff >= 0 && !stream.rcv_buf.contains_key(&header.sn) {
                    stream.rcv_buf.insert(
                        header.sn,
                        Segment {
                            sn: header.sn,
                            frg: header.frg,
                            data: payload,
                        },
                    );
                }

                promote(stream, unix_seconds);

                if stream.rcv_buf.len() > MAX_RCV_BUF {
                    stats.backlog_overflows += 1;
                    let lowest = *stream.rcv_buf.keys().next().expect("non-empty");
                    stream.rcv_nxt = lowest;
                    promote(stream, unix_seconds);
                }

                if !stream.rcv_buf.is_empty()
                    && unix_seconds - stream.last_progress_sec > MAX_GAP_SECONDS
                {
                    stats.gaps_skipped += 1;
                    let lowest = *stream.rcv_buf.keys().next().expect("non-empty");
                    stream.rcv_nxt = lowest;
                    promote(stream, unix_seconds);
                }
            }

            offset += SEGMENT_HEADER_SIZE + payload_len;
        }

        // Drain whole messages off the front of the queue. `frg` counts down
        // within a message, so the fragment that arrived first carries the
        // highest number.
        let mut messages = Vec::new();
        while !stream.rcv_queue.is_empty() {
            let expected_count = stream.rcv_queue.front().expect("non-empty").frg as u32 + 1;
            if stream.rcv_queue.len() < expected_count as usize {
                break;
            }

            let complete = (0..expected_count)
                .all(|i| stream.rcv_queue[i as usize].frg == (expected_count - 1 - i) as u8);

            if !complete {
                stream.rcv_queue.pop_front();
                continue;
            }

            let mut payload = Vec::new();
            for _ in 0..expected_count {
                let segment = stream.rcv_queue.pop_front().expect("checked above");
                payload.extend_from_slice(&segment.data);
            }
            messages.push(payload);
        }

        messages
    }
}

/// Move every segment the buffer holds contiguously onto the output queue.
fn promote(stream: &mut Stream, unix_seconds: i64) {
    while let Some(segment) = stream.rcv_buf.remove(&stream.rcv_nxt) {
        stream.rcv_queue.push_back(segment);
        stream.rcv_nxt = stream.rcv_nxt.wrapping_add(1);
        stream.last_progress_sec = unix_seconds;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONV: u32 = 0x1234_5678;

    fn segment(frg: u8, sn: u32, payload: &[u8]) -> Vec<u8> {
        segment_with(CMD_PUSH, frg, sn, payload)
    }

    fn segment_with(cmd: u8, frg: u8, sn: u32, payload: &[u8]) -> Vec<u8> {
        let header = SegmentHeader {
            conv: CONV,
            token: 0,
            cmd,
            frg,
            wnd: 128,
            ts: 0,
            sn,
            una: 0,
            len: payload.len() as u32,
        };
        let mut out = header.encode().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn headers_round_trip_with_the_expected_endianness() {
        let header = SegmentHeader {
            conv: 0x1122_3344,
            token: 0x5566_7788,
            cmd: CMD_PUSH,
            frg: 2,
            wnd: 0x99AA,
            ts: 0xBBCC_DDEE,
            sn: 0x0102_0304,
            una: 0x0506_0708,
            len: 0x090A_0B0C,
        };
        let bytes = header.encode();
        // conv is little-endian on the wire.
        assert_eq!(&bytes[0..4], &[0x44, 0x33, 0x22, 0x11]);
        assert_eq!(SegmentHeader::decode(&bytes).unwrap(), header);
        assert!(matches!(
            SegmentHeader::decode(&bytes[..27]),
            Err(KcpError::ShortSegment(27))
        ));

        let message = MessageHeader {
            magic: [0x4D, 0x54, 0x50, 0x00],
            command_id: 1175,
            head_length: 0,
            body_length: 0x0000_1234,
        };
        let bytes = message.encode();
        // command id is big-endian here.
        assert_eq!(&bytes[4..6], &[0x04, 0x97]);
        assert_eq!(MessageHeader::decode(&bytes).unwrap(), message);
        assert!(matches!(
            MessageHeader::decode(&bytes[..11]),
            Err(KcpError::ShortMessageHeader(11))
        ));
    }

    #[test]
    fn reassembles_a_single_segment_message() {
        let mut kcp = Kcp::new();
        let messages = kcp.receive(&segment(0, 0, b"hello"), Direction::Outgoing, 1000);
        assert_eq!(messages, vec![b"hello".to_vec()]);
        assert_eq!(kcp.stats(), &KcpStats::default());
    }

    #[test]
    fn reassembles_a_two_fragment_message_in_arrival_order() {
        let mut kcp = Kcp::new();
        // First fragment carries the higher frg, exactly as the game sends it.
        assert!(kcp
            .receive(&segment(1, 0, b"part-"), Direction::Outgoing, 1000)
            .is_empty());
        let messages = kcp.receive(&segment(0, 1, b"two"), Direction::Outgoing, 1000);
        assert_eq!(messages, vec![b"part-two".to_vec()]);
    }

    #[test]
    fn holds_out_of_order_segments_until_the_gap_is_filled() {
        let mut kcp = Kcp::new();
        assert_eq!(
            kcp.receive(&segment(0, 0, b"a"), Direction::Outgoing, 1000),
            vec![b"a".to_vec()]
        );
        // sn=2 arrives before sn=1: buffered, nothing emitted yet.
        assert!(kcp
            .receive(&segment(0, 2, b"c"), Direction::Outgoing, 1000)
            .is_empty());
        // sn=1 closes the gap; both are released in order.
        let messages = kcp.receive(&segment(0, 1, b"b"), Direction::Outgoing, 1000);
        assert_eq!(messages, vec![b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(kcp.stats(), &KcpStats::default());
    }

    #[test]
    fn skips_a_gap_that_never_fills() {
        let mut kcp = Kcp::new();
        assert_eq!(
            kcp.receive(&segment(0, 0, b"a"), Direction::Outgoing, 1000),
            vec![b"a".to_vec()]
        );
        // One second later sn=1 is still missing; not yet given up on.
        assert!(kcp
            .receive(&segment(0, 2, b"c"), Direction::Outgoing, 1001)
            .is_empty());
        // Four seconds in, the gap is abandoned and the stream jumps to sn=2.
        let messages = kcp.receive(&segment(0, 3, b"d"), Direction::Outgoing, 1004);
        assert_eq!(messages, vec![b"c".to_vec(), b"d".to_vec()]);
        assert_eq!(kcp.stats().gaps_skipped, 1);
        assert_eq!(kcp.stats().backlog_overflows, 0);
    }

    #[test]
    fn drops_segments_older_than_the_next_expected_one() {
        let mut kcp = Kcp::new();
        assert_eq!(
            kcp.receive(&segment(0, 5, b"six"), Direction::Outgoing, 1000),
            vec![b"six".to_vec()]
        );
        // sn=5 was promoted, so rcv_nxt is 6 and anything lower is a duplicate.
        assert!(kcp
            .receive(&segment(0, 2, b"three"), Direction::Outgoing, 1000)
            .is_empty());
    }

    #[test]
    fn a_new_conv_resets_both_directions_independently() {
        let mut kcp = Kcp::new();
        assert_eq!(
            kcp.receive(&segment(0, 10, b"old"), Direction::Outgoing, 1000),
            vec![b"old".to_vec()]
        );

        // Same sn on a different conv would be dropped without the reset.
        let mut new_conv = segment(0, 10, b"new");
        new_conv[0..4].copy_from_slice(&0x8765_4321u32.to_le_bytes());
        assert_eq!(
            kcp.receive(&new_conv, Direction::Outgoing, 1001),
            vec![b"new".to_vec()]
        );
        assert_eq!(kcp.stats().conv_resets, 1);

        // The incoming stream is untouched and still tracks its own conv.
        assert_eq!(
            kcp.receive(&segment(0, 0, b"in"), Direction::Incoming, 1001),
            vec![b"in".to_vec()]
        );
        assert_eq!(kcp.stats().conv_resets, 1);
    }

    #[test]
    fn non_push_commands_carry_no_payload() {
        let mut kcp = Kcp::new();
        assert!(kcp
            .receive(
                &segment_with(CMD_ACK, 0, 0, b"ignored"),
                Direction::Outgoing,
                1000
            )
            .is_empty());
        // An ACK with a len of 0 still advances the cursor correctly.
        assert_eq!(
            kcp.receive(
                &segment_with(CMD_WASK, 0, 1, b""),
                Direction::Outgoing,
                1000
            )
            .len(),
            0
        );
        assert_eq!(
            kcp.receive(&segment(0, 0, b"real"), Direction::Outgoing, 1000),
            vec![b"real".to_vec()]
        );
    }

    #[test]
    fn multiple_segments_in_one_datagram_are_all_read() {
        let mut kcp = Kcp::new();
        let mut datagram = segment(0, 0, b"one");
        datagram.extend_from_slice(&segment(0, 1, b"two"));
        assert_eq!(
            kcp.receive(&datagram, Direction::Outgoing, 1000),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
    }

    #[test]
    fn a_truncated_trailing_segment_is_ignored() {
        let mut kcp = Kcp::new();
        let mut datagram = segment(0, 0, b"complete");
        datagram.extend_from_slice(&segment(0, 1, b"truncated")[..10]);
        let messages = kcp.receive(&datagram, Direction::Outgoing, 1000);
        assert_eq!(messages, vec![b"complete".to_vec()]);

        // Declared length longer than the datagram: stop without emitting.
        let mut short = segment(0, 0, b"abcdef");
        short[24..28].copy_from_slice(&100u32.to_le_bytes());
        assert!(Kcp::new()
            .receive(&short, Direction::Outgoing, 1000)
            .is_empty());
    }

    #[test]
    fn the_backlog_cap_forces_the_stream_forward() {
        let mut kcp = Kcp::new();
        assert_eq!(
            kcp.receive(&segment(0, 0, b"first"), Direction::Outgoing, 1000),
            vec![b"first".to_vec()]
        );
        // sn=1 is missing forever; buffer sn=2..=514, one over the 512 cap.
        let mut emitted = 0;
        for sn in 2..=514u32 {
            emitted += kcp
                .receive(&segment(0, sn, b"x"), Direction::Outgoing, 1000)
                .len();
        }
        assert_eq!(kcp.stats().backlog_overflows, 1);
        // Everything buffered was contiguous, so it all drains at once.
        assert_eq!(emitted, 513);
    }
}
