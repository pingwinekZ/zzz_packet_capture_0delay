//! The WebSocket frame codec: RFC 6455 sections 5.2 and 5.5, and only the parts
//! this server uses.
//!
//! Ported from the frame handling inside `Server::readLoop`, `senderLoop` and
//! `encodeTextFrame`. The reference is minimal on purpose — text frames outbound,
//! close and ping understood inbound, everything else ignored — and the details
//! it does not do are worth naming, because they are deliberate here too:
//!
//! * No fragmentation: the FIN bit is never set and never checked, continuation
//!   frames are ignored, and an outbound payload is always one frame.
//! * No `RSV` handling and no permessage-deflate.
//! * Inbound frames from the client are expected to be masked and are unmasked;
//!   an unmasked one is tolerated rather than rejected with a protocol error.
//! * Server frames are never masked, as the RFC requires.
//!
//! ## Idle sockets
//!
//! The reference reads with asio, where a read completes when data arrives, when
//! the peer closes, or when the operation is cancelled. A blocking `recv` has no
//! third case: on Windows, `shutdown` does not interrupt a `recv` that is already
//! blocked, so a reader thread parked on a quiet client can never be told to
//! stop. The socket therefore carries a read timeout, and [`FrameRead::Idle`]
//! reports a wait that expired without consuming anything, letting the caller
//! check its own stop flag and try again.
//!
//! The one behaviour this changes: a peer that stops *in the middle* of a frame
//! for longer than that timeout is dropped as stalled, where the reference would
//! wait indefinitely. A frame is written by a single `send` in every client that
//! matters here, so the gap cannot open between a frame's own bytes unless the
//! peer has stopped for good.

use std::fmt;
use std::io::{self, Read};

/// The largest inbound payload, checked before allocating.
///
/// The reference refuses anything above this and closes the connection. It is a
/// sanity bound rather than a protocol limit: the largest frame the game's
/// export produces is a few hundred kilobytes.
pub const MAX_INBOUND_PAYLOAD: u64 = 64 * 1024 * 1024;

/// Frame opcodes, by the low nibble of the first byte.
pub mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// What one call to [`read_frame`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameRead {
    Frame(Frame),
    /// The read timed out before a single byte of a frame arrived: the socket is
    /// idle and nothing was consumed, so the caller may look at its stop flag and
    /// read again. Only a reader whose socket has a read timeout set produces
    /// this.
    Idle,
    /// The peer closed the connection at a frame boundary.
    Ended,
}

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    /// A 64-bit length with its most significant bit set, which RFC 6455 section
    /// 5.2 forbids. The reference closes the connection.
    LengthHasMsbSet,
    /// A payload above [`MAX_INBOUND_PAYLOAD`].
    PayloadTooLarge(u64),
}

/// Whether an error is a socket timeout rather than a failure.
///
/// Both kinds have to be recognised: a read timeout is `WouldBlock` on unix and
/// `TimedOut` on Windows.
pub fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::LengthHasMsbSet => write!(f, "frame length has its high bit set"),
            Self::PayloadTooLarge(length) => {
                write!(f, "frame payload of {length} bytes is too large")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Encodes one unmasked server frame, choosing the shortest length form.
pub fn encode(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    let length = payload.len();
    if length < 126 {
        frame.push(length as u8);
    } else if length <= 0xFFFF {
        frame.push(126);
        frame.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(length as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

/// A text frame, the only kind this server sends.
pub fn encode_text(payload: &str) -> Vec<u8> {
    encode(opcode::TEXT, payload.as_bytes())
}

/// A pong frame echoing the ping's payload, as the reference does.
pub fn encode_pong(payload: &[u8]) -> Vec<u8> {
    encode(opcode::PONG, payload)
}

/// The reply to a client's close: an empty close frame, `{0x88, 0x00}`.
///
/// The reference writes exactly these two bytes rather than echoing the client's
/// status code, and this is byte-for-byte the same.
pub fn encode_close() -> [u8; 2] {
    [0x88, 0x00]
}

/// Reads one frame from `reader`.
///
/// [`FrameRead::Ended`] means the connection ended cleanly before a header — the
/// client simply went away. [`FrameRead::Idle`] means the socket timed out with
/// nothing consumed. Any other problem is an error, and the caller closes the
/// connection.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<FrameRead, FrameError> {
    let mut head = [0u8; 2];
    match read_full(reader, &mut head)? {
        Chunk::Filled => {}
        Chunk::Ended => return Ok(FrameRead::Ended),
        Chunk::Idle => return Ok(FrameRead::Idle),
    }

    let opcode = head[0] & 0x0F;
    let masked = head[1] & 0x80 != 0;
    let length = match head[1] & 0x7F {
        126 => {
            let mut extended = [0u8; 2];
            // Past the header the frame is in flight: a socket that falls silent
            // here has stalled rather than gone idle.
            read_full(reader, &mut extended)?;
            u64::from(u16::from_be_bytes(extended))
        }
        127 => {
            let mut extended = [0u8; 8];
            read_full(reader, &mut extended)?;
            if extended[0] & 0x80 != 0 {
                return Err(FrameError::LengthHasMsbSet);
            }
            u64::from_be_bytes(extended)
        }
        code => u64::from(code),
    };
    // Checked before the mask key is read and before anything is allocated, so a
    // hostile length cannot make the server ask for memory. The reference checks
    // it at the same point.
    if length > MAX_INBOUND_PAYLOAD {
        return Err(FrameError::PayloadTooLarge(length));
    }

    let mask = if masked {
        let mut mask = [0u8; 4];
        read_full(reader, &mut mask)?;
        Some(mask)
    } else {
        None
    };

    let mut payload = vec![0u8; length as usize];
    read_full(reader, &mut payload)?;
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    Ok(FrameRead::Frame(Frame { opcode, payload }))
}

fn eof() -> FrameError {
    FrameError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "connection closed mid-frame",
    ))
}

fn stalled() -> FrameError {
    FrameError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "the peer stalled mid-frame",
    ))
}

/// The outcome of trying to fill a buffer.
enum Chunk {
    Filled,
    /// The connection ended, with nothing read.
    Ended,
    /// The socket timed out, with nothing read.
    Idle,
}

/// Fills `buffer`. A partial fill is an error, because a half-read frame cannot
/// be interpreted — whether it was cut short by a close or by a stall.
fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<Chunk, FrameError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => {
                return if filled == 0 {
                    Ok(Chunk::Ended)
                } else {
                    Err(eof())
                }
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if is_timeout(&error) => {
                return if filled == 0 {
                    Ok(Chunk::Idle)
                } else {
                    Err(stalled())
                }
            }
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    Ok(Chunk::Filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client frame: masked, as a client must send it.
    fn client_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0x80 | opcode];
        let length = payload.len();
        if length < 126 {
            frame.push(0x80 | length as u8);
        } else if length <= 0xFFFF {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        frame
    }

    #[test]
    fn encodes_every_length_form() {
        // 7-bit, 16-bit and 64-bit lengths, with the boundary values.
        assert_eq!(encode_text("hi"), vec![0x81, 2, b'h', b'i']);
        assert_eq!(encode_text(""), vec![0x81, 0]);

        let short = "x".repeat(125);
        assert_eq!(encode_text(&short)[..2], [0x81, 125]);

        let medium = "x".repeat(126);
        let encoded = encode_text(&medium);
        assert_eq!(encoded[..4], [0x81, 126, 0x00, 126]);

        let long = "x".repeat(0x10000);
        let encoded = encode_text(&long);
        assert_eq!(&encoded[..2], [0x81, 127]);
        assert_eq!(
            &encoded[2..10],
            &(0x10000u64).to_be_bytes(),
            "64-bit big-endian length"
        );
        assert_eq!(encoded.len(), long.len() + 10);

        // Exactly 65535 still fits in the 16-bit form.
        let boundary = "x".repeat(0xFFFF);
        assert_eq!(encode_text(&boundary)[1], 126);
    }

    #[test]
    fn closes_with_the_reference_bytes() {
        // The reference writes `{0x88, 0x00}`; it does not echo the peer's code.
        assert_eq!(encode_close(), [0x88, 0x00]);
    }

    /// The frame a read produced, or a panic naming what it produced instead.
    fn frame_of(outcome: Result<FrameRead, FrameError>) -> Frame {
        match outcome {
            Ok(FrameRead::Frame(frame)) => frame,
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    #[test]
    fn reads_masked_frames_of_every_length_and_unmasks_them() {
        let mask = [0x12, 0x34, 0x56, 0x78];
        for length in [0usize, 1, 125, 126, 700, 0xFFFF] {
            let payload: Vec<u8> = (0..length).map(|index| (index % 256) as u8).collect();
            let wire = client_frame(opcode::TEXT, &payload, mask);
            let frame = frame_of(read_frame(&mut wire.as_slice()));
            assert_eq!(frame.opcode, opcode::TEXT);
            assert_eq!(frame.payload, payload, "length {length}");
        }
    }

    #[test]
    fn reads_an_unmasked_frame_too() {
        // RFC 6455 requires clients to mask; the reference tolerates a client
        // that does not, and so does this.
        let wire = encode_text("plain");
        let frame = frame_of(read_frame(&mut wire.as_slice()));
        assert_eq!(frame.opcode, opcode::TEXT);
        assert_eq!(frame.payload, b"plain");
    }

    #[test]
    fn reads_one_frame_at_a_time_from_a_stream() {
        // Two frames back to back, which is what a client that pipelines them
        // looks like — and the reason the handshake reader must not swallow the
        // rest of its buffer.
        let mask = [1, 2, 3, 4];
        let mut wire = client_frame(opcode::PING, b"p", mask);
        wire.extend(client_frame(opcode::CLOSE, b"", mask));
        let mut reader = wire.as_slice();

        let first = frame_of(read_frame(&mut reader));
        assert_eq!(
            (first.opcode, first.payload.as_slice()),
            (opcode::PING, b"p".as_slice())
        );
        assert_eq!(frame_of(read_frame(&mut reader)).opcode, opcode::CLOSE);
        assert_eq!(
            read_frame(&mut reader).unwrap(),
            FrameRead::Ended,
            "then the stream ends"
        );
    }

    #[test]
    fn reports_a_clean_end_separately_from_a_truncated_frame() {
        // Nothing at all: the client went away.
        assert_eq!(read_frame(&mut [].as_slice()).unwrap(), FrameRead::Ended);
        // A header promising more than is there: that is an error, not an end.
        let wire = [0x81u8, 4, b'a'];
        assert!(matches!(
            read_frame(&mut wire.as_slice()),
            Err(FrameError::Io(_))
        ));
        // Half a header.
        let wire = [0x81u8];
        assert!(matches!(
            read_frame(&mut wire.as_slice()),
            Err(FrameError::Io(_))
        ));
    }

    /// A socket that never has anything to give: every read times out.
    struct Idle;

    impl Read for Idle {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "nothing yet"))
        }
    }

    /// A socket that hands over `data`, then goes quiet.
    struct Stalls {
        data: Vec<u8>,
        at: usize,
    }

    impl Read for Stalls {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.at >= self.data.len() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "stalled"));
            }
            let take = (self.data.len() - self.at).min(buffer.len());
            buffer[..take].copy_from_slice(&self.data[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    #[test]
    fn reports_an_idle_socket_separately_from_a_closed_one() {
        // This distinction is what lets the server notice a stop request while it
        // is parked waiting for a quiet client: see the module docs.
        assert_eq!(read_frame(&mut Idle).unwrap(), FrameRead::Idle);
        // `TimedOut` is the Windows spelling of the same thing, and a reader that
        // is idle *after* a frame has started is a stall, not an idle socket.
        assert_eq!(
            read_frame(&mut Stalls {
                data: Vec::new(),
                at: 0
            })
            .unwrap(),
            FrameRead::Idle
        );
        let outcome = read_frame(&mut Stalls {
            data: vec![0x81],
            at: 0,
        });
        assert!(
            matches!(&outcome, Err(FrameError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "half a header then silence is a stalled connection, got {outcome:?}"
        );
    }

    #[test]
    fn an_idle_timeout_is_not_a_failure() {
        assert!(is_timeout(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(is_timeout(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(!is_timeout(&io::Error::from(io::ErrorKind::Interrupted)));
        assert!(!is_timeout(&io::Error::from(io::ErrorKind::BrokenPipe)));
    }

    #[test]
    fn rejects_the_lengths_the_reference_rejects() {
        // A 64-bit length with the high bit set.
        let mut wire = vec![0x82, 127];
        wire.extend_from_slice(&0x8000_0000_0000_0001u64.to_be_bytes());
        assert!(matches!(
            read_frame(&mut wire.as_slice()),
            Err(FrameError::LengthHasMsbSet)
        ));

        // Above the 64 MiB cap. The length is refused before the payload is
        // allocated, so this costs nothing to test.
        let mut wire = vec![0x82, 127];
        wire.extend_from_slice(&(MAX_INBOUND_PAYLOAD + 1).to_be_bytes());
        assert!(matches!(
            read_frame(&mut wire.as_slice()),
            Err(FrameError::PayloadTooLarge(length)) if length == MAX_INBOUND_PAYLOAD + 1
        ));
    }
}
