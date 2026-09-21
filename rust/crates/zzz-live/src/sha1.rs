//! SHA-1, because the WebSocket handshake requires it.
//!
//! `Sec-WebSocket-Accept` is `base64(SHA-1(key + GUID))` — RFC 6455 fixes the
//! algorithm, so there is no choice involved and no security property being
//! relied on: the value only has to match what the client computed the same way.
//!
//! The C++ calls OpenSSL's `SHA1` and `EVP_EncodeBlock`. Rather than take a
//! dependency for one 40-line hash, this is the algorithm verbatim, checked
//! against the FIPS 180-1 test vectors and the RFC 6455 example in the tests
//! below. (Base64 is already ported in `zzz-crypto`, next to the other string
//! helpers, and is reused rather than rewritten.)

/// The initial state: the first 32 bits of the fractional parts of the square
/// roots of 2, 3, 5, 10 — i.e. `sqrt(2)`…`sqrt(10)`.
const INITIAL: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// A streaming SHA-1. `update` may be called any number of times.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    filled: usize,
    /// Total bytes fed in, for the length the padding appends.
    length: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: INITIAL,
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    /// Feed data. The length counter is not a `usize` because the padding
    /// encodes the length in *bits* as a 64-bit big-endian value.
    pub fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        self.feed(data);
    }

    /// The 20-byte digest.
    pub fn finish(mut self) -> [u8; 20] {
        let bit_length = self.length.wrapping_mul(8);

        // Pad: a single 1 bit, then zeros until the length is 56 mod 64, then
        // the 64-bit length. Feeding these through `feed` (rather than `update`)
        // keeps the length counter meaning "message bytes".
        self.feed(&[0x80]);
        while self.filled != 56 {
            self.feed(&[0]);
        }
        self.feed(&bit_length.to_be_bytes());

        let mut digest = [0u8; 20];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Absorb bytes without touching the length counter.
    fn feed(&mut self, mut data: &[u8]) {
        if self.filled > 0 {
            let want = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + want].copy_from_slice(&data[..want]);
            self.filled += want;
            data = &data[want..];
            if self.filled == 64 {
                compress(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            compress(&mut self.state, &block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.filled = data.len();
        }
    }
}

/// One-shot convenience.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finish()
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut schedule = [0u32; 80];
    for (index, word) in schedule.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[index * 4],
            block[index * 4 + 1],
            block[index * 4 + 2],
            block[index * 4 + 3],
        ]);
    }
    for index in 16..80 {
        schedule[index] = (schedule[index - 3]
            ^ schedule[index - 8]
            ^ schedule[index - 14]
            ^ schedule[index - 16])
            .rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (index, word) in schedule.iter().enumerate() {
        let (f, k) = match index {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: &[u8; 20]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn matches_the_published_vectors() {
        // FIPS 180-1 / RFC 3174.
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        // 56 bytes: the case where padding does not fit in the final block, so
        // a whole extra block is required.
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // Two blocks exactly, with no room for padding.
        assert_eq!(
            hex(&sha1(&[b'a'; 64])),
            "0098ba824b5c16427bd7a1122a5a442a25ec644d"
        );
    }

    #[test]
    fn matches_the_long_message_vector() {
        // A million 'a's, the standard multi-block check.
        let mut hasher = Sha1::new();
        for _ in 0..1000 {
            hasher.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&hasher.finish()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn streaming_in_pieces_matches_one_shot() {
        // The chunk boundaries walk across the 64-byte block edge in both
        // directions, which is where a buffer bug would show.
        let data: Vec<u8> = (0..300u32).map(|index| (index % 251) as u8).collect();
        let expected = sha1(&data);
        for chunk in [1usize, 7, 63, 64, 65, 128, 299] {
            let mut hasher = Sha1::new();
            for piece in data.chunks(chunk) {
                hasher.update(piece);
            }
            assert_eq!(hasher.finish(), expected, "chunk size {chunk}");
        }
        // And a zero-length update in the middle changes nothing.
        let mut hasher = Sha1::new();
        hasher.update(&data[..100]);
        hasher.update(&[]);
        hasher.update(&data[100..]);
        assert_eq!(hasher.finish(), expected);
    }

    #[test]
    fn computes_the_rfc_6455_accept_value() {
        // The example from RFC 6455 section 1.3, which is also the fixture the
        // C++ self-test uses.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        assert_eq!(
            zzz_crypto::b64_encode(&hasher.finish()),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
