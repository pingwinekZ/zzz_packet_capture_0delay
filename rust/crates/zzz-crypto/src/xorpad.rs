//! Port of `src/crypto/xorpad.hpp`.
//!
//! Two pads are used. The *region* pad is derived from the per-region seed in
//! `datamine.json` and XORed over every message body before the handshake
//! completes; the *session* pad is derived from `session_key` afterwards. The
//! only difference between them is the byte order of each MT19937-64 word, which
//! is why the C++ `generate` takes a `bigEndian` flag.

use crate::mt19937::Mt19937_64;

/// `crypto::xorpad::size`.
pub const PAD_SIZE: usize = 4096;

/// `crypto::xorpad::generate`. `big_endian` reverses each 64-bit word's bytes.
pub fn generate(seed: u64, big_endian: bool) -> [u8; PAD_SIZE] {
    let mut mt = Mt19937_64::new(seed);
    let mut pad = [0u8; PAD_SIZE];
    for i in 0..(PAD_SIZE / 8) {
        let val = mt.next_u64();
        let bytes = if big_endian {
            val.to_be_bytes()
        } else {
            val.to_le_bytes()
        };
        pad[i * 8..i * 8 + 8].copy_from_slice(&bytes);
    }
    pad
}

/// `crypto::xorpad::initial` — the region pad, little-endian words.
pub fn region(seed: u64) -> [u8; PAD_SIZE] {
    generate(seed, false)
}

/// `crypto::xorpad::session` — the session pad, big-endian words.
pub fn session(session_key: u64) -> [u8; PAD_SIZE] {
    generate(session_key, true)
}

/// The active region pad.
///
/// The C++ code keeps this in a function-local `static` that it regenerates
/// whenever the selected region changes. Holding it in a value instead removes
/// the shared mutable state, so nothing has to reason about which region a pad
/// belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorPad {
    bytes: [u8; PAD_SIZE],
}

impl XorPad {
    pub fn for_region(seed: u64) -> Self {
        Self {
            bytes: region(seed),
        }
    }

    pub fn for_session(session_key: u64) -> Self {
        Self {
            bytes: session(session_key),
        }
    }

    pub fn bytes(&self) -> &[u8; PAD_SIZE] {
        &self.bytes
    }
}

/// `crypto::Session::decryptBody` — repeating-key XOR over the whole body.
pub fn xor_in_place(data: &mut [u8], pad: &[u8]) {
    debug_assert!(!pad.is_empty());
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= pad[i % pad.len()];
    }
}

/// Convenience wrapper allocating the output, matching how the original is used.
pub fn xor_bytes(data: &[u8], pad: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    xor_in_place(&mut out, pad);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_pads_are_byte_reversals_of_each_other() {
        // The region and session generators consume the same MT stream; only the
        // per-word byte order differs. This pins that relationship.
        let seed = 0x9543_521F_C9C8_CAED;
        let le = region(seed);
        let be = session(seed);
        for i in 0..(PAD_SIZE / 8) {
            let mut word = le[i * 8..i * 8 + 8].to_vec();
            word.reverse();
            assert_eq!(&word[..], &be[i * 8..i * 8 + 8]);
        }
    }

    #[test]
    fn pads_are_stable_for_a_given_seed() {
        let a = region(0x9543_521F_C9C8_CAED);
        let b = region(0x9543_521F_C9C8_CAED);
        assert_eq!(a, b);
        assert_ne!(a, region(0x1A7E_69FE_2F49_590A));
    }

    #[test]
    fn xor_is_its_own_inverse_and_wraps_at_the_pad_length() {
        let pad = region(42);
        let data: Vec<u8> = (0..PAD_SIZE + 100).map(|i| (i % 251) as u8).collect();
        let mut buf = data.clone();
        xor_in_place(&mut buf, &pad);
        assert_ne!(buf, data);
        // Byte PAD_SIZE must use pad[0] again.
        assert_eq!(buf[PAD_SIZE], data[PAD_SIZE] ^ pad[0]);
        xor_in_place(&mut buf, &pad);
        assert_eq!(buf, data);
    }
}
