//! Port of `src/crypto/ec2b.hpp` — the `Ec2b` stream scrambler used to turn the
//! dispatch gateway's `client_secret_key` blob into the per-region XOR seed.
//!
//! Endianness is a trap in the original: the magic is compared big-endian while
//! the two length fields are read little-endian (`util::reversedInteger` vs
//! `util::to`). Both are preserved here explicitly.

use std::fmt;

use crate::b64::b64_decode;
use crate::ec2b_tables::{
    G11, G13, G14, G9, KEY_XOR_PAD_TABLE, ROUND_KEYS, SBOX_INV, SHIFT_ROWS_INV,
};

pub const MAGIC: u32 = 0x45633262; // "Ec2b"
pub const KEY_SIZE: usize = 16;
pub const SEED_SIZE: usize = 2048;
pub const FINAL_XOR: u64 = 0xCEAC_3B5A_8678_37AC;
/// Smallest well-formed header: magic + key size + 16-byte key + payload size.
const MIN_LEN: usize = 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ec2bError {
    TooShort(usize),
    BadMagic(u32),
    BadKeySize(u32),
    BadPayloadSize(u32),
    PayloadOutOfBounds,
}

impl fmt::Display for Ec2bError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(len) => write!(f, "Ec2b: too short ({len} bytes)"),
            Self::BadMagic(m) => write!(f, "Ec2b: bad magic {m:#010X}"),
            Self::BadKeySize(s) => write!(f, "Ec2b: bad key size {s}"),
            Self::BadPayloadSize(s) => write!(f, "Ec2b: bad payload size {s}"),
            Self::PayloadOutOfBounds => write!(f, "Ec2b: payload out of bounds"),
        }
    }
}

impl std::error::Error for Ec2bError {}

/// `crypto::ec2b::unscramble_aes_key`: the inverse AES cipher applied to the
/// scrambled key, with the rounds wired around the baked-in `roundKeys`.
pub fn unscramble_aes_key(key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let mut chip = *key;

    for i in 0..16 {
        chip[i] ^= ROUND_KEYS[i];
    }

    for rnd in 1..10 {
        for byte in chip.iter_mut() {
            *byte = SBOX_INV[*byte as usize];
        }
        let temp = chip;
        for i in 0..16 {
            chip[i] = temp[SHIFT_ROWS_INV[i] as usize];
        }
        for col in (0..16).step_by(4) {
            let a0 = chip[col];
            let a1 = chip[col + 1];
            let a2 = chip[col + 2];
            let a3 = chip[col + 3];
            chip[col] = G14[a0 as usize] ^ G9[a3 as usize] ^ G13[a2 as usize] ^ G11[a1 as usize];
            chip[col + 1] =
                G14[a1 as usize] ^ G9[a0 as usize] ^ G13[a3 as usize] ^ G11[a2 as usize];
            chip[col + 2] =
                G14[a2 as usize] ^ G9[a1 as usize] ^ G13[a0 as usize] ^ G11[a3 as usize];
            chip[col + 3] =
                G14[a3 as usize] ^ G9[a2 as usize] ^ G13[a1 as usize] ^ G11[a0 as usize];
        }
        for i in 0..16 {
            chip[i] ^= ROUND_KEYS[rnd * 16 + i];
        }
    }

    for byte in chip.iter_mut() {
        *byte = SBOX_INV[*byte as usize];
    }
    {
        let temp = chip;
        for i in 0..16 {
            chip[i] = temp[SHIFT_ROWS_INV[i] as usize];
        }
    }
    for i in 0..16 {
        chip[i] ^= ROUND_KEYS[160 + i];
    }

    chip
}

/// `crypto::ec2b::Parsed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub key: [u8; KEY_SIZE],
    pub seed: [u8; SEED_SIZE],
}

/// `crypto::ec2b::parse`.
pub fn parse(data: &[u8]) -> Result<Parsed, Ec2bError> {
    if data.len() < MIN_LEN {
        return Err(Ec2bError::TooShort(data.len()));
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != MAGIC {
        return Err(Ec2bError::BadMagic(magic));
    }

    let key_sz = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if key_sz != KEY_SIZE as u32 {
        return Err(Ec2bError::BadKeySize(key_sz));
    }

    let payload_sz_off = 8 + KEY_SIZE;
    if payload_sz_off + 4 > data.len() {
        return Err(Ec2bError::TooShort(data.len()));
    }
    let payload_sz = u32::from_le_bytes([
        data[payload_sz_off],
        data[payload_sz_off + 1],
        data[payload_sz_off + 2],
        data[payload_sz_off + 3],
    ]);
    if payload_sz != SEED_SIZE as u32 {
        return Err(Ec2bError::BadPayloadSize(payload_sz));
    }

    let data_off = payload_sz_off + 4;
    let payload_end = data_off + payload_sz as usize;
    if payload_end > data.len() {
        return Err(Ec2bError::PayloadOutOfBounds);
    }

    let mut scrambled_key = [0u8; KEY_SIZE];
    scrambled_key.copy_from_slice(&data[8..8 + KEY_SIZE]);

    let mut seed = [0u8; SEED_SIZE];
    seed.copy_from_slice(&data[data_off..payload_end]);

    let mut key = unscramble_aes_key(&scrambled_key);
    for i in 0..16 {
        key[i] ^= KEY_XOR_PAD_TABLE[i];
    }

    Ok(Parsed { key, seed })
}

/// `crypto::ec2b::scramble` — XOR of every 64-bit word, both key halves and the
/// final constant.
pub fn scramble(parsed: &Parsed) -> u64 {
    let mut val = u64::MAX;
    for i in (0..SEED_SIZE).step_by(8) {
        let word: [u8; 8] = parsed.seed[i..i + 8].try_into().expect("8-byte window");
        val ^= u64::from_le_bytes(word);
    }
    let k0 = u64::from_le_bytes(parsed.key[0..8].try_into().expect("8-byte window"));
    let k1 = u64::from_le_bytes(parsed.key[8..16].try_into().expect("8-byte window"));
    val ^ k0 ^ k1 ^ FINAL_XOR
}

/// `crypto::ec2b::derive_seed` over the raw base64-decoded blob.
pub fn derive_seed(ec2b_data: &[u8]) -> Result<u64, Ec2bError> {
    Ok(scramble(&parse(ec2b_data)?))
}

/// Convenience: the dispatch gateway hands us the blob base64-encoded.
pub fn derive_seed_from_b64(client_secret_key: &str) -> Result<u64, Ec2bError> {
    derive_seed(&b64_decode(client_secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_blob(key: &[u8; 16], seed_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN_LEN + SEED_SIZE);
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.extend_from_slice(&(KEY_SIZE as u32).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&(SEED_SIZE as u32).to_le_bytes());
        out.extend(std::iter::repeat(seed_byte).take(SEED_SIZE));
        out
    }

    #[test]
    fn tables_match_the_values_the_cpp_header_ships() {
        // Spot checks against src/crypto/ec2b_tables.hpp.
        // The standard AES inverse S-box: S[0x00] = 0x63, so InvS[0x63] = 0x00.
        assert_eq!(SBOX_INV[0x00], 0x52);
        assert_eq!(SBOX_INV[0x63], 0x00);
        assert_eq!(SBOX_INV[0x50], 0x6C);
        assert_eq!(G9[1], 0x09);
        assert_eq!(G14[1], 0x0E);
        assert_eq!(SHIFT_ROWS_INV[1], 0x0D);
        assert_eq!(KEY_XOR_PAD_TABLE[0], 0xA2);
        assert_eq!(ROUND_KEYS[0], 0x3C);
        assert_eq!(ROUND_KEYS[175], 0x14);
    }

    #[test]
    fn parses_a_well_formed_blob() {
        let blob = synthetic_blob(&[0x11; 16], 0x00);
        let parsed = parse(&blob).unwrap();
        assert_eq!(parsed.seed, [0u8; SEED_SIZE]);
        // key = unscramble(scrambled) ^ pad, so it is reproducible and stable.
        assert_eq!(parsed.key, parse(&blob).unwrap().key);
    }

    #[test]
    fn rejects_malformed_blobs() {
        assert!(matches!(parse(&[0u8; 4]), Err(Ec2bError::TooShort(4))));

        let mut blob = synthetic_blob(&[0u8; 16], 0);
        blob[0] = 0x00;
        assert!(matches!(parse(&blob), Err(Ec2bError::BadMagic(_))));

        let mut blob = synthetic_blob(&[0u8; 16], 0);
        blob[4] = 15;
        assert!(matches!(parse(&blob), Err(Ec2bError::BadKeySize(15))));

        // The payload size is a little-endian u32 at offset 24: 2048 is
        // [0x00, 0x08, 0x00, 0x00], so zeroing byte 25 zeroes the field.
        let mut blob = synthetic_blob(&[0u8; 16], 0);
        blob[25] = 0;
        assert!(matches!(parse(&blob), Err(Ec2bError::BadPayloadSize(0))));

        let blob = synthetic_blob(&[0u8; 16], 0);
        assert!(matches!(
            parse(&blob[..blob.len() - 1]),
            Err(Ec2bError::PayloadOutOfBounds)
        ));
    }

    #[test]
    fn scramble_is_the_documented_xor_chain() {
        let parsed = Parsed {
            key: [
                1, 0, 0, 0, 0, 0, 0, 0, // k0 = 1
                2, 0, 0, 0, 0, 0, 0, 0, // k1 = 2
            ],
            seed: [0u8; SEED_SIZE],
        };
        // 256 words of zero leave val = !0, then ^ 1 ^ 2 ^ FINAL_XOR.
        assert_eq!(scramble(&parsed), u64::MAX ^ 1 ^ 2 ^ FINAL_XOR);

        let mut parsed = parsed;
        parsed.seed[0] = 0x0F;
        assert_eq!(
            scramble(&parsed),
            u64::MAX ^ 0x0F ^ 1 ^ 2 ^ FINAL_XOR,
            "seed words are read little-endian"
        );
    }

    /// Regression test for the real dispatch blobs.
    ///
    /// Drop the base64 `client_secret_key` from a `query_gateway` response into
    /// `rust/testdata/dispatch/<Region>.b64` (using `_` for characters that are
    /// not valid in a filename) and this derives the seed for every region and
    /// compares it with the committed `assets/datamine.json`. It runs as a no-op
    /// until at least one fixture exists.
    #[test]
    fn derives_the_regions_seeds_from_recorded_dispatch_blobs() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/dispatch");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };

        let datamine: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../assets/datamine.json"),
            )
            .expect("assets/datamine.json"),
        )
        .expect("datamine.json is valid JSON");

        // Region names in datamine.json ("TW,HK,MO") are not valid filenames, so
        // match on a normalised form instead.
        let normalise = |s: &str| -> String {
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_lowercase())
                .collect()
        };
        let seeds = datamine["xorSeeds"].as_object().expect("xorSeeds object");

        let mut checked = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("b64") {
                continue;
            }
            let stem = normalise(&path.file_stem().unwrap().to_string_lossy());
            let (region, expected) = seeds
                .iter()
                .find(|(region, _)| normalise(region) == stem)
                .map(|(region, seed)| (region.as_str(), seed.as_str().unwrap()))
                .unwrap_or_else(|| panic!("no xorSeeds entry for fixture file {path:?}"));

            let blob = std::fs::read_to_string(&path).expect("fixture is readable");
            let seed = derive_seed_from_b64(blob.trim()).expect("fixture blob parses");
            assert_eq!(
                format!("{seed:016X}"),
                expected.to_uppercase(),
                "seed mismatch for {region}"
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "fixture directory existed but held no .b64 files"
        );
    }
}
