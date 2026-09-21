//! Parity gate against the C++ implementation.
//!
//! `rust/testdata/parity/cpp_vectors.txt` is the verbatim output of
//! `tools/cpp_parity.cpp`, which is compiled against the headers under
//! `src/crypto/` — the code the game's own build uses. This test recomputes
//! every vector with the Rust port and asserts the two agree.
//!
//! That matters more than it looks. The crypto layer has no room for
//! interpretation: a mistyped entry in `ec2b_tables`, a wrong byte order in the
//! pad generator or an off-by-one in the .NET generator would not fail loudly at
//! runtime, it would silently produce a wrong pad, and the symptom would be
//! "nothing decodes" — indistinguishable from a game update having changed the
//! protocol. This is the difference between those two diagnoses.
//!
//! Regenerate the fixture with the C++ compiler after changing anything under
//! `src/crypto/` or `src/util/`; the instructions are at the top of the file.

use zzz_crypto::ec2b::{derive_seed, KEY_SIZE, SEED_SIZE};
use zzz_crypto::netrand::{client_rand_key, seed_from_unix_seconds, NetRandom};
use zzz_crypto::xorpad;

const FIXTURE: &str = include_str!("../../../testdata/parity/cpp_vectors.txt");

fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// The 64-bit LCG `tools/cpp_parity.cpp` uses to fill its synthetic blobs.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn synthetic_blob(key_seed: u64, payload_seed: u64) -> Vec<u8> {
    let mut blob = vec![0u8; 28 + SEED_SIZE];
    blob[0..4].copy_from_slice(b"Ec2b");
    blob[4..8].copy_from_slice(&(KEY_SIZE as u32).to_le_bytes());
    let mut state = key_seed;
    for offset in (0..KEY_SIZE).step_by(8) {
        blob[8 + offset..8 + offset + 8].copy_from_slice(&lcg(&mut state).to_le_bytes());
    }
    blob[24..28].copy_from_slice(&(SEED_SIZE as u32).to_le_bytes());
    let mut state = payload_seed;
    for offset in (0..SEED_SIZE).step_by(8) {
        blob[28 + offset..28 + offset + 8].copy_from_slice(&lcg(&mut state).to_le_bytes());
    }
    blob
}

#[test]
fn the_rust_port_reproduces_the_cpp_vectors() {
    let mut checked = 0usize;

    for line in FIXTURE.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let field: Vec<&str> = line.split_whitespace().collect();
        match field[0] {
            kind @ ("pad_region" | "pad_session") => {
                let seed = u64::from_str_radix(field[1], 16).expect("seed is hex");
                let pad = xorpad::generate(seed, kind == "pad_session");
                assert_eq!(hex(&pad[..32]), field[2], "pad bytes differ: {line}");
                assert_eq!(
                    format!("{:016X}", fnv1a(&pad)),
                    field[3],
                    "pad differs beyond the first 32 bytes: {line}"
                );
            }
            "random" => {
                let seed: i32 = field[1].parse().expect("seed is an i32");
                let mut rng = NetRandom::new(seed);
                for (index, expected) in field[2..].iter().enumerate() {
                    assert_eq!(
                        rng.next_sample().to_string(),
                        *expected,
                        "sample {index} differs: {line}"
                    );
                }
            }
            "client_rand_key" => {
                let seed: i32 = field[1].parse().expect("seed is an i32");
                assert_eq!(
                    format!("{:016X}", client_rand_key(seed)),
                    field[2],
                    "{line}"
                );
            }
            "seed_from_seconds" => {
                let seconds: i64 = field[1].parse().expect("seconds is an i64");
                assert_eq!(
                    seed_from_unix_seconds(seconds).to_string(),
                    field[2],
                    "{line}"
                );
            }
            "ec2b" => {
                let key_seed = u64::from_str_radix(field[1], 16).expect("key seed is hex");
                let payload_seed = u64::from_str_radix(field[2], 16).expect("payload seed is hex");
                let blob = synthetic_blob(key_seed, payload_seed);
                // Check the blob itself first, so a mismatch in the derived seed
                // cannot be blamed on the two sides building different inputs.
                assert_eq!(
                    format!("{:016X}", fnv1a(&blob)),
                    field[3],
                    "the two sides built different blobs: {line}"
                );
                let derived = derive_seed(&blob).expect("synthetic blob parses");
                assert_eq!(format!("{derived:016X}"), field[4], "{line}");
            }
            other => panic!("unknown vector kind {other:?} in the fixture"),
        }
        checked += 1;
    }

    // Guards against the fixture being truncated into a vacuous pass.
    assert!(
        checked >= 30,
        "only {checked} vectors were checked, expected at least 30"
    );
}
