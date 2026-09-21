//! Crypto primitives, ported verbatim from `src/crypto/*` of the C++ implementation.
//!
//! Nothing here does I/O and nothing here depends on another crate in this
//! workspace, so the whole module is testable on its own. Every algorithm that
//! has to match the game byte-for-byte says so in its doc comment.

pub mod b64;
pub mod ec2b;
pub mod ec2b_tables;
/// The embedded RSA key material. Not re-exported: use [`rsa::key`].
pub mod key;
pub mod mt19937;
pub mod netrand;
pub mod rsa;
pub mod xorpad;

pub use b64::{b64_decode, b64_encode, extract_xml_tag, to_zod_key, B64Error};
pub use ec2b::{derive_seed, Ec2bError};
pub use mt19937::Mt19937_64;
pub use netrand::{client_rand_key, seed_from_unix_seconds, NetRandom};
pub use rsa::{RsaError, KEY_SIZE};
pub use xorpad::{XorPad, PAD_SIZE};
