//! Port of `src/crypto/rsa.hpp`.
//!
//! The C++ code hands OpenSSL the modulus, exponent and private exponent (no
//! primes, so it cannot use CRT) and asks for `RSA_PKCS1_PADDING`. That is plain
//! `m = c^d mod n` followed by PKCS#1 v1.5 unpadding, which is what we do here
//! with `num-bigint` — the `rsa` crate cannot build a key from `(n, e, d)` alone.

use std::fmt;
use std::sync::LazyLock;

use num_bigint::BigUint;

use crate::b64::{b64_decode, extract_xml_tag, B64Error};
use crate::key::CLIENT_PRIVATE_KEY;

/// `crypto::rsa::KeySize` — RSA-1024 is 128 bytes.
pub const KEY_SIZE: usize = 128;
/// `crypto::rsa::PublicExponent`.
pub const PUBLIC_EXPONENT: u64 = 65537;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaError {
    Key(B64Error),
    /// Key material is not `KEY_SIZE` bytes long.
    BadKeySize {
        name: &'static str,
        len: usize,
    },
    /// Ciphertext is not exactly `KEY_SIZE` bytes, or not a multiple of it.
    BadCiphertextSize(usize),
    /// Ciphertext is numerically >= n, or the exponentiation produced no value.
    DecryptFailed,
    /// PKCS#1 v1.5 padding was malformed (bad block type, or PS shorter than 8).
    PaddingInvalid,
}

impl fmt::Display for RsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(e) => write!(f, "RSA key: {e}"),
            Self::BadKeySize { name, len } => {
                write!(f, "RSA key: {name} is {len} bytes, expected {KEY_SIZE}")
            }
            Self::BadCiphertextSize(len) => {
                write!(
                    f,
                    "RSA: input of {len} bytes is not a multiple of {KEY_SIZE}"
                )
            }
            Self::DecryptFailed => write!(f, "RSA decrypt failed"),
            Self::PaddingInvalid => write!(f, "RSA decrypt failed (invalid padding)"),
        }
    }
}

impl std::error::Error for RsaError {}

/// Port of `crypto::rsa::Key`, built from the embedded XML key material.
pub struct Key {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

impl Key {
    fn from_xml(xml: &str) -> Result<Self, RsaError> {
        let n_bytes =
            b64_decode(extract_xml_tag(xml, "<Modulus>", "</Modulus>").map_err(RsaError::Key)?);
        let d_bytes = b64_decode(extract_xml_tag(xml, "<D>", "</D>").map_err(RsaError::Key)?);
        if n_bytes.len() != KEY_SIZE {
            return Err(RsaError::BadKeySize {
                name: "Modulus",
                len: n_bytes.len(),
            });
        }
        if d_bytes.len() != KEY_SIZE {
            return Err(RsaError::BadKeySize {
                name: "D",
                len: d_bytes.len(),
            });
        }
        Ok(Self {
            n: BigUint::from_bytes_be(&n_bytes),
            e: BigUint::from(PUBLIC_EXPONENT),
            d: BigUint::from_bytes_be(&d_bytes),
        })
    }
}

// The C++ code builds this once in a function-local `static` and throws on
// failure. Caching a `Result` keeps the failure non-fatal: a broken embedded key
// reports an error instead of aborting the capture thread.
static EMBEDDED_KEY: LazyLock<Result<Key, RsaError>> =
    LazyLock::new(|| Key::from_xml(CLIENT_PRIVATE_KEY));

/// The key parsed from [`crate::key::CLIENT_PRIVATE_KEY`].
pub fn key() -> Result<&'static Key, RsaError> {
    match &*EMBEDDED_KEY {
        Ok(k) => Ok(k),
        Err(e) => Err(e.clone()),
    }
}

fn unpad_pkcs1_v15(em: &[u8]) -> Result<&[u8], RsaError> {
    // EM = 0x00 || 0x02 || PS || 0x00 || M, with PS at least 8 bytes. These are
    // the same conditions OpenSSL checks before it hands back the plaintext.
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x02 {
        return Err(RsaError::PaddingInvalid);
    }
    let sep = em[2..]
        .iter()
        .position(|&b| b == 0)
        .map(|i| i + 2)
        .ok_or(RsaError::PaddingInvalid)?;
    if sep - 2 < 8 {
        return Err(RsaError::PaddingInvalid);
    }
    Ok(&em[sep + 1..])
}

/// `crypto::rsa::decryptBlock` — one 128-byte block, RSA-1024 PKCS#1 v1.5.
pub fn decrypt_block(ciphertext: &[u8]) -> Result<Vec<u8>, RsaError> {
    if ciphertext.len() != KEY_SIZE {
        return Err(RsaError::BadCiphertextSize(ciphertext.len()));
    }
    let key = key()?;

    let c = BigUint::from_bytes_be(ciphertext);
    if c >= key.n {
        return Err(RsaError::DecryptFailed);
    }

    let m = c.modpow(&key.d, &key.n);

    // Left-pad to the modulus width: a plaintext shorter than the modulus would
    // otherwise lose its leading zero bytes and shift the padding check.
    let raw = m.to_bytes_be();
    let mut em = vec![0u8; KEY_SIZE];
    em[KEY_SIZE - raw.len()..].copy_from_slice(&raw);

    Ok(unpad_pkcs1_v15(&em)?.to_vec())
}

/// `crypto::rsa::decryptMulti` — concatenation of independently padded blocks.
pub fn decrypt_multi(data: &[u8]) -> Result<Vec<u8>, RsaError> {
    if data.len() % KEY_SIZE != 0 {
        return Err(RsaError::BadCiphertextSize(data.len()));
    }
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks_exact(KEY_SIZE) {
        out.extend_from_slice(&decrypt_block(block)?);
    }
    Ok(out)
}

/// PKCS#1 v1.5 encryption padding: `0x00 || 0x02 || PS || 0x00 || M`.
fn pkcs1_v15_pad(message: &[u8]) -> Result<Vec<u8>, RsaError> {
    // PS must be at least 8 bytes, so a message can be at most KEY_SIZE - 11.
    if message.len() > KEY_SIZE - 11 {
        return Err(RsaError::PaddingInvalid);
    }
    let ps_len = KEY_SIZE - 3 - message.len();
    let mut em = vec![0u8; KEY_SIZE];
    em[1] = 0x02;
    // Non-zero filler, as the spec requires. The original only ever decrypts, so
    // the particular bytes do not matter; a fixed sequence keeps this repeatable.
    for (i, byte) in em[2..2 + ps_len].iter_mut().enumerate() {
        *byte = (i % 255 + 1) as u8;
    }
    em[2 + ps_len] = 0x00;
    em[3 + ps_len..].copy_from_slice(message);
    Ok(em)
}

/// Raise an encoded message to the public exponent — the inverse of the
/// exponentiation inside [`decrypt_block`].
fn encipher_em(key: &Key, em: &[u8]) -> Vec<u8> {
    let c = BigUint::from_bytes_be(em).modpow(&key.e, &key.n);
    let raw = c.to_bytes_be();
    let mut out = vec![0u8; KEY_SIZE];
    out[KEY_SIZE - raw.len()..].copy_from_slice(&raw);
    out
}

/// Encrypt one message with the embedded public key, PKCS#1 v1.5 padded.
///
/// The C++ build only ever decrypts, but without the inverse there is no way to
/// build a `PlayerGetTokenScRsp` fixture from outside the crate — and that is what
/// tests the whole capture pipeline against a session it produced itself.
pub fn encrypt_block(message: &[u8]) -> Result<Vec<u8>, RsaError> {
    let key = key()?;
    Ok(encipher_em(key, &pkcs1_v15_pad(message)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(message: &[u8]) -> Vec<u8> {
        let mut em = vec![0u8; KEY_SIZE];
        em[0] = 0x00;
        em[1] = 0x02;
        let ps_len = KEY_SIZE - 3 - message.len();
        assert!(ps_len >= 8, "test message too long");
        // Non-zero filler, like a real PKCS#1 v1.5 encoder produces.
        for b in &mut em[2..2 + ps_len] {
            *b = 0xAA;
        }
        em[2 + ps_len] = 0x00;
        em[3 + ps_len..].copy_from_slice(message);
        em
    }

    #[test]
    fn embedded_key_parses_and_is_consistent() {
        let key = key().expect("embedded key must parse");
        // RSA-1024 means 128 bytes, but note that this key's modulus has its top
        // bit clear, so it is 1023 bits wide. Padding to KEY_SIZE bytes is
        // therefore what makes the decryption correct, not the bit width.
        assert_eq!(key.n.to_bytes_be().len(), KEY_SIZE);
        assert!(key.n.bits() > 1000);
        assert_eq!(key.d.to_bytes_be().len(), KEY_SIZE);
        assert_eq!(key.e, BigUint::from(PUBLIC_EXPONENT));
    }

    #[test]
    fn decrypts_what_the_public_exponent_encrypted() {
        for message in [
            &b"server-rand-key"[..],
            &[0u8; 8],
            &b"x"[..],
            &b"1234567890abcdef"[..],
        ] {
            let ct = encrypt_block(message).unwrap();
            assert_eq!(decrypt_block(&ct).unwrap(), message);
        }
        // The padding helper agrees with the decoder's expectations.
        assert!(matches!(
            encrypt_block(&[0u8; KEY_SIZE]),
            Err(RsaError::PaddingInvalid)
        ));
    }

    #[test]
    fn decrypt_multi_concatenates_blocks() {
        let mut ct = encrypt_block(b"first").unwrap();
        ct.extend_from_slice(&encrypt_block(b"second").unwrap());
        assert_eq!(decrypt_multi(&ct).unwrap(), b"firstsecond");
    }

    #[test]
    fn rejects_malformed_padding_and_sizes() {
        let key = key().unwrap();
        // Right length, wrong block type. Built by hand rather than with
        // `encrypt_block`, because the point is to make the decoder reject it.
        let mut em = padded(b"payload");
        em[1] = 0x01;
        assert_eq!(
            decrypt_block(&encipher_em(key, &em)),
            Err(RsaError::PaddingInvalid)
        );

        // PS shorter than 8 bytes.
        let mut em = vec![0u8; KEY_SIZE];
        em[1] = 0x02;
        em[5] = 0x00;
        assert_eq!(
            decrypt_block(&encipher_em(key, &em)),
            Err(RsaError::PaddingInvalid)
        );

        assert!(matches!(
            decrypt_block(&[0u8; 64]),
            Err(RsaError::BadCiphertextSize(64))
        ));
        assert!(matches!(
            decrypt_multi(&[0u8; 200]),
            Err(RsaError::BadCiphertextSize(200))
        ));
    }
}
