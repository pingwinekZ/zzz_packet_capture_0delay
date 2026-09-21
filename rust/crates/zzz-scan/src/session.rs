//! Port of `src/crypto/session.hpp`: the handshake that turns two random halves
//! into the pad every later message is XORed with.
//!
//! The chain is: the region pad (built from the selected entry of `xorSeeds` in
//! `datamine.json`) decrypts the `PlayerGetTokenScRsp` body, one field of which is
//! a base64 RSA block holding the server's 8-byte `server_rand_key`. The client's
//! half is a .NET `Random` seeded from the login's wall-clock second, and only 32
//! bits of that seed are exposed, so it is recovered by trying every second in a
//! window around the packet's capture time and keeping the one whose pad makes the
//! body parse as protobuf. `session_key = server_rand_key ^ client_rand_key` then
//! seeds the pad used for the rest of the capture.
//!
//! The C++ keeps the pad in a function-local `static` that a separate thread can
//! rewrite under it. Here the pad is a field, so a session is a value: two of them
//! can exist at once, which is what lets a replay try every region seed to find
//! the one this capture used.

use std::fmt;

use zzz_crypto::b64::b64_decode;
use zzz_crypto::netrand::{client_rand_key, seed_from_unix_seconds};
use zzz_crypto::rsa;
use zzz_crypto::xorpad::{self, XorPad};
use zzz_wire::proto::{Message, ProtoError, Value};

/// `bruteForceClientRandKey`'s default `windowSeconds`.
pub const BRUTE_FORCE_WINDOW_SECONDS: i64 = 1800;

/// Why the handshake could not be completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The decrypted token response was not a protobuf message at all.
    Protobuf(ProtoError),
    /// No length-delimited field decrypted to an 8-byte key.
    ServerRandKeyNotFound,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protobuf(error) => write!(f, "token response is not protobuf: {error}"),
            Self::ServerRandKeyNotFound => {
                write!(f, "server_rand_key field not found in PlayerGetTokenScRsp")
            }
        }
    }
}

impl std::error::Error for SessionError {}

/// A seed that made a body parse, along with what it implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BruteForceMatch {
    /// The recovered `client_rand_key`.
    pub client_rand_key: u64,
    /// `server_rand_key ^ client_rand_key`, the value that seeds the session pad.
    pub session_key: u64,
    /// Seconds from the packet's capture time to the seed's second.
    pub delta: i64,
    /// The seed itself: `client_rand_key`'s low half.
    pub seed: i32,
}

/// The handshake state, and the pad currently in use.
#[derive(Debug, Clone)]
pub struct Session {
    pub server_rand_key: Option<u64>,
    pub client_rand_key: Option<u64>,
    pub session_key: Option<u64>,
    /// The region pad until the handshake completes, the session pad after.
    pad: XorPad,
    pad_ready: bool,
}

impl Session {
    /// A session that has not seen `PlayerGetTokenScRsp` yet.
    pub fn new(region_pad: XorPad) -> Self {
        Self {
            server_rand_key: None,
            client_rand_key: None,
            session_key: None,
            pad: region_pad,
            pad_ready: false,
        }
    }

    /// Whether the session pad has replaced the region pad.
    pub fn pad_ready(&self) -> bool {
        self.pad_ready
    }

    /// The pad currently in use.
    pub fn pad(&self) -> &XorPad {
        &self.pad
    }

    /// `Session::decryptBody` — repeating-key XOR with whichever pad is current.
    pub fn decrypt_body(&self, body: &[u8]) -> Vec<u8> {
        xorpad::xor_bytes(body, self.pad.bytes())
    }

    /// `Session::extractServerRandKey`.
    ///
    /// Walks every length-delimited field looking for one that decodes from
    /// base64 to exactly one RSA block and decrypts to 8 bytes. A field that is
    /// not base64 text is skipped rather than being an error, so an unknown
    /// fielde layout still finds the key.
    pub fn extract_server_rand_key(body: &[u8]) -> Result<u64, SessionError> {
        let message = Message::decode(body).map_err(SessionError::Protobuf)?;
        for field in &message.fields {
            let Value::LengthDelimited(bytes) = &field.value else {
                continue;
            };
            // Base64 is ASCII; a field holding arbitrary bytes cannot be one.
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            let decoded = b64_decode(text);
            if decoded.len() != rsa::KEY_SIZE {
                continue;
            }
            let Ok(plain) = rsa::decrypt_block(&decoded) else {
                continue;
            };
            if plain.len() != 8 {
                continue;
            }
            let mut key = [0u8; 8];
            key.copy_from_slice(&plain);
            return Ok(u64::from_le_bytes(key));
        }
        Err(SessionError::ServerRandKeyNotFound)
    }

    /// `Session::bruteForceClientRandKey`.
    ///
    /// A successful protobuf parse is the whole test — the original has nothing
    /// stronger available. That is only safe because a real body is far longer
    /// than the 32-byte minimum: for a 32-byte buffer a random pad has a
    /// non-trivial chance of parsing, but for the hundreds of bytes a real
    /// message occupies it does not happen.
    pub fn brute_force_client_rand_key(
        server_rand_key: u64,
        target_body: &[u8],
        unix_seconds: i64,
        window_seconds: i64,
    ) -> Option<BruteForceMatch> {
        for delta in -window_seconds..=window_seconds {
            let seed = seed_from_unix_seconds(unix_seconds + delta);
            let client = client_rand_key(seed);
            let session_key = server_rand_key ^ client;
            let pad = xorpad::session(session_key);
            let decrypted = xorpad::xor_bytes(target_body, &pad);
            if Message::decode(&decrypted).is_ok() {
                return Some(BruteForceMatch {
                    client_rand_key: client,
                    session_key,
                    delta,
                    seed,
                });
            }
        }
        None
    }

    /// `Session::deriveSessionKey` — recover the seed and adopt the session pad.
    ///
    /// `body` is the message body exactly as it arrived, still XORed with the
    /// session pad; the brute force removes that pad itself.
    pub fn derive_session_key(
        &mut self,
        body: &[u8],
        unix_seconds: i64,
    ) -> Option<BruteForceMatch> {
        let server = self.server_rand_key?;
        let found = Self::brute_force_client_rand_key(
            server,
            body,
            unix_seconds,
            BRUTE_FORCE_WINDOW_SECONDS,
        )?;
        self.client_rand_key = Some(found.client_rand_key);
        self.session_key = Some(found.session_key);
        self.pad = XorPad::for_session(found.session_key);
        self.pad_ready = true;
        Some(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zzz_crypto::b64::b64_encode;
    use zzz_wire::proto::Field;

    const SERVER_RAND_KEY: u64 = 0x1122_3344_5566_7788;
    const LOGIN_TIME: i64 = 1_760_000_000;

    /// A `PlayerGetTokenScRsp` body: a base64 RSA block among unrelated fields.
    fn token_body(server_rand_key: u64) -> Vec<u8> {
        let ciphertext = rsa::encrypt_block(&server_rand_key.to_le_bytes()).expect("encrypts");
        let mut message = Message::default();
        // A field that is not base64 at all must be skipped, not fatal.
        message.fields.push(Field::new(
            1,
            Value::LengthDelimited(vec![0xFF, 0x00, 0xFE]),
        ));
        message.fields.push(Field::new(
            9,
            Value::LengthDelimited(b64_encode(&ciphertext).into_bytes()),
        ));
        message.encode()
    }

    #[test]
    fn extracts_the_server_key_from_the_token_response() {
        let body = token_body(SERVER_RAND_KEY);
        assert_eq!(
            Session::extract_server_rand_key(&body).unwrap(),
            SERVER_RAND_KEY
        );
    }

    #[test]
    fn reports_a_token_response_without_a_usable_key() {
        // Parses as protobuf, but no field decrypts to 8 bytes.
        let mut message = Message::default();
        message.fields.push(Field::new(
            1,
            Value::LengthDelimited(b"not base64".to_vec()),
        ));
        assert_eq!(
            Session::extract_server_rand_key(&message.encode()),
            Err(SessionError::ServerRandKeyNotFound)
        );
        // Base64 of the wrong length is skipped for the same reason.
        let mut message = Message::default();
        message.fields.push(Field::new(
            1,
            Value::LengthDelimited(b64_encode(&[0u8; 16]).into_bytes()),
        ));
        assert_eq!(
            Session::extract_server_rand_key(&message.encode()),
            Err(SessionError::ServerRandKeyNotFound)
        );

        assert!(matches!(
            Session::extract_server_rand_key(&[0xFF, 0xFF, 0xFF]),
            Err(SessionError::Protobuf(_))
        ));
    }

    #[test]
    fn brute_forces_the_seed_from_a_body_it_encrypted_itself() {
        // A realistic body: hundreds of bytes, not the 32-byte minimum.
        let plain = Message {
            fields: vec![Field::new(3, Value::LengthDelimited(vec![0x5A; 200]))],
        }
        .encode();
        let seed = seed_from_unix_seconds(LOGIN_TIME - 7);
        let session_key = SERVER_RAND_KEY ^ client_rand_key(seed);
        let wire = xorpad::xor_bytes(&plain, &xorpad::session(session_key));

        let found = Session::brute_force_client_rand_key(
            SERVER_RAND_KEY,
            &wire,
            LOGIN_TIME,
            BRUTE_FORCE_WINDOW_SECONDS,
        )
        .expect("the seed is inside the window");

        assert_eq!(found.seed, seed);
        assert_eq!(found.delta, -7);
        assert_eq!(found.session_key, session_key);
        let restored = Message::decode(&xorpad::xor_bytes(
            &wire,
            &xorpad::session(found.session_key),
        ))
        .unwrap();
        assert_eq!(restored, Message::decode(&plain).unwrap());
    }

    #[test]
    fn brute_force_gives_up_outside_the_window() {
        let plain = Message {
            fields: vec![Field::new(3, Value::LengthDelimited(vec![0x5A; 200]))],
        }
        .encode();
        let seed = seed_from_unix_seconds(LOGIN_TIME - 5_000);
        let session_key = SERVER_RAND_KEY ^ client_rand_key(seed);
        let wire = xorpad::xor_bytes(&plain, &xorpad::session(session_key));

        assert_eq!(
            Session::brute_force_client_rand_key(SERVER_RAND_KEY, &wire, LOGIN_TIME, 1800),
            None
        );
        // Narrowing the window to nothing but the true second does find it.
        assert!(Session::brute_force_client_rand_key(
            SERVER_RAND_KEY,
            &wire,
            LOGIN_TIME - 5_000,
            0
        )
        .is_some());
    }

    #[test]
    fn the_session_pad_replaces_the_region_pad_once_derived() {
        let region_pad = XorPad::for_region(0x9543_521F_C9C8_CAED);
        let mut session = Session::new(region_pad.clone());
        assert!(!session.pad_ready());
        assert_eq!(session.pad(), &region_pad);

        // Deriving needs the server half first, exactly like the capture order.
        session.server_rand_key = Some(SERVER_RAND_KEY);

        let plain = Message {
            fields: vec![Field::new(3, Value::LengthDelimited(vec![0x5A; 200]))],
        }
        .encode();
        let seed = seed_from_unix_seconds(LOGIN_TIME);
        let session_key = SERVER_RAND_KEY ^ client_rand_key(seed);
        let wire = xorpad::xor_bytes(&plain, &xorpad::session(session_key));

        let found = session.derive_session_key(&wire, LOGIN_TIME).unwrap();
        assert_eq!(found.delta, 0);
        assert!(session.pad_ready());
        assert_eq!(session.session_key, Some(session_key));
        assert_eq!(session.pad(), &XorPad::for_session(session_key));

        // The region pad leaves this body as noise; the session pad restores it.
        assert_ne!(xorpad::xor_bytes(&wire, region_pad.bytes()), plain);
        assert_eq!(session.decrypt_body(&wire), plain);
    }

    #[test]
    fn deriving_without_the_server_key_does_nothing() {
        let mut session = Session::new(XorPad::for_region(1));
        assert_eq!(session.derive_session_key(&[0u8; 64], LOGIN_TIME), None);
        assert!(!session.pad_ready());
    }
}
