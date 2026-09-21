//! Port of `util::strings` from `src/util/strings.hpp`.
//!
//! The C++ version is `constexpr`/`consteval` because it runs at compile time to
//! decode the embedded RSA key; here the same routines run at startup instead,
//! which is why nothing needs to be const.

use std::fmt;

/// `util::strings::b64Val` — note that it maps every non-alphabet byte to 0
/// rather than failing, which `decode_b64` relies on for padding.
pub const fn b64_val(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum B64Error {
    OpenTagNotFound,
    CloseTagNotFound,
    SizeMismatch { expected: usize, actual: usize },
}

impl fmt::Display for B64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenTagNotFound => write!(f, "open tag not found"),
            Self::CloseTagNotFound => write!(f, "close tag not found"),
            Self::SizeMismatch { expected, actual } => {
                write!(f, "b64 size mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for B64Error {}

/// `util::strings::extractXmlTag`.
pub fn extract_xml_tag<'a>(
    xml: &'a str,
    open_tag: &str,
    close_tag: &str,
) -> Result<&'a str, B64Error> {
    let start = xml.find(open_tag).ok_or(B64Error::OpenTagNotFound)? + open_tag.len();
    let end = xml[start..]
        .find(close_tag)
        .ok_or(B64Error::CloseTagNotFound)?
        + start;
    Ok(&xml[start..end])
}

/// `util::strings::decodeB64`: skips `=`, `\n`, `\r`, space and tab, and every
/// other byte goes through `b64_val` (so garbage becomes zero bits rather than an
/// error, matching the original).
pub fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: i32 = 0;
    for &c in s.as_bytes() {
        if matches!(c, b'=' | b'\n' | b'\r' | b' ' | b'\t') {
            continue;
        }
        buf = (buf << 6) | u32::from(b64_val(c));
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    out
}

/// Standard base64 with `=` padding.
///
/// Not part of the C++ port — nothing there encodes — but the inverse is what
/// makes a fixture usable: a test or a tool has to be able to wrap an RSA block in
/// the same base64 that [`b64_decode`] reads back.
pub fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b1 = u32::from(chunk[0]);
        let b2 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b3 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let group = (b1 << 16) | (b2 << 8) | b3;
        out.push(ALPHABET[(group >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(group >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(group >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[group as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

/// `util::strings::decodeB64Fixed`: same decoder, but requires an exact length.
pub fn b64_decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], B64Error> {
    let decoded = b64_decode(s);
    if decoded.len() != N {
        return Err(B64Error::SizeMismatch {
            expected: N,
            actual: decoded.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// C's `isspace` in the default "C" locale, which includes vertical tab.
/// `char::is_ascii_whitespace` does not, so we spell it out.
const fn is_c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

/// `util::strings::toZodKey`.
///
/// Drops apostrophes and hyphens, turns every character that is neither
/// alphanumeric nor whitespace into a space, then concatenates the words with
/// only their first letter upper-cased (`"Jane Doe"` -> `"JaneDoe"`).
pub fn to_zod_key(res: &str) -> String {
    let stripped: Vec<char> = res.chars().filter(|c| *c != '\'' && *c != '-').collect();
    let mapped: Vec<char> = stripped
        .into_iter()
        .map(|c| {
            if c.is_ascii_alphanumeric() || is_c_space(c) {
                c
            } else {
                ' '
            }
        })
        .collect();

    let mut out = String::with_capacity(mapped.len());
    let mut i = 0;
    while i < mapped.len() {
        while i < mapped.len() && is_c_space(mapped[i]) {
            i += 1;
        }
        if i >= mapped.len() {
            break;
        }
        let start = i;
        while i < mapped.len() && !is_c_space(mapped[i]) {
            i += 1;
        }
        out.push(mapped[start].to_ascii_uppercase());
        out.extend(&mapped[start + 1..i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64_ignoring_padding_and_whitespace() {
        assert_eq!(b64_decode("AQID"), vec![1, 2, 3]);
        assert_eq!(b64_decode("AQ\nID"), vec![1, 2, 3]);
        assert_eq!(b64_decode("AQI="), vec![1, 2]);
    }

    #[test]
    fn encodes_what_the_decoder_reads_back() {
        // Known vectors, including both padding lengths.
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"a"), "YQ==");
        assert_eq!(b64_encode(b"ab"), "YWI=");
        assert_eq!(b64_encode(b"abc"), "YWJj");
        assert_eq!(b64_encode(&[1, 2, 3]), "AQID");

        // Round trip, including bytes that exercise the full alphabet.
        for len in 0..=200usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&bytes)), bytes, "length {len}");
        }
    }

    #[test]
    fn decode_fixed_rejects_wrong_length() {
        // "AQID" is 4 base64 characters, i.e. 3 bytes.
        assert_eq!(b64_decode_fixed::<3>("AQID").unwrap(), [1, 2, 3]);
        assert!(matches!(
            b64_decode_fixed::<4>("AQID"),
            Err(B64Error::SizeMismatch {
                expected: 4,
                actual: 3
            })
        ));
    }

    #[test]
    fn extracts_xml_tags() {
        let xml = "<RSAKeyValue><Modulus>abc</Modulus></RSAKeyValue>";
        assert_eq!(
            extract_xml_tag(xml, "<Modulus>", "</Modulus>").unwrap(),
            "abc"
        );
        assert_eq!(
            extract_xml_tag(xml, "<Missing>", "</Missing>"),
            Err(B64Error::OpenTagNotFound)
        );
    }

    #[test]
    fn zod_keys_concatenate_words_with_capitalised_initials() {
        assert_eq!(to_zod_key("Jane Doe"), "JaneDoe");
        assert_eq!(to_zod_key("Soldier 11"), "Soldier11");
        assert_eq!(to_zod_key("Rina's Wrench"), "RinasWrench");
        assert_eq!(to_zod_key("Qing-Yi"), "QingYi");
        assert_eq!(to_zod_key("hellfire  gears"), "HellfireGears");
        assert_eq!(to_zod_key(""), "");
    }
}
