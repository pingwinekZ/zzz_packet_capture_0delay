//! A JSON writer that matches glaze's output byte for byte.
//!
//! Only the pieces the ZOD export needs: strings, unsigned numbers, booleans,
//! arrays and objects with a fixed key order. Everything is built bottom-up out
//! of `String`s rather than written into one buffer through a stateful writer,
//! which keeps the key order explicit at the call site and makes commas
//! impossible to get wrong.
//!
//! See the crate docs for why this exists instead of `serde_json`.

/// A JSON string literal, escaped the way glaze escapes one.
///
/// glaze escapes `"`, `\`, and the five characters with a short escape
/// (`\b`, `\t`, `\n`, `\f`, `\r`). Every other byte, including `0x00`–`0x07`,
/// `0x0B` and `0x0E`–`0x1F`, is copied through verbatim. That produces invalid
/// JSON for those bytes, but it is what the reference emits, and the parity test
/// asserts byte equality against the reference's own output — so it is
/// reproduced here rather than corrected.
pub fn string(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len() + 2);
    out.push(b'"');
    for &byte in value.as_bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0D => out.extend_from_slice(b"\\r"),
            // Copied through, not escaped: see above. Every byte that reaches
            // this arm came from a UTF-8 string, so the result stays valid UTF-8
            // and non-ASCII text survives unescaped, as it does in glaze.
            other => out.push(other),
        }
    }
    out.push(b'"');
    // The only transformation above is replacing ASCII bytes with longer ASCII
    // escapes, so the input's UTF-8 validity carries over.
    debug_assert!(std::str::from_utf8(&out).is_ok());
    String::from_utf8(out).expect("escapes are ASCII and the rest is copied verbatim")
}

/// A program's numbers: glaze writes integers in decimal, with no sign or
/// exponent for the unsigned types the export uses.
pub fn number<T: std::fmt::Display>(value: T) -> String {
    value.to_string()
}

pub fn boolean(value: bool) -> String {
    (if value { "true" } else { "false" }).to_string()
}

/// An array of already-encoded values.
pub fn array(items: &[String]) -> String {
    let mut out = String::with_capacity(2 + items.len() * 8);
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(item);
    }
    out.push(']');
    out
}

/// An object from `(key, value)` pairs, in the order given.
///
/// A `None` value drops the key entirely, which is what glaze does with a
/// `std::nullopt`. An engaged `Some` is always written, even when it holds an
/// empty array: the reference distinguishes "not exported" from "exported and
/// empty", and so does the site reading it.
pub fn object(fields: &[(&str, Option<String>)]) -> String {
    let mut out = String::with_capacity(2 + fields.len() * 16);
    out.push('{');
    let mut first = true;
    for (key, value) in fields {
        let Some(value) = value else {
            continue;
        };
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&string(key));
        out.push(':');
        out.push_str(value);
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_exactly_what_glaze_escapes() {
        assert_eq!(string("a\"b"), r#""a\"b""#);
        assert_eq!(string("a\\b"), r#""a\\b""#);
        assert_eq!(string("a/b"), r#""a/b""#);
        assert_eq!(string("a\tb"), r#""a\tb""#);
        assert_eq!(string("a\nb"), r#""a\nb""#);
        assert_eq!(string("a\rb"), r#""a\rb""#);
        assert_eq!(string("a\x08b"), r#""a\bb""#);
        assert_eq!(string("a\x0Cb"), r#""a\fb""#);
    }

    /// The quirk the crate docs describe: glaze does *not* escape control bytes
    /// other than the five with a short escape, so neither does this.
    #[test]
    fn leaves_other_control_bytes_raw() {
        assert_eq!(string("a\x00b"), "\"a\u{0}b\"");
        assert_eq!(string("a\x01b"), "\"a\u{1}b\"");
        assert_eq!(string("a\x0Bb"), "\"a\u{b}b\"");
        assert_eq!(string("a\x1Fb"), "\"a\u{1F}b\"");
        assert_eq!(string("a\x7Fz"), "\"a\u{7F}z\"");
    }

    #[test]
    fn passes_utf8_through_unescaped() {
        assert_eq!(string("Anby \u{96ea}\u{8863}"), "\"Anby \u{96ea}\u{8863}\"");
    }

    #[test]
    fn omits_none_and_keeps_engaged_empties() {
        assert_eq!(object(&[("a", Some(number(1))), ("b", None)]), r#"{"a":1}"#);
        assert_eq!(
            object(&[("discs", Some(array(&[])))]),
            r#"{"discs":[]}"#,
            "an empty exported list is present, an unexported one is absent"
        );
        assert_eq!(object(&[]), "{}");
    }

    #[test]
    fn builds_arrays_and_scalars() {
        assert_eq!(array(&[]), "[]");
        assert_eq!(
            array(&[number(1), boolean(false), string("x")]),
            r#"[1,false,"x"]"#
        );
        assert_eq!(number(255u8), "255");
        assert_eq!(number(4294967295u32), "4294967295");
    }
}
