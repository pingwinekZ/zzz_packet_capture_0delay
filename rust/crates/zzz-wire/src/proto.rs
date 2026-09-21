//! A schema-free protobuf reader/writer, standing in for
//! `google::protobuf::UnknownFieldSet`.
//!
//! Behaviour that the rest of the port depends on, all matching protobuf's
//! `ParseFromArray`/`SerializeToString`:
//!
//! * An empty buffer decodes to an empty message, and that is a *success*. The
//!   session handshake brute-force relies on arbitrary decrypted bytes failing
//!   to parse, so the decoder has to reject what protobuf rejects: truncated
//!   input, field number 0, field numbers above 2^29-1, malformed varints,
//!   reserved wire types, and unterminated groups.
//! * Field order is preserved, including repeated occurrences of the same
//!   number, and re-encoding emits fields in that order.
//! * Re-encoding is canonical: minimal varints, length prefixes recomputed. That
//!   is what protobuf does when it re-serialises a nested unknown field, so a
//!   parse/rewrite/serialise round trip must reproduce it exactly.

use std::fmt;

/// Highest field number the protobuf wire format allows.
pub const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;

const WT_VARINT: u8 = 0;
const WT_FIXED64: u8 = 1;
const WT_LEN: u8 = 2;
const WT_START_GROUP: u8 = 3;
const WT_END_GROUP: u8 = 4;
const WT_FIXED32: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Ran out of bytes mid-value.
    Truncated,
    /// Varint longer than 10 bytes, or a 10th byte with bits above the 64th.
    MalformedVarint,
    /// Field number 0, or above [`MAX_FIELD_NUMBER`].
    InvalidFieldNumber(u32),
    /// Wire types 6 and 7 do not exist.
    InvalidWireType(u8),
    /// End-group without a matching start-group, or the reverse.
    UnexpectedEndGroup(u32),
    /// A nested message claiming more bytes than are left.
    LengthOverflow { declared: u64, remaining: usize },
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "protobuf: truncated input"),
            Self::MalformedVarint => write!(f, "protobuf: malformed varint"),
            Self::InvalidFieldNumber(n) => write!(f, "protobuf: invalid field number {n}"),
            Self::InvalidWireType(w) => write!(f, "protobuf: invalid wire type {w}"),
            Self::UnexpectedEndGroup(n) => {
                write!(f, "protobuf: unexpected end-group for field {n}")
            }
            Self::LengthOverflow {
                declared,
                remaining,
            } => write!(
                f,
                "protobuf: nested length {declared} exceeds {remaining} remaining bytes"
            ),
        }
    }
}

impl std::error::Error for ProtoError {}

/// One field's value, tagged with the wire type it was decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Varint(u64),
    Fixed64(u64),
    LengthDelimited(Vec<u8>),
    Fixed32(u32),
    Group(Vec<Field>),
}

impl Value {
    pub fn wire_type(&self) -> u8 {
        match self {
            Self::Varint(_) => WT_VARINT,
            Self::Fixed64(_) => WT_FIXED64,
            Self::LengthDelimited(_) => WT_LEN,
            Self::Group(_) => WT_START_GROUP,
            Self::Fixed32(_) => WT_FIXED32,
        }
    }

    pub fn as_varint(&self) -> Option<u64> {
        match self {
            Self::Varint(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::LengthDelimited(b) => Some(b),
            _ => None,
        }
    }

    /// Decode a length-delimited value as a nested message.
    pub fn as_message(&self) -> Option<Message> {
        Message::decode(self.as_bytes()?).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub number: u32,
    pub value: Value,
}

impl Field {
    pub fn new(number: u32, value: Value) -> Self {
        Self { number, value }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub fields: Vec<Field>,
}

impl Message {
    /// protobuf's `ParseFromArray`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut pos = 0;
        Ok(Self {
            fields: decode_fields(buf, &mut pos, None)?,
        })
    }

    /// protobuf's `SerializeToString`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_fields(&self.fields, &mut out);
        out
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Every field with this number, in encounter order.
    pub fn get(&self, number: u32) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.number == number)
    }

    /// The first field with this number.
    pub fn first(&self, number: u32) -> Option<&Field> {
        self.fields.iter().find(|f| f.number == number)
    }

    pub fn first_mut(&mut self, number: u32) -> Option<&mut Field> {
        self.fields.iter_mut().find(|f| f.number == number)
    }

    pub fn varint(&self, number: u32) -> Option<u64> {
        self.first(number)?.value.as_varint()
    }

    pub fn bytes(&self, number: u32) -> Option<&[u8]> {
        self.first(number)?.value.as_bytes()
    }

    pub fn nested(&self, number: u32) -> Option<Message> {
        self.first(number)?.value.as_message()
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, ProtoError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for i in 0..10 {
        let byte = *buf.get(*pos).ok_or(ProtoError::Truncated)?;
        *pos += 1;
        // The 10th byte may only contribute the single bit that is still free.
        if i == 9 && byte > 1 {
            return Err(ProtoError::MalformedVarint);
        }
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(ProtoError::MalformedVarint)
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_tag(out: &mut Vec<u8>, number: u32, wire_type: u8) {
    write_varint(out, (u64::from(number) << 3) | u64::from(wire_type));
}

/// `group` is the field number of the enclosing group, if any: reading its
/// end-group tag terminates this level.
fn decode_fields(
    buf: &[u8],
    pos: &mut usize,
    group: Option<u32>,
) -> Result<Vec<Field>, ProtoError> {
    let mut fields = Vec::new();
    while *pos < buf.len() {
        let tag = read_varint(buf, pos)?;
        let number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if number == 0 || number > MAX_FIELD_NUMBER {
            return Err(ProtoError::InvalidFieldNumber(number));
        }

        if wire_type == WT_END_GROUP {
            return match group {
                Some(open) if open == number => Ok(fields),
                _ => Err(ProtoError::UnexpectedEndGroup(number)),
            };
        }

        let value = match wire_type {
            WT_VARINT => Value::Varint(read_varint(buf, pos)?),
            WT_FIXED64 => {
                let end = *pos + 8;
                let bytes = buf.get(*pos..end).ok_or(ProtoError::Truncated)?;
                *pos = end;
                Value::Fixed64(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
            }
            WT_LEN => {
                let declared = read_varint(buf, pos)?;
                let remaining = buf.len() - *pos;
                if declared > remaining as u64 {
                    return Err(ProtoError::LengthOverflow {
                        declared,
                        remaining,
                    });
                }
                let end = *pos + declared as usize;
                let bytes = buf[*pos..end].to_vec();
                *pos = end;
                Value::LengthDelimited(bytes)
            }
            WT_START_GROUP => Value::Group(decode_fields(buf, pos, Some(number))?),
            WT_FIXED32 => {
                let end = *pos + 4;
                let bytes = buf.get(*pos..end).ok_or(ProtoError::Truncated)?;
                *pos = end;
                Value::Fixed32(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
            }
            other => return Err(ProtoError::InvalidWireType(other)),
        };

        fields.push(Field { number, value });
    }

    match group {
        // Reaching the end of the buffer inside a group means it never closed.
        Some(_) => Err(ProtoError::Truncated),
        None => Ok(fields),
    }
}

fn encode_fields(fields: &[Field], out: &mut Vec<u8>) {
    for field in fields {
        match &field.value {
            Value::Varint(v) => {
                write_tag(out, field.number, WT_VARINT);
                write_varint(out, *v);
            }
            Value::Fixed64(v) => {
                write_tag(out, field.number, WT_FIXED64);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::LengthDelimited(bytes) => {
                write_tag(out, field.number, WT_LEN);
                write_varint(out, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Value::Group(inner) => {
                write_tag(out, field.number, WT_START_GROUP);
                encode_fields(inner, out);
                write_tag(out, field.number, WT_END_GROUP);
            }
            Value::Fixed32(v) => {
                write_tag(out, field.number, WT_FIXED32);
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
}

/// Port of `pcap::SyncApplier::collectUints`.
///
/// A varint field yields one value; a length-delimited field is treated as a
/// packed varint list and decoded until a value runs off the end, keeping
/// whatever was already decoded.
pub fn collect_packed_uints(field: &Field) -> Vec<u32> {
    let mut out = Vec::new();
    match &field.value {
        Value::Varint(v) => out.push(*v as u32),
        Value::LengthDelimited(data) => {
            let mut pos = 0;
            while pos < data.len() {
                match read_varint(data, &mut pos) {
                    Ok(v) => out.push(v as u32),
                    Err(_) => break,
                }
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_a_valid_empty_message() {
        // Matches ParseFromArray("") == true, which the nested-message handling
        // and the handshake brute-force both depend on.
        let msg = Message::decode(&[]).unwrap();
        assert!(msg.is_empty());
        assert!(msg.encode().is_empty());
    }

    #[test]
    fn round_trips_every_wire_type() {
        let msg = Message {
            fields: vec![
                Field::new(1, Value::Varint(300)),
                Field::new(2, Value::Fixed64(0x0102_0304_0506_0708)),
                Field::new(3, Value::LengthDelimited(b"hello".to_vec())),
                Field::new(4, Value::Fixed32(0xDEAD_BEEF)),
                Field::new(5, Value::Group(vec![Field::new(1, Value::Varint(7))])),
            ],
        };
        let encoded = msg.encode();
        assert_eq!(Message::decode(&encoded).unwrap(), msg);
        assert_eq!(Message::decode(&encoded).unwrap().encode(), encoded);
    }

    #[test]
    fn preserves_field_order_and_repeats() {
        let msg = Message {
            fields: vec![
                Field::new(9, Value::Varint(1)),
                Field::new(3, Value::Varint(2)),
                Field::new(9, Value::Varint(3)),
            ],
        };
        let decoded = Message::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.get(9).count(), 2);
        assert_eq!(decoded.varint(9), Some(1));
    }

    #[test]
    fn encoding_is_minimal_like_protobuf() {
        let mut long_form = vec![1 << 3]; // tag for field 1, varint
        long_form.extend_from_slice(&[0x81, 0x80, 0x80, 0x00]); // 1 encoded in 4 bytes
        let msg = Message::decode(&long_form).unwrap();
        assert_eq!(msg.varint(1), Some(1));
        // Re-encoding canonicalises it, exactly as protobuf would.
        assert_eq!(msg.encode(), vec![1 << 3, 0x01]);
    }

    #[test]
    fn rejects_what_protobuf_rejects() {
        assert_eq!(Message::decode(&[0x08]), Err(ProtoError::Truncated));
        assert_eq!(
            Message::decode(&[0x00, 0x01]),
            Err(ProtoError::InvalidFieldNumber(0))
        );
        // Wire types 6 and 7 do not exist.
        assert_eq!(
            Message::decode(&[0x0E]),
            Err(ProtoError::InvalidWireType(6))
        );
        // varint with all continuation bits set for 10 bytes then more.
        let bad_varint = [
            0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ];
        assert_eq!(
            Message::decode(&bad_varint),
            Err(ProtoError::MalformedVarint)
        );
        // Length prefix longer than what is left.
        assert!(matches!(
            Message::decode(&[0x12, 0x05, 0x01]),
            Err(ProtoError::LengthOverflow { .. })
        ));
        // End-group without a start, and an unterminated group.
        assert_eq!(
            Message::decode(&[0x0C]),
            Err(ProtoError::UnexpectedEndGroup(1))
        );
        assert_eq!(Message::decode(&[0x0B]), Err(ProtoError::Truncated));
    }

    #[test]
    fn a_field_number_above_the_limit_is_rejected() {
        let mut buf = Vec::new();
        write_tag(&mut buf, MAX_FIELD_NUMBER, WT_VARINT);
        write_varint(&mut buf, 1);
        assert!(Message::decode(&buf).is_ok());

        let mut buf = Vec::new();
        write_varint(&mut buf, u64::from(MAX_FIELD_NUMBER + 1) << 3);
        assert_eq!(
            Message::decode(&buf),
            Err(ProtoError::InvalidFieldNumber(MAX_FIELD_NUMBER + 1))
        );
    }

    #[test]
    fn nested_messages_decode_and_reencode() {
        let inner = Message {
            fields: vec![Field::new(1, Value::Varint(42))],
        };
        let outer = Message {
            fields: vec![Field::new(6, Value::LengthDelimited(inner.encode()))],
        };
        let decoded = Message::decode(&outer.encode()).unwrap();
        assert_eq!(decoded.nested(6).unwrap(), inner);
        assert_eq!(decoded.encode(), outer.encode());
    }

    #[test]
    fn packed_uints_keep_partial_results() {
        let packed = Field::new(1, Value::LengthDelimited(vec![1, 2, 3, 0x80]));
        assert_eq!(collect_packed_uints(&packed), vec![1, 2, 3]);

        assert_eq!(
            collect_packed_uints(&Field::new(1, Value::Varint(7))),
            vec![7]
        );
        assert!(collect_packed_uints(&Field::new(1, Value::Fixed32(1))).is_empty());
    }

    #[test]
    fn large_values_survive_the_round_trip() {
        let msg = Message {
            fields: vec![Field::new(1, Value::Varint(u64::MAX))],
        };
        assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
    }
}
