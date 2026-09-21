//! Port of `src/crypto/xorProtoFields.hpp`.
//!
//! The game obfuscates selected scalar field *values* by XORing them with a
//! constant taken from the datamine; submessages are recursed into by following
//! the descriptor's type name as an entry name, and the rewritten submessage is
//! re-serialised in place.

use crate::proto::{Message, Value};
use crate::protonap::{ProtoEntry, Protonap};

/// Rewrite every field of `message` that `entry` marks as XOR-obfuscated.
///
/// `entry` is the descriptor for the command the message belongs to, as returned
/// by [`Protonap::entry_by_cmd`]; passing `None` (an unknown command) leaves the
/// message untouched, matching the C++ early return.
pub fn xor_proto_fields(message: &mut Message, entry: Option<&ProtoEntry>, nap: &Protonap) {
    let Some(entry) = entry else {
        return;
    };

    for field in message.fields.iter_mut() {
        let Some(descriptor) = entry
            .fields
            .iter()
            .find(|d| i64::from(d.number) == i64::from(field.number))
        else {
            continue;
        };

        // Not a native type and not an enum: treat the payload as a submessage.
        if !descriptor.is_native_type && !descriptor.is_enum {
            if let Value::LengthDelimited(bytes) = &field.value {
                if let Ok(mut nested) = Message::decode(bytes) {
                    xor_proto_fields(&mut nested, nap.entry_by_name(&descriptor.type_name), nap);
                    field.value = Value::LengthDelimited(nested.encode());
                }
            }
            continue;
        }

        // A descriptor without an xor_value means "nothing to do" (0 is a real
        // value in nap.json, so this is `Option`, not a sentinel).
        let Some(xor_value) = descriptor.xor_value else {
            continue;
        };

        match &mut field.value {
            Value::Varint(v) => *v ^= u64::from(xor_value),
            Value::Fixed32(v) => *v ^= xor_value,
            Value::Fixed64(v) => *v ^= u64::from(xor_value),
            // The C++ switch has no case for length-delimited/group, so those
            // fields keep their bytes even when an xor_value is present.
            Value::LengthDelimited(_) | Value::Group(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protonap::ProtoEntryField;

    fn scalar(number: i32, xor_value: Option<u32>) -> ProtoEntryField {
        ProtoEntryField {
            number,
            name: format!("s{number}"),
            type_name: "uint32".into(),
            xor_value,
            is_native_type: true,
            is_enum: false,
            repeated: false,
        }
    }

    fn submessage(number: i32, type_name: &str) -> ProtoEntryField {
        ProtoEntryField {
            number,
            name: format!("m{number}"),
            type_name: type_name.into(),
            xor_value: None,
            is_native_type: false,
            is_enum: false,
            repeated: false,
        }
    }

    fn nap() -> Protonap {
        Protonap::new(vec![
            ProtoEntry {
                cmd_id: Some(100),
                name: "Outer".into(),
                fields: vec![
                    scalar(1, Some(0x1234)),
                    scalar(2, None),
                    submessage(3, "Inner"),
                    scalar(4, Some(0xFF)),
                ],
            },
            ProtoEntry {
                cmd_id: None,
                name: "Inner".into(),
                fields: vec![scalar(1, Some(0xABCD))],
            },
        ])
    }

    #[test]
    fn xors_only_the_values_the_descriptor_marks() {
        let nap = nap();
        let inner = Message {
            fields: vec![crate::proto::Field::new(1, Value::Varint(0x1111))],
        };
        let mut msg = Message {
            fields: vec![
                crate::proto::Field::new(1, Value::Varint(0x0001)),
                crate::proto::Field::new(2, Value::Varint(0x0001)),
                crate::proto::Field::new(3, Value::LengthDelimited(inner.encode())),
                crate::proto::Field::new(9, Value::Varint(0x0001)),
            ],
        };

        xor_proto_fields(&mut msg, nap.entry_by_cmd(100), &nap);

        // Marked scalar: XORed.
        assert_eq!(msg.varint(1), Some(0x0001 ^ 0x1234));
        // Descriptor present but no xor_value: untouched.
        assert_eq!(msg.varint(2), Some(0x0001));
        // Unknown field number: untouched.
        assert_eq!(msg.varint(9), Some(0x0001));
        // Submessage: recursed, inner field XORed.
        let nested = msg.nested(3).unwrap();
        assert_eq!(nested.varint(1), Some(0x1111 ^ 0xABCD));
    }

    #[test]
    fn a_length_delimited_field_with_an_xor_value_keeps_its_bytes() {
        // Matches the missing case in the C++ switch.
        let nap = Protonap::new(vec![ProtoEntry {
            cmd_id: Some(7),
            name: "Odd".into(),
            fields: vec![ProtoEntryField {
                number: 1,
                name: "blob".into(),
                type_name: "bytes".into(),
                xor_value: Some(0xFFFF),
                is_native_type: true,
                is_enum: false,
                repeated: false,
            }],
        }]);
        let mut msg = Message {
            fields: vec![crate::proto::Field::new(
                1,
                Value::LengthDelimited(b"payload".to_vec()),
            )],
        };
        xor_proto_fields(&mut msg, nap.entry_by_cmd(7), &nap);
        assert_eq!(msg.bytes(1), Some(&b"payload"[..]));
    }

    #[test]
    fn enum_fields_are_not_treated_as_submessages() {
        let nap = Protonap::new(vec![ProtoEntry {
            cmd_id: Some(1),
            name: "E".into(),
            fields: vec![ProtoEntryField {
                number: 1,
                name: "e".into(),
                type_name: "Inner".into(),
                xor_value: Some(0x5),
                is_native_type: false,
                is_enum: true,
                repeated: false,
            }],
        }]);
        let mut msg = Message {
            fields: vec![crate::proto::Field::new(1, Value::Varint(0x10))],
        };
        xor_proto_fields(&mut msg, nap.entry_by_cmd(1), &nap);
        assert_eq!(msg.varint(1), Some(0x15));
    }

    #[test]
    fn an_unknown_command_leaves_the_message_alone() {
        let nap = nap();
        let mut msg = Message {
            fields: vec![crate::proto::Field::new(1, Value::Varint(0x0001))],
        };
        let before = msg.clone();
        xor_proto_fields(&mut msg, nap.entry_by_cmd(4242), &nap);
        assert_eq!(msg, before);
    }

    #[test]
    fn xor_is_involutive_for_varints() {
        let nap = nap();
        let original = Message {
            fields: vec![crate::proto::Field::new(1, Value::Varint(0xDEAD_BEEF))],
        };
        let mut msg = original.clone();
        xor_proto_fields(&mut msg, nap.entry_by_cmd(100), &nap);
        xor_proto_fields(&mut msg, nap.entry_by_cmd(100), &nap);
        assert_eq!(msg, original);
    }
}
