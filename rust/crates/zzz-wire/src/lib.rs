//! Everything between "a UDP payload arrived" and "here is a decoded command":
//! KCP segment reassembly, a schema-free protobuf reader/writer, the per-command
//! field-number XOR, and the `nap.json` descriptor index.
//!
//! The C++ build pays for libprotobuf + upb + protoc to get
//! `google::protobuf::UnknownFieldSet`. The tool never has a schema for these
//! messages — it walks unknown fields and rewrites selected field numbers — so
//! `proto::Message` is a small direct replacement.

pub mod kcp;
pub mod proto;
pub mod protonap;
pub mod xor_fields;

pub use kcp::{Direction, Kcp, KcpStats, MessageHeader, SegmentHeader, MESSAGE_HEADER_SIZE};
pub use proto::{collect_packed_uints, Field, Message, ProtoError, Value};
pub use protonap::{ProtoEntry, ProtoEntryField, Protonap};
pub use xor_fields::xor_proto_fields;
