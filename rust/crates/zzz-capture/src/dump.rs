//! The recorded-capture file, in the format `pcap.hpp`'s
//! `storeCapturePacketsToFile` writes:
//!
//! ```json
//! {"packets":[{"direction":0,"timestamp":1758300000,"data":[1,2,3]}]}
//! ```
//!
//! Reading tolerates `direction` as either the numeric enum value or the word
//! `"incoming"`/`"outgoing"`, because which of the two the C++ serialiser emits
//! depends on how glaze is configured and this file is our hand-off format.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{Direction, Packet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpPacket {
    /// 0 = incoming, 1 = outgoing.
    #[serde(serialize_with = "serialize_direction")]
    #[serde(deserialize_with = "deserialize_direction")]
    pub direction: u8,
    pub timestamp: i64,
    pub data: Vec<u8>,
}

impl DumpPacket {
    pub fn direction(&self) -> Direction {
        if self.direction == 1 {
            Direction::Outgoing
        } else {
            Direction::Incoming
        }
    }
}

fn serialize_direction<S: serde::Serializer>(direction: &u8, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u8(*direction)
}

fn deserialize_direction<'de, D: Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    use serde::de::Error;
    use serde_json::Value;

    match Value::deserialize(d)? {
        Value::Number(n) => n
            .as_u64()
            .map(|n| n as u8)
            .ok_or_else(|| D::Error::custom("direction is not an integer")),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "incoming" => Ok(0),
            "outgoing" => Ok(1),
            other => Err(D::Error::custom(format!("unknown direction {other:?}"))),
        },
        other => Err(D::Error::custom(format!(
            "direction must be a number or a name, got {other}"
        ))),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dump {
    #[serde(default)]
    pub packets: Vec<DumpPacket>,
}

#[derive(Debug)]
pub enum DumpError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl fmt::Display for DumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Json { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for DumpError {}

impl Dump {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn push(&mut self, packet: &Packet) {
        self.packets.push(DumpPacket {
            direction: match packet.direction {
                Direction::Outgoing => 1,
                Direction::Incoming => 0,
            },
            timestamp: packet.timestamp,
            data: packet.data.clone(),
        });
    }

    /// Total payload bytes captured, for progress reporting.
    pub fn payload_bytes(&self) -> usize {
        self.packets.iter().map(|p| p.data.len()).sum()
    }

    /// Replay the dump as packets, in capture order.
    pub fn iter_packets(&self) -> impl Iterator<Item = Packet> + '_ {
        self.packets.iter().map(|p| Packet {
            direction: p.direction(),
            timestamp: p.timestamp,
            data: p.data.clone(),
        })
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn save(&self, path: &Path) -> Result<(), DumpError> {
        let json = self.to_json().map_err(|source| DumpError::Json {
            path: path.to_path_buf(),
            source,
        })?;
        std::fs::write(path, json).map_err(|source| DumpError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn load(path: &Path) -> Result<Self, DumpError> {
        let json = std::fs::read_to_string(path).map_err(|source| DumpError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&json).map_err(|source| DumpError::Json {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direction_of(json: &str) -> u8 {
        Dump::from_json(json).unwrap().packets[0].direction
    }

    #[test]
    fn round_trips_through_the_cpp_format() {
        let mut dump = Dump::new();
        dump.push(&Packet {
            direction: Direction::Outgoing,
            timestamp: 1_758_300_000,
            data: vec![1, 2, 3],
        });
        dump.push(&Packet {
            direction: Direction::Incoming,
            timestamp: 1_758_300_001,
            data: vec![],
        });

        let json = dump.to_json().unwrap();
        assert_eq!(
            json,
            r#"{"packets":[{"direction":1,"timestamp":1758300000,"data":[1,2,3]},{"direction":0,"timestamp":1758300001,"data":[]}]}"#
        );
        assert_eq!(Dump::from_json(&json).unwrap(), dump);
        assert_eq!(dump.payload_bytes(), 3);

        let replayed: Vec<Packet> = dump.iter_packets().collect();
        assert_eq!(replayed[0].direction, Direction::Outgoing);
        assert_eq!(replayed[1].data, Vec::<u8>::new());
    }

    #[test]
    fn accepts_a_numeric_direction() {
        assert_eq!(
            direction_of(r#"{"packets":[{"direction":0,"timestamp":1,"data":[]}]}"#),
            0
        );
        assert_eq!(
            direction_of(r#"{"packets":[{"direction":1,"timestamp":1,"data":[]}]}"#),
            1
        );
    }

    #[test]
    fn accepts_a_named_direction_and_bad_capitalisation() {
        assert_eq!(
            direction_of(r#"{"packets":[{"direction":"incoming","timestamp":1,"data":[]}]}"#),
            0
        );
        assert_eq!(
            direction_of(r#"{"packets":[{"direction":"Outgoing","timestamp":1,"data":[]}]}"#),
            1
        );
    }

    #[test]
    fn rejects_a_direction_it_cannot_interpret() {
        assert!(Dump::from_json(
            r#"{"packets":[{"direction":"sideways","timestamp":1,"data":[]}]}"#
        )
        .is_err());
        assert!(
            Dump::from_json(r#"{"packets":[{"direction":null,"timestamp":1,"data":[]}]}"#).is_err()
        );
    }

    #[test]
    fn tolerates_missing_and_extra_keys() {
        // An empty file is an empty capture, not an error.
        assert!(Dump::from_json("{}").unwrap().is_empty());
        assert!(Dump::from_json(r#"{"packets":[]}"#).unwrap().is_empty());
        // Unknown keys, as a future C++ version might add, are ignored.
        let dump = Dump::from_json(
            r#"{"version":2,"packets":[{"direction":0,"timestamp":5,"data":[9],"note":"x"}]}"#,
        )
        .unwrap();
        assert_eq!(dump.len(), 1);
        assert_eq!(dump.packets[0].data, vec![9]);
    }

    #[test]
    fn summarises_size_for_progress_output() {
        let dump = Dump::from_json(
            r#"{"packets":[{"direction":0,"timestamp":1,"data":[1,2,3,4]},{"direction":1,"timestamp":2,"data":[5]}]}"#,
        )
        .unwrap();
        assert_eq!(dump.payload_bytes(), 5);
    }
}
