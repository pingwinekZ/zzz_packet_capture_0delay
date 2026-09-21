//! Port of `src/data/disc.hpp`, `engine.hpp`, `agent.hpp` and `statMap.hpp`.
//!
//! These are the shapes the UI and the ZOD export consume, parsed out of the
//! schema-free protobuf messages by field number, with every number taken from
//! `assets/datamine.json` so a game update stays a data change.
//!
//! Two deviations from the original, both deliberate and both about not dying:
//!
//! * `statMap.at(key)` throws for an id the table does not have, and
//!   `NanokaData::get()....at(id)` throws for an id nanoka has not published.
//!   A lookup returns `Option` here, so a new stat or a brand-new w-engine
//!   degrades to an unnamed entry.
//! * The C++ calls `UnknownField::varint()` / `length_delimited()` without
//!   checking the wire type, which is undefined behaviour when it does not
//!   match. Fields are type-checked here. On well-formed packets the two agree.

use zzz_gamedata::Datamine;
use zzz_wire::proto::{Message, Value};

/// `data::StatInfo`. The name comes from the table, not from the game.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatInfo {
    pub name: &'static str,
    /// Percentages are sent in hundredths, so the display value is `v / 100`.
    pub is_percentage: bool,
}

/// `data::statMap` — the complete stat id mapping. Kept as a table rather than a
/// `match` because it is data, and because the test asserts every entry.
pub const STAT_MAP: &[(u32, &str, bool)] = &[
    (11102, "hp_", true),
    (11103, "hp", false),
    (12102, "atk_", true),
    (12103, "atk", false),
    (12202, "impact_", true),
    (13102, "def_", true),
    (13103, "def", false),
    (20103, "crit_", true),
    (21103, "crit_dmg_", true),
    (23103, "pen_", true),
    (23203, "pen", false),
    (30502, "enerRegen_", true),
    (31203, "anomProf", false),
    (31402, "anomMas_", true),
    (31503, "physical_dmg_", true),
    (31603, "fire_dmg_", true),
    (31703, "ice_dmg_", true),
    (31803, "electric_dmg_", true),
    (31903, "ether_dmg_", true),
    (32303, "wind_dmg_", true),
];

/// `data::statMap.at(key)`, without the throw.
pub fn stat_info(key: u32) -> Option<StatInfo> {
    STAT_MAP
        .iter()
        .find(|(id, _, _)| *id == key)
        .map(|(_, name, is_percentage)| StatInfo {
            name,
            is_percentage: *is_percentage,
        })
}

/// `Serialization::Zod::keyRarity` — the letter the export writes for a rarity.
///
/// The original indexes this with `disc.getRarity()` and throws on anything
/// missing, so the bands it knows about are exactly 3, 4 and 5. A disc whose id
/// falls outside that is reported as unknown rather than killing the export.
pub fn rarity_key(rarity: u32) -> Option<&'static str> {
    match rarity {
        3 => Some("B"),
        4 => Some("A"),
        5 => Some("S"),
        _ => None,
    }
}

/// The last varint carried under a field number.
///
/// The original assigns on every match, so the last occurrence wins. A match
/// whose wire type is not a varint is skipped rather than read as one.
fn last_varint(message: &Message, number: u32) -> Option<u64> {
    message
        .fields
        .iter()
        .rev()
        .filter(|field| field.number == number)
        .find_map(|field| field.value.as_varint())
}

/// A scalar field, defaulting to zero the way the original's members do.
fn varint_field(message: &Message, number: u32) -> u32 {
    last_varint(message, number).unwrap_or(0) as u32
}

/// A nested message field.
///
/// `None` means the wire type was not length-delimited (the original would read
/// undefined memory). `Some(default)` means the payload did not parse, which the
/// original reports as an empty nested struct.
fn nested_or_default(value: &Value) -> Option<Message> {
    let bytes = value.as_bytes()?;
    Some(Message::decode(bytes).unwrap_or_default())
}

/// `data::DiscStat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscStat {
    pub key: u32,
    pub base_value: u32,
    pub add_value: u32,
}

impl DiscStat {
    pub fn from_message(message: &Message, datamine: &Datamine) -> Self {
        Self {
            key: varint_field(message, datamine.disc_stat.key),
            base_value: varint_field(message, datamine.disc_stat.base_value),
            add_value: varint_field(message, datamine.disc_stat.add_value),
        }
    }

    /// `DiscStat::getStatName`.
    pub fn stat_name(&self) -> Option<&'static str> {
        stat_info(self.key).map(|info| info.name)
    }

    /// Whether the value is a percentage, and therefore sent in hundredths.
    pub fn is_percentage(&self) -> bool {
        stat_info(self.key).is_some_and(|info| info.is_percentage)
    }
}

/// `data::DiscInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscInfo {
    pub uid: u32,
    pub id: u32,
    pub level: u32,
    pub main_stat: DiscStat,
    pub sub_stats: Vec<DiscStat>,
}

impl DiscInfo {
    /// `getRarity` — 1-based, encoded in the id.
    pub fn rarity(&self) -> u32 {
        self.id / 10 % 10 + 1
    }

    /// `getSlot` — 1..=6, encoded in the id.
    pub fn slot(&self) -> u32 {
        self.id % 10
    }

    /// `getSet` — the disc set id, which is the id with the slot and rarity
    /// digits stripped. This is the key `data::DiscInfo::getSetName` looks up.
    pub fn set_id(&self) -> u32 {
        self.id / 100 * 100
    }

    pub fn from_message(message: &Message, datamine: &Datamine) -> Self {
        let mut disc = Self::default();
        for field in &message.fields {
            if field.number == datamine.disc_info.uid {
                disc.uid = varint_field(message, field.number);
            } else if field.number == datamine.disc_info.id {
                disc.id = varint_field(message, field.number);
            } else if field.number == datamine.disc_info.level {
                disc.level = varint_field(message, field.number);
            } else if field.number == datamine.disc_info.main_stat {
                if let Some(nested) = nested_or_default(&field.value) {
                    disc.main_stat = DiscStat::from_message(&nested, datamine);
                }
            } else if field.number == datamine.disc_info.sub_stats {
                if let Some(nested) = nested_or_default(&field.value) {
                    disc.sub_stats
                        .push(DiscStat::from_message(&nested, datamine));
                }
            }
        }
        disc
    }
}

/// `data::WeaponInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WeaponInfo {
    pub id: u32,
    pub uid: u32,
    pub level: u32,
    pub phase: u32,
    pub modification: u32,
}

impl WeaponInfo {
    pub fn from_message(message: &Message, datamine: &Datamine) -> Self {
        Self {
            id: varint_field(message, datamine.weapon_info.id),
            uid: varint_field(message, datamine.weapon_info.uid),
            level: varint_field(message, datamine.weapon_info.level),
            phase: varint_field(message, datamine.weapon_info.phase),
            modification: varint_field(message, datamine.weapon_info.modification),
        }
    }
}

/// `data::AvatarSkillLevel`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AvatarSkillLevel {
    pub skill_type: u32,
    pub level: u32,
}

impl AvatarSkillLevel {
    pub fn from_message(message: &Message, datamine: &Datamine) -> Self {
        Self {
            skill_type: varint_field(message, datamine.agent_skill.skill_type),
            level: varint_field(message, datamine.agent_skill.level),
        }
    }
}

/// `data::DressedEquip`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DressedEquip {
    pub uid: u32,
    pub slot: u32,
}

impl DressedEquip {
    pub fn from_message(message: &Message, datamine: &Datamine) -> Self {
        Self {
            uid: varint_field(message, datamine.agent_equip.uid),
            slot: varint_field(message, datamine.agent_equip.slot),
        }
    }
}

/// `data::AgentInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentInfo {
    pub id: u32,
    pub level: u32,
    pub promotion: u32,
    pub weapon_uid: u32,
    pub mindscape: u32,
    pub skills: Vec<AvatarSkillLevel>,
    pub dressed_equips: Vec<DressedEquip>,
}

impl AgentInfo {
    /// The level of one skill, by the position the export reads it from.
    ///
    /// `IAgent::fromInstance` indexes `skills` positionally — 0 basic, 1 special,
    /// 2 dodge, 3 chain, 4 core, 5 assist — and `.at()` throws if the agent came
    /// with fewer entries than that.
    pub fn skill_level(&self, position: usize) -> Option<u32> {
        self.skills.get(position).map(|skill| skill.level)
    }

    pub fn from_message(message: &Message, datamine: &Datamine) -> Self {
        let mut agent = Self::default();
        for field in &message.fields {
            if field.number == datamine.agent_info.id {
                agent.id = varint_field(message, field.number);
            } else if field.number == datamine.agent_info.level {
                agent.level = varint_field(message, field.number);
            } else if field.number == datamine.agent_info.promotion {
                agent.promotion = varint_field(message, field.number);
            } else if field.number == datamine.agent_info.weapon_uid {
                agent.weapon_uid = varint_field(message, field.number);
            } else if field.number == datamine.agent_info.mindscape {
                agent.mindscape = varint_field(message, field.number);
            } else if field.number == datamine.agent_info.skills {
                if let Some(nested) = nested_or_default(&field.value) {
                    agent
                        .skills
                        .push(AvatarSkillLevel::from_message(&nested, datamine));
                }
            } else if field.number == datamine.agent_info.dressed_equips {
                if let Some(nested) = nested_or_default(&field.value) {
                    agent
                        .dressed_equips
                        .push(DressedEquip::from_message(&nested, datamine));
                }
            }
        }
        agent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zzz_wire::proto::Field;

    fn datamine() -> Datamine {
        Datamine::parse(include_str!("../../../../assets/datamine.json")).expect("assets")
    }

    #[test]
    fn the_stat_table_matches_the_cpp_header() {
        assert_eq!(STAT_MAP.len(), 20);
        assert_eq!(
            stat_info(11102),
            Some(StatInfo {
                name: "hp_",
                is_percentage: true
            })
        );
        assert_eq!(
            stat_info(31203),
            Some(StatInfo {
                name: "anomProf",
                is_percentage: false
            })
        );
        // Unknown ids return None rather than throwing like `std::map::at`.
        assert_eq!(stat_info(0), None);
        // Names are unique, which is what makes them usable as export keys.
        let mut names: Vec<&str> = STAT_MAP.iter().map(|(_, name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), STAT_MAP.len());
    }

    #[test]
    fn disc_ids_decode_into_rarity_slot_and_set() {
        // 31244 is set 31200, rarity digit 4, slot 4. The digit is a rarity
        // *band*, not an index: `RarityKey.hpp` maps the resulting 5 to "S" and
        // 3/4 to "B"/"A", so the export's `keyRarity.at()` needs 3..=5.
        let disc = DiscInfo {
            id: 31244,
            ..DiscInfo::default()
        };
        assert_eq!(disc.set_id(), 31200);
        assert_eq!(disc.rarity(), 5);
        assert_eq!(disc.slot(), 4);

        let disc = DiscInfo {
            id: 31003,
            ..DiscInfo::default()
        };
        assert_eq!(disc.set_id(), 31000);
        assert_eq!(disc.rarity(), 1);
        assert_eq!(disc.slot(), 3);

        // `keyRarity` has no entry below 3, which is where the export throws.
        assert_eq!(rarity_key(3), Some("B"));
        assert_eq!(rarity_key(5), Some("S"));
        assert_eq!(rarity_key(1), None);
    }

    #[test]
    fn parses_a_disc_with_a_main_stat_and_substats() {
        let datamine = datamine();
        let stat = |key: u32, base: u64, add: u64| Message {
            fields: vec![
                Field::new(datamine.disc_stat.key, Value::Varint(u64::from(key))),
                Field::new(datamine.disc_stat.base_value, Value::Varint(base)),
                Field::new(datamine.disc_stat.add_value, Value::Varint(add)),
            ],
        };
        let message = Message {
            fields: vec![
                Field::new(datamine.disc_info.uid, Value::Varint(15916)),
                Field::new(datamine.disc_info.id, Value::Varint(31204)),
                Field::new(datamine.disc_info.level, Value::Varint(15)),
                Field::new(
                    datamine.disc_info.main_stat,
                    Value::LengthDelimited(stat(11103, 550, 0).encode()),
                ),
                Field::new(
                    datamine.disc_info.sub_stats,
                    Value::LengthDelimited(stat(20103, 240, 2).encode()),
                ),
                Field::new(
                    datamine.disc_info.sub_stats,
                    Value::LengthDelimited(stat(12103, 19, 0).encode()),
                ),
            ],
        };

        let disc = DiscInfo::from_message(&message, &datamine);
        assert_eq!(disc.uid, 15916);
        assert_eq!(disc.id, 31204);
        assert_eq!(disc.level, 15);
        assert_eq!(disc.main_stat.stat_name(), Some("hp"));
        assert_eq!(disc.main_stat.base_value, 550);
        assert_eq!(disc.sub_stats.len(), 2);
        assert_eq!(disc.sub_stats[0].stat_name(), Some("crit_"));
        assert!(disc.sub_stats[0].is_percentage());
        assert_eq!(disc.sub_stats[0].add_value, 2);
        assert_eq!(disc.sub_stats[1].stat_name(), Some("atk"));
        // An id the table does not know is reported, not fatal.
        let unknown = DiscStat {
            key: 999_999,
            ..DiscStat::default()
        };
        assert_eq!(unknown.stat_name(), None);
        assert!(!unknown.is_percentage());
    }

    #[test]
    fn a_scalar_field_takes_the_last_occurrence() {
        let datamine = datamine();
        let message = Message {
            fields: vec![
                Field::new(datamine.disc_info.uid, Value::Varint(1)),
                Field::new(datamine.disc_info.uid, Value::Varint(2)),
            ],
        };
        assert_eq!(DiscInfo::from_message(&message, &datamine).uid, 2);

        // A field of the wrong wire type is ignored rather than read as a varint.
        let message = Message {
            fields: vec![Field::new(
                datamine.disc_info.uid,
                Value::LengthDelimited(vec![1, 2, 3]),
            )],
        };
        assert_eq!(DiscInfo::from_message(&message, &datamine).uid, 0);
    }

    #[test]
    fn an_unparseable_nested_stat_becomes_an_empty_one() {
        // The original's `DiscStat::fromBytes` returns `{}` when the nested
        // `ParseFromString` fails, so the entry still exists.
        let datamine = datamine();
        let message = Message {
            fields: vec![
                Field::new(
                    datamine.disc_info.main_stat,
                    Value::LengthDelimited(vec![0xFF, 0xFF]),
                ),
                Field::new(
                    datamine.disc_info.sub_stats,
                    Value::LengthDelimited(vec![0xFF, 0xFF]),
                ),
            ],
        };
        let disc = DiscInfo::from_message(&message, &datamine);
        assert_eq!(disc.main_stat, DiscStat::default());
        assert_eq!(disc.sub_stats.len(), 1);
        assert_eq!(disc.sub_stats[0], DiscStat::default());
    }

    #[test]
    fn parses_agents_engines_and_their_nested_entries() {
        let datamine = datamine();
        let skill = |kind: u64, level: u64| {
            Message {
                fields: vec![
                    Field::new(datamine.agent_skill.skill_type, Value::Varint(kind)),
                    Field::new(datamine.agent_skill.level, Value::Varint(level)),
                ],
            }
            .encode()
        };
        let equip = Message {
            fields: vec![
                Field::new(datamine.agent_equip.uid, Value::Varint(77)),
                Field::new(datamine.agent_equip.slot, Value::Varint(3)),
            ],
        }
        .encode();

        let agent_message = Message {
            fields: vec![
                Field::new(datamine.agent_info.id, Value::Varint(1581)),
                Field::new(datamine.agent_info.level, Value::Varint(60)),
                Field::new(datamine.agent_info.promotion, Value::Varint(6)),
                Field::new(datamine.agent_info.weapon_uid, Value::Varint(15031)),
                Field::new(datamine.agent_info.mindscape, Value::Varint(2)),
                Field::new(
                    datamine.agent_info.skills,
                    Value::LengthDelimited(skill(0, 12)),
                ),
                Field::new(
                    datamine.agent_info.skills,
                    Value::LengthDelimited(skill(1, 11)),
                ),
                Field::new(
                    datamine.agent_info.dressed_equips,
                    Value::LengthDelimited(equip),
                ),
            ],
        };
        let agent = AgentInfo::from_message(&agent_message, &datamine);
        assert_eq!(agent.id, 1581);
        assert_eq!(agent.level, 60);
        assert_eq!(agent.promotion, 6);
        assert_eq!(agent.weapon_uid, 15031);
        assert_eq!(agent.mindscape, 2);
        assert_eq!(agent.skills.len(), 2);
        assert_eq!(agent.skill_level(0), Some(12));
        assert_eq!(agent.skill_level(1), Some(11));
        // The export indexes six skills positionally; a short list is `None`.
        assert_eq!(agent.skill_level(5), None);
        assert_eq!(
            agent.dressed_equips,
            vec![DressedEquip { uid: 77, slot: 3 }]
        );

        let weapon_message = Message {
            fields: vec![
                Field::new(datamine.weapon_info.id, Value::Varint(15031)),
                Field::new(datamine.weapon_info.uid, Value::Varint(15031)),
                Field::new(datamine.weapon_info.level, Value::Varint(60)),
                Field::new(datamine.weapon_info.phase, Value::Varint(1)),
                Field::new(datamine.weapon_info.modification, Value::Varint(5)),
            ],
        };
        let weapon = WeaponInfo::from_message(&weapon_message, &datamine);
        assert_eq!(
            weapon,
            WeaponInfo {
                id: 15031,
                uid: 15031,
                level: 60,
                phase: 1,
                modification: 5,
            }
        );
    }
}
