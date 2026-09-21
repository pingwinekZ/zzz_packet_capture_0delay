//! `src/serialization/zod/` — `IZOD`, `IAgent`, `IDisc`, `IEngine`, `ISubstat`.

use std::collections::BTreeMap;
use std::fmt;

use zzz_crypto::to_zod_key;
use zzz_scan::{rarity_key, AgentInfo, DiscInfo, Inventory, WeaponInfo};

use crate::json;
use crate::names::Names;
use crate::settings::ExportSettings;

/// `IZOD::format`.
pub const ZOD_FORMAT: &str = "ZOD";
/// `IZOD::version`.
pub const ZOD_VERSION: u8 = 1;
/// `IZOD::source`.
pub const ZOD_SOURCE: &str = "ZZZ Packet Capture";

/// How many substat entries the reference writes, always.
const SUBSTAT_SLOTS: usize = 4;

/// The six skill levels `IAgent::fromInstance` reads, by the field each one
/// becomes. The positions are what matter — the game sends skills as a repeated
/// message and the reference indexes the vector — but naming them makes an
/// out-of-range error legible.
const SKILL_POSITIONS: [(usize, &str); 6] = [
    (0, "basic"),
    (1, "special"),
    (2, "dodge"),
    (3, "chain"),
    (4, "core"),
    (5, "assist"),
];

/// `Serialization::Zod::ISubstat`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ISubstat {
    /// `data::statMap`'s name for the stat, e.g. `crit_dmg_`.
    pub key: String,
    /// How many times the substat was upgraded.
    pub upgrades: u32,
}

/// `Serialization::Zod::IDisc`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IDisc {
    pub set_key: String,
    pub slot_key: String,
    pub level: u8,
    pub rarity: String,
    pub main_stat_key: String,
    /// The agent wearing it, or empty when it is in the bag.
    pub location: String,
    pub lock: bool,
    pub trash: bool,
    pub substats: Vec<ISubstat>,
}

/// `Serialization::Zod::IEngine`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IEngine {
    pub key: String,
    pub level: u8,
    pub modification: u8,
    pub phase: u8,
    /// The agent wearing it, or empty when it is in the bag.
    pub location: String,
    pub lock: bool,
    /// The uid the game knows it by, e.g. `zzz_wengine_15031`.
    pub id: String,
}

/// `Serialization::Zod::IAgent`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IAgent {
    /// Always empty. The reference declares the key and never assigns it; the
    /// site needs it present or it sets every skill to level 1.
    pub equipped_engine: String,
    pub key: String,
    pub level: u8,
    pub mindscape: u8,
    /// Zero-based, so the captured value minus one.
    pub promotion: u8,
    /// Zero-based like `promotion`; this is the "core" skill.
    pub core: u8,
    pub dodge: u8,
    pub basic: u8,
    pub chain: u8,
    pub special: u8,
    pub assist: u8,
    /// Always zero: the reference assigns a constant.
    pub potential: u8,
    /// `None` when w-engines were not exported at all, which the site reads as
    /// "leave the previously imported value alone". An empty key means the agent
    /// names an engine that was not in the capture.
    pub wengine_key: Option<String>,
    pub wengine_phase: Option<u8>,
    /// The agent's export key, repeated.
    pub id: String,
}

/// `Serialization::Zod::IZOD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Izod {
    pub format: String,
    pub version: u8,
    pub source: String,
    /// `None` when agents were not exported; `Some(vec![])` when the filter kept
    /// nothing. The site treats those differently.
    pub characters: Option<Vec<IAgent>>,
    pub discs: Option<Vec<IDisc>>,
    pub wengines: Option<Vec<IEngine>>,
}

/// Why an export could not be produced.
///
/// Each variant is a case where the reference throws — `std::map::at`,
/// `std::vector::at` — but where the caller can do something useful instead of
/// losing the process. All of them name the record so the cause is obvious.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// An agent id `nanokaData.json` has no name for.
    UnknownCharacter { id: u32 },
    /// A w-engine id `nanokaData.json` has no name for.
    UnknownWeapon { id: u32 },
    /// A disc set id `nanokaData.json` has no name for.
    UnknownEquipment { set_id: u32 },
    /// A stat id `data::statMap` has no name for.
    UnknownStat { key: u32 },
    /// A disc rarity `keyRarity` has no letter for.
    UnmappedRarity { rarity: u32 },
    /// An agent whose skill list is shorter than the six positions the export
    /// reads.
    MissingSkill {
        agent: u32,
        position: usize,
        len: usize,
    },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCharacter { id } => write!(
                f,
                "agent {id} has no name in the nanoka data; run `zzzcap update` (the game \
                 may also have added an agent the published tables do not have yet)"
            ),
            Self::UnknownWeapon { id } => write!(
                f,
                "w-engine {id} has no name in the nanoka data; run `zzzcap update`"
            ),
            Self::UnknownEquipment { set_id } => write!(
                f,
                "disc set {set_id} has no name in the nanoka data; run `zzzcap update`"
            ),
            Self::UnknownStat { key } => write!(
                f,
                "stat {key} is not in the stat table (`data/statMap.hpp`); the game may \
                 have added one"
            ),
            Self::UnmappedRarity { rarity } => write!(
                f,
                "disc rarity {rarity} has no letter; the reference maps 3, 4 and 5 to B, A \
                 and S, so this disc id is probably being read wrong"
            ),
            Self::MissingSkill {
                agent,
                position,
                len,
            } => {
                let name = skill_position_name(*position).unwrap_or("?");
                write!(
                    f,
                    "agent {agent} arrived with {len} skill entries, so position {position} \
                     ({name}) is missing; the export reads all six positionally"
                )
            }
        }
    }
}

impl std::error::Error for ExportError {}

/// The export field a skill position becomes, for error messages.
fn skill_position_name(position: usize) -> Option<&'static str> {
    SKILL_POSITIONS
        .iter()
        .find(|(index, _)| *index == position)
        .map(|(_, name)| *name)
}

impl Default for Izod {
    fn default() -> Self {
        Self {
            format: ZOD_FORMAT.to_string(),
            version: ZOD_VERSION,
            source: ZOD_SOURCE.to_string(),
            characters: None,
            discs: None,
            wengines: None,
        }
    }
}

impl Izod {
    /// `IZOD::fromPcap`.
    ///
    /// The two maps are built first, over *every* agent and engine, before any
    /// filtering: the settings decide what is written, not what is known, so a
    /// record the floors exclude can still be what another record points at.
    ///
    /// Because those maps need each agent's name, an agent whose id nanoka has
    /// never heard of fails the export even when agents are not being exported.
    /// That is the reference's behaviour — it calls `agent.name()` while filling
    /// the map — and keeping it means "which names are known" has one answer
    /// rather than depending on the flags.
    pub fn from_inventory(
        inventory: &Inventory,
        names: &dyn Names,
        settings: &ExportSettings,
    ) -> Result<Self, ExportError> {
        let mut engine_owner: BTreeMap<u32, String> = BTreeMap::new();
        let mut disc_owner: BTreeMap<u32, String> = BTreeMap::new();
        for agent in &inventory.agents {
            let owner = to_zod_key(character_name(names, agent.id)?);
            // A later agent wins, which matters for the zero uid: every agent
            // with no w-engine writes `engine_owner[0]`, and the reference's
            // `map[key] = value` ends up with the last one of them.
            engine_owner.insert(agent.weapon_uid, owner.clone());
            for equip in &agent.dressed_equips {
                disc_owner.insert(equip.uid, owner.clone());
            }
        }
        let engines_by_uid: BTreeMap<u32, &WeaponInfo> = inventory
            .engines
            .iter()
            .map(|engine| (engine.uid, engine))
            .collect();

        let characters = if settings.export_agents {
            let mut out = Vec::new();
            for agent in &inventory.agents {
                if agent.level < u32::from(settings.min_agent_level) {
                    continue;
                }
                // An unknown rarity cannot be compared, and dropping the record
                // would hide a brand-new agent. It is let through so the key
                // lookup reports the id instead.
                if let Some(rarity) = names.character_rarity(agent.id) {
                    if rarity < u32::from(settings.min_agent_rarity) {
                        continue;
                    }
                }
                out.push(agent_export(
                    agent,
                    &engines_by_uid,
                    names,
                    settings.export_engines,
                )?);
            }
            Some(out)
        } else {
            None
        };

        let discs = if settings.export_discs {
            let mut out = Vec::new();
            for disc in &inventory.discs {
                if disc.level < u32::from(settings.min_disc_level) {
                    continue;
                }
                if disc.rarity() < u32::from(settings.min_disc_rarity) {
                    continue;
                }
                out.push(disc_export(disc, &disc_owner, names)?);
            }
            Some(out)
        } else {
            None
        };

        let wengines = if settings.export_engines {
            let mut out = Vec::new();
            for engine in &inventory.engines {
                if engine.level < u32::from(settings.min_engine_level) {
                    continue;
                }
                if let Some(rarity) = names.weapon_rarity(engine.id) {
                    if rarity < u32::from(settings.min_engine_rarity) {
                        continue;
                    }
                }
                out.push(engine_export(engine, &engine_owner, names)?);
            }
            Some(out)
        } else {
            None
        };

        Ok(Self {
            format: ZOD_FORMAT.to_string(),
            version: ZOD_VERSION,
            source: ZOD_SOURCE.to_string(),
            characters,
            discs,
            wengines,
        })
    }

    /// The payload a *live* client receives: `Home::State::makeLiveZodJson`.
    ///
    /// Two rules separate this from the file export, and both follow from the
    /// optimizer's import being replace-semantics per category — whatever the
    /// payload says is what the account becomes:
    ///
    /// * **The floors are ignored.** `minDiscRarity` and its five siblings are
    ///   zeroed here even when the caller sets them, because a floor would delete
    ///   every record below it from the site's database on the next snapshot. The
    ///   category toggles are still honoured: they are how the user says "stop
    ///   syncing w-engines".
    /// * **An empty category is `null`, never `[]`.** An empty list means
    ///   "everything was deleted"; an absent one means "nothing to say", which
    ///   the site leaves alone. This is the state at the start of a session,
    ///   before the load responses have arrived.
    ///
    /// Note that this makes the payload depend on what the capture has seen so
    /// far, not on what the account owns: a category the game has not sent yet is
    /// a category the site keeps its previous values for.
    pub fn for_live(
        inventory: &Inventory,
        names: &dyn Names,
        settings: &ExportSettings,
    ) -> Result<Self, ExportError> {
        let settings = ExportSettings {
            min_disc_rarity: 0,
            min_disc_level: 0,
            min_engine_rarity: 0,
            min_engine_level: 0,
            min_agent_rarity: 0,
            min_agent_level: 0,
            ..*settings
        };
        let mut zod = Self::from_inventory(inventory, names, &settings)?;
        null_if_empty(&mut zod.characters);
        null_if_empty(&mut zod.discs);
        null_if_empty(&mut zod.wengines);
        Ok(zod)
    }

    /// The JSON the reference writes, byte for byte.
    pub fn to_json(&self) -> String {
        json::object(&[
            ("format", Some(json::string(&self.format))),
            ("version", Some(json::number(self.version))),
            ("source", Some(json::string(&self.source))),
            (
                "characters",
                self.characters
                    .as_ref()
                    .map(|list| json::array(&map_json(list, IAgent::to_json))),
            ),
            (
                "discs",
                self.discs
                    .as_ref()
                    .map(|list| json::array(&map_json(list, IDisc::to_json))),
            ),
            (
                "wengines",
                self.wengines
                    .as_ref()
                    .map(|list| json::array(&map_json(list, IEngine::to_json))),
            ),
        ])
    }
}

fn map_json<T>(items: &[T], encode: fn(&T) -> String) -> Vec<String> {
    items.iter().map(encode).collect()
}

/// Turns an exported-but-empty list into an absent one, which is what a live
/// payload wants: see [`Izod::for_live`].
fn null_if_empty<T>(list: &mut Option<Vec<T>>) {
    if list.as_ref().is_some_and(Vec::is_empty) {
        *list = None;
    }
}

impl ISubstat {
    pub fn to_json(&self) -> String {
        json::object(&[
            ("key", Some(json::string(&self.key))),
            ("upgrades", Some(json::number(self.upgrades))),
        ])
    }
}

impl IDisc {
    /// The key order is the reference's declaration order, and glaze writes
    /// members in that order.
    pub fn to_json(&self) -> String {
        json::object(&[
            ("setKey", Some(json::string(&self.set_key))),
            ("slotKey", Some(json::string(&self.slot_key))),
            ("level", Some(json::number(self.level))),
            ("rarity", Some(json::string(&self.rarity))),
            ("mainStatKey", Some(json::string(&self.main_stat_key))),
            ("location", Some(json::string(&self.location))),
            ("lock", Some(json::boolean(self.lock))),
            ("trash", Some(json::boolean(self.trash))),
            (
                "substats",
                Some(json::array(&map_json(&self.substats, ISubstat::to_json))),
            ),
        ])
    }
}

impl IEngine {
    pub fn to_json(&self) -> String {
        json::object(&[
            ("key", Some(json::string(&self.key))),
            ("level", Some(json::number(self.level))),
            ("modification", Some(json::number(self.modification))),
            ("phase", Some(json::number(self.phase))),
            ("location", Some(json::string(&self.location))),
            ("lock", Some(json::boolean(self.lock))),
            ("id", Some(json::string(&self.id))),
        ])
    }
}

impl IAgent {
    pub fn to_json(&self) -> String {
        json::object(&[
            ("equippedEngine", Some(json::string(&self.equipped_engine))),
            ("key", Some(json::string(&self.key))),
            ("level", Some(json::number(self.level))),
            ("mindscape", Some(json::number(self.mindscape))),
            ("promotion", Some(json::number(self.promotion))),
            ("core", Some(json::number(self.core))),
            ("dodge", Some(json::number(self.dodge))),
            ("basic", Some(json::number(self.basic))),
            ("chain", Some(json::number(self.chain))),
            ("special", Some(json::number(self.special))),
            ("assist", Some(json::number(self.assist))),
            ("potential", Some(json::number(self.potential))),
            (
                "wengineKey",
                self.wengine_key.as_ref().map(|key| json::string(key)),
            ),
            ("wenginePhase", self.wengine_phase.map(json::number)),
            ("id", Some(json::string(&self.id))),
        ])
    }
}
fn character_name(names: &dyn Names, id: u32) -> Result<&str, ExportError> {
    names
        .character_name(id)
        .ok_or(ExportError::UnknownCharacter { id })
}

fn weapon_name(names: &dyn Names, id: u32) -> Result<&str, ExportError> {
    names
        .weapon_name(id)
        .ok_or(ExportError::UnknownWeapon { id })
}

/// `IAgent::fromInstance`.
fn agent_export(
    agent: &AgentInfo,
    engines: &BTreeMap<u32, &WeaponInfo>,
    names: &dyn Names,
    export_engines: bool,
) -> Result<IAgent, ExportError> {
    let key = to_zod_key(character_name(names, agent.id)?);
    let skill = |position: usize| -> Result<u32, ExportError> {
        agent
            .skill_level(position)
            .ok_or(ExportError::MissingSkill {
                agent: agent.id,
                position,
                len: agent.skills.len(),
            })
    };

    let (wengine_key, wengine_phase) = if export_engines {
        match engines.get(&agent.weapon_uid) {
            Some(engine) => (
                Some(to_zod_key(weapon_name(names, engine.id)?)),
                Some(engine.phase as u8),
            ),
            // The agent names a w-engine that never arrived. The reference writes
            // an empty key and phase 1 rather than leaving the fields out, which
            // is how the site is told to clear the slot.
            None => (Some(String::new()), Some(1)),
        }
    } else {
        // Not exported at all: omitted, so the site keeps whatever it has.
        (None, None)
    };

    Ok(IAgent {
        equipped_engine: String::new(),
        key: key.clone(),
        level: agent.level as u8,
        mindscape: agent.mindscape as u8,
        // `promotion` and `core` are zero-based in the export. A captured zero
        // wraps to 255 in the reference (`static_cast<uint8_t>(0 - 1)`), so the
        // subtraction wraps here too instead of panicking.
        promotion: agent.promotion.wrapping_sub(1) as u8,
        core: skill(4)?.wrapping_sub(1) as u8,
        dodge: skill(2)? as u8,
        basic: skill(0)? as u8,
        chain: skill(3)? as u8,
        special: skill(1)? as u8,
        assist: skill(5)? as u8,
        potential: 0,
        wengine_key,
        wengine_phase,
        id: key,
    })
}

/// `IDisc::fromInstance`.
fn disc_export(
    disc: &DiscInfo,
    owners: &BTreeMap<u32, String>,
    names: &dyn Names,
) -> Result<IDisc, ExportError> {
    let set_id = disc.set_id();
    let set_name = names
        .equipment_name(set_id)
        .ok_or(ExportError::UnknownEquipment { set_id })?;
    let rarity = disc.rarity();
    let rarity_letter = rarity_key(rarity).ok_or(ExportError::UnmappedRarity { rarity })?;
    let main_stat_key = disc.main_stat.stat_name().ok_or(ExportError::UnknownStat {
        key: disc.main_stat.key,
    })?;

    // The reference makes four entries and zips the captured substats into them,
    // so fewer than four pads with empty entries and more than four loses the
    // extras. `add_value` is the upgrade count, not the value.
    let mut substats = Vec::with_capacity(SUBSTAT_SLOTS);
    for index in 0..SUBSTAT_SLOTS {
        match disc.sub_stats.get(index) {
            Some(stat) => substats.push(ISubstat {
                key: stat
                    .stat_name()
                    .ok_or(ExportError::UnknownStat { key: stat.key })?
                    .to_string(),
                upgrades: stat.add_value,
            }),
            None => substats.push(ISubstat::default()),
        }
    }

    Ok(IDisc {
        set_key: to_zod_key(set_name),
        slot_key: disc.slot().to_string(),
        level: disc.level as u8,
        rarity: rarity_letter.to_string(),
        main_stat_key: main_stat_key.to_string(),
        location: owners.get(&disc.uid).cloned().unwrap_or_default(),
        lock: false,
        trash: false,
        substats,
    })
}

/// `IEngine::fromInstance`.
fn engine_export(
    engine: &WeaponInfo,
    owners: &BTreeMap<u32, String>,
    names: &dyn Names,
) -> Result<IEngine, ExportError> {
    Ok(IEngine {
        key: to_zod_key(weapon_name(names, engine.id)?),
        level: engine.level as u8,
        modification: engine.modification as u8,
        phase: engine.phase as u8,
        location: owners.get(&engine.uid).cloned().unwrap_or_default(),
        lock: false,
        id: format!("zzz_wengine_{}", engine.uid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use zzz_scan::{AvatarSkillLevel, DiscStat, DressedEquip};

    /// Names fixed in the test, so nothing here needs the nanoka cache.
    #[derive(Default)]
    struct FixedNames {
        characters: BTreeMap<u32, (String, u32)>,
        weapons: BTreeMap<u32, (String, u32)>,
        equipment: BTreeMap<u32, String>,
    }

    impl Names for FixedNames {
        fn character_name(&self, id: u32) -> Option<&str> {
            self.characters.get(&id).map(|(name, _)| name.as_str())
        }

        fn character_rarity(&self, id: u32) -> Option<u32> {
            self.characters.get(&id).map(|(_, rarity)| *rarity)
        }

        fn weapon_name(&self, id: u32) -> Option<&str> {
            self.weapons.get(&id).map(|(name, _)| name.as_str())
        }

        fn weapon_rarity(&self, id: u32) -> Option<u32> {
            self.weapons.get(&id).map(|(_, rarity)| *rarity)
        }

        fn equipment_name(&self, set_id: u32) -> Option<&str> {
            self.equipment.get(&set_id).map(String::as_str)
        }
    }

    /// The names the reference was run with when the expected JSON in
    /// `writes_the_bytes_the_reference_wrote` was captured.
    fn reference_names() -> FixedNames {
        let mut names = FixedNames::default();
        names.characters.insert(1011, ("Anby".into(), 4));
        names.characters.insert(1581, ("Yixuan".into(), 5));
        names.weapons.insert(25, ("[Lunar] Pleniluna".into(), 4));
        names.weapons.insert(15031, ("Deep Sea Visitor".into(), 5));
        names.equipment.insert(31300, "Woodpecker Electro".into());
        names.equipment.insert(31200, "Feathered Fate".into());
        names
    }

    fn agent(id: u32, level: u32) -> AgentInfo {
        AgentInfo {
            id,
            level,
            ..AgentInfo::default()
        }
    }

    /// The shape and field order the reference writes, pinned without a
    /// compiler, a capture or the nanoka cache, so this runs everywhere.
    ///
    /// The expected bytes are what glaze 8.4 — the version the C++ project
    /// builds against — produced for these values when probed directly; the
    /// end-to-end check against the reference's own `IZOD` and `fromInstance`
    /// code is `tests/cpp_export_parity.rs`.
    #[test]
    fn writes_the_shape_the_reference_writes() {
        let names = reference_names();
        let mut skills: Vec<AvatarSkillLevel> = (0..6)
            .map(|kind| AvatarSkillLevel {
                skill_type: kind,
                level: 11,
            })
            .collect();
        skills[4].level = 7; // core is exported zero-based, so this becomes 6

        let inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                level: 60,
                promotion: 6,
                weapon_uid: 25,
                mindscape: 6,
                skills,
                dressed_equips: vec![DressedEquip { uid: 900, slot: 1 }],
            }],
            engines: vec![WeaponInfo {
                id: 25,
                uid: 25,
                level: 60,
                phase: 5,
                modification: 5,
            }],
            discs: vec![DiscInfo {
                uid: 900,
                // 31341: set 31300, rarity digit 4 (band 5, "S"), slot 1.
                id: 31341,
                level: 15,
                main_stat: DiscStat {
                    key: 11103,
                    base_value: 550,
                    add_value: 0,
                },
                sub_stats: vec![
                    DiscStat {
                        key: 21103,
                        base_value: 24,
                        add_value: 2,
                    },
                    DiscStat {
                        // 12102 is `atk_`; 12103 is the flat `atk`.
                        key: 12102,
                        base_value: 19,
                        add_value: 1,
                    },
                ],
            }],
        };

        let zod = Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap();
        assert_eq!(
            zod.to_json(),
            concat!(
                r#"{"format":"ZOD","version":1,"source":"ZZZ Packet Capture","characters":["#,
                r#"{"equippedEngine":"","key":"Anby","level":60,"mindscape":6,"promotion":5,"#,
                r#""core":6,"dodge":11,"basic":11,"chain":11,"special":11,"assist":11,"#,
                r#""potential":0,"wengineKey":"LunarPleniluna","wenginePhase":5,"id":"Anby"}],"#,
                r#""discs":[{"setKey":"WoodpeckerElectro","slotKey":"1","level":15,"rarity":"S","#,
                r#""mainStatKey":"hp","location":"Anby","lock":false,"trash":false,"substats":["#,
                r#"{"key":"crit_dmg_","upgrades":2},{"key":"atk_","upgrades":1},"#,
                r#"{"key":"","upgrades":0},{"key":"","upgrades":0}]}],"#,
                r#""wengines":[{"key":"LunarPleniluna","level":60,"modification":5,"phase":5,"#,
                r#""location":"Anby","lock":false,"id":"zzz_wengine_25"}]}"#,
            )
        );
    }

    #[test]
    fn an_export_with_nothing_selected_omits_the_three_lists() {
        let settings = ExportSettings {
            export_agents: false,
            export_discs: false,
            export_engines: false,
            ..ExportSettings::default()
        };
        let zod =
            Izod::from_inventory(&Inventory::default(), &FixedNames::default(), &settings).unwrap();
        assert_eq!(
            zod.to_json(),
            r#"{"format":"ZOD","version":1,"source":"ZZZ Packet Capture"}"#
        );
    }

    #[test]
    fn an_empty_selection_is_written_as_an_empty_list() {
        // Not the same thing as the case above: an exported-but-empty list tells
        // the site to clear what it has, and the reference distinguishes them.
        let zod = Izod::from_inventory(
            &Inventory::default(),
            &FixedNames::default(),
            &ExportSettings::default(),
        )
        .unwrap();
        assert_eq!(
            zod.to_json(),
            concat!(
                r#"{"format":"ZOD","version":1,"source":"ZZZ Packet Capture","characters":[],"#,
                r#""discs":[],"wengines":[]}"#,
            )
        );
    }

    #[test]
    fn an_agent_wearing_an_engine_that_never_arrived_gets_an_empty_key() {
        // The reference writes "" and phase 1 rather than omitting the fields,
        // which is how the site is told to clear the slot.
        let names = reference_names();
        let inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                level: 60,
                weapon_uid: 999,
                skills: (0..6)
                    .map(|kind| AvatarSkillLevel {
                        skill_type: kind,
                        level: 1,
                    })
                    .collect(),
                ..AgentInfo::default()
            }],
            ..Inventory::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap();
        let agent = &zod.characters.unwrap()[0];
        assert_eq!(agent.wengine_key.as_deref(), Some(""));
        assert_eq!(agent.wengine_phase, Some(1));

        // With w-engines not exported at all the fields are omitted instead.
        let settings = ExportSettings {
            export_engines: false,
            ..ExportSettings::unfiltered()
        };
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        let agent = &zod.characters.unwrap()[0];
        assert_eq!(agent.wengine_key, None);
        assert_eq!(agent.wengine_phase, None);
        assert!(!agent.to_json().contains("wengineKey"));
        assert!(zod.wengines.is_none());
    }

    #[test]
    fn levels_and_counts_truncate_the_way_a_cpp_cast_does() {
        let names = reference_names();
        let inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                // 300 & 0xFF == 44, and 0 - 1 wraps to 255 in a uint8.
                level: 300,
                promotion: 0,
                skills: (0..6)
                    .map(|kind| AvatarSkillLevel {
                        skill_type: kind,
                        level: 0,
                    })
                    .collect(),
                ..AgentInfo::default()
            }],
            engines: vec![WeaponInfo {
                id: 25,
                uid: 7,
                level: 300,
                phase: 300,
                modification: 300,
            }],
            ..Inventory::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap();
        let agent = &zod.characters.unwrap()[0];
        assert_eq!(agent.level, 44);
        assert_eq!(agent.promotion, 255);
        assert_eq!(agent.core, 255, "core is skill 4 minus one, wrapping");
        let engine = &zod.wengines.unwrap()[0];
        assert_eq!(
            (engine.level, engine.phase, engine.modification),
            (44, 44, 44)
        );
    }

    #[test]
    fn substats_are_padded_to_four_and_extra_ones_dropped() {
        let names = reference_names();
        let disc = |subs: Vec<DiscStat>| DiscInfo {
            uid: 1,
            id: 31341,
            level: 15,
            main_stat: DiscStat {
                key: 11103,
                ..DiscStat::default()
            },
            sub_stats: subs,
        };
        let stat = |key: u32, add: u32| DiscStat {
            key,
            base_value: 1,
            add_value: add,
        };

        let inventory = Inventory {
            discs: vec![
                disc(vec![stat(20103, 1)]),
                disc(vec![
                    stat(20103, 1),
                    stat(21103, 2),
                    stat(12102, 3),
                    stat(13102, 4),
                    // A fifth and sixth entry the reference never reads.
                    stat(23103, 5),
                    stat(30502, 6),
                ]),
            ],
            ..Inventory::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap();
        let discs = zod.discs.unwrap();

        assert_eq!(discs[0].substats.len(), 4);
        assert_eq!(discs[0].substats[0].key, "crit_");
        assert_eq!(discs[0].substats[1], ISubstat::default());
        assert_eq!(discs[0].substats[3], ISubstat::default());

        assert_eq!(discs[1].substats.len(), 4);
        assert_eq!(
            discs[1]
                .substats
                .iter()
                .map(|sub| (sub.key.as_str(), sub.upgrades))
                .collect::<Vec<_>>(),
            vec![("crit_", 1), ("crit_dmg_", 2), ("atk_", 3), ("def_", 4),],
            "the fifth and sixth substats are dropped, not merged"
        );
    }

    #[test]
    fn the_floors_keep_and_drop_what_they_should() {
        let names = reference_names();
        let mut inventory = Inventory {
            agents: vec![agent(1011, 60), agent(1581, 1)],
            engines: vec![
                WeaponInfo {
                    id: 25,
                    uid: 25,
                    level: 60,
                    ..WeaponInfo::default()
                },
                WeaponInfo {
                    id: 15031,
                    uid: 15031,
                    level: 0,
                    ..WeaponInfo::default()
                },
            ],
            discs: vec![
                DiscInfo {
                    uid: 1,
                    id: 31341,
                    level: 15,
                    main_stat: DiscStat {
                        key: 11103,
                        ..DiscStat::default()
                    },
                    ..DiscInfo::default()
                },
                DiscInfo {
                    uid: 2,
                    id: 31341,
                    level: 3,
                    main_stat: DiscStat {
                        key: 11103,
                        ..DiscStat::default()
                    },
                    ..DiscInfo::default()
                },
            ],
        };
        for agent in &mut inventory.agents {
            agent.skills = (0..6)
                .map(|kind| AvatarSkillLevel {
                    skill_type: kind,
                    level: 1,
                })
                .collect();
        }

        // Every level floor defaults to 0 and every rarity floor to three stars
        // or the band it names, so with the defaults nothing here is dropped.
        let zod = Izod::from_inventory(&inventory, &names, &ExportSettings::default()).unwrap();
        assert_eq!(zod.characters.as_ref().unwrap().len(), 2);
        assert_eq!(zod.discs.as_ref().unwrap().len(), 2);
        assert_eq!(zod.wengines.as_ref().unwrap().len(), 2);

        // A disc level floor takes the level-3 one, leaving the level-15 disc.
        let settings = ExportSettings {
            min_disc_level: 5,
            ..ExportSettings::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        let discs = zod.discs.unwrap();
        assert_eq!(discs.len(), 1);
        assert_eq!(discs[0].level, 15);

        // A five-star floor takes the four-star agent with it.
        let settings = ExportSettings {
            min_agent_rarity: 5,
            ..ExportSettings::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        let characters = zod.characters.unwrap();
        assert_eq!(characters.len(), 1);
        assert_eq!(characters[0].id, "Yixuan");

        // And a level floor takes the one that never levelled.
        let settings = ExportSettings {
            min_agent_level: 2,
            ..ExportSettings::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        assert_eq!(zod.characters.unwrap()[0].id, "Anby");

        // An engine level floor takes the unlevelled one.
        let settings = ExportSettings {
            min_engine_level: 1,
            ..ExportSettings::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        assert_eq!(zod.wengines.unwrap().len(), 1);

        // A rarity floor above what a disc can be drops all of them.
        let settings = ExportSettings {
            min_disc_rarity: 6,
            ..ExportSettings::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        assert!(zod.discs.unwrap().is_empty());
    }

    #[test]
    fn the_maps_are_built_before_the_filtering() {
        // An engine worn by an agent the agent floor excludes still has to come
        // out with that agent as its location: `IZOD::fromPcap` fills both maps
        // from the unfiltered inventory.
        let names = reference_names();
        let mut inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                level: 1,
                weapon_uid: 25,
                skills: (0..6)
                    .map(|kind| AvatarSkillLevel {
                        skill_type: kind,
                        level: 1,
                    })
                    .collect(),
                ..AgentInfo::default()
            }],
            engines: vec![WeaponInfo {
                id: 25,
                uid: 25,
                level: 60,
                ..WeaponInfo::default()
            }],
            ..Inventory::default()
        };
        let settings = ExportSettings {
            min_agent_level: 60,
            ..ExportSettings::unfiltered()
        };
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        assert!(
            zod.characters.unwrap().is_empty(),
            "the agent is filtered out"
        );
        assert_eq!(zod.wengines.unwrap()[0].location, "Anby");

        // And an unequipped engine has no location at all.
        inventory.engines.push(WeaponInfo {
            id: 25,
            uid: 26,
            level: 60,
            ..WeaponInfo::default()
        });
        let zod = Izod::from_inventory(&inventory, &names, &settings).unwrap();
        let engines = zod.wengines.unwrap();
        assert_eq!(engines[0].location, "Anby");
        assert_eq!(engines[1].location, "");
    }

    #[test]
    fn the_disc_owner_map_is_keyed_by_the_dressed_uid() {
        // `discMap[equip.uid]`, not `discMap[disc.uid]` from the disc's own
        // record — the two happen to be the same number, and this pins that the
        // agent's list is what supplies the location.
        let names = reference_names();
        let inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                level: 60,
                skills: (0..6)
                    .map(|kind| AvatarSkillLevel {
                        skill_type: kind,
                        level: 1,
                    })
                    .collect(),
                dressed_equips: vec![DressedEquip { uid: 900, slot: 1 }],
                ..AgentInfo::default()
            }],
            discs: vec![
                DiscInfo {
                    uid: 900,
                    id: 31341,
                    level: 15,
                    main_stat: DiscStat {
                        key: 11103,
                        ..DiscStat::default()
                    },
                    ..DiscInfo::default()
                },
                DiscInfo {
                    uid: 901,
                    id: 31341,
                    level: 15,
                    main_stat: DiscStat {
                        key: 11103,
                        ..DiscStat::default()
                    },
                    ..DiscInfo::default()
                },
            ],
            ..Inventory::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap();
        let discs = zod.discs.unwrap();
        assert_eq!(discs[0].location, "Anby");
        assert_eq!(discs[1].location, "", "never dressed, so nowhere to be");
    }

    #[test]
    fn an_unknown_id_fails_the_export_by_name() {
        let names = reference_names();
        let bare = |id: u32| AgentInfo {
            id,
            skills: (0..6)
                .map(|kind| AvatarSkillLevel {
                    skill_type: kind,
                    level: 1,
                })
                .collect(),
            ..AgentInfo::default()
        };

        let inventory = Inventory {
            agents: vec![bare(9999)],
            ..Inventory::default()
        };
        assert_eq!(
            Izod::from_inventory(&inventory, &names, &ExportSettings::default()).unwrap_err(),
            ExportError::UnknownCharacter { id: 9999 }
        );

        // Even with agents switched off: the reference dereferences every
        // agent's name while building the engine map.
        let settings = ExportSettings {
            export_agents: false,
            ..ExportSettings::default()
        };
        assert!(Izod::from_inventory(&inventory, &names, &settings).is_err());

        let inventory = Inventory {
            agents: vec![bare(1011)],
            engines: vec![WeaponInfo {
                id: 9999,
                uid: 5,
                level: 60,
                ..WeaponInfo::default()
            }],
            ..Inventory::default()
        };
        assert_eq!(
            Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap_err(),
            ExportError::UnknownWeapon { id: 9999 }
        );

        let inventory = Inventory {
            discs: vec![DiscInfo {
                id: 31991,
                level: 15,
                main_stat: DiscStat {
                    key: 11103,
                    ..DiscStat::default()
                },
                ..DiscInfo::default()
            }],
            ..Inventory::default()
        };
        assert_eq!(
            Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap_err(),
            ExportError::UnknownEquipment { set_id: 31900 }
        );
    }

    #[test]
    fn an_unreadable_stat_or_rarity_fails_the_export() {
        let names = reference_names();
        let inventory = Inventory {
            discs: vec![DiscInfo {
                id: 31341,
                level: 15,
                main_stat: DiscStat {
                    key: 424242,
                    ..DiscStat::default()
                },
                ..DiscInfo::default()
            }],
            ..Inventory::default()
        };
        assert_eq!(
            Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap_err(),
            ExportError::UnknownStat { key: 424242 }
        );

        // A substat is only read for the four slots that are written, so an
        // unreadable one in slot five does not stop the export.
        let inventory = Inventory {
            discs: vec![DiscInfo {
                id: 31341,
                level: 15,
                main_stat: DiscStat {
                    key: 11103,
                    ..DiscStat::default()
                },
                sub_stats: vec![DiscStat {
                    key: 424242,
                    ..DiscStat::default()
                }],
                ..DiscInfo::default()
            }],
            ..Inventory::default()
        };
        assert_eq!(
            Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap_err(),
            ExportError::UnknownStat { key: 424242 }
        );

        // Rarity band 1 has no letter in `keyRarity`: 31301 is set 31300, a
        // rarity digit of 0 (band 1) and slot 1.
        let inventory = Inventory {
            discs: vec![DiscInfo {
                id: 31301,
                level: 15,
                main_stat: DiscStat {
                    key: 11103,
                    ..DiscStat::default()
                },
                ..DiscInfo::default()
            }],
            ..Inventory::default()
        };
        assert_eq!(
            Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap_err(),
            ExportError::UnmappedRarity { rarity: 1 }
        );
    }

    #[test]
    fn an_agent_with_too_few_skills_fails_the_export() {
        let names = reference_names();
        let inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                level: 60,
                // Positions 0..4 are present, so reading position 5 throws in the
                // reference and is reported here.
                skills: (0..5)
                    .map(|kind| AvatarSkillLevel {
                        skill_type: kind,
                        level: 1,
                    })
                    .collect(),
                ..AgentInfo::default()
            }],
            ..Inventory::default()
        };
        let error =
            Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap_err();
        assert_eq!(
            error,
            ExportError::MissingSkill {
                agent: 1011,
                position: 5,
                len: 5
            }
        );
        assert!(error.to_string().contains("assist"), "{error}");
    }

    #[test]
    fn the_live_payload_ignores_the_floors() {
        // A snapshot that applied a floor would delete every record below it from
        // the site, so the floors are zeroed however they were set.
        let names = reference_names();
        let inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                level: 1,
                skills: (0..6)
                    .map(|kind| AvatarSkillLevel {
                        skill_type: kind,
                        level: 1,
                    })
                    .collect(),
                ..AgentInfo::default()
            }],
            discs: vec![DiscInfo {
                uid: 1,
                id: 31341,
                level: 3,
                main_stat: DiscStat {
                    key: 11103,
                    ..DiscStat::default()
                },
                ..DiscInfo::default()
            }],
            ..Inventory::default()
        };

        let floors = ExportSettings {
            min_agent_rarity: 5,
            min_disc_rarity: 5,
            min_disc_level: 10,
            ..ExportSettings::default()
        };

        // The file export with those floors drops both records...
        let file = Izod::from_inventory(&inventory, &names, &floors).unwrap();
        assert!(file.characters.as_ref().unwrap().is_empty());
        assert!(file.discs.as_ref().unwrap().is_empty());
        // ...and the live payload keeps them.
        let live = Izod::for_live(&inventory, &names, &floors).unwrap();
        assert_eq!(live.characters.as_ref().unwrap().len(), 1);
        assert_eq!(live.discs.as_ref().unwrap().len(), 1);
        // A category the capture has nothing for is null rather than empty.
        assert!(live.wengines.is_none());
        assert!(!live.to_json().contains("wengines"));
    }

    #[test]
    fn a_live_payload_sends_nothing_for_a_switched_off_category() {
        let names = reference_names();
        let inventory = Inventory {
            engines: vec![WeaponInfo {
                id: 25,
                uid: 25,
                level: 60,
                ..WeaponInfo::default()
            }],
            ..Inventory::default()
        };
        let settings = ExportSettings {
            export_engines: false,
            ..ExportSettings::default()
        };
        let live = Izod::for_live(&inventory, &names, &settings).unwrap();
        assert!(
            live.wengines.is_none(),
            "switched off, so the site keeps what it has"
        );
        assert!(live.characters.is_none() && live.discs.is_none());
        assert_eq!(
            live.to_json(),
            r#"{"format":"ZOD","version":1,"source":"ZZZ Packet Capture"}"#,
            "a snapshot with nothing in it is still valid JSON the site ignores"
        );

        // With engines on, the empty categories stay null and the engine list
        // arrives — the one difference from the all-off payload above.
        let live = Izod::for_live(&inventory, &names, &ExportSettings::default()).unwrap();
        assert_eq!(live.wengines.as_ref().unwrap().len(), 1);
        assert!(live.characters.is_none());
    }

    #[test]
    fn export_keys_drop_apostrophes_and_hyphens() {
        // `toZodKey` is shared with the rest of the port; what matters here is
        // that every key in the export goes through it.
        let mut names = reference_names();
        names.characters.insert(1011, ("Yanagi's Blade".into(), 5));
        names.equipment.insert(31300, "Branch & Blade Song".into());
        let inventory = Inventory {
            agents: vec![AgentInfo {
                id: 1011,
                level: 60,
                skills: (0..6)
                    .map(|kind| AvatarSkillLevel {
                        skill_type: kind,
                        level: 1,
                    })
                    .collect(),
                ..AgentInfo::default()
            }],
            discs: vec![DiscInfo {
                uid: 1,
                id: 31341,
                level: 15,
                main_stat: DiscStat {
                    key: 11103,
                    ..DiscStat::default()
                },
                ..DiscInfo::default()
            }],
            ..Inventory::default()
        };
        let zod = Izod::from_inventory(&inventory, &names, &ExportSettings::unfiltered()).unwrap();
        assert_eq!(zod.characters.as_ref().unwrap()[0].key, "YanagisBlade");
        assert_eq!(zod.characters.as_ref().unwrap()[0].id, "YanagisBlade");
        assert_eq!(zod.discs.as_ref().unwrap()[0].set_key, "BranchBladeSong");
    }
}
