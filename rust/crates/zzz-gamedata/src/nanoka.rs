//! `static.nanoka.cc` lookup tables: agent and w-engine display names plus the
//! rarity ("rank") of each.
//!
//! These are keyed by the ids that appear in packets. The C++ version uses
//! `std::map::at`, which throws — and therefore kills the process — the moment a
//! game update introduces an id nanoka has not published yet. Here the lookups
//! return `Option` so a brand-new agent degrades to an unnamed entry instead of
//! taking the capture down with it.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

pub const MANIFEST_URL: &str = "https://static.nanoka.cc/manifest.json";

pub fn character_url(version: &str) -> String {
    format!("https://static.nanoka.cc/zzz/{version}/character.json")
}

pub fn equipment_url(version: &str) -> String {
    format!("https://static.nanoka.cc/zzz/{version}/equipment.json")
}

pub fn weapon_url(version: &str) -> String {
    format!("https://static.nanoka.cc/zzz/{version}/weapon.json")
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct Character {
    /// 0-based rarity, so `rank + 1` is the in-game star rating.
    #[serde(default)]
    pub rank: u32,
    #[serde(default)]
    pub en: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct Weapon {
    #[serde(default)]
    pub rank: u32,
    #[serde(default)]
    pub en: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct EquipmentName {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct Equipment {
    #[serde(default)]
    pub en: EquipmentName,
}

pub type Characters = BTreeMap<u32, Character>;
pub type Weapons = BTreeMap<u32, Weapon>;
pub type Equipments = BTreeMap<u32, Equipment>;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NanokaData {
    /// The `zzz.live` version these tables were fetched for.
    pub version: String,
    pub characters: Characters,
    pub weapons: Weapons,
    pub equipment: Equipments,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NanokaManifest {
    pub zzz: NanokaZzz,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct NanokaZzz {
    #[serde(default)]
    pub live: String,
}

impl NanokaManifest {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let zzz = serde_json::from_str::<NanokaZzzWrapper>(json)?.zzz;
        Ok(Self { zzz })
    }
}

#[derive(Deserialize)]
struct NanokaZzzWrapper {
    #[serde(default)]
    zzz: NanokaZzz,
}

impl NanokaData {
    /// Build from the three per-version files.
    pub fn from_json(
        version: &str,
        characters: &str,
        weapons: &str,
        equipment: &str,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            version: version.to_string(),
            characters: serde_json::from_str(characters)?,
            weapons: serde_json::from_str(weapons)?,
            equipment: serde_json::from_str(equipment)?,
        })
    }

    pub fn character_name(&self, id: u32) -> Option<&str> {
        self.characters.get(&id).map(|c| c.en.as_str())
    }

    /// `rank + 1`, the number the export filters compare against.
    pub fn character_rarity(&self, id: u32) -> Option<u32> {
        self.characters.get(&id).map(|c| c.rank + 1)
    }

    pub fn weapon_name(&self, id: u32) -> Option<&str> {
        self.weapons.get(&id).map(|w| w.en.as_str())
    }

    pub fn weapon_rarity(&self, id: u32) -> Option<u32> {
        self.weapons.get(&id).map(|w| w.rank + 1)
    }

    pub fn equipment_name(&self, id: u32) -> Option<&str> {
        self.equipment.get(&id).map(|e| e.en.name.as_str())
    }
}

impl fmt::Display for NanokaData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "nanoka {} ({} agents, {} w-engines, {} sets)",
            self.version,
            self.characters.len(),
            self.weapons.len(),
            self.equipment.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_three_files() {
        let characters = r#"{"1581":{"rank":4,"en":"Yixuan"},"1441":{"rank":3,"en":"Anby"}}"#;
        let weapons = r#"{"14911":{"rank":4,"en":"Boisterous Echoes"}}"#;
        let equipment = r#"{"31000":{"en":{"name":"Branch & Blade Song"}}}"#;

        let data = NanokaData::from_json("3.2", characters, weapons, equipment).unwrap();
        assert_eq!(data.character_name(1581), Some("Yixuan"));
        // rank is 0-based in the source data; the export filter wants 1-based.
        assert_eq!(data.character_rarity(1581), Some(5));
        assert_eq!(data.character_rarity(1441), Some(4));
        assert_eq!(data.weapon_name(14911), Some("Boisterous Echoes"));
        assert_eq!(data.weapon_rarity(14911), Some(5));
        assert_eq!(data.equipment_name(31000), Some("Branch & Blade Song"));
    }

    #[test]
    fn unknown_ids_return_none_instead_of_panicking() {
        // This is the case the C++ `std::map::at` throws on.
        let data = NanokaData::from_json("3.2", "{}", "{}", "{}").unwrap();
        assert_eq!(data.character_name(9999), None);
        assert_eq!(data.character_rarity(9999), None);
        assert_eq!(data.weapon_name(9999), None);
        assert_eq!(data.equipment_name(9999), None);
    }

    #[test]
    fn tolerates_extra_keys_and_missing_ones() {
        // The live files carry more per entry than we read, and glaze is
        // configured with error_on_unknown_keys = false; serde ignores extras by
        // default, so the same data must still parse.
        let characters =
            r#"{"1581":{"rank":4,"en":"Yixuan","extra":{"nested":true},"tags":["a"]}}"#;
        let data = NanokaData::from_json("3.2", characters, "{}", "{}").unwrap();
        assert_eq!(data.character_name(1581), Some("Yixuan"));

        let characters = r#"{"1581":{"en":"Yixuan"}}"#;
        let data = NanokaData::from_json("3.2", characters, "{}", "{}").unwrap();
        assert_eq!(data.character_rarity(1581), Some(1));
    }

    #[test]
    fn parses_the_nanoka_manifest() {
        let manifest = NanokaManifest::parse(r#"{"zzz":{"live":"3.2"},"other":1}"#).unwrap();
        assert_eq!(manifest.zzz.live, "3.2");
        // A missing zzz block must not fail; the C++ falls back to an empty one.
        let manifest = NanokaManifest::parse("{}").unwrap();
        assert!(manifest.zzz.live.is_empty());
    }

    #[test]
    fn builds_the_versioned_urls() {
        assert_eq!(
            character_url("3.2"),
            "https://static.nanoka.cc/zzz/3.2/character.json"
        );
        assert_eq!(
            weapon_url("3.2"),
            "https://static.nanoka.cc/zzz/3.2/weapon.json"
        );
        assert_eq!(
            equipment_url("3.2"),
            "https://static.nanoka.cc/zzz/3.2/equipment.json"
        );
    }
}
