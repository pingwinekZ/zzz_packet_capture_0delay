//! `assets/datamine.json` — the per-game-version reverse engineering results.
//!
//! Every field number the parser needs lives here so a game update is a data
//! change rather than a code change. The keys in the file are a mix of camelCase
//! and snake_case, so each field names its key explicitly.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AvatarSkillLevel {
    #[serde(rename = "skill_type")]
    pub skill_type: u32,
    pub level: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DressedEquip {
    pub uid: u32,
    pub slot: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AgentInfoFields {
    pub id: u32,
    pub level: u32,
    pub promotion: u32,
    #[serde(rename = "weaponUid")]
    pub weapon_uid: u32,
    pub mindscape: u32,
    pub skills: u32,
    #[serde(rename = "dressed_equips")]
    pub dressed_equips: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AgentData {
    pub agents: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EquipData {
    pub discs: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WeaponData {
    pub weapons: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DiscStatFields {
    pub key: u32,
    #[serde(rename = "base_value")]
    pub base_value: u32,
    #[serde(rename = "add_value")]
    pub add_value: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DiscInfoFields {
    pub uid: u32,
    pub id: u32,
    pub level: u32,
    #[serde(rename = "mainStat")]
    pub main_stat: u32,
    #[serde(rename = "subStats")]
    pub sub_stats: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WeaponInfoFields {
    pub id: u32,
    pub uid: u32,
    pub level: u32,
    pub phase: u32,
    pub modification: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SyncAvatarData {
    #[serde(rename = "avatarSync")]
    pub avatar_sync: u32,
    pub avatars: u32,
    pub dels: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SyncItemData {
    #[serde(rename = "itemSync")]
    pub item_sync: u32,
    pub equips: u32,
    pub weapons: u32,
    #[serde(rename = "deletedEquips")]
    pub deleted_equips: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EquipDismantle {
    pub uid: u32,
    pub uids: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Datamine {
    /// Region name -> 16-hex-digit XOR seed.
    #[serde(rename = "xorSeeds")]
    pub xor_seeds: BTreeMap<String, String>,

    #[serde(rename = "cmdPlayerGetTokenScRsp")]
    pub cmd_player_get_token_sc_rsp: u32,
    #[serde(rename = "cmdGetEquipDataScRsp")]
    pub cmd_get_equip_data_sc_rsp: u32,
    #[serde(rename = "cmdGetWeaponDataScRsp")]
    pub cmd_get_weapon_data_sc_rsp: u32,
    #[serde(rename = "cmdGetAvatarDataScRsp")]
    pub cmd_get_avatar_data_sc_rsp: u32,
    #[serde(rename = "cmdPlayerSyncScNotify")]
    pub cmd_player_sync_sc_notify: u32,
    #[serde(rename = "cmdDismantleEquipCsReq")]
    pub cmd_dismantle_equip_cs_req: u32,

    #[serde(rename = "syncAvatarData")]
    pub sync_avatar_data: SyncAvatarData,
    #[serde(rename = "syncItemData")]
    pub sync_item_data: SyncItemData,
    #[serde(rename = "equipDismantle")]
    pub equip_dismantle: EquipDismantle,

    #[serde(rename = "agentData")]
    pub agent_data: AgentData,
    #[serde(rename = "agentInfo")]
    pub agent_info: AgentInfoFields,
    #[serde(rename = "agentSkill")]
    pub agent_skill: AvatarSkillLevel,
    #[serde(rename = "agentEquip")]
    pub agent_equip: DressedEquip,

    #[serde(rename = "equipData")]
    pub equip_data: EquipData,
    #[serde(rename = "discInfo")]
    pub disc_info: DiscInfoFields,
    #[serde(rename = "discStat")]
    pub disc_stat: DiscStatFields,

    #[serde(rename = "weaponData")]
    pub weapon_data: WeaponData,
    #[serde(rename = "weaponInfo")]
    pub weapon_info: WeaponInfoFields,
}

impl Datamine {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The 16-hex-digit seed for a region, parsed the way the C++ does with
    /// `std::stoull(seed, nullptr, 16)`.
    pub fn seed_for_region(&self, region: &str) -> Option<u64> {
        let seed = self.xor_seeds.get(region)?;
        u64::from_str_radix(seed.trim(), 16).ok()
    }

    /// Reverse lookup, as used to preselect the region once a seed is known.
    pub fn region_for_seed(&self, seed: u64) -> Option<&str> {
        self.xor_seeds
            .iter()
            .find(|(_, value)| u64::from_str_radix(value.trim(), 16) == Ok(seed))
            .map(|(region, _)| region.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_committed_file() {
        let json = include_str!("../../../../assets/datamine.json");
        let datamine = Datamine::parse(json).expect("assets/datamine.json parses");

        assert_eq!(datamine.cmd_player_get_token_sc_rsp, 4937);
        assert_eq!(datamine.cmd_player_sync_sc_notify, 1175);
        assert_eq!(datamine.sync_item_data.deleted_equips, 8);
        assert_eq!(datamine.agent_info.weapon_uid, 12);
        assert_eq!(datamine.disc_stat.add_value, 7);
        assert_eq!(datamine.xor_seeds.len(), 4);
    }

    #[test]
    fn region_seeds_round_trip() {
        let datamine = Datamine::parse(include_str!("../../../../assets/datamine.json")).unwrap();
        let seed = datamine.seed_for_region("Europe").unwrap();
        assert_eq!(seed, 0x9543_521F_C9C8_CAED);
        assert_eq!(datamine.region_for_seed(seed), Some("Europe"));
        assert_eq!(datamine.seed_for_region("Nope"), None);

        // The region name with punctuation in it is a real key.
        assert_eq!(
            datamine.seed_for_region("TW,HK,MO"),
            Some(0x883B_2720_4BF7_25D3)
        );
    }
}
