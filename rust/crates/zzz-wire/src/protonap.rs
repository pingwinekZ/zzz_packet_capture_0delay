//! Port of `src/serialization/proto.hpp` — the `nap.json` descriptor index.
//!
//! `nap.json` is the reverse-engineered field map: for each command id it lists
//! every field number, its (obfuscated) name, its type, and the value it is XORed
//! with. It is generated per game version, so the lookups here have to behave
//! exactly like the C++ ones even in the odd cases (duplicate names, entries with
//! a null `cmd_id`).

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ProtoEntryField {
    #[serde(default)]
    pub number: i32,
    #[serde(default)]
    pub name: String,
    /// Type name: a scalar (`uint32`, `string`, ...) or, for submessages, the
    /// name of the entry this field's message type maps to.
    #[serde(rename = "type", default)]
    pub type_name: String,
    #[serde(default)]
    pub xor_value: Option<u32>,
    #[serde(default)]
    pub is_native_type: bool,
    #[serde(default)]
    pub is_enum: bool,
    #[serde(default)]
    pub repeated: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtoEntry {
    #[serde(default)]
    pub cmd_id: Option<u16>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub fields: Vec<ProtoEntryField>,
}

/// `serialization::Proto`.
#[derive(Debug, Default)]
pub struct Protonap {
    entries: Vec<ProtoEntry>,
    /// `entries[i].cmd_id.unwrap_or(0)`, kept in the same order as `entries` so
    /// `entry_by_cmd` can binary search it exactly like `std::lower_bound`.
    cmd_keys: Vec<u32>,
    by_name: HashMap<String, usize>,
}

impl Protonap {
    pub fn new(mut entries: Vec<ProtoEntry>) -> Self {
        for entry in entries.iter_mut() {
            entry.fields.sort_by_key(|f| f.number);
        }
        // `std::sort` is not stable, so among equal keys the C++ order is
        // unspecified; a stable sort at least keeps behaviour deterministic.
        entries.sort_by_key(|e| e.cmd_id.unwrap_or(0));
        let cmd_keys = entries
            .iter()
            .map(|e| u32::from(e.cmd_id.unwrap_or(0)))
            .collect();

        let mut by_name = HashMap::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            // `populateEntriesByName` overwrites, so the last entry wins.
            by_name.insert(entry.name.clone(), index);
        }

        Self {
            entries,
            cmd_keys,
            by_name,
        }
    }

    pub fn entries(&self) -> &[ProtoEntry] {
        &self.entries
    }

    /// `Proto::getEntryById`. Note the original returns a pointer into a sorted
    /// array and compares `cmd_id.value_or(0)`, so entries with a null `cmd_id`
    /// are reachable as command 0 — preserved here.
    pub fn entry_by_cmd(&self, cmd_id: u16) -> Option<&ProtoEntry> {
        let wanted = u32::from(cmd_id);
        let index = self.cmd_keys.partition_point(|&key| key < wanted);
        let entry = self.entries.get(index)?;
        if u32::from(entry.cmd_id.unwrap_or(0)) == wanted {
            Some(entry)
        } else {
            None
        }
    }

    /// `Proto::getEntryByName`.
    pub fn entry_by_name(&self, name: &str) -> Option<&ProtoEntry> {
        self.by_name.get(name).map(|&index| &self.entries[index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cmd_id: Option<u16>, name: &str, numbers: &[i32]) -> ProtoEntry {
        ProtoEntry {
            cmd_id,
            name: name.to_string(),
            fields: numbers
                .iter()
                .map(|&number| ProtoEntryField {
                    number,
                    name: format!("f{number}"),
                    type_name: "uint32".into(),
                    xor_value: None,
                    is_native_type: true,
                    is_enum: false,
                    repeated: false,
                })
                .collect(),
        }
    }

    fn nap() -> Protonap {
        Protonap::new(vec![
            entry(Some(1175), "PlayerSyncScNotify", &[15, 9]),
            entry(Some(4937), "PlayerGetTokenScRsp", &[1]),
            entry(None, "NoCmd", &[1]),
            entry(Some(2470), "GetAvatarDataScRsp", &[2, 1, 3]),
        ])
    }

    #[test]
    fn lookups_by_cmd_id_work_regardless_of_input_order() {
        let nap = nap();
        assert_eq!(nap.entry_by_cmd(1175).unwrap().name, "PlayerSyncScNotify");
        assert_eq!(nap.entry_by_cmd(2470).unwrap().name, "GetAvatarDataScRsp");
        assert!(nap.entry_by_cmd(9999).is_none());
    }

    #[test]
    fn fields_are_sorted_by_number_like_the_cpp_version() {
        let nap = nap();
        let numbers: Vec<i32> = nap
            .entry_by_cmd(1175)
            .unwrap()
            .fields
            .iter()
            .map(|f| f.number)
            .collect();
        assert_eq!(numbers, vec![9, 15]);
    }

    #[test]
    fn names_are_indexed_with_last_write_wins() {
        let nap = Protonap::new(vec![
            entry(Some(1), "Dup", &[1]),
            entry(Some(2), "Dup", &[1]),
        ]);
        assert_eq!(nap.entry_by_name("Dup").unwrap().cmd_id, Some(2));
        assert!(nap.entry_by_name("Nope").is_none());
    }

    #[test]
    fn null_cmd_id_entries_are_reachable_as_command_zero() {
        // Matches `cmd_id.value_or(0)` in the original.
        let nap = nap();
        assert_eq!(nap.entry_by_cmd(0).unwrap().name, "NoCmd");
    }

    #[test]
    fn parses_the_real_shape_of_nap_json() {
        // First entry of the committed assets/nap.json, verbatim.
        let json = r#"[{"name":"CKLPODCNKJB","cmd_id":null,"fields":[
            {"number":2,"name":"OIOGINEENIN","type":"uint32","repeated":true,"is_native_type":true,"is_enum":false,"xor_value":0},
            {"number":11,"name":"BDADLDPMIFP","type":"uint32","repeated":false,"is_native_type":true,"is_enum":false,"xor_value":5927}]}]"#;
        let entries: Vec<ProtoEntry> = serde_json::from_str(json).unwrap();
        let nap = Protonap::new(entries);
        let entry = nap.entry_by_name("CKLPODCNKJB").unwrap();
        assert_eq!(entry.cmd_id, None);
        assert_eq!(entry.fields.len(), 2);
        assert_eq!(entry.fields[1].xor_value, Some(5927));
    }

    #[test]
    fn parses_a_submessage_field() {
        // Submessage fields carry the target entry's name in "type".
        let json = r#"[{"name":"Outer","cmd_id":10,"fields":[
            {"number":1,"name":"Inner","type":"InnerType","repeated":false,"is_native_type":false,"is_enum":false}]},
            {"name":"InnerType","cmd_id":null,"fields":[]}]"#;
        let nap = Protonap::new(serde_json::from_str(json).unwrap());
        let field = &nap.entry_by_cmd(10).unwrap().fields[0];
        assert_eq!(field.type_name, "InnerType");
        assert_eq!(field.xor_value, None);
        assert!(nap.entry_by_name(&field.type_name).is_some());
    }
}
