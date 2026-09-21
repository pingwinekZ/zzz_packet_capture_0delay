//! Port of `src/pcap/sync.hpp` plus the extraction the message handler in
//! `src/pcap/pcap.hpp` does inline.
//!
//! The original splits this in two: a `SyncApplier` constructed per message that
//! borrows the three vectors `Pcap` owns, and a handful of `if (commandId == ...)`
//! blocks in `processMessageBody` that upsert straight into the same vectors.
//! [`Inventory`] owns the state and carries all of it, so replaying a dump leaves
//! a value behind instead of a pile of side effects on a capture object.
//!
//! The command ids and field numbers all come from `assets/datamine.json`, so a
//! game update is a data change. The one piece of genuine trickiness is the
//! fallback in [`Inventory::apply_item_sync`]: when the `deletedEquips` field
//! moved between versions the original starts probing *every other* field of
//! `ItemSync` for a uid it recognises, and says so when it hits. That is how the
//! new field number gets discovered, and it is kept intact.

use zzz_gamedata::Datamine;
use zzz_wire::proto::{Message, Value};

use crate::model::{AgentInfo, DiscInfo, WeaponInfo};

/// `pcap::SyncResult`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncResult {
    /// Whether anything was inserted, replaced or removed.
    pub changed: bool,
    /// Entries inserted or replaced.
    pub upserts: u32,
    /// Entries removed.
    pub removals: u32,
}

impl SyncResult {
    fn absorb(&mut self, other: Self) {
        self.changed |= other.changed;
        self.upserts += other.upserts;
        self.removals += other.removals;
    }
}

/// One item-level change, for a live view of *what* changed.
///
/// The summary counters say how much moved; these say what. An equip move, a
/// dismantled disc, a new pull — each becomes one of these, in capture order.
/// Names are attached by the caller (the GUI, mostly) because `zzz-scan` has no
/// access to the name tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemChange {
    /// A disc arrived for the first time: a new pull, or the login's own load.
    DiscAdded {
        uid: u32,
        id: u32,
        level: u32,
        rarity: u32,
    },
    /// A disc's record changed: levelled up, or re-rolled its stats.
    DiscUpdated {
        uid: u32,
        id: u32,
        level: u32,
        rarity: u32,
    },
    /// A disc left the inventory: dismantled, consumed, or traded in.
    DiscRemoved { uid: u32, id: u32 },
    /// A w-engine arrived for the first time.
    EngineAdded {
        uid: u32,
        id: u32,
        level: u32,
        phase: u32,
    },
    /// A w-engine's record changed.
    EngineUpdated {
        uid: u32,
        id: u32,
        level: u32,
        phase: u32,
    },
    /// A w-engine left the inventory.
    EngineRemoved { uid: u32, id: u32 },
    /// An agent arrived for the first time.
    AgentAdded {
        id: u32,
        level: u32,
        weapon_uid: u32,
    },
    /// An agent's record changed — level, mindscape, or the w-engine they wear.
    AgentUpdated {
        id: u32,
        level: u32,
        /// The engine they wore before this change, if they wore one.
        previous_weapon_uid: u32,
        weapon_uid: u32,
    },
    /// An agent left the inventory. In practice this does not happen — the game
    /// keeps owned agents — but the sync carries it, so it is reported.
    AgentRemoved { id: u32 },
}

impl ItemChange {
    /// The disc uid the change is about, when it is a disc change.
    pub fn disc_uid(&self) -> Option<u32> {
        match self {
            Self::DiscAdded { uid, .. }
            | Self::DiscUpdated { uid, .. }
            | Self::DiscRemoved { uid, .. } => Some(*uid),
            _ => None,
        }
    }

    /// The w-engine uid the change is about, when it is an engine change.
    pub fn engine_uid(&self) -> Option<u32> {
        match self {
            Self::EngineAdded { uid, .. }
            | Self::EngineUpdated { uid, .. }
            | Self::EngineRemoved { uid, .. } => Some(*uid),
            _ => None,
        }
    }

    /// The agent id the change is about, when it is an agent change.
    pub fn agent_id(&self) -> Option<u32> {
        match self {
            Self::AgentAdded { id, .. }
            | Self::AgentUpdated { id, .. }
            | Self::AgentRemoved { id } => Some(*id),
            _ => None,
        }
    }
}

/// Something an extraction pass did that is worth reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractEvent {
    /// `PlayerSyncScNotify`.
    PlayerSync(SyncResult),
    /// `DismantleEquipCsReq`.
    Dismantle(SyncResult),
    /// A load response carried the whole inventory: `GetEquipDataScRsp`.
    Discs { upserted: usize },
    /// `GetWeaponDataScRsp`.
    Weapons { upserted: usize },
    /// `GetAvatarDataScRsp`.
    Avatars { upserted: usize },
    /// The `deletedEquips` field number moved and a uid was recognised in
    /// another field of `ItemSync`. The C++ prints this line, and it is how the
    /// next game version's field number gets found, so it is kept as an event.
    FallbackRemoval { uid: u32, field: u32 },
    /// Every item-level change a message produced, in field order. Emitted for
    /// every extraction message, including the initial load responses — the
    /// consumer can show or suppress those with the `load` event alongside.
    Changes(Vec<ItemChange>),
}

/// What a whole replay extracted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExtractSummary {
    pub player_syncs: u64,
    pub sync_upserts: u64,
    pub sync_removals: u64,
    pub dismantles: u64,
    pub dismantle_removals: u64,
    pub disc_loads: u64,
    pub weapon_loads: u64,
    pub avatar_loads: u64,
    /// Every fallback removal, in capture order. Bounded by how often the
    /// original's probe actually matched, which is rare.
    pub fallback_removals: Vec<(u32, u32)>,
    // The item-level counters, filled by `Changes` events. `*_added` counts
    // records that were not there before, which during a login includes the
    // whole inventory.
    pub discs_added: u64,
    pub discs_updated: u64,
    pub discs_removed: u64,
    pub engines_added: u64,
    pub engines_updated: u64,
    pub engines_removed: u64,
    pub agents_added: u64,
    pub agents_updated: u64,
    pub agents_removed: u64,
}

impl ExtractSummary {
    /// Fold one pass's events in.
    pub fn absorb(&mut self, events: &[ExtractEvent]) {
        for event in events {
            match event {
                ExtractEvent::PlayerSync(result) => {
                    self.player_syncs += 1;
                    self.sync_upserts += u64::from(result.upserts);
                    self.sync_removals += u64::from(result.removals);
                }
                ExtractEvent::Dismantle(result) => {
                    self.dismantles += 1;
                    self.dismantle_removals += u64::from(result.removals);
                }
                ExtractEvent::Discs { .. } => self.disc_loads += 1,
                ExtractEvent::Weapons { .. } => self.weapon_loads += 1,
                ExtractEvent::Avatars { .. } => self.avatar_loads += 1,
                ExtractEvent::FallbackRemoval { uid, field } => {
                    self.fallback_removals.push((*uid, *field));
                }
                ExtractEvent::Changes(changes) => {
                    for change in changes {
                        match change {
                            ItemChange::DiscAdded { .. } => self.discs_added += 1,
                            ItemChange::DiscUpdated { .. } => self.discs_updated += 1,
                            ItemChange::DiscRemoved { .. } => self.discs_removed += 1,
                            ItemChange::EngineAdded { .. } => self.engines_added += 1,
                            ItemChange::EngineUpdated { .. } => self.engines_updated += 1,
                            ItemChange::EngineRemoved { .. } => self.engines_removed += 1,
                            ItemChange::AgentAdded { .. } => self.agents_added += 1,
                            ItemChange::AgentUpdated { .. } => self.agents_updated += 1,
                            ItemChange::AgentRemoved { .. } => self.agents_removed += 1,
                        }
                    }
                }
            }
        }
    }
}

/// The player's discs, w-engines and agents.
///
/// Whether an upsert added a record or replaced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    Added,
    Updated,
}

/// Upserts keep the original's semantics exactly, which means an upsert reports
/// `true` even when the entry is identical to the one it replaced. That is
/// deliberate there — it drives a UI refresh, and a false negative would leave
/// the window stale — so it is not "optimised" away here.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub discs: Vec<DiscInfo>,
    pub engines: Vec<WeaponInfo>,
    pub agents: Vec<AgentInfo>,
}

impl Inventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.discs.is_empty() && self.engines.is_empty() && self.agents.is_empty()
    }

    /// `SyncApplier::upsertDisc`.
    ///
    /// The `bool` is the reference's "did this count as a change"; the [`Upsert`]
    /// says whether it was an addition or a replacement, which the change log
    /// needs and the counters summarize.
    pub fn upsert_disc(&mut self, disc: DiscInfo) -> (bool, Upsert) {
        match self.discs.iter_mut().find(|held| held.uid == disc.uid) {
            Some(held) => {
                let kind = Upsert::Updated;
                *held = disc;
                (true, kind)
            }
            None => {
                self.discs.push(disc);
                (true, Upsert::Added)
            }
        }
    }

    /// `SyncApplier::upsertEngine`.
    pub fn upsert_engine(&mut self, engine: WeaponInfo) -> (bool, Upsert) {
        match self.engines.iter_mut().find(|held| held.uid == engine.uid) {
            Some(held) => {
                let kind = Upsert::Updated;
                *held = engine;
                (true, kind)
            }
            None => {
                self.engines.push(engine);
                (true, Upsert::Added)
            }
        }
    }

    /// `SyncApplier::upsertAgent`.
    ///
    /// Unlike the item upserts this one reports the engine the agent wore before,
    /// because "who equips the w-engine" is the question the change log exists
    /// to answer.
    pub fn upsert_agent(&mut self, agent: AgentInfo) -> (bool, Upsert, u32) {
        match self.agents.iter_mut().find(|held| held.id == agent.id) {
            Some(held) => {
                let previous = held.weapon_uid;
                let kind = Upsert::Updated;
                *held = agent;
                (true, kind, previous)
            }
            None => {
                self.agents.push(agent);
                (true, Upsert::Added, 0)
            }
        }
    }

    pub fn remove_disc(&mut self, uid: u32) -> bool {
        match self.discs.iter().position(|held| held.uid == uid) {
            Some(index) => {
                self.discs.remove(index);
                true
            }
            None => false,
        }
    }

    pub fn remove_engine(&mut self, uid: u32) -> bool {
        match self.engines.iter().position(|held| held.uid == uid) {
            Some(index) => {
                self.engines.remove(index);
                true
            }
            None => false,
        }
    }

    pub fn remove_agent(&mut self, id: u32) -> bool {
        match self.agents.iter().position(|held| held.id == id) {
            Some(index) => {
                self.agents.remove(index);
                true
            }
            None => false,
        }
    }

    /// `SyncApplier::applyPlayerSync` — `PlayerSyncScNotify`.
    ///
    /// Only length-delimited fields are considered, as in the original.
    pub fn apply_player_sync(
        &mut self,
        message: &Message,
        datamine: &Datamine,
        events: &mut Vec<ExtractEvent>,
        changes: &mut Vec<ItemChange>,
    ) -> SyncResult {
        let mut result = SyncResult::default();
        for field in &message.fields {
            let Some(nested) = field.value.as_message() else {
                continue;
            };
            if field.number == datamine.sync_avatar_data.avatar_sync {
                result.absorb(self.apply_avatar_sync(&nested, datamine, changes));
            } else if field.number == datamine.sync_item_data.item_sync {
                result.absorb(self.apply_item_sync(&nested, datamine, events, changes));
            }
        }
        result
    }

    /// `SyncApplier::applyAvatarSync`.
    fn apply_avatar_sync(
        &mut self,
        message: &Message,
        datamine: &Datamine,
        changes: &mut Vec<ItemChange>,
    ) -> SyncResult {
        let mut result = SyncResult::default();
        for field in &message.fields {
            if field.number == datamine.sync_avatar_data.avatars {
                if let Some(nested) = field.value.as_message() {
                    let agent = AgentInfo::from_message(&nested, datamine);
                    let (changed, kind, previous) = self.upsert_agent(agent.clone());
                    if changed {
                        result.changed = true;
                        result.upserts += 1;
                    }
                    changes.push(match kind {
                        Upsert::Added => ItemChange::AgentAdded {
                            id: agent.id,
                            level: agent.level,
                            weapon_uid: agent.weapon_uid,
                        },
                        Upsert::Updated => ItemChange::AgentUpdated {
                            id: agent.id,
                            level: agent.level,
                            previous_weapon_uid: previous,
                            weapon_uid: agent.weapon_uid,
                        },
                    });
                }
            } else if field.number == datamine.sync_avatar_data.dels {
                for id in collect_uints(&field.value) {
                    if self.remove_agent(id) {
                        result.changed = true;
                        result.removals += 1;
                        changes.push(ItemChange::AgentRemoved { id });
                    }
                }
            }
        }
        result
    }

    /// `SyncApplier::applyItemSync`.
    fn apply_item_sync(
        &mut self,
        message: &Message,
        datamine: &Datamine,
        events: &mut Vec<ExtractEvent>,
        changes: &mut Vec<ItemChange>,
    ) -> SyncResult {
        let mut result = SyncResult::default();
        for field in &message.fields {
            if field.number == datamine.sync_item_data.equips {
                if let Some(nested) = field.value.as_message() {
                    let disc = DiscInfo::from_message(&nested, datamine);
                    let (changed, kind) = self.upsert_disc(disc.clone());
                    if changed {
                        result.changed = true;
                        result.upserts += 1;
                    }
                    changes.push(match kind {
                        Upsert::Added => ItemChange::DiscAdded {
                            uid: disc.uid,
                            id: disc.id,
                            level: disc.level,
                            rarity: disc.rarity(),
                        },
                        Upsert::Updated => ItemChange::DiscUpdated {
                            uid: disc.uid,
                            id: disc.id,
                            level: disc.level,
                            rarity: disc.rarity(),
                        },
                    });
                }
            } else if field.number == datamine.sync_item_data.weapons {
                if let Some(nested) = field.value.as_message() {
                    let engine = WeaponInfo::from_message(&nested, datamine);
                    let (changed, kind) = self.upsert_engine(engine.clone());
                    if changed {
                        result.changed = true;
                        result.upserts += 1;
                    }
                    changes.push(match kind {
                        Upsert::Added => ItemChange::EngineAdded {
                            uid: engine.uid,
                            id: engine.id,
                            level: engine.level,
                            phase: engine.phase,
                        },
                        Upsert::Updated => ItemChange::EngineUpdated {
                            uid: engine.uid,
                            id: engine.id,
                            level: engine.level,
                            phase: engine.phase,
                        },
                    });
                }
            } else if field.number == datamine.sync_item_data.deleted_equips {
                for uid in collect_uints(&field.value) {
                    let removed = self.discs.iter().find(|disc| disc.uid == uid).cloned();
                    if self.remove_disc(uid) {
                        result.changed = true;
                        result.removals += 1;
                        let (id, _) = removed
                            .map(|disc| (disc.id, disc))
                            .unwrap_or((0, DiscInfo::default()));
                        changes.push(ItemChange::DiscRemoved { uid, id });
                    }
                }
            } else {
                // The bring-up fallback: an unknown field may carry deleted disc
                // uids under a new number. It only acts on a uid it recognises,
                // so a hit is evidence rather than a guess.
                if !matches!(field.value, Value::Varint(_) | Value::LengthDelimited(_)) {
                    continue;
                }
                for uid in collect_uints(&field.value) {
                    let removed = self.discs.iter().find(|disc| disc.uid == uid).cloned();
                    if self.remove_disc(uid) {
                        result.changed = true;
                        result.removals += 1;
                        events.push(ExtractEvent::FallbackRemoval {
                            uid,
                            field: field.number,
                        });
                        changes.push(ItemChange::DiscRemoved {
                            uid,
                            id: removed.map_or(0, |disc| disc.id),
                        });
                    }
                }
            }
        }
        result
    }

    /// `SyncApplier::applyEquipDismantle` — `DismantleEquipCsReq`.
    ///
    /// Note the original's `removeDisc(uid) | removeEngine(uid)`: a bitwise or, so
    /// *both* are attempted and a uid present in both lists is removed from both.
    /// Short-circuiting here would change behaviour.
    pub fn apply_equip_dismantle(
        &mut self,
        message: &Message,
        datamine: &Datamine,
        changes: &mut Vec<ItemChange>,
    ) -> SyncResult {
        let mut result = SyncResult::default();
        let mut uids = Vec::new();
        for field in &message.fields {
            if field.number == datamine.equip_dismantle.uid
                || field.number == datamine.equip_dismantle.uids
            {
                uids.extend(collect_uints(&field.value));
            }
        }
        for uid in uids {
            let disc = self.discs.iter().find(|disc| disc.uid == uid).cloned();
            let engine = self.engines.iter().find(|held| held.uid == uid).cloned();
            let removed_disc = self.remove_disc(uid);
            let removed_engine = self.remove_engine(uid);
            if removed_disc | removed_engine {
                result.changed = true;
                result.removals += 1;
            }
            if removed_disc {
                changes.push(ItemChange::DiscRemoved {
                    uid,
                    id: disc.map_or(0, |disc| disc.id),
                });
            }
            if removed_engine {
                changes.push(ItemChange::EngineRemoved {
                    uid,
                    id: engine.map_or(0, |engine| engine.id),
                });
            }
        }
        result
    }

    /// `cmdGetEquipDataScRsp`: the whole disc inventory arrives as repeated
    /// nested `equipData.discs`.
    pub fn apply_equip_data(
        &mut self,
        message: &Message,
        datamine: &Datamine,
        changes: &mut Vec<ItemChange>,
    ) -> usize {
        let mut upserted = 0;
        for field in &message.fields {
            if field.number != datamine.equip_data.discs {
                continue;
            }
            if let Some(nested) = field.value.as_message() {
                let disc = DiscInfo::from_message(&nested, datamine);
                let (_, kind) = self.upsert_disc(disc.clone());
                changes.push(match kind {
                    Upsert::Added => ItemChange::DiscAdded {
                        uid: disc.uid,
                        id: disc.id,
                        level: disc.level,
                        rarity: disc.rarity(),
                    },
                    Upsert::Updated => ItemChange::DiscUpdated {
                        uid: disc.uid,
                        id: disc.id,
                        level: disc.level,
                        rarity: disc.rarity(),
                    },
                });
                upserted += 1;
            }
        }
        upserted
    }

    /// `cmdGetWeaponDataScRsp`.
    pub fn apply_weapon_data(
        &mut self,
        message: &Message,
        datamine: &Datamine,
        changes: &mut Vec<ItemChange>,
    ) -> usize {
        let mut upserted = 0;
        for field in &message.fields {
            if field.number != datamine.weapon_data.weapons {
                continue;
            }
            if let Some(nested) = field.value.as_message() {
                let engine = WeaponInfo::from_message(&nested, datamine);
                let (_, kind) = self.upsert_engine(engine.clone());
                changes.push(match kind {
                    Upsert::Added => ItemChange::EngineAdded {
                        uid: engine.uid,
                        id: engine.id,
                        level: engine.level,
                        phase: engine.phase,
                    },
                    Upsert::Updated => ItemChange::EngineUpdated {
                        uid: engine.uid,
                        id: engine.id,
                        level: engine.level,
                        phase: engine.phase,
                    },
                });
                upserted += 1;
            }
        }
        upserted
    }

    /// `cmdGetAvatarDataScRsp`.
    pub fn apply_avatar_data(
        &mut self,
        message: &Message,
        datamine: &Datamine,
        changes: &mut Vec<ItemChange>,
    ) -> usize {
        let mut upserted = 0;
        for field in &message.fields {
            if field.number != datamine.agent_data.agents {
                continue;
            }
            if let Some(nested) = field.value.as_message() {
                let agent = AgentInfo::from_message(&nested, datamine);
                let (_, kind, previous) = self.upsert_agent(agent.clone());
                changes.push(match kind {
                    Upsert::Added => ItemChange::AgentAdded {
                        id: agent.id,
                        level: agent.level,
                        weapon_uid: agent.weapon_uid,
                    },
                    Upsert::Updated => ItemChange::AgentUpdated {
                        id: agent.id,
                        level: agent.level,
                        previous_weapon_uid: previous,
                        weapon_uid: agent.weapon_uid,
                    },
                });
                upserted += 1;
            }
        }
        upserted
    }

    /// The extraction the message handler in `pcap.hpp` does once a message has
    /// decoded and its field numbers have been XORed back.
    ///
    /// Returns no events for the commands that extract nothing, which is most of
    /// them.
    pub fn apply(
        &mut self,
        command_id: u16,
        message: &Message,
        datamine: &Datamine,
    ) -> Vec<ExtractEvent> {
        let command = u32::from(command_id);
        let mut events = Vec::new();
        let mut changes = Vec::new();

        if command == datamine.cmd_player_sync_sc_notify {
            let result = self.apply_player_sync(message, datamine, &mut events, &mut changes);
            events.push(ExtractEvent::PlayerSync(result));
        } else if command == datamine.cmd_dismantle_equip_cs_req {
            events.push(ExtractEvent::Dismantle(self.apply_equip_dismantle(
                message,
                datamine,
                &mut changes,
            )));
        } else if command == datamine.cmd_get_equip_data_sc_rsp {
            events.push(ExtractEvent::Discs {
                upserted: self.apply_equip_data(message, datamine, &mut changes),
            });
        } else if command == datamine.cmd_get_weapon_data_sc_rsp {
            events.push(ExtractEvent::Weapons {
                upserted: self.apply_weapon_data(message, datamine, &mut changes),
            });
        } else if command == datamine.cmd_get_avatar_data_sc_rsp {
            events.push(ExtractEvent::Avatars {
                upserted: self.apply_avatar_data(message, datamine, &mut changes),
            });
        }

        // Every message that extracted anything reports its item-level changes,
        // even when that list is empty: the consumer keys the "what changed"
        // display off this event's presence.
        events.push(ExtractEvent::Changes(changes));
        events
    }
}

/// `SyncApplier::collectUints` — a repeated `uint32`, packed or not.
///
/// A varint field contributes one value; a length-delimited one is read as a
/// packed list, stopping at an unterminated varint exactly as the original does.
pub fn collect_uints(value: &Value) -> Vec<u32> {
    match value {
        Value::Varint(word) => vec![*word as u32],
        Value::LengthDelimited(data) => {
            let mut out = Vec::new();
            let mut pos = 0usize;
            while pos < data.len() {
                let mut word = 0u64;
                let mut shift = 0u32;
                let mut complete = false;
                while pos < data.len() && shift < 64 {
                    let byte = data[pos];
                    pos += 1;
                    word |= u64::from(byte & 0x7F) << shift;
                    if byte & 0x80 == 0 {
                        complete = true;
                        break;
                    }
                    shift += 7;
                }
                if !complete {
                    break;
                }
                out.push(word as u32);
            }
            out
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zzz_wire::proto::Field;

    fn datamine() -> Datamine {
        Datamine::parse(include_str!("../../../../assets/datamine.json")).expect("assets")
    }

    /// Varint-encode, so a packed repeated `uint32` can be built by hand.
    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn packed(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| varint(u64::from(*value)))
            .collect()
    }

    fn disc(uid: u64, id: u64, level: u64) -> Vec<u8> {
        let datamine = datamine();
        Message {
            fields: vec![
                Field::new(datamine.disc_info.uid, Value::Varint(uid)),
                Field::new(datamine.disc_info.id, Value::Varint(id)),
                Field::new(datamine.disc_info.level, Value::Varint(level)),
            ],
        }
        .encode()
    }

    fn engine(uid: u64, id: u64) -> Vec<u8> {
        let datamine = datamine();
        Message {
            fields: vec![
                Field::new(datamine.weapon_info.uid, Value::Varint(uid)),
                Field::new(datamine.weapon_info.id, Value::Varint(id)),
            ],
        }
        .encode()
    }

    fn agent(id: u64, level: u64) -> Vec<u8> {
        let datamine = datamine();
        Message {
            fields: vec![
                Field::new(datamine.agent_info.id, Value::Varint(id)),
                Field::new(datamine.agent_info.level, Value::Varint(level)),
            ],
        }
        .encode()
    }

    /// `PlayerSyncScNotify` with both submessages present.
    fn player_sync(
        discs: &[Vec<u8>],
        engines: &[Vec<u8>],
        deleted_discs: &[u32],
        agents: &[Vec<u8>],
        deleted_agents: &[u32],
    ) -> Message {
        let datamine = datamine();
        let mut item_fields = Vec::new();
        for bytes in discs {
            item_fields.push(Field::new(
                datamine.sync_item_data.equips,
                Value::LengthDelimited(bytes.clone()),
            ));
        }
        for bytes in engines {
            item_fields.push(Field::new(
                datamine.sync_item_data.weapons,
                Value::LengthDelimited(bytes.clone()),
            ));
        }
        if !deleted_discs.is_empty() {
            item_fields.push(Field::new(
                datamine.sync_item_data.deleted_equips,
                Value::LengthDelimited(packed(deleted_discs)),
            ));
        }

        let mut avatar_fields = Vec::new();
        for bytes in agents {
            avatar_fields.push(Field::new(
                datamine.sync_avatar_data.avatars,
                Value::LengthDelimited(bytes.clone()),
            ));
        }
        if !deleted_agents.is_empty() {
            avatar_fields.push(Field::new(
                datamine.sync_avatar_data.dels,
                Value::LengthDelimited(packed(deleted_agents)),
            ));
        }

        Message {
            fields: vec![
                Field::new(
                    datamine.sync_avatar_data.avatar_sync,
                    Value::LengthDelimited(
                        Message {
                            fields: avatar_fields,
                        }
                        .encode(),
                    ),
                ),
                Field::new(
                    datamine.sync_item_data.item_sync,
                    Value::LengthDelimited(
                        Message {
                            fields: item_fields,
                        }
                        .encode(),
                    ),
                ),
            ],
        }
    }

    #[test]
    fn an_upsert_replaces_in_place_and_always_reports_changed() {
        let mut inventory = Inventory::new();
        assert_eq!(
            inventory.upsert_disc(DiscInfo {
                uid: 1,
                level: 5,
                ..DiscInfo::default()
            }),
            (true, Upsert::Added)
        );
        // The original returns `true` unconditionally, even when nothing moved:
        // it drives a UI refresh, and a false negative would leave it stale.
        assert_eq!(
            inventory.upsert_disc(DiscInfo {
                uid: 1,
                level: 9,
                ..DiscInfo::default()
            }),
            (true, Upsert::Updated)
        );
        assert_eq!(inventory.discs.len(), 1);
        assert_eq!(inventory.discs[0].level, 9);

        assert_eq!(
            inventory.upsert_engine(WeaponInfo {
                uid: 2,
                ..WeaponInfo::default()
            }),
            (true, Upsert::Added)
        );
        let (changed, kind, _) = inventory.upsert_agent(AgentInfo {
            id: 3,
            ..AgentInfo::default()
        });
        assert!(changed);
        assert_eq!(kind, Upsert::Added);
        assert!(!inventory.is_empty());
        // Removal reports whether anything matched, which is what the callers
        // count as a removal.
        assert!(inventory.remove_disc(1));
        assert!(!inventory.remove_disc(1));
        assert!(inventory.remove_engine(2));
        assert!(inventory.remove_agent(3));
        assert!(inventory.is_empty());
    }

    #[test]
    fn a_player_sync_upserts_discs_engines_and_agents() {
        let datamine = datamine();
        let mut inventory = Inventory::new();
        let message = player_sync(
            &[disc(15916, 31204, 15), disc(15917, 31204, 12)],
            &[engine(15031, 15031)],
            &[],
            &[agent(1581, 60)],
            &[],
        );

        let mut events = Vec::new();
        let mut changes = Vec::new();
        let result = inventory.apply_player_sync(&message, &datamine, &mut events, &mut changes);
        assert!(result.changed);
        // Two discs, one engine and one agent: the avatar sync upserts too.
        assert_eq!(result.upserts, 4);
        assert_eq!(result.removals, 0);
        assert!(events.is_empty(), "no fallback was needed: {events:?}");
        assert_eq!(inventory.discs.len(), 2);
        assert_eq!(inventory.discs[0].uid, 15916);
        assert_eq!(inventory.discs[0].id, 31204);
        assert_eq!(inventory.discs[0].level, 15);
        assert_eq!(inventory.engines.len(), 1);
        assert_eq!(inventory.engines[0].id, 15031);
        assert_eq!(inventory.agents.len(), 1);
        assert_eq!(inventory.agents[0].id, 1581);
        assert_eq!(inventory.agents[0].level, 60);
    }

    #[test]
    fn a_player_sync_deletes_discs_and_agents() {
        let datamine = datamine();
        let mut inventory = Inventory::new();
        inventory.upsert_disc(DiscInfo {
            uid: 15916,
            ..DiscInfo::default()
        });
        inventory.upsert_disc(DiscInfo {
            uid: 4242,
            ..DiscInfo::default()
        });
        inventory.upsert_agent(AgentInfo {
            id: 1700,
            ..AgentInfo::default()
        });

        let message = player_sync(&[], &[], &[15916], &[], &[1700]);
        let mut events = Vec::new();
        let mut changes = Vec::new();
        let result = inventory.apply_player_sync(&message, &datamine, &mut events, &mut changes);

        assert!(result.changed);
        assert_eq!(result.upserts, 0);
        assert_eq!(result.removals, 2, "one disc and one agent");
        assert_eq!(inventory.discs.len(), 1);
        assert_eq!(inventory.discs[0].uid, 4242);
        assert!(inventory.agents.is_empty());
    }

    #[test]
    fn the_fallback_finds_a_deleted_equips_field_that_moved() {
        // The 3.2 bring-up case: the uids arrive under a field number datamine
        // does not know yet. The original probes every other field and acts only
        // on a uid it recognises, which is how the new number gets discovered.
        let datamine = datamine();
        let mut inventory = Inventory::new();
        inventory.upsert_disc(DiscInfo {
            uid: 15916,
            ..DiscInfo::default()
        });

        let mut message = player_sync(&[], &[], &[], &[], &[]);
        // A second item sync carrying the uid in an unknown field, plus a uid
        // that matches nothing and must be ignored.
        let moved = Message {
            fields: vec![Field::new(
                99,
                Value::LengthDelimited(packed(&[15916, 777])),
            )],
        };
        message.fields.push(Field::new(
            datamine.sync_item_data.item_sync,
            Value::LengthDelimited(moved.encode()),
        ));

        let mut events = Vec::new();
        let mut changes = Vec::new();
        let result = inventory.apply_player_sync(&message, &datamine, &mut events, &mut changes);
        assert!(result.changed);
        assert_eq!(result.removals, 1, "only the uid that exists is removed");
        assert!(inventory.discs.is_empty());
        assert_eq!(
            events,
            vec![ExtractEvent::FallbackRemoval {
                uid: 15916,
                field: 99
            }]
        );
    }

    #[test]
    fn the_fallback_ignores_wire_types_it_cannot_read() {
        let datamine = datamine();
        let mut inventory = Inventory::new();
        inventory.upsert_disc(DiscInfo {
            uid: 15916,
            ..DiscInfo::default()
        });

        let mut message = player_sync(&[], &[], &[], &[], &[]);
        // A fixed32 field whose bits happen to equal the uid: the original skips
        // these before collecting, so the disc must survive.
        let moved = Message {
            fields: vec![Field::new(99, Value::Fixed32(15916))],
        };
        message.fields.push(Field::new(
            datamine.sync_item_data.item_sync,
            Value::LengthDelimited(moved.encode()),
        ));

        let mut events = Vec::new();
        let mut changes = Vec::new();
        let result = inventory.apply_player_sync(&message, &datamine, &mut events, &mut changes);
        assert!(!result.changed);
        assert_eq!(inventory.discs.len(), 1);
        assert!(events.is_empty());
    }

    #[test]
    fn a_dismantle_removes_a_uid_from_both_lists() {
        // The original writes `removeDisc(uid) | removeEngine(uid)`: a bitwise or,
        // so both are attempted. They cannot both be true, but a uid present as
        // both a disc and a w-engine must still lose both.
        let datamine = datamine();
        let mut inventory = Inventory::new();
        inventory.upsert_disc(DiscInfo {
            uid: 5,
            ..DiscInfo::default()
        });
        inventory.upsert_engine(WeaponInfo {
            uid: 5,
            ..WeaponInfo::default()
        });

        let message = Message {
            fields: vec![Field::new(
                datamine.equip_dismantle.uids,
                Value::LengthDelimited(packed(&[5])),
            )],
        };
        let mut changes = Vec::new();
        let result = inventory.apply_equip_dismantle(&message, &datamine, &mut changes);
        assert!(result.changed);
        assert_eq!(result.removals, 1, "one uid, counted once");
        assert!(inventory.discs.is_empty());
        assert!(inventory.engines.is_empty());
    }

    #[test]
    fn a_dismantle_reads_packed_and_unpacked_uids() {
        let datamine = datamine();
        let mut inventory = Inventory::new();
        for uid in 1..=4 {
            inventory.upsert_disc(DiscInfo {
                uid,
                ..DiscInfo::default()
            });
        }

        // A packed list under the repeated field, plus unpacked varint entries.
        let message = Message {
            fields: vec![
                Field::new(
                    datamine.equip_dismantle.uids,
                    Value::LengthDelimited(packed(&[1, 2, 3])),
                ),
                Field::new(datamine.equip_dismantle.uid, Value::Varint(4)),
                // A uid nobody has: not counted.
                Field::new(datamine.equip_dismantle.uid, Value::Varint(99)),
            ],
        };
        let mut changes = Vec::new();
        let result = inventory.apply_equip_dismantle(&message, &datamine, &mut changes);
        assert_eq!(result.removals, 4);
        assert!(inventory.discs.is_empty());
    }

    #[test]
    fn the_load_responses_fill_the_whole_inventory() {
        let datamine = datamine();
        let mut inventory = Inventory::new();

        let equip_data = Message {
            fields: (0..3)
                .map(|index| {
                    Field::new(
                        datamine.equip_data.discs,
                        Value::LengthDelimited(disc(100 + index, 31204, 1)),
                    )
                })
                .collect(),
        };
        let events = inventory.apply(
            datamine.cmd_get_equip_data_sc_rsp as u16,
            &equip_data,
            &datamine,
        );
        assert_eq!(
            events,
            vec![
                ExtractEvent::Discs { upserted: 3 },
                // The load reports its changes too, which is how the GUI can show
                // "the login itself added these".
                ExtractEvent::Changes(vec![
                    ItemChange::DiscAdded {
                        uid: 100,
                        id: 31204,
                        level: 1,
                        rarity: 1
                    },
                    ItemChange::DiscAdded {
                        uid: 101,
                        id: 31204,
                        level: 1,
                        rarity: 1
                    },
                    ItemChange::DiscAdded {
                        uid: 102,
                        id: 31204,
                        level: 1,
                        rarity: 1
                    },
                ])
            ]
        );

        let weapon_data = Message {
            fields: vec![Field::new(
                datamine.weapon_data.weapons,
                Value::LengthDelimited(engine(15031, 15031)),
            )],
        };
        let events = inventory.apply(
            datamine.cmd_get_weapon_data_sc_rsp as u16,
            &weapon_data,
            &datamine,
        );
        assert_eq!(
            events,
            vec![
                ExtractEvent::Weapons { upserted: 1 },
                ExtractEvent::Changes(vec![ItemChange::EngineAdded {
                    uid: 15031,
                    id: 15031,
                    level: 0,
                    phase: 0
                }])
            ]
        );

        let avatar_data = Message {
            fields: vec![Field::new(
                datamine.agent_data.agents,
                Value::LengthDelimited(agent(1581, 60)),
            )],
        };
        let events = inventory.apply(
            datamine.cmd_get_avatar_data_sc_rsp as u16,
            &avatar_data,
            &datamine,
        );
        assert_eq!(
            events,
            vec![
                ExtractEvent::Avatars { upserted: 1 },
                ExtractEvent::Changes(vec![ItemChange::AgentAdded {
                    id: 1581,
                    level: 60,
                    weapon_uid: 0
                }])
            ]
        );

        assert_eq!(inventory.discs.len(), 3);
        assert_eq!(inventory.engines.len(), 1);
        assert_eq!(inventory.agents.len(), 1);

        // A message that extracts nothing still reports an empty change list —
        // every decoded message does — but nothing else.
        let unrelated = inventory.apply(4242, &Message::default(), &datamine);
        assert_eq!(unrelated, vec![ExtractEvent::Changes(Vec::new())]);
        assert_eq!(inventory.discs.len(), 3);
    }

    #[test]
    fn the_summary_folds_the_events_it_is_given() {
        let mut summary = ExtractSummary::default();
        summary.absorb(&[
            ExtractEvent::PlayerSync(SyncResult {
                changed: true,
                upserts: 4,
                removals: 1,
            }),
            ExtractEvent::Dismantle(SyncResult {
                changed: true,
                upserts: 0,
                removals: 2,
            }),
            ExtractEvent::Discs { upserted: 3 },
            ExtractEvent::FallbackRemoval { uid: 77, field: 99 },
        ]);
        assert_eq!(summary.player_syncs, 1);
        assert_eq!(summary.sync_upserts, 4);
        assert_eq!(summary.sync_removals, 1);
        assert_eq!(summary.dismantles, 1);
        assert_eq!(summary.dismantle_removals, 2);
        assert_eq!(summary.disc_loads, 1);
        assert_eq!(summary.weapon_loads, 0);
        assert_eq!(summary.avatar_loads, 0);
        assert_eq!(summary.fallback_removals, vec![(77, 99)]);
    }

    #[test]
    fn collect_uints_matches_the_cpp_packed_reader() {
        // A single varint field contributes one value.
        assert_eq!(collect_uints(&Value::Varint(300)), vec![300]);
        // Multi-byte varints, packed back to back.
        assert_eq!(
            collect_uints(&Value::LengthDelimited(packed(&[1, 128, 300]))),
            vec![1, 128, 300]
        );
        // The C++ casts to uint32, so a wider value is truncated rather than
        // rejected.
        assert_eq!(
            collect_uints(&Value::LengthDelimited(varint(0x1_0000_0005))),
            vec![5]
        );
        // An unterminated varint stops the walk, keeping what came before it.
        let mut truncated = packed(&[7]);
        truncated.push(0x80);
        assert_eq!(collect_uints(&Value::LengthDelimited(truncated)), vec![7]);
        // Wire types the original does not read contribute nothing.
        assert_eq!(collect_uints(&Value::Fixed32(5)), Vec::<u32>::new());
        assert_eq!(
            collect_uints(&Value::LengthDelimited(vec![])),
            Vec::<u32>::new()
        );
    }
}
