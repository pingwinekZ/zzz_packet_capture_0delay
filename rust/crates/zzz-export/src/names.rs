//! The name and rarity lookups the export needs, behind a trait.
//!
//! The reference reads them from the `NanokaData` singleton, which fetches from
//! `static.nanoka.cc` and *throws* for an id the published tables do not have.
//! Splitting the lookup out does two things: an export can be tested against
//! names fixed in the test, and every caller sees an `Option` that the export
//! turns into a named error rather than a silent empty key.

use zzz_gamedata::NanokaData;

/// Display names and rarities, keyed by the ids that appear in packets.
pub trait Names {
    /// The agent's English name.
    fn character_name(&self, id: u32) -> Option<&str>;
    /// The agent's star rating, already `rank + 1`.
    fn character_rarity(&self, id: u32) -> Option<u32>;
    /// The w-engine's English name.
    fn weapon_name(&self, id: u32) -> Option<&str>;
    /// The w-engine's star rating, already `rank + 1`.
    fn weapon_rarity(&self, id: u32) -> Option<u32>;
    /// The disc set's English name, keyed by the set id (`id / 100 * 100`).
    fn equipment_name(&self, set_id: u32) -> Option<&str>;
}

/// A borrowed [`NanokaData`], so an export can take names from the loaded game
/// data without giving up ownership of it.
pub struct NanokaNames<'a>(pub &'a NanokaData);

impl Names for NanokaNames<'_> {
    fn character_name(&self, id: u32) -> Option<&str> {
        self.0.character_name(id)
    }

    fn character_rarity(&self, id: u32) -> Option<u32> {
        self.0.character_rarity(id)
    }

    fn weapon_name(&self, id: u32) -> Option<&str> {
        self.0.weapon_name(id)
    }

    fn weapon_rarity(&self, id: u32) -> Option<u32> {
        self.0.weapon_rarity(id)
    }

    fn equipment_name(&self, set_id: u32) -> Option<&str> {
        self.0.equipment_name(set_id)
    }
}
