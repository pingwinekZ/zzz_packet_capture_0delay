//! `data::ExportSettings` — which parts of the inventory are written.
//!
//! There are two kinds of switch here. The three `export_*` fields select a
//! whole category: off means the key is absent from the JSON, which the site
//! reads as "keep what was imported last time". The two `*_equip_status` fields
//! decide whether an item's equip link is written at all: off means the
//! `location` key is omitted, so the site sees the item as unequipped.

/// `data::ExportSettings`, reduced to the five filters this port offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportSettings {
    pub export_discs: bool,
    pub export_agents: bool,
    pub export_engines: bool,
    /// Write each disc's `location` — the agent wearing it, or `""` in the bag.
    /// Off omits the key, so the site sees every disc as unequipped.
    pub export_disc_equip_status: bool,
    /// Write each w-engine's `location`, and each agent's `wengineKey` /
    /// `wenginePhase`. Off omits all three, so the site sees no equip links.
    pub export_engine_equip_status: bool,
}

impl Default for ExportSettings {
    fn default() -> Self {
        Self {
            export_discs: true,
            export_agents: true,
            export_engines: true,
            export_disc_equip_status: true,
            export_engine_equip_status: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_filter_is_on_by_default() {
        let settings = ExportSettings::default();
        assert!(settings.export_discs);
        assert!(settings.export_agents);
        assert!(settings.export_engines);
        assert!(settings.export_disc_equip_status);
        assert!(settings.export_engine_equip_status);
    }
}
