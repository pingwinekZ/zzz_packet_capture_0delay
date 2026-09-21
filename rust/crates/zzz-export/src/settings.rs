//! `data::ExportSettings` — which parts of the inventory to write, and the
//! floors below which a record is left out.

/// `data::ExportSettings`.
///
/// The defaults are the reference's, and the two rarity floors are worth noting
/// because they mean different things in different filters:
///
/// * `min_disc_rarity` is compared against the rarity decoded from the disc id
///   (`3`/`4`/`5`), the same band `keyRarity` has letters for.
/// * `min_agent_rarity` and `min_engine_rarity` are compared against the nanoka
///   rank *plus one*, so a five-star agent has rarity 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportSettings {
    pub min_disc_rarity: u8,
    pub min_disc_level: u8,
    pub min_engine_rarity: u8,
    pub min_engine_level: u8,
    pub min_agent_rarity: u8,
    pub min_agent_level: u8,
    pub export_discs: bool,
    pub export_agents: bool,
    pub export_engines: bool,
}

impl Default for ExportSettings {
    fn default() -> Self {
        Self {
            min_disc_rarity: 3,
            min_disc_level: 0,
            min_engine_rarity: 3,
            min_engine_level: 0,
            min_agent_rarity: 4,
            min_agent_level: 0,
            export_discs: true,
            export_agents: true,
            export_engines: true,
        }
    }
}

impl ExportSettings {
    /// Everything, with no floors at all. Useful for a parity run, where the
    /// point is to compare every record rather than a plausible slice of them.
    pub fn unfiltered() -> Self {
        Self {
            min_disc_rarity: 0,
            min_disc_level: 0,
            min_engine_rarity: 0,
            min_engine_level: 0,
            min_agent_rarity: 0,
            min_agent_level: 0,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_cpp_header() {
        let settings = ExportSettings::default();
        assert_eq!(settings.min_disc_rarity, 3);
        assert_eq!(settings.min_disc_level, 0);
        assert_eq!(settings.min_engine_rarity, 3);
        assert_eq!(settings.min_engine_level, 0);
        // Four stars and up by default: this is the one floor that is not zero.
        assert_eq!(settings.min_agent_rarity, 4);
        assert_eq!(settings.min_agent_level, 0);
        assert!(settings.export_discs && settings.export_agents && settings.export_engines);
    }
}
