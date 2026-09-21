//! The live pipeline shared by `zzzcap live` and the GUI: packets in, the region
//! detected, the inventory extracted, snapshots served, every change logged.
//!
//! Extracted into its own crate rather than kept in `zzz-cli` so the two front
//! ends cannot drift: whatever the console prints, the GUI shows, because both
//! run this.
//!
//! The threading contract is the one the reference establishes with its
//! observers: [`Session::feed`] is called from the capture thread, does the
//! decoding, and reports progress through the callbacks; the callbacks are the
//! only cross-thread surface, so neither the WebSocket server nor the GUI ever
//! touches the decoder directly.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zzz_capture::Dump;
use zzz_crypto::xorpad::XorPad;
use zzz_export::{ExportSettings, Izod, Names, NanokaNames};
use zzz_gamedata::GameData;
use zzz_live::Server;
use zzz_scan::{ExtractSummary, ItemChange, Scanner};

/// How many packets a region candidate gets to prove itself in, when a dump or a
/// first detection window is scored.
pub const DETECT_PACKETS: usize = 600;

/// How many messages a region candidate must decode to be believed when the
/// handshake is not in the window. A wrong seed can manage an accidental parse
/// or two; it cannot manage eight.
pub const MIN_VIABLE_DECODES: u64 = 8;

/// How many packets the server holds back while it is still trying to place the
/// region, and the point at which it gives up rather than run dead.
pub const DETECT_LIMIT: usize = 4000;

/// How often [`Session::feed`] reports progress while nothing is changing.
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// Everything the extraction summary counts, so "did anything change" is one
/// comparison rather than a field list kept in sync by hand.
pub fn extraction_total(summary: &ExtractSummary) -> u64 {
    summary.player_syncs
        + summary.sync_upserts
        + summary.sync_removals
        + summary.dismantles
        + summary.dismantle_removals
        + summary.disc_loads
        + summary.weapon_loads
        + summary.avatar_loads
        + summary.discs_added
        + summary.discs_updated
        + summary.discs_removed
        + summary.engines_added
        + summary.engines_updated
        + summary.engines_removed
        + summary.agents_added
        + summary.agents_updated
        + summary.agents_removed
}

/// One line of the change log: an item-level change plus the names that make it
/// readable. Built by [`Session`] because it is the only place that has both the
/// change and the name tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Capture-order sequence number, so the display can keep them sorted even
    /// when several arrive between two frames.
    pub sequence: u64,
    /// Human-readable, names resolved: `Anby equips [Lunar] Pleniluna`.
    pub text: String,
    /// The raw change, for anything that wants to filter on the kind.
    pub change: ItemChange,
}

/// A cheap snapshot of where the session is, sent after every packet. Small
/// enough to cross threads per packet; the inventory itself is not in here —
/// see [`Callbacks::inventory`] for the expensive one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Status {
    pub packets: u64,
    pub snapshots: u64,
    pub discs: usize,
    pub engines: usize,
    pub agents: usize,
    pub region: Option<String>,
}

/// What the caller wants to hear about. Both front ends install these.
#[derive(Default, Clone)]
pub struct Callbacks {
    /// A progress or diagnostic line: region detected, packets counted.
    pub log: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// A snapshot was served to the WebSocket clients.
    pub snapshot: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// One or more item-level changes were applied.
    pub changes: Option<Arc<dyn Fn(Vec<LogEntry>) + Send + Sync>>,
    /// Where the session is now. One per fed packet, so it must stay cheap.
    pub status: Option<Arc<dyn Fn(Status) + Send + Sync>>,
    /// A clone of the extracted inventory, sent only when it changed. During a
    /// login that is a handful of times; during play, once per applied sync.
    pub inventory: Option<Arc<dyn Fn(Arc<zzz_scan::Inventory>) + Send + Sync>>,
}

impl Callbacks {
    fn log(&self, line: impl Into<String>) {
        if let Some(log) = &self.log {
            log(line.into());
        }
    }
}

/// Region name and seed pairs to try, most specific first.
pub fn candidate_seeds(
    data: &GameData,
    region: Option<&str>,
    seed: Option<&str>,
) -> Result<Vec<(String, u64)>, String> {
    if let Some(text) = seed {
        let value = u64::from_str_radix(text.trim_start_matches("0x"), 16)
            .map_err(|_| format!("--seed {text:?} is not a hex number"))?;
        return Ok(vec![("--seed".to_string(), value)]);
    }
    if let Some(name) = region {
        let value = data.seed_for_region(name).ok_or_else(|| {
            let known: Vec<&str> = data.datamine.xor_seeds.keys().map(String::as_str).collect();
            format!(
                "region {name:?} is not in datamine.json (known: {})",
                known.join(", ")
            )
        })?;
        return Ok(vec![(name.to_string(), value)]);
    }

    Ok(data
        .datamine
        .xor_seeds
        .iter()
        .filter_map(|(name, text)| {
            u64::from_str_radix(text, 16)
                .ok()
                .map(|value| (name.clone(), value))
        })
        .collect())
}

/// Why a feed produced no snapshot.
#[derive(Debug)]
pub enum FeedError {
    /// No region seed decrypted anything within [`DETECT_LIMIT`] packets.
    RegionNotFound { packets: usize },
    /// A snapshot could not be built: a name the data files do not have.
    Export(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionNotFound { packets } => write!(
                f,
                "no region seed decrypts the first {packets} packets: either the game has \
                 updated and `xorSeeds` in datamine.json is stale, or this traffic is not the \
                 game's — pass a region or seed to skip detection"
            ),
            Self::Export(error) => write!(f, "{error}"),
        }
    }
}

/// The live pipeline: feed packets, get snapshots and a change log.
///
/// The region is not known until the login handshake has been seen, so the first
/// packets are held back and scored exactly as `replay` scores a whole dump.
/// Once the region is settled every packet goes straight to the scanner.
pub struct Session<'a> {
    data: &'a GameData,
    candidates: Vec<(String, u64)>,
    settings: ExportSettings,
    server: Option<&'a Server>,
    latest: Arc<Mutex<String>>,
    scanner: Option<Scanner<'a>>,
    /// Packets held back while the region is unknown: the window the next
    /// detection attempt is scored on.
    pending: Dump,
    region: Option<String>,
    callbacks: Callbacks,
    packets: AtomicU64,
    snapshots: AtomicU64,
    last_progress: Mutex<Instant>,
}

impl<'a> Session<'a> {
    pub fn new(
        data: &'a GameData,
        candidates: Vec<(String, u64)>,
        settings: ExportSettings,
        server: Option<&'a Server>,
        callbacks: Callbacks,
    ) -> Self {
        Self {
            data,
            candidates,
            settings,
            server,
            latest: Arc::new(Mutex::new(String::new())),
            scanner: None,
            pending: Dump::new(),
            region: None,
            callbacks,
            packets: AtomicU64::new(0),
            snapshots: AtomicU64::new(0),
            last_progress: Mutex::new(Instant::now()),
        }
    }

    /// The callback that produces a connecting client's first payload. Hand the
    /// same closure to [`Server::on_snapshot_requested`].
    pub fn snapshot_source(&self) -> Arc<Mutex<String>> {
        Arc::clone(&self.latest)
    }

    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// Replaces the export settings. The GUI calls this whenever its sync
    /// toggles move mid-capture, so the next snapshot honors them without a
    /// restart.
    pub fn set_settings(&mut self, settings: ExportSettings) {
        self.settings = settings;
    }

    pub fn packets(&self) -> u64 {
        self.packets.load(Ordering::Relaxed)
    }

    pub fn snapshots(&self) -> u64 {
        self.snapshots.load(Ordering::Relaxed)
    }

    pub fn inventory(&self) -> Option<&zzz_scan::Inventory> {
        self.scanner.as_ref().map(Scanner::inventory)
    }

    pub fn extract(&self) -> Option<&ExtractSummary> {
        self.scanner.as_ref().map(Scanner::extract)
    }

    pub fn stats(&self) -> Option<&zzz_scan::DecodeStats> {
        self.scanner.as_ref().map(Scanner::stats)
    }

    /// Feeds one captured packet.
    pub fn feed(&mut self, packet: &zzz_capture::Packet) -> Result<(), FeedError> {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.progress();

        if self.scanner.is_none() {
            self.pending.push(packet);
            // Retried every half-window from the first full one: the handshake is
            // at the start of a session, and a session starts after this does.
            let half_window = (DETECT_PACKETS / 2).max(1);
            if self.pending.len() < DETECT_PACKETS || self.pending.len() % half_window != 0 {
                return Ok(());
            }
            let Some((label, value)) = self.detect() else {
                if self.pending.len() >= DETECT_LIMIT {
                    return Err(FeedError::RegionNotFound {
                        packets: self.pending.len(),
                    });
                }
                return Ok(());
            };
            self.region = Some(label);
            let pending = std::mem::take(&mut self.pending);
            let mut scanner = Scanner::new(
                XorPad::for_region(value),
                &self.data.datamine,
                &self.data.nap,
            );
            for held in &pending.packets {
                scanner.feed(&held.data, held.direction(), held.timestamp);
            }
            // The held-back window holds the login: full-inventory load
            // responses. That is the baseline, not a set of changes — drop it
            // so the change log starts empty and only shows what happens after
            // the login. The inventory itself still reaches the UI through the
            // snapshot and status callbacks below.
            scanner.take_changes();
            self.scanner = Some(scanner);
            return self.publish().map_err(FeedError::Export);
        }

        let (changed, had_load, changes) = {
            let scanner = self.scanner.as_mut().expect("set just above");
            let before = extraction_total(scanner.extract());
            scanner.feed(&packet.data, packet.direction, packet.timestamp);
            let after = extraction_total(scanner.extract());
            let had_load = scanner.last_feed_had_load();
            let changes = scanner.take_changes();
            (after != before, had_load, changes)
        };
        // A load response carries the whole baseline inventory: logging it
        // would dump ~1k "added" lines over the real deltas, so it is dropped.
        // The inventory itself still reaches the UI through snapshots and the
        // status counters. A packet that mixes a load with a sync drops the
        // sync's lines too, which is acceptable collateral during a login.
        if !had_load {
            self.record_changes(changes);
        }
        if changed {
            self.publish().map_err(FeedError::Export)?;
        }
        self.report_status();
        Ok(())
    }

    /// Sends [`Status`] if anyone is listening.
    fn report_status(&self) {
        let Some(status) = &self.callbacks.status else {
            return;
        };
        let (discs, engines, agents) = match self.scanner.as_ref().map(Scanner::inventory) {
            Some(inventory) => (
                inventory.discs.len(),
                inventory.engines.len(),
                inventory.agents.len(),
            ),
            None => (0, 0, 0),
        };
        status(Status {
            packets: self.packets(),
            snapshots: self.snapshots(),
            discs,
            engines,
            agents,
            region: self.region.clone(),
        });
    }

    /// Scores the held-back packets the way `replay` scores a dump.
    fn detect(&mut self) -> Option<(String, u64)> {
        let pending_len = self.pending.len();
        let mut best: Option<(String, u64, u64)> = None;
        for (label, seed) in &self.candidates {
            let scanner = Scanner::new(
                XorPad::for_region(*seed),
                &self.data.datamine,
                &self.data.nap,
            );
            let mut trial = scanner;
            for held in self
                .pending
                .packets
                .iter()
                .take(DETECT_PACKETS.min(pending_len))
            {
                trial.feed(&held.data, held.direction(), held.timestamp);
            }
            let score = trial.stats().decoded;
            let complete = trial.handshake_complete();
            if (complete || score >= MIN_VIABLE_DECODES)
                && best.as_ref().map_or(true, |(_, _, seen)| score > *seen)
            {
                best = Some((label.clone(), *seed, score));
            }
        }
        let (label, seed, score) = best?;
        self.callbacks.log(format!(
            "region detected: {label}, {score} messages in the first {} packets",
            DETECT_PACKETS.min(pending_len)
        ));
        Some((label, seed))
    }

    /// Turns raw `ItemChange`s into named log lines and hands them to the
    /// callback. Names come from the nanoka tables, so a game update that adds a
    /// new agent shows its id until `zzzcap update` runs.
    fn record_changes(&mut self, changes: Vec<ItemChange>) {
        if changes.is_empty() {
            return;
        }
        let names = NanokaNames(&self.data.nanoka);
        let inventory = self.scanner.as_ref().map(Scanner::inventory);
        let entries = changes
            .into_iter()
            .map(|change| LogEntry {
                sequence: 0,
                text: describe_change(&change, &names, inventory),
                change,
            })
            .collect();
        if let Some(callback) = &self.callbacks.changes {
            callback(entries);
        }
    }

    /// Builds the live payload from what has been extracted and sends it out.
    fn publish(&mut self) -> Result<(), String> {
        let Some(scanner) = self.scanner.as_ref() else {
            return Ok(());
        };
        let json = if !scanner.inventory().is_empty() {
            let zod = Izod::for_live(
                scanner.inventory(),
                &NanokaNames(&self.data.nanoka),
                &self.settings,
            )
            .map_err(|error| {
                format!(
                    "cannot build a snapshot: {error} — the session stops rather than sending \
                     a payload the optimizer would import"
                )
            })?;
            zod.to_json()
        } else {
            // Nothing extracted yet: every category would be null, which the
            // optimizer ignores. The reference's caller skips an empty payload
            // for the same reason.
            return Ok(());
        };

        {
            let mut latest = self.latest.lock().unwrap();
            if *latest == json {
                return Ok(());
            }
            *latest = json.clone();
        }
        if let Some(server) = self.server {
            server.broadcast_text(&json);
        }
        self.snapshots.fetch_add(1, Ordering::Relaxed);
        if let Some(inventory) = &self.callbacks.inventory {
            inventory(Arc::new(scanner.inventory().clone()));
        }

        let inventory = scanner.inventory();
        self.callbacks.log(format!(
            "snapshot {} ({} KiB): {} discs, {} w-engines, {} agents, {} client(s)",
            self.snapshots.load(Ordering::Relaxed),
            json.len() / 1024,
            inventory.discs.len(),
            inventory.engines.len(),
            inventory.agents.len(),
            self.server.map_or(0, Server::client_count),
        ));
        if let Some(snapshot) = &self.callbacks.snapshot {
            snapshot(json);
        }
        Ok(())
    }

    fn progress(&mut self) {
        let due = {
            let mut last = self.last_progress.lock().unwrap();
            if last.elapsed() >= PROGRESS_INTERVAL {
                *last = Instant::now();
                true
            } else {
                false
            }
        };
        if !due {
            return;
        }
        match self.scanner.as_ref().map(Scanner::inventory) {
            Some(inventory) if !inventory.is_empty() => self.callbacks.log(format!(
                "{} packets, {} snapshots, {} discs, {} w-engines, {} agents",
                self.packets(),
                self.snapshots(),
                inventory.discs.len(),
                inventory.engines.len(),
                inventory.agents.len()
            )),
            _ => self
                .callbacks
                .log(format!("{} packets, no region yet", self.packets())),
        }
    }
}

/// The engine name for a uid, looked up in the extracted inventory.
fn engine_name(
    inventory: Option<&zzz_scan::Inventory>,
    uid: u32,
    names: &NanokaNames<'_>,
) -> String {
    inventory
        .and_then(|inventory| {
            inventory
                .engines
                .iter()
                .find(|engine| engine.uid == uid)
                .and_then(|engine| names.weapon_name(engine.id).map(str::to_string))
        })
        .unwrap_or_else(|| format!("w-engine {uid}"))
}

/// The disc name the set id maps to, or the raw id.
fn disc_name(id: u32, names: &NanokaNames<'_>) -> String {
    let disc = zzz_scan::DiscInfo {
        id,
        ..zzz_scan::DiscInfo::default()
    };
    names
        .equipment_name(disc.set_id())
        .map(|set| format!("{set} slot {}", disc.slot()))
        .unwrap_or_else(|| format!("disc {id}"))
}

/// One human-readable line per change. This is the console's vocabulary; the
/// GUI shows the same text so the two cannot disagree about what happened.
pub fn describe_change(
    change: &ItemChange,
    names: &NanokaNames<'_>,
    inventory: Option<&zzz_scan::Inventory>,
) -> String {
    let agent_name = |id: u32| {
        names
            .character_name(id)
            .map(str::to_string)
            .unwrap_or_else(|| format!("agent {id}"))
    };
    match change {
        ItemChange::DiscAdded {
            uid,
            id,
            level,
            rarity,
        } => format!(
            "+ disc  {}  Lv{level} R{rarity}  (uid {uid})",
            disc_name(*id, names)
        ),
        ItemChange::DiscUpdated {
            uid,
            id,
            level,
            rarity,
        } => format!(
            "~ disc  {}  Lv{level} R{rarity}  (uid {uid})",
            disc_name(*id, names)
        ),
        ItemChange::DiscRemoved { uid, id } => {
            format!("- disc  {}  (uid {uid})", disc_name(*id, names))
        }
        ItemChange::EngineAdded {
            uid,
            id,
            level,
            phase,
        } => format!(
            "+ w-engine  {}  Lv{level} P{phase}  (uid {uid})",
            names.weapon_name(*id).unwrap_or("?")
        ),
        ItemChange::EngineUpdated {
            uid,
            id,
            level,
            phase,
        } => format!(
            "~ w-engine  {}  Lv{level} P{phase}  (uid {uid})",
            names.weapon_name(*id).unwrap_or("?")
        ),
        ItemChange::EngineRemoved { uid, id } => format!(
            "- w-engine  {}  (uid {uid})",
            names.weapon_name(*id).unwrap_or("?")
        ),
        ItemChange::AgentAdded {
            id,
            level,
            weapon_uid,
        } => format!(
            "+ agent  {}  Lv{level}{}",
            agent_name(*id),
            if *weapon_uid == 0 {
                String::new()
            } else {
                format!("  equips {}", engine_name(inventory, *weapon_uid, names))
            }
        ),
        ItemChange::AgentUpdated {
            id,
            level,
            previous_weapon_uid,
            weapon_uid,
        } => {
            if *previous_weapon_uid == *weapon_uid {
                format!("~ agent  {}  Lv{level}", agent_name(*id))
            } else if *weapon_uid == 0 {
                format!(
                    "~ agent  {}  unequips {}",
                    agent_name(*id),
                    engine_name(inventory, *previous_weapon_uid, names)
                )
            } else if *previous_weapon_uid == 0 {
                format!(
                    "~ agent  {}  equips {}",
                    agent_name(*id),
                    engine_name(inventory, *weapon_uid, names)
                )
            } else {
                format!(
                    "~ agent  {}  swaps {} for {}",
                    agent_name(*id),
                    engine_name(inventory, *previous_weapon_uid, names),
                    engine_name(inventory, *weapon_uid, names)
                )
            }
        }
        ItemChange::AgentRemoved { id } => format!("- agent  {}", agent_name(*id)),
    }
}

/// A bounded queue of change-log lines. The GUI's console panel is a ring
/// buffer: old lines fall off the front so a long session cannot grow it
/// without limit.
#[derive(Debug)]
pub struct ChangeLog {
    entries: Mutex<VecDeque<LogEntry>>,
    next: AtomicU64,
    capacity: usize,
    dropped: AtomicU64,
}

impl ChangeLog {
    /// Keeps the most recent `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
            next: AtomicU64::new(1),
            capacity,
            dropped: AtomicU64::new(0),
        }
    }

    pub fn push(&self, mut entries: Vec<LogEntry>) {
        let mut next = self.next.load(Ordering::Relaxed);
        for entry in &mut entries {
            entry.sequence = next;
            next += 1;
        }
        self.next.store(next, Ordering::Relaxed);

        let mut held = self.entries.lock().unwrap();
        held.extend(entries);
        while held.len() > self.capacity {
            held.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A snapshot of the log, oldest first.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().unwrap().iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many entries fell off the front.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zzz_scan::ItemChange;

    #[test]
    fn the_change_log_is_a_ring_buffer_with_sequence_numbers() {
        let log = ChangeLog::new(3);
        let change = |text: &str| LogEntry {
            sequence: 0,
            text: text.to_string(),
            change: ItemChange::AgentRemoved { id: 1 },
        };
        for index in 0..5 {
            log.push(vec![change(&format!("line {index}"))]);
        }

        let held = log.entries();
        assert_eq!(held.len(), 3, "capacity");
        assert_eq!(held[0].text, "line 2", "oldest fell off");
        assert_eq!(
            held.iter().map(|entry| entry.sequence).collect::<Vec<_>>(),
            vec![3, 4, 5],
            "sequence numbers survive trimming"
        );
        assert_eq!(log.dropped(), 2);
    }

    #[test]
    fn a_batch_is_numbered_together() {
        let log = ChangeLog::new(10);
        log.push(vec![
            LogEntry {
                sequence: 0,
                text: "a".into(),
                change: ItemChange::AgentRemoved { id: 1 },
            },
            LogEntry {
                sequence: 0,
                text: "b".into(),
                change: ItemChange::AgentRemoved { id: 1 },
            },
        ]);
        assert_eq!(
            log.entries()
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn extraction_total_counts_every_field() {
        let summary = ExtractSummary {
            player_syncs: 1,
            discs_added: 2,
            engines_removed: 3,
            ..ExtractSummary::default()
        };
        assert_eq!(extraction_total(&summary), 6);
    }
}
