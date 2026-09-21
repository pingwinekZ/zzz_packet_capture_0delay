// A GUI app opens no console window on Windows: without this the linker keeps
// the console subsystem, so launching zzzgui.exe from Explorer parks an empty
// cmd window next to ours. Standard streams then go nowhere, which is fine —
// nothing here prints to them, and everything the user needs is in the
// window's own console panel.
#![windows_subsystem = "windows"]

//! The capture app's window — the port of `src/ui`, rethought around what the
//! tool actually does now.
//!
//! The reference GUI has three tabs (agents, engines, discs) and two controls
//! (region, capture) plus the live-export switch. This keeps all of that and
//! adds what the rewrite makes possible: a **console** that logs every
//! item-level change as it is captured — who equipped which w-engine, which disc
//! was dismantled, what a pull added — because the extraction now produces those
//! events and the reference GUI never showed them.
//!
//! Threading follows the reference's observer model: the capture thread feeds
//! `zzz_session::Session`, and results reach the UI through channels that
//! [`App::logic`] drains. The UI thread never touches the decoder; the capture
//! thread never touches the UI.
//!
//! Layout note: eframe 0.36 gives `App::ui` a plain `egui::Ui`, so the panels
//! are added *inside* it — `egui::Panel` first, `CentralPanel` last, which is
//! the order the egui docs require.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use eframe::egui;
use zzz_capture::{Capture, GAME_PORT};
use zzz_export::{ExportSettings, Izod, NanokaNames};
use zzz_gamedata::{GameData, HttpFetcher}; // HttpFetcher: background auto-update on startup
use zzz_live::Server;
use zzz_scan::Inventory;
use zzz_session::{Callbacks, ChangeLog, LogEntry, Session, Status};

/// Where the data files live, relative to where the app is started — the same
/// default the CLI uses.
const DEFAULT_ASSETS: &str = "../assets";

/// Picks the assets directory. `DEFAULT_ASSETS` (working directory) wins when
/// it holds usable files, so development checkouts keep working; otherwise a
/// folder shipped next to the executable — or above it — is used, so a
/// release folder carrying its own `assets/` works wherever it is unpacked.
/// When nothing loads anywhere, the download targets the folder next to the
/// executable, keeping a portable install self-contained.
fn resolve_assets() -> PathBuf {
    let fallback = PathBuf::from(DEFAULT_ASSETS);
    if GameData::load(&fallback).is_ok() {
        return fallback;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in [dir.join("assets"), dir.join(DEFAULT_ASSETS)] {
                if GameData::load(&candidate).is_ok() {
                    return candidate;
                }
            }
            return dir.join("assets");
        }
    }
    fallback
}

/// The reference's live-export port.
const LIVE_PORT: u16 = zzz_live::DEFAULT_PORT;

/// How many console lines the window keeps. Old ones fall off the front.
const CONSOLE_LINES: usize = 400;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 640.0])
            .with_title("ZZZ Packet Capture"),
        ..Default::default()
    };
    eframe::run_native(
        "zzz-gui",
        options,
        Box::new(|_creation| Ok(Box::new(App::new(resolve_assets())))),
    )
}

/// One session's worth of worker state: the capture thread and the server it
/// feeds. Stopped (and joined) when the user presses stop or closes the window.
struct Running {
    capture: Arc<Capture>,
    server: Option<Arc<Server>>,
    worker: Option<JoinHandle<()>>,
}

impl Running {
    /// Stops the driver and the server and joins the worker. Safe twice.
    fn stop(&mut self) {
        self.capture.stop();
        if let Some(server) = &self.server {
            server.stop();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.server = None;
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Default)]
struct App {
    assets: PathBuf,
    data: Option<Result<Arc<GameData>, String>>,

    /// Set while the background auto-update thread runs. The UI stays usable;
    /// [`App::logic`] picks up the result.
    updating: bool,
    update_rx: Option<Receiver<UpdateOutcome>>,
    /// Non-fatal note from the last auto-update (e.g. "updated to 3.2" or
    /// "could not check for updates: offline, using local copy").
    update_note: Option<String>,

    region: Option<String>,
    capturing: bool,
    live_export: bool,

    settings: ExportSettings,
    port: u16,

    running: Option<Running>,
    /// The settings the capture thread reads each packet. The checkboxes edit
    /// `settings`; while capturing it is mirrored here so the running session
    /// picks toggles up without a restart.
    live_settings: Option<Arc<Mutex<ExportSettings>>>,
    log_tx: Option<Sender<String>>,
    log_rx: Option<Receiver<String>>,
    log_lines: Vec<String>,
    change_log: Option<Arc<ChangeLog>>,

    /// The latest inventory the capture thread published, if any. Kept after
    /// the capture stops so the result can still be copied.
    inventory: Option<Arc<Inventory>>,
    inv_rx: Option<Receiver<Arc<Inventory>>>,

    status: Status,
}

impl App {
    fn new(assets: PathBuf) -> Self {
        let mut app = Self {
            assets,
            settings: ExportSettings::default(),
            port: GAME_PORT,
            ..App::default()
        };
        // Try the local copy synchronously so a good install is usable
        // immediately, then reconcile with the published files in the
        // background (download when missing, refresh when stale).
        match GameData::load(&app.assets) {
            Ok(data) => {
                app.data = Some(Ok(Arc::new(data)));
                app.begin_auto_update(false);
            }
            Err(_) => {
                app.begin_auto_update(true);
            }
        }
        app
    }

    /// Starts the background ensure: download when the files are missing,
    /// refresh when the published manifest is newer (or the name cache is
    /// empty). `blocking` only decides the initial UI state; the work always
    /// happens off the UI thread. Safe to call twice — the second call is a
    /// no-op while an update is in flight.
    fn begin_auto_update(&mut self, blocking: bool) {
        if self.updating {
            return;
        }
        // "Reload data" clears `self.data`; keep that as a manual trigger even
        // when the files load fine locally.
        if blocking {
            self.data = None;
        }
        self.updating = true;
        self.update_note = if blocking {
            Some(format!(
                "Downloading data files into {}…",
                self.assets.display()
            ))
        } else {
            Some("Checking for data updates…".to_string())
        };
        let (tx, rx) = channel::<UpdateOutcome>();
        self.update_rx = Some(rx);
        let assets = self.assets.clone();
        let had_local = !blocking;
        let _ = std::thread::Builder::new()
            .name("zzz-data-update".to_string())
            .spawn(move || {
                let _ = tx.send(ensure_data(assets, had_local));
            });
    }

    /// Picks up a finished background auto-update, if any. Called from
    /// [`logic`](eframe::App::logic) so it runs even while the window is
    /// hidden.
    fn poll_update(&mut self) {
        let done = match &self.update_rx {
            Some(rx) => match rx.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(UpdateOutcome {
                    data: None,
                    note: Some("data update thread stopped unexpectedly".to_string()),
                }),
            },
            None => None,
        };
        if let Some(outcome) = done {
            self.update_rx = None;
            self.updating = false;
            if let Some(data) = outcome.data {
                self.data = Some(data.map(Arc::new));
            }
            self.update_note = outcome.note;
        }
    }

    /// Loads (or reloads) the data files. Retried from "Refresh data".
    fn data(&mut self) -> Option<Arc<GameData>> {
        if self.data.is_none() {
            let path = self.assets.clone();
            self.data = Some(
                GameData::load(&path)
                    .map(Arc::new)
                    .map_err(|e| e.to_string()),
            );
        }
        match self.data.as_ref() {
            Some(Ok(data)) => Some(Arc::clone(data)),
            _ => None,
        }
    }

    fn data_error(&self) -> Option<&str> {
        match self.data.as_ref() {
            Some(Err(error)) => Some(error),
            _ => None,
        }
    }

    /// Builds the ZOD export from the last published inventory and copies it,
    /// like `zzzcap export` with the window's Sync toggles. A refusal (an id
    /// the name cache does not know) lands in the console instead, with the
    /// fix next to it.
    fn copy_zod(&mut self, ctx: &egui::Context) {
        let (Some(inventory), Some(data)) = (self.inventory.clone(), self.data()) else {
            return;
        };
        match Izod::from_inventory(&inventory, &NanokaNames(&data.nanoka), &self.settings) {
            Ok(zod) => {
                let json = zod.to_json();
                ctx.output_mut(|o| o.commands.push(egui::OutputCommand::CopyText(json.clone())));
                self.log_lines.push(format!(
                    "copied ZOD ({} KiB: {} discs, {} w-engines, {} agents)",
                    json.len() / 1024,
                    zod.discs.as_ref().map_or(0, Vec::len),
                    zod.wengines.as_ref().map_or(0, Vec::len),
                    zod.characters.as_ref().map_or(0, Vec::len),
                ));
            }
            Err(error) => self.log_lines.push(format!(
                "copy failed: {error} — press “Check for updates” for fresh names"
            )),
        }
    }

    /// Starts capture, and the live server alongside it if the switch is on.
    fn start(&mut self) {
        let (log_tx, log_rx) = channel::<String>();
        self.log_tx = Some(log_tx.clone());
        self.log_rx = Some(log_rx);

        let Some(data) = self.data() else {
            let reason = self
                .data_error()
                .unwrap_or("data files are not loaded")
                .to_string();
            let _ = log_tx.send(format!("cannot start capture: {reason}"));
            return;
        };

        let change_log = Arc::new(ChangeLog::new(CONSOLE_LINES));
        self.change_log = Some(Arc::clone(&change_log));
        self.log_lines.clear();
        self.inventory = None;
        self.status = Status::default();
        let (inv_tx, inv_rx) = channel::<Arc<Inventory>>();
        self.inv_rx = Some(inv_rx);

        // The server starts before the capture, exactly as the reference's
        // toggle does, so a client that connects during the login is served —
        // with the latest snapshot once there is one.
        let server = if self.live_export {
            let server = Arc::new(Server::new());
            match server.start(LIVE_PORT) {
                Ok(()) => Some(server),
                Err(error) => {
                    let _ = log_tx.send(format!("ws: {error}; continuing without live export"));
                    self.live_export = false;
                    None
                }
            }
        } else {
            None
        };

        let capture = match Capture::open(self.port) {
            Ok(capture) => Arc::new(capture),
            Err(error) => {
                // Keep the log channel so the reason stays visible in the
                // console instead of vanishing with the receiver. Known causes
                // (no admin rights, missing driver) get their hint appended,
                // like the CLI does.
                let message = match error.hint() {
                    Some(hint) => format!("capture: {error}\n  {hint}"),
                    None => format!("capture: {error}"),
                };
                let _ = log_tx.send(message);
                if let Some(server) = &server {
                    server.stop();
                }
                return;
            }
        };

        let candidates =
            zzz_session::candidate_seeds(&data, self.region.as_deref(), None).unwrap_or_default();

        // Shared with the checkboxes: the worker re-reads it every packet so
        // mid-capture toggles apply without a restart.
        let settings = Arc::new(Mutex::new(self.settings));
        self.live_settings = Some(Arc::clone(&settings));

        let worker = std::thread::Builder::new()
            .name("zzz-capture".to_string())
            .spawn({
                let data = Arc::clone(&data);
                let capture = Arc::clone(&capture);
                let changes = Arc::clone(&change_log);
                let log_tx = log_tx.clone();
                let server_thread = server.clone();
                let settings = Arc::clone(&settings);
                move || {
                    run_session(SessionArgs {
                        data,
                        candidates,
                        capture,
                        server: server_thread,
                        change_log: changes,
                        log_tx,
                        settings,
                        inv_tx,
                    })
                }
            })
            .ok();

        self.running = Some(Running {
            capture,
            server,
            worker,
        });
        self.capturing = true;
        let _ = log_tx.send(format!(
            "listening on UDP {} — start the game and log in",
            self.port
        ));
    }

    fn stop(&mut self) {
        if let Some(mut running) = self.running.take() {
            running.stop();
        }
        self.capturing = false;
        self.live_settings = None;
        if let Some(log_tx) = &self.log_tx {
            let _ = log_tx.send("stopped".to_string());
        }
    }

    /// Drains the channels the capture thread writes. Called from `logic`, so
    /// it also runs while the window is hidden.
    fn drain(&mut self) {
        let mut lines = Vec::new();
        if let Some(receiver) = &self.log_rx {
            while let Ok(line) = receiver.try_recv() {
                lines.push(line);
            }
        }
        for line in lines {
            // The status lines are machine-readable counters, not console
            // text; they update the header instead of scrolling by.
            if let Some(status) = line.strip_prefix("status|") {
                self.apply_status(status);
            } else {
                self.log_lines.push(line);
            }
        }
        if self.log_lines.len() > CONSOLE_LINES {
            let excess = self.log_lines.len() - CONSOLE_LINES;
            self.log_lines.drain(..excess);
        }
        // Only the newest inventory matters for the copy button; older ones
        // are dropped unread.
        if let Some(receiver) = &self.inv_rx {
            while let Ok(inventory) = receiver.try_recv() {
                self.inventory = Some(inventory);
            }
        }
    }

    /// Parses one `packets|snapshots|discs|engines|agents|region` line.
    fn apply_status(&mut self, fields: &str) {
        let mut parts = fields.split('|');
        let number = |index: usize| -> u64 {
            parts
                .clone()
                .nth(index)
                .and_then(|part| part.parse().ok())
                .unwrap_or(0)
        };
        self.status = Status {
            packets: number(0),
            snapshots: number(1),
            discs: number(2) as usize,
            engines: number(3) as usize,
            agents: number(4) as usize,
            region: parts
                .nth(5)
                .and_then(|region| (region != "-").then(|| region.to_string())),
        };
    }
}

/// The result the background auto-update thread hands back to the UI.
struct UpdateOutcome {
    /// `None` when nothing changed (local copy was already current and is
    /// already in `App::data`); `Some` when the files were (re)loaded.
    data: Option<Result<GameData, String>>,
    note: Option<String>,
}

/// Loads the data files, downloading/refreshing them when needed. Runs off the
/// UI thread; see [`App::begin_auto_update`].
///
/// * Missing or unreadable files are fetched unconditionally.
/// * A present copy is kept as-is unless the published manifest is newer or
///   the nanoka name cache is empty, in which case [`refresh`](zzz_gamedata::refresh)
///   runs and the files are reloaded.
/// * A failed refresh never discards a usable local copy: the local data is
///   returned with a warning note. Only when there is no local copy does the
///   fetch error become the result.
fn ensure_data(assets: PathBuf, had_local: bool) -> UpdateOutcome {
    let local = GameData::load(&assets);
    let fetcher = HttpFetcher::new();

    // Missing files: this is the first-run case from the bug report. There is
    // nothing to compare against, so fetch straight away.
    let local = match local {
        Ok(data) => data,
        Err(load_error) => {
            return fetch_then_load(&assets, &fetcher, None, &load_error.to_string())
        }
    };

    let nanoka_empty = local.nanoka.characters.is_empty() && local.nanoka.weapons.is_empty();
    let stale = match zzz_gamedata::update_available(&assets, &fetcher) {
        Ok(available) => available,
        Err(error) => {
            // Offline: keep working with what is on disk.
            return UpdateOutcome {
                data: had_local.then_some(Ok(local)),
                note: Some(format!(
                    "could not check for updates ({error}); using local copy"
                )),
            };
        }
    };
    if !stale && !nanoka_empty {
        return UpdateOutcome {
            data: had_local.then_some(Ok(local)),
            note: None,
        };
    }

    match zzz_gamedata::refresh(&assets, &fetcher) {
        Ok(report) => match GameData::load(&assets) {
            Ok(reloaded) => {
                let mut note = match report.version {
                    Some(version) => format!("data files updated (version {version})"),
                    None => "data files updated".to_string(),
                };
                if !report.kept_local.is_empty() {
                    let kept: Vec<String> = report
                        .kept_local
                        .iter()
                        .map(|(name, reasons)| format!("{name}: {}", reasons.join(", ")))
                        .collect();
                    note = format!("{note}; kept local {}", kept.join("; "));
                }
                UpdateOutcome {
                    data: Some(Ok(reloaded)),
                    note: Some(note),
                }
            }
            Err(error) => UpdateOutcome {
                data: Some(Ok(local)),
                note: Some(format!(
                    "update downloaded but the result would not load ({error}); using previous copy"
                )),
            },
        },
        Err(error) => UpdateOutcome {
            data: had_local.then_some(Ok(local)),
            note: Some(format!("data update failed ({error}); using local copy")),
        },
    }
}

/// Fetches everything into `assets` and loads it. `previous_error` is the load
/// failure that triggered the download, so an offline machine gets both facts.
fn fetch_then_load(
    assets: &std::path::Path,
    fetcher: &HttpFetcher,
    local: Option<GameData>,
    previous_error: &str,
) -> UpdateOutcome {
    match zzz_gamedata::refresh(assets, fetcher) {
        Ok(report) => match GameData::load(assets) {
            Ok(data) => {
                let note = match report.version {
                    Some(version) => {
                        format!("downloaded data files (version {version})")
                    }
                    None => "downloaded data files".to_string(),
                };
                UpdateOutcome {
                    data: Some(Ok(data)),
                    note: Some(note),
                }
            }
            Err(error) => match local {
                Some(data) => UpdateOutcome {
                    data: Some(Ok(data)),
                    note: Some(format!(
                        "download completed but the files would not load ({error}); using previous copy"
                    )),
                },
                None => {
                    // Refresh can succeed without writing datamine/nap when the
                    // published copies are refused (stale or unparseable for
                    // this build). Surface that instead of a bare IO error.
                    let refusal = report
                        .kept_local
                        .iter()
                        .map(|(name, reasons)| format!("{name}: {}", reasons.join(", ")))
                        .collect::<Vec<_>>()
                        .join("; ");
                    let detail = if refusal.is_empty() {
                        error.to_string()
                    } else {
                        format!("{error}; published files refused ({refusal})")
                    };
                    UpdateOutcome {
                        data: Some(Err(format!("{previous_error}; download also failed: {detail}"))),
                        note: None,
                    }
                }
            },
        },
        Err(fetch_error) => match local {
            Some(data) => UpdateOutcome {
                data: Some(Ok(data)),
                note: Some(format!(
                    "data download failed ({fetch_error}); using local copy"
                )),
            },
            None => UpdateOutcome {
                data: Some(Err(format!(
                    "{previous_error}; automatic download failed: {fetch_error} — \
                     check the connection or run `zzzcap update` in {}",
                    assets.display()
                ))),
                note: None,
            },
        },
    }
}

/// What the capture thread needs. Bundled so [`run_session`] does not grow a
/// parameter per feature.
struct SessionArgs {
    data: Arc<GameData>,
    candidates: Vec<(String, u64)>,
    capture: Arc<Capture>,
    server: Option<Arc<Server>>,
    change_log: Arc<ChangeLog>,
    log_tx: Sender<String>,
    settings: Arc<Mutex<ExportSettings>>,
    inv_tx: Sender<Arc<Inventory>>,
}

/// The capture thread's body: open a session, feed it every packet the driver
/// hands over, and stop on the first hard error or when the driver is stopped.
fn run_session(args: SessionArgs) {
    let SessionArgs {
        data,
        candidates,
        capture,
        server,
        change_log,
        log_tx,
        settings,
        inv_tx,
    } = args;
    let logger = {
        let log_tx = log_tx.clone();
        move |line: String| {
            let _ = log_tx.send(line);
        }
    };

    // The status channel shares the log's sender; the GUI parses the
    // `status|...` lines into counters instead of showing them.
    let status_log = log_tx.clone();

    let callbacks = Callbacks {
        log: Some(Arc::new(logger.clone())),
        snapshot: None,
        changes: {
            let change_log = Arc::clone(&change_log);
            Some(Arc::new(move |entries: Vec<LogEntry>| {
                change_log.push(entries);
            }))
        },
        status: Some(Arc::new(move |status: Status| {
            let _ = status_log.send(format!(
                "status|{}|{}|{}|{}|{}|{}",
                status.packets,
                status.snapshots,
                status.discs,
                status.engines,
                status.agents,
                status.region.as_deref().unwrap_or("-"),
            ));
        })),
        // The copy button reads the latest inventory off the UI thread, so
        // every published one is forwarded; the UI keeps only the newest.
        inventory: Some(Arc::new(move |inventory: Arc<Inventory>| {
            let _ = inv_tx.send(inventory);
        })),
    };

    // The server reads the session's latest snapshot through this hook once the
    // session exists, which is also why the session is created first. The
    // session also gets the server itself so every snapshot is broadcast to
    // already-connected clients — without it they would see "connected" but
    // never receive anything unless they reconnected after a snapshot landed.
    let mut session = Session::new(
        &data,
        candidates,
        *settings.lock().unwrap(),
        server.as_deref(),
        callbacks,
    );
    if let Some(server) = &server {
        let source = session.snapshot_source();
        server.on_snapshot_requested(move || source.lock().unwrap().clone());
    }

    let mut buffer = vec![0u8; 0xFFFF];
    loop {
        // The Sync checkboxes write through here: re-read the shared settings
        // every packet so mid-capture toggles apply to the next snapshot.
        session.set_settings(*settings.lock().unwrap());
        match capture.recv(&mut buffer) {
            Ok(Some(packet)) => {
                if let Err(error) = session.feed(&packet) {
                    logger(format!("error: {error}"));
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => {
                logger(format!("capture: {error}"));
                break;
            }
        }
    }
    capture.stop();
    if let Some(server) = &server {
        server.stop();
    }
}

impl eframe::App for App {
    /// Runs once per frame even when the window is hidden — this is where the
    /// channels are drained.
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_update();
        self.drain();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Panels are added inside the root ui in eframe 0.36, order matters,
        // and CentralPanel comes last.
        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(4.0);
            self.controls(ui);
            ui.add_space(4.0);
        });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                match (&self.status.region, self.capturing) {
                    (Some(region), true) => {
                        ui.label(format!("capturing — region {region}"));
                    }
                    (Some(region), false) => {
                        ui.label(format!("idle — last region {region}"));
                    }
                    (None, true) => {
                        ui.label("capturing — waiting for the login to detect the region…");
                    }
                    (None, false) => {
                        ui.label("idle");
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.monospace(format!(
                        "{} packets · {} snapshots · {} discs · {} w-engines · {} agents",
                        self.status.packets,
                        self.status.snapshots,
                        self.status.discs,
                        self.status.engines,
                        self.status.agents,
                    ));
                });
            });
        });

        egui::Panel::right("console")
            .resizable(true)
            .default_size(420.0)
            .min_size(260.0)
            .show(ui, |ui| {
                ui.heading("Console");
                ui.separator();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.log_lines {
                            ui.monospace(line);
                        }
                    });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            self.main_panel(ui);
        });

        // Stream the console while capturing, and keep polling while the
        // background data update runs.
        if self.capturing || self.updating {
            ui.ctx().request_repaint_after(Duration::from_millis(120));
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop();
    }
}

impl App {
    /// The header row: everything the reference's "Scanning" expander had.
    fn controls(&mut self, ui: &mut egui::Ui) {
        let data_ready = self.data().is_some();

        // Region picker, pre-populated from datamine.json. Auto-detect is the
        // default and almost always right. Locked while capturing: the region
        // candidates are fixed when the session starts, so a mid-capture
        // change would silently do nothing.
        let regions: Vec<String> = self
            .data()
            .map(|data| {
                let mut names: Vec<String> = data.datamine.xor_seeds.keys().cloned().collect();
                names.sort();
                names
            })
            .unwrap_or_default();
        ui.add_enabled_ui(!self.capturing, |ui| {
            egui::ComboBox::from_id_salt("region")
                .selected_text(self.region.clone().unwrap_or_else(|| "Auto-detect".into()))
                .width(130.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.region, None, "Auto-detect");
                    for name in &regions {
                        ui.selectable_value(&mut self.region, Some(name.clone()), name.clone());
                    }
                });
        });

        ui.separator();

        let start_stop = egui::Button::new(if self.capturing {
            "Capturing… (click to stop)"
        } else {
            "Start capture"
        });
        if ui
            .add_enabled(data_ready || self.capturing, start_stop)
            .clicked()
        {
            if self.capturing {
                self.stop();
            } else {
                self.start();
            }
        }
        if !data_ready && !self.capturing {
            ui.weak("waiting for data files…");
        }

        // The live-export toggle. Turning it on mid-capture starts the server
        // immediately and the next snapshot is served; turning it off stops it,
        // exactly like the reference's toggle. Turning it on while idle arms
        // it: the server starts with the next capture.
        let toggle = egui::Button::new(if self.live_export {
            "Live export: On"
        } else {
            "Live export: Off"
        });
        if ui.add(toggle).clicked() {
            self.live_export = !self.live_export;
            match (&mut self.running, self.live_export) {
                (Some(running), true) => {
                    let server = Arc::new(Server::new());
                    if let Some(log_tx) = &self.log_tx {
                        let log_tx = log_tx.clone();
                        server.on_log(move |line| {
                            let _ = log_tx.send(line.to_string());
                        });
                    }
                    match server.start(LIVE_PORT) {
                        Ok(()) => {
                            running.server = Some(server);
                            let _ = self.log_tx.as_ref().map(|tx| {
                                tx.send(format!("ws: listening on ws://127.0.0.1:{LIVE_PORT}/ws"))
                            });
                        }
                        Err(error) => {
                            self.live_export = false;
                            if let Some(log_tx) = &self.log_tx {
                                let _ = log_tx.send(format!("ws: {error}"));
                            }
                        }
                    }
                }
                (Some(running), false) => {
                    if let Some(server) = running.server.take() {
                        server.stop();
                    }
                }
                // Idle: there is no server yet, so keep the flag. Start capture
                // picks it up and starts the server alongside the session.
                (None, _) => {}
            }
        }

        ui.separator();
        ui.label("Sync:");
        ui.checkbox(&mut self.settings.export_discs, "Discs");
        ui.checkbox(&mut self.settings.export_engines, "W-engines");
        ui.checkbox(&mut self.settings.export_agents, "Agents");
        // While capturing the worker owns a copy; mirror the toggles into it
        // so they apply to the next snapshot without a restart.
        if let Some(live) = &self.live_settings {
            *live.lock().unwrap() = self.settings;
        }

        ui.separator();
        if ui.button("Reload data").clicked() {
            // Drop the cached copy and re-resolve: local reload first, then a
            // background freshness check (or a full download when missing).
            self.data = None;
            self.update_note = None;
            match GameData::load(&self.assets) {
                Ok(data) => {
                    self.data = Some(Ok(Arc::new(data)));
                    self.begin_auto_update(false);
                }
                Err(_) => {
                    self.begin_auto_update(true);
                }
            }
        }
        if ui.button("Check for updates").clicked() {
            self.begin_auto_update(false);
        }
        if self.updating {
            ui.spinner();
        } else if let Some(note) = self.update_note.clone() {
            ui.label(note);
        }
    }

    /// The centre: the data-file error, the idle note, or the inventory.
    fn main_panel(&mut self, ui: &mut egui::Ui) {
        if self.updating && self.data.is_none() {
            ui.heading("Downloading data files…");
            ui.label(
                self.update_note
                    .clone()
                    .unwrap_or_else(|| "Fetching datamine.json, nap.json and names…".to_string()),
            );
            ui.label(format!("Target: {}", self.assets.display()));
            ui.spinner();
            return;
        }
        if let Some(error) = self.data_error() {
            ui.heading("Data files missing");
            ui.label(error);
            ui.label(format!(
                "The app tried to download datamine.json, nap.json and manifest.json into {} automatically.",
                self.assets.display()
            ));
            if ui.button("Retry download / check for updates").clicked() {
                self.data = None;
                self.update_note = None;
                self.begin_auto_update(true);
            }
            return;
        }

        let Some(change_log) = &self.change_log else {
            ui.heading("Not capturing");
            ui.label(
                "Press “Start capture”, then log into the game. The region is \
                      detected from the login automatically unless you pick one.",
            );
            if self.updating {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        self.update_note
                            .clone()
                            .unwrap_or_else(|| "Checking for data updates…".to_string()),
                    );
                });
            } else if let Some(note) = self.update_note.clone() {
                ui.label(note);
            }
            return;
        };

        let entries = change_log.entries();
        let mut discs_added = 0usize;
        let mut engines_added = 0usize;
        let mut agents_added = 0usize;
        let mut discs_removed = 0usize;
        let mut engines_removed = 0usize;
        for entry in &entries {
            match &entry.change {
                zzz_scan::ItemChange::DiscAdded { .. } => discs_added += 1,
                zzz_scan::ItemChange::EngineAdded { .. } => engines_added += 1,
                zzz_scan::ItemChange::AgentAdded { .. } => agents_added += 1,
                zzz_scan::ItemChange::DiscRemoved { .. } => discs_removed += 1,
                zzz_scan::ItemChange::EngineRemoved { .. } => engines_removed += 1,
                _ => {}
            }
        }
        ui.heading("This session");
        ui.label(format!(
            "{discs_added} discs added · {discs_removed} removed · \
             {engines_added} w-engines added · {engines_removed} removed · \
             {agents_added} agents added"
        ));
        if self.status.packets > 0 {
            ui.separator();
            ui.label(format!(
                "inventory now: {} discs, {} w-engines, {} agents",
                self.status.discs, self.status.engines, self.status.agents,
            ));
        }
        // The file-export equivalent of `zzzcap export` with the window's
        // Sync toggles: works with live export off, and after the capture
        // stopped, from the last published inventory.
        let can_copy = self.inventory.is_some() && self.data().is_some();
        if ui
            .add_enabled(can_copy, egui::Button::new("Copy ZOD JSON"))
            .clicked()
        {
            self.copy_zod(ui.ctx());
        }

        ui.separator();
        ui.heading("Changes");
        ui.add_space(2.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            for entry in entries.iter().rev() {
                // Newest at the top, like a feed. The sequence number keeps the
                // capture order readable even after trimming.
                ui.monospace(format!("{:>4}  {}", entry.sequence, entry.text));
            }
            if entries.is_empty() {
                ui.weak(
                    "Nothing yet. Discs, w-engines and agents appear here as \
                         the game sends them.",
                );
            }
        });
    }
}
