//! Loading and refreshing of the data files the parser depends on.
//!
//! The C++ build scattered this over three function-local `static`s
//! (`Datamine::get`, `Proto::get`, `NanokaData::get`) that each did their own
//! hidden network fetch and threw on failure. Here the four files are loaded into
//! one [`GameData`] value, updating is an explicit call, and a missing or stale
//! file is reported rather than thrown from inside a getter.

pub mod datamine;
pub mod fetch;
pub mod nanoka;
pub mod version;

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub use datamine::Datamine;
pub use fetch::{ClosureFetcher, Fetcher, HttpFetcher, OfflineFetcher, StaticFetcher};
pub use nanoka::NanokaData;
pub use version::Version;
pub use zzz_wire::{ProtoEntry, Protonap};

/// Where the committed data files are published (this fork's assets).
const RAW_BASE: &str =
    "https://raw.githubusercontent.com/pingwinekZ/zzz_packet_capture_0delay/refs/heads/master/assets";

pub fn manifest_url() -> String {
    format!("{RAW_BASE}/{MANIFEST_FILE}")
}

pub fn datamine_url() -> String {
    format!("{RAW_BASE}/{DATAMINE_FILE}")
}

pub fn proto_url() -> String {
    format!("{RAW_BASE}/{PROTO_FILE}")
}

pub const MANIFEST_FILE: &str = "manifest.json";
pub const DATAMINE_FILE: &str = "datamine.json";
pub const PROTO_FILE: &str = "nap.json";
pub const NANOKA_FILE: &str = "nanokaData.json";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    #[serde(default)]
    pub version: String,
}

#[derive(Debug)]
pub enum DataError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: Option<PathBuf>,
        source: serde_json::Error,
    },
    Fetch(String),
    Invalid(String),
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Json {
                path: Some(path),
                source,
            } => {
                write!(f, "{}: {source}", path.display())
            }
            Self::Json { path: None, source } => write!(f, "{source}"),
            Self::Fetch(url) => write!(f, "{url}"),
            Self::Invalid(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DataError {}

fn read_file(path: &Path) -> Result<String, DataError> {
    std::fs::read_to_string(path).map_err(|source| DataError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn parse<T: serde::de::DeserializeOwned>(path: &Path, json: &str) -> Result<T, DataError> {
    serde_json::from_str(json).map_err(|source| DataError::Json {
        path: Some(path.to_path_buf()),
        source,
    })
}

/// `assets/manifest.json`.
pub fn local_manifest(assets_dir: &Path) -> Option<Manifest> {
    let json = read_file(&assets_dir.join(MANIFEST_FILE)).ok()?;
    serde_json::from_str(&json).ok()
}

pub fn local_version(assets_dir: &Path) -> Option<Version> {
    local_manifest(assets_dir).map(|m| Version::parse(&m.version))
}

/// Everything the parser needs, loaded from disk.
#[derive(Debug)]
pub struct GameData {
    pub datamine: Datamine,
    pub proto_entries: Vec<ProtoEntry>,
    pub nap: Protonap,
    pub nanoka: NanokaData,
}

impl GameData {
    /// Load `datamine.json`, `nap.json` and (if present) `nanokaData.json`.
    ///
    /// `nanokaData.json` is a cache of a network resource, so a missing or
    /// unreadable copy leaves [`GameData::nanoka`] empty rather than failing the
    /// load — names then fall back to blank strings.
    pub fn load(assets_dir: &Path) -> Result<Self, DataError> {
        let datamine_path = assets_dir.join(DATAMINE_FILE);
        let datamine =
            Datamine::parse(&read_file(&datamine_path)?).map_err(|source| DataError::Json {
                path: Some(datamine_path),
                source,
            })?;

        let proto_path = assets_dir.join(PROTO_FILE);
        let entries: Vec<ProtoEntry> = parse(&proto_path, &read_file(&proto_path)?)?;

        let nanoka = read_file(&assets_dir.join(NANOKA_FILE))
            .ok()
            .and_then(|json| serde_json::from_str::<NanokaData>(&json).ok())
            .unwrap_or_default();

        Ok(Self {
            datamine,
            nap: Protonap::new(entries.clone()),
            proto_entries: entries,
            nanoka,
        })
    }

    pub fn seed_for_region(&self, region: &str) -> Option<u64> {
        self.datamine.seed_for_region(region)
    }

    pub fn region_for_seed(&self, seed: u64) -> Option<&str> {
        self.datamine.region_for_seed(seed)
    }
}

/// What [`refresh`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RefreshReport {
    /// Names of the files that were replaced.
    pub updated_files: Vec<&'static str>,
    /// The `version` from the manifest that was downloaded, if one was.
    pub version: Option<Version>,
    /// The nanoka `zzz.live` version the cache was refreshed to, if it was.
    pub nanoka_version: Option<String>,
    /// Files that were fetched but *not* written, because the published copy is
    /// not usable. Each entry names why; see [`datamine_refusal`].
    pub kept_local: Vec<(&'static str, Vec<String>)>,
    /// Files that were perfectly usable but not written, because their partner
    /// was refused and the two have to move together.
    pub held_back: Vec<&'static str>,
}

impl RefreshReport {
    pub fn is_empty(&self) -> bool {
        self.updated_files.is_empty()
    }

    /// Whether anything was refused for being older than the local copy.
    pub fn kept_local_names(&self) -> Vec<&'static str> {
        self.kept_local.iter().map(|(name, _)| *name).collect()
    }
}

/// `Home::State::initState`: is the committed manifest older than the published
/// one?
pub fn update_available(assets_dir: &Path, fetcher: &dyn Fetcher) -> Result<bool, DataError> {
    let latest = fetch_manifest(fetcher)?;
    let local = local_version(assets_dir).unwrap_or_default();
    Ok(local < Version::parse(&latest.version))
}

fn fetch_manifest(fetcher: &dyn Fetcher) -> Result<Manifest, DataError> {
    let url = manifest_url();
    let body = fetcher.get(&url).map_err(DataError::Fetch)?;
    serde_json::from_str(&body).map_err(|source| DataError::Json { path: None, source })
}

/// `Home::State::updateData`: replace the data files from the published copies,
/// then refresh the nanoka cache if it is for a different game version.
pub fn refresh(assets_dir: &Path, fetcher: &dyn Fetcher) -> Result<RefreshReport, DataError> {
    let mut report = RefreshReport::default();
    std::fs::create_dir_all(assets_dir).map_err(|source| DataError::Io {
        path: assets_dir.to_path_buf(),
        source,
    })?;

    let manifest_body = fetcher.get(&manifest_url()).map_err(DataError::Fetch)?;
    let manifest: Manifest = serde_json::from_str(&manifest_body)
        .map_err(|source| DataError::Json { path: None, source })?;
    let version = Version::parse(&manifest.version);

    write(assets_dir, MANIFEST_FILE, &manifest_body, &mut report)?;

    let datamine_body = fetcher.get(&datamine_url()).map_err(DataError::Fetch)?;
    let proto_body = fetcher.get(&proto_url()).map_err(DataError::Fetch)?;

    // One guard for both files: they are generated together for a game version,
    // so writing one without the other would leave the parser reading field
    // numbers from one version and XOR values from another. If either is
    // refused, neither is written and the local copies stay. Note this runs
    // *before* parsing, because an older published file is a refusal rather than
    // a hard failure.
    let mut kept = Vec::new();
    if let Some(reasons) = datamine_refusal(&local_body(assets_dir, DATAMINE_FILE), &datamine_body)
    {
        kept.push((DATAMINE_FILE, reasons));
    }
    if let Some(reasons) = nap_refusal(&local_body(assets_dir, PROTO_FILE), &proto_body) {
        kept.push((PROTO_FILE, reasons));
    }
    if kept.is_empty() {
        write(assets_dir, DATAMINE_FILE, &datamine_body, &mut report)?;
        write(assets_dir, PROTO_FILE, &proto_body, &mut report)?;
    } else {
        // Whichever of the pair was not itself refused is held back with it, and
        // reported as such: "already current" would be wrong about a file that
        // was fine but deliberately left alone.
        for name in [DATAMINE_FILE, PROTO_FILE] {
            if !kept.iter().any(|(refused, _)| *refused == name) {
                report.held_back.push(name);
            }
        }
        report.kept_local = kept;
    }

    // The nanoka cache is independent of the two files above, so it is refreshed
    // either way: it only ever contributes display names.
    report.nanoka_version = refresh_nanoka(assets_dir, fetcher, &mut report)?;
    report.version = Some(version);
    Ok(report)
}

fn refresh_nanoka(
    assets_dir: &Path,
    fetcher: &dyn Fetcher,
    report: &mut RefreshReport,
) -> Result<Option<String>, DataError> {
    let manifest_body = fetcher
        .get(nanoka::MANIFEST_URL)
        .map_err(DataError::Fetch)?;
    let manifest = nanoka::NanokaManifest::parse(&manifest_body)
        .map_err(|source| DataError::Json { path: None, source })?;
    let live = manifest.zzz.live;
    if live.is_empty() {
        return Ok(None);
    }

    let cached = read_file(&assets_dir.join(NANOKA_FILE))
        .ok()
        .and_then(|json| serde_json::from_str::<NanokaData>(&json).ok());
    if cached.as_ref().is_some_and(|data| data.version == live) {
        return Ok(Some(live));
    }

    let characters = fetch_ok(fetcher, &nanoka::character_url(&live))?;
    let equipment = fetch_ok(fetcher, &nanoka::equipment_url(&live))?;
    let weapons = fetch_ok(fetcher, &nanoka::weapon_url(&live))?;
    let data = NanokaData::from_json(&live, &characters, &weapons, &equipment)
        .map_err(|source| DataError::Json { path: None, source })?;

    let body =
        serde_json::to_string(&data).map_err(|source| DataError::Json { path: None, source })?;
    write(assets_dir, NANOKA_FILE, &body, report)?;
    Ok(Some(data.version))
}

/// The local copy of a data file, or an empty string if there is not one.
fn local_body(assets_dir: &Path, name: &'static str) -> String {
    read_file(&assets_dir.join(name)).unwrap_or_default()
}

/// Why a fetched `datamine.json` must not replace the local copy, if it must not.
///
/// Two situations, both reported rather than fatal so the rest of a refresh still
/// happens: the published copy is older and would drop keys the local one has,
/// or this build cannot parse it at all (a published schema the binary predates).
fn datamine_refusal(local: &str, published: &str) -> Option<Vec<String>> {
    if let Some(dropped) = dropped_keys(local, published) {
        return Some(
            dropped
                .into_iter()
                .map(|key| format!("drops `{key}`"))
                .collect(),
        );
    }
    Datamine::parse(published)
        .err()
        .map(|error| vec![format!("this build cannot parse it: {error}")])
}

/// The same for `nap.json`.
fn nap_refusal(local: &str, published: &str) -> Option<Vec<String>> {
    if let Some(dropped) = dropped_nap_entries(local, published) {
        return Some(
            dropped
                .into_iter()
                .map(|name| format!("drops descriptor `{name}`"))
                .collect(),
        );
    }
    serde_json::from_str::<Vec<ProtoEntry>>(published)
        .err()
        .map(|error| vec![format!("this build cannot parse it: {error}")])
}

/// Top-level keys the local file has and a fetched copy does not.
///
/// This is how a *downgrade* is caught, and comparing version strings cannot do
/// it: `manifest.json`'s version does not change when fields are added, so a
/// working copy that has grown `syncItemData` and friends still reports the same
/// number as an older published one. Replacing the file would then silently drop
/// field numbers the parser reads, and the symptom would be "extraction stopped
/// working", which looks exactly like a game update. `None` means there is
/// nothing to worry about.
fn dropped_keys(local: &str, published: &str) -> Option<Vec<String>> {
    let local = serde_json::from_str::<serde_json::Value>(local).ok()?;
    let published = serde_json::from_str::<serde_json::Value>(published).ok()?;
    let local = local.as_object()?;
    let published = published.as_object()?;
    let dropped: Vec<String> = local
        .keys()
        .filter(|key| !published.contains_key(*key))
        .cloned()
        .collect();
    (!dropped.is_empty()).then_some(dropped)
}

/// `nap.json` entry names the local file has and a fetched copy does not.
///
/// Losing a descriptor is worse than losing a field number: the descriptor
/// carries the XOR value that de-obfuscates a field, so a missing entry silently
/// produces garbage values instead of a parse error.
fn dropped_nap_entries(local: &str, published: &str) -> Option<Vec<String>> {
    fn names(body: &str) -> Option<Vec<String>> {
        let entries = serde_json::from_str::<Vec<ProtoEntry>>(body).ok()?;
        Some(entries.into_iter().map(|entry| entry.name).collect())
    }

    let mut local = names(local)?;
    local.sort_unstable();
    local.dedup();
    let published: std::collections::HashSet<String> = names(published)?.into_iter().collect();
    let dropped: Vec<String> = local
        .into_iter()
        .filter(|name| !published.contains(name))
        .collect();
    (!dropped.is_empty()).then_some(dropped)
}

fn fetch_ok(fetcher: &dyn Fetcher, url: &str) -> Result<String, DataError> {
    let body = fetcher.get(url).map_err(DataError::Fetch)?;
    if body.trim().is_empty() {
        return Err(DataError::Fetch(format!("empty response from {url}")));
    }
    Ok(body)
}

fn write(
    assets_dir: &Path,
    name: &'static str,
    body: &str,
    report: &mut RefreshReport,
) -> Result<(), DataError> {
    let path = assets_dir.join(name);
    std::fs::write(&path, body).map_err(|source| DataError::Io { path, source })?;
    report.updated_files.push(name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zzz-gamedata-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loads_the_committed_assets() {
        let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets");
        let data = GameData::load(&assets).expect("committed assets load");

        assert_eq!(data.datamine.cmd_player_sync_sc_notify, 1175);
        assert!(!data.proto_entries.is_empty());
        assert_eq!(data.nap.entries().len(), data.proto_entries.len());
        assert_eq!(data.seed_for_region("Asia"), Some(0x1A7E_69FE_2F49_590A));
        assert_eq!(local_version(&assets), Some(Version::parse("3.2")));
    }

    #[test]
    fn a_missing_asset_fails_with_the_path_in_the_error() {
        let dir = scratch_dir("missing");
        let err = GameData::load(&dir).unwrap_err();
        assert!(err.to_string().contains(DATAMINE_FILE), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refreshes_every_data_file_from_the_fetcher() {
        let dir = scratch_dir("refresh");
        let fetcher = StaticFetcher::new()
            .with(manifest_url(), r#"{"version":"9.9"}"#)
            .with(nanoka::MANIFEST_URL, r#"{"zzz":{"live":"9.9"}}"#)
            .with(
                nanoka::character_url("9.9"),
                r#"{"1":{"rank":0,"en":"New"}}"#,
            )
            .with(
                nanoka::equipment_url("9.9"),
                r#"{"2":{"en":{"name":"Set"}}}"#,
            )
            .with(nanoka::weapon_url("9.9"), r#"{"3":{"rank":1,"en":"Gun"}}"#);

        // datamine.json and nap.json are not canned, so the refresh must fail
        // before it writes anything that would break the cache.
        let err = refresh(&dir, &fetcher).unwrap_err();
        assert!(matches!(err, DataError::Fetch(_)));
        assert!(!dir.join(DATAMINE_FILE).exists());

        let datamine =
            read_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets/datamine.json"))
                .unwrap();
        let proto =
            read_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets/nap.json"))
                .unwrap();
        let fetcher = fetcher
            .with(datamine_url(), datamine)
            .with(proto_url(), proto);

        let report = refresh(&dir, &fetcher).unwrap();
        assert_eq!(
            report.updated_files,
            vec![MANIFEST_FILE, DATAMINE_FILE, PROTO_FILE, NANOKA_FILE]
        );
        assert_eq!(report.version, Some(Version::parse("9.9")));
        assert_eq!(report.nanoka_version.as_deref(), Some("9.9"));

        let data = GameData::load(&dir).unwrap();
        assert_eq!(data.nanoka.character_name(1), Some("New"));
        assert_eq!(local_version(&dir), Some(Version::parse("9.9")));

        // A second refresh is a no-op for nanoka, whose cache already matches.
        let report = refresh(&dir, &fetcher).unwrap();
        assert!(!report.updated_files.contains(&NANOKA_FILE));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The committed files, which are what a working copy has locally.
    fn committed(name: &str) -> String {
        read_file(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../assets")
                .join(name),
        )
        .expect("committed asset")
    }

    /// A fetcher that serves the committed files, with the two data files
    /// replaced by `datamine` and `proto`.
    fn fetcher_for(datamine: &str, proto: &str) -> StaticFetcher {
        StaticFetcher::new()
            .with(manifest_url(), r#"{"version":"3.2"}"#)
            .with(datamine_url(), datamine)
            .with(proto_url(), proto)
            .with(nanoka::MANIFEST_URL, r#"{"zzz":{"live":"3.2"}}"#)
            .with(nanoka::character_url("3.2"), r#"{"1":{"rank":0,"en":"A"}}"#)
            .with(nanoka::equipment_url("3.2"), r#"{"2":{"en":{"name":"S"}}}"#)
            .with(nanoka::weapon_url("3.2"), r#"{"3":{"rank":1,"en":"W"}}"#)
    }

    /// A directory holding the committed data files, as a working copy would.
    fn local_assets(name: &str) -> PathBuf {
        let dir = scratch_dir(name);
        std::fs::write(dir.join(DATAMINE_FILE), committed(DATAMINE_FILE)).unwrap();
        std::fs::write(dir.join(PROTO_FILE), committed(PROTO_FILE)).unwrap();
        dir
    }

    #[test]
    fn refuses_a_published_datamine_that_would_drop_keys() {
        // This is not hypothetical: the repository's published `datamine.json` is
        // older than the committed one and drops `syncItemData`, `equipDismantle`
        // and the sync command ids. The version string is the same in both, so
        // only the key set can tell them apart.
        let dir = local_assets("downgrade");
        let local = committed(DATAMINE_FILE);
        let older = local.replace("\"syncItemData\"", "\"itemSyncData\"");

        let report = refresh(&dir, &fetcher_for(&older, &committed(PROTO_FILE))).unwrap();

        assert_eq!(report.kept_local_names(), vec![DATAMINE_FILE]);
        assert_eq!(
            report.kept_local[0].1,
            vec!["drops `syncItemData`".to_string()]
        );
        // nap.json was fine on its own, but the two have to move together.
        assert_eq!(report.held_back, vec![PROTO_FILE]);
        assert_eq!(read_file(&dir.join(DATAMINE_FILE)).unwrap(), local);
        // The nanoka cache is independent, so it still refreshed: that is the
        // whole point of reporting a refusal rather than failing outright.
        assert!(report.updated_files.contains(&NANOKA_FILE));
        assert_eq!(report.nanoka_version.as_deref(), Some("3.2"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_a_published_nap_that_would_drop_descriptors() {
        // Losing a descriptor is worse than losing a field number: the descriptor
        // carries the XOR value, so the values come out garbled rather than
        // failing to parse.
        let dir = local_assets("shrink-nap");
        let mut entries: Vec<serde_json::Value> =
            serde_json::from_str(&committed(PROTO_FILE)).unwrap();
        let dropped = entries.last().unwrap()["name"]
            .as_str()
            .unwrap()
            .to_string();
        entries.pop();
        let smaller = serde_json::to_string(&entries).unwrap();

        let report = refresh(&dir, &fetcher_for(&committed(DATAMINE_FILE), &smaller)).unwrap();

        assert_eq!(report.kept_local_names(), vec![PROTO_FILE]);
        assert_eq!(
            report.kept_local[0].1,
            vec![format!("drops descriptor `{dropped}`")]
        );
        assert_eq!(report.held_back, vec![DATAMINE_FILE]);
        assert_eq!(
            read_file(&dir.join(PROTO_FILE)).unwrap(),
            committed(PROTO_FILE)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_a_published_datamine_this_build_cannot_parse() {
        let dir = local_assets("unparseable");
        let local = committed(DATAMINE_FILE);

        // An empty object is valid JSON and shares no keys with the local file,
        // so it is refused for dropping everything rather than for parsing.
        let report = refresh(
            &dir,
            &fetcher_for("{\"xorSeeds\":{}}", &committed(PROTO_FILE)),
        )
        .unwrap();
        assert_eq!(report.kept_local_names(), vec![DATAMINE_FILE]);
        assert!(
            report.kept_local[0]
                .1
                .iter()
                .any(|reason| reason.contains("cmdPlayerSyncScNotify")),
            "reasons were {:?}",
            report.kept_local[0].1
        );

        // Something that keeps every key but is not a datamine at all is refused
        // for not parsing, and reported as such rather than as a fatal error.
        let mangled = local.replace(
            "\"cmdPlayerSyncScNotify\":",
            "\"cmdPlayerSyncScNotify\": \"x\", \"ignored\":",
        );
        let report = refresh(&dir, &fetcher_for(&mangled, &committed(PROTO_FILE))).unwrap();
        assert!(
            report.kept_local[0]
                .1
                .iter()
                .any(|reason| reason.contains("cannot parse")),
            "reasons were {:?}",
            report.kept_local[0].1
        );
        assert_eq!(read_file(&dir.join(DATAMINE_FILE)).unwrap(), local);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn accepts_a_published_datamine_that_only_adds_keys() {
        let dir = local_assets("newer");
        let local = committed(DATAMINE_FILE);
        // A new key was added to a newer published file: nothing is lost, so the
        // refresh is allowed and the local copy is replaced.
        let mut value: serde_json::Value = serde_json::from_str(&local).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("cmdSomethingNew".into(), serde_json::json!(1));
        let newer = serde_json::to_string(&value).unwrap();

        let report = refresh(&dir, &fetcher_for(&newer, &committed(PROTO_FILE))).unwrap();

        assert!(report.kept_local.is_empty(), "{:?}", report.kept_local);
        assert!(report.held_back.is_empty());
        assert!(report.updated_files.contains(&DATAMINE_FILE));
        assert!(report.updated_files.contains(&PROTO_FILE));
        assert_ne!(read_file(&dir.join(DATAMINE_FILE)).unwrap(), local);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn update_available_compares_versions() {
        let dir = scratch_dir("update");
        std::fs::write(dir.join(MANIFEST_FILE), r#"{"version":"3.2"}"#).unwrap();

        let older = StaticFetcher::new().with(manifest_url(), r#"{"version":"3.1"}"#);
        assert!(!update_available(&dir, &older).unwrap());

        let newer = StaticFetcher::new().with(manifest_url(), r#"{"version":"3.3"}"#);
        assert!(update_available(&dir, &newer).unwrap());

        // Offline runs report the fetch failure instead of guessing.
        assert!(update_available(&dir, &OfflineFetcher).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
