//! The ZOD export, checked against the C++ reference's own output.
//!
//! `tools/cpp_export.cpp` compiles `src/serialization/zod/` — `IZOD::fromPcap`
//! and the three `fromInstance` converters — together with the real `data::*`
//! model and `data::ExportSettings`, and lets glaze serialize the result. The
//! two goldens beside this test are its output:
//!
//! * `zod_export.json` — the inventory decoded from `rust/login_capture.json`,
//!   exported with every floor at zero so the comparison covers all 1393 discs,
//!   342 w-engines and 48 agents rather than the slice a filter would keep.
//! * `zod_edge_export.json` — a small synthetic inventory exported with the
//!   *default* settings, which is where the filters, the padded substat slots,
//!   the w-engine that never arrived and the disc below the rarity floor are
//!   exercised.
//!
//! Both files were produced by that harness reading `zod_inventory.json` and
//! `zod_edge_inventory.json`, which are committed next to them. Regenerating
//! them is `cargo test -p zzz-export --test cpp_export_parity -- --ignored
//! write_parity_inputs`, then two runs of the harness; the command lines are in
//! `tools/cpp_export.cpp`.
//!
//! What this proves and what it does not. It proves the exporter is
//! byte-identical to the reference over the inventory of a real session,
//! including key derivation, zero-based conversions, the four substat slots and
//! the JSON escaping. It does not re-run the capture-to-inventory half of the
//! C++ program: that needs protobuf, OpenSSL and pcap++, none of which are
//! buildable here, and the Rust half of it is already pinned against this same
//! dump by `zzz-cli/tests/login_capture.rs`.

use std::path::{Path, PathBuf};

use serde_json::json;

use zzz_capture::Dump;
use zzz_crypto::xorpad::XorPad;
use zzz_export::{ExportSettings, Izod, NanokaNames};
use zzz_gamedata::GameData;
use zzz_scan::{
    AvatarSkillLevel, DiscInfo, DiscStat, DressedEquip, Inventory, Scanner, WeaponInfo,
};

/// Relative to this crate: `rust/crates/zzz-export`.
const ASSETS: &str = "../../../assets";
const DUMP: &str = "../../login_capture.json";
const PARITY: &str = "../../testdata/parity";

/// The region `rust/login_capture.json` was recorded in, as `zzzcap replay`
/// detects it.
const REGION: &str = "Europe";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn parity_path(name: &str) -> PathBuf {
    repo_path(PARITY).join(name)
}

fn assets() -> GameData {
    GameData::load(&repo_path(ASSETS)).expect("the committed assets load")
}

/// The inventory the recorded capture decodes to, or `None` when the dump is not
/// on this machine.
fn captured_inventory() -> Option<Inventory> {
    let path = repo_path(DUMP);
    if !path.exists() {
        return None;
    }
    let dump = Dump::load(&path).expect("the recorded dump loads");
    let data = assets();
    let seed = data.seed_for_region(REGION).expect("Europe is a region");
    let mut scanner = Scanner::new(XorPad::for_region(seed), &data.datamine, &data.nap);
    for packet in &dump.packets {
        scanner.feed(&packet.data, packet.direction(), packet.timestamp);
    }
    Some(scanner.inventory().clone())
}

/// The neutral hand-off the C++ harness reads.
///
/// The member names are the C++ structs' own — `mainStat`, `base_value`,
/// `weaponUid`, `dressed_equips` — because glaze deserializes straight into
/// `data::DiscInfo`, `data::WeaponInfo` and `data::AgentInfo`. Nothing about the
/// export passes through this shape, so a mistake here shows up as the harness
/// reading the wrong numbers, not as both sides agreeing on a mistake.
fn intermediate(inventory: &Inventory) -> String {
    let stat = |stat: &DiscStat| {
        json!({
            "key": stat.key,
            "base_value": stat.base_value,
            "add_value": stat.add_value,
        })
    };
    let value = json!({
        "discs": inventory
            .discs
            .iter()
            .map(|disc| json!({
                "uid": disc.uid,
                "id": disc.id,
                "level": disc.level,
                "mainStat": stat(&disc.main_stat),
                "subStats": disc.sub_stats.iter().map(stat).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "engines": inventory
            .engines
            .iter()
            .map(|engine| json!({
                "id": engine.id,
                "uid": engine.uid,
                "level": engine.level,
                "phase": engine.phase,
                "modification": engine.modification,
            }))
            .collect::<Vec<_>>(),
        "agents": inventory
            .agents
            .iter()
            .map(|agent| json!({
                "id": agent.id,
                "level": agent.level,
                "promotion": agent.promotion,
                "weaponUid": agent.weapon_uid,
                "mindscape": agent.mindscape,
                "skills": agent
                    .skills
                    .iter()
                    .map(|skill| json!({
                        "skill_type": skill.skill_type,
                        "level": skill.level,
                    }))
                    .collect::<Vec<_>>(),
                "dressed_equips": agent
                    .dressed_equips
                    .iter()
                    .map(|equip| json!({"uid": equip.uid, "slot": equip.slot}))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string(&value).expect("the intermediate serializes")
}

/// A small inventory that reaches the corners the real capture does not: an
/// agent wearing a w-engine that is not in the list, an agent wearing one that
/// is, an unequipped w-engine, a dressed and a bagged disc, a disc below the
/// default rarity floor, and substats both shorter and longer than the four
/// slots the reference writes.
///
/// The ids are real ones — 1011 Anby, 1021 Nekomata, 12001 `[Lunar] Pleniluna`,
/// set 31300 — because the C++ side looks the names up in
/// `assets/nanokaData.json` while this side takes them from the same file
/// through `NanokaNames`. Invented ids would make the two disagree for a reason
/// that has nothing to do with the export.
fn edge_inventory() -> Inventory {
    let skills = |levels: [u32; 6]| {
        levels
            .iter()
            .enumerate()
            .map(|(kind, level)| AvatarSkillLevel {
                skill_type: kind as u32,
                level: *level,
            })
            .collect::<Vec<_>>()
    };
    let stat = |key: u32, base: u32, add: u32| DiscStat {
        key,
        base_value: base,
        add_value: add,
    };
    let disc = |uid: u32, id: u32, level: u32, subs: Vec<DiscStat>| DiscInfo {
        uid,
        id,
        level,
        // `hp` for the main stat, so the name lookup is exercised too.
        main_stat: stat(11103, 550, 0),
        sub_stats: subs,
    };

    Inventory {
        agents: vec![
            // Wears 12001, which is in the engine list below.
            zzz_scan::AgentInfo {
                id: 1011,
                level: 60,
                promotion: 6,
                weapon_uid: 12001,
                mindscape: 6,
                // Position 4 is the core skill, exported one lower.
                skills: skills([12, 11, 12, 11, 7, 11]),
                dressed_equips: vec![DressedEquip { uid: 900, slot: 1 }],
            },
            // Names a w-engine that never arrived.
            zzz_scan::AgentInfo {
                id: 1021,
                level: 1,
                promotion: 1,
                weapon_uid: 999_999,
                mindscape: 0,
                skills: skills([1, 1, 1, 1, 1, 1]),
                dressed_equips: vec![DressedEquip { uid: 901, slot: 2 }],
            },
        ],
        engines: vec![
            WeaponInfo {
                id: 12001,
                uid: 12001,
                level: 60,
                phase: 5,
                modification: 4,
            },
            // In the bag: no agent names it.
            WeaponInfo {
                id: 12002,
                uid: 700,
                level: 1,
                phase: 1,
                modification: 0,
            },
        ],
        discs: vec![
            // Dressed by Anby, four substats.
            disc(
                900,
                31341,
                15,
                vec![stat(20103, 240, 2), stat(21103, 480, 1)],
            ),
            // In the bag, five substats: the fifth is dropped.
            disc(
                902,
                31342,
                12,
                vec![
                    stat(20103, 240, 1),
                    stat(12102, 190, 0),
                    stat(13102, 190, 0),
                    stat(23103, 90, 0),
                    stat(30502, 120, 0),
                ],
            ),
            // Rarity band 1, below the default floor of 3: the default settings
            // must drop it before the export reaches `keyRarity`, which has no
            // letter for it.
            disc(903, 31301, 15, vec![]),
        ],
    }
}

fn export(inventory: &Inventory, settings: &ExportSettings) -> String {
    let data = assets();
    assert!(
        !data.nanoka.characters.is_empty(),
        "assets/nanokaData.json is missing, so the export keys cannot be derived; \
         run `zzzcap update`"
    );
    let names = NanokaNames(&data.nanoka);
    Izod::from_inventory(inventory, &names, settings)
        .expect("the fixture exports")
        .to_json()
}

/// Compare over bytes, and show where they diverge rather than dumping two
/// multi-hundred-kilobyte strings.
fn assert_same_bytes(label: &str, expected: &str, actual: &str) {
    if expected == actual {
        return;
    }
    let first = expected
        .bytes()
        .zip(actual.bytes())
        .position(|(left, right)| left != right)
        .unwrap_or(expected.len().min(actual.len()));
    let window = |text: &str| {
        text.get(first.saturating_sub(40)..(first + 40).min(text.len()))
            .unwrap_or("")
            .to_string()
    };
    panic!(
        "{label}: the export differs from the reference\n\
         at byte {first} (of {} reference, {} ours)\n\
         reference: ...{}...\n\
         ours:      ...{}...",
        expected.len(),
        actual.len(),
        window(expected),
        window(actual),
    );
}

/// The synthetic inventory, against the reference's default settings.
#[test]
fn the_edge_cases_export_the_reference_bytes() {
    let golden = parity_path("zod_edge_export.json");
    if !golden.exists() {
        eprintln!("skipping: {} is not present", golden.display());
        return;
    }
    let expected = std::fs::read_to_string(&golden).expect("the golden reads");
    let actual = export(&edge_inventory(), &ExportSettings::default());
    assert_same_bytes("zod_edge_export.json", &expected, &actual);

    // And the fixture really does reach the corners it claims to, so a golden
    // that stopped covering them would not pass unnoticed.
    let zod = Izod::from_inventory(
        &edge_inventory(),
        &NanokaNames(&assets().nanoka),
        &ExportSettings::default(),
    )
    .expect("the fixture exports");
    let characters = zod.characters.expect("agents are exported");
    assert_eq!(characters.len(), 2);
    assert_eq!(characters[0].key, "Anby");
    assert_eq!(characters[0].core, 6, "skill 4 minus one");
    assert_eq!(characters[0].wengine_key.as_deref(), Some("LunarPleniluna"));
    assert_eq!(
        characters[1].wengine_key.as_deref(),
        Some(""),
        "an engine that never arrived leaves an empty key"
    );
    assert_eq!(characters[1].wengine_phase, Some(1));

    let discs = zod.discs.expect("discs are exported");
    assert_eq!(discs.len(), 2, "the rarity-band-1 disc is filtered out");
    assert_eq!(discs[0].location, "Anby");
    assert_eq!(discs[1].location, "", "never dressed");
    assert!(
        discs.iter().all(|disc| disc.substats.len() == 4),
        "the reference always writes four substat slots"
    );
    assert_eq!(discs[0].substats[2].key, "", "padded, not omitted");

    let engines = zod.wengines.expect("w-engines are exported");
    assert_eq!(engines.len(), 2);
    assert_eq!(engines[0].location, "Anby");
    assert_eq!(engines[0].id, "zzz_wengine_12001");
    assert_eq!(engines[1].location, "", "in the bag");
}

/// The recorded capture's inventory, against the reference with every floor at
/// zero.
#[test]
fn the_recorded_capture_exports_the_reference_bytes() {
    let golden = parity_path("zod_export.json");
    let intermediate_file = parity_path("zod_inventory.json");
    if !golden.exists() || !intermediate_file.exists() {
        eprintln!("skipping: the recorded-capture goldens are not present");
        return;
    }

    let committed: Inventory = {
        // The intermediate is the harness's input, so reading it back and
        // exporting it is what makes this test meaningful on a machine that
        // never recorded the session.
        let text = std::fs::read_to_string(&intermediate_file).expect("the intermediate reads");
        let value: serde_json::Value = serde_json::from_str(&text).expect("it is JSON");
        let stat = |value: &serde_json::Value| DiscStat {
            key: value["key"].as_u64().unwrap_or_default() as u32,
            base_value: value["base_value"].as_u64().unwrap_or_default() as u32,
            add_value: value["add_value"].as_u64().unwrap_or_default() as u32,
        };
        let list = |key: &str| value[key].as_array().cloned().unwrap_or_default();
        Inventory {
            discs: list("discs")
                .iter()
                .map(|disc| DiscInfo {
                    uid: disc["uid"].as_u64().unwrap_or_default() as u32,
                    id: disc["id"].as_u64().unwrap_or_default() as u32,
                    level: disc["level"].as_u64().unwrap_or_default() as u32,
                    main_stat: stat(&disc["mainStat"]),
                    sub_stats: disc["subStats"]
                        .as_array()
                        .map(|subs| subs.iter().map(stat).collect())
                        .unwrap_or_default(),
                })
                .collect(),
            engines: list("engines")
                .iter()
                .map(|engine| WeaponInfo {
                    id: engine["id"].as_u64().unwrap_or_default() as u32,
                    uid: engine["uid"].as_u64().unwrap_or_default() as u32,
                    level: engine["level"].as_u64().unwrap_or_default() as u32,
                    phase: engine["phase"].as_u64().unwrap_or_default() as u32,
                    modification: engine["modification"].as_u64().unwrap_or_default() as u32,
                })
                .collect(),
            agents: list("agents")
                .iter()
                .map(|agent| zzz_scan::AgentInfo {
                    id: agent["id"].as_u64().unwrap_or_default() as u32,
                    level: agent["level"].as_u64().unwrap_or_default() as u32,
                    promotion: agent["promotion"].as_u64().unwrap_or_default() as u32,
                    weapon_uid: agent["weaponUid"].as_u64().unwrap_or_default() as u32,
                    mindscape: agent["mindscape"].as_u64().unwrap_or_default() as u32,
                    skills: agent["skills"]
                        .as_array()
                        .map(|skills| {
                            skills
                                .iter()
                                .map(|skill| AvatarSkillLevel {
                                    skill_type: skill["skill_type"].as_u64().unwrap_or_default()
                                        as u32,
                                    level: skill["level"].as_u64().unwrap_or_default() as u32,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    dressed_equips: agent["dressed_equips"]
                        .as_array()
                        .map(|equips| {
                            equips
                                .iter()
                                .map(|equip| DressedEquip {
                                    uid: equip["uid"].as_u64().unwrap_or_default() as u32,
                                    slot: equip["slot"].as_u64().unwrap_or_default() as u32,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect(),
        }
    };

    assert_eq!(committed.discs.len(), 1393);
    assert_eq!(committed.engines.len(), 342);
    assert_eq!(committed.agents.len(), 48);

    let expected = std::fs::read_to_string(&golden).expect("the golden reads");
    assert_same_bytes(
        "zod_export.json",
        &expected,
        &export(&committed, &ExportSettings::unfiltered()),
    );

    // When the dump is here too, the intermediate has to be what the pipeline
    // decodes from it — otherwise the golden would be checking an inventory that
    // no longer corresponds to the capture.
    if let Some(inventory) = captured_inventory() {
        let text = std::fs::read_to_string(&intermediate_file).unwrap();
        assert_eq!(
            intermediate(&inventory),
            text.trim_end(),
            "the committed intermediate is not what the recorded capture decodes to; \
             regenerate it with the ignored test in this file"
        );
    }
}

/// Writes the two intermediates the harness reads. Ignored by default: it is a
/// step in regenerating the goldens, not a check.
#[test]
#[ignore = "regenerating the parity goldens, not a check"]
fn write_parity_inputs() {
    let inventory = captured_inventory().expect("rust/login_capture.json must be present");
    std::fs::write(parity_path("zod_inventory.json"), intermediate(&inventory)).expect("write");
    std::fs::write(
        parity_path("zod_edge_inventory.json"),
        intermediate(&edge_inventory()),
    )
    .expect("write");
    eprintln!(
        "wrote zod_inventory.json ({} discs, {} engines, {} agents) and zod_edge_inventory.json.\n\
         Now run the harness from the repository root:\n  \
         tools/cpp_export.exe rust/testdata/parity/zod_inventory.json \
         rust/testdata/parity/zod_export.json unfiltered\n  \
         tools/cpp_export.exe rust/testdata/parity/zod_edge_inventory.json \
         rust/testdata/parity/zod_edge_export.json default",
        inventory.discs.len(),
        inventory.engines.len(),
        inventory.agents.len(),
    );
}
