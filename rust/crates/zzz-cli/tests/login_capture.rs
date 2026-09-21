//! Regression test against a recorded live login.
//!
//! Dormant unless the dump is present, the same way the EC2B dispatch fixtures
//! are: 16 MB of a real session is not something to commit, so this only runs on
//! the machine that recorded it. When it *is* there it pins the entire pipeline —
//! region seed, handshake, KCP reassembly, protobuf and the extraction pass — to
//! numbers that came from real traffic rather than from a fixture written by the
//! same code it tests.
//!
//! The numbers below describe *that specific session*, so re-recording
//! `rust/login_capture.json` means updating them. That is intended: a change that
//! silently alters how many discs a capture yields is exactly what this is here
//! to catch.

use std::path::Path;

use zzz_capture::Dump;
use zzz_crypto::xorpad::XorPad;
use zzz_gamedata::GameData;
use zzz_scan::Scanner;

/// Relative to this crate: `rust/crates/zzz-cli`.
const DUMP: &str = "../../login_capture.json";
const ASSETS: &str = "../../../assets";

fn recorded_dump() -> Option<Dump> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DUMP);
    if !path.exists() {
        return None;
    }
    Some(Dump::load(&path).expect("the recorded dump loads"))
}

fn assets() -> GameData {
    GameData::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join(ASSETS))
        .expect("the committed assets load")
}

#[test]
fn the_recorded_login_completes_its_handshake() {
    let Some(dump) = recorded_dump() else {
        return;
    };
    let data = assets();
    let seed = data
        .seed_for_region("Europe")
        .expect("Europe is a known region");
    let mut scanner = Scanner::new(XorPad::for_region(seed), &data.datamine, &data.nap);
    for packet in &dump.packets {
        scanner.feed(&packet.data, packet.direction(), packet.timestamp);
    }

    let session = scanner.session();
    assert!(
        scanner.handshake_complete(),
        "the session pad was never derived"
    );
    assert_eq!(
        format!("{:016X}", session.server_rand_key.expect("server half")),
        "01C3AE156AB095E1"
    );
    assert_eq!(
        format!("{:016X}", session.client_rand_key.expect("client half")),
        "21DAF5F2E2428CE0"
    );
    assert_eq!(
        format!("{:016X}", session.session_key.expect("session key")),
        "20195BE788F21901"
    );

    let stats = scanner.stats();
    assert!(stats.decoded > 300, "decoded {}", stats.decoded);
    // Exactly one message fails to parse, and it is the handshake carrier: it is
    // decrypted with the old pad before the key it carries is derived, so its
    // body is noise by design.
    assert_eq!(stats.proto_failures, 1);
    assert_eq!(scanner.kcp_stats().backlog_overflows, 0);
    assert_eq!(scanner.kcp_stats().conv_resets, 0);

    // No message in this capture carried a moved `deletedEquips` field, so the
    // fallback stayed quiet.
    assert!(scanner.extract().fallback_removals.is_empty());
}

#[test]
fn the_recorded_login_yields_the_accounts_inventory() {
    let Some(dump) = recorded_dump() else {
        return;
    };
    let data = assets();
    let seed = data
        .seed_for_region("Europe")
        .expect("Europe is a known region");
    let mut scanner = Scanner::new(XorPad::for_region(seed), &data.datamine, &data.nap);
    for packet in &dump.packets {
        scanner.feed(&packet.data, packet.direction(), packet.timestamp);
    }

    let inventory = scanner.inventory();
    assert_eq!(inventory.discs.len(), 1393);
    assert_eq!(inventory.engines.len(), 342);
    assert_eq!(inventory.agents.len(), 48);

    // The load responses are where the inventory comes from in this capture; the
    // ten syncs it also carries had nothing to apply.
    let extract = scanner.extract();
    assert_eq!(extract.disc_loads, 1);
    assert_eq!(extract.weapon_loads, 1);
    assert_eq!(extract.avatar_loads, 1);
    assert_eq!(extract.player_syncs, 10);
    assert_eq!(extract.sync_upserts, 0);

    // Every disc decodes to a real set id and a rarity the export has a letter
    // for, which is the check that the disc submessage is being read with the
    // right field numbers.
    for disc in &inventory.discs {
        assert_eq!(disc.set_id() % 100, 0);
        assert!(
            (31000..=34200).contains(&disc.set_id()),
            "{}",
            disc.set_id()
        );
        assert!(
            zzz_scan::rarity_key(disc.rarity()).is_some(),
            "rarity {} for disc {}",
            disc.rarity(),
            disc.id
        );
        assert!(disc.slot() <= 6);
        assert!(
            disc.main_stat.stat_name().is_some(),
            "unknown main stat key {}",
            disc.main_stat.key
        );
        assert!(
            disc.sub_stats.len() <= 4,
            "a disc has at most four substats"
        );
    }

    // The one link between the two lists. An agent names the engine it wears by
    // uid, so a mismatch here would mean one of them is misread.
    let worn: Vec<u32> = inventory
        .agents
        .iter()
        .filter(|agent| agent.weapon_uid != 0)
        .map(|agent| agent.weapon_uid)
        .collect();
    assert_eq!(worn.len(), 36);
    for uid in worn {
        let engine = inventory
            .engines
            .iter()
            .find(|engine| engine.uid == uid)
            .unwrap_or_else(|| panic!("agent wears w-engine {uid}, which was never decoded"));
        // Every engine in use is at the level cap, and the other 306 are
        // unlevelled duplicates — so this is a real cross-check of the engine
        // field numbers rather than a tautology. `phase` and `modification` are
        // deliberately not asserted: they vary across maxed engines, and the
        // export passes `phase` through as `wenginePhase` without interpreting
        // it, so this test has no business claiming to know what they mean.
        assert_eq!(engine.level, 60, "worn engine {uid}");
    }

    // Rarity bands the export writes letters for: this account is all S-rank, and
    // `keyRarity` has no entry below 3, so anything else would need noticing.
    assert!(
        inventory.discs.iter().all(|disc| disc.rarity() == 5),
        "the fixture account is all S-rank"
    );
}
