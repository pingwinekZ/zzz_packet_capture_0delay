//! `zzzcap` — the console front end.
//!
//! Everything the tool does is available from here, so a game update can be
//! investigated without the GUI: capture a session, replay a recorded dump,
//! export the decoded data, and serve it to the optimizer live over the same
//! WebSocket the GUI uses. The GUI is a thin shell over the same crates.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use std::collections::BTreeMap;

use clap::{Parser, Subcommand};
use zzz_capture::{Capture, Dump, Packet, GAME_PORT};
use zzz_crypto::xorpad::XorPad;
use zzz_export::{ExportSettings, Izod, NanokaNames};
use zzz_gamedata::{GameData, HttpFetcher};
use zzz_scan::{rarity_key, DiscStat, Scanner};

/// `WINDIVERT_MTU_MAX`: the biggest packet the driver can hand over.
const BUFFER_SIZE: usize = 0xFFFF;
/// How often the dump is written while capturing, so an interrupt still leaves a
/// usable file.
const CHECKPOINT: Duration = Duration::from_secs(2);

#[derive(Parser)]
#[command(name = "zzzcap", about = "Zenless Zone Zero packet capture", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture live game traffic into a dump file.
    Capture {
        /// UDP port to listen on.
        #[arg(long, default_value_t = GAME_PORT)]
        port: u16,
        /// Where to write the recording.
        #[arg(long, default_value = "captured_packets.json")]
        out: PathBuf,
        /// Stop after this many seconds; 0 runs until interrupted.
        #[arg(long, default_value_t = 180)]
        seconds: u64,
    },
    /// Decode a recorded dump: report its structure, recover the session keys,
    /// summarize the messages in it and extract the inventory.
    Replay {
        /// Dump to read, as written by `capture` or by the C++ build.
        #[arg(long = "in", default_value = "captured_packets.json")]
        input: PathBuf,
        /// Directory holding `datamine.json` and `nap.json`.
        #[arg(long, default_value = "../assets")]
        assets: PathBuf,
        /// Region whose `xorSeeds` entry this capture used. Tried and scored if
        /// omitted, which is almost always what you want.
        #[arg(long)]
        region: Option<String>,
        /// Explicit seed as the hex string `datamine.json` stores (overrides
        /// `--region`, and skips detection).
        #[arg(long)]
        seed: Option<String>,
        /// List every disc instead of summarizing them per set. A login sync
        /// carries the whole inventory, so this is hundreds of lines.
        #[arg(long)]
        discs: bool,
    },
    /// Write the decoded inventory as the optimizer's ZOD JSON.
    Export {
        /// Dump to read, as written by `capture` or by the C++ build.
        #[arg(long = "in", default_value = "captured_packets.json")]
        input: PathBuf,
        /// Directory holding `datamine.json` and `nap.json`.
        #[arg(long, default_value = "../assets")]
        assets: PathBuf,
        /// Region whose `xorSeeds` entry this capture used. Tried and scored if
        /// omitted.
        #[arg(long)]
        region: Option<String>,
        /// Explicit seed as the hex string `datamine.json` stores.
        #[arg(long)]
        seed: Option<String>,
        /// Where to write the JSON; `-` writes it to stdout, with the report on
        /// stderr so a redirect gives you a clean file.
        #[arg(long, default_value = "-")]
        out: String,
        /// Lowest agent rarity to write, counted in stars (the default of 4
        /// leaves out the game's three-star agents).
        #[arg(long, default_value_t = 4)]
        min_agent_rarity: u8,
        /// Raise to leave out agents that were captured but never levelled.
        #[arg(long, default_value_t = 0)]
        min_agent_level: u8,
        /// Lowest disc rarity to write, as the band the game encodes in the disc
        /// id: 3, 4 and 5 are the export's B, A and S.
        #[arg(long, default_value_t = 3)]
        min_disc_rarity: u8,
        /// Raise to leave out under-levelled discs.
        #[arg(long, default_value_t = 0)]
        min_disc_level: u8,
        /// Lowest w-engine rarity to write, counted in stars.
        #[arg(long, default_value_t = 3)]
        min_engine_rarity: u8,
        /// Raise to leave out w-engines that were captured but never levelled.
        #[arg(long, default_value_t = 0)]
        min_engine_level: u8,
        /// Leave a category out entirely, rather than writing it empty. The site
        /// reads an absent list as "keep what was imported last time".
        #[arg(long)]
        no_agents: bool,
        /// As `--no-agents`, for discs.
        #[arg(long)]
        no_discs: bool,
        /// As `--no-agents`, for w-engines.
        #[arg(long)]
        no_engines: bool,
    },
    /// Serve the decoded inventory to the optimizer over the reference's
    /// WebSocket, so it can be pulled live instead of imported from a file.
    ///
    /// A snapshot is sent whenever the capture changes the inventory, and a
    /// client that connects in between is given the last one. Categories the
    /// capture has nothing for are left out of the payload rather than sent
    /// empty, because the optimizer's import replaces what it has.
    Live {
        /// Directory holding `datamine.json` and `nap.json`.
        #[arg(long, default_value = "../assets")]
        assets: PathBuf,
        /// Stream this recorded dump instead of capturing from the game. It is
        /// fed as fast as it reads, so this is how the server is exercised
        /// without the game running — and on a non-Windows host, the only way.
        #[arg(long = "in")]
        input: Option<PathBuf>,
        /// Region whose `xorSeeds` entry the traffic uses. Tried and scored if
        /// omitted, on the packets that arrive before the login.
        #[arg(long)]
        region: Option<String>,
        /// Explicit seed as the hex string `datamine.json` stores (overrides
        /// `--region`, and skips detection).
        #[arg(long)]
        seed: Option<String>,
        /// UDP port the game's traffic uses. Ignored with `--in`.
        #[arg(long, default_value_t = GAME_PORT)]
        port: u16,
        /// Port the optimizer connects to; `23313` is the reference's.
        #[arg(long = "ws-port", default_value_t = zzz_live::DEFAULT_PORT)]
        ws_port: u16,
        /// Send no agents, so the site keeps the ones it has. As with
        /// `export`, a switched-off category is never sent as an empty list.
        #[arg(long)]
        no_agents: bool,
        /// As `--no-agents`, for discs.
        #[arg(long)]
        no_discs: bool,
        /// As `--no-agents`, for w-engines.
        #[arg(long)]
        no_engines: bool,
        /// Stop after this many seconds; 0 runs until interrupted. A dump that
        /// runs out does not stop the server: it keeps serving what it was fed.
        #[arg(long, default_value_t = 0)]
        seconds: u64,
    },
    /// Refresh the data files from their published copies: `manifest.json`,
    /// `datamine.json`, `nap.json` and the nanoka name cache.
    Update {
        /// Directory holding the data files.
        #[arg(long, default_value = "../assets")]
        assets: PathBuf,
    },
}

/// How many packets a region candidate gets to prove itself in.
///
/// The handshake is at the very start of a session, so a few hundred packets is
/// more than enough, and the alternative — decoding a whole capture per region —
/// costs far more for no extra certainty.
const DETECT_PACKETS: usize = 600;

/// How many messages a region candidate must decode to be believed when the
/// handshake is not in the capture. A wrong seed can manage an accidental parse
/// or two; it cannot manage eight.
const MIN_VIABLE_DECODES: u64 = 8;

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Capture { port, out, seconds } => report(capture(port, &out, seconds)),
        Command::Replay {
            input,
            assets,
            region,
            seed,
            discs,
        } => report(replay(
            &input,
            &assets,
            region.as_deref(),
            seed.as_deref(),
            discs,
        )),
        Command::Export {
            input,
            assets,
            region,
            seed,
            out,
            min_agent_rarity,
            min_agent_level,
            min_disc_rarity,
            min_disc_level,
            min_engine_rarity,
            min_engine_level,
            no_agents,
            no_discs,
            no_engines,
        } => report(export(
            &input,
            &assets,
            region.as_deref(),
            seed.as_deref(),
            &out,
            ExportSettings {
                min_agent_rarity,
                min_agent_level,
                min_disc_rarity,
                min_disc_level,
                min_engine_rarity,
                min_engine_level,
                export_agents: !no_agents,
                export_discs: !no_discs,
                export_engines: !no_engines,
            },
        )),
        Command::Live {
            assets,
            input,
            region,
            seed,
            port,
            ws_port,
            no_agents,
            no_discs,
            no_engines,
            seconds,
        } => report(live(LiveOptions {
            assets: &assets,
            input: input.as_deref(),
            region: region.as_deref(),
            seed: seed.as_deref(),
            port,
            ws_port,
            settings: ExportSettings {
                export_agents: !no_agents,
                export_discs: !no_discs,
                export_engines: !no_engines,
                ..ExportSettings::default()
            },
            seconds,
        })),
        Command::Update { assets } => report(update(&assets)),
    }
}

/// `zzzcap update`: pull the data files the parser depends on.
///
/// Called this rather than "download" because the files are replacements, not
/// additions: what matters is which ones actually differ, which is why the bytes
/// are compared before and after rather than trusting that "fetched" means
/// "changed".
fn update(assets: &Path) -> Result<(), String> {
    const FILES: [&str; 4] = [
        zzz_gamedata::MANIFEST_FILE,
        zzz_gamedata::DATAMINE_FILE,
        zzz_gamedata::PROTO_FILE,
        zzz_gamedata::NANOKA_FILE,
    ];

    let before: Vec<Option<Vec<u8>>> = FILES
        .iter()
        .map(|name| std::fs::read(assets.join(name)).ok())
        .collect();

    println!("Refreshing {} from the published copies", assets.display());
    let report = zzz_gamedata::refresh(assets, &HttpFetcher::new()).map_err(|error| {
        format!(
            "{error}\n       nothing was left half-written: each file is parsed before it replaces the cache"
        )
    })?;

    for (name, previous) in FILES.iter().zip(&before) {
        // A file that was refused is reported in its own block below, with the
        // reason; saying "already current" about it here would be a lie.
        if report.kept_local_names().contains(name) {
            continue;
        }
        if report.held_back.contains(name) {
            println!(
                "  {name:<18} held back: the other half of the pair was refused, and the two\n                     have to come from the same game version"
            );
            continue;
        }
        if !report.updated_files.contains(name) {
            // nanoka is only rewritten when its version differs from live, so
            // "already current" is the normal outcome for a second run.
            println!("  {name:<18} already current");
            continue;
        }
        let after = std::fs::read(assets.join(name)).ok();
        let state = match previous {
            Some(previous) if after.as_ref() == Some(previous) => {
                "rewritten, byte for byte the same"
            }
            Some(_) => "updated",
            None => "added",
        };
        println!("  {name:<18} {state}");
    }

    for (name, reasons) in &report.kept_local {
        println!("  {name:<18} kept the local copy — the published one is not usable:");
        for reason in reasons.iter().take(6) {
            println!("                     {reason}");
        }
        if reasons.len() > 6 {
            println!("                     ...and {} more", reasons.len() - 6);
        }
    }

    match report.version {
        Some(version) => println!("  data version:      {version}"),
        None => println!("  data version:      not reported"),
    }
    if let Some(nanoka) = report.nanoka_version {
        println!("  nanoka version:    {nanoka}");
    }
    if report.updated_files.is_empty() && report.kept_local.is_empty() {
        println!("Nothing needed updating.");
    } else {
        println!("Done; `replay` will use these files.");
    }
    Ok(())
}

fn report(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn capture(port: u16, out: &Path, seconds: u64) -> Result<(), String> {
    let capture = Capture::open(port).map_err(describe)?;

    println!("Listening for UDP port {port}");
    println!("  driver filter: {}", Capture::port_filter(port));
    println!("  writing to:    {}", out.display());
    if seconds > 0 {
        println!("  auto-stop:     {seconds}s");
    }
    println!(
        "Start the game and log in. The dump is rewritten every {}s, so an",
        CHECKPOINT.as_secs()
    );
    println!("interrupt still leaves a usable file.");

    let state = Arc::new(Mutex::new(Dump::new()));
    let deadline = (seconds > 0).then(|| Instant::now() + Duration::from_secs(seconds));
    let started = Instant::now();

    let writer = {
        let capture = capture.clone();
        let state = Arc::clone(&state);
        let path = out.to_path_buf();
        std::thread::spawn(move || loop {
            std::thread::sleep(CHECKPOINT);
            let snapshot = clone_state(&state);
            if let Err(error) = snapshot.save(&path) {
                eprintln!("warning: could not write {}: {error}", path.display());
            } else {
                println!(
                    "  {} packets, {} KiB, {}s elapsed",
                    snapshot.len(),
                    snapshot.payload_bytes() / 1024,
                    started.elapsed().as_secs()
                );
            }

            if capture.is_stopped() || deadline.is_some_and(|d| Instant::now() >= d) {
                capture.stop();
                break;
            }
        })
    };

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut failure = None;
    loop {
        match capture.recv(&mut buffer) {
            Ok(Some(packet)) => {
                let mut guard = lock(&state);
                guard.push(&packet);
            }
            Ok(None) => break,
            Err(error) => {
                failure = Some(describe(error));
                capture.stop();
                break;
            }
        }
    }

    let _ = writer.join();
    let elapsed = started.elapsed();

    // Final, authoritative write: the checkpoint thread may have run before the
    // last packets landed.
    let dump = clone_state(&state);
    if let Err(error) = dump.save(out) {
        return Err(format!("could not write {}: {error}", out.display()));
    }

    println!();
    println!(
        "Captured {} packets ({} KiB) in {:.1}s",
        dump.len(),
        dump.payload_bytes() / 1024,
        elapsed.as_secs_f64()
    );
    println!("  incoming: {}", count_direction(&dump, 0));
    println!("  outgoing: {}", count_direction(&dump, 1));
    if capture.skipped() > 0 {
        println!(
            "  ignored:  {} (not UDP for port {port})",
            capture.skipped()
        );
    }
    if capture.direction_conflicts() > 0 {
        println!(
            "  caution:  {} packets where the port and WinDivert's address disagreed about direction",
            capture.direction_conflicts()
        );
    }
    println!("Written to {}", out.display());
    if dump.is_empty() {
        println!("Nothing was captured. Check that the game is running and logged in,");
        println!("and that the region's traffic actually uses port {port}.");
    }

    match failure {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

#[cfg(not(windows))]
fn capture(_port: u16, _out: &Path, _seconds: u64) -> Result<(), String> {
    Err("live capture is only implemented for Windows so far".into())
}

/// A quick "what am I looking at?" pass over a dump.
///
/// Worth keeping around rather than throwing away: when a game update changes the
/// framing, this is what tells you whether what you captured is still KCP at all,
/// or whether the parser is the thing that broke.
fn structure_report(dump: &Dump) {
    use std::collections::BTreeMap;

    let mut sizes: BTreeMap<usize, usize> = BTreeMap::new();
    let mut commands: BTreeMap<u8, usize> = BTreeMap::new();
    let mut convs: BTreeMap<u32, usize> = BTreeMap::new();
    let mut fragments: BTreeMap<u8, usize> = BTreeMap::new();

    for packet in &dump.packets {
        *sizes.entry(packet.data.len() / 128).or_default() += 1;
        // A KCP segment header is 28 bytes: conv, token, cmd, frg, wnd, ts, sn,
        // una, len. If this dump is KCP, `cmd` should be dominated by 81 (PUSH)
        // and 82 (ACK).
        if packet.data.len() >= 28 {
            *commands.entry(packet.data[8]).or_default() += 1;
            *fragments.entry(packet.data[9]).or_default() += 1;
            let conv = u32::from_le_bytes([
                packet.data[0],
                packet.data[1],
                packet.data[2],
                packet.data[3],
            ]);
            *convs.entry(conv).or_default() += 1;
        }
    }

    let top = |map: &BTreeMap<usize, usize>| {
        let mut entries: Vec<(usize, usize)> = map.iter().map(|(k, v)| (*k, *v)).collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        entries
    };

    println!("  payload size buckets (128-byte units):");
    for (bucket, count) in top(&sizes).into_iter().take(4) {
        println!("    {}-{} bytes: {count}", bucket * 128, bucket * 128 + 127);
    }

    if commands.is_empty() {
        println!("  no payload long enough to hold a KCP header");
        return;
    }

    println!("  byte at offset 8 (KCP cmd; 81=PUSH, 82=ACK):");
    let mut ordered: Vec<(u8, usize)> = commands.iter().map(|(k, v)| (*k, *v)).collect();
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    for (value, count) in ordered.into_iter().take(4) {
        println!("    {value}: {count}");
    }

    println!("  byte at offset 9 (KCP frg):");
    let mut ordered: Vec<(u8, usize)> = fragments.iter().map(|(k, v)| (*k, *v)).collect();
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    for (value, count) in ordered.into_iter().take(4) {
        println!("    {value}: {count}");
    }

    println!("  most common conv values:");
    let mut ordered: Vec<(u32, usize)> = convs.iter().map(|(k, v)| (*k, *v)).collect();
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    for (value, count) in ordered.into_iter().take(3) {
        println!("    {value:#010X}: {count}");
    }

    // Sequence numbers climb by one within a direction, and they go backwards
    // for two reasons that mean opposite things. An isolated dip that returns
    // straight to the high-water mark is a retransmission or a reordered
    // datagram -- ordinary UDP behaviour, and what KCP exists to absorb. A second
    // connection filed under one direction instead keeps climbing from its own
    // low counter, so every dip is followed by a sustained run of +1 steps.
    //
    // A KCP segment carries the millisecond timestamp of its *first* send, so a
    // retransmit is also identifiable by its ts being far behind the stream. Two
    // independent signals agreeing is what makes this a diagnosis rather than a
    // guess.
    struct Seg {
        at: i64,
        ts: u32,
        sn: u32,
        cmd: u8,
        frg: u8,
        declared: u32,
    }

    for (label, direction) in [("incoming", 0u8), ("outgoing", 1u8)] {
        let mut segments: Vec<Seg> = Vec::new();
        for packet in dump.packets.iter().filter(|p| p.direction == direction) {
            if packet.data.len() < 28 {
                continue;
            }
            let cmd = packet.data[8];
            if !matches!(cmd, 81..=84) {
                continue;
            }
            let word = |offset: usize| {
                u32::from_le_bytes([
                    packet.data[offset],
                    packet.data[offset + 1],
                    packet.data[offset + 2],
                    packet.data[offset + 3],
                ])
            };
            segments.push(Seg {
                at: packet.timestamp,
                ts: word(12),
                sn: word(16),
                cmd,
                frg: packet.data[9],
                declared: word(24),
            });
        }

        if segments.is_empty() {
            continue;
        }

        let start = segments[0].at;
        let (mut step, mut backwards, mut duplicates, mut jumps) = (0usize, 0usize, 0usize, 0usize);
        let (mut resuming, mut isolated, mut stale) = (0usize, 0usize, 0usize);
        let mut dips: Vec<(u32, i64, i64, &Seg)> = Vec::new();
        let mut max_ts = segments[0].ts;
        for (index, pair) in segments.windows(2).enumerate() {
            let diff = pair[1].sn as i64 - pair[0].sn as i64;
            match diff {
                0 => duplicates += 1,
                1 => step += 1,
                d if d < 0 => backwards += 1,
                _ => jumps += 1,
            }
            if diff <= -64 {
                // Does this dip resume its own counter, or return to the top?
                let run = (1..8usize)
                    .take_while(|k| {
                        segments
                            .get(index + 1 + k)
                            .is_some_and(|next| next.sn == pair[1].sn.wrapping_add(*k as u32))
                    })
                    .count();
                if run >= 6 {
                    resuming += 1;
                } else {
                    isolated += 1;
                }
                if max_ts.saturating_sub(pair[1].ts) > 1000 {
                    stale += 1;
                }
                dips.push((pair[1].sn, diff, pair[1].at - start, &pair[1]));
            }
            max_ts = max_ts.max(pair[1].ts);
        }
        dips.sort_by_key(|entry| entry.1);
        println!(
            "  {label}: {} KCP segments; sn steps: {step} forward-by-one, {jumps} gaps/jumps, {backwards} backwards",
            segments.len()
        );
        println!(
            "    retransmits (sn repeated back-to-back): {duplicates}; dips: {isolated} returned to the top, {resuming} resumed a low counter"
        );
        if !dips.is_empty() {
            println!(
                "    {stale} of {} dips arrived over a second after they were first sent",
                dips.len()
            );
            let shown = dips
                .iter()
                .take(3)
                .map(|(sn, diff, at, seg)| {
                    format!(
                        "sn={sn} ({diff}, +{at}s, cmd={} frg={} len={})",
                        seg.cmd, seg.frg, seg.declared
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("    deepest dips: {shown}");
        }
        println!(
            "    first {} (sn, cmd, frg, declared len):",
            segments.len().min(6)
        );
        for segment in segments.iter().take(6) {
            println!(
                "      sn={} cmd={} frg={} len={}",
                segment.sn, segment.cmd, segment.frg, segment.declared
            );
        }

        // Only a sustained climb from a low counter means two streams were filed
        // under one direction; nothing downstream can reassemble that, and it is
        // invisible without this check.
        if resuming >= 3 && resuming * 4 >= resuming + isolated {
            println!(
                "    warning: {resuming} dips resume a low counter and keep climbing, so this"
            );
            println!(
                "             direction holds two interleaved streams. The dump labels are wrong;"
            );
            println!("             re-capture with a build that derives direction from the port.");
        } else if resuming > 0 {
            println!(
                "    note: {resuming} dips resume a low counter, which reads as a second stream,"
            );
            println!("          but they are isolated and the rest of the stream is contiguous.");
        }
    }
}

fn replay(
    input: &Path,
    assets: &Path,
    region: Option<&str>,
    seed: Option<&str>,
    list_discs: bool,
) -> Result<(), String> {
    let dump = Dump::load(input).map_err(|error| error.to_string())?;
    let mut min_time = i64::MAX;
    let mut max_time = i64::MIN;
    for packet in &dump.packets {
        min_time = min_time.min(packet.timestamp);
        max_time = max_time.max(packet.timestamp);
    }

    println!(
        "{}: {} packets, {} KiB",
        input.display(),
        dump.len(),
        dump.payload_bytes() / 1024
    );
    println!("  incoming: {}", count_direction(&dump, 0));
    println!("  outgoing: {}", count_direction(&dump, 1));
    if dump.is_empty() {
        return Ok(());
    }
    println!(
        "  timespan: {} ({}s)",
        if min_time == max_time {
            "one instant".to_string()
        } else {
            format!("{min_time}..{max_time}")
        },
        max_time.saturating_sub(min_time)
    );
    println!(
        "  largest payload: {} bytes",
        dump.packets.iter().map(|p| p.data.len()).max().unwrap_or(0)
    );
    structure_report(&dump);

    let data = GameData::load(assets).map_err(|error| error.to_string())?;
    let candidates = candidate_seeds(&data, region, seed)?;
    println!(
        "\nDecoding against {} ({} regions)",
        assets.display(),
        data.datamine.xor_seeds.len()
    );

    let (chosen, detection) = choose_seed(&dump, &data, &candidates);
    for line in &detection {
        println!("{line}");
    }
    let Some((label, seed_value)) = chosen else {
        println!("\nNo region seed decrypts this capture.");
        println!("Either the game has updated and `xorSeeds` in datamine.json is stale, or the");
        println!("dump itself is not decodable — see any warning above.");
        return Ok(());
    };

    let scanner = scan(&dump, &data, XorPad::for_region(seed_value), dump.len());
    report_decoding(&data, &label, seed_value, &scanner);
    report_inventory(&data, &scanner, list_discs);
    report_export(&data, &scanner);
    Ok(())
}

/// A dry run of `zzzcap export` with its default settings.
///
/// The inventory above already says how much was extracted; what this adds is
/// whether the *export* can be produced from it at all, which fails for a name
/// the nanoka tables do not have — better to find that out here, with the rest
/// of the diagnosis, than at the moment you try to import the file.
fn report_export(data: &GameData, scanner: &Scanner<'_>) {
    println!("\nExport (this is what `zzzcap export` would write with its default floors)");
    match Izod::from_inventory(
        scanner.inventory(),
        &NanokaNames(&data.nanoka),
        &ExportSettings::default(),
    ) {
        Ok(zod) => println!(
            "  {} agents, {} discs, {} w-engines",
            zod.characters.as_ref().map_or(0, Vec::len),
            zod.discs.as_ref().map_or(0, Vec::len),
            zod.wengines.as_ref().map_or(0, Vec::len),
        ),
        Err(error) => println!("  would fail: {error}"),
    }
}

/// `zzzcap export`: decode a dump and write the ZOD JSON directly.
///
/// The report goes to stderr when the JSON goes to stdout, so
/// `zzzcap export --in capture.json > zod.json` leaves a file the optimizer can
/// read with nothing in front of it.
fn export(
    input: &Path,
    assets: &Path,
    region: Option<&str>,
    seed: Option<&str>,
    out: &str,
    settings: ExportSettings,
) -> Result<(), String> {
    let to_stdout = out == "-";
    let say = |line: String| {
        if to_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    let dump = Dump::load(input).map_err(|error| error.to_string())?;
    let data = GameData::load(assets).map_err(|error| error.to_string())?;
    let candidates = candidate_seeds(&data, region, seed)?;
    let (chosen, detection) = choose_seed(&dump, &data, &candidates);
    for line in detection {
        say(line);
    }
    let Some((label, seed_value)) = chosen else {
        return Err(
            "no region seed decrypts this capture: the game may have updated, so the \
             `xorSeeds` in datamine.json could be stale"
                .to_string(),
        );
    };

    let scanner = scan(&dump, &data, XorPad::for_region(seed_value), dump.len());
    let inventory = scanner.inventory();
    // An empty export is never what the user wants: every category would arrive
    // empty, and the site's import would clear what is already there. A capture
    // with no load response in it is a capture that missed the login, not an
    // account with nothing in it.
    if inventory.is_empty() {
        // Two problems produce an empty inventory and the fix differs, so they
        // are told apart by the strongest evidence available. A completed
        // handshake means the pad is right, and the capture simply has no load
        // response in it. Without one, a wrong pad is far more likely than a
        // capture that missed the login — but not certain, and `decoded` is not
        // proof either way: a wrong pad can parse the odd tiny body by chance,
        // which is why the count is shown rather than judged.
        if scanner.handshake_complete() {
            return Err(format!(
                "{label} ({seed_value:016X}) completed the handshake but nothing was extracted: \
                 no GetEquipDataScRsp, GetWeaponDataScRsp or GetAvatarDataScRsp arrived, so the \
                 capture probably started after the login finished"
            ));
        }
        let stats = scanner.stats();
        return Err(format!(
            "{label} ({seed_value:016X}) produced no session key and no inventory \
             ({} messages decoded, {} bodies that did not parse): either this is the wrong \
             region, or the capture has no login in it — `zzzcap replay --in {}` reports which",
            stats.decoded,
            stats.proto_failures,
            input.display(),
        ));
    }

    let zod = Izod::from_inventory(inventory, &NanokaNames(&data.nanoka), &settings)
        .map_err(|error| error.to_string())?;
    let json = zod.to_json();

    match out {
        // `print!`, not `println!`: `--out - > zod.json` and `--out zod.json`
        // then write the same bytes, which is what makes the two interchangeable.
        "-" => print!("{json}"),
        path => {
            std::fs::write(path, &json).map_err(|error| format!("{path}: {error}"))?;
            say(format!("Wrote {path} ({}) bytes", json.len()));
        }
    }
    // "written of captured" per category, or a plain note when the category was
    // switched off: a floor that dropped records has to be visible, and "0
    // agents" would read as an empty account rather than as `--no-agents`.
    let category = |name: &str, written: Option<usize>, captured: usize| match written {
        Some(count) => format!("{count} of {captured} {name}"),
        None => format!("{name} not exported"),
    };
    say(format!(
        "Exported from {label} ({seed_value:016X}): {}",
        [
            category(
                "discs",
                zod.discs.as_ref().map(Vec::len),
                inventory.discs.len()
            ),
            category(
                "w-engines",
                zod.wengines.as_ref().map(Vec::len),
                inventory.engines.len(),
            ),
            category(
                "agents",
                zod.characters.as_ref().map(Vec::len),
                inventory.agents.len(),
            ),
        ]
        .join(", ")
    ));
    Ok(())
}

/// Everything the extraction summary counts, so "did anything change" is one
/// comparison rather than a field list kept in sync by hand.
fn extraction_total(summary: &zzz_scan::ExtractSummary) -> u64 {
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

/// How many packets the live server holds back while it is still trying to place
/// the region.
///
/// The first attempt is the window `replay` scores, but a live capture can start
/// before the login does, so the attempt is repeated on a growing prefix up to
/// this cap. Past it there is nothing to serve and the session stops with an error
/// rather than running dead — which is also what keeps the held-back window's
/// memory bounded.
const LIVE_DETECT_LIMIT: usize = 4000;

/// How often the live server says what it has seen. A run that is waiting for the
/// game to log in should not look hung.
const LIVE_PROGRESS: Duration = Duration::from_secs(5);

/// What `zzzcap live` was asked to do. The fields mirror the flags, which is why
/// this is a struct rather than a long argument list.
struct LiveOptions<'a> {
    assets: &'a Path,
    input: Option<&'a Path>,
    region: Option<&'a str>,
    seed: Option<&'a str>,
    /// The game's UDP port, used only when capturing.
    port: u16,
    /// The port the optimizer connects to.
    ws_port: u16,
    settings: ExportSettings,
    seconds: u64,
}

/// `zzzcap live`: serve the inventory to the optimizer as it is captured.
///
/// The port and the payload are the reference's: the server comes from
/// `websocketServer.hpp`, and each snapshot is `makeLiveZodJson` — see
/// [`Izod::for_live`] for the two rules that make a live payload different from a
/// written one.
fn live(options: LiveOptions<'_>) -> Result<(), String> {
    let LiveOptions {
        assets,
        input,
        region,
        seed,
        port,
        ws_port,
        settings,
        seconds,
    } = options;

    let data = GameData::load(assets).map_err(|error| error.to_string())?;
    let candidates = candidate_seeds(&data, region, seed)?;

    let server = zzz_live::Server::new();
    server.on_log(|line| println!("  {line}"));
    // A client that connects between two snapshots is given the last one. The
    // reference recomputes the payload in `onSnapshotRequested`; the value is the
    // same, so it is kept rather than built twice.
    let latest: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let snapshot = Arc::clone(&latest);
    server.on_snapshot_requested(move || snapshot.lock().unwrap().clone());
    server
        .start(ws_port)
        .map_err(|error| format!("{error} (is another live session already running?)"))?;

    println!("Serving the inventory on ws://127.0.0.1:{ws_port}/ws");
    println!(
        "  categories:  {}",
        [
            if settings.export_discs { "discs" } else { "-" },
            if settings.export_engines {
                "w-engines"
            } else {
                "-"
            },
            if settings.export_agents {
                "agents"
            } else {
                "-"
            },
        ]
        .join(" ")
    );
    match input {
        Some(path) => println!(
            "  source:      {} (fed as fast as it reads)",
            path.display()
        ),
        None => println!("  source:      live UDP port {port}"),
    }
    if input.is_none() && region.is_none() && seed.is_none() {
        println!("  region:      detected from the login, like `replay` does");
    }

    let started = Instant::now();
    let mut session = Live::new(&data, &candidates, settings, &server, latest);
    let outcome = match input {
        Some(path) => session.stream_dump(path),
        None => stream_device(&mut session, port, seconds),
    };

    // A recorded dump runs out, and that is not a reason to drop the optimizer:
    // the server goes on serving what it was handed until it is interrupted.
    if outcome.is_ok() && input.is_some() {
        println!(
            "  dump fed; serving until interrupted{}",
            match seconds {
                0 => String::new(),
                seconds => format!(" or {seconds}s"),
            }
        );
        while seconds == 0 || started.elapsed() < Duration::from_secs(seconds) {
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    server.stop();
    session.report();
    outcome
}

/// The live pipeline: packets in, snapshots out.
///
/// The region is not known until the login handshake has been seen, so the first
/// packets are held back and scored exactly as `replay` scores a whole dump. Once
/// the region is settled every packet goes straight to the scanner, and anything
/// the extraction applies produces a snapshot.
struct Live<'a> {
    data: &'a GameData,
    candidates: &'a [(String, u64)],
    settings: ExportSettings,
    server: &'a zzz_live::Server,
    /// The payload a client that connects between snapshots receives.
    latest: Arc<Mutex<String>>,
    scanner: Option<Scanner<'a>>,
    /// Packets held back while the region is unknown: the window the next
    /// detection attempt is scored on.
    pending: Dump,
    region: Option<String>,
    packets: u64,
    snapshots: u64,
    snapshot_bytes: usize,
    last_progress: Instant,
}

impl<'a> Live<'a> {
    fn new(
        data: &'a GameData,
        candidates: &'a [(String, u64)],
        settings: ExportSettings,
        server: &'a zzz_live::Server,
        latest: Arc<Mutex<String>>,
    ) -> Self {
        Self {
            data,
            candidates,
            settings,
            server,
            latest,
            scanner: None,
            pending: Dump::new(),
            region: None,
            packets: 0,
            snapshots: 0,
            snapshot_bytes: 0,
            last_progress: Instant::now(),
        }
    }

    /// Feeds one captured packet.
    fn packet(&mut self, packet: &Packet) -> Result<(), String> {
        self.packets += 1;
        self.progress();

        if self.scanner.is_none() {
            self.pending.push(packet);
            // Retried every half-window from the first full one: the handshake is
            // at the start of a session, and a session starts after this does.
            let half_window = (DETECT_PACKETS / 2).max(1);
            if self.pending.len() < DETECT_PACKETS || self.pending.len() % half_window != 0 {
                return Ok(());
            }
            let (chosen, detection) = choose_seed(&self.pending, self.data, self.candidates);
            let Some((label, value)) = chosen else {
                if self.pending.len() >= LIVE_DETECT_LIMIT {
                    return Err(format!(
                        "no region seed decrypts the first {} packets: either the game has \
                         updated and `xorSeeds` in datamine.json is stale, or this traffic is \
                         not the game's — pass --region or --seed to skip detection",
                        self.pending.len()
                    ));
                }
                return Ok(());
            };
            for line in detection {
                println!("{line}");
            }
            let scanner = scan(
                &self.pending,
                self.data,
                XorPad::for_region(value),
                self.pending.len(),
            );
            self.scanner = Some(scanner);
            self.region = Some(label);
            // The held-back window is only kept until it has been decoded.
            self.pending = Dump::new();
            return self.publish();
        }

        let scanner = self.scanner.as_mut().expect("set just above");
        let before = extractions(scanner);
        scanner.feed(&packet.data, packet.direction, packet.timestamp);
        if extractions(scanner) != before {
            return self.publish();
        }
        Ok(())
    }

    /// Rebuilds the payload from what has been extracted and sends it out.
    fn publish(&mut self) -> Result<(), String> {
        let json = match self.scanner.as_ref() {
            // Nothing extracted yet: every category would be null, which the
            // optimizer ignores. The reference's caller skips an empty payload for
            // the same reason.
            Some(scanner) if !scanner.inventory().is_empty() => {
                let zod = Izod::for_live(
                    scanner.inventory(),
                    &NanokaNames(&self.data.nanoka),
                    &self.settings,
                )
                .map_err(|error| {
                    format!(
                        "cannot build a snapshot: {error} — the session stops rather than \
                         sending a payload the optimizer would import"
                    )
                })?;
                zod.to_json()
            }
            _ => return Ok(()),
        };

        {
            let mut latest = self.latest.lock().unwrap();
            // An applied sync that changed nothing among the exported categories
            // produces the same bytes; sending them again would only make the
            // optimizer re-import what it already has.
            if *latest == json {
                return Ok(());
            }
            *latest = json.clone();
        }
        self.server.broadcast_text(&json);
        self.snapshots += 1;
        self.snapshot_bytes = json.len();

        let inventory = self.scanner.as_ref().map(|scanner| scanner.inventory());
        let (discs, engines, agents) = match inventory {
            Some(inventory) => (
                inventory.discs.len(),
                inventory.engines.len(),
                inventory.agents.len(),
            ),
            None => (0, 0, 0),
        };
        println!(
            "  snapshot {} ({} KiB): {discs} discs, {engines} w-engines, {agents} agents, \
             {} client(s)",
            self.snapshots,
            json.len() / 1024,
            self.server.client_count()
        );
        Ok(())
    }

    /// Feeds a recorded dump. This is what makes the server exercisable without
    /// the game, and the only source on a host with no capture driver.
    fn stream_dump(&mut self, path: &Path) -> Result<(), String> {
        let dump = Dump::load(path).map_err(|error| error.to_string())?;
        println!("  {} packets in {}", dump.len(), path.display());
        for packet in dump.iter_packets() {
            self.packet(&packet)?;
        }
        Ok(())
    }

    fn progress(&mut self) {
        if self.last_progress.elapsed() < LIVE_PROGRESS {
            return;
        }
        self.last_progress = Instant::now();
        match self.scanner.as_ref().map(Scanner::inventory) {
            Some(inventory) if !inventory.is_empty() => println!(
                "  {} packets, {} snapshots, {} discs, {} w-engines, {} agents",
                self.packets,
                self.snapshots,
                inventory.discs.len(),
                inventory.engines.len(),
                inventory.agents.len()
            ),
            _ => println!("  {} packets, no region yet", self.packets),
        }
    }

    /// What the session did, once the server has stopped.
    fn report(&self) {
        println!();
        match (&self.region, &self.scanner) {
            (Some(region), Some(scanner)) => {
                let inventory = scanner.inventory();
                let stats = scanner.stats();
                println!(
                    "Served {region}: {} discs, {} w-engines, {} agents",
                    inventory.discs.len(),
                    inventory.engines.len(),
                    inventory.agents.len()
                );
                println!("  packets:   {}", self.packets);
                println!(
                    "  snapshots: {} sent, last {} bytes",
                    self.snapshots, self.snapshot_bytes
                );
                println!(
                    "  messages:  {} decoded of {} reassembled",
                    stats.decoded, stats.messages
                );
            }
            _ => {
                println!(
                    "Served nothing: no region seed was found in {} packets.",
                    self.packets
                );
                println!("  Pass --region or --seed to skip detection.");
            }
        }
    }
}

/// How many extraction events have been applied.
///
/// This is the live equivalent of the reference broadcasting from
/// `pcap.onEventUpdate`: any applied sync counts, whether or not it changed a
/// record, and a payload that turns out identical is deduplicated in [`Live::publish`].
fn extractions(scanner: &Scanner<'_>) -> u64 {
    extraction_total(scanner.extract())
}

#[cfg(windows)]
fn stream_device(session: &mut Live<'_>, port: u16, seconds: u64) -> Result<(), String> {
    let capture = Capture::open(port).map_err(describe)?;
    println!("  filter:      {}", Capture::port_filter(port));
    if seconds > 0 {
        println!("  auto-stop:   {seconds}s");
    }

    let deadline = (seconds > 0).then(|| Instant::now() + Duration::from_secs(seconds));
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut failure = None;
    loop {
        match capture.recv(&mut buffer) {
            Ok(Some(packet)) => {
                // A refusal from the pipeline — no region, or a record the data
                // files cannot name — ends the session: there is nothing useful to
                // serve until it is dealt with, and the driver has to be released
                // so the reason is not buried under packet noise.
                if let Err(error) = session.packet(&packet) {
                    failure = Some(error);
                    capture.stop();
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => {
                failure = Some(describe(error));
                capture.stop();
                break;
            }
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            capture.stop();
            break;
        }
    }

    match failure {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

#[cfg(not(windows))]
fn stream_device(_session: &mut Live<'_>, _port: u16, _seconds: u64) -> Result<(), String> {
    Err(
        "live capture is only implemented for Windows so far; serve a recorded \
         capture with --in <dump> instead"
            .into(),
    )
}

/// Region name and seed pairs to try, most specific first.
fn candidate_seeds(
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
                "--region {name:?} is not in datamine.json (known: {})",
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

/// Pick the region seed this capture used by decoding with each in turn.
///
/// The score is how many messages actually parse, which is the only honest test
/// available: `xorSeeds` changes with a game update, and a capture cannot say
/// which region it came from. The right seed decodes hundreds of messages and a
/// wrong one decodes none, so the gap is not close.
/// Returns the chosen seed and the lines describing how it was chosen. The lines
/// are returned rather than printed so that a caller writing JSON to stdout can
/// send them to stderr instead.
fn choose_seed(
    dump: &Dump,
    data: &GameData,
    candidates: &[(String, u64)],
) -> (Option<(String, u64)>, Vec<String>) {
    let mut report = Vec::new();

    if candidates.len() == 1 {
        let (label, seed) = &candidates[0];
        report.push(format!("  using {label} ({seed:016X})"));
        return (Some((label.clone(), *seed)), report);
    }

    let mut best: Option<(String, u64, u64)> = None;
    for (label, seed) in candidates {
        let scanner = scan(
            dump,
            data,
            XorPad::for_region(*seed),
            DETECT_PACKETS.min(dump.len()),
        );
        let score = scanner.stats().decoded;
        let complete = scanner.handshake_complete();
        report.push(format!(
            "  {label:<12} {seed:016X}  {score} messages decoded{}",
            if complete {
                ", session key derived"
            } else {
                ""
            }
        ));

        // One or two parsed messages prove nothing: a wrong pad can produce the
        // odd accidental parse. A real session either completes the handshake or
        // decodes messages in bulk, and a wrong seed does neither.
        if (complete || score >= MIN_VIABLE_DECODES)
            && best.as_ref().map_or(true, |(_, _, seen)| score > *seen)
        {
            best = Some((label.clone(), *seed, score));
        }
    }

    let chosen = best.map(|(label, seed, score)| {
        report.push(format!(
            "  detected region: {label} ({seed:016X}), {score} messages in the first {DETECT_PACKETS}"
        ));
        (label, seed)
    });
    if chosen.is_none() {
        report.push(format!(
            "  no region produced a session key or {MIN_VIABLE_DECODES}+ decoded messages"
        ));
    }
    (chosen, report)
}

/// Replay a dump through the decoder.
fn scan<'a>(dump: &Dump, data: &'a GameData, pad: XorPad, limit: usize) -> Scanner<'a> {
    let mut scanner = Scanner::new(pad, &data.datamine, &data.nap);
    for packet in dump.packets.iter().take(limit) {
        scanner.feed(&packet.data, packet.direction(), packet.timestamp);
    }
    scanner
}

fn report_decoding(data: &GameData, label: &str, seed: u64, scanner: &Scanner<'_>) {
    let session = scanner.session();
    let stats = scanner.stats();
    let kcp = scanner.kcp_stats();

    println!("\nSession");
    println!("  region:           {label} ({seed:016X})");
    match session.server_rand_key {
        Some(key) => println!("  server_rand_key:  {key:016X}"),
        None => println!("  server_rand_key:  not found (no PlayerGetTokenScRsp in this capture)"),
    }
    match (session.client_rand_key, session.session_key) {
        (Some(client), Some(key)) => {
            println!("  client_rand_key:  {client:016X}");
            println!("  session_key:      {key:016X}");
        }
        _ => println!("  session_key:      not derived"),
    }
    println!(
        "  session pad:      {}",
        if scanner.handshake_complete() {
            "in use"
        } else {
            "still the region pad"
        }
    );

    println!("\nMessages");
    println!("  reassembled:  {}", stats.messages);
    println!("  decoded:      {}", stats.decoded);
    println!("  not protobuf: {}", stats.proto_failures);
    println!("  empty:        {}", stats.empty_bodies);
    println!(
        "  kcp: {} conv resets, {} gaps skipped, {} backlog overflows",
        kcp.conv_resets, kcp.gaps_skipped, kcp.backlog_overflows
    );

    if !scanner.first.is_empty() {
        println!("  first messages:");
        for message in &scanner.first {
            let name = data
                .nap
                .entry_by_cmd(message.command_id)
                .map(|entry| entry.name.as_str())
                .unwrap_or("?");
            println!(
                "    {} ({} bytes, {} fields) {}",
                message.command_id, message.bytes, message.fields, name
            );
        }
    }

    if !scanner.commands.is_empty() {
        let mut ordered: Vec<(&u16, &u64)> = scanner.commands.iter().collect();
        ordered.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        println!("  most frequent commands:");
        for (command_id, count) in ordered.into_iter().take(10) {
            let name = data
                .nap
                .entry_by_cmd(*command_id)
                .map(|entry| entry.name.as_str())
                .unwrap_or("?");
            println!("    {command_id} x{count} {name}");
        }
    }
}

/// The extracted inventory.
///
/// Discs are summarized per set rather than listed: a login sync carries the
/// whole inventory, so a real capture has hundreds and listing them buries
/// everything else. `--discs` asks for the full list.
fn report_inventory(data: &GameData, scanner: &Scanner<'_>, list_discs: bool) {
    let inventory = scanner.inventory();
    let extract = scanner.extract();

    println!("\nInventory");
    println!(
        "  extracted:  {} syncs ({} upserts, {} removals), {} dismantles ({} removals), {} load responses",
        extract.player_syncs,
        extract.sync_upserts,
        extract.sync_removals,
        extract.dismantles,
        extract.dismantle_removals,
        extract.disc_loads + extract.weapon_loads + extract.avatar_loads,
    );
    for (uid, field) in &extract.fallback_removals {
        println!(
            "  fallback:   disc {uid} was deleted through item field {field}, not `deletedEquips`"
        );
        println!(
            "              ({}), so that field number has probably moved in this game version",
            data.datamine.sync_item_data.deleted_equips
        );
    }

    if inventory.is_empty() {
        println!("  nothing extracted: no sync or load response in this capture carried data");
        return;
    }
    // An agent names the w-engine it wears by uid, which is the only link between
    // the two lists: it is what tells "the account owns 342 engines" apart from
    // "the two extractions agree about which ones are in use".
    let mut worn: BTreeMap<u32, u32> = BTreeMap::new();
    for agent in &inventory.agents {
        if agent.weapon_uid != 0 {
            worn.entry(agent.weapon_uid).or_insert(agent.id);
        }
    }
    let dangling = inventory
        .agents
        .iter()
        .filter(|agent| agent.weapon_uid != 0 && !worn.contains_key(&agent.weapon_uid))
        .count();

    println!("  discs:      {}", inventory.discs.len());
    println!(
        "  engines:    {} ({} worn by an agent)",
        inventory.engines.len(),
        worn.len()
    );
    println!("  agents:     {}", inventory.agents.len());
    let names_available = !data.nanoka.characters.is_empty();
    if !names_available {
        println!(
            "  names:      unavailable (assets/nanokaData.json is missing), showing ids;\n              run `zzzcap update` to fetch names"
        );
    }
    if dangling > 0 {
        println!(
            "  caution:    {dangling} agents wear a w-engine uid that is not in the engine list"
        );
    }

    let mut agents: Vec<_> = inventory.agents.iter().collect();
    agents.sort_by_key(|agent| agent.id);
    println!("  agents:");
    for agent in agents {
        // The export reads six skills positionally; showing all six here is how
        // you notice an agent that arrived with fewer.
        let skills = (0..6)
            .map(|position| match agent.skill_level(position) {
                Some(level) => level.to_string(),
                None => "-".to_string(),
            })
            .collect::<Vec<_>>()
            .join("/");
        println!(
            "    {:<26} id {:<7} Lv {:<3} P{:<3} M{:<3} wengine {:<7} skills {skills}",
            data.nanoka.character_name(agent.id).unwrap_or("?"),
            agent.id,
            agent.level,
            agent.promotion,
            agent.mindscape,
            if agent.weapon_uid == 0 {
                "-".to_string()
            } else {
                agent.weapon_uid.to_string()
            },
        );
    }

    let mut engines: Vec<_> = inventory.engines.iter().collect();
    engines.sort_by_key(|engine| engine.id);
    println!("  engines:");
    for engine in engines {
        println!(
            "    {:<26} id {:<7} uid {:<7} Lv {:<3} phase {} mod {}{}",
            data.nanoka.weapon_name(engine.id).unwrap_or("?"),
            engine.id,
            engine.uid,
            engine.level,
            engine.phase,
            engine.modification,
            match worn.get(&engine.uid) {
                Some(agent) => format!("  worn by agent {agent}"),
                None => String::new(),
            },
        );
    }

    println!("  discs:");
    // Set id -> rarity -> count, so the table reads like the in-game inventory
    // rather than as 400 lines.
    let mut by_set: BTreeMap<u32, BTreeMap<u32, usize>> = BTreeMap::new();
    let mut unnamed: BTreeMap<u32, usize> = BTreeMap::new();
    for disc in &inventory.discs {
        *by_set
            .entry(disc.set_id())
            .or_default()
            .entry(disc.rarity())
            .or_default() += 1;
        // Only meaningful with names to compare against: without nanoka data
        // every set is "unknown", which would read as a game-update warning.
        if names_available && data.nanoka.equipment_name(disc.set_id()).is_none() {
            *unnamed.entry(disc.set_id()).or_default() += 1;
        }
    }

    let mut sets: Vec<_> = by_set.iter().collect();
    sets.sort_by_key(|(_, rarities)| std::cmp::Reverse(rarities.values().sum::<usize>()));
    for (set, rarities) in sets {
        let total: usize = rarities.values().sum();
        let breakdown = rarities
            .iter()
            .map(|(rarity, count)| format!("{} {count}", rarity_key(*rarity).unwrap_or("?")))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "    {:<26} {total:>4} discs   {breakdown}",
            data.nanoka.equipment_name(*set).unwrap_or("?")
        );
    }
    if !unnamed.is_empty() {
        let ids = unnamed
            .keys()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "    caution: {} of {} discs use a set id nanoka does not know: {ids}",
            unnamed.values().sum::<usize>(),
            inventory.discs.len()
        );
    }

    if list_discs {
        println!("  every disc:");
        let mut discs: Vec<_> = inventory.discs.iter().collect();
        discs.sort_by_key(|disc| (disc.set_id(), disc.slot(), disc.uid));
        for disc in discs {
            let subs = disc
                .sub_stats
                .iter()
                .map(format_substat)
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "    uid {:<7} id {:<7} {:<26} slot{} {} Lv{:<3} {}{}",
                disc.uid,
                disc.id,
                data.nanoka.equipment_name(disc.set_id()).unwrap_or("?"),
                disc.slot(),
                rarity_key(disc.rarity()).unwrap_or("?"),
                disc.level,
                format_stat(&disc.main_stat),
                if subs.is_empty() {
                    String::new()
                } else {
                    format!("  subs: {subs}")
                },
            );
        }
    }
}

/// A stat as the game sends it.
///
/// Only the key is shown, plus `base`/`add` as the raw numbers they are: the
/// reference implementation never reads a main stat's value — the ZOD export
/// writes `mainStatKey` and nothing else — so the meaning of these two numbers is
/// not established, and printing one as "the" value would be a guess.
fn format_stat(stat: &DiscStat) -> String {
    match stat.stat_name() {
        Some(name) => format!("{name} (base {} add {})", stat.base_value, stat.add_value),
        None => format!(
            "stat#{} (base {} add {})",
            stat.key, stat.base_value, stat.add_value
        ),
    }
}

/// A substat and how many times it was upgraded.
fn format_substat(stat: &DiscStat) -> String {
    let name = stat
        .stat_name()
        .map(str::to_string)
        .unwrap_or_else(|| format!("stat#{}", stat.key));
    format!("{name} +{}", stat.add_value)
}

fn count_direction(dump: &Dump, direction: u8) -> usize {
    dump.packets
        .iter()
        .filter(|p| p.direction == direction)
        .count()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clone_state(state: &Arc<Mutex<Dump>>) -> Dump {
    lock(state).clone()
}

#[cfg(windows)]
fn describe(error: zzz_capture::CaptureError) -> String {
    match error.hint() {
        Some(hint) => format!("{error}\n       {hint}"),
        None => error.to_string(),
    }
}
