# zzz_packet_capture (Rust rewrite)

Rust rewrite of the C++ tool. The C++ tree at the repository root stays buildable
and is the reference implementation we diff against: both the crypto primitives
and the ZOD export are checked against it *byte for byte*, by compiling the
original code rather than by re-deriving what it ought to print.

## Layout

| Crate | Replaces | Notes |
| --- | --- | --- |
| `zzz-crypto` | `src/crypto/*` | RSA, EC2B, XOR pads, .NET `Random`. No I/O, no internal deps. |
| `zzz-wire` | `src/kcp/*`, protobuf `UnknownFieldSet` usage, `crypto::xorProtoFields` | KCP reassembly, generic protobuf wire reader/writer, field-number XOR, protonap. |
| `zzz-gamedata` | `datamine.hpp`, `manifest.hpp`, `nanokaData.hpp`, `serialization/proto.hpp` | Where the parser gets its field numbers and display names. The only crate that talks to the network. |
| `zzz-capture` | `src/pcap/*` (capture half) + PcapPlusPlus | WinDivert through hand-rolled FFI, IP/UDP parsing, the recorded-dump format. |
| `zzz-scan` | `src/crypto/session.hpp`, `src/data/*`, `src/pcap/sync.hpp` | Session handshake, per-message decrypt, the disc/w-engine/agent model, and the sync applier. |
| `zzz-export` | `src/serialization/zod/*` | The ZOD JSON an optimizer imports, and the only JSON writer in the tree that does not go through `serde_json` (see below). |
| `zzz-live` | `src/websocket/websocketServer.hpp` | The WebSocket server the optimizer pulls the inventory from. No asio, no OpenSSL: `std::net` plus threads, and a hand-rolled SHA-1. |
| `zzz-session` | `src/ui/home.cpp` (the pipeline part) | The live decode-and-serve pipeline — region detection, scanning, snapshots, the change log — shared by the CLI and the GUI so the two cannot drift. |
| `zzz-gui` | `src/ui/*` | The window: capture controls, the sync toggles, live export, and a **console** that logs every item-level change (equips, dismantles, new pulls) with real names. |
| `zzz-cli` | `main.cpp`, `tools/*` | `zzzcap capture` / `replay` / `export` / `live` / `update`. |

Planned but not written yet: the `query_dispatch` region lookup
(`src/dispatch/dispatch.hpp`) that would let the seeds refresh themselves.

Rust compiles with the MSVC toolchain alone — no CMake, Ninja, vcpkg, Vulkan SDK
or OpenSSL. `cargo test` is currently 185 tests and takes seconds. (The GUI
adds `eframe`; nothing else pulls new crates.)

`assets/` is still the repository-root one — the crates embed it with
`include_bytes!` so there is a single source of truth for `manifest.json`,
`datamine.json` and `nap.json`.

## Exactness notes

The crypto and wire layers must reproduce the C++ output *bit for bit*; see the
per-module comments. Places where the original relies on the host being
little-endian (`util::to<T>` is a raw unaligned read) use explicit
`from_le_bytes`/`to_le_bytes` here, which is equivalent on x86_64 and also
correct on a big-endian host.

## Live capture on Windows

The Windows backend loads `WinDivert.dll` dynamically, so the only build-time
requirement is that the DLL and its driver sit next to the executable. The build
script in `zzz-cli` copies them from `.windivert/`, which is not committed — fetch
it once:

```bash
cd rust
mkdir -p .windivert && cd .windivert
curl -sSLo WinDivert-2.2.2-A.zip \
  https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
# Must match the hash pinned in vcpkg-overlay-ports/windivert/portfile.cmake:
sha512sum -c <<< "92eb2ef98ced175d44de1cdb7c52f2ebc534b6a997926baeb83bfe94cba9287b438f796aff11f6163918bcdbc25bcd4e3383715f139f690d207ce219f846a345  WinDivert-2.2.2-A.zip"
unzip -q WinDivert-2.2.2-A.zip
```

Set `WINDIVERT_DIR` to point somewhere else if you keep the release elsewhere.

Capturing needs an **elevated console**: the driver only loads with administrator
rights, and without them `WinDivertOpen` fails with Win32 error 5.

```powershell
cd rust
cargo run -p zzz-cli -- capture --seconds 180
```

## Decoding a capture

```bash
cargo run -p zzz-cli -- replay --in captured_packets.json
```

`replay` reports the dump's structure, then decodes it. It detects which
`xorSeeds` region the capture used by trying each — the right seed decodes
hundreds of messages and completes the handshake, a wrong one decodes nothing —
then reassembles KCP in both directions, recovers `server_rand_key` and
`client_rand_key`, and summarizes the commands it saw. `--region`/`--seed` skip
detection; `--assets` points at a different data directory.

Two facts about direction, because getting them wrong costs a debugging session:

* Direction comes from the UDP port — `dst == 20501` means outgoing — exactly as
  `Pcap::processRawPacket` decides it. WinDivert's address also carries it, in the
  32-bit bitfield word that starts at byte 8: `Layer:8`, `Event:8`, `Sniffed:1`,
  `Outbound:1`, so `Outbound` is byte 10 mask `0x02`. Byte 11 is `Reserved1` and
  always reads zero, so reading it there labels every packet incoming.
* That failure is silent — two KCP streams filed under one label just look like a
  noisy capture, so `replay` classifies the backwards steps it sees. Sequence
  numbers climb by one within a direction, and a dip means one of two things:
  a retransmit or reordered datagram (which returns straight to the high-water
  mark, and which KCP exists to absorb), or a second connection restarting from
  its own low counter and *climbing from there*. Only the second is a warning.
  A KCP segment carries the millisecond timestamp of its first send, so a
  retransmit also shows a `ts` far behind the stream; `replay` reports both
  signals.

A real 99-second login capture (5542 packets) shows this working: of 3884
incoming steps, 3307 are forward-by-one and 90 are dips — of which 82 return to
the top, and 64 carry a stale `ts`. Those late duplicates are dropped by the reassembler's
`diff < 0` check — the same policy as the C++ — which is why the capture decodes
cleanly: 561 messages reassembled, 395 decoded, 0 gaps skipped, 0 backlog
overflows.

## The inventory

`replay` also reports what it extracted, which is the difference between "395
messages decoded" and "the account owns 1393 discs, 342 w-engines and 48 agents":

```
Inventory
  extracted:  10 syncs (0 upserts, 0 removals), 0 dismantles (0 removals), 3 load responses
  discs:      1393
  engines:    342 (36 worn by an agent)
  agents:     48
```

Extraction runs where the original runs it — in the message handler, as soon as a
body decodes and its obfuscated values have been XORed back — and it is driven by
the same `datamine.json` field numbers. Both halves are covered: the load
responses (`GetEquipDataScRsp`, `GetWeaponDataScRsp`, `GetAvatarDataScRsp`, which
is where this capture's inventory came from) and the incremental syncs
(`PlayerSyncScNotify`, `DismantleEquipCsReq`).

The `ItemSync` fallback is kept from the original: an unknown field is probed for
uids the inventory recognises, because that is how the `deletedEquips` field
number gets rediscovered when it moves, and a hit is reported rather than silently
applied. Discs are summarized per set rather than listed — a login carries the
whole inventory — and `--discs` prints every one.

Two things the report deliberately does **not** claim:

* **Main-stat values.** `DiscStat` carries `base_value` and `add_value`, but the
  reference implementation only ever reads the stat *key*; the ZOD export writes
  `mainStatKey` and nothing else. On the recorded capture both numbers are
  identical for a Lv0 and a Lv15 disc of the same set and slot, so neither is a
  level-scaled value, and `replay --discs` shows them as the raw numbers they are
  instead of inventing a formula. Sub-stat `add_value` is different: the export
  uses it as the upgrade count, so that one is rendered as `crit_ +2`.
* **Names**, which come from the nanoka cache — run `zzzcap update` once (see
  below). Set ids are checked against that table, and a set it does not know is
  reported as a possible game update rather than silently blanked.

The report cross-checks the two lists against each other, because an agent names
the w-engine it wears by uid: on the recorded capture all 36 engines in use are at
the level cap while the other 306 are unlevelled, and no agent points at an engine
that never arrived. That is what makes the extraction trustworthy rather than
merely plausible.

## The export

```bash
cargo run -p zzz-cli -- export --in captured_packets.json --out zod.json
```

That writes the ZOD JSON the optimizer imports: 48 agents, 1393 discs and 342
w-engines for the recorded login. `--out -` (the default) writes the JSON to
stdout and the report to stderr, so a redirect gives you a clean file — and the
same bytes as `--out`, which is why `print!` is used rather than `println!`.

The floors are the reference's defaults, and they are worth reading before you
change them: `--min-agent-rarity 4` (the game's three-star agents are left out),
`--min-disc-rarity 3` and `--min-engine-rarity 3`. Note that agent and w-engine
rarity is counted in *stars*, from the nanoka rank, while disc rarity is the band
the game encodes in the disc id — 3, 4 and 5 are the export's B, A and S. The two
floors count different things because the reference compares them against
different sources.

`--no-agents`, `--no-discs` and `--no-engines` leave a category *out of the
file*. That is not the same as writing it empty, and it is not a cosmetic choice:
an absent list tells the site to keep what it imported last time, while an empty
one clears it.

Two refusals rather than bad output. An inventory that decoded nothing is not
exported at all, because every category would arrive empty and the import would
clear the account. And an id with no name in the nanoka cache fails with the id
named — an export key is derived from the name, so there is no honest value to
substitute; `zzzcap update` is the fix. The reference throws in both cases.

### Why the JSON writer is hand-written

The reference serializes with glaze, and glaze escapes less than JSON allows. It
escapes `"`, `\`, `\b`, `\t`, `\n`, `\f` and `\r` and writes **every other
control byte raw**, which is invalid JSON for a name containing one;
`serde_json` escapes all of `0x00..0x1F`. Since the goal is the reference's
exactly bytes, `zzz-export/src/json.rs` reproduces glaze's escape set — quirks
included — and `tools/cpp_glaze_probe.cpp` is how that set was established and
how it can be rechecked after a glaze upgrade. glaze also writes a `uint8_t` as a
number rather than a character, which the export's signed-width fields depend on.

Two behaviours of the reference are reproduced even though they look wrong,
because matching it is the point: `equippedEngine` is always the empty string
(`IAgent::fromInstance` never assigns it), and `promotion`/`core` are written as
`value - 1`, so a captured `0` wraps to `255` rather than failing.

## Refreshing the data files

```bash
cargo run -p zzz-cli -- update
```

That fetches `manifest.json`, `datamine.json`, `nap.json` and the nanoka name
cache from the published copies. `--assets` points somewhere else.

The rule worth knowing: **a published file that is older than the local one is
refused, not written.** `manifest.json`'s version does not change when fields are
added, so the published `datamine.json` can be behind the working copy that built
the binary — in this tree it is, and it drops `cmdPlayerSyncScNotify`,
`syncAvatarData`, `syncItemData`, `equipDismantle` and `cmdDismantleEquipCsReq`.
Writing it would silently disable sync extraction, and the symptom would look
exactly like a game update. So `update` compares the *key sets* — and the nap
descriptor names, where losing an entry garbles field values instead of failing
to parse — keeps the local file, and reports what the published one would have
dropped. `datamine.json` and `nap.json` are guarded as a pair, because they are
generated together for a game version and a mismatched pair is worse than one
that is simply old.

The nanoka cache is deliberately not part of that guard: it only ever contributes
display names, so `update` refreshes names even when it keeps the data files.
That cache is gitignored; delete the line in `.gitignore` if you would rather
commit names than fetch them.

## Reference vectors

These are the assertions that make the port trustworthy without needing the game:

| Module | Pinned against |
| --- | --- |
| `mt19937` | The published `std::mt19937_64` sequence for seed 5489 |
| `netrand` | The documented `System.Random(0)`: first `Next()` is 1559595546 |
| `rsa` | Encrypt with `e`, decrypt with `d`, compare, using the embedded key |
| `ec2b` | Table spot checks, plus a fixture test that derives each region's seed and compares it with `assets/datamine.json` |
| `proto` | protobuf's accept/reject semantics: empty input parses, field number 0 does not, groups must terminate |
| `kcp` | Reassembly, gap-skipping, the 512-segment backlog cap, per-direction conv resets |
| `zzz-scan` | A synthetic login handshake built from the real `assets/`: token response, the key-carrying message, then a message that only decodes with the session pad. Plus a decoded `PlayerSyncScNotify` reaching the inventory |
| `model`/`snapshot` | Every field number from `datamine.json`, the stat table, the applier's upsert/replace/remove semantics, the moved-`deletedEquips` fallback, and packed uid lists |
| the recorded login | A real capture, when present: handshake keys, 1393 discs, 342 engines, 48 agents, and every w-engine in use at the level cap |
| `refresh` | The downgrade guard: a published datamine that drops a key, a published nap that drops a descriptor, one this build cannot parse, and one that only adds keys |
| `datamine`/`nanoka` | The committed `assets/*.json`, and a full refresh against a canned fetcher |
| `json` | glaze's escape set, byte by byte, over all 32 control codes |
| `zod` | The shape and field order the reference writes, the zero-based conversions, the four padded substat slots, the maps that are built before filtering, and every refusal |
| `zzz-export` | **The C++ implementation itself** — see the export parity section below |
| all of `zzz-crypto` | **The C++ implementation itself** — see below |

## Parity against the C++ build

The strongest check available is not a hand-written expectation but the original
code. `tools/cpp_parity.cpp` compiles against the headers in `src/crypto/` and
prints reference vectors; `rust/testdata/parity/cpp_vectors.txt` is that output,
committed; and `rust/crates/zzz-crypto/tests/cpp_parity.rs` recomputes all 32
vectors and asserts the Rust port matches.

It covers both pad byte orders for seven seeds (including the four region seeds
and the session key from a real capture), the first eight `.NET Random` samples
for six seeds including `Int32.MinValue`, `client_rand_key`,
`seed_from_unix_seconds`, and `ec2b::derive_seed` over synthetic blobs — which
exercises the inverse AES, the G-tables, the shift rows and the 256-word scramble
loop without needing a recorded dispatch blob.

It needs no vcpkg, protobuf or OpenSSL, because every header it touches is
dependency-free. `vcvars64.bat` can be skipped by setting `INCLUDE`/`LIB` by
hand; see the comment at the top of the file.

```bash
# from the repo root, with cl.exe reachable
cl /nologo /std:c++latest /EHsc /W3 /O2 /I src tools\cpp_parity.cpp
```

Regenerate the fixture after changing anything under `src/crypto/` or `src/util/`.
If a vector changes, that is a real behavioural difference and the Rust port has
to follow it.

## The export, against the C++ export

`tools/cpp_export.cpp` does for the exporter what `cpp_parity.cpp` does for the
crypto: it **compiles the reference's own code** — `IZOD::fromPcap`,
`IAgent::fromInstance`, `IDisc::fromInstance`, `IEngine::fromInstance` — together
with the real `data::*` model, `data::ExportSettings`, `util::strings::toZodKey`
and the real nanoka/datamine loaders, reads an inventory, and writes the JSON.
Two of its outputs are committed as fixtures:

| Fixture | What it is |
| --- | --- |
| `testdata/parity/zod_export.json` | The inventory decoded from `login_capture.json`, with every floor at zero: all 1393 discs, 342 w-engines and 48 agents, 401 KB |
| `testdata/parity/zod_edge_export.json` | A small synthetic inventory at the *default* settings: the filters, the padded substat slots, a w-engine that never arrived, a disc below the rarity floor |

`rust/crates/zzz-export/tests/cpp_export_parity.rs` asserts the Rust export
reproduces both byte for byte. The inputs (`zod_inventory.json`,
`zod_edge_inventory.json`) are committed too, so the comparison runs on a machine
that has never recorded a session — only the nanoka cache is needed, for names.

The `cl` line is in the harness's header. Two of the three libraries the real
tree links are absent here (no vcpkg, so no protobuf and no pcap++, and no
OpenSSL), and the harness stands in for the parts of them the export touches:
`tools/.shim/pcap/pcap.hpp` supplies the three inventory vectors `IZOD::fromPcap`
reads, and `tools/.shim/google/protobuf/unknown_field_set.h` is a working
wire-format `UnknownFieldSet`. Neither is in the path the export takes — nothing
between the input inventory and the output bytes is reimplemented, and that is
what makes the comparison worth having.

Regenerating the fixtures:

```bash
# 1. write the two intermediates from the recorded capture
cargo test -p zzz-export --test cpp_export_parity -- --ignored write_parity_inputs
# 2. run the reference export over each of them, from the repo root
tools\cpp_export.exe rust\testdata\parity\zod_inventory.json rust\testdata\parity\zod_export.json unfiltered
tools\cpp_export.exe rust\testdata\parity\zod_edge_inventory.json rust\testdata\parity\zod_edge_export.json default
# 3. check the port still agrees
cargo test -p zzz-export --test cpp_export_parity
```

The whole capture-to-JSON path is worth one more check, because it is the one the
user takes: `zzzcap export --in login_capture.json --out zod.json` produces a file
with the same MD5 as the harness reading `zod_inventory.json` in `default` mode.

## The live server

`zzzcap live` serves the inventory to the optimizer over the same WebSocket the
C++ app does, so the site's "Live import" switch works against this build:

```bash
cargo run -p zzz-cli -- live                  # capture and serve on 23313
cargo run -p zzz-cli -- live --in login_capture.json   # serve a recorded dump
cargo run -p zzz-cli -- live --no-engines     # leave w-engines alone
```

It listens on `127.0.0.1:23313` and accepts any path, so the optimizer's
`ws://127.0.0.1:23313/ws` works as it is. A *snapshot* is a ZOD JSON payload sent
whenever the capture changes the inventory, and a client that connects in between
is given the last one.

Three rules decide what a live payload may contain, and all three follow from the
optimizer importing with replace semantics — what the payload says is what the
account becomes:

* **The floors are ignored.** `--min-disc-level` and its siblings are zeroed for a
  live payload however they were passed: a floor would delete every record below
  it from the site on the next snapshot. `--no-agents` / `--no-discs` /
  `--no-engines` still apply, because that is how the user says "stop syncing
  this".
* **An empty category is absent, never `[]`.** An empty list means "everything was
  deleted"; an absent one means "nothing to say", which the site leaves alone.
  This is the state at the start of a session, before the load responses land.
* **A snapshot that cannot be built stops the session.** An unknown name or stat
  is a refusal here as it is for a file export, rather than something to serve
  half of.

`rust/crates/zzz-cli/tests/live_cli.rs` runs the built binary against the recorded
login and pulls the payload over a socket, asserting the account arrives whole
(1393 discs, 342 w-engines, 48 agents) and that `--no-engines` produces a payload
with no `wengines` key at all.

### Why the reader polls

The reference gets this from asio, which cancels a pending read when the socket is
closed. A blocking `recv` cannot be interrupted that way: on Windows,
`shutdown(Both)`, `shutdown(Read)` and closing a *duplicate* handle all leave a
blocked `recv` blocked — only an incoming close from the peer completes it. That
was measured, not assumed (`tools/` keeps no harness for it; the three cases were
run and are recorded here because the first two are the ones everyone expects to
work).

So a client's socket carries a read timeout, the reader checks whether it has been
asked to stop whenever a read times out, and writes get a timeout of their own so
that a client which stops reading cannot park the sender. That is what bounds
`stop()`. The one behaviour it changes: a peer that stalls *mid-frame* for longer
than the read timeout is dropped, where the reference would wait forever.

## The GUI

```bash
cargo run -p zzz-gui --release
```

Same layout as the reference — region picker, start/stop, the live-export
toggle, the three sync checkboxes — plus a right-hand **console** panel that the
reference never had: every disc added, w-engine equipped or unequipped (by
agent name), and removal is logged with real names as the capture sees it. The
change log is a ring buffer, so an all-night session cannot grow it without
bound.

`zzz-gui` runs the same `zzz-session` pipeline `zzzcap live` runs, so the two
cannot disagree about what was captured.

## Commands

```bash
cargo test
cargo clippy --all-targets
cargo fmt --check
```

`zzzcap` itself:

```bash
cargo run -p zzz-cli -- capture --seconds 180
cargo run -p zzz-cli -- replay  --in login_capture.json
cargo run -p zzz-cli -- export  --in login_capture.json --out zod.json
cargo run -p zzz-cli -- live    --in login_capture.json
cargo run -p zzz-cli -- update
```

On Windows the toolchain lives in `%USERPROFILE%\.cargo\bin`, but note that `$USERPROFILE`
is a Windows path with a colon in it, so it cannot be appended to `PATH` directly from
Git Bash:

```bash
export PATH="$(cygpath -u "$USERPROFILE")/.cargo/bin:$PATH"
```
