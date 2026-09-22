# About
A packet capture based scanner for Zenless Zone Zero. Used to quickly gather all your discs, engines and agents data from the game in a single click.

It can be used to quickly import all your data into [Zenless Optimizer](https://pingwinekz.github.io/zenless-optimizer-0delay/) or other tools that accept the same data format.

Features of the fork are:
- Continuous capture - you don't need to relaunch the game to capture again, changes in game like new disc or upgraded disc are captured so the export data is always fresh.
- Live Export - capture result continuously flowing into the optimizer, so what you see on website matches your in-game data.

<img width="982" height="672" alt="zzzgui_72ozTBJKMD" src="https://github.com/user-attachments/assets/d01620eb-4c59-49fb-b211-604919b1dfb0" />

# Usage
- Download the latest version from the [releases page](https://github.com/pingwinekZ/zzz_packet_capture_0delay/releases)
- Extract the archive to a folder of your choice and start `zzzgui.exe` **as administrator** (capturing needs the WinDivert driver, which only loads elevated)
- On first start the app downloads `datamine.json`, `nap.json`, `manifest.json` and the name cache into `../assets` by itself
- Press "Start capture", then start the game and log in — the region is detected automatically
- Turn on "Live export" before capturing to serve the inventory to the optimizer at `ws://127.0.0.1:23313/ws`, press "Copy ZOD JSON" to copy the optimizer import to the clipboard, or use `zzzcap.exe export` afterwards to write it to a file

# Disclaimer
If you have experience and want to help your best bet is to help with updating [GracefulDumper](https://github.com/AleXu224/GracefulDumper) to the latest version of the game, since that is the main blocker.
If you are eager to help but have no experience then please don't hesitate to reach out [AleXu224](https://github.com/AleXu224) and ask for how things are done.

# Building

The app is written in Rust and builds with the MSVC toolchain:

```powershell
cd rust
cargo build --release -p zzz-cli -p zzz-gui
```

This produces `rust/target/release/zzzgui.exe` (the window) and `rust/target/release/zzzcap.exe` (the console tool: `capture` / `replay` / `export` / `live` / `update`). The `WinDivert.dll` / `WinDivert64.sys` next to them come from `rust/.windivert/` (see `rust/README.md`); live capture needs them plus an elevated console. Developer docs live in `rust/README.md`.

# Credits
Massive thanks to the Reversed Rooms Discord for helping [AleXu224](https://github.com/AleXu224) with the reverse engineering. 
