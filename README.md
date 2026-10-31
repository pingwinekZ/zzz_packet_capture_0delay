# About
A packet capture based scanner for Zenless Zone Zero. Used to quickly gather all your discs, engines and agents data from the game in a single click. Supports game version **3.3** (`OSPRODWin3.3.0`).

It can be used to quickly import all your data into [Zenless Optimizer](https://pingwinekz.github.io/zenless-optimizer-0delay/) or other tools that accept the same data format.

Features of the fork are:
- Continuous capture - you don't need to relaunch the game to capture again, changes in game like new disc or upgraded disc are captured so the export data is always fresh.
- Live Export - capture result continuously flowing into the optimizer, so what you see on website matches your in-game data.

<img width="982" height="672" alt="zzzgui_72ozTBJKMD" src="https://github.com/user-attachments/assets/d01620eb-4c59-49fb-b211-604919b1dfb0" />

# Usage

## Windows
- Download the latest `win64` archive from the [releases page](https://github.com/pingwinekZ/zzz_packet_capture_0delay/releases)
- Extract the archive to a folder of your choice and start `zzzgui.exe` **as administrator** (capturing needs the WinDivert driver, which only loads elevated)
- On first start the app downloads `datamine.json`, `nap.json`, `manifest.json` and the name cache into `../assets` by itself
- Press "Start capture", then start the game and log in — the region is detected automatically
- Turn on "Live export" before capturing to serve the inventory to the optimizer at `ws://127.0.0.1:23313/ws` **OR** press "Copy ZOD JSON" to copy the optimizer import to the clipboard

## Linux
- Download the latest `linux-x86_64` archive from the [releases page](https://github.com/pingwinekZ/zzz_packet_capture_0delay/releases)
- Extract the archive and keep the `lib/` folder next to the binaries: it contains libpcap, so there is nothing to install and no dependency on the distribution's libpcap version
- Live capture needs raw-socket access. Run the binaries as root, or grant the capability once:
  `sudo setcap cap_net_raw,cap_net_admin=eip ./zzzcap` and `sudo setcap cap_net_raw,cap_net_admin=eip ./zzzgui`
- Start `./zzzgui`, or use the console: `./zzzcap capture --seconds 180`
- The rest is the same as on Windows: start the game and log in, then use live export, or run `zzzcap live` for the console equivalent. A game running under Wine/Proton is captured through the host network stack like any other process.
- Capture listens on every interface by default. If your traffic goes through a VPN or a specific adapter, set `ZZZ_CAPTURE_DEVICE=eth0` (or the matching name from `ip link`) before starting.
- The archive is built on Ubuntu 22.04, so it needs glibc 2.35 or newer (Ubuntu 22.04+, Debian 12+, current Fedora/Arch). On an older distribution, build it from source instead (see Building).

# Disclaimer
If you have experience and want to help your best bet is to help with updating [GracefulDumper](https://github.com/AleXu224/GracefulDumper) to the latest version of the game, since that is the main blocker.
If you are eager to help but have no experience then please don't hesitate to reach out [AleXu224](https://github.com/AleXu224) and ask for how things are done.

# Building

The app is written in Rust. On Windows it builds with the MSVC toolchain; on Linux it needs libpcap headers, plus the usual X11/Wayland/GL development packages for the GUI:

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev libxkbcommon-dev libwayland-dev libx11-dev libgl1-mesa-dev

cd rust
cargo build --release -p zzz-cli -p zzz-gui
```

This produces `zzzgui` (the window) and `zzzcap` (the console tool: `capture` / `replay` / `probe` / `export` / `live` / `update`) in `rust/target/release/`. On Windows, `WinDivert.dll` / `WinDivert64.sys` are copied next to them from `rust/.windivert/` (see `rust/README.md`); live capture needs them plus an elevated console. Developer docs live in `rust/README.md`.

The field numbers live in `assets/datamine.json`, so a game update is a data change; `zzzcap probe` is the tool that re-derives them from a capture.

# Credits
Massive thanks to the Reversed Rooms Discord for helping [AleXu224](https://github.com/AleXu224) with the reverse engineering. 
