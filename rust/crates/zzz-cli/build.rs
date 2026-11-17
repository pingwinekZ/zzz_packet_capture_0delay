//! Copies the WinDivert runtime files next to the built executable.
//!
//! The backend loads `WinDivert.dll` dynamically, so there is nothing to link.
//! The DLL does need its matching `WinDivert64.sys` in the same folder, and the
//! driver only loads into an elevated process. Both files come from the official
//! WinDivert 2.2.2 release; see `rust/README.md` for the download and the SHA-512
//! that matches the port in `vcpkg-overlay-ports/`.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = std::env::var("WINDIVERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace.join(".windivert/WinDivert-2.2.2-A"));
    println!("cargo:rerun-if-env-changed=WINDIVERT_DIR");
    println!("cargo:rerun-if-changed={}", source.display());

    // The release archive keeps the 64-bit files in `x64/`; a hand-assembled
    // folder may just have them directly.
    let files = ["WinDivert.dll", "WinDivert64.sys"];
    let origin = if source.join("x64/WinDivert.dll").exists() {
        source.join("x64")
    } else {
        source.clone()
    };

    let Some(target) = profile_dir() else {
        return;
    };

    for name in files {
        let from = origin.join(name);
        if !from.exists() {
            println!(
                "cargo:warning=WinDivert file not found at {}; live capture will fail until it is there (see rust/README.md)",
                from.display()
            );
            continue;
        }
        if let Err(error) = copy_if_newer(&from, &target.join(name)) {
            println!("cargo:warning=could not copy {name}: {error}");
        }
    }
}

/// `OUT_DIR` is somewhere under `<target>/<profile>/build/`, and the executable
/// lands in `<target>/<profile>/`. The number of levels between `build` and `out`
/// is not fixed: older Cargo used `build/<crate>-<hash>/out`, newer Cargo nests
/// `build/<crate>/<hash>/out`, so counting ancestors puts the files one level too
/// high on the newer layout. Look for the `build` component instead.
fn profile_dir() -> Option<PathBuf> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").ok()?);
    out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

fn copy_if_newer(from: &Path, to: &Path) -> std::io::Result<()> {
    // The destination does not exist on the first build, which is not an error.
    let source_modified = std::fs::metadata(from).and_then(|m| m.modified()).ok();
    let destination_modified = std::fs::metadata(to).and_then(|m| m.modified()).ok();
    if let (Some(source), Some(destination)) = (source_modified, destination_modified) {
        if destination >= source {
            return Ok(());
        }
    }
    std::fs::copy(from, to)?;
    Ok(())
}
