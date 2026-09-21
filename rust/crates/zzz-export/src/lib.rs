//! ZOD export — the JSON an optimizer imports, ported from
//! `src/serialization/zod/`.
//!
//! Three layers, in the order the reference applies them:
//!
//! 1. [`ExportSettings`] decides what is written at all.
//! 2. [`Izod::from_inventory`] filters the captured inventory and converts each
//!    record into its export shape (`IAgent::fromInstance` and friends).
//! 3. [`Izod::to_json`] serializes it.
//!
//! Layer 3 is hand-written rather than delegated to `serde_json`, and that is
//! the one thing worth understanding before changing anything here. The
//! reference serializes with glaze, and glaze's escaping is *narrower than
//! JSON allows*: it escapes only `"`, `\`, `\b`, `\t`, `\n`, `\f` and `\r`, and
//! emits every other control byte raw. `serde_json` escapes all of `0x00..0x1F`
//! as `\u00XX`, so a single control character in a name — or in anything a future
//! data source supplies — would produce different bytes from the reference for
//! the same input. Since the point of this crate is to be indistinguishable from
//! the reference, [`json`] reproduces glaze's escape set exactly, quirks
//! included. `tests/cpp_export_parity.rs` pins that against output the real C++
//! code produced.
//!
//! Two behaviours of the reference are reproduced deliberately even though they
//! look like bugs, because a byte-for-byte match is the goal:
//!
//! * `equippedEngine` is always the empty string. `IAgent::fromInstance` never
//!   assigns it; the field exists because the site needs the key to be present.
//! * `promotion` and `core` are written as `value - 1`, so a record that carries
//!   `0` wraps to `255` rather than failing. See [`Izod::from_inventory`].
//!
//! Where the reference *throws* (`std::map::at` on a name it does not have, or
//! `std::vector::at` on a skill list that is too short), this port returns an
//! [`ExportError`] instead. It is still a refusal — an export with invented keys
//! or zeroed skill levels would be imported silently, which is worse than an
//! error — but the caller chooses what to do about it, and the error names the
//! record.

pub mod json;
pub mod names;
pub mod settings;
pub mod zod;

pub use names::{Names, NanokaNames};
pub use settings::ExportSettings;
pub use zod::{
    ExportError, IAgent, IDisc, IEngine, ISubstat, Izod, ZOD_FORMAT, ZOD_SOURCE, ZOD_VERSION,
};
