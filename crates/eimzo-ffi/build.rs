//! Generates the UniFFI scaffolding from `eimzo.udl` at build time. `expect`
//! is deliberate here: a build script is the one place it belongs, since a
//! failure here is a broken build, not a runtime path.
//!
//! The file lives under `src/`, not the crate root: `uniffi-bindgen generate
//! --library` (used by `scripts/build-core.sh` to emit the Swift bindings)
//! hardcodes `<crate root>/src/<name>.udl` as the only place it will look
//! for a crate's UDL file in library mode, with no flag to override it.
fn main() {
    uniffi::generate_scaffolding("./src/eimzo.udl").expect("uniffi scaffolding");
}
