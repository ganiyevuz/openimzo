//! The binding generator, as a binary in this crate so it always matches the
//! `uniffi` version the library itself is built against. Running a
//! separately-installed `uniffi-bindgen` risks a version skew that produces
//! Swift which compiles and then misbehaves at run time.
fn main() {
    uniffi::uniffi_bindgen_main()
}
