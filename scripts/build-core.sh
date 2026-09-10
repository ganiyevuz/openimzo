#!/usr/bin/env bash
# Builds the Rust core into a framework the macOS app links against.
#
# Two architectures, one static library each, merged with `lipo` into one
# universal library, then one plain macOS framework holding it, plus the
# Swift bindings generated from the same crate. Everything lands under
# macos/ and nothing under it is committed: this script is the source of
# truth, not its output.
set -euo pipefail

cd "$(dirname "$0")/.."
CRATE=openimzo-ffi
LIB=libopenimzo_ffi.a
OUT=macos
GEN="$OUT/Generated"
PROFILE="${1:-release}"

case "$PROFILE" in
  release) CARGO_FLAGS=(--release); TARGET_DIR=release ;;
  debug)   CARGO_FLAGS=();          TARGET_DIR=debug ;;
  *) echo "usage: $0 [release|debug]" >&2; exit 2 ;;
esac

# Xcode runs this as a build phase with the PATH it was launched with, which
# for Xcode.app started from the Dock is a short system PATH that has never
# seen a shell profile. rustup installs into ~/.cargo/bin, so a build that
# works in a terminal fails in the IDE with nothing but "cargo: command not
# found". Add rustup's own location when cargo is not already reachable, and
# say something useful rather than failing at the first call site.
if ! command -v cargo >/dev/null 2>&1; then
  PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
  export PATH
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not on PATH and is not at ${CARGO_HOME:-$HOME/.cargo}/bin." >&2
  echo "       Install Rust from https://rustup.rs, then build again." >&2
  exit 127
fi

# The app targets macOS 14 (macos/project.yml, three places). Nothing told the
# Rust side that, so a standalone run of this script compiled the vendored C and
# assembly in `ring` against whatever SDK the host happens to have — the linker
# then said so, once per object: "built for newer macOS version 27.0 than being
# linked 14.0". Under Xcode the warning hid itself, because Xcode exports this
# variable into the build phase and cargo inherited a correct value by luck; the
# standalone run is the one that produces the framework a release actually
# ships, and that is the run that was wrong. More than noise: objects compiled
# against a newer SDK can reference symbols absent on 14, which fails when a
# person on an older machine opens the app and never here.
#
# Respects a value already in the environment, so Xcode still wins when it sets
# one, and supplies the floor when nothing does.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"

echo "==> building $CRATE for both architectures ($PROFILE)"
for arch in aarch64-apple-darwin x86_64-apple-darwin; do
  # `/bin/bash` on macOS is still 3.2, which treats expanding a zero-element
  # array under `set -u` as an unbound variable; the `+` form only expands
  # the array when it is set (even to empty), which sidesteps the bug and
  # still works on any bash new enough not to need it.
  cargo build -p "$CRATE" --target "$arch" "${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"}"
done

echo "==> generating Swift bindings"
rm -rf "$GEN"
mkdir -p "$GEN"
cargo run --bin uniffi-bindgen -- generate \
  --library "target/aarch64-apple-darwin/$TARGET_DIR/$LIB" \
  --language swift \
  --out-dir "$GEN"

# UniFFI emits `<name>FFI.modulemap` as a plain (non-framework) module map,
# written for headers that sit next to it in the same directory.
mv "$GEN"/*.modulemap "$GEN/module.modulemap"

# `lipo` merges the two per-architecture static libraries into one universal
# one -- both architectures target the same single macOS platform, unlike
# an iOS device/simulator split, so there is only ever one slice for a
# framework to carry.
UNIVERSAL_DIR="target/universal-macos/$TARGET_DIR"
mkdir -p "$UNIVERSAL_DIR"
lipo -create \
  "target/aarch64-apple-darwin/$TARGET_DIR/$LIB" \
  "target/x86_64-apple-darwin/$TARGET_DIR/$LIB" \
  -output "$UNIVERSAL_DIR/$LIB"

# Named `openimzoFFI`, matching the module UniFFI's generated Swift binds to
# (`import openimzoFFI` in Generated/openimzo.swift): Clang resolves `import
# <Name>` for a framework by looking for `<Name>.framework` directly, then
# reading whatever module its module map declares inside -- the framework's
# own directory (and binary) name has to match the import, independent of
# the module name in the modulemap, but keeping all three the same avoids
# carrying two names for one thing.
echo "==> assembling the framework"
FRAMEWORK="$OUT/openimzoFFI.framework"
rm -rf "$FRAMEWORK"
mkdir -p "$FRAMEWORK/Headers" "$FRAMEWORK/Modules"
cp "$GEN"/*.h "$FRAMEWORK/Headers/"
cp "$UNIVERSAL_DIR/$LIB" "$FRAMEWORK/openimzoFFI"

# Inside a framework's own module map, an unqualified `header` name resolves
# against that framework's Headers/ directory, so the `framework module`
# form of UniFFI's plain module map works unchanged -- only the leading
# keyword differs from what UniFFI wrote for the flat headers-plus-modulemap
# directory this used to be.
sed 's/^module /framework module /' "$GEN/module.modulemap" > "$FRAMEWORK/Modules/module.modulemap"

echo "==> done"
echo "    framework: $FRAMEWORK"
echo "    bindings:  $GEN/openimzo.swift"
