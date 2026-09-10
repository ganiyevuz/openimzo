#!/usr/bin/env bash
# Rebuilds OpenImzo.app the way a stranger checking a release would want to:
# unsigned, and with every known source of build-to-build variation pinned or
# normalized, so the result hashes identically no matter which machine, which
# directory, or which moment built it.
#
# This produces the UNSIGNED artifact only. A signed, notarized .app can never
# be byte-identical to this one -- see docs/verifying-a-release.md for why,
# and what to compare instead.
#
# Usage: scripts/reproducible-build.sh [output-dir]   (default: dist/)
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd -P)"

# --- fail-fast guards: cheap checks, before any of the expensive work below --
if [ -z "${SOURCE_DATE_EPOCH:-}" ] && ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: $REPO_ROOT is not a git checkout, and SOURCE_DATE_EPOCH isn't set." >&2
  echo "       Either build from a git checkout, or export SOURCE_DATE_EPOCH yourself." >&2
  exit 1
fi
if ! command -v rsync >/dev/null 2>&1; then
  echo "error: rsync is required (used to stage a clean copy of the checkout; see below)." >&2
  exit 127
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required (used to package the build deterministically; see below)." >&2
  exit 127
fi
if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "error: xcodebuild is required (Xcode itself, not just the Command Line Tools)." >&2
  exit 127
fi

# .xcode-version pins the toolchain the same way rust-toolchain.toml pins Rust -- but
# unlike rust-toolchain.toml, nothing about Xcode reads this file automatically:
# `rustup` provisions the exact compiler on its own the moment cargo/rustc runs in this
# checkout, while Xcode has to already be installed and selected by hand. So this script
# checks it itself, before doing any of the expensive work below, rather than silently
# building with whatever `xcode-select` currently points at. A different Xcode means a
# different SDK -- a different `LC_BUILD_VERSION`, different compiler internals -- for a
# real reason that neither `--remap-path-prefix` nor `-ffile-prefix-map` can reach,
# because those fix embedded *paths*, not toolchain version metadata. Building with the
# wrong Xcode produces a different hash that has nothing to do with tampering; better to
# say so up front than let someone find that out after a ten-minute build.
EXPECTED_XCODE="$(tr -d '[:space:]' < "$REPO_ROOT/.xcode-version")"
ACTUAL_XCODE="$(xcodebuild -version | awk 'NR==1{print $2}')"
if [ "$EXPECTED_XCODE" != "$ACTUAL_XCODE" ]; then
  echo "error: this checkout pins Xcode $EXPECTED_XCODE (.xcode-version), but 'xcodebuild -version' reports $ACTUAL_XCODE." >&2
  echo "       Install and select Xcode $EXPECTED_XCODE first, e.g.:" >&2
  echo "         sudo xcode-select -s /Applications/Xcode_${EXPECTED_XCODE}.app" >&2
  echo "       A different Xcode produces a different, but not tampered-with, hash -- see docs/verifying-a-release.md." >&2
  exit 1
fi
echo "==> Xcode $ACTUAL_XCODE matches the pinned version (.xcode-version)"

OUT_DIR="${1:-dist}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"

# --- claim the fixed staging path before touching it ---------------------
# The whole reason $STAGE (below) is a fixed literal rather than a per-run
# temp directory is so the linker's OSO debug-map entries (see the staging
# comment further down) name the same path for everyone -- a per-run path
# would reopen exactly the leak that fixes. But a fixed, shared path is
# something two builds can collide on if they happen to run at the same
# time: verified this the hard way -- a second run started against the same
# path while a first was still going tore the tree down from underneath it
# (`rm: Directory not empty`, then a build failure mid-compile once the first
# run's own files started vanishing). Since docs/verifying-a-release.md asks
# a verifier to build the same thing twice to compare, two terminals running
# it at once is the obvious way to do exactly that -- so this has to fail
# loudly and immediately, before either run touches $STAGE, rather than
# corrupt both.
STAGE="${OPENIMZO_BUILD_STAGE:-/tmp/openimzo-build}"
LOCKDIR="$STAGE.lock"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  HOLDER_PID="$(cat "$LOCKDIR/pid" 2>/dev/null || true)"
  if [ -n "$HOLDER_PID" ] && kill -0 "$HOLDER_PID" 2>/dev/null; then
    echo "error: another build (PID $HOLDER_PID) is already using $STAGE." >&2
    echo "       Only one build can use a given staging path at a time -- the fixed path" >&2
    echo "       is what makes the linker's recorded paths match everyone else's, which" >&2
    echo "       only holds if it isn't shared between two builds running at once." >&2
    echo "       Wait for PID $HOLDER_PID to finish, then run this again." >&2
    exit 1
  fi
  echo "error: $LOCKDIR exists, but PID ${HOLDER_PID:-(unknown)} recorded in it is not running." >&2
  echo "       This looks like it was left behind by a build that didn't exit cleanly" >&2
  echo "       (killed, or the machine restarted), not one that's still running. If" >&2
  echo "       you're sure nothing is using $STAGE right now, clear it and retry:" >&2
  echo "         rm -rf \"$LOCKDIR\" \"$STAGE\"" >&2
  exit 1
fi
cleanup() {
  local status=$?
  rm -rf "$LOCKDIR"
  exit "$status"
}
trap cleanup EXIT
echo $$ > "$LOCKDIR/pid"

# --- pin the environment: nothing about *when* or *what surrounds* this run
# should reach the output --------------------------------------------------
export LC_ALL=C
export TZ=UTC

# The standard reproducible-builds knob. Pinned to the commit being built, not
# to "now", so every rebuild of the same commit -- today or in five years --
# agrees. Respects a caller-supplied value (a CI job building a tag might want
# the tag's own commit time rather than whatever HEAD happens to be).
: "${SOURCE_DATE_EPOCH:=$(git -C "$REPO_ROOT" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "==> commit $COMMIT, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($(date -u -r "$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S UTC'))"

# Cargo already disables incremental compilation for --release; pinned
# explicitly anyway; an incremental cache is itself a form of build-to-build
# state, and this shouldn't depend on that default never changing.
export CARGO_INCREMENTAL=0

# scripts/build-core.sh honors an *inherited* MACOSX_DEPLOYMENT_TARGET
# (`export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"`) rather than
# always setting it itself -- correct for an ordinary Xcode build, where Xcode's own
# project setting should be free to win over a stray shell variable, so don't "fix"
# that script to match this one. This script is not an ordinary build, though: it
# exists to be hermetic, so it pins the value explicitly rather than deferring to
# whatever the caller's shell happens to carry -- plausible to have set, for anyone who
# also does iOS work, and invisible to `--remap-path-prefix`/`-ffile-prefix-map`
# entirely, since it changes which SDK symbols get linked, not any embedded path.
export MACOSX_DEPLOYMENT_TARGET=14.0

# --- stage the checkout at a fixed, literal path ------------------------
# ld64 records, as a plain absolute path, where it found every object file it
# linked -- one `OSO` stab entry per object (`nm -a` shows them), so a
# debugger can find the originals later. That path is wherever this checkout
# happens to live, which is exactly the thing two different clones of the
# same commit disagree on by construction. `--remap-path-prefix` and
# `-ffile-prefix-map` below fix what the *compiler* embeds into each object;
# neither touches this, because it's inserted by the *linker* from its own
# search-path argument, after the fact.
#
# Verified against this project's own framework: `nm -a` on a plain
# `xcodebuild ... build` of an unmodified checkout showed 55 `OSO` entries,
# every one naming this checkout's own absolute path
# (.../eimzoFFI.framework/eimzoFFI); a second checkout in a differently-named
# directory produced the same 55 entries under its own path instead. Building
# both from the same fixed path, as below, removed the difference.
#
# Not $TMPDIR: on macOS that's a per-user, per-login-session directory with a
# random component of its own, which would just move the problem rather than
# fix it. $STAGE itself (and the lock guarding it) were already claimed
# above, before this script did anything else -- everyone comparing hashes
# has to agree on the same value for the comparison to mean anything, so the
# default is a fixed literal that ships in this script and in the release
# workflow, and OPENIMZO_BUILD_STAGE exists to override it only for someone
# who has a specific reason not to compare their hash against anyone else's.
echo "==> staging a clean copy of the checkout at $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"
# Only what the build reads. target/ and macos/'s generated build products are
# excluded on purpose: scripts/build-core.sh (invoked below) regenerates all
# of it, and copying yesterday's build products would just copy yesterday's
# absolute paths into today's build.
rsync -a \
  --exclude .git \
  --exclude target \
  --exclude macos/Generated \
  --exclude macos/eimzoFFI.framework \
  --exclude 'macos/*.xcodeproj/xcuserdata' \
  --exclude 'macos/*.xcodeproj/project.xcworkspace/xcuserdata' \
  --exclude dist \
  "$REPO_ROOT/" "$STAGE/"

CARGO_HOME_REAL="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"

# rustc embeds the absolute path of every source file it compiles into
# panic locations (`file!()`, `#[track_caller]`) -- plain string constants in
# the shipped binary, present regardless of debug-info settings, so stripping
# later doesn't remove them. Verified: an unmodified release build of this
# workspace embeds 1397 copies of $CARGO_HOME below, all from crates.io
# sources checked out under it (e.g. tokio, uniffi); a rebuild under a
# different username, or with a different CARGO_HOME, embeds a different 1397
# strings and nothing else about the build differs. Remapped to a fixed,
# fake path here -- not stripped to nothing -- so the panic messages this
# project's own error handling relies on stay meaningful, just anonymized.
export RUSTFLAGS="--remap-path-prefix=$STAGE=/build/openimzo --remap-path-prefix=$CARGO_HOME_REAL=/build/cargo-home"

# `ring`'s vendored C and assembly sources aren't compiled by rustc -- its
# build script invokes the platform C compiler directly -- so RUSTFLAGS's
# remap never reaches them. Verified separately: with RUSTFLAGS's remap alone,
# 88 embedded paths remained, all under ring's own source tree.
# -ffile-prefix-map is clang/gcc's equivalent, covering both debug info and
# `__FILE__`-style macros.
export CFLAGS="-ffile-prefix-map=$CARGO_HOME_REAL=/build/cargo-home -ffile-prefix-map=$STAGE=/build/openimzo"
export CXXFLAGS="$CFLAGS"
export CPPFLAGS="$CFLAGS"

echo "==> building the Rust core"
"$STAGE/scripts/build-core.sh" release

DERIVED="${STAGE}-derived"
rm -rf "$DERIVED"

echo "==> building OpenImzo.app (Release, unsigned)"
# CODE_SIGNING_ALLOWED=NO/CODE_SIGN_IDENTITY=""/CODE_SIGNING_REQUIRED=NO
# together turn off the Xcode-driven codesign step entirely. They do not (and
# cannot) turn off the linker's own mandatory ad-hoc signature -- every arm64
# Mach-O executable needs at least one to run at all -- but that one is a
# hash of the binary's own content with no timestamp or identity in it
# (`codesign -dv` reports it as `adhoc,linker-signed`; ld64 does this by
# default via the `-reproducible` flag clang already passes it), so it is
# exactly as reproducible as the bytes underneath it and does not reopen the
# problem this script exists to close. It's removed outright below anyway,
# once stripping has invalidated it.
xcodebuild -project "$STAGE/macos/OpenImzo.xcodeproj" -scheme OpenImzo -configuration Release \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO \
  build

APP="$DERIVED/Build/Products/Release/OpenImzo.app"
EXE="$APP/Contents/MacOS/OpenImzo"

echo "==> stripping the local (debug-map) symbol table"
# Xcode strips this only for an *install*-style build (DEPLOYMENT_POSTPROCESSING),
# not a plain `build`; without it, the debug map (`nm -a`, entries of kind
# OSO) names $DERIVED -- and unlike $STAGE above, that path can't be pinned to
# a fixed literal without also dictating where every user's Xcode
# DerivedData lives. These entries exist so a debugger can find the original
# intermediate object files on the machine that produced them; they are not
# needed at runtime, and they are not what a crash gets symbolicated against
# -- the .dSYM Xcode generates alongside (matched to this binary by the
# LC_UUID, not by these paths) is. Verified: `strip -S` removes exactly the
# debug/local symbol table and leaves everything else -- including the
# exported symbols dynamic linking needs -- unchanged.
strip -S "$EXE"

echo "==> removing the linker's ad-hoc signature"
# strip changes the bytes the ad-hoc signature above was a hash of, which
# invalidates it -- it's still physically present as a stale, mismatched
# blob unless something removes it. `codesign --remove-signature` isn't
# signing anything (no identity, no keychain, no credential, nothing this
# project's release process ever has access to at this stage) -- it only
# deletes a signature that's already there, the direct inverse of the
# operation docs/verifying-a-release.md's Step 2 asks a verifier to run on
# the *signed* download. Doing it here too, rather than shipping a binary
# whose signature is merely broken, means both sides of that comparison go
# through the identical tool doing the identical thing, instead of asking
# `strip` and `codesign --remove-signature` to happen to agree.
codesign --remove-signature "$EXE"

echo "==> packaging"
ZIP="$OUT_DIR/OpenImzo-unsigned-macos.zip"
rm -f "$ZIP"
# A plain `zip -r` stores each entry's own mtime, and enumerates the directory
# in whatever order the filesystem happens to hand entries back in -- both of
# which are exactly the per-run variation this script exists to remove.
# zipfile.ZipFile gives explicit control over both: a fixed, sorted entry
# order and a fixed per-entry timestamp (derived from SOURCE_DATE_EPOCH, like
# everything else here) set directly on every entry, without regard to the
# real file's mtime -- so nothing upstream needs to touch the actual files on
# disk to get a deterministic zip. No per-machine extra fields (owner, ACLs,
# xattrs) either, since this writes each entry from scratch rather than
# shelling out to `zip`/`ditto`.
python3 - "$APP" "$ZIP" "$SOURCE_DATE_EPOCH" <<'PY'
import os
import stat
import sys
import zipfile

app_path, zip_path, source_date_epoch = sys.argv[1], sys.argv[2], int(sys.argv[3])
root = os.path.dirname(app_path)
date_time = __import__("time").gmtime(source_date_epoch)[:6]

entries = []
for dirpath, dirnames, filenames in os.walk(app_path):
    dirnames.sort()
    for name in sorted(filenames):
        entries.append(os.path.join(dirpath, name))
entries.sort()

with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for path in entries:
        arcname = os.path.relpath(path, root)
        st = os.lstat(path)
        info = zipfile.ZipInfo(arcname, date_time=date_time)
        info.compress_type = zipfile.ZIP_DEFLATED
        # Preserve only what changes behavior (executable bit) plus the
        # regular-file/symlink type bit; drop everything machine- or
        # user-specific (owner, group, ACL-derived extra bits).
        if stat.S_ISLNK(st.st_mode):
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, os.readlink(path))
            continue
        mode = 0o755 if (st.st_mode & stat.S_IXUSR) else 0o644
        info.external_attr = (stat.S_IFREG | mode) << 16
        with open(path, "rb") as f:
            zf.writestr(info, f.read())
PY

SHA="$(shasum -a 256 "$ZIP" | awk '{print $1}')"
echo "$SHA  $(basename "$ZIP")" > "$OUT_DIR/SHA256SUMS"
echo "==> done"
echo "    app:  $APP"
echo "    zip:  $ZIP"
echo "    sha256: $SHA"
echo
echo "This build is unsigned: its local symbol table was stripped and its"
echo "ad-hoc signature explicitly removed above. To run it locally on Apple"
echo "Silicon (which requires *some* signature to execute at all), sign it ad"
echo "hoc yourself first -- no Apple ID or certificate needed:"
echo "  codesign --force -s - \"$APP\""
