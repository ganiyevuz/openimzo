#!/usr/bin/env bash
# Builds the drag-to-Applications disk image a person downloads.
#
# The window is laid out deliberately: the app on the left, an Applications
# alias on the right, and nothing else visible -- the background, the icon
# positions and the window size are all set here rather than left to whatever
# the Finder happens to remember, so the image looks the same on a machine that
# has never seen it before.
set -euo pipefail

cd "$(dirname "$0")/.."
APP="${1:-}"
if [ -z "$APP" ] || [ ! -d "$APP" ]; then
  echo "usage: scripts/make-dmg.sh /path/to/OpenImzo.app [output.dmg]" >&2
  exit 2
fi

# A plain `xcodebuild build` produces a binary for the machine that ran it and
# says nothing about it, so an Intel Mac downloading the image would simply be
# told the app is damaged. Build releases with:
#
#   xcodebuild ... -destination 'generic/platform=macOS' \
#     ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO
#
# and this refuses anything else, rather than trusting that whoever ran the
# build remembered. Checked, not asserted.
BIN="$APP/Contents/MacOS/OpenImzo"
for arch in arm64 x86_64; do
  if ! lipo -archs "$BIN" | tr ' ' '\n' | grep -qx "$arch"; then
    echo "refusing: $BIN has no $arch slice (found: $(lipo -archs "$BIN"))." >&2
    echo "a release image must run on both Apple Silicon and Intel." >&2
    exit 1
  fi
done

OUT="${2:-dist/OpenImzo.dmg}"
mkdir -p "$(dirname "$OUT")"
NAME="OpenImzo"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "${OUT%.dmg}.rw.dmg"' EXIT

cp -R "$APP" "$STAGE/$NAME.app"
ln -s /Applications "$STAGE/Applications"

# The window's own background: product name, an arrow between where the two
# icons land, and the drag instruction in all three languages the app speaks.
# `brand/dmg-background.tiff` carries a 1x and a 2x representation in one file,
# which is the only way the Finder draws it sharp on a Retina display -- see
# scripts/make-dmg-background.swift, which draws it. A leading dot keeps the
# folder out of the window it is decorating.
BACKGROUND="brand/dmg-background.tiff"
if [ ! -f "$BACKGROUND" ]; then
  echo "refusing: $BACKGROUND is missing; run scripts/make-dmg-background.swift" >&2
  exit 1
fi
mkdir -p "$STAGE/.background"
cp "$BACKGROUND" "$STAGE/.background/background.tiff"

# A writable image first: the Finder cannot arrange icons inside a read-only
# one, and the arrangement is the whole point of a drag-to-install window.
SIZE=$(( $(du -sm "$STAGE" | cut -f1) + 40 ))
rm -f "${OUT%.dmg}.rw.dmg"
hdiutil create -srcfolder "$STAGE" -volname "$NAME" -fs HFS+ \
  -format UDRW -size "${SIZE}m" "${OUT%.dmg}.rw.dmg" >/dev/null

DEV=$(hdiutil attach -readwrite -noverify -noautoopen "${OUT%.dmg}.rw.dmg" \
      | grep -E '^/dev/' | head -1 | awk '{print $1}')
MOUNT="/Volumes/$NAME"
sleep 1

osascript <<APPLESCRIPT >/dev/null
tell application "Finder"
  tell disk "$NAME"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set the bounds of container window to {200, 160, 800, 560}
    set opts to the icon view options of container window
    set arrangement of opts to not arranged
    set icon size of opts to 128
    -- Addressed through the whole path expression rather than through the opts
    -- variable: setting background picture on that variable is the incantation
    -- every guide gives, and it fails on this macOS with -10006, because opts
    -- holds a value here, not a reference to set a property on. Naming the
    -- option in full works, confirmed by reading backgroundImageAlias back out
    -- of the volume's own .DS_Store afterwards.
    -- (No backticks anywhere in this heredoc: it is unquoted, so the shell
    -- would run whatever they contained before AppleScript ever saw it.)
    set background picture of the icon view options of container window to file ".background:background.tiff"
    -- Labels under the icons rather than beside them, so the two names sit in
    -- the gap the background leaves for them.
    set label position of opts to bottom
    set position of item "$NAME.app" of container window to {150, 190}
    set position of item "Applications" of container window to {450, 190}
    close
    open
    update without registering applications
    delay 2
  end tell
end tell
APPLESCRIPT

chmod -Rf go-w "$MOUNT" || true
sync
hdiutil detach "$DEV" >/dev/null

rm -f "$OUT"
hdiutil convert "${OUT%.dmg}.rw.dmg" -format UDZO -imagekey zlib-level=9 -o "$OUT" >/dev/null

echo "==> $OUT"
shasum -a 256 "$OUT" | awk '{print "    sha256: "$1}'
