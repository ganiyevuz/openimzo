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
OUT="${2:-dist/OpenImzo.dmg}"
mkdir -p "$(dirname "$OUT")"
NAME="OpenImzo"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "${OUT%.dmg}.rw.dmg"' EXIT

cp -R "$APP" "$STAGE/$NAME.app"
ln -s /Applications "$STAGE/Applications"

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
