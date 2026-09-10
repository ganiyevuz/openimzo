# Brand assets

The mark, and everything derived from it. Nothing here ships inside the app —
these are the sources the shipped files were generated from, kept so the icon
can be regenerated rather than reverse-engineered from a 1024px PNG.

| File | What it is |
|---|---|
| `logo.png` | The master, as supplied. 1254×1254, **no alpha channel** — the transparency checkerboard is painted into the pixels. |
| `logo-flattened.png` | `logo.png` with that checkerboard removed: transparency flood-filled in from all four corners, then trimmed to the blue square (1112×1118). |

## Derived, and committed where they are used

- `macos/OpenImzo/Resources/AppIcon.icns` — `logo-flattened.png` resized to
  824×824 and centred on a 1024×1024 canvas, which is the proportion Apple's
  macOS icon grid expects, then rendered at each of the ten iconset sizes
  individually (not scaled down from one master, so 16pt and 32pt stay
  legible) and assembled with `iconutil -c icns`.
- `crates/openimzo-server/resources/html/openimzo-logo.png` — the same
  flattened mark at web size, embedded in the server binary and served on
  the two local pages.

The checkerboard is the trap worth remembering: pasted straight in, `logo.png`
gives an app icon with grey checkered corners on every Mac, and it looks
correct in any preview that draws its own checkerboard behind transparency.
