# OpenImzo

OpenImzo is an independent, from-scratch, open-source macOS client for E-IMZO — the
local signing service Uzbek government websites require in order to sign documents with
a person's national digital-signature key. It listens on the same local
ports and speaks the same WebSocket/JSON protocol as the original Java/Swing client, so
existing sites work against it unchanged, while being a native app whose entire source
you can read, build, and check yourself.

**OpenImzo is not affiliated with, endorsed by, or supported by the operators of
E-IMZO, or by any government agency.** It was built by observing the original client's
on-the-wire and on-disk behaviour from the outside, not by any relationship with its
authors. The name sits close to the original's on purpose — a compatible client only
matters if sites can't tell it apart — but closeness in name is not endorsement, and the
GPL-3.0 license this project ships under grants no trademark rights over it.

## What works

- The local protocol every E-IMZO-integrated site depends on: the WebSocket RPC surface
  and static HTTP pages on `127.0.0.1`, request/response shapes, status codes and reason
  text matching the original.
- File-backed keys: PKCS#12 (`.pfx`) and the YTKS-2 container, with the same key
  discovery rules the original uses across mounted volumes and user-added folders.
- GOST R 34.10-2001 signing and verification on the CryptoPro A/B/C curves under the
  Uzbek OIDs, and GOST R 34.11-94 hashing.
- PKCS#7/CMS signing, PKCS#10 certificate requests, X.509 handling, and the `apikey`
  origin-verification flow sites use to authorize themselves.
- A native macOS menu-bar app in place of the original's Java/Swing tray app: a
  management window, password and permission dialogs, and settings.

## What doesn't work yet

**Hardware tokens — ID-card, BAIK, UZGUARD — are not implemented.** The RPC functions
for them exist and answer the same way the original does when no reader or driver is
present, so a site that merely checks for their availability won't break, but there is
currently no way to actually sign with a hardware token. This is planned for a future
release, not abandoned.

## What will never come back

The original E-IMZO bundles an L3VPN client, a "gateway mode" for relaying signing
requests over a network, and a remote ID-card emulator with its own binary protocol.
None of these are part of OpenImzo, and none are planned — they are deliberately
dropped, not merely delayed. Legacy alg-1 (1024-bit) key generation and signing is
dropped the same way; parsing certificates that already carry an alg-1 signature is
kept, for display only.

## Building

Requirements: a Rust toolchain (the exact channel is pinned in `rust-toolchain.toml`;
`rustup` will pick it up automatically) and Xcode targeting macOS 14 or later.
`xcodegen` is only needed if you intend to change `macos/project.yml` yourself — the
`.xcodeproj` it generates is committed, so building from a clean checkout does not
require installing it.

```sh
git clone https://github.com/ganiyevuz/openimzo
cd openimzo
open macos/OpenImzo.xcodeproj
```

Build/run the `OpenImzo` scheme, or from the command line:

```sh
xcodebuild -project macos/OpenImzo.xcodeproj -scheme OpenImzo -configuration Release build
```

There is no separate setup step: a "Build the Rust core" phase runs `scripts/build-core.sh`
before every build, so the first build compiles the Rust workspace and regenerates
`macos/openimzoFFI.framework` and `macos/Generated/openimzo.swift` on its own. You can run
`scripts/build-core.sh release` directly too — the same script, useful outside Xcode (CI,
or checking a release build's provenance) — but nothing about a normal build depends on
having run it first.

## Verifying a release you downloaded

No prebuilt release exists yet. When one is published, the steps for checking a
downloaded build against the source it claims to come from — what to download, what to
run, what to compare, and what a mismatch means — will live at
[`docs/verifying-a-release.md`](docs/verifying-a-release.md).

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE) for the full text. Every third-party Rust
dependency's declared license is inventoried in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

## Security

This project reimplements a national cryptographic signing client. See
[`SECURITY.md`](SECURITY.md) for how to report a vulnerability, what is in scope, and
an honest account of what the cryptography does and does not currently guarantee.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
