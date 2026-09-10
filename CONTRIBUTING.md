# Contributing

OpenImzo is maintained by one person, in their spare time. There's no team behind it,
so review and merges happen when they happen — please don't read silence as
disinterest.

## Before you start

For anything beyond a small fix, open an issue first describing what you want to change
and why. This project's whole point is that a stranger can read it and trust it, so
changes that touch behaviour a website depends on, or the cryptography, get read
carefully; talking about the approach before writing the code saves both of us time.

Found a security vulnerability rather than a bug? Don't open an issue or PR for it — see
[`SECURITY.md`](SECURITY.md).

## Building and running your change

See [`README.md`](README.md#building). There is no separate development setup beyond
that.

## How changes are verified

This project has no unit test suite, by design — it is a client for a fixed external
protocol, and its own power-on self-test, a clean build, and behavioural cross-checks
against the original client's own libraries (`tools/java-harness`) are what a change is
actually verified against. Before opening a pull request:

- `cargo clippy --workspace --all-targets -- -D warnings` must be clean. Do not run
  `cargo fmt` — this workspace is hand-formatted and carries no rustfmt config on
  purpose; match the style already around the code you're touching.
- The Swift app must produce a **clean** build (not an incremental one — those replay
  cached results and can hide new warnings) with zero warnings.
- If you touch any user-visible string in the macOS app, run
  `python3 scripts/check-localization.py`; it fails on a string missing a catalogue
  entry or a catalogue entry missing a translation.
- If your change affects the RPC protocol surface, describe in the PR how you confirmed
  behaviour still matches the original client (`tools/java-harness` is the tool for
  this), not just that it compiles.

## Changes to the cryptography

`crates/eimzo-crypto/` gets more scrutiny than the rest of the tree, not less. If your
change touches `ec.rs` or `gost3410.rs`, say explicitly in the PR description what
stays constant-time and what doesn't, and read [`SECURITY.md`](SECURITY.md) first —
it names the properties the current code claims and the ones it explicitly does not, and
a change that quietly narrows either without saying so is the kind of thing this project
exists to avoid.

## License

By contributing, you agree your contribution is licensed under GPL-3.0-or-later, the
same license as the rest of the project (see [`LICENSE`](LICENSE)). If your change adds
a new dependency, check [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) first —
not every permissive license is automatically fine here (see that file's note on
Apache-2.0 and why the project's own license choice matters to that answer).
