# Third-party dependency licenses

OpenImzo is licensed GPL-3.0-or-later (see [`LICENSE`](LICENSE)). That choice means
every dependency actually compiled into the workspace has to be license-compatible with
it — a GPL-3.0 project can't ship with an incompatible dependency baked in, however
useful that dependency is. This document is that check, made available for anyone to
re-run rather than taken on faith.

## Method

Run against `cargo metadata --all-features`, across the whole workspace, so it includes
every crate actually reachable in the dependency graph rather than only direct
dependencies, then filtered down to exclude this workspace's own seven crates (they are
us, not a third party, and of course declare `GPL-3.0-or-later`). Every remaining
package in the graph declares an SPDX license expression in its own metadata; none is
missing a license or file-only.

You can reproduce it yourself, from the repository root:

```sh
cargo metadata --all-features --format-version 1 | python3 -c "
import json, sys, collections
d = json.load(sys.stdin)
ours = set(d['workspace_members'])
pkgs = [p for p in d['packages'] if p['id'] not in ours]
print('third-party packages:', len(pkgs))
c = collections.Counter(p['license'] or '(missing)' for p in pkgs)
for lic, n in c.most_common():
    print(f'{n:>4}  {lic}')
"
```

Re-run this whenever `Cargo.lock` changes meaningfully — a new dependency, a major
version bump of an existing one — and always before ever changing the project's own
license away from GPL-3.0. The table below is that command's actual output, not a
hand-copied summary of it; if you run it against the `Cargo.lock` committed alongside
this file, you should get the same numbers.

## Result (audited 2026-09-10, against this commit's `Cargo.lock`): clear for GPL-3.0

310 third-party packages in the resolved dependency graph:

| count | license |
|---|---|
| 167 | MIT OR Apache-2.0 |
| 52 | MIT |
| 30 | Apache-2.0 OR MIT |
| 18 | Unicode-3.0 |
| 10 | MIT/Apache-2.0 |
| 9 | MPL-2.0 |
| 4 | Apache-2.0 OR ISC OR MIT |
| 2 each | Unlicense OR MIT · Apache-2.0 · MIT OR Apache-2.0 OR Zlib · ISC · BSD-2-Clause OR Apache-2.0 OR MIT |
| 1 each | Apache-2.0 / MIT · MIT OR BSD-3-Clause · MIT AND BSD-3-Clause · MIT OR Apache-2.0 OR LGPL-2.1-or-later · Apache-2.0 AND ISC · Apache-2.0 OR BSL-1.0 · BSD-3-Clause · Zlib OR Apache-2.0 OR MIT · (MIT OR Apache-2.0) AND Unicode-3.0 · Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |

**Nothing here blocks GPL-3.0.** MIT, ISC, BSD-2-Clause, BSD-3-Clause, Zlib, Unlicense,
BSL-1.0 and Unicode-3.0 are all permissive and GPL-compatible outright, including in the
two combined forms above (an `AND` of two permissive licenses, and the Apache-2.0/LLVM
exception variant). MPL-2.0 carries its own secondary-license clause that makes it
explicitly GPL-compatible. The single package offering `LGPL-2.1-or-later` (`r-efi`,
pulled in transitively) only as one arm of an `OR` with MIT and Apache-2.0 is used under
MIT.

**The one result worth calling out, because the license choice above is exactly what
makes it come out clean.** Apache-2.0 is compatible with GPL**v3** and is *not*
compatible with GPLv2 — its patent-retaliation and indemnification clauses are an
additional restriction that GPLv2's own terms forbid. 224 of the 310 third-party
packages here — more than two-thirds — are Apache-2.0, or offer it as one arm of a
choice. Had this project's license been GPL-2.0 instead of GPL-3.0, most of this
dependency tree would have been unusable outright, and this audit would have come out
very differently. **If anyone ever "simplifies" the project's license — including
downgrading to GPL-2.0 — this audit needs to be redone from scratch, because the
GPL-3.0 choice is the reason it passes.**

## What this is not

This is a **mechanical scan of declared SPDX metadata**, not a legal review. It checks
what each crate's own `Cargo.toml` claims its license is; it does not check that a
crate's actual `LICENSE` file, in the copy of the source actually compiled, matches
what its metadata declares. For a project whose entire pitch is that people can verify
it, that gap is worth naming rather than quietly relying on: a real legal review before
treating this as a compliance guarantee is proportionate, and hasn't been done.

## Scope

This covers the Rust workspace (`crates/`) only. The macOS app (`macos/`) has no
external dependencies of its own beyond Apple's system frameworks and the Swift
bindings UniFFI generates from this same workspace at build time — there is nothing
further to audit there.
