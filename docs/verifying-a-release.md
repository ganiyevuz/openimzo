# Verifying a release

This is for someone who does not want to take our word for it: you downloaded an
OpenImzo build, and you want to know whether the bytes you got actually came from the
source in this repository, rather than from something a compromised build machine, a
tampered download, or a dishonest maintainer slipped in instead.

The short version: rebuild the unsigned artifact from source yourself and compare its
hash to the one we publish. That comparison is the actual security property; everything
else on this page is either how to also check the signed convenience download, or how
to not fool yourself about what a match or a mismatch means.

## What we publish, and why there are two of them

Every release attaches two `.zip` files of the same app:

- **`OpenImzo-unsigned-macos.zip`** — built by [`scripts/reproducible-build.sh`](../scripts/reproducible-build.sh)
  and nothing else. Not code-signed with any identity, not notarized. Anyone can produce
  a byte-for-byte identical copy of this one from source, and that's the whole point of
  it: it exists to be checked, not to be comfortable to run.
- **`OpenImzo-signed-macos.zip`** — the convenience download. Signed with the
  maintainer's Apple Developer ID and notarized by Apple, so Gatekeeper doesn't
  interrogate you on first launch. This is almost certainly the one you actually want to
  run day to day.

**These two files can never be byte-identical, and that is not a bug to be fixed.**
Signing a macOS app embeds a cryptographic signature into the executable itself, and
notarization adds a trusted timestamp from Apple's own timestamp authority — a value
that depends on the literal moment the signing happened, which no engineering effort
can make match a different moment. Any project claiming its signed release hashes the
same as its unsigned one either isn't really notarizing it or is measuring the wrong
thing. What we claim instead is narrower and actually checkable: the *code* inside the
signed download — everything except the signature itself — is exactly the code in the
unsigned download, which is exactly what building from source at this commit produces.

## Step 1: rebuild the unsigned artifact and compare

This is the check that matters most, and the one we can tell you to run with full
confidence, because it's the same command our own CI runs to produce the release in the
first place — see [`.github/workflows/release.yml`](../.github/workflows/release.yml).

Requirements: a Mac, and the exact toolchain versions this project pins —
[`rust-toolchain.toml`](../rust-toolchain.toml) and [`.xcode-version`](../.xcode-version).
The two aren't enforced the same way: `rustup` reads `rust-toolchain.toml` on its own and
installs the pinned Rust compiler automatically the moment you build, with no action on
your part. Xcode doesn't auto-switch versions, so `scripts/reproducible-build.sh` checks
`.xcode-version` itself, before doing anything else — it won't silently build with
whatever `xcode-select` currently points at, it aborts if that doesn't match. You still
have to install and select the right Xcode yourself; the script just refuses to guess.
Using the wrong version of either is the single most likely reason for a mismatch that
has nothing to do with tampering; see
[What a mismatch means](#what-a-mismatch-does-and-does-not-mean) below before assuming
the worst.

```sh
git clone https://github.com/ganiyevuz/openimzo
cd openimzo
git checkout <the tag or commit the release names>
scripts/reproducible-build.sh
```

Expect this to take several minutes and use a couple of gigabytes of disk, not seconds:
it stages a fresh copy of the checkout and compiles the whole Rust workspace -- including
a full TLS and HTTP stack (`rustls`, `ring`, `hyper`, `reqwest`) -- from a cold `target/`
for both architectures, every single time, by design (see the staging note below for
why). A quiet terminal for a while is normal, not a hang.

Run one of these at a time per machine, not several at once: the script stages the
checkout at a fixed path on purpose (that's what defeats the linker's own path-leaking
debug-map entries, mentioned above), and a fixed path is something two builds running
concurrently on the same machine can only collide on, not share safely — the script
detects this itself and refuses to proceed rather than silently corrupting either build,
telling you whether another build is genuinely still running or just left something
behind.

This prints a `sha256:` line and writes it to `dist/SHA256SUMS`. Compare it against the
`SHA256SUMS` file attached to the GitHub release, or against the hash printed in the
release's own GitHub Actions run (also attached there as a signed build-provenance
attestation — see [Provenance](#provenance-the-build-log-and-the-attestation) below).
They should match exactly.

If you'd rather not clone and build the whole thing just to check one number, you can
instead just download `OpenImzo-unsigned-macos.zip` from the release and hash it
yourself:

```sh
shasum -a 256 OpenImzo-unsigned-macos.zip
```

— but doing that only tells you the file matches what GitHub is currently serving. It
does not tell you that what GitHub is serving actually came from this source, which is
the thing rebuilding it yourself establishes. A hash comparison against a number that
came from the same place as the file it's checking proves nothing; treat the "just
compare the published hash" version as a sanity check, not the real verification.

## Step 2: checking the signed download against the unsigned one

Signing rewrites exactly one file in the bundle — `Contents/MacOS/OpenImzo`, the main
executable — by appending a signature block and updating a couple of size fields in its
Mach-O load commands to point at it. It does not rewrite anything else. Our release
process is built to make this checkable rather than asserted: the signed `.zip` is
produced by taking the exact `.app` that `scripts/reproducible-build.sh` already built
and hashed for the unsigned release, and running `codesign`/notarization over it —
nothing is recompiled, relinked, or rebuilt for the signed copy. So:

**Every file in the bundle except the main executable should be byte-identical between
the two downloads.**

```sh
unzip -q OpenImzo-unsigned-macos.zip -d unsigned
unzip -q OpenImzo-signed-macos.zip -d signed
diff -r --exclude=OpenImzo --exclude=_CodeSignature \
  unsigned/OpenImzo.app/Contents signed/OpenImzo.app/Contents
```

A clean `diff` (no output) confirms the Info.plist, resources, and localized strings in
the download you're about to run are exactly what the public, rebuildable source
produces — not a resource silently swapped in only for the signed build. (At low
confidence, and not yet checked: notarization stapling may write ticket data somewhere
in the bundle other than `_CodeSignature/`. If a real signed release ever shows a `diff`
here that isn't in `_CodeSignature/`, check whether that's the cause before treating it
as a mismatch — this exclude list may need to grow.)

**For the executable itself**, the signature makes a literal `diff` fail even when
nothing meaningful differs, so compare with the tool that understands the difference —
applied to **both** sides, not just the signed one:

```sh
codesign --remove-signature unsigned/OpenImzo.app/Contents/MacOS/OpenImzo
codesign --remove-signature signed/OpenImzo.app/Contents/MacOS/OpenImzo
diff unsigned/OpenImzo.app/Contents/MacOS/OpenImzo \
     signed/OpenImzo.app/Contents/MacOS/OpenImzo
```

Symmetrically, on purpose: `scripts/reproducible-build.sh` already runs
`codesign --remove-signature` on the unsigned executable as its last build step (arm64
code needs *some* signature to run at all, so the linker embeds a minimal one
automatically, and stripping the local symbol table just before invalidates it — the
script removes that stale signature outright rather than shipping a binary carrying a
broken one). The first `codesign --remove-signature` above should therefore find nothing
left to remove and be a no-op; it's there so this instruction still works even against
an unsigned build produced by an earlier version of the script. The point of running the
same command on both is not trusting `strip` and `codesign --remove-signature` to happen
to agree on what "the code without a signature" looks like — nothing has established
that they do — but instead putting both executables through the literal same operation
and diffing what comes out. A clean `diff` afterward means the executable's actual code
is identical, and the only thing signing added was the signature itself.

**Caveat, stated plainly:** as of this writing no signed release has shipped yet, so we
have not run this exact round trip ourselves end to end — doing so needs a real Apple
Developer ID signing an actual build, which is a separate, credentialed step from
everything `scripts/reproducible-build.sh` does, and this document is deliberately
scoped to what we've actually executed. We will run it before the first tagged release
and update this paragraph with the result. If you run it first and it doesn't come out
clean, try the symmetric form above before concluding something is wrong — but if it
still doesn't come out clean, please open a private security advisory (see
[`SECURITY.md`](../SECURITY.md)) rather than assuming the documentation is merely wrong
— that specific mismatch is exactly the scenario this whole page exists to catch.

## What a match does, and does not, prove

A match means: the code in the release you downloaded is the code you get from
compiling the source in this repository at the commit the release names, using the
toolchain versions this repository pins. That's a real, meaningful thing — it rules out
a tampered download, a compromised build server shipping different code than the public
source, or a maintainer quietly distributing something other than what's in the git
history.

It does **not** mean the source itself is safe. Reproducible builds verify that the
binary matches the source; they say nothing about whether the source has bugs,
intentional or not. That's what reading the code — and, for the cryptography
specifically, [`SECURITY.md`](../SECURITY.md)'s account of what is and isn't
constant-time — is for. A reproducible build of a backdoored program reproduces the
backdoor faithfully.

It also rests on one thing you're trusting by using this document at all: that
`rust-toolchain.toml`, `.xcode-version`, and `scripts/reproducible-build.sh` themselves
haven't been tampered with in a way that makes a compromised build look clean. Comparing
the running release against a build from a git checkout you fetched independently — not
from a copy the release itself pointed you at — is what actually closes that gap.

## What a mismatch does, and does not, mean

A mismatch is not automatically evidence of tampering. In order of likelihood, actually
check first:

1. **A different Rust or Xcode version.** `scripts/reproducible-build.sh` checks
   `.xcode-version` against `xcodebuild -version` itself and refuses to build at all on a
   mismatch, so this specific case shouldn't reach the point of producing a wrong hash
   silently — if you got a hash instead of that error, your Xcode already matched. Rust
   is worth a second look anyway: `rustc --version` should match `rust-toolchain.toml`'s
   pinned channel exactly, though `rustup` installs the pinned toolchain automatically
   the first time you build in the checkout, so this one is unlikely to be wrong unless
   something unusual overrode it (a `RUSTUP_TOOLCHAIN` environment variable, for
   instance).
2. **You built from the wrong commit.** Double-check `git rev-parse HEAD` against the
   commit the release names — a release built from a tag doesn't necessarily match the
   tip of `main` today. This one is worth understanding, not just checking: the expected
   hash is per-*commit*, not per-project. `scripts/reproducible-build.sh` derives
   `SOURCE_DATE_EPOCH` from the commit being built (`git log -1 --format=%ct`), and that
   value ends up in the packaged zip's own timestamps — so even an otherwise-identical
   source tree checked out at a different commit produces a different hash, with nothing
   wrong and nothing to explain beyond "wrong commit." Don't read a mismatch here as
   evidence of anything until you've confirmed both sides built the exact same commit.
3. **Local environment leaking in anyway.** `scripts/reproducible-build.sh` pins what we
   found and verified actually varies (see the script's own comments for what and why);
   if your environment has something unusual we didn't test against, say so in an issue
   — a mismatch we can't explain either way is exactly the kind of report this process
   is supposed to make possible, not something to quietly work around.

If you've ruled out the above and it still doesn't match, that's a real finding — please
report it as a security issue (see [`SECURITY.md`](../SECURITY.md)) rather than a bug,
even if you're not sure yet whether it's malicious. It's the scenario this entire
mechanism exists to surface.

## Provenance: the build log and the attestation

Every release is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
on GitHub-hosted infrastructure, not on a maintainer's own machine, and the full build
log — every command that ran, in order, with nothing hidden — is public on the repository's
Actions tab for that run. Reading it is itself a form of verification: it's the same
`scripts/reproducible-build.sh` this page tells you to run yourself, so the log should
look exactly like your own terminal output, modulo the paths.

The workflow also attaches a [build provenance
attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
to the unsigned artifact — a signed statement, backed by GitHub's own OIDC identity for
the workflow run, of exactly which workflow, commit, and repository produced it. You can
check it without trusting anything we say about the release at all:

```sh
gh attestation verify OpenImzo-unsigned-macos.zip --repo ganiyevuz/openimzo
```

This tells you the artifact was built by *a* run of the named workflow at the named
repository — it's a statement about where the bytes came from, not a substitute for
Step 1. Rebuilding it yourself is what tells you the workflow actually did what it
claims to.
