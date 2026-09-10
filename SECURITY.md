# Security Policy

OpenImzo reimplements a national cryptographic signing client — the local service that
Uzbek government websites call to sign documents with a person's digital signature. It runs a WebSocket/HTTP server bound to `127.0.0.1` that any web page a
user's browser visits can reach, by design, because that is how E-IMZO-integrated sites
talk to it. Findings in the signing path are the most valuable thing anyone can send us.

This is a one-person project with no company, no security team, and no paid support
behind it. What follows is what we can actually commit to, not a template.

## Reporting a vulnerability

Please use [GitHub's private security advisory
form](https://github.com/ganiyevuz/openimzo/security/advisories/new) on this
repository rather than a public issue, so a real vulnerability isn't disclosed before a
fix exists. If that form is ever unavailable to you, open a regular issue asking to be
pointed at another channel — don't put exploit details in it.

There is no bug bounty. Expect acknowledgement on a best-effort basis, not a
contractual SLA — realistically, days rather than hours. There are no tagged releases
yet; report against the current state of the `main` branch. Once releases exist, only
the most recent one is supported.

## Scope

**In scope:**
- The Rust core (`crates/`): GOST hashing and signing, PKCS#12/PKCS#7/PKCS#10/X.509
  handling, key discovery and file parsing, the RPC dispatch and origin/`apikey` checks.
- The macOS app (`macos/`): the local WebSocket/HTTP server, password and permission
  dialogs, keychain and TLS-trust handling, on-disk settings and key storage.
- Anything reachable by a website talking to `127.0.0.1:64646`/`64443` the way a real
  E-IMZO-integrated site would.

**Out of scope for now:** the hardware-token plugins (ID-card, BAIK, UZGUARD). They are
not implemented — every call into them answers with the same "no device" response the
original gives when no reader is attached — so there is no live code path there to
attack yet. Also out of scope: the original E-IMZO Java client itself. Its behaviour is
real and its defects are real, but this repository does not control or fix it.

**Where the reverse-engineering research lives.** OpenImzo's own source is entirely
public. The research that revealed how the original E-IMZO client behaves — and where
it has defects, including cryptographic ones — was done separately and stays in a
private repository. It is not published here on purpose: it documents exploitable
weaknesses in software that is currently mandatory for many people to run, and
publishing it would be a disclosure against the original client, not documentation of
this one. Nothing about OpenImzo's own security claims depends on that material staying
private — everything this project asks you to trust is in this repository, and you can
read all of it.

## The cryptography: what was done, and what it does not establish

The elliptic-curve signing path (`crates/eimzo-crypto/src/ec.rs`,
`crates/eimzo-crypto/src/gost3410.rs`) was rewritten from textbook variable-time
double-and-add over `num-bigint` to a fixed-iteration Montgomery ladder over
`crypto-bigint`'s constant-width arithmetic, specifically because the original approach
leaked the secret scalar's bit length and bit pattern through timing — and the two
values that pass through it, the private key and the per-signature nonce, are exactly
the two whose recovery from a handful of signatures breaks the scheme through ordinary
lattice cryptanalysis.

**What was measured, and what it shows.** A round-robin timing comparison across five
scalars of different bit length and Hamming weight found a 233,700× spread between the
fastest and slowest median before the rewrite, and a 1.00× spread after it. The pair
that carries the argument is two scalars of the *same* bit length and *different*
Hamming weight — 4914 µs vs. 9815 µs before, 222.8 µs vs. 222.7 µs after — because a
difference driven by length alone could hide a difference driven by weight underneath
it, and this pair rules that out.

**This is a demonstration, not a proof of constant-time execution**, and we are not
going to describe it as more than that. It is wall-clock timing on a busy
general-purpose machine, using five scalars, not a statistical test — no `dudect`, no
Welch's t-test over thousands of classes, no instruction-count measurement under a
simulator. Constant-time source is not constant-time machine code: the compiler is free
to lower a conditional select to a branch. The generated assembly was inspected on one
architecture (aarch64) with one toolchain, and it showed no conditional branches in the
field addition, the Montgomery reduction, or the ladder body, with the ladder's
conditional swaps compiling to bitwise selects rather than branches — that is a real
result, but it is one architecture and one compiler, not a guarantee across the ones we
haven't checked, and no microarchitectural side channel (cache timing, power, EM) has
been examined at all.

As a secondary effect, the constant-time version also turned out to be roughly 30×
faster than the code it replaced (signing: 7544 µs → 225 µs; verification: 14740 µs →
507 µs) — the old code paid a modular inversion at every step of affine arithmetic,
which the new projective-coordinate ladder avoids. That is not a security property, but
it does mean "constant-time" did not cost anything here; if anything it paid for itself.

**What is still variable-time, named rather than left implicit:**

- **The `BigUint → U256` conversion boundary.** The scalar reaches the ladder as a
  `BigUint`; the number of 64-bit limbs `num-bigint` hands over depends on the value,
  which leaks at roughly a 2⁻⁶⁴ rate for a uniformly drawn 256-bit scalar. Closing it
  fully means changing the type carried at the public API boundary, which cascades
  through several crates.
- **Verification is not on a separate, deliberately-fast backend — it inherits the
  same constant-time ladder as signing, because the rewrite left only one arithmetic
  path.** `gost3410::verify`'s two scalar multiplications (`c.base_mul(&z1)` and
  `c.mul(&z2, q)`) and the point addition that follows all run through the identical
  fixed-iteration Montgomery ladder and complete-addition formula signing uses — they
  didn't need to be constant-time, since they operate on public values, but there is
  no other implementation left for them to use. What genuinely remains variable-time
  in `verify` are three specific `num-bigint` operations building the values fed into
  that ladder: the modular inverse `e.modpow(&(n-2), &n)`, and the two multiplications
  computing `z1` and `z2`. All three operate only on public values — a signature, a
  hash, a peer's public key — which do not need constant-time handling, so this is by
  design and not an oversight.
- **`random_scalar`'s rejection loop leaks its own iteration count in signing
  latency**, observably so: on two of the four supported curves, roughly half of all
  draws are rejected and discarded, so the loop iterating twice on average (up to a
  bounded maximum) is the ordinary case, not a rare one. This is safe for a specific,
  checked reason, not because it's rare: a rejected candidate is statistically
  independent of the one eventually accepted, so the retry count carries no information
  about the nonce that gets used, and rejection sampling accepts uniformly over the
  valid range, so — unlike reducing a wide random value modulo the curve order — it
  introduces no bias for a lattice attack to exploit.
- **Everything below `crypto-bigint`** — the compiler and the CPU. See above: one
  architecture, one toolchain, no microarchitectural testing, no claim beyond what was
  actually checked.

**What cannot be zeroized, named rather than glossed over.** The live named
intermediates in the ladder — coordinates, the scalar's own fixed-width copy, the
per-signature nonce draw — are scrubbed on drop. Three things are not reachable by that
mechanism at all:
- compiler-generated copies of `crypto-bigint`'s `Copy` residue type, made implicitly
  by ordinary value-passing arithmetic, which have no name for `zeroize` to find;
- `num-bigint`'s own internal digit storage, which has no `zeroize` feature in the
  version (0.4) this workspace uses — confirmed by attempting to compile against one;
- the internal table of powers that modular inversion (`pow`) builds from a
  nonce-derived value.

**The private key itself (`PrivateKey::d`) is a `num-bigint` value and is deliberately
not zeroized on drop.** Changing that would change the type `PrivateKey` carries,
cascading through the crates above it. Buffers derived from it at the points where it
is actually serialized or exported — PKCS#8 encoding and the QR-key export path — are
scrubbed, and that scrubbing has been checked, not just written.

If any of the above is wrong, out of date, or you can defeat one of the properties it
claims, that is exactly the report we want.

**Secret-derived comparisons outside `ec.rs`.** Two checks elsewhere in `eimzo-pki`
compare a value derived from a user-supplied password against a value read from an
untrusted key file: the PKCS#12 integrity MAC (`pkcs12/pbe.rs`) and the YTKS-2
password-check digest (`ytks.rs`). Both use `subtle::ConstantTimeEq` rather than the
language's own `==`, so neither comparison can leak how many leading bytes matched
through its timing.

## Everything else

Ordinary vulnerability classes apply too and are welcome: parsing of untrusted
PKCS#12/X.509/CMS input, origin/`apikey` bypasses, TLS trust installation, local
privilege or sandbox issues, and anything that leaks or mishandles a password, PIN, or
private key outside the paths described above.
