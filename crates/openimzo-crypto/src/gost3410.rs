//! GOST R 34.10-2001 signing and verification with E-IMZO's own byte
//! conventions.

use crate::ec::{CurveParams, Point};
use crate::{CryptoError, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// How many candidates the two rejection loops below will draw before giving up.
///
/// `random_scalar` draws uniformly from 2²⁵⁶ and accepts only `[1, n-1]`, so its
/// rejection rate is `1 − (n−1)/2²⁵⁶` — and on half these curves that is not a
/// small number. Computed from the four orders in `ec.rs`:
///
/// | curve | n / 2²⁵⁶ | P(a draw is rejected) | mean draws | P(128 in a row) |
/// |-------|----------|-----------------------|------------|-----------------|
/// | A     | 1.0000   | 2⁻¹²⁸·⁸               | 1.00       | 2⁻¹⁶⁴⁸⁶         |
/// | B     | 0.5000   | 0.500                 | 2.00       | 2⁻¹²⁸           |
/// | C     | 0.6079   | 0.392                 | 1.65       | 2⁻¹⁷³           |
/// | Test  | 0.5000   | 0.500                 | 2.00       | 2⁻¹²⁸           |
///
/// B's and Test's orders sit just above 2²⁵⁵, so **about half of all draws are
/// rejected** there and the loop is the ordinary path — it runs twice per
/// signature on average — not the theoretical guard an earlier version of this
/// comment described, which claimed a "~2⁻³² per draw" rate that was wrong for
/// all four curves.
///
/// Why 128 rather than 64: at 64 the worst curve reaches the bound with
/// probability 2⁻⁶⁴ per call, which nobody alive would ever see, but 128 is free
/// — the bound is not a latency budget, and 128 iterations of a ~218 µs
/// operation is ~28 ms before erroring, which no person notices — and it puts
/// the spurious-failure rate at 2⁻¹²⁸, below anything worth discussing.
///
/// `sign_with_k`'s own rejection is the rare one: it refuses a nonce only when r
/// or s comes out zero, ~2⁻²⁵⁵.
///
/// What the bound is actually for is neither of those: a `CurveParams` whose p
/// or n is not an odd 256-bit prime, which nothing in this crate constructs but
/// which the struct's public fields do not forbid. Unbounded, such a curve spins
/// forever with a person waiting on a signature; bounded, it is an error.
const MAX_ATTEMPTS: usize = 128;

/// e = (hash as little-endian integer) mod n, with e == 0 replaced by 1.
pub fn hash_to_e(n: &BigUint, hash: &[u8; 32]) -> BigUint {
    let e = BigUint::from_bytes_le(hash) % n;
    if e.is_zero() {
        BigUint::one()
    } else {
        e
    }
}

/// Uniform scalar in [1, n-1] by rejection sampling from 32 random bytes.
/// Errors if `MAX_ATTEMPTS` candidates all fall outside the range.
///
/// How many draws it took is plainly visible in signing latency on three of the
/// four curves — see `MAX_ATTEMPTS` — and that is not a leak worth hiding. A
/// rejected candidate is statistically independent of the one finally accepted,
/// so the count carries no information about the nonce actually used; and
/// rejection sampling accepts uniformly over `[1, n-1]`, so unlike reducing a
/// wide draw modulo n it introduces no bias for a lattice attack to work with.
/// Those two properties are worth more than a constant iteration count would be.
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R, n: &BigUint) -> Result<BigUint> {
    for _ in 0..MAX_ATTEMPTS {
        // The draw is the nonce in the clear, and on B and Test about half of
        // them are discarded, so this runs twice per signature on average and up
        // to `MAX_ATTEMPTS` times. `Zeroizing` rather than a scrub at the end of
        // the iteration: it holds on every path out, including the `return` below
        // and any future one, instead of depending on the control flow staying
        // the shape it is today.
        let mut buf = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(buf.as_mut());
        let k = BigUint::from_bytes_be(buf.as_ref());
        if !k.is_zero() && &k < n {
            return Ok(k);
        }
    }
    Err(CryptoError::Unsupported("curve order admits no scalar in range".into()))
}

/// (r, s) for a given nonce k; None if r or s is zero (caller retries with a new k).
pub fn sign_with_k(c: &CurveParams, d: &BigUint, e: &BigUint, k: &BigUint) -> Option<(BigUint, BigUint)> {
    let point = c.base_mul(k)?;
    let r = point.x % &c.n;
    if r.is_zero() {
        return None;
    }
    let s = c.mul_add_mod_n(&r, d, k, e);
    if s.is_zero() {
        return None;
    }
    Some((r, s))
}

/// Errors if `MAX_ATTEMPTS` nonces all fail to produce a signature.
pub fn sign<R: RngCore + CryptoRng>(c: &CurveParams, d: &BigUint, hash: &[u8; 32], rng: &mut R) -> Result<[u8; 64]> {
    let e = hash_to_e(&c.n, hash);
    for _ in 0..MAX_ATTEMPTS {
        let k = random_scalar(rng, &c.n)?;
        if let Some((r, s)) = sign_with_k(c, d, &e, &k) {
            return Ok(encode_signature(&s, &r));
        }
    }
    Err(CryptoError::Unsupported("curve parameters admit no signature".into()))
}

fn write_be32(dst: &mut [u8], v: &BigUint) {
    let bytes = v.to_bytes_be();
    assert!(bytes.len() <= 32, "value does not fit in 32 bytes");
    for b in dst.iter_mut() {
        *b = 0;
    }
    dst[32 - bytes.len()..].copy_from_slice(&bytes);
}

/// 64 bytes = s (32, big-endian) || r (32, big-endian).
pub fn encode_signature(s: &BigUint, r: &BigUint) -> [u8; 64] {
    let mut out = [0u8; 64];
    write_be32(&mut out[..32], s);
    write_be32(&mut out[32..], r);
    out
}

/// Returns (s, r). Extra trailing bytes are ignored, shorter input is rejected (as the original).
pub fn decode_signature(sig: &[u8]) -> Option<(BigUint, BigUint)> {
    if sig.len() < 64 {
        return None;
    }
    Some((BigUint::from_bytes_be(&sig[..32]), BigUint::from_bytes_be(&sig[32..64])))
}

pub fn verify(c: &CurveParams, q: &Point, hash: &[u8; 32], sig: &[u8]) -> bool {
    let Some((s, r)) = decode_signature(sig) else {
        return false;
    };
    if r.is_zero() || s.is_zero() || r >= c.n || s >= c.n {
        return false;
    }
    if !c.is_on_curve(q) {
        return false;
    }
    let e = hash_to_e(&c.n, hash);
    let v = e.modpow(&(&c.n - 2u32), &c.n);
    let z1 = (&s * &v) % &c.n;
    let z2 = (&c.n - (&r * &v) % &c.n) % &c.n;
    let p1 = c.base_mul(&z1);
    let p2 = c.mul(&z2, q);
    match c.add(p1.as_ref(), p2.as_ref()) {
        Some(cp) => cp.x % &c.n == r,
        None => false,
    }
}

pub fn public_from_private(c: &CurveParams, d: &BigUint) -> Option<Point> {
    c.base_mul(d)
}
