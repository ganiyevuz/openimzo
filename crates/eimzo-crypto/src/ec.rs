//! Short Weierstrass curves y² = x³ + ax + b over GF(p).
//! Curves A, B, C are the GOST R 34.10-2001 CryptoPro parameter sets.
//! `Test` is the RFC 7091 test curve, used only by the self-test.
//!
//! # Timing
//!
//! `mul` carries secret scalars — the per-signature nonce and the private key
//! (`gost3410.rs`) — so it is written not to let them show through its running
//! time. Three things make that work, and each replaced something that did not:
//!
//! - Field elements are a fixed 256 bits (`crypto_bigint::U256` in Montgomery
//!   form), not `num_bigint::BigUint`, whose operations short-circuit on value
//!   and so differ by operand. Every curve here is 256-bit, so the fixed width
//!   costs nothing.
//! - Point arithmetic uses the complete addition formula of Renes, Costello and
//!   Batina (2015), which is correct for every input pair with no exceptional
//!   case, so nothing has to be decided at run time — not "is this a doubling",
//!   not "is either side the point at infinity".
//! - The scalar loop is a Montgomery ladder over a *fixed* 256 iterations, and
//!   picks between its two running points with a constant-time conditional swap
//!   rather than a branch. Both bits do the same two additions in the same
//!   order, so neither the scalar's length nor its bit pattern is traced out.
//!
//! What this does **not** claim. It is not a proof of constant-time execution,
//! and two things in particular are known to fall short of one:
//!
//! - The scalar arrives as a `BigUint`, whose limb count is the number of
//!   *non-zero-leading* 64-bit digits. `to_u256` always writes all four digits,
//!   so only `num-bigint`'s own iterator length varies with the value; for a
//!   scalar drawn uniformly below a 256-bit order that is four digits with
//!   probability 1 − 2⁻⁶⁴. Removing even that would mean changing the type the
//!   public API carries.
//! - Below `crypto-bigint` sits the compiler and the CPU. Constant-time
//!   intent in source is not the same as constant-time machine code. An
//!   assembly inspection of the field addition, the Montgomery reduction and
//!   the ladder body found no conditional branches; that is not the same as a
//!   microarchitectural audit, and none has been done.
//!
//! # Secret material left in memory
//!
//! The ladder's running points are worse to leave behind than the scalar is.
//! Each intermediate is m·P for a *prefix* of the scalar, so the sequence of
//! them encodes the scalar bit by bit.
//!
//! The fixed-width rewrite improved this rather than costing anything. The affine
//! `num-bigint` implementation it replaced produced roughly 383 of those
//! intermediates per scalar multiplication as *heap* allocations — two `BigUint`
//! coordinates per step, plus the `modpow` temporaries of the modular inversion
//! every step performed — and freed every one without scrubbing, where it stayed
//! until the allocator happened to reuse the block. The ladder keeps more
//! intermediates but in a reused stack frame, and they can be named, so they can
//! be scrubbed.
//!
//! What is scrubbed, with `zeroize`'s volatile writes, is everything this module
//! can name: both ladder points and the scalar's fixed-width copy at the end of
//! `mul`, the inverse of Z in `to_affine`, the operand residues in
//! `mul_add_mod_n_ct` (two of which are the private key and the nonce), and the
//! byte buffer `to_u256` builds.
//!
//! What cannot be reached, and so is not claimed:
//!
//! - **Copies the compiler made.** `DynResidue` is `Copy`; each of the 512
//!   complete additions per scalar multiplication takes its operands by value,
//!   returns by value and names ten temporaries internally. Those are unnamed
//!   at this level, and LLVM may additionally keep them in registers or spill
//!   them to further stack slots. `zeroize` clears the memory it is handed, not
//!   duplicates of it.
//! - **The scalar's own `BigUint`.** The nonce reaches `mul` as a
//!   `num_bigint::BigUint`, which owns its digit storage and exposes no in-place
//!   scrubbing; num-bigint 0.4 has no `zeroize` feature. `keys.rs` already
//!   documents the same gap for `PrivateKey::d`. Closing it means changing the
//!   type the public API carries.
//! - **`crypto-bigint`'s own internals.** `DynResidue::pow`, which `invert`
//!   uses on the nonce-derived Z, builds a sixteen-entry table of powers on its
//!   own stack.

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use crypto_bigint::{Encoding, Integer, U256};
use num_bigint::BigUint;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CurveId {
    A,
    B,
    C,
    Test,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Clone, Debug)]
pub struct CurveParams {
    pub id: CurveId,
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub n: BigUint,
    pub g: Point,
}

fn h(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("valid hex constant")
}

impl CurveId {
    pub fn name(self) -> &'static str {
        match self {
            CurveId::A => "A",
            CurveId::B => "B",
            CurveId::C => "C",
            CurveId::Test => "TEST",
        }
    }

    pub fn params(self) -> CurveParams {
        match self {
            CurveId::A => CurveParams {
                id: self,
                p: h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
                a: h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
                b: h("A6"),
                n: h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
                g: Point { x: h("1"), y: h("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14") },
            },
            CurveId::B => CurveParams {
                id: self,
                p: h("8000000000000000000000000000000000000000000000000000000000000C99"),
                a: h("8000000000000000000000000000000000000000000000000000000000000C96"),
                b: h("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B"),
                n: h("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"),
                g: Point { x: h("1"), y: h("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC") },
            },
            CurveId::C => CurveParams {
                id: self,
                p: h("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B"),
                a: h("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"),
                b: h("805A"),
                n: h("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9"),
                g: Point { x: h("0"), y: h("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67") },
            },
            CurveId::Test => CurveParams {
                id: self,
                p: h("8000000000000000000000000000000000000000000000000000000000000431"),
                a: h("7"),
                b: h("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
                n: h("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
                g: Point { x: h("2"), y: h("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8") },
            },
        }
    }
}

/// Every curve in this module is 256-bit, so the fixed width below has no
/// special cases and the scalar loop has one shape.
const LIMBS: usize = U256::LIMBS;
const SCALAR_BITS: usize = U256::BITS;

/// An element of GF(p) in Montgomery form.
type Fp = DynResidue<LIMBS>;

/// A point in projective coordinates (X : Y : Z), the form the complete
/// addition formula works in. Z == 0 is the point at infinity, so infinity is
/// an ordinary value here rather than a case to test for.
#[derive(Clone, Copy)]
struct Proj {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl ConditionallySelectable for Proj {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Proj {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Zeroize for Proj {
    /// Every intermediate `Proj` in the ladder is m·P for a *prefix* of the
    /// scalar, so the sequence of them is a bit-by-bit encoding of the scalar
    /// itself — strictly worse to leave lying around than the scalar would be.
    /// `DynResidue::zeroize` scrubs the Montgomery value and deliberately leaves
    /// the modulus parameters alone, which is what we want: those are the curve's
    /// public constants.
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

/// The fixed-width view of a curve: the field modulus in Montgomery form and
/// the curve constants the formulas need, derived once from the `BigUint`
/// parameters the public API carries.
struct Field {
    m: DynResidueParams<LIMBS>,
    a: Fp,
    b: Fp,
    b3: Fp,
    /// p − 2, the exponent that inverts a field element by Fermat's little theorem.
    p_minus_2: U256,
}

impl Field {
    fn new(c: &CurveParams) -> Option<Field> {
        let p = to_u256(&c.p)?;
        // `DynResidueParams::new` panics on an even modulus. Every p reaching it
        // is a prime constant of this module, but check rather than rely on it.
        if !bool::from(p.is_odd()) {
            return None;
        }
        let m = DynResidueParams::new(&p);
        let a = Fp::new(&to_u256(&c.a)?, m);
        let b = Fp::new(&to_u256(&c.b)?, m);
        let b3 = b.add(&b).add(&b);
        Some(Field { m, a, b, b3, p_minus_2: p.wrapping_sub(&U256::from_u8(2)) })
    }

    fn identity(&self) -> Proj {
        Proj { x: Fp::zero(self.m), y: Fp::one(self.m), z: Fp::zero(self.m) }
    }

    fn project(&self, pt: &Point) -> Option<Proj> {
        Some(Proj {
            x: Fp::new(&to_u256(&pt.x)?, self.m),
            y: Fp::new(&to_u256(&pt.y)?, self.m),
            z: Fp::one(self.m),
        })
    }

    /// x^(p−2) mod p — the inverse of a non-zero x, by Fermat's little theorem.
    /// `DynResidue::pow` walks a fixed 256 exponent bits and reads its window
    /// from a table by constant-time selection, so the time it takes does not
    /// depend on the element being inverted.
    fn invert(&self, x: &Fp) -> Fp {
        x.pow(&self.p_minus_2)
    }

    /// None for the point at infinity.
    fn to_affine(&self, pt: &Proj) -> Option<Point> {
        if bool::from(pt.z.retrieve().ct_eq(&U256::ZERO)) {
            return None;
        }
        let mut zi = self.invert(&pt.z);
        let out = Point { x: from_u256(&pt.x.mul(&zi).retrieve()), y: from_u256(&pt.y.mul(&zi).retrieve()) };
        // The two coordinates are public; Z and its inverse are not.
        zi.zeroize();
        Some(out)
    }

    /// Renes–Costello–Batina (2015), Algorithm 1: complete addition on a short
    /// Weierstrass curve with any `a`. "Complete" means it is correct for every
    /// input pair with no exceptional case — P + Q, P + P, P + (−P) and either
    /// side being the point at infinity all come out of the same straight-line
    /// sequence. That is what lets the ladder below use it for both its
    /// addition and its doubling, and run with no branch at all.
    ///
    /// Line numbers are the paper's; the shadowing keeps its register names.
    fn add(&self, p: &Proj, q: &Proj) -> Proj {
        let (x1, y1, z1) = (p.x, p.y, p.z);
        let (x2, y2, z2) = (q.x, q.y, q.z);
        let (ca, cb3) = (self.a, self.b3);

        let t0 = x1.mul(&x2); //  1
        let t1 = y1.mul(&y2); //  2
        let t2 = z1.mul(&z2); //  3
        let t3 = x1.add(&y1); //  4
        let t4 = x2.add(&y2); //  5
        let t3 = t3.mul(&t4); //  6
        let t4 = t0.add(&t1); //  7
        let t3 = t3.sub(&t4); //  8
        let t4 = x1.add(&z1); //  9
        let t5 = x2.add(&z2); // 10
        let t4 = t4.mul(&t5); // 11
        let t5 = t0.add(&t2); // 12
        let t4 = t4.sub(&t5); // 13
        let t5 = y1.add(&z1); // 14
        let x3 = y2.add(&z2); // 15
        let t5 = t5.mul(&x3); // 16
        let x3 = t1.add(&t2); // 17
        let t5 = t5.sub(&x3); // 18
        let z3 = ca.mul(&t4); // 19
        let x3 = cb3.mul(&t2); // 20
        let z3 = x3.add(&z3); // 21
        let x3 = t1.sub(&z3); // 22
        let z3 = t1.add(&z3); // 23
        let y3 = x3.mul(&z3); // 24
        let t1 = t0.add(&t0); // 25
        let t1 = t1.add(&t0); // 26
        let t2 = ca.mul(&t2); // 27
        let t4 = cb3.mul(&t4); // 28
        let t1 = t1.add(&t2); // 29
        let t2 = t0.sub(&t2); // 30
        let t2 = ca.mul(&t2); // 31
        let t4 = t4.add(&t2); // 32
        let t0 = t1.mul(&t4); // 33
        let y3 = y3.add(&t0); // 34
        let t0 = t5.mul(&t4); // 35
        let x3 = t3.mul(&x3); // 36
        let x3 = x3.sub(&t0); // 37
        let t0 = t3.mul(&t1); // 38
        let z3 = t5.mul(&z3); // 39
        let z3 = z3.add(&t0); // 40

        Proj { x: x3, y: y3, z: z3 }
    }
}

/// A `BigUint` as a fixed 256-bit integer, or None if it does not fit.
///
/// The loop always writes all four 64-bit digits, so the only thing that varies
/// with the value is how many digits `num-bigint`'s own iterator hands over.
/// See the module doc.
fn to_u256(v: &BigUint) -> Option<U256> {
    let mut digits = v.iter_u64_digits();
    let mut be = [0u8; 32];
    // Least significant digit first, so from the end of the big-endian buffer.
    for chunk in be.rchunks_exact_mut(8) {
        chunk.copy_from_slice(&digits.next().unwrap_or(0).to_be_bytes());
    }
    let too_wide = digits.next().is_some();
    let out = U256::from_be_bytes(be);
    // `be` held the scalar in the clear on every secret-path call.
    be.zeroize();
    if too_wide {
        return None;
    }
    Some(out)
}

/// `v` as a residue mod `m`, with the fixed-width copy made on the way scrubbed.
fn residue(v: &BigUint, m: DynResidueParams<LIMBS>) -> Option<Fp> {
    let mut u = to_u256(v)?;
    let r = Fp::new(&u, m);
    u.zeroize();
    Some(r)
}

fn from_u256(v: &U256) -> BigUint {
    BigUint::from_bytes_be(&v.to_be_bytes())
}

impl CurveParams {
    pub fn is_on_curve(&self, pt: &Point) -> bool {
        if pt.x >= self.p || pt.y >= self.p {
            return false;
        }
        let (Some(f), Some(x), Some(y)) = (Field::new(self), to_u256(&pt.x), to_u256(&pt.y)) else {
            return false;
        };
        let x = Fp::new(&x, f.m);
        let y = Fp::new(&y, f.m);
        let lhs = y.mul(&y);
        let rhs = x.mul(&x).mul(&x).add(&f.a.mul(&x)).add(&f.b);
        bool::from(lhs.ct_eq(&rhs))
    }

    /// Returns None for the point at infinity.
    pub fn double(&self, pt: &Point) -> Option<Point> {
        let f = Field::new(self)?;
        let p = f.project(pt)?;
        f.to_affine(&f.add(&p, &p))
    }

    /// Group law with None = point at infinity.
    pub fn add(&self, p1: Option<&Point>, p2: Option<&Point>) -> Option<Point> {
        match (p1, p2) {
            (None, q) | (q, None) => q.cloned(),
            (Some(a), Some(b)) => {
                let f = Field::new(self)?;
                let (pa, pb) = (f.project(a)?, f.project(b)?);
                f.to_affine(&f.add(&pa, &pb))
            }
        }
    }

    /// Scalar multiplication by a Montgomery ladder over a fixed 256 iterations.
    ///
    /// Whatever the scalar, every iteration performs the same two complete
    /// additions in the same order, and which of the two running points takes
    /// which result is decided by a constant-time conditional swap rather than
    /// a branch. Neither the scalar's bit length nor its bit pattern reaches
    /// the sequence of operations. See the module doc for the limits of that.
    pub fn mul(&self, k: &BigUint, pt: &Point) -> Option<Point> {
        let f = Field::new(self)?;
        let base = f.project(pt)?;
        // Every scalar on the secret path is already reduced — the nonce, the
        // private key and the verifier's z1/z2 are all < n. A wider one can
        // only come from a caller outside this crate; reducing it first is
        // exact, because each curve here has prime order n and cofactor 1, so
        // k·P == (k mod n)·P.
        let k = match to_u256(k) {
            Some(k) => k,
            None => to_u256(&(k % &self.n))?,
        };

        let mut k = k;
        let mut r0 = f.identity();
        let mut r1 = base;
        for i in (0..SCALAR_BITS).rev() {
            let bit = Choice::from(k.bit(i));
            Proj::conditional_swap(&mut r0, &mut r1, bit);
            r1 = f.add(&r0, &r1);
            r0 = f.add(&r0, &r0);
            Proj::conditional_swap(&mut r0, &mut r1, bit);
        }
        let out = f.to_affine(&r0);
        // r0 and r1 are k·P and (k+1)·P, and the slots they sit in held every
        // prefix multiple on the way here. k is the scalar in the clear. See the
        // module doc for the copies of all three that cannot be reached.
        r0.zeroize();
        r1.zeroize();
        k.zeroize();
        out
    }

    pub fn base_mul(&self, k: &BigUint) -> Option<Point> {
        self.mul(k, &self.g)
    }

    /// `(a·b + c·d) mod n`, in fixed-width Montgomery form so that how long it
    /// takes does not depend on the operands.
    ///
    /// `gost3410`'s signature value `s = (r·d + k·e) mod n` is exactly this
    /// shape, and two of its four operands are secret: the private key and the
    /// per-signature nonce. Computed with `num-bigint` it was measurably
    /// value-dependent — enough that the same 255-bit scalar took 250 ns at
    /// Hamming weight 1 and 291 ns at weight 255 — which is the same class of
    /// leak `mul` above exists to close, on the same two secrets.
    ///
    /// Falls back to `num-bigint` if `n` is not an odd number below 2²⁵⁶. No
    /// curve here is: `CurveId::params()` is the only source of a `CurveParams`
    /// and all four orders are odd 256-bit primes.
    pub(crate) fn mul_add_mod_n(&self, a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint) -> BigUint {
        match self.mul_add_mod_n_ct(a, b, c, d) {
            Some(s) => s,
            None => (a * b + c * d) % &self.n,
        }
    }

    fn mul_add_mod_n_ct(&self, a: &BigUint, b: &BigUint, c: &BigUint, d: &BigUint) -> Option<BigUint> {
        let n = to_u256(&self.n)?;
        // `DynResidueParams::new` panics on an even modulus.
        if !bool::from(n.is_odd()) {
            return None;
        }
        let m = DynResidueParams::new(&n);
        let (mut ra, mut rb) = (residue(a, m)?, residue(b, m)?);
        let (mut rc, mut rd) = (residue(c, m)?, residue(d, m)?);
        let s = from_u256(&ra.mul(&rb).add(&rc.mul(&rd)).retrieve());
        // `s` is public — it is half the signature. Two of its operands are the
        // private key and the nonce.
        ra.zeroize();
        rb.zeroize();
        rc.zeroize();
        rd.zeroize();
        Some(s)
    }
}
