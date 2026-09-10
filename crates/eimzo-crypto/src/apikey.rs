//! Verification of E-IMZO API keys: ECGOST3410 on curve A over GOST94(GOST94(domain)),
//! hex signature s||r, fixed public key, matching the original.

use crate::ec::{CurveId, Point};
use crate::gost3410::verify;
use crate::hash::gost94;
use num_bigint::BigUint;

const QX: &str = "29c7371abeb628c21dea54d24e6f17ad5de119bc495dcd402b27e642efa78cbd";
const QY: &str = "be1401d23a79d1270d13332a0b4b1aefa533d2f75133c3cbc0061d8e47869749";

pub fn fixed_public_key() -> Point {
    Point {
        x: BigUint::parse_bytes(QX.as_bytes(), 16).expect("hex"),
        y: BigUint::parse_bytes(QY.as_bytes(), 16).expect("hex"),
    }
}

fn verify_double_hash(message: &[u8], sig_hex: &str) -> bool {
    let Ok(sig) = hex::decode(sig_hex.trim()) else {
        return false;
    };
    if sig.len() != 64 {
        return false;
    }
    let dig = gost94(message);
    let hash = gost94(&dig);
    verify(&CurveId::A.params(), &fixed_public_key(), &hash, &sig)
}

/// `apikey` argument check and cache validation.
pub fn verify_domain(domain: &str, apikey_hex: &str) -> bool {
    verify_double_hash(domain.as_bytes(), apikey_hex)
}

/// Signed content check (the original used it for update manifests).
pub fn verify_content(content: &[u8], sig_hex: &str) -> bool {
    verify_double_hash(content, sig_hex)
}
