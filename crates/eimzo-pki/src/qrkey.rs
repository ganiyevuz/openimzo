//! "QR-key" export for the E-IMZO ID-card mobile app, matching the original's own format.

use crate::{PkiError, Result};
use eimzo_crypto::ec::CurveId;
use eimzo_crypto::hash::gost94;
use eimzo_crypto::magma::{Magma, SBOX_D_A};
use eimzo_crypto::PrivateKey;
use zeroize::Zeroize;

/// Returns `E7 31 01 <curveType> || Magma-ECB_K(d || gost94(d))` (68 bytes); the QR code carries its hex.
pub fn export(key: &PrivateKey, password: &str) -> Result<Vec<u8>> {
    if password.is_empty() || !password.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(PkiError::Unsupported("QR-key password must match [0-9A-Za-z]+".into()));
    }
    let curve_type: u8 = match key.curve {
        CurveId::A => 1,
        CurveId::B => 2,
        CurveId::C => 3,
        CurveId::Test => return Err(PkiError::Unsupported("test curve".into())),
    };
    let mut enc_key = gost94(password.as_bytes());
    for _ in 0..999 {
        enc_key = gost94(&enc_key);
    }
    let mut d = key.d_be32();
    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(&d);
    secret.extend_from_slice(&gost94(&d));
    let ct = Magma::new(&enc_key, &SBOX_D_A).ecb_encrypt(&secret);
    d.zeroize();
    secret.zeroize();
    enc_key.zeroize();
    let ct = ct?;
    let mut out = vec![0xE7, 0x31, 0x01, curve_type];
    out.extend_from_slice(&ct);
    Ok(out)
}
