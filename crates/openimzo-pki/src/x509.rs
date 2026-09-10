//! X.509 parsing, signature checks and the info view.

use crate::dn::dn_to_string;
use crate::view::{CertificateView, PublicKeyInfoView, SignatureInfoView};
use crate::{PkiError, Result};
use base64::Engine as _;
use chrono::{DateTime, Local};
use der::{Decode, DecodePem, Encode};
use openimzo_crypto::hash::gost94;
use openimzo_crypto::keys::{KeyFamily, PublicKey};
use openimzo_crypto::oid;
use num_bigint::BigInt;
use std::time::SystemTime;
use x509_cert::time::Time;
use x509_cert::Certificate;

pub fn parse_certificate_der(der_bytes: &[u8]) -> Result<Certificate> {
    Ok(Certificate::from_der(der_bytes)?)
}

/// DER, PEM, or base64 (of DER or of PEM) — the same tolerance the original applies to inputs.
pub fn parse_certificate_any(input: &[u8]) -> Result<Certificate> {
    if let Ok(c) = Certificate::from_der(input) {
        return Ok(c);
    }
    if let Ok(text) = std::str::from_utf8(input) {
        if text.contains("-----BEGIN") {
            return Ok(Certificate::from_pem(text)?);
        }
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes()) {
            if let Ok(c) = Certificate::from_der(&raw) {
                return Ok(c);
            }
            if let Ok(inner) = std::str::from_utf8(&raw) {
                if inner.contains("-----BEGIN") {
                    return Ok(Certificate::from_pem(inner)?);
                }
            }
        }
    }
    Err(PkiError::Asn1("not a DER, PEM or base64 certificate".into()))
}

pub fn public_key(cert: &Certificate) -> Result<PublicKey> {
    Ok(PublicKey::from_spki(&cert.tbs_certificate.subject_public_key_info)?)
}

/// Java `BigInteger.toString(16)` of the (signed) serial INTEGER.
pub fn serial_hex(cert: &Certificate) -> String {
    BigInt::from_signed_bytes_be(cert.tbs_certificate.serial_number.as_bytes()).to_str_radix(16)
}

pub fn system_time(t: &Time) -> SystemTime {
    t.to_system_time()
}

/// Milliseconds since the Unix epoch, the way Jackson serializes a Java
/// `Date` field with no format annotation — the wire type of the `ytks` key
/// listing's own `validFrom`/`validTo`, which go out as a bare number, not
/// as the formatted string `x509.get_certificate_info` uses for the fields
/// of the same two names.
pub fn epoch_millis(t: SystemTime) -> i64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// `yyyy.MM.dd HH:mm:ss` in the local time zone, as the original formats it.
pub fn format_time_local(t: SystemTime) -> String {
    let dt: DateTime<Local> = t.into();
    dt.format("%Y.%m.%d %H:%M:%S").to_string()
}

/// True when `subject`'s signature verifies under `issuer`'s public key (national algorithms only).
pub fn verify_certificate_signature(subject: &Certificate, issuer: &Certificate) -> Result<bool> {
    let family = KeyFamily::from_sig_oid(&subject.signature_algorithm.oid)
        .ok_or_else(|| PkiError::Unsupported(format!("signature algorithm {}", subject.signature_algorithm.oid)))?;
    let _ = family;
    let tbs = subject.tbs_certificate.to_der()?;
    let hash = gost94(&tbs);
    let key = public_key(issuer)?;
    Ok(key.verify(&hash, subject.signature.raw_bytes()))
}

pub fn certificate_view(cert: &Certificate) -> Result<CertificateView> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    // The names the original's own provider registers
    // (`oid::algorithm_name`); anything else falls back to the OID's own
    // text, as BouncyCastle does and as the original does for the same OIDs.
    let key_alg_name = oid::algorithm_name(&spki.algorithm.oid).map(str::to_string).unwrap_or_else(|| spki.algorithm.oid.to_string());
    let sign_alg_name =
        oid::algorithm_name(&cert.signature_algorithm.oid).map(str::to_string).unwrap_or_else(|| cert.signature_algorithm.oid.to_string());
    Ok(CertificateView {
        serial_number: serial_hex(cert),
        subject_name: dn_to_string(&cert.tbs_certificate.subject),
        valid_from: format_time_local(system_time(&cert.tbs_certificate.validity.not_before)),
        valid_to: format_time_local(system_time(&cert.tbs_certificate.validity.not_after)),
        issuer_name: dn_to_string(&cert.tbs_certificate.issuer),
        public_key: Some(PublicKeyInfoView {
            key_alg_name,
            public_key: base64::engine::general_purpose::STANDARD.encode(spki.to_der()?),
        }),
        signature: SignatureInfoView { sign_alg_name, signature: hex::encode(cert.signature.raw_bytes()) },
    })
}

/// True when the certificate is its own issuer and the signature verifies (used for chain building).
pub fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer && verify_certificate_signature(cert, cert).unwrap_or(false)
}
