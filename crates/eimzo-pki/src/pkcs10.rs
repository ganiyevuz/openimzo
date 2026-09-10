//! PKCS#10 certification requests.

use crate::dn::{dn_from_string, dn_to_string};
use crate::view::{Pkcs10InfoView, PublicKeyInfoView, SignatureInfoView};
use crate::{PkiError, Result};
use base64::Engine as _;
use const_oid::ObjectIdentifier;
use der::asn1::{Any, BitString, OctetString, SetOfVec, Utf8StringRef};
use der::{Decode, DecodePem, Encode};
use eimzo_crypto::hash::gost94;
use eimzo_crypto::keys::{algorithm_with_null, PrivateKey, PublicKey};
use eimzo_crypto::oid;
use rand_core::{CryptoRng, RngCore};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::pkix::certpolicy::{CertificatePolicies, PolicyInformation, PolicyQualifierInfo};
use x509_cert::ext::Extension;
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq, Version};

pub const ID_CE_CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
pub const ID_QT_UNOTICE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.2");

/// `certificatePolicies` with one `PolicyInformation{oid, [unotice: SEQUENCE{UTF8String(oid)}]}` per OID,
/// exactly the original's `PolicyQualifierInfo(id_qt_unotice, DERSequence(DERUTF8String(oid)))`.
pub fn certificate_policies_extension(policy_oids: &[String], critical: bool) -> Result<Extension> {
    let mut infos = Vec::new();
    for raw in policy_oids {
        let text = raw.trim();
        let policy_identifier = ObjectIdentifier::new(text).map_err(|_| PkiError::Unsupported(format!("invalid certificate policy OID {text}")))?;
        let notice: Vec<Utf8StringRef<'_>> = vec![Utf8StringRef::new(text)?];
        infos.push(PolicyInformation {
            policy_identifier,
            policy_qualifiers: Some(vec![PolicyQualifierInfo { policy_qualifier_id: ID_QT_UNOTICE, qualifier: Some(Any::encode_from(&notice)?) }]),
        });
    }
    Ok(Extension { extn_id: ID_CE_CERTIFICATE_POLICIES, critical, extn_value: OctetString::new(CertificatePolicies(infos).to_der()?)? })
}

/// Builds and signs a request. `policy_oids` empty -> no attributes (as the original).
pub fn build<R: RngCore + CryptoRng>(key: &PrivateKey, subject: &str, policy_oids: &[String], rng: &mut R) -> Result<Vec<u8>> {
    let mut attributes: Attributes = SetOfVec::new();
    if !policy_oids.is_empty() {
        let ext = certificate_policies_extension(policy_oids, true)?;
        attributes.insert(Attribute::try_from(ExtensionReq(vec![ext]))?)?;
    }
    let info = CertReqInfo { version: Version::V1, subject: dn_from_string(subject)?, public_key: key.public_key().to_spki()?, attributes };
    let signature = key.sign(&gost94(&info.to_der()?), rng)?;
    let req = CertReq { info, algorithm: algorithm_with_null(key.family.sig_oid()), signature: BitString::from_bytes(&signature)? };
    Ok(req.to_der()?)
}

/// PEM, then base64 of PEM, then base64 of DER (the original's order), plus raw DER.
pub fn parse(input: &[u8]) -> Result<CertReq> {
    if let Ok(r) = CertReq::from_der(input) {
        return Ok(r);
    }
    let text = std::str::from_utf8(input).map_err(|_| PkiError::Asn1("request is neither DER nor text".into()))?;
    if text.contains("-----BEGIN") {
        return Ok(CertReq::from_pem(text)?);
    }
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes()).map_err(|_| PkiError::Asn1("request is not base64".into()))?;
    if let Ok(inner) = std::str::from_utf8(&raw) {
        if inner.contains("-----BEGIN") {
            return Ok(CertReq::from_pem(inner)?);
        }
    }
    Ok(CertReq::from_der(&raw)?)
}

pub fn verify_signature(req: &CertReq) -> Result<bool> {
    let pk = PublicKey::from_spki(&req.info.public_key)?;
    Ok(pk.verify(&gost94(&req.info.to_der()?), req.signature.raw_bytes()))
}

pub fn info_view(req: &CertReq) -> Result<Pkcs10InfoView> {
    let spki = &req.info.public_key;
    // The names the original's own provider registers (`oid::algorithm_name`);
    // anything else falls back to the OID's own text, as BouncyCastle does
    // and as the original does for the same OIDs.
    let key_alg_name = oid::algorithm_name(&spki.algorithm.oid).map(str::to_string).unwrap_or_else(|| spki.algorithm.oid.to_string());
    let sign_alg_name = oid::algorithm_name(&req.algorithm.oid).map(str::to_string).unwrap_or_else(|| req.algorithm.oid.to_string());
    Ok(Pkcs10InfoView {
        subject_name: dn_to_string(&req.info.subject),
        public_key: PublicKeyInfoView { key_alg_name, public_key: base64::engine::general_purpose::STANDARD.encode(spki.to_der()?) },
        signature: SignatureInfoView { sign_alg_name, signature: hex::encode(req.signature.raw_bytes()) },
        verified: verify_signature(req).unwrap_or(false),
    })
}
