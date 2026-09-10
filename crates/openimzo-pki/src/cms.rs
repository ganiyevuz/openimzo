//! CMS / PKCS#7 SignedData as produced and consumed by E-IMZO.

use crate::dn::dn_to_string;
use crate::view::{CertificateView, SignerIdView};
use crate::x509::{certificate_view, public_key, serial_hex};
use crate::{PkiError, Result};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode, Tag, Tagged};
use openimzo_crypto::hash::gost94;
use openimzo_crypto::keys::algorithm_with_null;
use openimzo_crypto::oid::{DIGEST_OZDST_A, DIGEST_OZMST_A};
use openimzo_crypto::PrivateKey;
use num_bigint::BigInt;
use rand_core::{CryptoRng, RngCore};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::Certificate;

pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
pub const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
pub const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
pub const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

fn attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(value)?;
    Ok(Attribute { oid, values })
}

fn signed_attributes(content_hash: &[u8; 32], now: SystemTime) -> Result<Attributes> {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();
    let signing_time = UtcTime::from_unix_duration(Duration::from_secs(secs))?;
    let mut set = SetOfVec::new();
    set.insert(attribute(ID_CONTENT_TYPE, Any::encode_from(&ID_DATA)?)?)?;
    set.insert(attribute(ID_SIGNING_TIME, Any::encode_from(&signing_time)?)?)?;
    set.insert(attribute(ID_MESSAGE_DIGEST, Any::encode_from(&OctetString::new(content_hash.to_vec())?)?)?)?;
    Ok(set)
}

/// Returns the DER of `ContentInfo { signedData }`. `chain[0]` must be the signer's certificate.
pub fn sign<R: RngCore + CryptoRng>(content: &[u8], attached: bool, key: &PrivateKey, chain: &[Certificate], now: SystemTime, rng: &mut R) -> Result<Vec<u8>> {
    let signer_cert = chain.first().ok_or_else(|| PkiError::NotFound("signer certificate".into()))?;
    let family = key.family;
    let content_hash = gost94(content);
    let attrs = signed_attributes(&content_hash, now)?;
    let attrs_der = attrs.to_der()?; // SET OF encoding: exactly what is hashed and signed
    let signature = key.sign(&gost94(&attrs_der), rng)?;

    let signer = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: signer_cert.tbs_certificate.issuer.clone(),
            serial_number: signer_cert.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: algorithm_with_null(family.digest_oid()),
        signed_attrs: Some(attrs),
        signature_algorithm: algorithm_with_null(family.sig_oid()),
        signature: OctetString::new(signature.to_vec())?,
        unsigned_attrs: None,
    };
    let mut digest_algorithms: DigestAlgorithmIdentifiers = SetOfVec::new();
    digest_algorithms.insert(algorithm_with_null(family.digest_oid()))?;
    let certs: Vec<CertificateChoices> = chain.iter().cloned().map(CertificateChoices::Certificate).collect();
    let signed = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: if attached { Some(Any::encode_from(&OctetString::new(content.to_vec())?)?) } else { None },
        },
        certificates: Some(CertificateSet::from(SetOfVec::try_from(certs)?)),
        crls: None,
        signer_infos: SignerInfos::from(SetOfVec::try_from(vec![signer])?),
    };
    let ci = ContentInfo { content_type: ID_SIGNED_DATA, content: Any::encode_from(&signed)? };
    Ok(ci.to_der()?)
}

#[derive(Clone, Debug)]
pub struct SignerResult {
    pub signer_id: SignerIdView,
    pub serial_hex: String,
    pub signing_time: Option<SystemTime>,
    pub signature: Vec<u8>,
    pub digest: Vec<u8>,
    pub verified: bool,
    pub certificate: Option<Certificate>,
    pub certificate_view: Option<CertificateView>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CmsInfo {
    pub content: Vec<u8>,
    pub signers: Vec<SignerResult>,
}

fn find_attr(attrs: &Attributes, oid: ObjectIdentifier) -> Option<&Any> {
    attrs.iter().find(|a| a.oid == oid).and_then(|a| a.values.iter().next())
}

pub fn verify(cms_der: &[u8], detached_content: Option<&[u8]>) -> Result<CmsInfo> {
    // The original signs through BouncyCastle's streaming `CMSSignedDataGenerator`, which writes BER,
    // not DER: indefinite lengths and a fragmented, constructed `eContent` OCTET STRING. Canonicalize
    // to DER before decoding; `der`/`cms` only ever accept the latter.
    let der_bytes = crate::ber::to_der(cms_der)?;
    let ci = ContentInfo::from_der(&der_bytes)?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(PkiError::Unsupported(format!("content type {}", ci.content_type)));
    }
    let sd: SignedData = ci.content.decode_as()?;
    let content: Vec<u8> = match (&sd.encap_content_info.econtent, detached_content) {
        (Some(e), _) => {
            let o: OctetString = e.decode_as()?;
            o.as_bytes().to_vec()
        }
        (None, Some(d)) => d.to_vec(),
        (None, None) => return Err(PkiError::NotFound("detached content is required".into())),
    };
    let certs: Vec<Certificate> = sd
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(x) => Some(x.clone()),
            _ => None,
        })
        .collect();
    let content_hash = gost94(&content);
    let mut signers = Vec::new();
    for si in sd.signer_infos.0.iter() {
        let SignerIdentifier::IssuerAndSerialNumber(ias) = &si.sid else {
            signers.push(SignerResult {
                signer_id: SignerIdView { issuer: String::new(), subject_serial_number: String::new() },
                serial_hex: String::new(),
                signing_time: None,
                signature: si.signature.as_bytes().to_vec(),
                digest: Vec::new(),
                verified: false,
                certificate: None,
                certificate_view: None,
                error: Some("subjectKeyIdentifier signer identification is not supported".into()),
            });
            continue;
        };
        let serial = BigInt::from_signed_bytes_be(ias.serial_number.as_bytes()).to_str_radix(16);
        let cert = certs
            .iter()
            .find(|c| c.tbs_certificate.issuer == ias.issuer && c.tbs_certificate.serial_number == ias.serial_number)
            .cloned();
        let signature = si.signature.as_bytes().to_vec();
        let has_signed_attrs = si.signed_attrs.is_some();
        let (signed_input, digest_attr, signing_time, content_type_attr) = match &si.signed_attrs {
            Some(attrs) => {
                let md = find_attr(attrs, ID_MESSAGE_DIGEST).and_then(|a| a.decode_as::<OctetString>().ok()).map(|o| o.as_bytes().to_vec());
                let st = find_attr(attrs, ID_SIGNING_TIME)
                    .filter(|a| a.tag() == Tag::UtcTime)
                    .and_then(|a| a.decode_as::<UtcTime>().ok())
                    .map(|t| UNIX_EPOCH + t.to_unix_duration());
                let ct = find_attr(attrs, ID_CONTENT_TYPE).and_then(|a| a.decode_as::<ObjectIdentifier>().ok());
                (attrs.to_der()?, md, st, ct)
            }
            None => (content.clone(), None, None, None),
        };
        let mut verified = false;
        let mut error = None;
        match &cert {
            None => error = Some("signer certificate is not embedded in the CMS".into()),
            Some(c) => match public_key(c) {
                Err(e) => error = Some(e.to_string()),
                Ok(pk) => {
                    // RFC 5652 §5.3/§5.6: when signedAttrs are present, contentType and messageDigest
                    // are mandatory and bind the signature to this SignedData's content; a missing or
                    // mismatched attribute must fail closed rather than fall back to "not checked".
                    if si.digest_alg.oid != DIGEST_OZDST_A && si.digest_alg.oid != DIGEST_OZMST_A {
                        error = Some(format!("unsupported digest algorithm {}", si.digest_alg.oid));
                    } else if has_signed_attrs && content_type_attr != Some(sd.encap_content_info.econtent_type) {
                        error = Some("contentType attribute does not match the encapsulated content type".into());
                    } else if has_signed_attrs && digest_attr.is_none() {
                        error = Some("signed attributes are present but messageDigest is missing or malformed".into());
                    } else if has_signed_attrs && digest_attr.as_deref() != Some(content_hash.as_slice()) {
                        error = Some("messageDigest does not match the content".into());
                    } else if !pk.verify(&gost94(&signed_input), &signature) {
                        error = Some("signature does not verify".into());
                    } else {
                        verified = true;
                    }
                }
            },
        }
        // A malformed certificate must only sink this signer's result, not the whole `verify` call.
        let mut certificate_view_result = None;
        if let Some(c) = &cert {
            match certificate_view(c) {
                Ok(v) => certificate_view_result = Some(v),
                Err(e) => {
                    verified = false;
                    error = Some(match error.take() {
                        Some(existing) => format!("{existing}; {e}"),
                        None => e.to_string(),
                    });
                }
            }
        }
        let certificate_view = certificate_view_result;
        signers.push(SignerResult {
            signer_id: SignerIdView { issuer: dn_to_string(&ias.issuer), subject_serial_number: serial.clone() },
            serial_hex: cert.as_ref().map(serial_hex).unwrap_or(serial),
            signing_time,
            signature,
            digest: digest_attr.unwrap_or_default(),
            verified,
            certificate: cert,
            certificate_view,
            error,
        });
    }
    Ok(CmsInfo { content, signers })
}
