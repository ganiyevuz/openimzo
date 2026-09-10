//! Temporary self-signed 3-certificate chain for `save_temporary_pfx` / enrollment step 1,
//! matching the original: root v1 -> CA v3 -> subject v3, 7 days, 64-bit serials.

use crate::dn::dn_from_string;
use crate::pkcs10::certificate_policies_extension;
use crate::Result;
use der::asn1::{BitString, OctetString};
use der::Encode;
use eimzo_crypto::hash::gost94;
use eimzo_crypto::keys::{algorithm_with_null, PrivateKey, PublicKey};
use eimzo_crypto::oid::TEMP_CERT_POLICY;
use rand_core::{CryptoRng, RngCore};
use sha1::{Digest, Sha1};
use std::time::{Duration, SystemTime};
use x509_cert::certificate::{TbsCertificate, Version};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

const VALIDITY_DAYS: u64 = 7;

fn random_serial<R: RngCore + CryptoRng>(rng: &mut R) -> Result<SerialNumber> {
    let mut b = [0u8; 8];
    rng.fill_bytes(&mut b);
    b[0] &= 0x7f; // positive, no leading zero needed
    if b[0] == 0 {
        b[0] = 1;
    }
    Ok(SerialNumber::new(&b)?)
}

fn key_identifier(public: &PublicKey) -> Result<Vec<u8>> {
    let spki = public.to_spki()?;
    Ok(Sha1::digest(spki.subject_public_key.raw_bytes()).to_vec())
}

#[allow(clippy::too_many_arguments)]
fn make_certificate<R: RngCore + CryptoRng>(
    rng: &mut R,
    version: Version,
    issuer: &Name,
    subject: &Name,
    subject_public: &PublicKey,
    signer: &PrivateKey,
    validity: &Validity,
    extensions: Vec<Extension>,
) -> Result<Certificate> {
    let sig_alg = algorithm_with_null(signer.family.sig_oid());
    let tbs = TbsCertificate {
        version,
        serial_number: random_serial(rng)?,
        signature: sig_alg.clone(),
        issuer: issuer.clone(),
        validity: *validity,
        subject: subject.clone(),
        subject_public_key_info: subject_public.to_spki()?,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: if extensions.is_empty() { None } else { Some(extensions) },
    };
    let signature = signer.sign(&gost94(&tbs.to_der()?), rng)?;
    Ok(Certificate { tbs_certificate: tbs, signature_algorithm: sig_alg, signature: BitString::from_bytes(&signature)? })
}

/// Returns `[subject, ca, root]`. Root and CA get fresh key pairs of the subject key's family and curve.
pub fn issue<R: RngCore + CryptoRng>(subject_public: &PublicKey, subject_x500: &str, rng: &mut R) -> Result<Vec<Certificate>> {
    let family = subject_public.family;
    let curve = subject_public.curve;
    let root_key = PrivateKey::generate(family, curve, rng)?;
    let ca_key = PrivateKey::generate(family, curve, rng)?;
    let root_name = dn_from_string("CN=Temporary Root,L=Tashkent,C=UZ")?;
    let ca_name = dn_from_string("CN=Temporary CA,L=Tashkent,C=UZ")?;
    let subject_name = dn_from_string(subject_x500)?;
    let now = SystemTime::now();
    let validity = Validity { not_before: Time::try_from(now)?, not_after: Time::try_from(now + Duration::from_secs(VALIDITY_DAYS * 86_400))? };

    let root = make_certificate(rng, Version::V1, &root_name, &root_name, &root_key.public_key(), &root_key, &validity, vec![])?;

    let ca_public = ca_key.public_key();
    let ca_exts = vec![
        BasicConstraints { ca: true, path_len_constraint: Some(0) }.to_extension(&ca_name, &[])?,
        KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation | KeyUsages::KeyAgreement | KeyUsages::KeyCertSign | KeyUsages::CRLSign).to_extension(&ca_name, &[])?,
        SubjectKeyIdentifier(OctetString::new(key_identifier(&ca_public)?)?).to_extension(&ca_name, &[])?,
        AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(key_identifier(&root_key.public_key())?)?), authority_cert_issuer: None, authority_cert_serial_number: None }.to_extension(&ca_name, &[])?,
    ];
    let ca = make_certificate(rng, Version::V3, &root_name, &ca_name, &ca_public, &root_key, &validity, ca_exts)?;

    let subject_exts = vec![
        KeyUsage(KeyUsages::KeyAgreement.into()).to_extension(&subject_name, &[])?,
        certificate_policies_extension(&[TEMP_CERT_POLICY.to_string()], false)?,
        SubjectKeyIdentifier(OctetString::new(key_identifier(subject_public)?)?).to_extension(&subject_name, &[])?,
        AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(key_identifier(&ca_public)?)?), authority_cert_issuer: None, authority_cert_serial_number: None }.to_extension(&subject_name, &[])?,
    ];
    let subject = make_certificate(rng, Version::V3, &ca_name, &subject_name, subject_public, &ca_key, &validity, subject_exts)?;
    Ok(vec![subject, ca, root])
}
