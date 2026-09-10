//! PFX writer: one shrouded key bag per key entry plus certificate bags, HMAC-SHA256 MAC.

use super::pbe;
use super::reader::{Pkcs12Store, FRIENDLY_NAME, ID_DATA, LOCAL_KEY_ID};
use crate::Result;
use cms::content_info::ContentInfo;
use der::asn1::{Any, AnyRef, BmpString, OctetString, SetOfVec};
use der::Encode;
use pkcs12::cert_type::CertBag;
use pkcs12::digest_info::DigestInfo;
use pkcs12::mac_data::MacData;
use pkcs12::pbe_params::EncryptedPrivateKeyInfo;
use pkcs12::pfx::{Pfx, Version};
use pkcs12::safe_bag::SafeBag;
use rand_core::{CryptoRng, RngCore};
use sha1::{Digest, Sha1};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, Attributes};

const MAC_ITERATIONS: i32 = 10_000;

fn attribute(oid: const_oid::ObjectIdentifier, value: Any) -> Result<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(value)?;
    Ok(Attribute { oid, values })
}

fn bag_attributes(alias: &str, local_key_id: &[u8]) -> Result<Attributes> {
    let mut attrs = SetOfVec::new();
    attrs.insert(attribute(FRIENDLY_NAME, Any::encode_from(&BmpString::from_utf8(alias)?)?)?)?;
    attrs.insert(attribute(LOCAL_KEY_ID, Any::encode_from(&OctetString::new(local_key_id.to_vec())?)?)?)?;
    Ok(attrs)
}

fn cert_bag(der: Vec<u8>, attrs: Option<Attributes>) -> Result<SafeBag> {
    let cb = CertBag { cert_id: pkcs12::PKCS_12_X509_CERT_OID, cert_value: OctetString::new(der)? };
    Ok(SafeBag { bag_id: pkcs12::PKCS_12_CERT_BAG_OID, bag_value: cb.to_der()?, bag_attributes: attrs })
}

fn data_content_info(safe_contents_der: Vec<u8>) -> Result<ContentInfo> {
    Ok(ContentInfo { content_type: ID_DATA, content: Any::encode_from(&OctetString::new(safe_contents_der)?)? })
}

pub fn write<R: RngCore + CryptoRng>(store: &Pkcs12Store, password: &str, rng: &mut R) -> Result<Vec<u8>> {
    let mut key_bags: Vec<SafeBag> = Vec::new();
    let mut cert_bags: Vec<SafeBag> = Vec::new();
    let mut written_certs: Vec<Vec<u8>> = Vec::new();

    for k in &store.keys {
        let spki = k.private_key.public_key().to_spki_der()?;
        let lkid: Vec<u8> = k.local_key_id.clone().unwrap_or_else(|| Sha1::digest(&spki).to_vec());
        let p8 = k.private_key.to_pkcs8_der()?;
        let (alg, ct) = pbe::encrypt_pbes2(password, &p8, rng)?;
        let epki = EncryptedPrivateKeyInfo { encryption_algorithm: alg, encrypted_data: OctetString::new(ct)? };
        key_bags.push(SafeBag {
            bag_id: pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: epki.to_der()?,
            bag_attributes: Some(bag_attributes(&k.alias, &lkid)?),
        });
        for (i, cert) in k.chain.iter().enumerate() {
            let der = cert.to_der()?;
            if written_certs.contains(&der) {
                continue;
            }
            let attrs = if i == 0 { Some(bag_attributes(&k.alias, &lkid)?) } else { None };
            cert_bags.push(cert_bag(der.clone(), attrs)?);
            written_certs.push(der);
        }
    }
    for c in &store.certs {
        let der = c.certificate.to_der()?;
        if written_certs.contains(&der) {
            continue;
        }
        let attrs = match (&c.alias, &c.local_key_id) {
            (Some(alias), Some(id)) => Some(bag_attributes(alias, id)?),
            (Some(alias), None) => {
                let mut a = SetOfVec::new();
                a.insert(attribute(FRIENDLY_NAME, Any::encode_from(&BmpString::from_utf8(alias)?)?)?)?;
                Some(a)
            }
            _ => None,
        };
        cert_bags.push(cert_bag(der.clone(), attrs)?);
        written_certs.push(der);
    }

    let auth_safe: Vec<ContentInfo> = vec![data_content_info(key_bags.to_der()?)?, data_content_info(cert_bags.to_der()?)?];
    let auth_der = auth_safe.to_der()?;

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let mac = pbe::compute_mac(&pbe::ID_SHA256, password, &salt, MAC_ITERATIONS, &auth_der)?;
    let pfx = Pfx {
        version: Version::V3,
        auth_safe: ContentInfo { content_type: ID_DATA, content: Any::encode_from(&OctetString::new(auth_der)?)? },
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifierOwned { oid: pbe::ID_SHA256, parameters: Some(Any::from(AnyRef::NULL)) },
                digest: OctetString::new(mac)?,
            },
            mac_salt: OctetString::new(salt.to_vec())?,
            iterations: MAC_ITERATIONS,
        }),
    };
    Ok(pfx.to_der()?)
}
