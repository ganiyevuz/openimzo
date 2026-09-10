//! PFX parsing with the original's acceptance rules.

use super::pbe;
use crate::x509::public_key;
use crate::{PkiError, Result};
use cms::content_info::ContentInfo;
use cms::encrypted_data::EncryptedData;
use const_oid::ObjectIdentifier;
use der::asn1::{BmpString, ContextSpecific, OctetString};
use der::Decode;
use openimzo_crypto::PrivateKey;
use pkcs12::cert_type::CertBag;
use pkcs12::pbe_params::EncryptedPrivateKeyInfo;
use pkcs12::pfx::{Pfx, Version};
use pkcs12::safe_bag::SafeBag;
use x509_cert::attr::Attributes;
use x509_cert::Certificate;
use zeroize::Zeroize;

pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
pub const ID_ENCRYPTED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
pub const FRIENDLY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.20");
pub const LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub alias: String,
    pub local_key_id: Option<Vec<u8>>,
    pub private_key: PrivateKey,
    /// End-entity certificate first, then issuers as far as they are present in the file.
    pub chain: Vec<Certificate>,
}

#[derive(Clone, Debug)]
pub struct CertEntry {
    pub alias: Option<String>,
    pub local_key_id: Option<Vec<u8>>,
    pub certificate: Certificate,
}

#[derive(Clone, Debug, Default)]
pub struct Pkcs12Store {
    pub keys: Vec<KeyEntry>,
    /// Every certificate bag in file order (also those that belong to a key chain).
    pub certs: Vec<CertEntry>,
}

struct RawKeyBag {
    alias: String,
    local_key_id: Option<Vec<u8>>,
    epki: EncryptedPrivateKeyInfo,
}

/// `SafeBag::bag_value` (this crate version) holds the raw TLV of the ASN.1 `bagValue [0]
/// EXPLICIT ...` field, outer context tag included, rather than the unwrapped inner content —
/// unlike `cms::content_info::ContentInfo::content`, whose derive strips that wrapper. Strip it
/// here before decoding the bag payload.
fn bag_value<'a, T: der::Decode<'a>>(bytes: &'a [u8]) -> Result<T> {
    let cs: ContextSpecific<T> = ContextSpecific::from_der(bytes)?;
    Ok(cs.value)
}

fn utf16be_to_string(bytes: &[u8]) -> String {
    // A plain index loop rather than `chunks_exact(2)` (clippy::chunks_exact_to_as_chunks).
    let mut units = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        units.push(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

fn bag_attributes(attrs: &Option<Attributes>) -> (Option<String>, Option<Vec<u8>>) {
    let mut alias = None;
    let mut lkid = None;
    if let Some(set) = attrs {
        for attr in set.iter() {
            let Some(value) = attr.values.iter().next() else { continue };
            if attr.oid == FRIENDLY_NAME {
                if let Ok(bmp) = value.decode_as::<BmpString>() {
                    let s = utf16be_to_string(bmp.as_bytes());
                    if !s.is_empty() {
                        alias = Some(s);
                    }
                }
            } else if attr.oid == LOCAL_KEY_ID {
                if let Ok(os) = value.decode_as::<OctetString>() {
                    lkid = Some(os.as_bytes().to_vec());
                }
            }
        }
    }
    (alias, lkid)
}

/// Returns the parsed PFX and the raw `authSafe` content octets (the MAC covers exactly these).
fn parse_pfx(bytes: &[u8]) -> Result<(Pfx, Vec<u8>)> {
    let pfx = Pfx::from_der(bytes)?;
    if pfx.version != Version::V3 {
        return Err(PkiError::UnsupportedPfxFormat("PFX version is not 3".into()));
    }
    if pfx.auth_safe.content_type != ID_DATA {
        return Err(PkiError::UnsupportedPfxFormat("authSafe is not of type data".into()));
    }
    let content: OctetString = pfx.auth_safe.content.decode_as()?;
    let bytes = content.as_bytes().to_vec();
    Ok((pfx, bytes))
}

/// Walks the AuthenticatedSafe. With `password == None` encrypted parts are skipped (alias listing).
fn collect_bags(content: &[u8], password: Option<&str>) -> Result<(Vec<RawKeyBag>, Vec<CertEntry>)> {
    let safes: Vec<ContentInfo> = Vec::<ContentInfo>::from_der(content)?;
    let mut keys = Vec::new();
    let mut certs = Vec::new();
    for ci in safes {
        let safe_der: Vec<u8> = if ci.content_type == ID_DATA {
            let o: OctetString = ci.content.decode_as()?;
            o.as_bytes().to_vec()
        } else if ci.content_type == ID_ENCRYPTED_DATA {
            let Some(pw) = password else { continue };
            let ed: EncryptedData = ci.content.decode_as()?;
            let eci = ed.enc_content_info;
            let ct = eci
                .encrypted_content
                .ok_or_else(|| PkiError::Asn1("encryptedData without content".into()))?;
            pbe::decrypt(&eci.content_enc_alg, pw, ct.as_bytes())?
        } else {
            continue;
        };
        let bags: Vec<SafeBag> = Vec::<SafeBag>::from_der(&safe_der)?;
        for bag in bags {
            let (alias, local_key_id) = bag_attributes(&bag.bag_attributes);
            if bag.bag_id == pkcs12::PKCS_12_PKCS8_KEY_BAG_OID {
                let Some(alias) = alias else { continue };
                let epki: EncryptedPrivateKeyInfo = bag_value(&bag.bag_value)?;
                keys.push(RawKeyBag { alias, local_key_id, epki });
            } else if bag.bag_id == pkcs12::PKCS_12_CERT_BAG_OID {
                let cb: CertBag = bag_value(&bag.bag_value)?;
                if cb.cert_id != pkcs12::PKCS_12_X509_CERT_OID {
                    continue;
                }
                let certificate = Certificate::from_der(cb.cert_value.as_bytes())?;
                certs.push(CertEntry { alias, local_key_id, certificate });
            }
            // keyBag (unshrouded) and other bag types are ignored, as in the original.
        }
    }
    Ok((keys, certs))
}

/// End-entity by localKeyId or public-key match, then follow issuer links (the JDK's behaviour).
/// Without a match, all certificates in file order (the original's fallback reader).
fn build_chain(key: &PrivateKey, local_key_id: &Option<Vec<u8>>, certs: &[CertEntry]) -> Vec<Certificate> {
    let public = key.public_key();
    let ee = certs
        .iter()
        .find(|c| local_key_id.is_some() && c.local_key_id == *local_key_id)
        .or_else(|| certs.iter().find(|c| public_key(&c.certificate).map(|p| p == public).unwrap_or(false)));
    let Some(ee) = ee else {
        return certs.iter().map(|c| c.certificate.clone()).collect();
    };
    let mut chain = vec![ee.certificate.clone()];
    let mut current = ee.certificate.clone();
    loop {
        if current.tbs_certificate.subject == current.tbs_certificate.issuer {
            break;
        }
        let next = certs
            .iter()
            .find(|c| c.certificate.tbs_certificate.subject == current.tbs_certificate.issuer && !chain.contains(&c.certificate));
        match next {
            Some(n) => {
                chain.push(n.certificate.clone());
                current = n.certificate.clone();
            }
            None => break,
        }
    }
    chain
}

/// Full read: MAC check, decryption of every part, key decryption, chain building.
pub fn read(bytes: &[u8], password: &str) -> Result<Pkcs12Store> {
    let (pfx, content) = parse_pfx(bytes)?;
    if let Some(mac) = &pfx.mac_data {
        if !pbe::verify_mac(mac, &content, password)? {
            return Err(PkiError::PasswordIncorrect);
        }
    }
    let (raw_keys, certs) = collect_bags(&content, Some(password))?;
    let mut keys = Vec::new();
    for rk in raw_keys {
        let mut p8 = pbe::decrypt(&rk.epki.encryption_algorithm, password, rk.epki.encrypted_data.as_bytes())?;
        let private_key = PrivateKey::from_pkcs8_der(&p8);
        p8.zeroize();
        let private_key = private_key?;
        let chain = build_chain(&private_key, &rk.local_key_id, &certs);
        keys.push(KeyEntry { alias: rk.alias, local_key_id: rk.local_key_id, private_key, chain });
    }
    Ok(Pkcs12Store { keys, certs })
}

/// What the original's `listAliases` sees when it loads the PFX with a null password:
/// key-bag aliases from unencrypted parts; certificate aliases only when there are no keys.
pub fn list_aliases(bytes: &[u8]) -> Result<Vec<String>> {
    let (_, content) = parse_pfx(bytes)?;
    let (keys, certs) = collect_bags(&content, None)?;
    let mut aliases: Vec<String> = keys.iter().map(|k| k.alias.clone()).collect();
    if aliases.is_empty() {
        aliases.extend(certs.iter().filter_map(|c| c.alias.clone()));
    }
    aliases.dedup();
    Ok(aliases)
}
