//! YTKS-2 ("YT Key Store") — the .yks files of the original.

use crate::pkcs12::password::utf16_be;
use crate::{PkiError, Result};
use der::asn1::{Any, AnyRef, OctetString};
use der::{Decode, Encode};
use openimzo_crypto::hash::gost94;
use openimzo_crypto::magma::{pad_seq, unpad_seq, Magma, SBOX_D_A};
use openimzo_crypto::{oid, PrivateKey};
use pkcs12::pbe_params::EncryptedPrivateKeyInfo;
use rand_core::{CryptoRng, RngCore};
use spki::AlgorithmIdentifierOwned;
use subtle::ConstantTimeEq;
use x509_cert::Certificate;
use zeroize::Zeroize;

const MAGIC: u32 = 0xFEED_BEEF;
const SALT_STRING: &[u8] = b"The IT Crowd";
pub const READ_ONLY_PASSWORD: &str = "00000000";

#[derive(Clone, Debug)]
pub enum YtksEntry {
    Key { alias: String, created_ms: i64, private_key: PrivateKey, chain: Vec<Certificate> },
    TrustedCert { alias: String, created_ms: i64, certificate: Box<Certificate> },
}

#[derive(Clone, Debug, Default)]
pub struct YtksStore {
    pub entries: Vec<YtksEntry>,
}

/// What listing needs without the password: alias and the end-entity certificate of key entries.
#[derive(Clone, Debug)]
pub struct YtksListEntry {
    pub alias: String,
    pub certificate: Option<Certificate>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(PkiError::Asn1("truncated YTKS file".into()));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.i32()?;
        if n < 0 {
            return Err(PkiError::Asn1("negative length".into()));
        }
        Ok(self.take(n as usize)?.to_vec())
    }
    /// Java DataInputStream.readUTF: u16 length + modified UTF-8 (plain UTF-8 for BMP text without NULs).
    fn utf(&mut self) -> Result<String> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")) as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
}

fn write_utf(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as i32).to_be_bytes());
    out.extend_from_slice(b);
}

fn file_digest(password: &str, body: &[u8]) -> [u8; 32] {
    let mut input = utf16_be(password);
    input.extend_from_slice(SALT_STRING);
    input.extend_from_slice(body);
    gost94(&input)
}

fn envelope_key(pw: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(pw.len() + salt.len() + 32);
    input.extend_from_slice(pw);
    input.extend_from_slice(salt);
    let mut h = gost94(&input);
    for _ in 0..999 {
        let mut again = Vec::with_capacity(pw.len() + salt.len() + 32);
        again.extend_from_slice(pw);
        again.extend_from_slice(salt);
        again.extend_from_slice(&h);
        h = gost94(&again);
    }
    h
}

fn decrypt_key(epki_der: &[u8], password: &str) -> Result<PrivateKey> {
    let epki = EncryptedPrivateKeyInfo::from_der(epki_der)?;
    let o = epki.encryption_algorithm.oid;
    if o != oid::YTKS2_ENCRYPTED_PRIVATE_KEY && o != oid::YTKS2_ENCRYPTED_PRIVATE_KEY_OLD {
        return Err(PkiError::Unsupported(format!("YTKS key algorithm {o}")));
    }
    let env = epki.encrypted_data.as_bytes();
    if env.len() < 64 + 8 {
        return Err(PkiError::Asn1("YTKS envelope too short".into()));
    }
    let salt = &env[..32];
    let checksum = &env[env.len() - 32..];
    let ct = &env[32..env.len() - 32];
    let mut pw = utf16_be(password);
    let mut key = envelope_key(&pw, salt);
    let padded = Magma::new(&key, &SBOX_D_A).ecb_decrypt(ct).map_err(|_| PkiError::PasswordIncorrect);
    key.zeroize();
    let mut padded = padded?;
    let pkcs8 = unpad_seq(&padded).map_err(|_| PkiError::PasswordIncorrect);
    padded.zeroize();
    let mut pkcs8 = pkcs8?;
    let mut check_input = pw.clone();
    check_input.extend_from_slice(&pkcs8);
    // Constant-time: this digest is derived from the file's password.
    let digest_matches: bool = gost94(&check_input).as_slice().ct_eq(checksum).into();
    check_input.zeroize();
    pw.zeroize();
    if !digest_matches {
        pkcs8.zeroize();
        return Err(PkiError::PasswordIncorrect);
    }
    let result = PrivateKey::from_pkcs8_der(&pkcs8);
    pkcs8.zeroize();
    Ok(result?)
}

fn encrypt_key<R: RngCore + CryptoRng>(key: &PrivateKey, password: &str, rng: &mut R) -> Result<Vec<u8>> {
    let mut pkcs8 = key.to_pkcs8_der()?;
    let mut pw = utf16_be(password);
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    let mut k = envelope_key(&pw, &salt);
    let mut padded = pad_seq(&pkcs8);
    let ct = Magma::new(&k, &SBOX_D_A).ecb_encrypt(&padded);
    padded.zeroize();
    k.zeroize();
    let ct = ct?;
    let mut check_input = pw.clone();
    check_input.extend_from_slice(&pkcs8);
    let checksum = gost94(&check_input);
    check_input.zeroize();
    pw.zeroize();
    pkcs8.zeroize();
    let mut env = Vec::with_capacity(32 + ct.len() + 32);
    env.extend_from_slice(&salt);
    env.extend_from_slice(&ct);
    env.extend_from_slice(&checksum);
    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifierOwned { oid: oid::YTKS2_ENCRYPTED_PRIVATE_KEY, parameters: Some(Any::from(AnyRef::NULL)) },
        encrypted_data: OctetString::new(env)?,
    };
    Ok(epki.to_der()?)
}

struct RawEntry {
    kind: i32,
    alias: String,
    created_ms: i64,
    key_der: Option<Vec<u8>>,
    certs: Vec<Certificate>,
}

fn parse(bytes: &[u8], password: &str) -> Result<Vec<RawEntry>> {
    if bytes.len() < 32 + 12 {
        return Err(PkiError::Asn1("not a YtKeyStore".into()));
    }
    let body = &bytes[..bytes.len() - 32];
    let digest = &bytes[bytes.len() - 32..];
    if file_digest(password, body) != digest && password != READ_ONLY_PASSWORD {
        return Err(PkiError::PasswordIncorrect);
    }
    let mut r = Reader { data: body, pos: 0 };
    if r.i32()? as u32 != MAGIC {
        return Err(PkiError::Asn1("not a YtKeyStore".into()));
    }
    let _format = r.i32()?;
    let count = r.i32()?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let kind = r.i32()?;
        let alias = r.utf()?;
        let created_ms = r.i64()?;
        match kind {
            1 => {
                let key_der = r.bytes()?;
                let chain_len = r.i32()?;
                let mut certs = Vec::new();
                for _ in 0..chain_len {
                    let _cert_type = r.utf()?;
                    certs.push(Certificate::from_der(&r.bytes()?)?);
                }
                entries.push(RawEntry { kind, alias, created_ms, key_der: Some(key_der), certs });
            }
            2 => {
                let _cert_type = r.utf()?;
                let cert = Certificate::from_der(&r.bytes()?)?;
                entries.push(RawEntry { kind, alias, created_ms, key_der: None, certs: vec![cert] });
            }
            other => return Err(PkiError::Unsupported(format!("YTKS entry type {other}"))),
        }
    }
    Ok(entries)
}

/// Listing with the read-only bypass password (no key decryption).
pub fn list(bytes: &[u8]) -> Result<Vec<YtksListEntry>> {
    Ok(parse(bytes, READ_ONLY_PASSWORD)?
        .into_iter()
        .map(|e| YtksListEntry { alias: e.alias, certificate: e.certs.first().cloned() })
        .collect())
}

pub fn read(bytes: &[u8], password: &str) -> Result<YtksStore> {
    let mut entries = Vec::new();
    for e in parse(bytes, password)? {
        match (e.kind, e.key_der) {
            (1, Some(key_der)) => {
                let private_key = decrypt_key(&key_der, password)?;
                entries.push(YtksEntry::Key { alias: e.alias, created_ms: e.created_ms, private_key, chain: e.certs });
            }
            _ => {
                let certificate = e.certs.into_iter().next().ok_or_else(|| PkiError::Asn1("trusted entry without certificate".into()))?;
                entries.push(YtksEntry::TrustedCert { alias: e.alias, created_ms: e.created_ms, certificate: Box::new(certificate) });
            }
        }
    }
    Ok(YtksStore { entries })
}

pub fn write<R: RngCore + CryptoRng>(store: &YtksStore, password: &str, rng: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&MAGIC.to_be_bytes());
    body.extend_from_slice(&2i32.to_be_bytes());
    body.extend_from_slice(&(store.entries.len() as i32).to_be_bytes());
    for e in &store.entries {
        match e {
            YtksEntry::Key { alias, created_ms, private_key, chain } => {
                body.extend_from_slice(&1i32.to_be_bytes());
                write_utf(&mut body, alias);
                body.extend_from_slice(&created_ms.to_be_bytes());
                write_bytes(&mut body, &encrypt_key(private_key, password, rng)?);
                body.extend_from_slice(&(chain.len() as i32).to_be_bytes());
                for c in chain {
                    write_utf(&mut body, "X.509");
                    write_bytes(&mut body, &c.to_der()?);
                }
            }
            YtksEntry::TrustedCert { alias, created_ms, certificate } => {
                body.extend_from_slice(&2i32.to_be_bytes());
                write_utf(&mut body, alias);
                body.extend_from_slice(&created_ms.to_be_bytes());
                write_utf(&mut body, "X.509");
                write_bytes(&mut body, &certificate.to_der()?);
            }
        }
    }
    let digest = file_digest(password, &body);
    body.extend_from_slice(&digest);
    Ok(body)
}

/// Conversion helpers used by the CLI and, later, the tray utilities (same password on both sides).
pub fn from_pkcs12(store: &crate::pkcs12::Pkcs12Store, now_ms: i64) -> YtksStore {
    let mut entries = Vec::new();
    for k in &store.keys {
        entries.push(YtksEntry::Key { alias: k.alias.clone(), created_ms: now_ms, private_key: k.private_key.clone(), chain: k.chain.clone() });
    }
    // Standalone trusted certificates (not part of any key's chain) must survive the round trip too.
    for c in &store.certs {
        if store.keys.iter().any(|k| k.chain.contains(&c.certificate)) {
            continue;
        }
        let alias = c.alias.clone().unwrap_or_else(|| crate::dn::dn_to_string(&c.certificate.tbs_certificate.subject));
        entries.push(YtksEntry::TrustedCert { alias, created_ms: now_ms, certificate: Box::new(c.certificate.clone()) });
    }
    YtksStore { entries }
}

pub fn to_pkcs12(store: &YtksStore) -> crate::pkcs12::Pkcs12Store {
    let mut out = crate::pkcs12::Pkcs12Store::default();
    for e in &store.entries {
        match e {
            YtksEntry::Key { alias, private_key, chain, .. } => out.keys.push(crate::pkcs12::KeyEntry {
                alias: alias.clone(),
                local_key_id: None,
                private_key: private_key.clone(),
                chain: chain.clone(),
            }),
            YtksEntry::TrustedCert { alias, certificate, .. } => out.certs.push(crate::pkcs12::CertEntry {
                alias: Some(alias.clone()),
                local_key_id: None,
                certificate: (**certificate).clone(),
            }),
        }
    }
    out
}
