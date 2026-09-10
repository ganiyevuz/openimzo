//! Password-based encryption and MAC for PKCS#12.

use super::password::{bmp_with_terminator, pkcs5_bytes};
use crate::{PkiError, Result};
use cipher::block_padding::Pkcs7;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecryptMut, InnerIvInit, KeyIvInit};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, AnyRef};
use der::Encode;
use hmac::{Hmac, Mac};
use pkcs12::kdf::{derive_key, Pkcs12KeyType};
use pkcs12::mac_data::MacData;
use pkcs12::pbe_params::Pkcs12PbeParams;
use pkcs5::pbes2;
use rand_core::{CryptoRng, RngCore};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use spki::AlgorithmIdentifierOwned;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

fn bad(e: impl core::fmt::Display) -> PkiError {
    PkiError::Asn1(e.to_string())
}

/// Decrypts `ct` under `alg` (PBES2, SHA1-3DES, RC2-128, RC2-40). Padding failures mean a wrong password.
pub fn decrypt(alg: &AlgorithmIdentifierOwned, password: &str, ct: &[u8]) -> Result<Vec<u8>> {
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| PkiError::Asn1("PBE algorithm without parameters".into()))?;
    if alg.oid == pbes2::PBES2_OID {
        let params_der = params.to_der()?;
        let p = pbes2::Parameters::try_from(AnyRef::try_from(params_der.as_slice())?).map_err(bad)?;
        return p.decrypt(pkcs5_bytes(password), ct).map_err(|_| PkiError::PasswordIncorrect);
    }
    let pp: Pkcs12PbeParams = params.decode_as()?;
    let pw = bmp_with_terminator(password);
    let salt = pp.salt.as_bytes();
    if alg.oid == pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC {
        let mut key = derive_key::<Sha1>(&pw, salt, Pkcs12KeyType::EncryptionKey, pp.iterations, 24);
        let mut iv = derive_key::<Sha1>(&pw, salt, Pkcs12KeyType::Iv, pp.iterations, 8);
        let dec = cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv).map_err(bad);
        key.zeroize();
        iv.zeroize();
        return dec?.decrypt_padded_vec_mut::<Pkcs7>(ct).map_err(|_| PkiError::PasswordIncorrect);
    }
    let rc2 = if alg.oid == pkcs12::PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC {
        Some((16usize, 128usize))
    } else if alg.oid == pkcs12::PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC {
        Some((5usize, 40usize))
    } else {
        None
    };
    if let Some((key_len, eff_bits)) = rc2 {
        let mut key = derive_key::<Sha1>(&pw, salt, Pkcs12KeyType::EncryptionKey, pp.iterations, key_len);
        let mut iv = derive_key::<Sha1>(&pw, salt, Pkcs12KeyType::Iv, pp.iterations, 8);
        let cipher = rc2::Rc2::new_with_eff_key_len(&key, eff_bits);
        key.zeroize();
        let dec = cbc::Decryptor::<rc2::Rc2>::inner_iv_init(cipher, GenericArray::from_slice(&iv));
        iv.zeroize();
        return dec.decrypt_padded_vec_mut::<Pkcs7>(ct).map_err(|_| PkiError::PasswordIncorrect);
    }
    Err(PkiError::Unsupported(format!("PBE algorithm {}", alg.oid)))
}

/// PBES2 / PBKDF2-HMAC-SHA256 (10 000 rounds) / AES-256-CBC, the scheme the writer uses.
pub fn encrypt_pbes2<R: RngCore + CryptoRng>(password: &str, plaintext: &[u8], rng: &mut R) -> Result<(AlgorithmIdentifierOwned, Vec<u8>)> {
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);
    let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(10_000, &salt, &iv).map_err(bad)?;
    let ct = params.encrypt(pkcs5_bytes(password), plaintext).map_err(bad)?;
    let alg = AlgorithmIdentifierOwned { oid: pbes2::PBES2_OID, parameters: Some(Any::encode_from(&params)?) };
    Ok((alg, ct))
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

pub fn compute_mac(alg: &ObjectIdentifier, password: &str, salt: &[u8], iterations: i32, content: &[u8]) -> Result<Vec<u8>> {
    let pw = bmp_with_terminator(password);
    let mac = if *alg == ID_SHA1 {
        let key = derive_key::<Sha1>(&pw, salt, Pkcs12KeyType::Mac, iterations, 20);
        hmac_sha1(&key, content)
    } else if *alg == ID_SHA256 {
        let key = derive_key::<Sha256>(&pw, salt, Pkcs12KeyType::Mac, iterations, 32);
        hmac_sha256(&key, content)
    } else if *alg == ID_SHA512 {
        let key = derive_key::<Sha512>(&pw, salt, Pkcs12KeyType::Mac, iterations, 64);
        hmac_sha512(&key, content)
    } else {
        return Err(PkiError::Unsupported(format!("MAC digest {alg}")));
    };
    Ok(mac)
}

pub fn verify_mac(mac_data: &MacData, content: &[u8], password: &str) -> Result<bool> {
    let computed = compute_mac(&mac_data.mac.algorithm.oid, password, mac_data.mac_salt.as_bytes(), mac_data.iterations, content)?;
    // Constant-time: this is the PKCS#12 integrity MAC, derived from the file's password.
    Ok(computed.as_slice().ct_eq(mac_data.mac.digest.as_bytes()).into())
}
