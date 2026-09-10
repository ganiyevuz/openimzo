//! GOST-family cryptography as used by E-IMZO: GOST R 34.11-94, GOST 28147-89,
//! GOST R 34.10-2001 on the CryptoPro curves, under Uzbek OIDs.

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("unsupported algorithm or parameter: {0}")]
    Unsupported(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid padding")]
    Padding,
}

impl From<der::Error> for CryptoError {
    fn from(e: der::Error) -> Self {
        CryptoError::Encoding(e.to_string())
    }
}

pub type Result<T> = core::result::Result<T, CryptoError>;

pub mod hash;
pub mod magma;
pub mod ec;
pub mod gost3410;
pub mod oid;
pub mod keys;
pub mod apikey;
pub mod selftest;

pub use keys::{KeyFamily, PrivateKey, PublicKey};
