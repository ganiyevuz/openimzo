#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("password incorrect or file corrupted")]
    PasswordIncorrect,
    #[error("unsupported PFX format: {0}")]
    UnsupportedPfxFormat(String),
    #[error("ASN.1 error: {0}")]
    Asn1(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("crypto: {0}")]
    Crypto(#[from] openimzo_crypto::CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<der::Error> for PkiError {
    fn from(e: der::Error) -> Self {
        PkiError::Asn1(e.to_string())
    }
}

pub type Result<T> = core::result::Result<T, PkiError>;
