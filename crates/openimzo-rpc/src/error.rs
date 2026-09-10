//! Every failure a web page can see, with the original's own status code
//! and message key.

use crate::i18n::{Arg, Lang, Messages};
use crate::model::Response;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("function is not found")]
    FunctionNotFound,
    #[error("invalid path argument")]
    InvalidArgPath,
    #[error("file name has bad chars")]
    FileNameHasBadChars,
    /// The original gives this message key two status codes: `-1004` from
    /// `save_pfx`, `-2009` from `save_temporary_pfx` and from `save_ytks`.
    /// The status travels with the error so each call site supplies its own.
    #[error("file exists")]
    FileExistsChooseOtherName(i32),
    #[error("invalid lang code")]
    InvalidLangCode,
    #[error("key id is not found")]
    KeyIdIsNotFound,
    #[error("key pair by id is not found")]
    KeyPairByIdIsNotFound,
    /// The original gives this one message key two different status codes
    /// depending which plugin's session lookup raises it: `-1013` for `ytks`,
    /// `-1014` for `pfx`. The status travels with the error rather than
    /// being hard-coded here, so each plugin supplies its own.
    #[error("key id of type {0} is not found")]
    KeyIdOfTypeIsNotFound(String, i32),
    #[error("key id is not supported")]
    KeyIdIsNotSupported,
    #[error("key id does not match")]
    KeyIdDoesNotMatch,
    #[error("key id is not supported for certificate")]
    KeyIdIsNotSupportedForCertificate,
    #[error("pin code length")]
    PinCodeLength { key: &'static str, args: Vec<Arg> },
    #[error("api key for domain {0} is invalid")]
    ApiKeyInvalid(String),
    #[error("failed to identify domain")]
    FailedToIdentifyDomain,
    #[error("api key for domain {0} is invalid (origin not allowed)")]
    OriginNotAllowed(String),
    #[error("certificate policies oids are not passed")]
    CertificatePoliciesNotPassed,
    #[error("failed to open pkcs10")]
    FailedToOpenPkcs10,
    #[error("invalid seed argument")]
    InvalidArgSeed,
    /// Two codes again: `-2002` in the pfx flow, `-2010` in the ytks flow.
    /// Despite the name, the original raises this when the key file is
    /// MISSING, and this rewrite matches that behaviour.
    #[error("key file is missing")]
    KeyFileExists(i32),
    #[error("certificate {0} is not found in pfx {1}")]
    CertificateNotFoundInPfx(String, String),
    #[error("certificate {0} is not found in yks {1}")]
    CertificateNotFoundInYks(String, String),
    #[error("disk is not found")]
    DiskIsNotFound,
    #[error("key file is already exists {0}")]
    KeyFileAlreadyExists(String),
    #[error("public key does not match")]
    PublicKeyDoesNotMatch { expected_x: String, expected_y: String, cert_x: String, cert_y: String },
    #[error("public key does not match private key")]
    PublicKeyDoesNotMatchPrivate,
    #[error("invalid certificate policy oid")]
    InvalidCertificatePolicyOid,
    #[error("process identifier is not found")]
    ProcessIdentifierNotFound,
    #[error("process id already exists")]
    ProcessIdAlreadyExists,
    #[error("in process")]
    InProcess,
    #[error("waiting user input")]
    WaitingUserInput,
    #[error("password enter canceled")]
    PasswordEnterCanceled,
    #[error("operation canceled")]
    OperationCanceled,
    #[error("canceled by user")]
    CanceledByUser,
    #[error("plug in usb disk and retry")]
    PlugInUsbDiskAndRetry,
    #[error("new passwords do not match")]
    NewPasswordsDoNotMatch,
    #[error("failed to create dir")]
    FailedToCreateDir,
    /// Anything not in the original's table. The message is shown to the site;
    /// it must never carry a type name, a path outside the request, or a trace.
    #[error("{0}")]
    Runtime(String),
}

impl RpcError {
    pub fn status(&self) -> i32 {
        use RpcError::*;
        match self {
            FunctionNotFound => 0,
            InvalidArgPath => -1002,
            FileNameHasBadChars => -1003,
            FileExistsChooseOtherName(status) => *status,
            InvalidLangCode => -1005,
            KeyIdIsNotFound => -1010,
            KeyPairByIdIsNotFound => -1011,
            KeyIdOfTypeIsNotFound(_, status) => *status,
            KeyIdIsNotSupported => -1015,
            KeyIdDoesNotMatch => -1016,
            KeyIdIsNotSupportedForCertificate => -1018,
            PinCodeLength { .. } => -1019,
            ApiKeyInvalid(_) => -1020,
            FailedToIdentifyDomain => -1021,
            OriginNotAllowed(_) => -1022,
            CertificatePoliciesNotPassed => -1023,
            FailedToOpenPkcs10 => -1028,
            InvalidArgSeed => -1029,
            KeyFileExists(status) => *status,
            CertificateNotFoundInPfx(_, _) => -2006,
            DiskIsNotFound => -2011,
            KeyFileAlreadyExists(_) => -2012,
            PublicKeyDoesNotMatch { .. } => -2020,
            PublicKeyDoesNotMatchPrivate => -2021,
            InvalidCertificatePolicyOid => -2023,
            CertificateNotFoundInYks(_, _) => -2024,
            ProcessIdentifierNotFound => -2025,
            ProcessIdAlreadyExists => -2026,
            InProcess => -3000,
            WaitingUserInput => -3001,
            PasswordEnterCanceled => -5000,
            OperationCanceled => -5001,
            CanceledByUser => -5002,
            PlugInUsbDiskAndRetry => -5003,
            NewPasswordsDoNotMatch => -5004,
            FailedToCreateDir => -9000,
            Runtime(_) => -9999,
        }
    }

    fn message_key(&self) -> &'static str {
        use RpcError::*;
        match self {
            FunctionNotFound => "function.is.not.found",
            InvalidArgPath => "invalid.arg.path",
            FileNameHasBadChars => "file.name.has.bad.chars",
            FileExistsChooseOtherName(_) => "file.exists.choose.other.name",
            InvalidLangCode => "invalid.lang.code",
            KeyIdIsNotFound => "key.id.is.not.found",
            KeyPairByIdIsNotFound => "key.pair.by.id.is.not.found",
            KeyIdOfTypeIsNotFound(_, _) => "key.id.of.type.s.is.not.found",
            KeyIdIsNotSupported => "key.id.is.not.supported",
            KeyIdDoesNotMatch => "key.id.does.not.match",
            KeyIdIsNotSupportedForCertificate => "key.id.is.not.supported.for.certificate",
            PinCodeLength { key, .. } => key,
            ApiKeyInvalid(_) | OriginNotAllowed(_) => "api.key.for.domain.s.is.invalid",
            FailedToIdentifyDomain => "failed.to.identify.domain",
            CertificatePoliciesNotPassed => "certificate.policies.oids.are.not.passed",
            FailedToOpenPkcs10 => "failed.to.open.pkcs10",
            InvalidArgSeed => "invalid.arg.seed",
            KeyFileExists(_) => "key.file.exists",
            CertificateNotFoundInPfx(_, _) => "certificate.s.is.not.found.in.pfx.s",
            CertificateNotFoundInYks(_, _) => "certificate.s.is.not.found.in.yks.s",
            DiskIsNotFound => "disk.is.not.found",
            KeyFileAlreadyExists(_) => "key.file.is.already.exists.s",
            PublicKeyDoesNotMatch { .. } => "public.key.does.not.match",
            PublicKeyDoesNotMatchPrivate => "public.key.does.not.match.to.private.key",
            InvalidCertificatePolicyOid => "invalid.certificate.policy.oid.passed",
            ProcessIdentifierNotFound => "process.identifier.is.not.found",
            ProcessIdAlreadyExists => "process.id.already.exists",
            InProcess => "in.process",
            WaitingUserInput => "waiting.user.input",
            PasswordEnterCanceled => "password.enter.canceled",
            OperationCanceled => "operation.canceled",
            CanceledByUser => "canceled.by.user",
            PlugInUsbDiskAndRetry => "plug.in.usb.disk.and.retry",
            NewPasswordsDoNotMatch => "new.passwords.do.not.match",
            FailedToCreateDir => "failed.to.create.dir",
            Runtime(_) => "",
        }
    }

    fn args(&self) -> Vec<Arg> {
        use RpcError::*;
        match self {
            KeyIdOfTypeIsNotFound(t, _) => vec![Arg::S(t.clone())],
            ApiKeyInvalid(d) | OriginNotAllowed(d) => vec![Arg::S(d.clone())],
            CertificateNotFoundInPfx(a, b) | CertificateNotFoundInYks(a, b) => {
                vec![Arg::S(a.clone()), Arg::S(b.clone())]
            }
            KeyFileAlreadyExists(p) => vec![Arg::S(p.clone())],
            FileExistsChooseOtherName(_) => Vec::new(),
            KeyFileExists(_) => Vec::new(),
            PublicKeyDoesNotMatch { expected_x, expected_y, cert_x, cert_y } => vec![
                Arg::S(expected_x.clone()),
                Arg::S(expected_y.clone()),
                Arg::S(cert_x.clone()),
                Arg::S(cert_y.clone()),
            ],
            PinCodeLength { args, .. } => args.clone(),
            _ => Vec::new(),
        }
    }

    pub fn reason(&self, messages: &Messages, lang: Lang) -> String {
        match self {
            RpcError::Runtime(text) => text.clone(),
            other => messages.format(lang, other.message_key(), &other.args()),
        }
    }

    pub fn into_response(self, messages: &Messages, lang: Lang) -> Response {
        Response::failure(self.status(), self.reason(messages, lang))
    }
}

/// Library errors reach a site only as a `Runtime` message. Nothing here may
/// leak a filesystem path the site did not supply or a Rust type name.
impl From<openimzo_pki::PkiError> for RpcError {
    fn from(e: openimzo_pki::PkiError) -> Self {
        RpcError::Runtime(e.to_string())
    }
}

impl From<openimzo_crypto::CryptoError> for RpcError {
    fn from(e: openimzo_crypto::CryptoError) -> Self {
        RpcError::Runtime(e.to_string())
    }
}

pub type Result<T> = core::result::Result<T, RpcError>;
