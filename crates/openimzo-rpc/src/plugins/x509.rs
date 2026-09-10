//! X.509 certificates: the chain behind a loaded key, an info view of an
//! arbitrary certificate, and one certificate's signature checked against
//! another's public key.
//! `fixtures/apidoc-original-uz.json`'s `x509` entry is the wire contract;
//! `keystore.rs` carries the stand-in device error `get_certificate_chain`
//! shares with `pkcs7::create_pkcs7` until phase 6.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::arg;
use crate::plugins::keystore;
use base64::Engine as _;
use der::Encode;
use openimzo_keys::SessionType;
use openimzo_pki::x509;
use serde_json::Value;

pub fn functions() -> Vec<FunctionSpec> {
    vec![
        function!(
            "x509",
            "get_certificate_chain",
            "Получить цепочку сертификатов в кодировке BASE64 по идентификатору ключа",
            [arg("certId", "Идентификатор ключа")],
            get_certificate_chain
        ),
        function!(
            "x509",
            "get_certificate_info",
            "Получить информацию о сертификате",
            [arg("certificate_64", "Сертификат в кодировке BASE64")],
            get_certificate_info
        ),
        function!(
            "x509",
            "verify_certificate",
            "Верификация подписи сертификата субъектка сертификатом издателя",
            [
                arg("subject_certificate_64", "Сертификат субъекта в кодировке BASE64"),
                arg("issuer_certificate_64", "Сертификат издателя в кодировке BASE64"),
            ],
            verify_certificate
        ),
    ]
}

async fn get_certificate_chain(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    match ctx.sessions.get(id).and_then(|d| d.kind) {
        None => Err(RpcError::KeyIdIsNotFound),
        Some(SessionType::PfxKeyStore) | Some(SessionType::YtksKeyStore) => {
            let (_key, chain) = keystore::stored_key_and_chain(ctx, origin, id).await?;
            let encoded: core::result::Result<Vec<Value>, der::Error> = chain
                .iter()
                .map(|c| c.to_der().map(|der| Value::String(base64::engine::general_purpose::STANDARD.encode(der))))
                .collect();
            let certificates = encoded.map_err(|e| RpcError::Runtime(e.to_string()))?;
            Ok(Response::success().with("certificates", Value::Array(certificates)))
        }
        // The original's four device session types; the fixed "no device
        // wired up yet" stand-in until phase 6.
        Some(kind) if keystore::is_device_session(kind) => Err(RpcError::Runtime(keystore::DEVICE_NOT_FOUND.into())),
        // The only type left is a fresh KEY_PAIR, which has no certificate
        // yet — the original's own default branch for this call.
        Some(_) => Err(RpcError::KeyIdIsNotSupportedForCertificate),
    }
}

async fn get_certificate_info(_ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    let certificate = x509::parse_certificate_any(request.arg(0).as_bytes())?;
    let view = x509::certificate_view(&certificate)?;
    Ok(Response::success().with("certificate_info", serde_json::to_value(&view).map_err(|e| RpcError::Runtime(e.to_string()))?))
}

async fn verify_certificate(_ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    let subject = x509::parse_certificate_any(request.arg(0).as_bytes())?;
    let issuer = x509::parse_certificate_any(request.arg(1).as_bytes())?;
    if x509::verify_certificate_signature(&subject, &issuer)? {
        Ok(Response::success())
    } else {
        Err(RpcError::Runtime("subject certificate is not signed by the issuer certificate".into()))
    }
}
