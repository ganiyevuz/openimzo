//! PKCS#10 certificate requests: keypair generation, CSR creation from a
//! fresh key pair or an existing key file, and CSR inspection.
//! `fixtures/apidoc-original-uz.json`'s `pkcs10` entry is the wire contract;
//! `keystore.rs` carries the stand-in device error `create_pkcs10` shares
//! with `pkcs7::create_pkcs7` until phase 6.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::keystore;
use crate::plugins::{arg, opt};
use crate::ui::{LegacyAlgAnswer, LegacyAlgRequest};
use base64::Engine as _;
use const_oid::ObjectIdentifier;
use der::Encode;
use openimzo_crypto::ec::CurveId;
use openimzo_crypto::{KeyFamily, PrivateKey};
use openimzo_keys::{SessionData, SessionType};
use openimzo_pki::{dn, pkcs10};
use rand_core::OsRng;
use serde_json::Value;

/// The original's fixed stand-in for an algorithm name that maps to neither
/// `KeyFamily`, once the legacy-algorithm confirmation (below) has already
/// had its say.
const UNSUPPORTED_ALGORITHM: &str = "Неподдерживаемый алгоритм";

pub fn functions() -> Vec<FunctionSpec> {
    vec![
        function!(
            "pkcs10",
            "create_pkcs10_from_key",
            "Формировать запрос на сертификат формата PKCS#10 из существующего ключа",
            [
                arg("id", "Идентификато ключа"),
                opt(
                    "replacement_x500_name",
                    "Имя субъекта в формате X.500 или '' если нужно получить имя из сертификата по идентификатору ключа"
                ),
                opt("cp_list", "OIDы политик применения сертификатов разделенных запятой"),
            ],
            create_pkcs10_from_key
        ),
        function!(
            "pkcs10",
            "get_pkcs10_info",
            "Получить информацию о запросе PKCS#10",
            [arg("pkcs10", "Сертификат в кодировке BASE64 или PEM")],
            get_pkcs10_info
        ),
        function!(
            "pkcs10",
            "create_pkcs10",
            "Формировать запрос на сертификат формата PKCS#10",
            [
                arg("id", "Идентификатор ключевой пары"),
                arg("subject_x500_name", "Имя субъекта в формате X.500"),
                opt("cp_list", "OIDы политик применения сертификатов разделенных запятой"),
            ],
            create_pkcs10
        ),
        function!(
            "pkcs10",
            "generate_keypair",
            "Сгенерировать ключевую пару",
            [
                arg("alg_name", "Название алгоритма"),
                opt("seed", "Случайные данные для инициализации генератора случайных чисел"),
            ],
            generate_keypair
        ),
    ]
}

/// `cp_list` split into policy OIDs, validated the same way
/// `openimzo_pki::pkcs10::build`'s certificate-policies extension validates
/// them internally — so a malformed OID is this function's own `-2023`
/// rather than a generic `-9999` surfacing from deeper inside `build`. `""`
/// means no policies at all.
///
/// `trim_each` reproduces a real difference in the original: `create_pkcs10`
/// validates (and embeds) each OID exactly as sent, so surrounding
/// whitespace makes an otherwise-valid OID invalid; `create_pkcs10_from_key`
/// trims each OID first.
fn parse_cp_list(cp_list: &str, trim_each: bool) -> Result<Vec<String>> {
    if cp_list.is_empty() {
        return Ok(Vec::new());
    }
    cp_list
        .split(',')
        .map(|raw| {
            let oid = if trim_each { raw.trim() } else { raw };
            ObjectIdentifier::new(oid).map_err(|_| RpcError::InvalidCertificatePolicyOid)?;
            Ok(oid.to_string())
        })
        .collect()
}

/// Generates a fresh key pair for `alg_name`, asking the legacy-algorithm
/// confirmation first when it isn't already the recommended one. Shared with
/// `pki::enroll_pfx_step1`, which needs exactly this before building its CSR,
/// so the confirmation logic lives in one place rather than two.
///
/// `seed` is accepted by both callers for wire compatibility, so a site
/// that sends one still gets a valid reply, but it is never used: every key
/// here comes from the OS CSPRNG alone, and nothing a website sends reaches
/// the generator. A deliberate choice, recorded in the spec's deviations
/// table — do not "wire the argument up".
pub(crate) async fn generate_key(ctx: &Ctx, origin: &Origin, alg_name: &str) -> Result<PrivateKey> {
    let effective_alg = if alg_name.eq_ignore_ascii_case("OZMST-286-2024-2") {
        alg_name.to_string()
    } else {
        let ask = LegacyAlgRequest {
            origin: origin.domain.clone(),
            requested: alg_name.to_string(),
            suggested: "OZMST-286-2024-2".to_string(),
        };
        match ctx.ui.confirm_legacy_algorithm(ask).await {
            Ok(LegacyAlgAnswer::UseSuggested) => "OZMST-286-2024-2".to_string(),
            Ok(LegacyAlgAnswer::KeepRequested) | Err(_) => alg_name.to_string(),
        }
    };
    let family = KeyFamily::from_algorithm_name(&effective_alg).ok_or_else(|| RpcError::Runtime(UNSUPPORTED_ALGORITHM.into()))?;
    keystore::blocking(move || -> Result<PrivateKey> { Ok(PrivateKey::generate(family, CurveId::A, &mut OsRng)?) }).await
}

async fn generate_keypair(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let alg_name = request.arg(0);
    let key = generate_key(ctx, origin, alg_name).await?;
    let id = ctx.sessions.put(SessionData { kind: Some(SessionType::KeyPair), key_pair: Some(key), ..Default::default() });
    Ok(Response::success().with("kpId", Value::String(id)).with("type", Value::String(SessionType::KeyPair.wire_name().to_string())))
}

async fn create_pkcs10(ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    let subject_x500_name = request.arg(1).to_string();
    let cp_list = parse_cp_list(request.arg(2), false)?;

    match ctx.sessions.get(id) {
        Some(data) if data.kind == Some(SessionType::KeyPair) => {
            let key = data.key_pair.ok_or(RpcError::KeyPairByIdIsNotFound)?;
            let der = keystore::blocking(move || -> Result<Vec<u8>> { Ok(pkcs10::build(&key, &subject_x500_name, &cp_list, &mut OsRng)?) })
                .await?;
            Ok(Response::success().with("pkcs10_64", Value::String(base64::engine::general_purpose::STANDARD.encode(&der))))
        }
        Some(data) if data.kind.is_some_and(keystore::is_device_session) => {
            Err(RpcError::Runtime(keystore::DEVICE_NOT_FOUND.into()))
        }
        None => Err(RpcError::KeyPairByIdIsNotFound),
        // A PFX/YTKS session, say — the original's own default branch.
        _ => Err(RpcError::KeyIdDoesNotMatch),
    }
}

async fn create_pkcs10_from_key(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    let replacement_x500_name = request.arg(1);
    let cp_list = parse_cp_list(request.arg(2), true)?;

    match ctx.sessions.get(id).and_then(|d| d.kind) {
        None => Err(RpcError::KeyIdIsNotFound),
        Some(SessionType::PfxKeyStore) | Some(SessionType::YtksKeyStore) => {
            let (key, chain) = keystore::stored_key_and_chain(ctx, origin, id).await?;
            let subject_certificate = chain.first().ok_or_else(|| RpcError::Runtime("stored key has no certificate".into()))?;
            let subject = if replacement_x500_name.is_empty() {
                dn::dn_to_string(&subject_certificate.tbs_certificate.subject)
            } else {
                replacement_x500_name.to_string()
            };
            let der = keystore::blocking(move || -> Result<Vec<u8>> { Ok(pkcs10::build(&key, &subject, &cp_list, &mut OsRng)?) }).await?;
            Ok(Response::success().with("pkcs10_64", Value::String(base64::engine::general_purpose::STANDARD.encode(&der))))
        }
        // KEY_PAIR and the four device types alike — the original doesn't
        // special-case devices here, unlike `create_pkcs7`/`create_pkcs10`.
        Some(_) => Err(RpcError::KeyIdIsNotSupported),
    }
}

async fn get_pkcs10_info(_ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    let req = pkcs10::parse(request.arg(0).as_bytes()).map_err(|_| RpcError::FailedToOpenPkcs10)?;
    let view = pkcs10::info_view(&req)?;
    let der = req.to_der().map_err(|e| RpcError::Runtime(e.to_string()))?;
    Ok(Response::success()
        .with("pkcs10_info", serde_json::to_value(&view).map_err(|e| RpcError::Runtime(e.to_string()))?)
        .with("pkcs10_64", Value::String(base64::engine::general_purpose::STANDARD.encode(&der))))
}
