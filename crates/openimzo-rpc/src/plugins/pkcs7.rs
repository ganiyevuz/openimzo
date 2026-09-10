//! PKCS#7/CMS signing — the core signing call every site relies on:
//! `fixtures/apidoc-original-uz.json`'s `pkcs7` entry is the wire contract.
//!
//! Only file-backed keys (`pfx`/`ytks` sessions) actually sign here. The
//! original's four hardware/device session types (ID-card, BAIK, UZGUARD,
//! CKC) go through a PIN dialog and a token helper instead; phase 6 wires
//! that up. Until then a device session id gets the same stand-in error as
//! every other plugin that touches those types (`keystore::DEVICE_NOT_FOUND`).

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::keystore;
use crate::plugins::{arg, opt};
use base64::Engine as _;
use openimzo_keys::SessionType;
use openimzo_pki::cms;
use rand_core::OsRng;
use serde_json::Value;
use std::time::SystemTime;

pub fn functions() -> Vec<FunctionSpec> {
    vec![function!(
        "pkcs7",
        "create_pkcs7",
        "Создать PKCS#7/CMS документ подписав ключем задаваемым идентификатором",
        [
            arg(
                "data_64",
                "Данные в кодировке BASE64 (будут предваритьльно декодированы, подписаны и вложены в документ)"
            ),
            arg("id", "Идентификатор ключа подписывающего лица (полученный из фукнции других плагинов)"),
            opt(
                "detached",
                "Возможные значения: 'yes' - будет создан PKCS#7/CMS документ без вложения исходных данных, 'no' или '' - будет создан PKCS#7/CMS документ с вложением исходных данных"
            ),
        ],
        create_pkcs7
    )]
}

/// `detached == "yes"` means detached; everything else (including an
/// explicit `"no"` or `""`, and an omitted argument, which `Request::arg`
/// cannot tell apart from an explicit `""`) means attached — so the
/// dispatcher's arity leniency changes nothing here: an omitted argument
/// lands on exactly the same branch an explicit empty string would.
async fn create_pkcs7(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let data_64 = request.arg(0);
    let id = request.arg(1);
    let detached = request.arg(2) == "yes";
    let data = base64::engine::general_purpose::STANDARD.decode(data_64).map_err(|e| RpcError::Runtime(e.to_string()))?;

    match ctx.sessions.get(id).and_then(|d| d.kind) {
        None => Err(RpcError::KeyIdIsNotFound),
        Some(SessionType::PfxKeyStore) | Some(SessionType::YtksKeyStore) => {
            let (key, chain) = keystore::stored_key_and_chain(ctx, origin, id).await?;
            let data_for_sign = data.clone();
            let der = keystore::blocking(move || -> Result<Vec<u8>> {
                Ok(cms::sign(&data_for_sign, !detached, &key, &chain, SystemTime::now(), &mut OsRng)?)
            })
            .await?;
            let info = cms::verify(&der, if detached { Some(&data) } else { None })?;
            let signer = info.signers.first().ok_or_else(|| RpcError::Runtime("signed document carries no signer".into()))?;
            Ok(Response::success()
                .with("pkcs7_64", Value::String(base64::engine::general_purpose::STANDARD.encode(&der)))
                .with("signer_serial_number", Value::String(signer.serial_hex.clone()))
                .with("signature_hex", Value::String(hex::encode(&signer.signature))))
        }
        // The original's four device session types; the fixed "no device
        // wired up yet" stand-in until phase 6.
        Some(kind) if keystore::is_device_session(kind) => Err(RpcError::Runtime(keystore::DEVICE_NOT_FOUND.into())),
        // The only type left is a fresh KEY_PAIR (no certificate yet), which
        // the original's own handler for this call falls through to this
        // status for.
        Some(_) => Err(RpcError::KeyIdIsNotSupported),
    }
}
