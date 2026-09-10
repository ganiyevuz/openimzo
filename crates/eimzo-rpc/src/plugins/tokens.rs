//! ID-card, BAIK, UZGUARD and CKC: E-IMZO's four hardware/crypto-container
//! plugins. Every one of them enumerates to an empty list and every write
//! operation answers "no device found" until phase 6 wires up real drivers;
//! `keystore::is_device_session`/`DEVICE_NOT_FOUND` already carry the same
//! stand-in for `pkcs7`, `pkcs10` and `x509`.
//! `fixtures/apidoc-original-uz.json` is the wire contract for
//! `ckc`/`idcard`/`baikey`/`uzgrd`. Note the wire name: UZGUARD's plugin id
//! is the five-letter `uzgrd`.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::arg;
use crate::plugins::keystore;
use serde_json::Value;

pub fn ckc_functions() -> Vec<FunctionSpec> {
    vec![
        function!("ckc", "supported_ckc", "Получить список типов поддерживаемых Крипто Контейнеров Ключа", [], supported_ckc),
        function!("ckc", "list_ckc", "Получить список Крипто Контейнеров Ключа", [], list_ckc),
        function!("ckc", "clear_saved_pin_codes", "Стереть сохраненые PIN-коды", [], clear_saved_pin_codes),
    ]
}

pub fn idcard_functions() -> Vec<FunctionSpec> {
    vec![
        function!("idcard", "clear_saved_pin_codes", "Стереть сохраненые PIN-коды", [], clear_saved_pin_codes),
        function!("idcard", "list_readers", "Получить список считывателей", [], list_readers),
        function!(
            "idcard",
            "get_encrypted_signed_cplc",
            "Получить зашифрованный и подписанный заводской номер USB-токена",
            [arg("nonce", "Значение NONCE")],
            get_encrypted_signed_cplc
        ),
        function!(
            "idcard",
            "personalize",
            "Персонализировать ID-карту записав новые сертификаты и установив PIN-код",
            [
                arg("pincode", "PIN-код"),
                arg("subject_certificate_64", "Сертификат субъекта в кодировке BASE64"),
                arg("ca_certificate_64", "Сертификат Центра Регистрации в кодировке BASE64"),
                arg("root_certificate_64", "Корневой сертификат в кодировке BASE64"),
            ],
            personalize
        ),
    ]
}

pub fn baikey_functions() -> Vec<FunctionSpec> {
    vec![
        function!("baikey", "clear_saved_pin_codes", "Стереть сохраненые PIN-коды", [], clear_saved_pin_codes),
        function!("baikey", "list_tokens", "Получить список BAIK-Token ов", [], list_tokens),
        function!(
            "baikey",
            "personalize",
            "Персонализировать BAIK-Token записав новые сертификаты и установив PIN-код",
            [
                arg("pincode", "PIN-код"),
                arg("subject_certificate_64", "Сертификат субъекта в кодировке BASE64"),
                arg("ca_certificate_64", "Сертификат Центра Регистрации в кодировке BASE64"),
                arg("root_certificate_64", "Корневой сертификат в кодировке BASE64"),
            ],
            personalize
        ),
    ]
}

pub fn uzgrd_functions() -> Vec<FunctionSpec> {
    vec![
        function!("uzgrd", "clear_saved_pin_codes", "Стереть сохраненые PIN-коды", [], clear_saved_pin_codes),
        function!("uzgrd", "list_tokens", "Получить список UZGUARD-Token ов", [], list_tokens),
        function!(
            "uzgrd",
            "personalize",
            "Персонализировать UZGUARD-Token записав новые сертификаты и установив PIN-код",
            [
                arg("pincode", "PIN-код"),
                arg("subject_certificate_64", "Сертификат субъекта в кодировке BASE64"),
                arg("ca_certificate_64", "Сертификат Центра Регистрации в кодировке BASE64"),
                arg("root_certificate_64", "Корневой сертификат в кодировке BASE64"),
            ],
            personalize
        ),
    ]
}

async fn supported_ckc(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    let list: Vec<Value> = ["idcard", "baikey", "uzgrd"].into_iter().map(|s| Value::String(s.to_string())).collect();
    Ok(Response::success().with("list", Value::Array(list)))
}

/// Phase 6 wires up enumeration across every token helper; none is present
/// meanwhile, so the container list is always empty.
async fn list_ckc(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    Ok(Response::success().with("devices", Value::Array(Vec::new())))
}

/// Phase 6 wires up real PIN storage for all four plugins; nothing is
/// cached yet, so every call here just succeeds with nothing to do.
async fn clear_saved_pin_codes(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    Ok(Response::success())
}

/// Phase 6 wires up PC/SC reader enumeration.
async fn list_readers(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    Ok(Response::success().with("readers", Value::Array(Vec::new())))
}

/// Phase 6 wires up BAIK/UZGUARD USB enumeration.
async fn list_tokens(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    Ok(Response::success().with("tokens", Value::Array(Vec::new())))
}

/// Phase 6 wires up the card-identity blob used to bootstrap ID-card
/// enrollment; no reader means no card to read it from.
async fn get_encrypted_signed_cplc(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    Err(RpcError::Runtime(keystore::DEVICE_NOT_FOUND.into()))
}

/// Phase 6 wires up writing certificates and a PIN to a fresh device, shared
/// by `idcard`, `baikey` and `uzgrd` alike (same arguments, same stand-in).
async fn personalize(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    Err(RpcError::Runtime(keystore::DEVICE_NOT_FOUND.into()))
}
