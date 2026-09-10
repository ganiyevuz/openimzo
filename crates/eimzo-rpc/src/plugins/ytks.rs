//! YTKS (`*.yks`) key files — the vendor's own keystore format.
//! `fixtures/apidoc-original-uz.json`'s `ytks` entry is the wire contract;
//! `keystore.rs` carries what this plugin shares with `pfx.rs`. Unlike
//! `pfx`, there is no `save_temporary_pfx` equivalent here — a temporary key
//! is always issued into a PFX file, even for sites that otherwise use YTKS.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::keystore;
use crate::plugins::{arg, opt};
use eimzo_crypto::PrivateKey;
use eimzo_keys::{KeyKind, SessionData, SessionType};
use eimzo_pki::x509;
use eimzo_pki::ytks::{self, YtksEntry, YtksStore};
use rand_core::OsRng;
use serde_json::Value;
use std::path::Path;

/// `unload_key` / `verify_password` / `change_password` all resolve `ytksId`
/// through the same "of type not found" check, at this plugin's status.
const WRONG_TYPE_STATUS: i32 = -1013;

/// The status `save_ytks` answers when the destination file already exists.
const FILE_EXISTS_SAVE_YTKS_STATUS: i32 = -2009;

/// This plugin's status for a missing key file — despite `KeyFileExists`'s
/// name, this is the status the original answers when the file cannot be
/// read at all.
const KEY_FILE_MISSING_STATUS: i32 = -2010;

pub fn functions() -> Vec<FunctionSpec> {
    vec![
        function!(
            "ytks",
            "change_password",
            "Изменить пароль хранилища ключей",
            [arg("ytksId", "Идентификатор ключа")],
            change_password
        ),
        function!(
            "ytks",
            "load_key",
            "Загрузить ключ и получить идентификатор ключа. Ключ будет доступен определенное время",
            [
                arg("disk", "Диск"),
                opt("path", "Путь (должна быть пустой или 'DSKEYS')"),
                arg("name", "Имя файла без расширения"),
                arg("alias", "Алиас ключа"),
                arg("serialNumber", "Серийный номер сертификата (HEX)"),
            ],
            load_key
        ),
        function!(
            "ytks",
            "unload_key",
            "Удалить загруженные ключи по идентификатору",
            [arg("ytksId", "Идентификатор ключа")],
            unload_key
        ),
        function!("ytks", "list_disks", "Получить список дисков", [], list_disks),
        function!(
            "ytks",
            "save_ytks",
            "Сохранить ключевую пару или существующий ключ и новые сертификаты в новый файл формата YTKS",
            [
                arg("disk", "Диск"),
                opt("path", "Путь (должна быть пустой или 'DSKEYS')"),
                arg("name", "Имя файла без расширения"),
                arg("alias", "Алиас ключа"),
                arg("id", "Идентификатор новой ключевой пары или существующего хранилища ключей (для обновления сертификатов)"),
                arg("new_key_password", "Пароль для нового ключа"),
                arg("subject_certificate_64", "Сертификат субъекта в кодировке BASE64"),
                arg("ca_certificate_64", "Сертификат Центра Регистрации в кодировке BASE64"),
                arg("root_certificate_64", "Корневой сертификат в кодировке BASE64"),
            ],
            save_ytks
        ),
        function!(
            "ytks",
            "list_certificates",
            "Получить список сертификатов пользователя",
            [arg("disk", "Диск")],
            list_certificates
        ),
        function!(
            "ytks",
            "verify_password",
            "Проверить пароль хранилища ключей",
            [arg("ytksId", "Идентификатор ключа")],
            verify_password
        ),
        function!(
            "ytks",
            "list_all_certificates",
            "Получить список всех сертификатов пользователя",
            [],
            list_all_certificates
        ),
    ]
}

/// A disk listing walks the filesystem for mounted volumes, so it runs on
/// the blocking pool like every other `Discovery` call — a stale network
/// mount must stall a blocking-pool worker, not the async runtime's own.
async fn list_disks(ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    let discovery = ctx.discovery.clone();
    let disks = keystore::blocking(move || -> Result<Vec<String>> { Ok(discovery.list_disks()) }).await?;
    Ok(Response::success().with("disks", Value::Array(disks.into_iter().map(Value::String).collect())))
}

/// Checking the disk is known and scanning it both touch the filesystem and
/// have nothing fallible between them, so they share one hop to the
/// blocking pool.
async fn list_certificates(ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    let disk = request.arg(0).to_string();
    let discovery = ctx.discovery.clone();
    let list = keystore::blocking(move || -> Result<Vec<eimzo_keys::KeyInfo>> {
        if !discovery.list_disks().iter().any(|d| d == &disk) {
            return Err(RpcError::DiskIsNotFound);
        }
        Ok(discovery.scan_disk(KeyKind::Ytks, &disk))
    })
    .await?;
    keystore::certificates_response(list)
}

/// Scans every disk, which is `list_certificates` again for each one found —
/// same reason it runs on the blocking pool.
async fn list_all_certificates(ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    let discovery = ctx.discovery.clone();
    let list = keystore::blocking(move || -> Result<Vec<eimzo_keys::KeyInfo>> { Ok(discovery.scan(KeyKind::Ytks)) }).await?;
    keystore::certificates_response(list)
}

/// Never opens the file with a password: only lists aliases and checks the
/// requested one is present. For an alias it finds, that alias's leaf
/// certificate serial — rendered as lowercase hex with no leading zeroes,
/// which is the form sites send (Java's `BigInteger.toString(16)`) — is
/// compared against `serialNumber` case-sensitively, and a mismatch is
/// `-2024`.
///
/// An alias that is not in the file at all gets the same `-2024`, which is
/// a deliberate deviation recorded in the spec's deviations table: the
/// message the wire protocol pairs with `-2024` names the alias, so it
/// describes the unknown-alias case at least as well as the mismatch case,
/// and one status for "that alias and serial are not both here" tells a
/// site nothing about which of the two it got wrong.
async fn load_key(ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    keystore::require_arity(request, 5)?;
    let disk = request.arg(0).to_string();
    let path = request.arg(1).to_string();
    let name = request.arg(2).to_string();
    let alias = request.arg(3);
    let serial_number = request.arg(4);
    keystore::validate_path(&path)?;
    // The disk resolution and the file read are both filesystem I/O with
    // nothing fallible in between, so they share one hop to the blocking pool.
    let discovery = ctx.discovery.clone();
    let (file, bytes) = keystore::blocking(move || -> Result<(std::path::PathBuf, Vec<u8>)> {
        let file = discovery.resolve(&disk, &path, &name, KeyKind::Ytks).ok_or(RpcError::DiskIsNotFound)?;
        let bytes = std::fs::read(&file).map_err(|_| RpcError::KeyFileExists(KEY_FILE_MISSING_STATUS))?;
        Ok((file, bytes))
    })
    .await?;
    let entries = ytks::list(&bytes)?;
    let entry = match entries.iter().find(|e| e.alias == alias) {
        Some(entry) => entry,
        // The original embeds the resolved file's own absolute path here,
        // not the bare file name — the same fix already applied to
        // `pfx::load_key`.
        None => return Err(RpcError::CertificateNotFoundInYks(alias.to_string(), file.display().to_string())),
    };
    let leaf_serial = entry.certificate.as_ref().map(x509::serial_hex);
    if leaf_serial.as_deref() != Some(serial_number) {
        return Err(RpcError::CertificateNotFoundInYks(alias.to_string(), file.display().to_string()));
    }
    let data = SessionData {
        kind: Some(SessionType::YtksKeyStore),
        key_store_path: Some(file),
        key_store_alias: Some(alias.to_string()),
        ..Default::default()
    };
    let id = ctx.sessions.put(data);
    Ok(Response::success()
        .with("ytksId", Value::String(id))
        .with("type", Value::String(SessionType::YtksKeyStore.wire_name().to_string())))
}

async fn unload_key(ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    keystore::require_keystore_type(ctx, id, SessionType::YtksKeyStore, WRONG_TYPE_STATUS)?;
    ctx.sessions.remove(id);
    Ok(Response::success())
}

async fn verify_password(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    let (path, alias) = keystore::require_keystore_session(ctx, id, SessionType::YtksKeyStore, WRONG_TYPE_STATUS)?;
    let subject = path.display().to_string();
    // `force = true`: verify_password always prompts and never remembers.
    let store = keystore::open_with_password(ctx, id, origin, &subject, true, move |pw| {
        let bytes = read_key_file(&path)?;
        ytks::read(&bytes, pw).map_err(keystore::open_error)
    })
    .await?;
    // Only checked, not kept: nothing reads a session's key material back,
    // so a passing password proves the alias opens and there is nothing
    // further to store (see `eimzo-keys/src/session.rs`).
    key_entry(store, &alias)?;
    Ok(Response::success())
}

async fn change_password(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    let (path, _alias) = keystore::require_keystore_session(ctx, id, SessionType::YtksKeyStore, WRONG_TYPE_STATUS)?;
    let subject = path.display().to_string();
    let path_for_read = path.clone();
    let store = keystore::open_with_password(ctx, id, origin, &subject, false, move |pw| {
        let bytes = read_key_file(&path_for_read)?;
        ytks::read(&bytes, pw).map_err(keystore::open_error)
    })
    .await?;
    let new_password = keystore::ask_new_password(ctx, origin, "new password").await?;
    let confirm_password = keystore::ask_new_password(ctx, origin, "new password (confirmation)").await?;
    if *new_password != *confirm_password {
        return Err(RpcError::NewPasswordsDoNotMatch);
    }
    let out = keystore::blocking(move || -> Result<Vec<u8>> { Ok(ytks::write(&store, &new_password, &mut OsRng)?) }).await?;
    keystore::overwrite_key_file(&path, &out).await?;
    ctx.sessions.remove(id);
    Ok(Response::success())
}

async fn save_ytks(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    keystore::require_arity(request, 9)?;
    let disk = request.arg(0).to_string();
    let path = request.arg(1).to_string();
    let name = request.arg(2).to_string();
    let alias = request.arg(3);
    let id = request.arg(4);
    let new_key_password = request.arg(5).to_string();
    keystore::validate_path(&path)?;
    keystore::validate_file_name(&name)?;
    let discovery = ctx.discovery.clone();
    let target = keystore::blocking(move || -> Result<std::path::PathBuf> {
        discovery.resolve(&disk, &path, &name, KeyKind::Ytks).ok_or(RpcError::DiskIsNotFound)
    })
    .await?;

    let subject_certificate = x509::parse_certificate_any(request.arg(6).as_bytes())?;
    let ca_certificate = x509::parse_certificate_any(request.arg(7).as_bytes())?;
    let root_certificate = x509::parse_certificate_any(request.arg(8).as_bytes())?;
    keystore::verify_chain(&subject_certificate, &ca_certificate, &root_certificate)?;

    let (private_key, is_new_key) = resolve_signing_key(ctx, origin, id).await?;
    keystore::check_key_matches_certificate(&private_key, &subject_certificate)?;

    // "Writing over an existing file is FILE_EXISTS_SAVE_YTKS_STATUS for a
    // KEY_PAIR session" — a YTKS_KEY_STORE session is re-issuing
    // certificates for a key that already has a file, so no such guard
    // applies to it.
    if is_new_key && target.exists() {
        return Err(RpcError::FileExistsChooseOtherName(FILE_EXISTS_SAVE_YTKS_STATUS));
    }

    let alias = alias.to_string();
    let bytes = keystore::blocking(move || -> Result<Vec<u8>> {
        let store = YtksStore {
            entries: vec![YtksEntry::Key {
                alias,
                created_ms: chrono::Utc::now().timestamp_millis(),
                private_key,
                chain: vec![subject_certificate, ca_certificate, root_certificate],
            }],
        };
        Ok(ytks::write(&store, &new_key_password, &mut OsRng)?)
    })
    .await?;
    // As `pfx::save_pfx`: a `YTKS_KEY_STORE` session's reissue (`is_new_key
    // = false`) may target the same file the session was loaded from, so
    // this write must still be able to replace it.
    keystore::overwrite_key_file(&target, &bytes).await?;
    Ok(Response::success())
}

/// The private key `save_ytks` signs the new file with: a `KEY_PAIR`
/// session's freshly generated key, used as-is; a `YTKS_KEY_STORE`
/// session's key, read from its own file after a password prompt. The
/// `bool` says whether the key is a fresh `KEY_PAIR` one, which gates the
/// overwrite check in the caller.
async fn resolve_signing_key(ctx: &Ctx, origin: &Origin, id: &str) -> Result<(PrivateKey, bool)> {
    match ctx.sessions.get(id) {
        Some(data) if data.kind == Some(SessionType::KeyPair) => {
            let key = data.key_pair.ok_or(RpcError::KeyPairByIdIsNotFound)?;
            Ok((key, true))
        }
        Some(data) if data.kind == Some(SessionType::YtksKeyStore) => {
            let path = data.key_store_path.ok_or(RpcError::KeyIdIsNotFound)?;
            let alias = data.key_store_alias.ok_or(RpcError::KeyIdIsNotFound)?;
            let subject = path.display().to_string();
            let store = keystore::open_with_password(ctx, id, origin, &subject, false, move |pw| {
                let bytes = read_key_file(&path)?;
                ytks::read(&bytes, pw).map_err(keystore::open_error)
            })
            .await?;
            let (private_key, _chain) = key_entry(store, &alias)?;
            Ok((private_key, false))
        }
        _ => Err(RpcError::KeyIdIsNotFound),
    }
}

/// The key entry named `alias` in an opened `YtksStore`. A store lists both
/// key entries and standalone trusted certificates; only the former can back
/// a session, so a trusted-cert match (which should not happen, since
/// `load_key` only ever records a key entry's alias) is treated the same as
/// not found.
fn key_entry(store: YtksStore, alias: &str) -> Result<(PrivateKey, Vec<x509_cert::Certificate>)> {
    for entry in store.entries {
        if let YtksEntry::Key { alias: entry_alias, private_key, chain, .. } = entry {
            if entry_alias == alias {
                return Ok((private_key, chain));
            }
        }
    }
    Err(RpcError::KeyIdIsNotFound)
}

/// The file read at the front of every `open_with_password` closure in this
/// plugin: this plugin's own missing-file status, not the generic message
/// `keystore::stored_key_and_chain` falls back to.
fn read_key_file(path: &Path) -> std::result::Result<Vec<u8>, keystore::OpenError> {
    std::fs::read(path).map_err(|_| keystore::OpenError::Other(RpcError::KeyFileExists(KEY_FILE_MISSING_STATUS)))
}
