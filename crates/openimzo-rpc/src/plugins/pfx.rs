//! PKCS#12 (`*.pfx`) key files — the format most sites actually use.
//! `fixtures/apidoc-original-uz.json`'s `pfx` entry is the wire contract;
//! `keystore.rs` carries what this plugin shares with `ytks.rs`.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::keystore;
use crate::plugins::{arg, opt};
use openimzo_crypto::PrivateKey;
use openimzo_keys::{KeyKind, SessionData, SessionType};
use openimzo_pki::pkcs12::{self, KeyEntry, Pkcs12Store};
use openimzo_pki::{tempchain, x509};
use rand_core::OsRng;
use serde_json::Value;
use std::path::Path;

/// `unload_key` / `verify_password` / `change_password` all resolve `pfxId`
/// through the same "of type not found" check, at this plugin's status.
const WRONG_TYPE_STATUS: i32 = -1014;

/// The status `save_pfx` answers when the destination file already exists.
const FILE_EXISTS_SAVE_PFX_STATUS: i32 = -1004;

/// The status `save_temporary_pfx` answers when the destination file
/// already exists.
const FILE_EXISTS_SAVE_TEMPORARY_PFX_STATUS: i32 = -2009;

/// This plugin's status for a missing key file — despite `KeyFileExists`'s
/// name, this is the status the original answers when the file cannot be
/// read at all.
const KEY_FILE_MISSING_STATUS: i32 = -2002;

pub fn functions() -> Vec<FunctionSpec> {
    vec![
        function!(
            "pfx",
            "change_password",
            "Изменить пароль хранилища ключей",
            [arg("pfxId", "Идентификатор ключа")],
            change_password
        ),
        function!(
            "pfx",
            "load_key",
            "Загрузить ключ и получить идентификатор ключа. Ключ будет доступен определенное время",
            [
                arg("disk", "Диск"),
                opt("path", "Путь (должна быть пустой или 'DSKEYS')"),
                arg("name", "Имя файла без расширения"),
                arg("alias", "Алиас ключа"),
            ],
            load_key
        ),
        function!(
            "pfx",
            "unload_key",
            "Удалить загруженные ключи по идентификатору",
            [arg("pfxId", "Идентификатор ключа")],
            unload_key
        ),
        function!("pfx", "list_disks", "Получить список дисков", [], list_disks),
        function!(
            "pfx",
            "save_temporary_pfx",
            "Сохранить ключевую пару и самоподписанный сертификат во временный файл формата PFX",
            [
                arg("disk", "Диск"),
                opt("path", "Путь (должна быть пустой или 'DSKEYS')"),
                arg("name", "Имя файла без расширения"),
                arg("alias", "Алиас ключа"),
                arg("id", "Идентификатор новой ключевой пары"),
                arg("password", "Пароль для временного ключа"),
                arg("subject_x500_name", "Имя субъекта в формате X.500"),
            ],
            save_temporary_pfx
        ),
        function!(
            "pfx",
            "list_certificates",
            "Получить список сертификатов пользователя",
            [arg("disk", "Диск")],
            list_certificates
        ),
        function!(
            "pfx",
            "save_pfx",
            "Сохранить ключевую пару или существующий ключ и новые сертификаты в новый файл формата PFX",
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
            save_pfx
        ),
        function!(
            "pfx",
            "verify_password",
            "Проверить пароль хранилища ключей",
            [arg("pfxId", "Идентификатор ключа")],
            verify_password
        ),
        function!(
            "pfx",
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
    let list = keystore::blocking(move || -> Result<Vec<openimzo_keys::KeyInfo>> {
        if !discovery.list_disks().iter().any(|d| d == &disk) {
            return Err(RpcError::DiskIsNotFound);
        }
        Ok(discovery.scan_disk(KeyKind::Pfx, &disk))
    })
    .await?;
    keystore::certificates_response(list)
}

/// Scans every disk, which is `list_certificates` again for each one found —
/// same reason it runs on the blocking pool.
async fn list_all_certificates(ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    let discovery = ctx.discovery.clone();
    let list = keystore::blocking(move || -> Result<Vec<openimzo_keys::KeyInfo>> { Ok(discovery.scan(KeyKind::Pfx)) }).await?;
    keystore::certificates_response(list)
}

/// Never opens the file with a password: only lists aliases and checks the
/// requested one is present.
async fn load_key(ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    keystore::require_arity(request, 4)?;
    let disk = request.arg(0).to_string();
    let path = request.arg(1).to_string();
    let name = request.arg(2).to_string();
    let alias = request.arg(3);
    keystore::validate_path(&path)?;
    // The disk resolution and the file read are both filesystem I/O with
    // nothing fallible in between, so they share one hop to the blocking pool.
    let discovery = ctx.discovery.clone();
    let (file, bytes) = keystore::blocking(move || -> Result<(std::path::PathBuf, Vec<u8>)> {
        let file = discovery.resolve(&disk, &path, &name, KeyKind::Pfx).ok_or(RpcError::DiskIsNotFound)?;
        let bytes = std::fs::read(&file).map_err(|_| RpcError::KeyFileExists(KEY_FILE_MISSING_STATUS))?;
        Ok((file, bytes))
    })
    .await?;
    let aliases = pkcs12::list_aliases(&bytes)?;
    if !aliases.iter().any(|a| a == alias) {
        // The original embeds the resolved file's own absolute path here,
        // not the bare file name — and it is the caller's own
        // `disk`/`path`/`name`
        // arguments recombined, not anything the caller could not already
        // work out, so this is not the kind of internal detail a reply must
        // withhold (contrast a Rust path or stack trace).
        return Err(RpcError::CertificateNotFoundInPfx(alias.to_string(), file.display().to_string()));
    }
    let data = SessionData {
        kind: Some(SessionType::PfxKeyStore),
        key_store_path: Some(file),
        key_store_alias: Some(alias.to_string()),
        ..Default::default()
    };
    let id = ctx.sessions.put(data);
    Ok(Response::success()
        .with("keyId", Value::String(id))
        .with("type", Value::String(SessionType::PfxKeyStore.wire_name().to_string())))
}

async fn unload_key(ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    keystore::require_keystore_type(ctx, id, SessionType::PfxKeyStore, WRONG_TYPE_STATUS)?;
    ctx.sessions.remove(id);
    Ok(Response::success())
}

async fn verify_password(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    let (path, alias) = keystore::require_keystore_session(ctx, id, SessionType::PfxKeyStore, WRONG_TYPE_STATUS)?;
    let subject = path.display().to_string();
    // `force = true`: verify_password always prompts and never remembers.
    let store = keystore::open_with_password(ctx, id, origin, &subject, true, move |pw| {
        let bytes = read_key_file(&path)?;
        pkcs12::read(&bytes, pw).map_err(keystore::open_error)
    })
    .await?;
    // Only checked, not kept: nothing reads a session's key material back,
    // so a passing password proves the alias opens and there is nothing
    // further to store (see `openimzo-keys/src/session.rs`).
    if !store.keys.iter().any(|k| k.alias == alias) {
        return Err(RpcError::KeyIdIsNotFound);
    }
    Ok(Response::success())
}

async fn change_password(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let id = request.arg(0);
    let (path, _alias) = keystore::require_keystore_session(ctx, id, SessionType::PfxKeyStore, WRONG_TYPE_STATUS)?;
    let subject = path.display().to_string();
    let path_for_read = path.clone();
    let store = keystore::open_with_password(ctx, id, origin, &subject, false, move |pw| {
        let bytes = read_key_file(&path_for_read)?;
        pkcs12::read(&bytes, pw).map_err(keystore::open_error)
    })
    .await?;
    let new_password = keystore::ask_new_password(ctx, origin, "new password").await?;
    let confirm_password = keystore::ask_new_password(ctx, origin, "new password (confirmation)").await?;
    if *new_password != *confirm_password {
        return Err(RpcError::NewPasswordsDoNotMatch);
    }
    let out = keystore::blocking(move || -> Result<Vec<u8>> { Ok(pkcs12::write(&store, &new_password, &mut OsRng)?) }).await?;
    keystore::overwrite_key_file(&path, &out).await?;
    ctx.sessions.remove(id);
    Ok(Response::success())
}

async fn save_pfx(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
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
        discovery.resolve(&disk, &path, &name, KeyKind::Pfx).ok_or(RpcError::DiskIsNotFound)
    })
    .await?;

    let subject_certificate = x509::parse_certificate_any(request.arg(6).as_bytes())?;
    let ca_certificate = x509::parse_certificate_any(request.arg(7).as_bytes())?;
    let root_certificate = x509::parse_certificate_any(request.arg(8).as_bytes())?;
    keystore::verify_chain(&subject_certificate, &ca_certificate, &root_certificate)?;

    let (private_key, is_new_key) = resolve_signing_key(ctx, origin, id).await?;
    keystore::check_key_matches_certificate(&private_key, &subject_certificate)?;

    // "Writing over an existing file is FILE_EXISTS_SAVE_PFX_STATUS for a
    // KEY_PAIR session" — a PFX_KEY_STORE session is re-issuing certificates
    // for a key that already has a file, so no such guard applies to it.
    if is_new_key && target.exists() {
        return Err(RpcError::FileExistsChooseOtherName(FILE_EXISTS_SAVE_PFX_STATUS));
    }

    let store = Pkcs12Store {
        keys: vec![KeyEntry {
            alias: alias.to_string(),
            local_key_id: None,
            private_key,
            chain: vec![subject_certificate, ca_certificate, root_certificate],
        }],
        certs: vec![],
    };
    let bytes = keystore::blocking(move || -> Result<Vec<u8>> { Ok(pkcs12::write(&store, &new_key_password, &mut OsRng)?) }).await?;
    // A `PFX_KEY_STORE` session's reissue (`is_new_key = false`) may target
    // the same file the session was loaded from, so this write must still
    // be able to replace it; the `target.exists()` guard above is what
    // keeps a fresh `KEY_PAIR` session from ever reaching here with a
    // target that already exists.
    keystore::overwrite_key_file(&target, &bytes).await?;
    Ok(Response::success())
}

/// The private key `save_pfx` signs the new file with: a `KEY_PAIR`
/// session's freshly generated key, used as-is; a `PFX_KEY_STORE` session's
/// key, read from its own file after a password prompt. The `bool` says
/// whether the key is a fresh `KEY_PAIR` one, which gates the overwrite
/// check in the caller.
async fn resolve_signing_key(ctx: &Ctx, origin: &Origin, id: &str) -> Result<(PrivateKey, bool)> {
    match ctx.sessions.get(id) {
        Some(data) if data.kind == Some(SessionType::KeyPair) => {
            let key = data.key_pair.ok_or(RpcError::KeyPairByIdIsNotFound)?;
            Ok((key, true))
        }
        Some(data) if data.kind == Some(SessionType::PfxKeyStore) => {
            let path = data.key_store_path.ok_or(RpcError::KeyIdIsNotFound)?;
            let alias = data.key_store_alias.ok_or(RpcError::KeyIdIsNotFound)?;
            let subject = path.display().to_string();
            let store = keystore::open_with_password(ctx, id, origin, &subject, false, move |pw| {
                let bytes = read_key_file(&path)?;
                pkcs12::read(&bytes, pw).map_err(keystore::open_error)
            })
            .await?;
            let entry = store.keys.into_iter().find(|k| k.alias == alias).ok_or(RpcError::KeyIdIsNotFound)?;
            Ok((entry.private_key, false))
        }
        _ => Err(RpcError::KeyIdIsNotFound),
    }
}

async fn save_temporary_pfx(ctx: &Ctx, _origin: &Origin, request: &Request) -> Result<Response> {
    keystore::require_arity(request, 7)?;
    let disk = request.arg(0).to_string();
    let path = request.arg(1).to_string();
    let name = request.arg(2).to_string();
    let alias = request.arg(3).to_string();
    let id = request.arg(4);
    let password = request.arg(5).to_string();
    let subject_x500_name = request.arg(6).to_string();
    keystore::validate_path(&path)?;
    keystore::validate_file_name(&name)?;
    let discovery = ctx.discovery.clone();
    let target = keystore::blocking(move || -> Result<std::path::PathBuf> {
        discovery.resolve(&disk, &path, &name, KeyKind::Pfx).ok_or(RpcError::DiskIsNotFound)
    })
    .await?;

    let key = match ctx.sessions.get(id) {
        Some(data) if data.kind == Some(SessionType::KeyPair) => data.key_pair.ok_or(RpcError::KeyPairByIdIsNotFound)?,
        _ => return Err(RpcError::KeyPairByIdIsNotFound),
    };
    if target.exists() {
        return Err(RpcError::FileExistsChooseOtherName(FILE_EXISTS_SAVE_TEMPORARY_PFX_STATUS));
    }
    let bytes = keystore::blocking(move || -> Result<Vec<u8>> {
        let chain = tempchain::issue(&key.public_key(), &subject_x500_name, &mut OsRng)?;
        let store = Pkcs12Store { keys: vec![KeyEntry { alias, local_key_id: None, private_key: key, chain }], certs: vec![] };
        Ok(pkcs12::write(&store, &password, &mut OsRng)?)
    })
    .await?;
    // The `exists()` check above is worth keeping for the immediate, plain
    // refusal it gives an ordinary caller; `create_key_file_exclusive`
    // closes the race a concurrent creator could otherwise land in between
    // that check and this write, the same way `openimzo-ffi`'s converters do.
    keystore::create_key_file_exclusive(&target, &bytes).await?;
    Ok(Response::success())
}

/// The file read at the front of every `open_with_password` closure in this
/// plugin: this plugin's own missing-file status, not the generic message
/// `keystore::stored_key_and_chain` falls back to.
fn read_key_file(path: &Path) -> std::result::Result<Vec<u8>, keystore::OpenError> {
    std::fs::read(path).map_err(|_| keystore::OpenError::Other(RpcError::KeyFileExists(KEY_FILE_MISSING_STATUS)))
}
