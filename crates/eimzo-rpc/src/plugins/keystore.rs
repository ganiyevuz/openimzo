//! Helpers shared by the `pfx` and `ytks` plugins: path/name validation, the
//! password-prompt loop with its caching and 3-attempt retry rules, the
//! chain and public-key checks `save_pfx` / `save_ytks` both run before
//! writing a new file, the atomic rewrite `change_password` uses to replace
//! one in place, and the one place a blocking body is handed to the
//! runtime's blocking pool.
//!
//! What differs between the two formats — listing a file's aliases without a
//! password, and which `SessionType` a loaded key becomes — stays in
//! `pfx.rs` and `ytks.rs`.

use crate::dispatch::Ctx;
use crate::error::{Result, RpcError};
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::ui::PasswordRequest;
use eimzo_crypto::PrivateKey;
use eimzo_keys::session::{PASSWORD_TTL_REMEMBERED, PASSWORD_TTL_TRANSIENT};
use eimzo_keys::{KeyInfo, SessionType};
use eimzo_pki::pkcs12;
use eimzo_pki::ytks::{self, YtksEntry};
use rand::RngCore;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use x509_cert::Certificate;
use zeroize::Zeroizing;

/// Runs a blocking body on the runtime's blocking pool.
///
/// Reading a key file, parsing a keystore and signing are all CPU- or
/// disk-bound and take milliseconds to seconds. Left inline in an async
/// handler they pin a worker thread, so one listing over a slow volume or
/// one signature stalls every other connection. Every such body in this
/// crate goes through here.
///
/// A panic inside the body, or a runtime shutting down, surfaces as a
/// generic runtime error rather than unwinding into the connection.
pub(super) async fn blocking<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!(error = %e, "blocking task failed");
            Err(RpcError::Runtime("operation failed".into()))
        }
    }
}

/// `path` must be `""` or `DSKEYS`, matching the original.
pub(super) fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || path == "DSKEYS" {
        Ok(())
    } else {
        Err(RpcError::InvalidArgPath)
    }
}

/// A new key file's name, checked before `save_pfx` / `save_ytks` /
/// `save_temporary_pfx` create one.
pub(super) fn validate_file_name(name: &str) -> Result<()> {
    if !name.is_empty() && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(RpcError::FileNameHasBadChars)
    }
}

/// Replaces `path`'s content with `bytes` without ever leaving it
/// half-written. `change_password`, in both `pfx.rs` and `ytks.rs`, is
/// rewriting the one file that holds a citizen's private key — often on a
/// removable stick — so power pulled mid-write must not cost the key. The
/// new bytes go to a freshly named temporary file in `path`'s own directory
/// first; only then does a rename replace `path`, which is atomic on every
/// filesystem this project targets, so either the old file or the complete
/// new one survives, never a truncated one. The temporary file is removed
/// if anything fails before the rename. No backup of the old content is
/// kept: a second copy of a private key on a shared stick is its own
/// problem.
///
/// The temporary file is created with owner-only permissions from the
/// moment it exists, matching `create_key_file_exclusive` below for the
/// same reason: this is a private key, and the rename that puts it in
/// place carries those permissions with it, so there is no later moment
/// that narrows a mode the destination might otherwise have inherited
/// looser.
///
/// Runs on the blocking pool: every step here is disk I/O.
///
/// `pub`, not `pub(super)` like the rest of this module: `eimzo-ffi`'s own
/// `Engine::change_password` reuses this directly rather than a second
/// implementation, per the same reasoning as the doc comment above — it is
/// rewriting the same kind of file, on the same kind of removable disk.
pub async fn overwrite_key_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    blocking(move || {
        let dir = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let mut suffix = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(format!(".tmp-{}", hex::encode(suffix)));
        let tmp_path = dir.join(tmp_name);
        let write_key_file_failed = || RpcError::Runtime("failed to write key file".into());

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // `sync_all`, not just `write_all`: a `DSKEYS` stick is typically
        // FAT, which is not journalled, so the rename below can become
        // durable before the bytes it now points at do. Without this, a
        // power cut in exactly that gap leaves `path` pointing at whatever
        // garbage was already on disk where the temporary file's data
        // should be -- worse than either the old key surviving or the new
        // one landing. Do not remove this as redundant with the rename.
        let write_result = options.open(&tmp_path).and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        });
        if let Err(e) = write_result {
            tracing::debug!(error = %e, "failed to write temporary key file");
            let _ = std::fs::remove_file(&tmp_path);
            return Err(write_key_file_failed());
        }
        if let Err(e) = std::fs::rename(&tmp_path, &path) {
            tracing::debug!(error = %e, "failed to replace key file with its rewritten temporary copy");
            let _ = std::fs::remove_file(&tmp_path);
            return Err(write_key_file_failed());
        }
        // The rename above is atomic, but the directory entry it changes
        // is its own piece of durable state, separate from the file data
        // `sync_all` above already covers -- on the same kind of
        // non-journalled FAT stick, this is what keeps that entry from
        // outliving a power cut only halfway. Not redundant with the
        // rename itself, which says nothing about durability.
        #[cfg(unix)]
        {
            if let Err(e) = std::fs::File::open(&dir).and_then(|d| d.sync_all()) {
                tracing::debug!(error = %e, "failed to sync key file's directory");
                return Err(write_key_file_failed());
            }
        }
        Ok(())
    })
    .await
}

/// Writes `bytes` to `path`, but — unlike `overwrite_key_file` above, which
/// replaces whatever it finds — refuses outright if anything is already
/// there. Use this, not `overwrite_key_file`, whenever the destination must
/// not exist: `convert_pfx_to_yks` and `convert_yks_to_pfx`, in
/// `eimzo-ffi`'s `engine.rs`, write their converted output through this.
///
/// Both converters already check `output.exists()` before this is ever
/// called, and that check is worth keeping: it gives an ordinary caller an
/// immediate, plain refusal. But it runs on the calling task, long before
/// the blocking task that reads the input, decrypts it and re-encrypts it
/// (password-based key derivation, in particular, is not instantaneous)
/// even starts. A file created at `path` during that gap would still be
/// silently replaced were the eventual write an ordinary
/// `overwrite_key_file` call — the check would be true sequentially and
/// false under a race. This function is the backstop that closes that
/// race rather than narrowing it: the destination is never opened for
/// writing except through an exclusive create, so it is the operating
/// system itself that refuses a concurrent creator, atomically, rather
/// than a check this code ran a moment earlier.
///
/// As with `overwrite_key_file`, the new bytes go to a freshly named
/// temporary file in `path`'s own directory first, so a crash mid-write
/// costs only the temporary. Getting the temporary into place, though,
/// cannot be a `rename` — a rename replaces whatever already sits at the
/// destination, which is exactly what must not happen here. Instead the
/// temporary is `hard_link`ed to `path`: like a `create_new` open,
/// `hard_link` fails with `AlreadyExists` if `path` already exists, and
/// does so atomically — the filesystem either creates the new directory
/// entry or it does not, with no window a concurrent creator could land
/// in. The temporary's own name is then removed, leaving `path` as the
/// only surviving name for the data (or, if that last removal itself
/// fails, leaving a harmless leftover temporary next to the now-correct
/// `path` — nothing about `path` itself is at risk either way).
///
/// FAT32 and exFAT — what a `DSKEYS` stick is normally formatted as — do not
/// support hard links at all: confirmed by running this function against
/// disk images of both, where `hard_link` fails on every attempt with
/// `ENOTSUP`, regardless of whether `path` already exists. When that specific
/// failure is what `hard_link` reports, this function falls back to a check
/// followed by a plain rename instead of treating it as an ordinary error —
/// see the comment at that fallback for how much weaker its guarantee is and
/// why it is accepted anyway. Every other `hard_link` failure, including the
/// destination already existing, is unaffected and behaves exactly as
/// described above.
///
/// The temporary file is created with owner-only permissions from the
/// moment it exists, matching `eimzo-server`'s own `write_atomic` for the
/// same reason: this is a private key, and there is no window in which it
/// should be readable by anyone else, however brief.
///
/// Runs on the blocking pool, like `overwrite_key_file`.
pub async fn create_key_file_exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    blocking(move || {
        let dir = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let mut suffix = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(format!(".tmp-{}", hex::encode(suffix)));
        let tmp_path = dir.join(tmp_name);
        let write_key_file_failed = || RpcError::Runtime("failed to write key file".into());

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // See `overwrite_key_file`'s identical comment: without `sync_all`
        // here, the `hard_link` below can outlive the data it points at on
        // a non-journalled FAT stick, and a power cut in that gap leaves
        // `path` linked to whatever garbage was already there instead of
        // either nothing or the new key.
        let write_result = options.open(&tmp_path).and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        });
        if let Err(e) = write_result {
            tracing::debug!(error = %e, "failed to write temporary key file");
            let _ = std::fs::remove_file(&tmp_path);
            return Err(write_key_file_failed());
        }

        match std::fs::hard_link(&tmp_path, &path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&tmp_path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(RpcError::KeyFileAlreadyExists(path.display().to_string()));
            }
            Err(e) if hard_link_unsupported(&e) => {
                // FAT32 and exFAT do not support hard links at all: writing
                // through this function against disk images of both showed
                // `hard_link` failing with `ENOTSUP` on every attempt, never
                // reaching the point of even checking whether `path` exists.
                // Since a `DSKEYS` stick is normally one of these two
                // formats, treating this the same as any other `hard_link`
                // failure would mean saving a new key -- and both key-format
                // conversions, which also write through this function --
                // fail outright on the exact hardware this program exists to
                // serve.
                //
                // The fallback is a plain existence check followed by a
                // `rename`, and it is weaker than the link on purpose: a
                // file created at `path` in the gap between the check and
                // the rename is silently replaced, which is precisely the
                // race the `hard_link` path above closes atomically. That
                // gap is accepted here only because the alternative is this
                // function not working at all on the filesystem these keys
                // actually live on -- not because the two guarantees are the
                // same.
                if path.exists() {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(RpcError::KeyFileAlreadyExists(path.display().to_string()));
                }
                if let Err(e) = std::fs::rename(&tmp_path, &path) {
                    tracing::debug!(error = %e, "failed to move temporary key file into place");
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(write_key_file_failed());
                }
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                tracing::debug!(error = %e, "failed to link temporary key file into place");
                return Err(write_key_file_failed());
            }
        }
        // Same reasoning as `overwrite_key_file`: the directory entry the
        // `hard_link` (or, on FAT/exFAT, the rename fallback) above just
        // added is its own piece of durable state, and on a non-journalled
        // FAT stick it can outlive the data it points at without this sync.
        // Not redundant with the link or rename itself.
        #[cfg(unix)]
        {
            if let Err(e) = std::fs::File::open(&dir).and_then(|d| d.sync_all()) {
                tracing::debug!(error = %e, "failed to sync key file's directory");
                return Err(write_key_file_failed());
            }
        }
        Ok(())
    })
    .await
}

/// `ENOTSUP` on the unix targets this crate builds for today — macOS, where
/// `create_key_file_exclusive`'s doc comment above records that a `hard_link`
/// on a FAT32 or exFAT disk image raised raw OS error `45`; and Linux, whose
/// libc defines `ENOTSUP` as `EOPNOTSUPP`, both `95`. A local constant
/// instead of pulling in the `libc` crate for one errno this crate otherwise
/// has no use for; add a case here rather than reaching for that crate if a
/// future unix target this project ships for turns out to need a third
/// value.
#[cfg(target_os = "linux")]
const ENOTSUP: i32 = 95;
#[cfg(all(unix, not(target_os = "linux")))]
const ENOTSUP: i32 = 45;

/// Whether `e`, from the `hard_link` attempt in `create_key_file_exclusive`,
/// means the filesystem does not support hard links at all, rather than an
/// ordinary failure such as the destination already existing.
///
/// `std::io::ErrorKind::Unsupported` is the portable spelling of this, but
/// running that call against FAT32 and exFAT disk images on this platform
/// showed the underlying `ENOTSUP` coming back as `ErrorKind::Uncategorized`
/// instead, with the raw OS error still `45` (`ENOTSUP`) underneath. Both
/// checks stay: the `kind()` check for whatever platform maps it correctly,
/// the raw-errno check for this one, which does not. Nothing else should
/// take this branch — a full disk, a permissions problem, or the destination
/// genuinely already existing must keep surfacing as the error it always
/// has.
fn hard_link_unsupported(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(unix)]
    {
        if e.raw_os_error() == Some(ENOTSUP) {
            return true;
        }
    }
    false
}

/// Some functions declare an optional argument ahead of required ones
/// (`path` sits between `disk` and `name`), which the dispatcher's arity
/// check does not model — it only knows the overall count is in range, not
/// which position was skipped. The original always demands the exact count;
/// a short call here would otherwise read `path`'s slot as `name`. Handlers
/// for such functions call this instead of trusting the dispatcher alone.
pub(super) fn require_arity(request: &Request, expected: usize) -> Result<()> {
    if request.arguments.len() == expected {
        Ok(())
    } else {
        Err(RpcError::FunctionNotFound)
    }
}

/// `certificates: [KeyInfo, …]` — the shape `list_certificates` and
/// `list_all_certificates` share in both plugins.
pub(super) fn certificates_response(list: Vec<KeyInfo>) -> Result<Response> {
    let value = serde_json::to_value(&list).map_err(|e| {
        tracing::debug!(error = %e, "could not serialize certificates list");
        RpcError::Runtime("could not serialize certificates list".into())
    })?;
    Ok(Response::success().with("certificates", value))
}

/// Whether `id` names a live session of exactly `want`'s type. Folds "no such
/// session" and "wrong type" into the one status/message the original's own
/// per-plugin session lookup raises for both (`missing_status` is `-1014`
/// for `pfx`, `-1013` for `ytks`).
pub(super) fn require_keystore_type(ctx: &Ctx, id: &str, want: SessionType, missing_status: i32) -> Result<()> {
    match ctx.sessions.type_of(id) {
        Some(kind) if kind == want => Ok(()),
        _ => Err(RpcError::KeyIdOfTypeIsNotFound(want.wire_name().to_string(), missing_status)),
    }
}

/// As `require_keystore_type`, but also returns the file path and alias a
/// `load_key` session recorded — `verify_password` and `change_password`
/// both need to reopen that file.
pub(super) fn require_keystore_session(
    ctx: &Ctx,
    id: &str,
    want: SessionType,
    missing_status: i32,
) -> Result<(PathBuf, String)> {
    let not_found = || RpcError::KeyIdOfTypeIsNotFound(want.wire_name().to_string(), missing_status);
    let data = ctx.sessions.get(id).filter(|d| d.kind == Some(want)).ok_or_else(not_found)?;
    match (data.key_store_path, data.key_store_alias) {
        (Some(path), Some(alias)) => Ok((path, alias)),
        _ => Err(not_found()),
    }
}

/// What a password-attempt closure passed to `open_with_password` reports.
/// Not `eimzo_pki::PkiError` directly: the closure also covers the file
/// read that opening a keystore starts with, and each caller needs its own
/// status for *that* failing (`-2002` for `pfx`, `-2010` for `ytks`, a fixed
/// generic message for `stored_key_and_chain`) rather than one mapping that
/// would have to serve all of them at once.
pub(super) enum OpenError {
    /// The wrong password: retried up to `open_with_password`'s own limit.
    WrongPassword,
    /// Anything else — a missing file, corrupted data — is not retried.
    Other(RpcError),
}

/// `eimzo_pki::PkiError` to `OpenError`, for the parse step of an
/// `open_with_password` closure: a wrong password is still distinguished
/// from every other failure, everything else becomes the same `Runtime`
/// message the original conversion (`impl From<PkiError> for RpcError`)
/// would produce.
pub(super) fn open_error(e: eimzo_pki::PkiError) -> OpenError {
    match e {
        eimzo_pki::PkiError::PasswordIncorrect => OpenError::WrongPassword,
        other => OpenError::Other(other.into()),
    }
}

/// Asks for the password that opens session `id`'s file, retrying up to
/// three times on a wrong password, matching the original. Unless
/// `force`, a cached password is tried first, and a password that opens the
/// file is cached in turn — for 6 hours if the user asked to remember it,
/// for 1 minute otherwise, matching the original. `force` skips the cache in
/// both directions: this is `verify_password`'s "always prompts and never
/// remembers".
///
/// `open` does the actual file read and parse/decrypt for one password
/// attempt, and runs on the blocking pool: reading the file and opening it
/// (a password-based decrypt) are both included, so a single hop covers
/// both rather than splitting them across two round trips to the pool. It
/// must be `Fn`, not `FnMut` — it may be tried more than once, from more
/// than one blocking task — and owns everything it touches so a fresh task
/// can run it: a caller building it over a path clones that path in first
/// (`move |pw| { ... }`).
pub(super) async fn open_with_password<T, F>(
    ctx: &Ctx,
    id: &str,
    origin: &Origin,
    subject: &str,
    force: bool,
    open: F,
) -> Result<T>
where
    T: Send + 'static,
    F: Fn(&str) -> std::result::Result<T, OpenError> + Send + Sync + 'static,
{
    let open = Arc::new(open);
    // Settings' own "remember passwords" toggle is a second, independent
    // reason never to cache, alongside `force` (`verify_password`'s "always
    // prompts and never remembers"): either one turns this off.
    let may_remember = !force && *ctx.remember_passwords.read();
    if !force {
        if let Some(cached) = ctx.sessions.cached_password(id) {
            let open = Arc::clone(&open);
            match blocking(move || Ok(open(&cached))).await? {
                Ok(value) => return Ok(value),
                Err(OpenError::WrongPassword) => ctx.sessions.expire_password(id),
                Err(OpenError::Other(e)) => return Err(e),
            }
        }
    }
    let mut last_error = None;
    // Attempts are capped at 3, after which the call answers -5000 rather
    // than leaving the page waiting on a reply that never comes.
    for _ in 0..3 {
        let request = PasswordRequest {
            origin: origin.domain.clone(),
            subject: subject.to_string(),
            error: last_error.take(),
            allow_remember: may_remember,
        };
        let answer = ctx.ui.ask_password(request).await.map_err(|_| RpcError::PasswordEnterCanceled)?;
        let attempt_password = answer.password.clone();
        let open = Arc::clone(&open);
        match blocking(move || Ok(open(&attempt_password))).await? {
            Ok(value) => {
                if may_remember {
                    let ttl = if answer.remember { PASSWORD_TTL_REMEMBERED } else { PASSWORD_TTL_TRANSIENT };
                    ctx.sessions.remember_password(id, &answer.password, ttl);
                }
                return Ok(value);
            }
            Err(OpenError::WrongPassword) => {
                last_error = Some(ctx.t("key.password.is.incorrect.or.key.file.is.corrupted"));
            }
            Err(OpenError::Other(e)) => return Err(e),
        }
    }
    Err(RpcError::PasswordEnterCanceled)
}

/// A single fresh password prompt for a value that is not opening anything —
/// the two new-password entries in `change_password`. Never checks or fills
/// the session's password cache, matching the original's own two-argument
/// password prompt: always prompts, never caches, no checkbox.
pub(super) async fn ask_new_password(ctx: &Ctx, origin: &Origin, subject: &str) -> Result<Zeroizing<String>> {
    let request =
        PasswordRequest { origin: origin.domain.clone(), subject: subject.to_string(), error: None, allow_remember: false };
    let answer = ctx.ui.ask_password(request).await.map_err(|_| RpcError::PasswordEnterCanceled)?;
    Ok(answer.password)
}

/// `subject` must be signed by `ca`, `ca` by `root`, and `root` by itself —
/// the chain check `save_pfx` / `save_ytks` run before writing a new file.
pub(super) fn verify_chain(subject: &Certificate, ca: &Certificate, root: &Certificate) -> Result<()> {
    require_signed_by(subject, ca, "subject")?;
    require_signed_by(ca, root, "CA")?;
    require_signed_by(root, root, "root")?;
    Ok(())
}

fn require_signed_by(child: &Certificate, issuer: &Certificate, what: &'static str) -> Result<()> {
    if eimzo_pki::x509::verify_certificate_signature(child, issuer)? {
        Ok(())
    } else {
        Err(RpcError::Runtime(format!("{what} certificate is not signed by the certificate presented for it")))
    }
}

/// The session's key must be the subject certificate's public key. An exact
/// match succeeds; a mismatch where both keys are on the same curve family
/// reports both points' coordinates (`-2020`); anything else — a different
/// algorithm or curve, or a certificate whose public key cannot be read at
/// all — is the plainer `-2021`.
pub(super) fn check_key_matches_certificate(private: &PrivateKey, subject_certificate: &Certificate) -> Result<()> {
    let session_key = private.public_key();
    let cert_key = eimzo_pki::x509::public_key(subject_certificate)?;
    if session_key == cert_key {
        return Ok(());
    }
    if session_key.family == cert_key.family && session_key.curve == cert_key.curve {
        return Err(RpcError::PublicKeyDoesNotMatch {
            expected_x: session_key.point.x.to_str_radix(16),
            expected_y: session_key.point.y.to_str_radix(16),
            cert_x: cert_key.point.x.to_str_radix(16),
            cert_y: cert_key.point.y.to_str_radix(16),
        });
    }
    Err(RpcError::PublicKeyDoesNotMatchPrivate)
}

/// The four hardware/device session types. `pkcs7`, `pkcs10` and `x509` each
/// answer these with the same stand-in error until phase 6 wires up the real
/// device flow.
pub(super) fn is_device_session(kind: SessionType) -> bool {
    matches!(
        kind,
        SessionType::IdcardKeyStore | SessionType::BaikTokenKeyStore | SessionType::UzguardTokenKeyStore | SessionType::CkcStore
    )
}

/// The text the original's device flow will eventually report once phase 6
/// lands; shared by every plugin that has to answer a device session type
/// meanwhile.
pub(super) const DEVICE_NOT_FOUND: &str = "Устройство не найдено";

/// The private key and certificate chain behind a `PFX_KEY_STORE` or
/// `YTKS_KEY_STORE` session, after a password prompt (cached allowed,
/// remember allowed). Shared by `pkcs7::create_pkcs7`,
/// `pkcs10::create_pkcs10_from_key` and `x509::get_certificate_chain`, all of
/// which need to open whichever file format the session's key happens to
/// live in — callers check the session's type themselves first, so any other
/// type reaching here (including a session that has since expired) is just
/// `KeyIdIsNotFound`.
///
/// A file that has gone missing since `load_key` is a plain `Runtime` error
/// here, not `pfx`/`ytks`'s own `-2002`/`-2010` status: the original's own
/// `create_pkcs7` / `create_pkcs10_from_key` / `get_certificate_chain` read
/// the file from inside the password handler, where a missing file falls
/// into the same broad catch as every other I/O or crypto failure. The read
/// and the parse run together, on the blocking pool, for the same reason
/// `open_with_password` itself does.
pub(super) async fn stored_key_and_chain(ctx: &Ctx, origin: &Origin, id: &str) -> Result<(PrivateKey, Vec<Certificate>)> {
    let data = ctx.sessions.get(id).ok_or(RpcError::KeyIdIsNotFound)?;
    let path = data.key_store_path.ok_or(RpcError::KeyIdIsNotFound)?;
    let alias = data.key_store_alias.ok_or(RpcError::KeyIdIsNotFound)?;
    let subject = path.display().to_string();
    match data.kind {
        Some(SessionType::PfxKeyStore) => {
            let path_for_read = path.clone();
            let store = open_with_password(ctx, id, origin, &subject, false, move |pw| {
                let bytes = read_for_missing_key_file(&path_for_read)?;
                pkcs12::read(&bytes, pw).map_err(open_error)
            })
            .await?;
            let entry = store.keys.into_iter().find(|k| k.alias == alias).ok_or(RpcError::KeyIdIsNotFound)?;
            Ok((entry.private_key, entry.chain))
        }
        Some(SessionType::YtksKeyStore) => {
            let path_for_read = path.clone();
            let store = open_with_password(ctx, id, origin, &subject, false, move |pw| {
                let bytes = read_for_missing_key_file(&path_for_read)?;
                ytks::read(&bytes, pw).map_err(open_error)
            })
            .await?;
            for entry in store.entries {
                if let YtksEntry::Key { alias: entry_alias, private_key, chain, .. } = entry {
                    if entry_alias == alias {
                        return Ok((private_key, chain));
                    }
                }
            }
            Err(RpcError::KeyIdIsNotFound)
        }
        _ => Err(RpcError::KeyIdIsNotFound),
    }
}

/// The file read at the bottom of `stored_key_and_chain`'s two closures: a
/// generic `Runtime` message regardless of which plugin's session led here,
/// since this helper is shared across plugins that never had their own
/// distinct status for it (contrast `pfx`/`ytks`'s own `load_key`, which do).
fn read_for_missing_key_file(path: &Path) -> std::result::Result<Vec<u8>, OpenError> {
    std::fs::read(path).map_err(|e| {
        tracing::debug!(error = %e, "key file could not be read");
        OpenError::Other(RpcError::Runtime("key file could not be read".into()))
    })
}
