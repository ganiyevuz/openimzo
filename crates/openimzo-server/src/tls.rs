//! The certificate the `wss` listener presents, generated once per install.
//!
//! The key pair is generated on this machine on first start, stored under
//! the app support directory with owner-only permissions, and never leaves
//! it. Per-install and never shipped inside the application, so no two
//! installations share a private key -- a deliberate choice, recorded in
//! the spec's deviations table.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Ten years, as the spec asks.
const VALIDITY_DAYS: i64 = 3650;
// Only the label a person inspecting the certificate sees; `load_or_generate` never
// re-checks an already-stored pair against this constant (see its own doc comment), so
// changing it does not invalidate, and is not read by, any certificate this crate
// already generated under the previous name.
const COMMON_NAME: &str = "OpenImzo";

/// How long a generation lock can sit untouched before it is treated as
/// abandoned by a process that crashed while holding it, rather than a
/// live generation in progress -- which takes milliseconds.
const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);
/// How long, and how often, a process that lost the generation race checks
/// for the winner's pair before giving up.
const LOCK_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(50);
const LOCK_WAIT_RETRIES: u32 = 20;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("could not read or write the TLS material")]
    Storage,
    #[error("could not generate the TLS material")]
    Generate,
    #[error("the stored TLS material is not usable")]
    Invalid,
}

#[derive(Clone)]
pub struct TlsMaterial {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
}

/// Where the certificate lives under `dir`, so a caller can tell a person
/// where to find it without duplicating the filename.
pub fn cert_path(dir: &Path) -> PathBuf {
    dir.join("tls-cert.pem")
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("tls-key.pem")
}

fn lock_path(dir: &Path) -> PathBuf {
    dir.join("tls.lock")
}

/// Reads the stored pair, generating a fresh one if it is missing, empty,
/// or unusable.
///
/// "Unusable" is decided by actually building the server configuration
/// from it -- the same check that would otherwise fail much later, when
/// the listener starts, and the only way to see that the key matches the
/// certificate. A pair a crash left half-written fails that the same way
/// a mismatched pair from two racing generations does, so both self-heal
/// the same way: discard and regenerate, once, rather than leaving the
/// server unable to start again until someone deletes the files by hand.
pub fn load_or_generate(dir: &Path) -> Result<TlsMaterial, TlsError> {
    if let Some(material) = read_pair(dir) {
        match validate(&material) {
            Ok(()) => return Ok(material),
            Err(error) => {
                tracing::debug!(%error, "stored TLS material failed to validate; regenerating");
            }
        }
    }
    let material = generate(dir)?;
    validate(&material)?;
    Ok(material)
}

/// Reads both files, treating either missing or empty as "not there" --
/// the same non-fatal state that sends the caller to `generate`.
fn read_pair(dir: &Path) -> Option<TlsMaterial> {
    let cert_pem = std::fs::read_to_string(cert_path(dir)).ok()?;
    let key_pem = std::fs::read_to_string(key_path(dir)).ok()?;
    if cert_pem.is_empty() || key_pem.is_empty() {
        return None;
    }
    Some(TlsMaterial { cert_pem, key_pem: Zeroizing::new(key_pem) })
}

/// The one place that confirms a pair is actually usable: both the load
/// path and the generate path go through this rather than each carrying
/// their own copy of the check.
fn validate(material: &TlsMaterial) -> Result<(), TlsError> {
    server_config(material).map(|_config| ())
}

/// Makes a fresh pair, serialized against other processes doing the same
/// with a lock file in the same directory: exactly one process creates it
/// (`create_new` fails for everyone else) and generates, while the rest
/// wait briefly and then read what the winner wrote, rather than each
/// generating its own and racing a mismatched certificate and key onto
/// disk.
fn generate(dir: &Path) -> Result<TlsMaterial, TlsError> {
    std::fs::create_dir_all(dir).map_err(|_| TlsError::Storage)?;
    let lock_path = lock_path(dir);
    loop {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&lock_path) {
            Ok(_lock_file) => {
                let result = generate_locked(dir);
                let _ = std::fs::remove_file(&lock_path);
                return result;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if lock_is_stale(&lock_path) {
                    // Whoever created this never cleaned it up, most
                    // likely a crash mid-generation. Clear it and try to
                    // take it ourselves rather than waiting on a process
                    // that no longer exists.
                    let _ = std::fs::remove_file(&lock_path);
                    continue;
                }
                for _ in 0..LOCK_WAIT_RETRIES {
                    std::thread::sleep(LOCK_WAIT_STEP);
                    if let Some(material) = read_pair(dir) {
                        return Ok(material);
                    }
                }
                return Err(TlsError::Storage);
            }
            Err(_) => return Err(TlsError::Storage),
        }
    }
}

fn lock_is_stale(lock_path: &Path) -> bool {
    std::fs::metadata(lock_path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age > LOCK_STALE_AFTER)
}

/// The actual certificate generation, run by whichever process wins the
/// lock in `generate`.
fn generate_locked(dir: &Path) -> Result<TlsMaterial, TlsError> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, COMMON_NAME);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
        SanType::DnsName("localhost".try_into().map_err(|_| TlsError::Generate)?),
    ];
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(VALIDITY_DAYS);

    let key = KeyPair::generate().map_err(|_| TlsError::Generate)?;
    let cert = params.self_signed(&key).map_err(|_| TlsError::Generate)?;
    let cert_pem = cert.pem();
    let key_pem = Zeroizing::new(key.serialize_pem());

    write_atomic(&key_path(dir), key_pem.as_bytes(), true)?;
    write_atomic(&cert_path(dir), cert_pem.as_bytes(), false)?;
    Ok(TlsMaterial { cert_pem, key_pem })
}

/// Writes `bytes` to `path` by building it under a temporary name in the
/// same directory and renaming it over the target, so a reader sees
/// either the previous complete file or the new one, never a half-written
/// one -- a rename within one directory is atomic on every filesystem
/// this project targets. `private` requests owner-only permissions from
/// the moment the temporary file exists, rather than narrowing them
/// afterwards: the certificate's own key, unlike the certificate, must
/// never be readable by anyone but the server, not even for the brief
/// window between the file existing and permissions being tightened on
/// it. The temporary name here is fixed, not randomized: `generate`'s
/// lock already guarantees this is the only process writing here, so
/// nothing else can collide on it.
fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<(), TlsError> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = dir.join(tmp_name);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if private {
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = private;
    }

    // `sync_all`, not just `write_all`: this directory can sit on
    // removable, non-journalled storage same as a `DSKEYS` stick, where
    // the rename below can become durable before the bytes it now points
    // at do. Without this, a power cut in that gap leaves `path` pointing
    // at whatever was already on disk where the temporary file's data
    // should be, not the previous certificate or the new one. Do not
    // remove this as redundant with the rename.
    let write_result = options.open(&tmp_path).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(TlsError::Storage);
    }
    if std::fs::rename(&tmp_path, path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(TlsError::Storage);
    }
    // The rename above is atomic, but the directory entry it changes is
    // its own piece of durable state, separate from the file data
    // `sync_all` above already covers -- on the same kind of
    // non-journalled storage, this is what keeps that entry from
    // outliving a power cut only halfway. Not redundant with the rename
    // itself, which says nothing about durability.
    #[cfg(unix)]
    {
        std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|_| TlsError::Storage)?;
    }
    Ok(())
}

/// The `rustls` configuration the TLS listener serves.
///
/// Builds with an explicit `ring` provider rather than `ServerConfig::builder()`'s
/// process-default one: `openimzo-rpc`'s `reqwest` pulls in `aws-lc-rs` alongside the
/// `ring` this crate asks for, and with both compiled in and no process-wide default
/// installed, `rustls` panics rather than guessing. Naming the provider here keeps
/// this function's behavior independent of what any other crate has (or hasn't)
/// installed as the process default.
pub fn server_config(material: &TlsMaterial) -> Result<std::sync::Arc<rustls::ServerConfig>, TlsError> {
    let certs = rustls_pemfile::certs(&mut material.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::Invalid)?;
    let key = rustls_pemfile::private_key(&mut material.key_pem.as_bytes())
        .map_err(|_| TlsError::Invalid)?
        .ok_or(TlsError::Invalid)?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Invalid)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsError::Invalid)?;
    Ok(std::sync::Arc::new(config))
}

/// Whether this machine's trust store accepts our own certificate, by
/// making a real request to our own TLS listener with the platform roots.
/// A refusal here is the normal state before the user installs it, not an
/// error: the caller turns it into a prompt.
pub async fn probe_trust(port: u16) -> bool {
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(_) => return false,
    };
    client.get(format!("https://127.0.0.1:{port}/")).send().await.is_ok()
}
