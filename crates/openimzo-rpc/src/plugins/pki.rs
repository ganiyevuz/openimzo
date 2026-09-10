//! The PFX enrollment wizard: a two-step flow that hands a site a CSR and a
//! temporary signature in step 1, then writes the CA-issued PFX to disk in
//! step 2. `fixtures/apidoc-original-uz.json`'s `pki` entry is the wire
//! contract.

use crate::dispatch::{gate_for, Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::keystore;
use crate::plugins::{arg, pkcs10};
use crate::ui::NewPfxRequest;
use base64::Engine as _;
use const_oid::ObjectIdentifier;
use openimzo_crypto::PrivateKey;
use openimzo_keys::discovery::DSKEYS;
use openimzo_keys::KeyKind;
use openimzo_pki::pkcs12::{self, KeyEntry, Pkcs12Store};
use openimzo_pki::{cms, pkcs10 as csr, tempchain, x509};
use rand_core::OsRng;
use serde_json::Value;
use std::time::SystemTime;
use zeroize::Zeroizing;

/// Everything `enroll_pfx_step2` needs that `enroll_pfx_step1` already
/// decided: which disk and file name the site chose (via `NewPfxRequest`)
/// and the key pair generated for the CSR. Kept in `Ctx::enrollments`,
/// keyed by the site's domain and guid, until step 2 either consumes it, it
/// expires, or the site abandons it.
pub struct Enrollment {
    disk: String,
    file_name: String,
    private_key: PrivateKey,
    password: Zeroizing<String>,
    /// When this attempt stops being usable. A site that starts an enrolment
    /// and never finishes it must not pin a private key in memory for the
    /// life of the process.
    expires: std::time::Instant,
}

/// How long a half-finished enrolment stays usable. Long enough for a person
/// to work through a certificate authority's web form, short enough that an
/// abandoned attempt does not linger.
pub const ENROLLMENT_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// The map key: an enrolment is owned by the site that started it.
fn enrollment_key(origin: &Origin, guid: &str) -> (String, String) {
    (origin.domain.clone(), guid.to_string())
}

/// Drops enrolments whose deadline has passed, so an abandoned attempt does
/// not hold its private key, and reclaims every enrolment turnstile nobody
/// is currently waiting on (the same reclaim rule as `origin.rs`'s own gate
/// map). Called at the start of step one so the map is tidied on the path a
/// site actually exercises, and from `Dispatcher::sweep`'s timer.
pub fn sweep_enrollments(ctx: &Ctx) {
    let now = std::time::Instant::now();
    ctx.enrollments.lock().retain(|_, e| e.expires > now);
    ctx.enrollment_gates.lock().retain(|_, gate| std::sync::Arc::strong_count(gate) > 1);
}

pub fn functions() -> Vec<FunctionSpec> {
    vec![
        function!(
            "pki",
            "enroll_pfx_step2",
            "Шаг №2 для получения ключа PFX",
            [
                arg("guid", "Идентификатор процесса GUID (полученный из Шага №1)"),
                arg("subject_certificate_64", "Сертификат субъекта в кодировке BASE64"),
                arg("ca_certificate_64", "Сертификат Центра Регистрации в кодировке BASE64"),
                arg("root_certificate_64", "Корневой сертификат в кодировке BASE64"),
                arg(
                    "data_64",
                    "Данные в кодировке BASE64 (будут предваритьльно декодированы, подписаны и вложены в документ)"
                ),
            ],
            enroll_pfx_step2
        ),

        function!(
            "pki",
            "enroll_pfx_step1",
            "Шаг №1 для получения ключа PFX",
            [
                arg("guid", "Идентификатор процесса GUID"),
                arg("alg_name", "Название алгоритма"),
                arg("seed", "Случайные данные для инициализации генератора случайных чисел"),
                arg("subject_x500_name", "Имя субъекта в формате X.500"),
                arg("cp_list", "OIDы политик применения сертификатов разделенных запятой"),
                arg("file_name", "Имя файла без расширения (если тип носителя ключа - файл)"),
                arg(
                    "data_64",
                    "Данные в кодировке BASE64 (будут предваритьльно декодированы, подписаны и вложены в документ)"
                ),
            ],
            enroll_pfx_step1
        ),
    
    ]
}

/// `cp_list` split into policy OIDs. Unlike `pkcs10::create_pkcs10`, where an
/// empty list just means "no policies", enrollment always issues a real
/// certificate and requires at least one — an empty argument is `-1023`,
/// the same status `pkcs10::build`'s own empty-policy path never reaches
/// (this function refuses the empty case before that code runs).
fn parse_required_cp_list(cp_list: &str) -> Result<Vec<String>> {
    if cp_list.is_empty() {
        return Err(RpcError::CertificatePoliciesNotPassed);
    }
    cp_list
        .split(',')
        .map(|raw| {
            ObjectIdentifier::new(raw).map_err(|_| RpcError::InvalidCertificatePolicyOid)?;
            Ok(raw.to_string())
        })
        .collect()
}

async fn enroll_pfx_step1(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let guid = request.arg(0);
    let alg_name = request.arg(1);
    // `seed` (arg 2) is accepted for wire compatibility but never used; see
    // `pkcs10::generate_key`.
    let subject_x500_name = request.arg(3);
    let cp_list = parse_required_cp_list(request.arg(4))?;
    let file_name = request.arg(5);
    let data_64 = request.arg(6);

    sweep_enrollments(ctx);
    let map_key = enrollment_key(origin, guid);
    // Cheap fast path: skip the turnstile entirely when the guid is already
    // known to be taken.
    if ctx.enrollments.lock().contains_key(&map_key) {
        return Err(RpcError::ProcessIdAlreadyExists);
    }
    keystore::validate_file_name(file_name)?;
    // A disk listing walks the filesystem for mounted volumes, so it runs on
    // the blocking pool like every other `Discovery` call.
    let discovery = ctx.discovery.clone();
    let disks = keystore::blocking(move || -> Result<Vec<String>> { Ok(discovery.list_disks()) }).await?;
    if disks.is_empty() {
        return Err(RpcError::PlugInUsbDiskAndRetry);
    }

    // One `enroll_pfx_step1` at a time per (site, guid): without this, two
    // calls carrying the same identifier both pass the check above, both run
    // the dialog and key generation, and the second silently overwrites the
    // first's entry, leaving the loser's reply naming a key that no longer
    // exists (a recorded follow-up). Held until
    // after the insert below.
    let gate = gate_for(&ctx.enrollment_gates, &map_key);
    let _turn = gate.lock().await;
    // Another call for this same (site, guid) may have finished while this
    // one waited for the turn.
    if ctx.enrollments.lock().contains_key(&map_key) {
        return Err(RpcError::ProcessIdAlreadyExists);
    }

    let answer = ctx
        .ui
        .ask_new_pfx(NewPfxRequest { origin: origin.domain.clone(), disks, file_path: format!("{DSKEYS}/{file_name}.pfx") })
        .await
        .map_err(|_| RpcError::PasswordEnterCanceled)?;

    let key = pkcs10::generate_key(ctx, origin, alg_name).await?;
    let data = base64::engine::general_purpose::STANDARD.decode(data_64).map_err(|e| RpcError::Runtime(e.to_string()))?;

    // The CSR, the temporary self-signed chain and the temporary signature
    // are all CPU-bound signing work with no `.await` between them, so one
    // hop to the blocking pool covers all three.
    let key_for_work = key.clone();
    let subject_owned = subject_x500_name.to_string();
    let (pkcs10_der, temp_chain, pkcs7_der) = keystore::blocking(move || -> Result<(Vec<u8>, Vec<x509_cert::Certificate>, Vec<u8>)> {
        let pkcs10_der = csr::build(&key_for_work, &subject_owned, &cp_list, &mut OsRng)?;
        let temp_chain = tempchain::issue(&key_for_work.public_key(), &subject_owned, &mut OsRng)?;
        let pkcs7_der = cms::sign(&data, true, &key_for_work, &temp_chain, SystemTime::now(), &mut OsRng)?;
        Ok((pkcs10_der, temp_chain, pkcs7_der))
    })
    .await?;

    let mut response = Response::success()
        .with("guid", Value::String(guid.to_string()))
        .with("pkcs10_64", Value::String(base64::engine::general_purpose::STANDARD.encode(&pkcs10_der)))
        .with("pkcs7_64", Value::String(base64::engine::general_purpose::STANDARD.encode(&pkcs7_der)))
        .with("password", Value::String(answer.password.to_string()))
        .with("disk", Value::String(answer.disk.clone()));
    if guid.contains("test") {
        // `tempchain::issue` always returns exactly `[subject, ca, root]`, but
        // this avoids indexing into it even so — no slice indexing in this
        // crate, full stop.
        let [subject_temp, ca_temp, root_temp] = temp_chain.as_slice() else {
            return Err(RpcError::Runtime("temporary chain has an unexpected shape".into()));
        };
        let der = |c: &x509_cert::Certificate| -> Result<String> {
            use der::Encode;
            c.to_der().map(|d| base64::engine::general_purpose::STANDARD.encode(d)).map_err(|e| RpcError::Runtime(e.to_string()))
        };
        response = response
            .with("tempUserCertificate", Value::String(der(subject_temp)?))
            .with("tempCACertificate", Value::String(der(ca_temp)?))
            .with("tempRootCertificate", Value::String(der(root_temp)?));
    }

    ctx.enrollments.lock().insert(
        map_key,
        Enrollment {
            disk: answer.disk,
            file_name: file_name.to_string(),
            private_key: key,
            password: answer.password,
            expires: std::time::Instant::now() + ENROLLMENT_TTL,
        },
    );
    Ok(response)
}

async fn enroll_pfx_step2(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let guid = request.arg(0);
    let map_key = enrollment_key(origin, guid);

    // Looked up before the certificate arguments are even parsed, so an
    // unknown guid is always `-2025` regardless of what else the call sent —
    // matching `enroll_pfx_step1`'s own check-first-generate-later shape.
    // Peeked, not removed: a failed verification below must leave the guid
    // usable for a retry with corrected certificates. Only a successful
    // finish drops the entry. An entry past its deadline is removed here and
    // treated the same as one that never existed.
    let (disk, file_name, private_key, password) = {
        let mut enrollments = ctx.enrollments.lock();
        match enrollments.get(&map_key) {
            Some(e) if e.expires > std::time::Instant::now() => {
                (e.disk.clone(), e.file_name.clone(), e.private_key.clone(), e.password.clone())
            }
            Some(_) => {
                enrollments.remove(&map_key);
                return Err(RpcError::ProcessIdentifierNotFound);
            }
            None => return Err(RpcError::ProcessIdentifierNotFound),
        }
    };

    let subject_certificate = x509::parse_certificate_any(request.arg(1).as_bytes())?;
    let ca_certificate = x509::parse_certificate_any(request.arg(2).as_bytes())?;
    let root_certificate = x509::parse_certificate_any(request.arg(3).as_bytes())?;
    let data = base64::engine::general_purpose::STANDARD.decode(request.arg(4)).map_err(|e| RpcError::Runtime(e.to_string()))?;

    keystore::verify_chain(&subject_certificate, &ca_certificate, &root_certificate)?;
    keystore::check_key_matches_certificate(&private_key, &subject_certificate)?;

    let discovery = ctx.discovery.clone();
    let target = keystore::blocking(move || -> Result<std::path::PathBuf> {
        discovery.resolve(&disk, DSKEYS, &file_name, KeyKind::Pfx).ok_or(RpcError::DiskIsNotFound)
    })
    .await?;
    let view = x509::certificate_view(&subject_certificate)?;
    let alias = format!("{},SERIALNUMBER={},VALIDFROM={},VALIDTO={}", view.subject_name, view.serial_number, view.valid_from, view.valid_to);

    let chain = vec![subject_certificate, ca_certificate, root_certificate];
    let store = Pkcs12Store { keys: vec![KeyEntry { alias: alias.clone(), local_key_id: None, private_key: private_key.clone(), chain: chain.clone() }], certs: vec![] };
    // A freshly chosen disk may not have a `DSKEYS` folder yet — the
    // enrollment wizard is exactly how one is meant to gain its first key,
    // unlike `pfx.save_pfx`, which only ever targets a folder `list_disks`
    // has already reported (and so already exists). Encoding the PFX and
    // creating that folder are sequential, blocking work with no `.await`
    // between them, so they share one hop to the blocking pool. The write
    // itself then goes through `keystore::overwrite_key_file` — the same
    // temp-then-rename helper `pfx`/`ytks`'s own handlers already use —
    // rather than a plain, non-atomic `std::fs::write`, so this brand-new
    // key file lands owner-only from the moment it exists, matching every
    // other private key this workspace writes. `overwrite_key_file`
    // replaces whatever it finds rather than refusing, matching this call
    // site's own prior behaviour of silently overwriting a same-named
    // file; `create_key_file_exclusive` would instead turn that case into
    // a new `KeyFileAlreadyExists` error this caller has never seen from
    // here. `overwrite_key_file` is async, so it is awaited on its own,
    // outside either blocking hop.
    let dir_target = target.clone();
    let bytes = keystore::blocking(move || -> Result<Vec<u8>> {
        if let Some(parent) = dir_target.parent() {
            std::fs::create_dir_all(parent).map_err(|_| RpcError::FailedToCreateDir)?;
        }
        Ok(pkcs12::write(&store, &password, &mut OsRng)?)
    })
    .await?;
    keystore::overwrite_key_file(&target, &bytes).await?;
    // The final signature has nothing to do with the write above — it only
    // needs `data`, `private_key` and `chain`, all already in hand — so it
    // gets its own hop to the blocking pool rather than riding the one
    // that produced `bytes`.
    let pkcs7_der = keystore::blocking(move || -> Result<Vec<u8>> {
        Ok(cms::sign(&data, true, &private_key, &chain, SystemTime::now(), &mut OsRng)?)
    })
    .await?;

    ctx.enrollments.lock().remove(&map_key);
    Ok(Response::success()
        .with("guid", Value::String(guid.to_string()))
        .with("pkcs7_64", Value::String(base64::engine::general_purpose::STANDARD.encode(&pkcs7_der)))
        .with("alias", Value::String(alias)))
}
