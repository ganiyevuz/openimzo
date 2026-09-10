use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "openimzo-cli", about = "Developer CLI for the OpenImzo core")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the power-on self-test of openimzo-crypto and print one line per check
    Selftest,
    /// Print the certificate info JSON (input: DER, PEM or base64 file)
    CertInfo { file: std::path::PathBuf },
    /// Check that SUBJECT is signed by ISSUER (national algorithms only)
    VerifyCert { subject: std::path::PathBuf, issuer: std::path::PathBuf },
    /// List key aliases of a PFX without a password (what sites see in list_all_certificates)
    PfxList { file: std::path::PathBuf },
    /// Open a PFX with its password and print the entries; optionally dump chain certificates as DER
    PfxOpen {
        file: std::path::PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long)]
        dump_certs: Option<std::path::PathBuf>,
    },
    /// Read a PFX with --old, write it to OUT with --new (same aliases and chains)
    PfxChangePassword {
        input: std::path::PathBuf,
        output: std::path::PathBuf,
        #[arg(long)]
        old: String,
        #[arg(long)]
        new: String,
    },
    /// Convert a PFX to a YKS with the same password
    PfxToYks { input: std::path::PathBuf, output: std::path::PathBuf, #[arg(long)] password: String },
    /// Convert a YKS to a PFX with the same password
    YksToPfx { input: std::path::PathBuf, output: std::path::PathBuf, #[arg(long)] password: String },
    /// List a YKS without the password (alias, subject, serial, validity, issuer, key algorithm)
    YksList { file: std::path::PathBuf },
    /// Create a PKCS#7/CMS signature with the first key of a PFX
    Sign {
        #[arg(long)] pfx: std::path::PathBuf,
        #[arg(long)] password: String,
        #[arg(long)] detached: bool,
        #[arg(short, long)] output: std::path::PathBuf,
        content: std::path::PathBuf,
    },
    /// Verify a PKCS#7/CMS signature (pass --content for detached signatures)
    Verify {
        #[arg(long)] content: Option<std::path::PathBuf>,
        file: std::path::PathBuf,
    },
    /// Build a PKCS#10 request from the first key of a PFX (or a fresh key with --generate)
    Csr {
        #[arg(long)] pfx: Option<std::path::PathBuf>,
        #[arg(long)] password: Option<String>,
        #[arg(long)] generate: bool,
        #[arg(long)] subject: String,
        #[arg(long, value_delimiter = ',')] policies: Vec<String>,
        #[arg(short, long)] output: std::path::PathBuf,
    },
    /// Print the PKCS#10 info JSON (DER, PEM or base64)
    CsrInfo { file: std::path::PathBuf },
    /// Generate a key, issue the temporary chain and write a PFX (what save_temporary_pfx does)
    TempPfx {
        #[arg(long)] subject: String,
        #[arg(long)] alias: String,
        #[arg(long)] password: String,
        #[arg(short, long)] output: std::path::PathBuf,
    },
    /// Print the QR-key hex for the first key of a PFX
    QrKey { #[arg(long)] pfx: std::path::PathBuf, #[arg(long)] password: String },
    /// List key files the way a site would see them
    KeysScan {
        /// Directory that stands in for /Volumes (use a fixture folder in development)
        #[arg(long)]
        volumes: Option<std::path::PathBuf>,
        /// Extra search folders, repeatable
        #[arg(long)]
        folder: Vec<std::path::PathBuf>,
        /// pfx or yks
        #[arg(long, default_value = "pfx")]
        kind: String,
    },
    /// Send one or more JSON requests to a single dispatcher, in order, and
    /// print one reply per line. A process can't carry a session across
    /// invocations, so a multi-step flow (load a key, then use its id; or
    /// `pki.enroll_pfx_step1` then `step2`) has to be one `rpc` call with
    /// several requests; a request containing `$FIELD` has it replaced with
    /// the string value of `field` from the most recent reply that carried
    /// one (matched case-insensitively, e.g. `$KEYID`, `$GUID`,
    /// `$TEMPUSERCERTIFICATE`).
    Rpc {
        /// Origin header to present, e.g. http://localhost
        #[arg(long, default_value = "http://localhost")]
        origin: String,
        /// Directory that stands in for /Volumes
        #[arg(long)]
        volumes: Option<std::path::PathBuf>,
        /// Extra search folder, repeatable
        #[arg(long)]
        folder: Vec<std::path::PathBuf>,
        /// Answer password prompts with this value instead of asking
        #[arg(long)]
        password: Option<String>,
        /// Refuse randseed.get's consent prompt instead of allowing it
        #[arg(long)]
        deny_randseed: bool,
        /// The requests, in order, e.g. '{"plugin":"pfx","name":"list_all_certificates"}'.
        /// When none are given, one JSON request per line is read from stdin
        /// instead — the OS caps a single process's argv well under
        /// `openimzo_rpc::dispatch::MAX_ARGUMENT_BYTES`, so stdin is the only way
        /// to exercise an argument anywhere near that limit.
        #[arg(num_args = 0..)]
        requests: Vec<String>,
    },
    /// Run the two listeners so a browser can talk to this build.
    Serve {
        /// Use ports that do not collide with a running original.
        #[arg(long)]
        dev: bool,
        /// Directory that stands in for /Volumes
        #[arg(long)]
        volumes: Option<std::path::PathBuf>,
        /// Extra search folder, repeatable
        #[arg(long)]
        folder: Vec<std::path::PathBuf>,
        /// Answer password prompts with this value instead of asking
        #[arg(long)]
        password: Option<String>,
        /// Where to keep the per-install TLS key and certificate. Defaults
        /// to a fixed spot under the OS temp directory, which macOS
        /// periodically clears -- pass this to keep a certificate a person
        /// has already trusted from silently vanishing between runs.
        #[arg(long)]
        tls_dir: Option<std::path::PathBuf>,
    },
}

/// A headless `UiDelegate` for the CLI: answers password prompts from
/// `--password`, always allows the (single, implicit) origin, and refuses
/// everything else — there is no one at the keyboard to ask.
struct CliUi {
    password: Option<String>,
    /// Answer `randseed.get`'s consent prompt with a refusal instead of the
    /// default allow — `--deny-randseed` on `Cmd::Rpc`, for exercising the
    /// `-5001` path without a real person to ask.
    deny_randseed: bool,
}

#[async_trait::async_trait]
impl openimzo_rpc::ui::UiDelegate for CliUi {
    async fn ask_password(
        &self,
        _request: openimzo_rpc::ui::PasswordRequest,
    ) -> Result<openimzo_rpc::ui::PasswordAnswer, openimzo_rpc::ui::UiError> {
        match &self.password {
            Some(password) => Ok(openimzo_rpc::ui::PasswordAnswer {
                password: zeroize::Zeroizing::new(password.clone()),
                remember: false,
            }),
            None => Err(openimzo_rpc::ui::UiError::Unavailable),
        }
    }

    async fn ask_permission(
        &self,
        _request: openimzo_rpc::ui::PermissionRequest,
    ) -> Result<openimzo_rpc::ui::PermissionAnswer, openimzo_rpc::ui::UiError> {
        Ok(openimzo_rpc::ui::PermissionAnswer::AllowAlways)
    }

    /// Answers from `--password` and always chooses the first offered disk —
    /// there is no one at the keyboard to pick one, and the CLI's own test
    /// fixtures only ever offer the one directory under test.
    async fn ask_new_pfx(
        &self,
        request: openimzo_rpc::ui::NewPfxRequest,
    ) -> Result<openimzo_rpc::ui::NewPfxAnswer, openimzo_rpc::ui::UiError> {
        match (&self.password, request.disks.first()) {
            (Some(password), Some(disk)) => {
                Ok(openimzo_rpc::ui::NewPfxAnswer { disk: disk.clone(), password: zeroize::Zeroizing::new(password.clone()) })
            }
            _ => Err(openimzo_rpc::ui::UiError::Unavailable),
        }
    }

    async fn confirm_legacy_algorithm(
        &self,
        _request: openimzo_rpc::ui::LegacyAlgRequest,
    ) -> Result<openimzo_rpc::ui::LegacyAlgAnswer, openimzo_rpc::ui::UiError> {
        Err(openimzo_rpc::ui::UiError::Unavailable)
    }

    /// No one to ask, so the CLI answers the same way it answers the
    /// permission dialog: allow by default, or deny when `--deny-randseed`
    /// asked for the refusal path to be exercised instead.
    async fn confirm_randseed(
        &self,
        _request: openimzo_rpc::ui::RandseedRequest,
    ) -> Result<openimzo_rpc::ui::Consent, openimzo_rpc::ui::UiError> {
        if self.deny_randseed {
            Ok(openimzo_rpc::ui::Consent::Deny)
        } else {
            Ok(openimzo_rpc::ui::Consent::Allow)
        }
    }
}

/// The CLI's `RandseedProvider`: hostname plus every network interface's
/// name and IP addresses, gathered with `if-addrs`/`hostname` — the only
/// place either crate is used, since `openimzo-rpc` itself may not read the
/// environment. The exact byte layout of this inner blob is this crate's
/// own; what has to match the protocol is the outer envelope
/// (`openimzo_rpc::plugins::randseed`), not this shape.
struct CliRandseedProvider;

impl openimzo_rpc::plugins::randseed::RandseedProvider for CliRandseedProvider {
    fn network_description(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let hostname = hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_default();
        out.extend_from_slice(hostname.as_bytes());
        out.push(0);
        if let Ok(interfaces) = if_addrs::get_if_addrs() {
            for iface in interfaces {
                out.extend_from_slice(iface.name.as_bytes());
                out.push(0);
                out.extend_from_slice(iface.ip().to_string().as_bytes());
                out.push(0);
            }
        }
        out
    }
}

/// An in-memory `ApikeyStore` for the CLI: nothing survives past the process,
/// which matches the CLI's "one call, one process" usage. Phase 3 persists
/// this to disk instead.
#[derive(Default)]
struct InMemoryApikeyStore {
    keys: std::sync::Mutex<Vec<(String, String)>>,
    allowed: std::sync::Mutex<Vec<String>>,
}

impl openimzo_rpc::origin::ApikeyStore for InMemoryApikeyStore {
    fn load(&self) -> Vec<(String, String)> {
        self.keys.lock().expect("apikey store lock").clone()
    }

    fn save_key(&self, domain: &str, key: &str) {
        self.keys.lock().expect("apikey store lock").push((domain.to_string(), key.to_string()));
    }

    fn save_allowed(&self, origin: &str) {
        self.allowed.lock().expect("apikey store lock").push(origin.to_string());
    }

    fn allowed(&self) -> Vec<String> {
        self.allowed.lock().expect("apikey store lock").clone()
    }

    fn forget(&self, domain: &str, origins: &[String]) {
        self.keys.lock().expect("apikey store lock").retain(|(d, _)| d != domain);
        self.allowed.lock().expect("apikey store lock").retain(|o| !origins.iter().any(|r| r == o));
    }
}

fn return_code(e: openimzo_pki::PkiError) -> i32 {
    match e {
        openimzo_pki::PkiError::PasswordIncorrect => 3,
        _ => 2,
    }
}

/// Where `serve` keeps its per-install TLS material when `--tls-dir` is not
/// given. A real packaged app would use its own application-support
/// directory; this developer CLI defaults to a fixed spot under the OS temp
/// directory instead, so repeated runs on one machine reuse the same
/// certificate without adding a directory-locating dependency this crate
/// does not otherwise need. That default sits under a directory macOS
/// periodically cleans out, though, so a certificate a person went to the
/// trouble of trusting can vanish and need trusting again -- `--tls-dir`
/// exists for exactly that, to point a longer-lived run somewhere stable.
fn tls_material_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("openimzo").join("tls")
}

/// One line per event, on stdout for the ones a person would want to see
/// while the server is up, stderr for a bind failure.
fn print_event(event: &openimzo_server::ServerEvent) {
    match event {
        openimzo_server::ServerEvent::Listening { port, tls } => {
            println!("listening on 127.0.0.1:{port} ({})", if *tls { "tls" } else { "plain" });
        }
        openimzo_server::ServerEvent::BindFailed { port, tls, reason } => {
            eprintln!("could not bind 127.0.0.1:{port} ({}): {reason}", if *tls { "tls" } else { "plain" });
        }
        openimzo_server::ServerEvent::Stopped => println!("stopped"),
    }
}

fn main() {
    let cli = Cli::parse();
    std::process::exit(run(cli));
}

fn run(cli: Cli) -> i32 {
    match cli.cmd {
        Cmd::Selftest => {
            let checks = openimzo_crypto::selftest::run();
            let mut failed = 0;
            for c in &checks {
                println!("{} {} {}", if c.ok { "PASS" } else { "FAIL" }, c.name, c.detail);
                if !c.ok {
                    failed += 1;
                }
            }
            println!("{} checks, {} failed", checks.len(), failed);
            if failed == 0 { 0 } else { 1 }
        }
        Cmd::CertInfo { file } => {
            let bytes = std::fs::read(&file).expect("read certificate");
            match openimzo_pki::x509::parse_certificate_any(&bytes).and_then(|c| openimzo_pki::x509::certificate_view(&c)) {
                Ok(view) => {
                    println!("{}", serde_json::to_string_pretty(&view).expect("json"));
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        Cmd::VerifyCert { subject, issuer } => {
            let s = openimzo_pki::x509::parse_certificate_any(&std::fs::read(&subject).expect("read")).expect("subject");
            let i = openimzo_pki::x509::parse_certificate_any(&std::fs::read(&issuer).expect("read")).expect("issuer");
            match openimzo_pki::x509::verify_certificate_signature(&s, &i) {
                Ok(true) => { println!("valid"); 0 }
                Ok(false) => { println!("INVALID"); 1 }
                Err(e) => { eprintln!("error: {e}"); 2 }
            }
        }
        Cmd::PfxList { file } => match openimzo_pki::pkcs12::list_aliases(&std::fs::read(&file).expect("read")) {
            Ok(aliases) => {
                for a in aliases {
                    println!("{a}");
                }
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        },
        Cmd::PfxOpen { file, password, dump_certs } => {
            match openimzo_pki::pkcs12::read(&std::fs::read(&file).expect("read"), &password) {
                Ok(store) => {
                    for (i, k) in store.keys.iter().enumerate() {
                        println!("key[{i}] alias={}", k.alias);
                        println!("  algorithm={} curve={}", k.private_key.family.algorithm_name(), k.private_key.curve.name());
                        for (n, c) in k.chain.iter().enumerate() {
                            let v = openimzo_pki::x509::certificate_view(c).expect("view");
                            println!("  chain[{n}] serial={} subject={} valid={}..{}", v.serial_number, v.subject_name, v.valid_from, v.valid_to);
                            if let Some(dir) = &dump_certs {
                                std::fs::create_dir_all(dir).expect("mkdir");
                                let der = <x509_cert::Certificate as der::Encode>::to_der(c).expect("der");
                                std::fs::write(dir.join(format!("key{i}-chain{n}.der")), der).expect("write");
                            }
                        }
                    }
                    println!("{} key entries, {} certificate bags", store.keys.len(), store.certs.len());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return_code(e)
                }
            }
        }
        Cmd::PfxChangePassword { input, output, old, new } => {
            let store = match openimzo_pki::pkcs12::read(&std::fs::read(&input).expect("read"), &old) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return return_code(e);
                }
            };
            let out = openimzo_pki::pkcs12::write(&store, &new, &mut rand_core::OsRng).expect("write");
            std::fs::write(&output, out).expect("write file");
            println!("wrote {}", output.display());
            0
        }
        Cmd::PfxToYks { input, output, password } => {
            let store = match openimzo_pki::pkcs12::read(&std::fs::read(&input).expect("read"), &password) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return return_code(e);
                }
            };
            let now = chrono::Utc::now().timestamp_millis();
            let yks = openimzo_pki::ytks::write(&openimzo_pki::ytks::from_pkcs12(&store, now), &password, &mut rand_core::OsRng).expect("write yks");
            std::fs::write(&output, yks).expect("write file");
            println!("wrote {}", output.display());
            0
        }
        Cmd::YksToPfx { input, output, password } => {
            let store = match openimzo_pki::ytks::read(&std::fs::read(&input).expect("read"), &password) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return return_code(e);
                }
            };
            let pfx = openimzo_pki::pkcs12::write(&openimzo_pki::ytks::to_pkcs12(&store), &password, &mut rand_core::OsRng).expect("write pfx");
            std::fs::write(&output, pfx).expect("write file");
            println!("wrote {}", output.display());
            0
        }
        Cmd::YksList { file } => match openimzo_pki::ytks::list(&std::fs::read(&file).expect("read")) {
            Ok(entries) => {
                for e in entries {
                    match e.certificate {
                        Some(c) => {
                            let v = openimzo_pki::x509::certificate_view(&c).expect("view");
                            println!("{} | serial={} | {} | {}..{} | issuer={} | {}", e.alias, v.serial_number, v.subject_name, v.valid_from, v.valid_to, v.issuer_name, v.public_key.map(|p| p.key_alg_name).unwrap_or_default());
                        }
                        None => println!("{}", e.alias),
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                return_code(e)
            }
        },
        Cmd::Sign { pfx, password, detached, output, content } => {
            let store = match openimzo_pki::pkcs12::read(&std::fs::read(&pfx).expect("read pfx"), &password) {
                Ok(s) => s,
                Err(e) => { eprintln!("error: {e}"); return return_code(e); }
            };
            let key = store.keys.first().expect("PFX has no key entry");
            let data = std::fs::read(&content).expect("read content");
            let p7 = openimzo_pki::cms::sign(&data, !detached, &key.private_key, &key.chain, std::time::SystemTime::now(), &mut rand_core::OsRng).expect("sign");
            std::fs::write(&output, &p7).expect("write");
            println!("wrote {} ({} bytes)", output.display(), p7.len());
            0
        }
        Cmd::Verify { content, file } => {
            let p7 = std::fs::read(&file).expect("read");
            let detached = content.as_ref().map(|p| std::fs::read(p).expect("read content"));
            match openimzo_pki::cms::verify(&p7, detached.as_deref()) {
                Ok(info) => {
                    let mut all = true;
                    for s in &info.signers {
                        all &= s.verified;
                        println!("signer serial={} issuer={} verified={} signingTime={} signature={} error={}",
                            s.serial_hex, s.signer_id.issuer, s.verified,
                            s.signing_time.map(openimzo_pki::x509::format_time_local).unwrap_or_default(),
                            hex::encode(&s.signature), s.error.clone().unwrap_or_default());
                    }
                    println!("content {} bytes, {} signer(s)", info.content.len(), info.signers.len());
                    if all { 0 } else { 1 }
                }
                Err(e) => { eprintln!("error: {e}"); 2 }
            }
        }
        Cmd::Csr { pfx, password, generate, subject, policies, output } => {
            let key = if generate {
                openimzo_crypto::PrivateKey::generate(openimzo_crypto::KeyFamily::Ozmst, openimzo_crypto::ec::CurveId::A, &mut rand_core::OsRng).expect("generate")
            } else {
                let store = openimzo_pki::pkcs12::read(&std::fs::read(pfx.expect("--pfx")).expect("read"), &password.expect("--password")).expect("open pfx");
                store.keys.first().expect("no key").private_key.clone()
            };
            let der = openimzo_pki::pkcs10::build(&key, &subject, &policies, &mut rand_core::OsRng).expect("csr");
            std::fs::write(&output, &der).expect("write");
            println!("wrote {} ({} bytes)", output.display(), der.len());
            0
        }
        Cmd::CsrInfo { file } => match openimzo_pki::pkcs10::parse(&std::fs::read(&file).expect("read")).and_then(|r| openimzo_pki::pkcs10::info_view(&r)) {
            Ok(v) => { println!("{}", serde_json::to_string_pretty(&v).expect("json")); if v.verified { 0 } else { 1 } }
            Err(e) => { eprintln!("error: {e}"); 2 }
        },
        Cmd::TempPfx { subject, alias, password, output } => {
            let key = openimzo_crypto::PrivateKey::generate(openimzo_crypto::KeyFamily::Ozmst, openimzo_crypto::ec::CurveId::A, &mut rand_core::OsRng).expect("generate");
            let chain = openimzo_pki::tempchain::issue(&key.public_key(), &subject, &mut rand_core::OsRng).expect("chain");
            let store = openimzo_pki::pkcs12::Pkcs12Store { keys: vec![openimzo_pki::pkcs12::KeyEntry { alias, local_key_id: None, private_key: key, chain }], certs: vec![] };
            let pfx = openimzo_pki::pkcs12::write(&store, &password, &mut rand_core::OsRng).expect("write");
            std::fs::write(&output, pfx).expect("write file");
            println!("wrote {}", output.display());
            0
        }
        Cmd::QrKey { pfx, password } => {
            let store = openimzo_pki::pkcs12::read(&std::fs::read(&pfx).expect("read"), &password).expect("open pfx");
            match openimzo_pki::qrkey::export(&store.keys.first().expect("no key").private_key, &password) {
                Ok(bytes) => { println!("{}", hex::encode(bytes)); 0 }
                Err(e) => { eprintln!("error: {e}"); 2 }
            }
        }
        Cmd::KeysScan { volumes, folder, kind } => {
            let kind = match kind.as_str() {
                "pfx" => openimzo_keys::KeyKind::Pfx,
                "yks" => openimzo_keys::KeyKind::Ytks,
                other => {
                    eprintln!("error: unknown kind {other}");
                    return 2;
                }
            };
            let cfg = openimzo_keys::DiscoveryConfig {
                volumes_dir: volumes.unwrap_or_else(|| std::path::PathBuf::from("/Volumes")),
                extra_folders: folder,
            };
            let d = openimzo_keys::Discovery::new(cfg);
            println!("{}", serde_json::to_string_pretty(&d.list_disks()).expect("json"));
            println!("{}", serde_json::to_string_pretty(&d.scan(kind)).expect("json"));
            0
        }
        Cmd::Rpc { origin, volumes, folder, password, deny_randseed, requests } => {
            let requests: Vec<String> = if requests.is_empty() {
                // Every line is one request, blank ones included: a blank
                // line is just another frame `serde_json::from_str` can't
                // parse, replied to the same as any other, rather than
                // silently dropped — one line in, one reply out, always.
                use std::io::BufRead;
                std::io::stdin().lock().lines().map_while(|l| l.ok()).collect()
            } else {
                requests
            };
            let cfg = openimzo_keys::DiscoveryConfig {
                volumes_dir: volumes.unwrap_or_else(|| std::path::PathBuf::from("/Volumes")),
                extra_folders: folder,
            };
            let sessions = std::sync::Arc::new(openimzo_keys::Sessions::new());
            let discovery = std::sync::Arc::new(openimzo_keys::Discovery::new(cfg));
            let ui = std::sync::Arc::new(openimzo_rpc::ui::UiBroker::new(Box::new(CliUi { password, deny_randseed })));
            let apikeys = std::sync::Arc::new(openimzo_rpc::origin::ApikeyService::new(
                openimzo_rpc::origin::ApikeyConfig::default(),
                Box::new(InMemoryApikeyStore::default()),
            ));
            let config = openimzo_rpc::dispatch::DispatcherConfig {
                randseed_provider: Some(std::sync::Arc::new(CliRandseedProvider)),
                ..Default::default()
            };
            let dispatcher = openimzo_rpc::dispatch::Dispatcher::new(config, sessions, discovery, ui, apikeys);
            let origin = openimzo_rpc::origin::Origin::from_header(&origin);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");

            // Every string-valued field of every reply so far, keyed by its
            // upper-cased name — `$KEYID`, `$YTKSID`, `$KPID` as before, but
            // also `$GUID`, `$DISK`, `$TEMPUSERCERTIFICATE`, and so on. A
            // later reply's field of the same name replaces the earlier one,
            // matching the old single-slot `$KEYID` behaviour exactly.
            let mut fields: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let mut all_succeeded = true;
            for text in requests {
                let mut text = text;
                for (name, value) in &fields {
                    text = text.replace(&format!("${name}"), value);
                }
                let request: openimzo_rpc::Request = match serde_json::from_str(&text) {
                    Ok(r) => r,
                    Err(_) => {
                        // A frame the dispatcher's own model can't be built
                        // from at all (not an object/array shape it accepts,
                        // or a field of the wrong JSON type) never reaches
                        // `Dispatcher::call`, so it gets the same reply as a
                        // well-formed request naming a function that doesn't
                        // exist — the original's frame decoder collapses the
                        // two the same way. Never echo the parser's own
                        // message: it can quote the offending byte and its
                        // line/column, which is exactly the kind of internal
                        // detail a reply must not carry.
                        let response = openimzo_rpc::error::RpcError::FunctionNotFound
                            .into_response(&dispatcher.ctx().messages, dispatcher.lang());
                        println!("{}", response.to_json());
                        all_succeeded = false;
                        continue;
                    }
                };
                let response = runtime.block_on(dispatcher.call(&origin, request));
                println!("{}", response.to_json());
                all_succeeded &= response.success;
                for (name, value) in &response.payload {
                    if let serde_json::Value::String(s) = value {
                        fields.insert(name.to_uppercase(), s.clone());
                    }
                }
            }
            if all_succeeded {
                0
            } else {
                1
            }
        }
        Cmd::Serve { dev, volumes, folder, password, tls_dir } => {
            let cfg = openimzo_keys::DiscoveryConfig {
                volumes_dir: volumes.unwrap_or_else(|| std::path::PathBuf::from("/Volumes")),
                extra_folders: folder,
            };
            let sessions = std::sync::Arc::new(openimzo_keys::Sessions::new());
            let discovery = std::sync::Arc::new(openimzo_keys::Discovery::new(cfg));
            // No one at the keyboard: `--deny-randseed` has no equivalent
            // here, so `randseed.get`'s consent prompt is always allowed,
            // same as `CliUi::ask_permission`.
            let ui = std::sync::Arc::new(openimzo_rpc::ui::UiBroker::new(Box::new(CliUi { password, deny_randseed: false })));
            let apikeys = std::sync::Arc::new(openimzo_rpc::origin::ApikeyService::new(
                openimzo_rpc::origin::ApikeyConfig::default(),
                Box::new(InMemoryApikeyStore::default()),
            ));
            let config = openimzo_rpc::dispatch::DispatcherConfig {
                randseed_provider: Some(std::sync::Arc::new(CliRandseedProvider)),
                ..Default::default()
            };
            let dispatcher =
                std::sync::Arc::new(openimzo_rpc::dispatch::Dispatcher::new(config, sessions, discovery, ui, apikeys));

            let material_dir = tls_dir.unwrap_or_else(tls_material_dir);
            let server_config = if dev {
                openimzo_server::ServerConfig::development(material_dir.clone())
            } else {
                openimzo_server::ServerConfig::production(material_dir.clone())
            };
            let ws_port = server_config.ws_port;
            let wss_port = server_config.wss_port;

            // Current-thread rather than `Rpc`'s choice matters here: `Server::start`
            // spawns its listener and sweeper tasks with `tokio::spawn` before this
            // function ever awaits, and only a single-threaded runtime guarantees none
            // of them run (and send their first `Listening`/`BindFailed` event) before
            // the `subscribe()` call just below has a chance to register.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");
            runtime.block_on(async move {
                let server = openimzo_server::Server::new(server_config, dispatcher);
                let has_cert = server.certificate_pem().is_some();
                // No `Platform` here to ask whether the original is
                // running -- this developer CLI always attempts the real
                // bind and lets the OS's own `AddrInUse` speak for itself.
                let handle = server.start(false);
                let mut events = handle.subscribe();

                println!("plain: ws://127.0.0.1:{ws_port}/service/cryptapi");
                println!("tls:   wss://127.0.0.1:{wss_port}/service/cryptapi");
                if has_cert {
                    println!("certificate: {}", openimzo_server::tls::cert_path(&material_dir).display());
                } else {
                    println!("certificate: none (the tls listener did not come up)");
                }

                loop {
                    tokio::select! {
                        event = events.recv() => match event {
                            Ok(event) => print_event(&event),
                            Err(_) => break,
                        },
                        _ = tokio::signal::ctrl_c() => break,
                    }
                }
                handle.stop().await;
            });
            0
        }
    }
}
