//! `new` builds every piece — the dispatcher, the two-listener server, the
//! engine's own tokio runtime — without binding anything; `start` binds,
//! `stop` unbinds, `status` reports what is currently up.
//!
//! The Swift side has no tokio of its own, so the engine owns one: built
//! once in `new` and kept alive for the engine's whole life. It must be
//! multi-threaded with a blocking pool, not a current-thread runtime — the
//! key-file work an earlier task moved onto the blocking pool depends on
//! that, and so does running the plain and TLS listeners at the same time.

use crate::delegate::{Platform, PlatformRandseedProvider, UiDelegate, UiDelegateAdapter};
use crate::events::{self, Event, EventStream};
use crate::types::{CertificateSummary, EngineConfig, EngineError, EngineStatus, KeyEntry, Settings, Site};
use openimzo_keys::{Discovery, DiscoveryConfig, KeyKind, Sessions};
use openimzo_rpc::dispatch::{Dispatcher, DispatcherConfig};
use openimzo_rpc::origin::{ApikeyConfig, ApikeyService, ApikeyStore};
use openimzo_rpc::ui::UiBroker;
use openimzo_rpc::{Lang, UiLang};
use openimzo_server::{Server, ServerConfig, ServerEvent, ServerHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;
use zeroize::Zeroizing;

/// Verified API keys and "allow always" decisions, persisted to
/// `<app_support_dir>/sites.json`
/// (the design spec) — the
/// real `ApikeyStore` the placeholder `InMemoryApikeyStore` this crate
/// started with was always meant to become. `ApikeyService` is the sole
/// owner of the domain/origin relationship (`origin::host_of`); every
/// method here just persists exactly the delta it is given, keyed however
/// `ApikeyService` already keys it, and rewrites the whole small file
/// afterward — there is no reason for a second copy of that logic here.
struct SitesStore {
    path: PathBuf,
    state: parking_lot::Mutex<SitesFile>,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct SitesFile {
    /// `(domain, key)` pairs, mirroring `ApikeyStore::load`'s own shape.
    keys: Vec<(String, String)>,
    /// Full `Origin` header text, mirroring `ApikeyStore::allowed`'s own shape.
    allowed: Vec<String>,
}

impl SitesStore {
    fn new(app_support_dir: &str) -> Self {
        let path = PathBuf::from(app_support_dir).join("sites.json");
        let state = std::fs::read(&path)
            .ok()
            .and_then(|bytes| match serde_json::from_slice::<SitesFile>(&bytes) {
                Ok(state) => Some(state),
                Err(e) => {
                    tracing::debug!(error = %e, "sites.json could not be parsed; starting empty");
                    None
                }
            })
            .unwrap_or_default();
        SitesStore { path, state: parking_lot::Mutex::new(state) }
    }

    /// Rewrites `sites.json` in full from `state`. Losing this one write
    /// costs a cached api key or a permission answer, not a signing key, so
    /// this writes directly rather than through the key file's
    /// atomic temp-then-rename helper.
    fn persist(&self, state: &SitesFile) {
        if let Some(dir) = self.path.parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                tracing::debug!(error = %e, "could not create the app support directory for sites.json");
                return;
            }
        }
        match serde_json::to_vec_pretty(state) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&self.path, bytes) {
                    tracing::debug!(error = %e, "sites.json could not be written");
                }
            }
            Err(e) => tracing::debug!(error = %e, "sites could not be serialized"),
        }
    }
}

impl ApikeyStore for SitesStore {
    fn load(&self) -> Vec<(String, String)> {
        self.state.lock().keys.clone()
    }

    fn save_key(&self, domain: &str, key: &str) {
        let mut state = self.state.lock();
        state.keys.retain(|(d, _)| d != domain);
        state.keys.push((domain.to_string(), key.to_string()));
        self.persist(&state);
    }

    fn save_allowed(&self, origin: &str) {
        let mut state = self.state.lock();
        if !state.allowed.iter().any(|o| o == origin) {
            state.allowed.push(origin.to_string());
        }
        self.persist(&state);
    }

    fn allowed(&self) -> Vec<String> {
        self.state.lock().allowed.clone()
    }

    fn forget(&self, domain: &str, origins: &[String]) {
        let mut state = self.state.lock();
        state.keys.retain(|(d, _)| d != domain);
        state.allowed.retain(|o| !origins.iter().any(|r| r == o));
        self.persist(&state);
    }
}

/// Whether each listener is actually bound right now, kept current by the
/// background task `Engine::new` spawns to watch the server's own
/// `ServerEvent`s. A `ServerHandle` existing only means `start` was called,
/// not that either listener came up -- a listener can fail to bind, most
/// commonly because the original E-IMZO already holds that port, while the
/// other still succeeds -- so `status` reads this instead of the handle.
#[derive(Clone, Copy, Debug, Default)]
struct ListenerStatus {
    ws: bool,
    wss: bool,
}

struct Inner {
    config: EngineConfig,
    dispatcher: Arc<Dispatcher>,
    /// Kept for `list_keys` and `rescan_keys` to rebuild a `Discovery` from
    /// `Platform::volumes_roots` again, the same way `new` does below
    /// (`build_discovery`) -- rather than reusing the dispatcher's own
    /// `Ctx.discovery`, which every RPC plugin handler shares and which
    /// would need interior mutability of its own just for this.
    platform: Arc<dyn Platform>,
    /// The last `Settings` read at construction or written by
    /// `update_settings`, so `settings()` has something to hand back
    /// without re-reading the file every call.
    settings: Settings,
    server: Server,
    /// The port the plain listener binds to, kept alongside `server` since
    /// `Server` does not expose its own configuration back out. Reported by
    /// `status` so the shell can show which port it is actually on.
    ws_port: u16,
    /// The port the TLS listener binds to, same reasoning as `ws_port`.
    /// Also read by `status`'s trust self-probe.
    wss_port: u16,
    handle: Option<ServerHandle>,
    /// Keeps the engine's runtime alive: `Engine::runtime` below is a cheap
    /// clone of this same runtime's handle, read without locking `inner`.
    /// Dropping this drops the runtime and everything still spawned on it,
    /// which is exactly what should happen when the whole `Engine` does.
    _runtime: tokio::runtime::Runtime,
}

#[derive(uniffi::Object)]
pub struct Engine {
    inner: parking_lot::Mutex<Inner>,
    runtime: tokio::runtime::Handle,
    /// The one channel behind every `EventStream` `events()` mints, and the
    /// same one `install_log_forwarding` points the `tracing` layer at.
    events: broadcast::Sender<Event>,
    listeners: Arc<parking_lot::RwLock<ListenerStatus>>,
}

/// Points the process's log forwarding away from this engine's own
/// channel once it is gone, so a consumer still holding an `EventStream`
/// learns the stream ended (`RecvError::Closed`) instead of waiting on
/// `recv` forever with nothing left to ever send into it.
/// `clear_log_forwarding` only clears the global if it still points at
/// `self.events` specifically, so an older engine finishing its drop after
/// a newer one has already taken over does not kill the newer one's
/// forwarding. Cheap and infallible -- a lock and a pointer comparison --
/// which is required here: `Drop` can run on any thread, including the
/// application's main one, so it must never block or fail.
impl Drop for Engine {
    fn drop(&mut self) {
        events::clear_log_forwarding(&self.events);
    }
}

/// Keeps `listeners` current and republishes every `ServerEvent` as
/// `Event::ServerStateChanged`, for as long as the engine's runtime lives.
/// Spawned once, in `Engine::new`, subscribed to `Server::subscribe`
/// before `start` is ever called -- so it can never miss a listener's
/// first event to a race against its own bind -- and left running across
/// every later `start`/`stop` cycle, since `Server` keeps the same
/// underlying channel for its whole life.
///
/// A receiver that falls behind (`Lagged`) resumes from the next event
/// rather than ending this task: losing an intermediate state still
/// leaves `status` accurate again as soon as the next event lands, but
/// stopping here would leave it wrong for the rest of the process's life.
async fn forward_server_events(
    mut server_events: broadcast::Receiver<ServerEvent>,
    listeners: Arc<parking_lot::RwLock<ListenerStatus>>,
    events: broadcast::Sender<Event>,
) {
    loop {
        let event = match server_events.recv().await {
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return,
        };
        match event {
            ServerEvent::Listening { tls, .. } => {
                let mut status = listeners.write();
                if tls {
                    status.wss = true;
                } else {
                    status.ws = true;
                }
            }
            ServerEvent::BindFailed { tls, .. } => {
                let mut status = listeners.write();
                if tls {
                    status.wss = false;
                } else {
                    status.ws = false;
                }
            }
            ServerEvent::Stopped => *listeners.write() = ListenerStatus::default(),
        }
        let _ = events.send(Event::ServerStateChanged);
    }
}

/// Builds the engine's own runtime. It must be multi-threaded — that is
/// what lets both listeners and the blocking pool run at once, and the
/// key-file work an earlier task moved onto the blocking pool depends on
/// it too — so there is no lesser runtime worth falling back to. If the OS
/// won't hand out the threads for it (starvation on thread or
/// file-descriptor limits), that is reported back to the caller as an
/// error: the detail goes to the log, and `Engine::new` fails instead of
/// the process falling back to a different runtime shape or aborting.
fn build_runtime() -> Result<tokio::runtime::Runtime, EngineError> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| {
        tracing::error!(error = %e, "the engine's runtime could not be created");
        EngineError::Failed
    })
}

/// Builds a `Discovery` from `platform`'s current `volumes_roots` and
/// `config`'s own `extra_folders`. `list_disks` (`openimzo_keys::Discovery`)
/// treats `volumes_dir` and every entry of `extra_folders` identically, so
/// the platform's first reported root becomes `volumes_dir` (matching
/// `DiscoveryConfig::default`'s single-root shape) and any further roots
/// join `extra_folders` alongside the configured ones.
///
/// Called fresh from `Engine::new`, `list_keys` and `rescan_keys` rather
/// than cached anywhere on `Engine` itself: a volume mounted or unmounted
/// since the last call — the entire reason `rescan_keys` exists — shows up
/// this way without `Ctx.discovery` (shared with every RPC plugin handler
/// in `openimzo-rpc`) needing to become mutable just to serve this one path.
fn build_discovery(platform: &Arc<dyn Platform>, config: &EngineConfig) -> Discovery {
    let mut volume_roots = platform.volumes_roots();
    let volumes_dir =
        if volume_roots.is_empty() { PathBuf::from("/Volumes") } else { PathBuf::from(volume_roots.remove(0)) };
    let mut extra_folders: Vec<PathBuf> = volume_roots.into_iter().map(PathBuf::from).collect();
    extra_folders.extend(config.extra_folders.iter().map(PathBuf::from));
    Discovery::new(DiscoveryConfig { volumes_dir, extra_folders })
}

/// Applies the parts of `settings` the core itself reads — as opposed to
/// `launch_at_login` and `keep_activity_log`, which are purely the Swift
/// shell's own concern — to a freshly built or already-running dispatcher.
/// Called from `Engine::new` (so a `settings.json` from a previous run
/// takes effect immediately, not only after the first `update_settings`)
/// and from `Engine::update_settings`.
fn apply_settings(dispatcher: &Dispatcher, settings: &Settings) {
    let ctx = dispatcher.ctx();
    *ctx.developer_mode.write() = settings.developer_mode;
    *ctx.remember_passwords.write() = settings.remember_passwords;
    *ctx.ask_before_randseed.write() = settings.ask_before_randseed;
    // `Lang` only has `ru`/`uz` (`app.change_ui_lang`'s own restriction);
    // an "en" shell preference has nothing for the RPC reply language to
    // become, so it is left at whatever the dispatcher already had rather
    // than guessed at.
    if let Some(lang) = Lang::from_code(&settings.lang) {
        dispatcher.set_lang(lang);
    }
    // The chrome language, which does have an "en" — it is what the two
    // pages served on 127.0.0.1 are written in, and nothing a website reads
    // is written in it. Same "leave it alone rather than guess" rule for a
    // code this build does not know.
    if let Some(ui_lang) = UiLang::from_code(&settings.ui_lang) {
        dispatcher.set_ui_lang(ui_lang);
    }
}

/// `KeyInfo`'s certificate-summary fields are `None` for every PFX entry —
/// `Discovery::scan`'s own `entries_of` only ever lists PFX aliases without
/// opening the file, since nothing this workspace exposes can read a PFX's
/// certificates without its password — and `Some` for YTKS entries, which
/// its read-only bypass does allow. `KeyEntry` mirrors that honestly with
/// empty strings rather than inventing a placeholder.
fn key_entry_from_info(info: openimzo_keys::KeyInfo) -> KeyEntry {
    let subject_name = info.subject_name.unwrap_or_default();
    let identity = crate::identity::identity_from(&info.alias, &subject_name);
    let is_pfx = extension_is(&info.full_path, "pfx");

    // A YKS carries its certificate in the clear, so `info` already has the validity. A PFX does
    // not, and the alias is the only other place it could be — the original writes `validfrom` /
    // `validto` into aliases it generates. Neither is guaranteed, which is what `has_validity`
    // is for: an unknown expiry must not read as "not expired".
    let (alias_from, alias_to) = crate::identity::alias_validity_millis(&info.alias);
    let valid_from_ms = info.valid_from.or(alias_from);
    let valid_to_ms = info.valid_to.or(alias_to);

    let now_ms = openimzo_pki::x509::epoch_millis(std::time::SystemTime::now());
    KeyEntry {
        disk: info.disk,
        path: info.path,
        name: info.name,
        full_path: info.full_path.display().to_string(),
        issuer_name: info.issuer_name.unwrap_or_default(),
        serial_number: info.serial_number.unwrap_or_default(),
        valid_from: valid_from_ms.map(format_epoch_millis).unwrap_or_default(),
        valid_to: valid_to_ms.map(format_epoch_millis).unwrap_or_default(),
        public_key_alg_name: info.public_key_alg_name.unwrap_or_default(),
        expired: valid_to_ms.map(|ms| ms < now_ms).unwrap_or(false),
        has_validity: valid_to_ms.is_some(),
        days_remaining: valid_to_ms.map(whole_days_until).unwrap_or(0),
        format: if is_pfx { "PFX".to_string() } else { "YKS".to_string() },
        // A PFX with no readable subject is locked, not empty. A YKS in the same state genuinely
        // has nothing to show, and offering to unlock it would be offering something that cannot
        // work — `unlock_key` refuses anything that is not a PFX.
        locked: is_pfx && subject_name.is_empty(),
        subject_name,
        alias: info.alias,
        identity,
    }
}

/// Whole days from now until `ms`, rounded toward zero and negative once past — so "expires
/// today" and "expired today" are 0 and -0, both of which the shell shows as the day itself
/// rather than as a count.
fn whole_days_until(ms: i64) -> i64 {
    let now = openimzo_pki::x509::epoch_millis(std::time::SystemTime::now());
    (ms - now) / (24 * 60 * 60 * 1000)
}

/// `yyyy.MM.dd HH:mm:ss`, local time zone, matching every other date this
/// workspace shows a person (`openimzo_pki::x509::format_time_local`) rather
/// than a bare millisecond count.
fn format_epoch_millis(ms: i64) -> String {
    let millis = u64::try_from(ms).unwrap_or(0);
    openimzo_pki::x509::format_time_local(std::time::UNIX_EPOCH + std::time::Duration::from_millis(millis))
}

/// `path` ends in `.ext`, case-insensitively — how `change_password` and
/// `export_qr_key` tell a PFX from a YKS, matching the extensions
/// `openimzo_keys::KeyKind` itself defines.
fn extension_is(path: &Path, ext: &str) -> bool {
    path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case(ext)).unwrap_or(false)
}

/// `PkiError` to `EngineError`, without detail: a wrong password is the one
/// distinction the shell needs to show a different message for, matching
/// the design spec's rule
/// that a core error crossing into the application carries a code and a
/// fixed message, never the original text (that goes to the log instead).
fn map_pki_error(e: openimzo_pki::PkiError) -> EngineError {
    match e {
        openimzo_pki::PkiError::PasswordIncorrect => EngineError::Password,
        other => {
            tracing::debug!(error = %other, "key operation failed");
            EngineError::KeyFile
        }
    }
}

#[uniffi::export]
impl Engine {
    #[uniffi::constructor]
    pub fn new(
        config: EngineConfig,
        platform: Arc<dyn Platform>,
        ui: Arc<dyn UiDelegate>,
    ) -> Result<Self, EngineError> {
        let runtime = build_runtime()?;
        let handle = runtime.handle().clone();

        let discovery = Arc::new(build_discovery(&platform, &config));
        let sessions = Arc::new(Sessions::new());
        let ui_broker = Arc::new(UiBroker::new(Box::new(UiDelegateAdapter::new(ui))));
        let apikeys =
            Arc::new(ApikeyService::new(ApikeyConfig::default(), Box::new(SitesStore::new(&config.app_support_dir))));
        // Without this, `randseed.get` fails for every site with `-1029`
        // regardless of Settings' "ask before seeding" toggle, since that
        // toggle is only consulted once a provider exists to answer with
        // (`crates/openimzo-rpc/src/plugins/randseed.rs`'s own `get`/`consent`).
        let dispatcher_config =
            DispatcherConfig { randseed_provider: Some(Arc::new(PlatformRandseedProvider::new(platform.clone()))), ..DispatcherConfig::default() };
        let dispatcher = Arc::new(Dispatcher::new(dispatcher_config, sessions, discovery, ui_broker, apikeys));

        // A `settings.json` from a previous run takes effect immediately,
        // not only after the shell's first `update_settings` call.
        let settings = crate::settings::load(&config.app_support_dir);
        apply_settings(&dispatcher, &settings);

        let material_dir = PathBuf::from(&config.app_support_dir).join("tls");
        let server_config = if config.dev_mode {
            ServerConfig::development(material_dir)
        } else {
            ServerConfig::production(material_dir)
        };
        let ws_port = server_config.ws_port;
        let wss_port = server_config.wss_port;
        let server = Server::new(server_config, dispatcher.clone());
        // Subscribed before the server has ever been started: `Server`
        // keeps this same channel for its whole life, created in `new`
        // above, so there is no listener task racing to send its first
        // event before anyone is listening.
        let server_events = server.subscribe();

        let (events_tx, _) = broadcast::channel(events::EVENT_CAPACITY);
        events::install_log_forwarding(events_tx.clone(), Path::new(&config.logs_dir));
        dispatcher.set_observer(Arc::new(events::ActivityObserver::new(events_tx.clone())));
        let listeners = Arc::new(parking_lot::RwLock::new(ListenerStatus::default()));

        let inner = Inner {
            config,
            dispatcher,
            platform,
            settings,
            server,
            ws_port,
            wss_port,
            handle: None,
            _runtime: runtime,
        };
        let engine = Engine {
            inner: parking_lot::Mutex::new(inner),
            runtime: handle,
            events: events_tx.clone(),
            listeners: listeners.clone(),
        };
        {
            // `tokio::spawn` needs an entered runtime context, same as
            // `start` below; the task itself then runs on the runtime's own
            // workers for as long as the runtime lives, well past this
            // call returning.
            let _guard = engine.runtime.enter();
            engine.runtime.spawn(forward_server_events(server_events, listeners, events_tx));
        }
        Ok(engine)
    }

    /// Binds both listeners. Calling this twice while already running is a
    /// no-op rather than a double bind: the second call finds a handle
    /// already in place and leaves it alone.
    ///
    /// Asks `Platform::is_legacy_client_running` before either listener
    /// touches a socket, so a production-mode bind failure caused by the
    /// original can be reported as exactly that (`Server::start`'s
    /// `original_running` parameter) rather than a bare port conflict.
    /// Development mode moved both ports out of the original's way, so the
    /// answer is asked here regardless but only changes anything when
    /// `EngineConfig.dev_mode` is unset.
    ///
    /// Mostly synchronous, like before `start` became `async fn`:
    /// `Server::start` calls `tokio::spawn`, which needs an entered runtime
    /// context, and entering is a synchronous, thread-local thing, done by
    /// hand with `Handle::enter` for the span of that one call. The one
    /// exception is a stale handle from a previous attempt whose listeners
    /// both failed to bind (below) -- retrying that one genuinely awaits
    /// `ServerHandle::stop` first, so `inner`'s lock is never held across
    /// that await: it is taken and dropped inside its own block, and
    /// re-acquired fresh afterward, rather than reused across the `.await`
    /// (which `uniffi::export` would then refuse to compile, since a
    /// `parking_lot::MutexGuard` held across a suspension point is not
    /// `Send`).
    pub async fn start(&self) {
        let stale = {
            let mut inner = self.inner.lock();
            if inner.handle.is_some() {
                let listeners = *self.listeners.read();
                if listeners.ws || listeners.wss {
                    return;
                }
                // A handle only means `start` was called, not that either
                // listener came up: both binds can fail (most commonly
                // because the original E-IMZO already holds both ports),
                // and `listeners` -- kept current by
                // `forward_server_events`, which watches
                // `Server::subscribe` regardless of `start` -- says
                // neither is actually up. Left alone, this handle would
                // block every retry forever with nothing alive behind it
                // but the sweeper. Take it so it can be stopped properly
                // below -- there is nothing else worth preserving from it
                // -- before a fresh one is spawned.
                inner.handle.take()
            } else {
                None
            }
        };
        if let Some(handle) = stale {
            handle.stop().await;
        }

        let mut inner = self.inner.lock();
        if inner.handle.is_some() {
            // Another `start` call already replaced it while this one
            // awaited `stop`.
            return;
        }
        let original_running = inner.platform.is_legacy_client_running();
        let _guard = self.runtime.enter();
        inner.handle = Some(inner.server.start(original_running));
    }

    /// Unbinds both listeners and waits for every listener task and the
    /// sweeper to actually stop. A no-op if the engine was never started or
    /// is already stopped.
    ///
    /// `ServerHandle::stop` only flips a watch and joins the tasks `start`
    /// already spawned onto the engine's runtime; joining a `JoinHandle`
    /// needs no runtime entered on the polling side; the task runs on its
    /// own runtime's workers regardless of who is waiting on it. So unlike
    /// `start`, becoming `async fn` here drops the need to touch the
    /// runtime at all: this used to be `self.runtime.block_on(handle.stop())`
    /// because turning that future into a blocking call was the only way a
    /// sync method could run it; now the caller can simply await it.
    pub async fn stop(&self) {
        let handle = self.inner.lock().handle.take();
        if let Some(handle) = handle {
            handle.stop().await;
        }
    }

    /// A snapshot of what is up right now. `ws` and `wss` each reflect
    /// whether that specific listener actually bound, kept current by the
    /// background task `new` spawns onto the server's own `ServerEvent`s --
    /// not merely whether `start` was called, which says nothing about a
    /// listener that failed to bind (most commonly because the original
    /// E-IMZO already holds that port) while the other came up fine.
    /// `tls_trusted` is a live self-probe against the TLS listener,
    /// matching the spec's own wording for the field; it is `false`, not
    /// probed, whenever that listener is not actually up or there is no
    /// certificate to present. `ws_port`/`wss_port` are the ports actually
    /// configured for this run -- the original's own in production, the
    /// development pair when `dev_mode` is set -- so the shell can show
    /// which it is on without knowing the port numbers itself.
    ///
    /// The probe itself talks real TLS over the network (`reqwest`), which
    /// needs a live reactor and timer under it — unlike `stop`, awaiting it
    /// directly with no runtime entered would panic the first time it tries
    /// to open the socket. Entering the runtime and holding the guard
    /// across the `await` is not an option either: `Handle::enter`'s guard
    /// is `!Send`, and uniffi's async machinery requires the exported
    /// method's future to be `Send`. So this spawns the probe onto the
    /// engine's own runtime, where it runs with that runtime's reactor
    /// already live, and only awaits the resulting `JoinHandle`, which — like
    /// `stop`'s join above — needs no entered runtime to wait on.
    pub async fn status(&self) -> EngineStatus {
        let (dev_mode, has_cert, ws_port, wss_port) = {
            let inner = self.inner.lock();
            (inner.config.dev_mode, inner.server.certificate_pem().is_some(), inner.ws_port, inner.wss_port)
        };
        let ListenerStatus { ws, wss } = *self.listeners.read();
        let tls_trusted = if wss && has_cert {
            self.runtime.spawn(openimzo_server::tls::probe_trust(wss_port)).await.unwrap_or(false)
        } else {
            false
        };
        EngineStatus { ws, wss, tls_trusted, dev_mode, ws_port, wss_port }
    }

    /// Reads the server's own certificate and asks `Platform` to install it
    /// as trusted, `system_wide` choosing the login or System keychain.
    /// Returns `false` without asking `Platform` at all if the TLS listener
    /// never generated a certificate — there is nothing to trust yet.
    /// Always sends `Event::TlsTrustChanged` once the platform call
    /// returns, success or failure alike: the shell re-queries `status` on
    /// that event, and a failed attempt still means the answer on screen is
    /// stale.
    pub async fn install_tls_trust(&self, system_wide: bool) -> bool {
        let (cert_pem, platform) = {
            let inner = self.inner.lock();
            (inner.server.certificate_pem(), inner.platform.clone())
        };
        let Some(cert_pem) = cert_pem else {
            return false;
        };
        let installed = platform.install_tls_trust(cert_pem, system_wide).await;
        let _ = self.events.send(Event::TlsTrustChanged);
        installed
    }

    /// A fresh subscription to every `Event` from this moment onward. Sync,
    /// unlike every other call here: minting one only clones a broadcast
    /// sender's receiver, nothing to await.
    pub fn events(&self) -> Arc<EventStream> {
        Arc::new(EventStream::new(self.events.subscribe()))
    }

    /// Every key file on every disk, PFX and YTKS both: `KeyInfo` plus the
    /// certificate summary section 3.6 asks for. Rebuilds a `Discovery`
    /// from the platform's current volumes on every call
    /// (`build_discovery`) rather than reusing the dispatcher's own, so a
    /// volume that came or went is reflected without waiting on
    /// `rescan_keys` first.
    ///
    /// No `Result`, matching the spec's own signature: a failure here
    /// degrades to an empty or partial list rather than an error, the same
    /// way `status` degrades `tls_trusted` to `false` rather than failing
    /// outright.
    pub async fn list_keys(&self) -> Vec<KeyEntry> {
        let (platform, config) = {
            let inner = self.inner.lock();
            (inner.platform.clone(), inner.config.clone())
        };
        let infos = self
            .runtime
            .spawn_blocking(move || {
                let discovery = build_discovery(&platform, &config);
                let mut out = discovery.scan(KeyKind::Pfx);
                out.extend(discovery.scan(KeyKind::Ytks));
                out
            })
            .await
            .unwrap_or_default();
        infos.into_iter().map(key_entry_from_info).collect()
    }

    /// Re-scans every disk and tells the shell the key list may be
    /// different now (`Event::KeysChanged`) — called on volume mount and
    /// unmount, and by "Rescan" in the UI (section 3.3; no polling).
    /// `Discovery` caches nothing, so `list_keys` recomputes its own answer
    /// fresh regardless of what this scan finds; running it here anyway,
    /// rather than only firing the event, puts a bad path or a permissions
    /// problem in the log at the moment of an explicit rescan instead of
    /// silently deferring it to whichever `list_keys` call happens to
    /// follow.
    pub async fn rescan_keys(&self) {
        let (platform, config) = {
            let inner = self.inner.lock();
            (inner.platform.clone(), inner.config.clone())
        };
        self.runtime
            .spawn_blocking(move || {
                let discovery = build_discovery(&platform, &config);
                let _ = discovery.scan(KeyKind::Pfx);
                let _ = discovery.scan(KeyKind::Ytks);
            })
            .await
            .ok();
        let _ = self.events.send(Event::KeysChanged);
    }

    /// Rewrites the key file at `path` under `new` instead of `old`,
    /// keeping every alias and chain: `openimzo_pki::pkcs12`/`ytks`'s own
    /// `read`/`write` round trip, exactly what `openimzo-cli`'s
    /// `PfxChangePassword` and its YKS analog already do, run off the
    /// runtime. The rewrite itself goes through
    /// `openimzo_rpc::plugins::keystore::overwrite_key_file` — the same
    /// temp-then-rename helper the `pfx`/`ytks` plugins' own
    /// `change_password` handlers use — rather than a second
    /// implementation of "replace a removable disk's only copy of a
    /// private key without a power cut costing it".
    pub async fn change_password(&self, path: String, old: String, new: String) -> Result<(), EngineError> {
        let old = Zeroizing::new(old);
        let new = Zeroizing::new(new);
        let path_buf = PathBuf::from(&path);
        let is_pfx = extension_is(&path_buf, "pfx");
        let is_yks = extension_is(&path_buf, "yks");
        let read_path = path_buf.clone();
        let bytes = self
            .runtime
            .spawn_blocking(move || -> std::result::Result<Vec<u8>, EngineError> {
                let data = std::fs::read(&read_path).map_err(|e| {
                    tracing::debug!(error = %e, "change_password: could not read key file");
                    EngineError::KeyFile
                })?;
                if is_pfx {
                    let store = openimzo_pki::pkcs12::read(&data, &old).map_err(map_pki_error)?;
                    openimzo_pki::pkcs12::write(&store, &new, &mut rand_core::OsRng).map_err(map_pki_error)
                } else if is_yks {
                    let store = openimzo_pki::ytks::read(&data, &old).map_err(map_pki_error)?;
                    openimzo_pki::ytks::write(&store, &new, &mut rand_core::OsRng).map_err(map_pki_error)
                } else {
                    Err(EngineError::KeyFile)
                }
            })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "change_password: blocking task panicked");
                EngineError::Failed
            })??;
        // Spawned onto `self.runtime`, not awaited bare: `overwrite_key_file` runs on the
        // blocking pool via the free-function `tokio::task::spawn_blocking` (see
        // `openimzo_rpc::plugins::keystore::blocking`), which panics ("there is no reactor
        // running") unless the calling context already has a Tokio runtime entered. Every other
        // method in this file that needs the reactor gets there through `self.runtime`
        // (`status`'s own doc comment explains why) — this call was the one write path that
        // still awaited such a future bare, which a real password change through the macOS
        // shell hit immediately.
        self.runtime
            .spawn(async move { openimzo_rpc::plugins::keystore::overwrite_key_file(&path_buf, &bytes).await })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "change_password: write task panicked");
                EngineError::Failed
            })?
            .map_err(|e| {
                tracing::debug!(error = %e, "change_password: could not rewrite key file");
                EngineError::Failed
            })
    }

    /// Writes a YKS alongside `path` with the same password and the same
    /// keys and chain — same directory, extension swapped, matching the
    /// original's own converter action ("Конвертировать в YKS") — rather
    /// than taking a second, output-path argument the original's own action
    /// never has either.
    pub async fn convert_pfx_to_yks(&self, path: String, password: String) -> Result<(), EngineError> {
        let password = Zeroizing::new(password);
        let input = PathBuf::from(&path);
        let output = input.with_extension("yks");
        if output.exists() {
            // Refusing outright when something already sits at `output` is
            // a deliberate choice, not a bug to "fix" into an overwrite: a
            // format conversion must never destroy a key file that is
            // already there, since the bytes it would replace may be the
            // only copy of a signing key in existence.
            //
            // This check alone only makes the refusal true sequentially,
            // not under a race: it runs here, on the calling task, while
            // the read/decrypt/re-encrypt below is handed to the blocking
            // pool and takes real time. A file created at `output` during
            // that window would still be silently replaced if the write
            // below went through the ordinary `overwrite_key_file`. It
            // stays anyway because it gives the ordinary caller an
            // immediate, plain refusal; `create_key_file_exclusive` below
            // is the backstop that makes the refusal hold even under that
            // race, by making the filesystem itself the one that refuses.
            return Err(EngineError::Failed);
        }
        let yks = self
            .runtime
            .spawn_blocking(move || -> std::result::Result<Vec<u8>, EngineError> {
                let data = std::fs::read(&input).map_err(|e| {
                    tracing::debug!(error = %e, "convert_pfx_to_yks: could not read key file");
                    EngineError::KeyFile
                })?;
                let store = openimzo_pki::pkcs12::read(&data, &password).map_err(map_pki_error)?;
                let now_ms = chrono::Utc::now().timestamp_millis();
                openimzo_pki::ytks::write(&openimzo_pki::ytks::from_pkcs12(&store, now_ms), &password, &mut rand_core::OsRng)
                    .map_err(map_pki_error)
            })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "convert_pfx_to_yks: blocking task panicked");
                EngineError::Failed
            })??;
        // See `change_password`'s own comment on the identical fix: spawned onto `self.runtime`
        // rather than awaited bare, since `create_key_file_exclusive` needs a live reactor.
        self.runtime
            .spawn(async move { openimzo_rpc::plugins::keystore::create_key_file_exclusive(&output, &yks).await })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "convert_pfx_to_yks: write task panicked");
                EngineError::Failed
            })?
            .map_err(|e| {
                tracing::debug!(error = %e, "convert_pfx_to_yks: could not write yks file");
                EngineError::Failed
            })
    }

    /// Mirror of `convert_pfx_to_yks`: writes a PFX alongside `path` with
    /// the same password and the same keys and chain, matching the
    /// original's "Конвертировать из YKS".
    pub async fn convert_yks_to_pfx(&self, path: String, password: String) -> Result<(), EngineError> {
        let password = Zeroizing::new(password);
        let input = PathBuf::from(&path);
        let output = input.with_extension("pfx");
        if output.exists() {
            // Refusing outright when something already sits at `output` is
            // a deliberate choice, not a bug to "fix" into an overwrite —
            // the same rule, and the same reason, as
            // `convert_pfx_to_yks`'s own check.
            //
            // As in `convert_pfx_to_yks`, this check alone only makes the
            // refusal true sequentially, not under a race, since the slow
            // read/decrypt/re-encrypt below runs on the blocking pool
            // after this check has already passed. It stays for the
            // ordinary, immediate refusal; `create_key_file_exclusive`
            // below is the backstop that holds even under a race.
            return Err(EngineError::Failed);
        }
        let pfx = self
            .runtime
            .spawn_blocking(move || -> std::result::Result<Vec<u8>, EngineError> {
                let data = std::fs::read(&input).map_err(|e| {
                    tracing::debug!(error = %e, "convert_yks_to_pfx: could not read key file");
                    EngineError::KeyFile
                })?;
                let store = openimzo_pki::ytks::read(&data, &password).map_err(map_pki_error)?;
                openimzo_pki::pkcs12::write(&openimzo_pki::ytks::to_pkcs12(&store), &password, &mut rand_core::OsRng)
                    .map_err(map_pki_error)
            })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "convert_yks_to_pfx: blocking task panicked");
                EngineError::Failed
            })??;
        // See `change_password`'s own comment on the identical fix: spawned onto `self.runtime`
        // rather than awaited bare, since `create_key_file_exclusive` needs a live reactor.
        self.runtime
            .spawn(async move { openimzo_rpc::plugins::keystore::create_key_file_exclusive(&output, &pfx).await })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "convert_yks_to_pfx: write task panicked");
                EngineError::Failed
            })?
            .map_err(|e| {
                tracing::debug!(error = %e, "convert_yks_to_pfx: could not write pfx file");
                EngineError::Failed
            })
    }

    /// The QR-key hex payload for a PFX's first key, matching the
    /// original's own "Конвертировать в QR-key" action — PFX only, which is
    /// also where the "exactly one private key" requirement comes from,
    /// enforced by `openimzo_pki::qrkey::export` itself.
    pub async fn export_qr_key(&self, path: String, password: String) -> Result<Vec<u8>, EngineError> {
        let password = Zeroizing::new(password);
        let path_buf = PathBuf::from(&path);
        if !extension_is(&path_buf, "pfx") {
            return Err(EngineError::KeyFile);
        }
        self.runtime
            .spawn_blocking(move || -> std::result::Result<Vec<u8>, EngineError> {
                let data = std::fs::read(&path_buf).map_err(|e| {
                    tracing::debug!(error = %e, "export_qr_key: could not read key file");
                    EngineError::KeyFile
                })?;
                let store = openimzo_pki::pkcs12::read(&data, &password).map_err(map_pki_error)?;
                let key = store.keys.first().ok_or(EngineError::KeyFile)?;
                openimzo_pki::qrkey::export(&key.private_key, &password).map_err(map_pki_error)
            })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "export_qr_key: blocking task panicked");
                EngineError::Failed
            })?
    }

    /// The certificate summary for one alias inside a password-protected PFX — everything
    /// `key_entry_from_info` cannot fill in for a PFX row without a password
    /// (a recorded task brief). Reads exactly the
    /// one file and alias the shell names, only when asked: nothing here scans or unlocks any
    /// other key, and `password` lives only for this call, wrapped in `Zeroizing` and dropped at
    /// the end of the blocking closure, the same discipline every other password path in this
    /// file already follows. Key material and parsing stay here, in Rust — the shell never opens
    /// the file itself.
    pub async fn unlock_key(&self, path: String, alias: String, password: String) -> Result<CertificateSummary, EngineError> {
        let password = Zeroizing::new(password);
        let path_buf = PathBuf::from(&path);
        if !extension_is(&path_buf, "pfx") {
            return Err(EngineError::KeyFile);
        }
        self.runtime
            .spawn_blocking(move || -> std::result::Result<CertificateSummary, EngineError> {
                let data = std::fs::read(&path_buf).map_err(|e| {
                    tracing::debug!(error = %e, "unlock_key: could not read key file");
                    EngineError::KeyFile
                })?;
                let store = openimzo_pki::pkcs12::read(&data, &password).map_err(map_pki_error)?;
                let key = store.keys.iter().find(|k| k.alias == alias).ok_or(EngineError::KeyFile)?;
                // End-entity certificate first (`pkcs12::KeyEntry::chain`'s own doc comment).
                let cert = key.chain.first().ok_or(EngineError::KeyFile)?;
                let view = openimzo_pki::x509::certificate_view(cert).map_err(|e| {
                    tracing::debug!(error = %e, "unlock_key: could not read certificate");
                    EngineError::KeyFile
                })?;
                let not_after = openimzo_pki::x509::system_time(&cert.tbs_certificate.validity.not_after);
                let expired = not_after < std::time::SystemTime::now();
                let identity = crate::identity::identity_from(&alias, &view.subject_name);
                let days_remaining = whole_days_until(openimzo_pki::x509::epoch_millis(not_after));
                Ok(CertificateSummary {
                    subject_name: view.subject_name,
                    issuer_name: view.issuer_name,
                    serial_number: view.serial_number,
                    valid_from: view.valid_from,
                    valid_to: view.valid_to,
                    public_key_alg_name: view.public_key.map(|p| p.key_alg_name).unwrap_or_default(),
                    expired,
                    identity,
                    days_remaining,
                })
            })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "unlock_key: blocking task panicked");
                EngineError::Failed
            })?
    }

    /// The settings read at construction, or the last ones
    /// `update_settings` wrote — never re-read from disk here, so this
    /// stays cheap.
    pub async fn settings(&self) -> Settings {
        let inner = self.inner.lock();
        inner.settings.clone()
    }

    /// Persists `settings` to `settings.json` and applies the parts the
    /// core itself reads (`apply_settings`) right away, rather than only on
    /// the next `Engine::new`.
    pub async fn update_settings(&self, settings: Settings) {
        let (dispatcher, app_support_dir) = {
            let mut inner = self.inner.lock();
            inner.settings = settings.clone();
            (inner.dispatcher.clone(), inner.config.app_support_dir.clone())
        };
        apply_settings(&dispatcher, &settings);
        self.runtime.spawn_blocking(move || crate::settings::save(&app_support_dir, &settings)).await.ok();
    }

    /// Every known site: the api-key cache and the permission decisions,
    /// merged by `ApikeyService::sites` in `openimzo-rpc`'s origin gate.
    pub async fn sites(&self) -> Vec<Site> {
        let apikeys = {
            let inner = self.inner.lock();
            inner.dispatcher.ctx().apikeys.clone()
        };
        apikeys
            .sites()
            .into_iter()
            .map(|record| Site {
                origin: record.origin,
                registered: record.registered,
                allowed_always: record.allowed_always,
            })
            .collect()
    }

    /// Forgets `domain` — a `Site.origin` value, bare domain or full origin
    /// either way — from both the api-key cache and every permission
    /// decision recorded for it, in memory and on disk
    /// (`ApikeyService::forget_site`).
    pub async fn forget_site(&self, domain: String) {
        let apikeys = {
            let inner = self.inner.lock();
            inner.dispatcher.ctx().apikeys.clone()
        };
        self.runtime.spawn_blocking(move || apikeys.forget_site(&domain)).await.ok();
    }

    /// Forgets every password any session currently has cached
    /// (`Sessions::clear_all_passwords`), regardless of how much of its own
    /// TTL was left.
    pub async fn clear_password_cache(&self) {
        let inner = self.inner.lock();
        inner.dispatcher.ctx().sessions.clear_all_passwords();
    }

    /// No PIN cache exists yet — `ask_pin` and hardware sessions are phase
    /// 6 work (section 3.6) — so this is a deliberate no-op until then, not
    /// a forgotten call.
    pub async fn clear_pin_cache(&self) {}
}
