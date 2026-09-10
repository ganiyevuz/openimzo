//! The two callback interfaces the macOS shell implements, and the adapter
//! that lets the foreign `UiDelegate` stand in for `eimzo_rpc::ui::UiDelegate`
//! so the broker built in phase 2A drives the real app unchanged.
//!
//! Every record here is this crate's own — none of them is the identically
//! named type in `eimzo_rpc::ui`, which carries different fields (it has no
//! `id` or `deadline`, for instance, since only the FFI boundary needs
//! those). The adapter's job is exactly translating between the two.

use async_trait::async_trait;
use rand::RngCore;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroizing;

/// What the person needs to answer a password prompt. `id` correlates this
/// one prompt with the `cancel` call if its deadline passes unanswered.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasswordRequest {
    pub id: String,
    pub origin: String,
    /// A file path or key alias, whichever the core has to hand — its own
    /// `PasswordRequest` carries only the one field for this, so there is
    /// nothing to split into separate "key alias" and "file path" fields
    /// without guessing which one applies.
    pub subject: String,
    pub allow_remember: bool,
    /// Set when a previous attempt was rejected, so the panel can show why.
    pub error: Option<String>,
    /// Seconds until the broker gives up waiting and abandons the prompt.
    pub deadline_secs: u32,
}

#[derive(uniffi::Record)]
pub struct PasswordAnswer {
    pub password: String,
    pub remember: bool,
}

impl fmt::Debug for PasswordAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordAnswer").field("password", &"<redacted>").field("remember", &self.remember).finish()
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PermissionRequest {
    pub origin: String,
    /// Seconds until the broker gives up waiting and abandons the prompt.
    pub deadline_secs: u32,
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PermissionAnswer {
    AllowOnce,
    AllowAlways,
    Deny,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NewPfxRequest {
    pub origin: String,
    /// Candidate disks the file may be written to.
    pub disks: Vec<String>,
    /// Relative path of the file to create, e.g. `DSKEYS/DS123.pfx`.
    pub file_path: String,
    /// Seconds until the broker gives up waiting and abandons the prompt.
    pub deadline_secs: u32,
}

#[derive(uniffi::Record)]
pub struct NewPfxAnswer {
    pub disk: String,
    pub password: String,
}

impl fmt::Debug for NewPfxAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewPfxAnswer").field("disk", &self.disk).field("password", &"<redacted>").finish()
    }
}

/// Implemented in Swift, called on the main actor, one at a time. The broker
/// in `eimzo-rpc` already serializes these and applies the deadline, so an
/// implementation may block on a person for as long as the panel is up.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait UiDelegate: Send + Sync {
    async fn ask_password(&self, request: PasswordRequest) -> Option<PasswordAnswer>;
    async fn ask_permission(&self, request: PermissionRequest) -> PermissionAnswer;
    async fn ask_new_pfx(&self, request: NewPfxRequest) -> Option<NewPfxAnswer>;
    async fn confirm_legacy_algorithm(&self, origin: String, requested: String, suggested: String, deadline_secs: u32) -> bool;
    async fn confirm_randseed(&self, origin: String, deadline_secs: u32) -> bool;
    async fn notify(&self, level: String, title: String, text: String);
    /// The deadline passed and the answer is no longer wanted: take the
    /// panel down.
    async fn cancel(&self, request_id: String);
}

/// Things only the shell can do.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait Platform: Send + Sync {
    fn app_support_dir(&self) -> String;
    fn logs_dir(&self) -> String;
    /// Where removable volumes are mounted. `/Volumes` on macOS.
    fn volumes_roots(&self) -> Vec<String>;
    fn is_legacy_client_running(&self) -> bool;
    async fn install_tls_trust(&self, cert_pem: String, system_wide: bool) -> bool;
    /// The machine's hostname and network interfaces, in whatever shape the
    /// shell likes — `randseed.get`'s `RandseedProvider`
    /// (`eimzo_rpc::plugins::randseed`) treats this as an opaque blob, same
    /// as `eimzo-cli`'s own `CliRandseedProvider`. A synchronous method,
    /// like `volumes_roots` and `is_legacy_client_running` above: gathering
    /// this never needs to suspend.
    fn network_description(&self) -> Vec<u8>;
}

/// Adapts `Platform::network_description` to `eimzo_rpc`'s own
/// `RandseedProvider`, so the macOS build has a real answer for
/// `randseed.get` — `eimzo-cli` wires its own `CliRandseedProvider` for the
/// same trait, gathering the same kind of information with the `if-addrs`
/// and `hostname` crates directly, since it has no shell to ask.
///
/// The two are deliberately not the same code: every other machine-specific
/// fact this crate needs (`volumes_roots`, `is_legacy_client_running`,
/// `app_support_dir`) already goes through `Platform`, answered by Swift,
/// rather than a Rust crate reading the environment directly — this keeps
/// that same line rather than adding `if-addrs`/`hostname` as a third,
/// unnecessary dependency of `eimzo-ffi` (or, worse, copy-pasting the CLI's
/// own gathering code into this crate, which is what the task that added
/// this explicitly ruled out). What both providers must agree on —
/// encryption, TLV framing, the RSA-wrapped key — stays solely in
/// `eimzo_rpc::plugins::randseed`, so the two can never diverge on the wire
/// format; only the raw bytes each embedder hands in differ.
pub(crate) struct PlatformRandseedProvider(Arc<dyn Platform>);

impl PlatformRandseedProvider {
    pub(crate) fn new(platform: Arc<dyn Platform>) -> Self {
        PlatformRandseedProvider(platform)
    }
}

impl eimzo_rpc::plugins::randseed::RandseedProvider for PlatformRandseedProvider {
    fn network_description(&self) -> Vec<u8> {
        self.0.network_description()
    }
}

/// The one clock every request's `deadline_secs` is read from
/// (`eimzo_rpc::ui::REQUEST_TIMEOUT`), so the panels' countdowns can never
/// drift from the deadline the broker itself actually enforces.
fn deadline_secs() -> u32 {
    eimzo_rpc::ui::REQUEST_TIMEOUT.as_secs() as u32
}

/// 16 random bytes, hex-encoded — the same shape `eimzo_keys::Sessions` uses
/// for its own ids, reused here for a dialog's correlation id.
fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Makes the foreign `UiDelegate` satisfy `eimzo_rpc::ui::UiDelegate`. The
/// broker serializes every call through this adapter, so at most one dialog
/// is ever open at a time; `current_request` remembers that dialog's id so a
/// later `dismiss` can tell the shell which one to take down, regardless of
/// which kind of prompt it was.
pub(crate) struct UiDelegateAdapter {
    ui: Arc<dyn UiDelegate>,
    current_request: parking_lot::Mutex<String>,
}

impl UiDelegateAdapter {
    pub(crate) fn new(ui: Arc<dyn UiDelegate>) -> Self {
        UiDelegateAdapter { ui, current_request: parking_lot::Mutex::new(String::new()) }
    }

    /// Mints a fresh id for the dialog about to open and remembers it.
    fn begin_request(&self) -> String {
        let id = new_request_id();
        *self.current_request.lock() = id.clone();
        id
    }
}

#[async_trait]
impl eimzo_rpc::ui::UiDelegate for UiDelegateAdapter {
    async fn ask_password(
        &self,
        request: eimzo_rpc::ui::PasswordRequest,
    ) -> Result<eimzo_rpc::ui::PasswordAnswer, eimzo_rpc::ui::UiError> {
        let id = self.begin_request();
        let foreign_request = PasswordRequest {
            id,
            origin: request.origin,
            subject: request.subject,
            allow_remember: request.allow_remember,
            error: request.error,
            deadline_secs: deadline_secs(),
        };
        match self.ui.ask_password(foreign_request).await {
            // Built straight from the value the shell hands back; nothing
            // else in this crate keeps a second copy of it, so there is
            // no lingering plaintext to zero out separately.
            Some(answer) => {
                Ok(eimzo_rpc::ui::PasswordAnswer { password: Zeroizing::new(answer.password), remember: answer.remember })
            }
            None => Err(eimzo_rpc::ui::UiError::Cancelled),
        }
    }

    async fn ask_permission(
        &self,
        request: eimzo_rpc::ui::PermissionRequest,
    ) -> Result<eimzo_rpc::ui::PermissionAnswer, eimzo_rpc::ui::UiError> {
        self.begin_request();
        let answer = self.ui.ask_permission(PermissionRequest { origin: request.origin, deadline_secs: deadline_secs() }).await;
        Ok(match answer {
            PermissionAnswer::AllowOnce => eimzo_rpc::ui::PermissionAnswer::AllowOnce,
            PermissionAnswer::AllowAlways => eimzo_rpc::ui::PermissionAnswer::AllowAlways,
            PermissionAnswer::Deny => eimzo_rpc::ui::PermissionAnswer::Deny,
        })
    }

    async fn ask_new_pfx(
        &self,
        request: eimzo_rpc::ui::NewPfxRequest,
    ) -> Result<eimzo_rpc::ui::NewPfxAnswer, eimzo_rpc::ui::UiError> {
        self.begin_request();
        let foreign_request = NewPfxRequest {
            origin: request.origin,
            disks: request.disks,
            file_path: request.file_path,
            deadline_secs: deadline_secs(),
        };
        match self.ui.ask_new_pfx(foreign_request).await {
            Some(answer) => {
                Ok(eimzo_rpc::ui::NewPfxAnswer { disk: answer.disk, password: Zeroizing::new(answer.password) })
            }
            None => Err(eimzo_rpc::ui::UiError::Cancelled),
        }
    }

    async fn confirm_legacy_algorithm(
        &self,
        request: eimzo_rpc::ui::LegacyAlgRequest,
    ) -> Result<eimzo_rpc::ui::LegacyAlgAnswer, eimzo_rpc::ui::UiError> {
        self.begin_request();
        let use_suggested = self
            .ui
            .confirm_legacy_algorithm(request.origin, request.requested, request.suggested, deadline_secs())
            .await;
        Ok(if use_suggested { eimzo_rpc::ui::LegacyAlgAnswer::UseSuggested } else { eimzo_rpc::ui::LegacyAlgAnswer::KeepRequested })
    }

    async fn confirm_randseed(
        &self,
        request: eimzo_rpc::ui::RandseedRequest,
    ) -> Result<eimzo_rpc::ui::Consent, eimzo_rpc::ui::UiError> {
        self.begin_request();
        let allow = self.ui.confirm_randseed(request.origin, deadline_secs()).await;
        Ok(if allow { eimzo_rpc::ui::Consent::Allow } else { eimzo_rpc::ui::Consent::Deny })
    }

    /// The deadline passed and `f` in `UiBroker::serialized` was dropped
    /// without an answer; tell the shell to take its panel down for real,
    /// rather than leaving a dropped Rust future as the only signal.
    async fn dismiss(&self) {
        let id = self.current_request.lock().clone();
        self.ui.cancel(id).await;
    }
}
