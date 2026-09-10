//! How an RPC function asks the person in front of the computer for something.
//! The dispatcher calls `UiBroker`; the app implements `UiDelegate`. Requests
//! are served one at a time so two sites cannot stack dialogs.

use async_trait::async_trait;
use std::fmt;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the broker waits for the app to take a stale dialog down before it
/// gives up and lets the next request have its turn anyway.
pub const DISMISS_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a request waits for its turn before giving up. A person can only
/// answer one dialog at a time, so a queue longer than a couple of deep is a
/// site misbehaving rather than a person being slow.
pub const TURN_WAIT_TIMEOUT: Duration = Duration::from_secs(90);

/// How many requests may be waiting for a turn at once. Past this, a new
/// request is refused immediately rather than joining an unbounded queue.
pub const MAX_WAITING: usize = 8;

#[derive(Clone, Debug)]
pub struct PasswordRequest {
    /// Site the request is on behalf of, e.g. `my.gov.uz`.
    pub origin: String,
    /// What the password opens, shown to the user (a file path or key name).
    pub subject: String,
    /// Set when a previous attempt failed, so the panel can show it.
    pub error: Option<String>,
    /// Whether to offer "remember for 6 hours".
    pub allow_remember: bool,
}

#[derive(Clone)]
pub struct PasswordAnswer {
    pub password: Zeroizing<String>,
    pub remember: bool,
}

impl fmt::Debug for PasswordAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordAnswer")
            .field("password", &"<redacted>")
            .field("remember", &self.remember)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct PermissionRequest {
    pub origin: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionAnswer {
    AllowOnce,
    AllowAlways,
    Deny,
}

#[derive(Clone, Debug)]
pub struct NewPfxRequest {
    pub origin: String,
    /// Candidate disks the file may be written to.
    pub disks: Vec<String>,
    /// Relative path of the file to create, e.g. `DSKEYS/DS123.pfx`.
    pub file_path: String,
}

#[derive(Clone)]
pub struct NewPfxAnswer {
    pub disk: String,
    pub password: Zeroizing<String>,
}

impl fmt::Debug for NewPfxAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewPfxAnswer")
            .field("disk", &self.disk)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct LegacyAlgRequest {
    pub origin: String,
    pub requested: String,
    pub suggested: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyAlgAnswer {
    UseSuggested,
    KeepRequested,
}

#[derive(Clone, Debug)]
pub struct RandseedRequest {
    pub origin: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    Allow,
    Deny,
}

#[derive(Debug, thiserror::Error)]
pub enum UiError {
    #[error("cancelled by the user")]
    Cancelled,
    #[error("timed out")]
    TimedOut,
    #[error("no user interface is available")]
    Unavailable,
    /// Refused before ever asking the delegate: either `MAX_WAITING` requests
    /// were already ahead of this one, or `TURN_WAIT_TIMEOUT` passed before a
    /// turn came free. Every existing caller already maps a `UiError` it
    /// doesn't otherwise recognise to the same cancelled-shaped status this
    /// one gets, so no call site needs to change for it.
    #[error("too many requests are already waiting for a turn")]
    Busy,
}

/// Implemented by the app. Every method may take as long as the person does;
/// the broker applies the deadline.
#[async_trait]
pub trait UiDelegate: Send + Sync {
    async fn ask_password(&self, request: PasswordRequest) -> Result<PasswordAnswer, UiError>;
    async fn ask_permission(&self, request: PermissionRequest) -> Result<PermissionAnswer, UiError>;
    async fn ask_new_pfx(&self, request: NewPfxRequest) -> Result<NewPfxAnswer, UiError>;
    async fn confirm_legacy_algorithm(&self, request: LegacyAlgRequest) -> Result<LegacyAlgAnswer, UiError>;
    async fn confirm_randseed(&self, request: RandseedRequest) -> Result<Consent, UiError>;

    /// Called when a request's deadline passes and the answer is abandoned.
    /// Close whatever dialog is on screen: the original hides its window rather
    /// than leaving it up for a request nobody is waiting on any more.
    async fn dismiss(&self) {}
}

/// The delegate used when the program runs with no user interface. Refuses
/// every request.
pub struct NoUi;

#[async_trait]
impl UiDelegate for NoUi {
    async fn ask_password(&self, _: PasswordRequest) -> Result<PasswordAnswer, UiError> {
        Err(UiError::Unavailable)
    }
    async fn ask_permission(&self, _: PermissionRequest) -> Result<PermissionAnswer, UiError> {
        Err(UiError::Unavailable)
    }
    async fn ask_new_pfx(&self, _: NewPfxRequest) -> Result<NewPfxAnswer, UiError> {
        Err(UiError::Unavailable)
    }
    async fn confirm_legacy_algorithm(&self, _: LegacyAlgRequest) -> Result<LegacyAlgAnswer, UiError> {
        Err(UiError::Unavailable)
    }
    async fn confirm_randseed(&self, _: RandseedRequest) -> Result<Consent, UiError> {
        Err(UiError::Unavailable)
    }
}

/// Serializes user interaction and applies the deadline.
pub struct UiBroker {
    delegate: Box<dyn UiDelegate>,
    turn: Mutex<()>,
    timeout: Duration,
    /// Admission gate for the turn mutex: a permit is held only while a
    /// request is waiting to acquire `turn`, and released the moment it
    /// wins, so this never bounds how many requests are being served (the
    /// turn mutex already limits that to one) — only how many may be queued
    /// up behind it. `try_acquire` refuses a request outright once
    /// `MAX_WAITING` others are already waiting.
    waiting: Semaphore,
}

impl UiBroker {
    pub fn new(delegate: Box<dyn UiDelegate>) -> Self {
        UiBroker { delegate, turn: Mutex::new(()), timeout: REQUEST_TIMEOUT, waiting: Semaphore::new(MAX_WAITING) }
    }

    pub fn with_timeout(delegate: Box<dyn UiDelegate>, timeout: Duration) -> Self {
        UiBroker { delegate, turn: Mutex::new(()), timeout, waiting: Semaphore::new(MAX_WAITING) }
    }

    async fn serialized<T, F>(&self, f: F) -> Result<T, UiError>
    where
        F: std::future::Future<Output = Result<T, UiError>>,
    {
        // Refuse past the cap rather than growing the queue without bound:
        // `try_acquire` never itself waits.
        let admitted = self.waiting.try_acquire().map_err(|_| UiError::Busy)?;
        // A person can only answer one dialog at a time; give up rather than
        // let one site sitting on a prompt stall every other site's turn
        // forever.
        let _guard = match tokio::time::timeout(TURN_WAIT_TIMEOUT, self.turn.lock()).await {
            Ok(guard) => guard,
            Err(_) => return Err(UiError::Busy),
        };
        // The turn is won; free this waiting-room slot for the next caller.
        drop(admitted);
        match tokio::time::timeout(self.timeout, f).await {
            Ok(result) => result,
            Err(_) => {
                // Still holding the turn, so the stale dialog comes down before
                // the next request opens one. A delegate that hangs here must not
                // wedge the broker, hence the second, shorter deadline.
                let _ = tokio::time::timeout(DISMISS_TIMEOUT, self.delegate.dismiss()).await;
                Err(UiError::TimedOut)
            }
        }
    }

    pub async fn ask_password(&self, request: PasswordRequest) -> Result<PasswordAnswer, UiError> {
        self.serialized(self.delegate.ask_password(request)).await
    }

    pub async fn ask_permission(&self, request: PermissionRequest) -> Result<PermissionAnswer, UiError> {
        self.serialized(self.delegate.ask_permission(request)).await
    }

    pub async fn ask_new_pfx(&self, request: NewPfxRequest) -> Result<NewPfxAnswer, UiError> {
        self.serialized(self.delegate.ask_new_pfx(request)).await
    }

    pub async fn confirm_legacy_algorithm(&self, request: LegacyAlgRequest) -> Result<LegacyAlgAnswer, UiError> {
        self.serialized(self.delegate.confirm_legacy_algorithm(request)).await
    }

    pub async fn confirm_randseed(&self, request: RandseedRequest) -> Result<Consent, UiError> {
        self.serialized(self.delegate.confirm_randseed(request)).await
    }
}
