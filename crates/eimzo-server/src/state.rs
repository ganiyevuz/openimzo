//! What every request handler can reach.

use crate::tls::TlsMaterial;
use eimzo_rpc::dispatch::Dispatcher;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::watch;

/// Reported to the shell so it can show why a listener is not up, and when
/// something changes underneath it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerEvent {
    /// A listener came up on this port.
    Listening { port: u16, tls: bool },
    /// A listener could not bind. `reason` is already human-readable and
    /// carries no internal detail.
    BindFailed { port: u16, tls: bool, reason: String },
    /// Both listeners are down because `stop` was called.
    Stopped,
}

#[derive(Clone)]
pub struct AppState {
    pub dispatcher: Arc<Dispatcher>,
    pub events: tokio::sync::broadcast::Sender<ServerEvent>,
    pub tls: Arc<RwLock<Option<TlsMaterial>>>,
    /// Flipped to `true` by `ServerHandle::stop`. Held here, not just inside
    /// `run.rs`, so a connection handler reached only through an axum
    /// extractor (a WebSocket's own message loop, spawned independently of
    /// either listener) can still `subscribe()` to it.
    pub shutdown: watch::Sender<bool>,
}
