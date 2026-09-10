//! Binding, serving and stopping the two listeners.

use crate::http;
use crate::state::{AppState, ServerEvent};
use crate::tls;
use crate::ServerConfig;
use openimzo_rpc::dispatch::Dispatcher;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

/// How often expired sessions and enrolments are dropped.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Generous for a loopback TLS handshake. A client that completes the TCP
/// connection and then sends nothing would otherwise hold this task, and
/// the accept loop's memory of it, forever.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct Server {
    config: ServerConfig,
    state: AppState,
}

pub struct ServerHandle {
    shutdown: watch::Sender<bool>,
    events: broadcast::Sender<ServerEvent>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Server {
    pub fn new(config: ServerConfig, dispatcher: Arc<Dispatcher>) -> Server {
        let (events, _) = broadcast::channel(64);
        // Created here, not in `start`, so it can live in `state` and reach
        // a connection handler that only ever sees an axum-extracted
        // `AppState` (a WebSocket's message loop, in particular).
        let (shutdown, _) = watch::channel(false);
        let material = tls::load_or_generate(&config.material_dir).ok();
        let state = AppState {
            dispatcher,
            events,
            tls: Arc::new(parking_lot::RwLock::new(material)),
            shutdown,
        };
        Server { config, state }
    }

    /// The certificate the shell offers to install, if there is one.
    pub fn certificate_pem(&self) -> Option<String> {
        self.state.tls.read().as_ref().map(|m| m.cert_pem.clone())
    }

    /// Every `Listening`, `BindFailed` and `Stopped` event this server ever
    /// sends, across every `start`/`stop` cycle, from the moment this call
    /// returns onward. Unlike `ServerHandle::subscribe`, this needs no
    /// handle -- the channel lives in `state`, created once in `new` -- so
    /// a caller can subscribe before the first `start` and never risk
    /// missing a listener's very first event to a race against its own
    /// bind.
    pub fn subscribe(&self) -> broadcast::Receiver<ServerEvent> {
        self.state.events.subscribe()
    }

    /// The two listeners share one router and one state. Each binds
    /// independently: one failing must not stop the other, because the
    /// common case on a machine that still has the original installed is
    /// that both ports are taken, and the shell needs to say which.
    ///
    /// `original_running` is the caller's answer to "is the original
    /// E-IMZO running right now", asked once before either listener
    /// touches a socket. It never decides whether a bind is attempted --
    /// both listeners always try, in every mode, because that answer is
    /// itself unverified and the OS's own bind is the one ground truth
    /// that fails honestly. A wrong "not running" is self-correcting: the
    /// bind simply fails and says so. A wrong "running" would not be, if
    /// it skipped the attempt instead of merely naming the failure -- the
    /// process could never start even with the ports free, and nothing
    /// would ever find out. So the answer only chooses which words a
    /// resulting `AddrInUse` failure gets (`bind_reason`): naming the
    /// original outright when the platform said it was running, or the
    /// same generic hint as always otherwise. It only ever changes
    /// anything in production: development mode already moved both ports
    /// out of the original's way, so its presence can never be the reason
    /// a development bind fails, and is folded into `original_conflict`
    /// below for that reason. If the bind succeeds anyway despite the
    /// platform having said the original was running, that is silent and
    /// unremarkable: the platform was simply wrong, and nothing was lost.
    pub fn start(&self, original_running: bool) -> ServerHandle {
        // `stop` leaves this at `true` forever -- it is only ever flipped,
        // never reset -- so a start after a stop would otherwise begin
        // with every subscriber already seeing a stopped signal: exactly
        // the gap `ws.rs`'s own guard and the `conn_shutdown.borrow()`
        // check below exist to catch, except here it is not a race, it is
        // certain. Reset it before any listener subscribes.
        //
        // Reset in place rather than replacing `state.shutdown` with a
        // fresh channel: `start` only ever gets `&self`, and this same
        // sender is shared by every clone of `AppState` a past or future
        // connection handler holds (the WebSocket loop in particular, via
        // `ws.rs`). Swapping in a new sender would need interior
        // mutability on that field, and would leave any handler still
        // holding an old `AppState` clone watching a channel this `start`
        // no longer touches -- incoherent. Resetting the existing value
        // keeps every clone, old or new, watching the same live channel.
        self.state.shutdown.send_replace(false);
        let mut tasks = Vec::new();
        let original_conflict = original_running && !self.config.dev_mode;

        // Plain listener.
        tasks.push(spawn_plain(
            self.config.ws_port,
            self.state.clone(),
            self.state.shutdown.subscribe(),
            original_conflict,
        ));

        // TLS listener, only if we have material to present.
        let material = self.state.tls.read().clone();
        match material {
            Some(material) => match tls::server_config(&material) {
                Ok(server_config) => tasks.push(spawn_tls(
                    self.config.wss_port,
                    server_config,
                    self.state.clone(),
                    self.state.shutdown.subscribe(),
                    original_conflict,
                )),
                Err(e) => {
                    let _ = self.state.events.send(ServerEvent::BindFailed {
                        port: self.config.wss_port,
                        tls: true,
                        reason: e.to_string(),
                    });
                }
            },
            None => {
                let _ = self.state.events.send(ServerEvent::BindFailed {
                    port: self.config.wss_port,
                    tls: true,
                    reason: "no TLS material".into(),
                });
            }
        }

        // The sweep that phase 2A left without a caller.
        tasks.push(spawn_sweeper(self.state.dispatcher.clone(), self.state.shutdown.subscribe()));

        ServerHandle { shutdown: self.state.shutdown.clone(), events: self.state.events.clone(), tasks }
    }
}

impl ServerHandle {
    /// Every `Listening`, `BindFailed` and `Stopped` event from this run,
    /// from the moment this call returns onward.
    pub fn subscribe(&self) -> broadcast::Receiver<ServerEvent> {
        self.events.subscribe()
    }

    /// Flips the shutdown watch, waits for every listener and the sweeper to
    /// notice and return, then reports it.
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        let _ = self.events.send(ServerEvent::Stopped);
    }
}

/// Translates a bind failure into words, and nothing else: no internal
/// detail crosses into a message a browser could show.
///
/// The wording is only ever picked apart for `AddrInUse` -- the one
/// failure a person can act on by quitting something -- and only then does
/// `original_conflict` matter: it names the original outright when the
/// platform had already said, before this bind was even attempted, that
/// the original E-IMZO is running (`ORIGINAL_RUNNING_REASON`), and falls
/// back to the same generic hint the port-conflict message has always
/// carried when it had not. `PermissionDenied` and everything else keep
/// their own plain wording regardless of what the platform said: naming
/// the original there would be a guess, and very possibly a wrong one.
fn bind_reason(e: &std::io::Error, original_conflict: bool) -> String {
    match e.kind() {
        std::io::ErrorKind::AddrInUse if original_conflict => ORIGINAL_RUNNING_REASON.into(),
        std::io::ErrorKind::AddrInUse => "the port is already in use, most likely by the original E-IMZO".into(),
        std::io::ErrorKind::PermissionDenied => "the system refused permission to use the port".into(),
        _ => "the port could not be opened".into(),
    }
}

/// The `AddrInUse` wording used once the bind has actually failed and the
/// platform had already told us, before that attempt, that the original
/// E-IMZO is the one running: a bare `AddrInUse` from the OS says only that
/// something holds the port, which a person cannot act on; naming the
/// original tells them exactly what to do about it (quit it, or use
/// development mode). No internal detail either way, matching
/// `bind_reason`'s own rule.
const ORIGINAL_RUNNING_REASON: &str = "the port is already in use by the original E-IMZO, which is currently running";

/// Waits for the shutdown watch to flip, for `axum::serve`'s graceful
/// shutdown hook.
async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    let _ = shutdown.changed().await;
}

fn spawn_plain(
    port: u16,
    state: AppState,
    shutdown: watch::Receiver<bool>,
    original_conflict: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                let reason = bind_reason(&e, original_conflict);
                tracing::warn!(port, tls = false, reason = %reason, "listener failed to bind");
                let _ = state.events.send(ServerEvent::BindFailed { port, tls: false, reason });
                return;
            }
        };
        let _ = state.events.send(ServerEvent::Listening { port, tls: false });
        let router = http::router(state);
        if let Err(e) = axum::serve(listener, router).with_graceful_shutdown(wait_for_shutdown(shutdown)).await {
            tracing::debug!(error = %e, "plain listener ended");
        }
    })
}

/// No `axum::serve` for this one: axum only drives a plain `TcpListener`, so
/// the TLS handshake is done by hand, one accepted connection at a time,
/// with `hyper-util`'s connection builder handed the same router every
/// plain-HTTP request goes through.
fn spawn_tls(
    port: u16,
    server_config: Arc<rustls::ServerConfig>,
    state: AppState,
    mut shutdown: watch::Receiver<bool>,
    original_conflict: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                let reason = bind_reason(&e, original_conflict);
                tracing::warn!(port, tls = true, reason = %reason, "listener failed to bind");
                let _ = state.events.send(ServerEvent::BindFailed { port, tls: true, reason });
                return;
            }
        };
        let _ = state.events.send(ServerEvent::Listening { port, tls: true });
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        // Taken before `state` is folded into the router below: each
        // accepted connection subscribes for its own receiver, so it can
        // watch for shutdown and end itself without this loop having to
        // track or join it.
        let shutdown_tx = state.shutdown.clone();
        let router = http::router(state);
        loop {
            let (stream, _) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::debug!(error = %e, "tls accept failed");
                        continue;
                    }
                },
                _ = shutdown.changed() => return,
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            let mut conn_shutdown = shutdown_tx.subscribe();
            // `subscribe()` freezes whatever value is already in the channel
            // as seen, so a receiver created after `stop()` already sent
            // `true` would wait on `changed()` forever and never notice
            // shutdown. A connection can be accepted in the same instant a
            // stop is requested, landing exactly in that gap. Catch it here
            // with `borrow()`, before spawning: no TLS handshake has
            // happened yet, so there is nothing to close gracefully - just
            // drop the stream. Do not remove this as redundant with the
            // `changed()` arms below: it is the only thing that catches this
            // particular timing.
            if *conn_shutdown.borrow() {
                continue;
            }
            tokio::spawn(async move {
                let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "tls handshake failed");
                        return;
                    }
                    // A client that opened the TCP connection and then sent
                    // nothing: drop it rather than hold this task forever.
                    Err(_) => {
                        tracing::debug!("tls handshake timed out");
                        return;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                let service = hyper::service::service_fn(move |request| {
                    tower::Service::call(&mut router.clone(), request)
                });
                let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                let conn = builder.serve_connection_with_upgrades(io, service);
                let mut conn = std::pin::pin!(conn);
                // A connection already past its WebSocket upgrade has
                // nothing left for `graceful_shutdown` to do here -
                // `ws::serve` is watching the same shutdown signal on its
                // own. This loop exists for everything else: a connection
                // still mid-handshake, or idling on HTTP/1.1 keep-alive,
                // which otherwise would sit here, spawned but unjoined,
                // past the point the server reports itself stopped.
                loop {
                    tokio::select! {
                        result = conn.as_mut() => {
                            if let Err(e) = result {
                                tracing::debug!(error = %e, "tls connection ended");
                            }
                            break;
                        }
                        _ = conn_shutdown.changed() => {
                            conn.as_mut().graceful_shutdown();
                        }
                    }
                }
            });
        }
    })
}

fn spawn_sweeper(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tokio::select! {
                _ = ticker.tick() => dispatcher.sweep(),
                _ = shutdown.changed() => return,
            }
        }
    })
}
