//! The event stream the shell awaits in a loop, so it learns what changed
//! without polling: server listener state, TLS trust, the key list, an
//! activity entry, and every formatted log line, in the order they happen.
//! `Engine::events` mints one `EventStream` per subscriber from a single
//! broadcast channel kept on `Engine`, so more than one caller can listen
//! at once and each sees every event from the moment it subscribed onward.
//!
//! `ServerStateChanged`, `TlsTrustChanged` and `KeysChanged` carry no
//! detail: each is a nudge to call the matching query again (`status`, and
//! -- once a later task adds them -- the TLS and key calls) for the fresh
//! value, matching the spec's own wording for these events. `Log` is the
//! exception: it exists to carry detail, formatted by `tracing` the same
//! way a log file would, which is why this module also installs the
//! process's one `tracing` subscriber -- but only the levels a person
//! reading a user interface should see. `debug!`/`trace!` call sites across
//! this workspace routinely carry a filesystem path or a raw library error
//! string, which belongs in a local log, not in a stream the application
//! displays; see the level filter in `install_log_forwarding` for where
//! that boundary is actually drawn.
//!
//! That boundary is also why a real log *file* exists at all: the spec's
//! deviations table sells "a code and a reason to the site, details in the
//! local log" as the trade-off for never forwarding internal error detail
//! or stack traces to a web page. The debug- and trace-level lines this
//! module's event layer deliberately drops are exactly those details, so
//! `install_log_forwarding` installs a second `tracing` layer alongside
//! the event one -- not instead of it -- writing everything `DEBUG` and
//! above to a daily-rotated file under `EngineConfig.logs_dir`. Two layers,
//! one subscriber: `tracing` only ever allows installing one subscriber
//! per process (the same constraint the event layer's own doc comment
//! already works around), so both destinations are layers on that one
//! subscriber rather than two competing `try_init` calls.
//!
//! The redaction rule is unchanged by this: nothing in this workspace logs
//! a password, PIN, or key material today (see `Event::Log`'s own doc), and
//! the file layer only ever writes what some call site already handed to
//! `tracing` -- it has no access to anything the event layer's `INFO`
//! filter does not also see go by. Widening this file layer's own level
//! filter is therefore safe by the same argument that keeps the event
//! layer at `INFO`; it must never become a place code starts logging a
//! secret on the assumption that a local file is a safe place for one.

use crate::types::ActivityEntry;
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::broadcast;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::Rotation;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// How many events a slow or absent shell can fall behind before the
/// oldest are dropped and `EventStream::next` silently skips ahead, rather
/// than this channel ever blocking whoever sends into it or growing
/// without bound. `Engine::new` sizes the one channel it hands to both
/// `EventStream` and the log-forwarding writer from this constant.
pub(crate) const EVENT_CAPACITY: usize = 256;

#[derive(Clone, Debug, uniffi::Enum)]
pub enum Event {
    /// A listener bound, failed to bind, or the server stopped. Carries no
    /// detail; call `Engine::status` again for what actually changed.
    ServerStateChanged,
    /// A trust installation attempt finished. Call `Engine::status` again
    /// for the fresh self-probe result.
    TlsTrustChanged,
    /// The key list may be different now. Call `Engine::list_keys` again.
    KeysChanged,
    Activity(ActivityEntry),
    /// One already-formatted line from the `tracing` layer this module
    /// installs, restricted to `INFO` and above -- see the level filter in
    /// `install_log_forwarding`. Never a password, PIN, or key: nothing in
    /// this workspace logs one, and this layer only formats what was
    /// already logged.
    Log(String),
}

/// A UniFFI object over one subscription to `Engine`'s broadcast channel.
#[derive(uniffi::Object)]
pub struct EventStream {
    // `tokio::sync::Mutex`, not `parking_lot`: `next` holds this across the
    // `.await` on `recv`, which a non-async-aware lock cannot do without
    // tripping `clippy::await_holding_lock` and, worse, actually blocking a
    // runtime worker thread while the guard sits idle.
    receiver: tokio::sync::Mutex<broadcast::Receiver<Event>>,
}

impl EventStream {
    pub(crate) fn new(receiver: broadcast::Receiver<Event>) -> Self {
        EventStream { receiver: tokio::sync::Mutex::new(receiver) }
    }
}

#[uniffi::export]
impl EventStream {
    /// Waits for the next event. A receiver that falls behind
    /// (`RecvError::Lagged`) just resumes waiting for the next one rather
    /// than surfacing an error: a dropped log line, or a redundant
    /// "changed" nudge the caller would have re-queried anyway, is not
    /// worth failing a UI over. Returns `None` once the channel itself is
    /// gone -- every `Event` sender dropped, including this module's own
    /// log-forwarding clone, which `Engine`'s teardown clears via
    /// `clear_log_forwarding` for exactly this reason -- so a stream held
    /// across a full engine teardown ends instead of waiting on `recv`
    /// forever.
    pub async fn next(&self) -> Option<Event> {
        let mut receiver = self.receiver.lock().await;
        loop {
            match receiver.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// Where the log-forwarding writer sends what it formats. A `RwLock` behind
/// a `OnceLock`, not a plain field on some long-lived value, because
/// `tracing_subscriber` instantiates a fresh `BroadcastWriter` for every
/// single formatted line (see below) and gives it no other way to reach
/// whichever `Engine` is current. An `Engine` built after an earlier one
/// repoints this rather than installing a second global subscriber, which
/// `tracing` does not allow. `clear_log_forwarding` below is the other side
/// of that: it takes this back to `None` once the `Engine` that pointed it
/// here is gone.
static LOG_TARGET: OnceLock<parking_lot::RwLock<Option<broadcast::Sender<Event>>>> = OnceLock::new();

fn log_target() -> &'static parking_lot::RwLock<Option<broadcast::Sender<Event>>> {
    LOG_TARGET.get_or_init(|| parking_lot::RwLock::new(None))
}

/// The most daily log files `install_log_forwarding`'s file layer keeps
/// before deleting the oldest. Small on purpose -- finding 5's whole
/// complaint is a log that can grow without bound on a machine that runs
/// for months -- but generous enough that a problem reported a week or two
/// after it happened still has a file to read.
const LOG_FILE_RETENTION: usize = 14;

/// Kept alive for the life of the process once `build_file_layer` creates
/// it: `tracing_appender::non_blocking` hands back a background writer
/// thread alongside this guard, and dropping the guard is what stops that
/// thread and flushes whatever it was still holding. A `OnceLock`, not a
/// field on `Engine`, for the same reason `LOG_TARGET` is one -- the file
/// layer this backs is part of the process's one `tracing` subscriber,
/// built at most once no matter how many `Engine`s come and go, so nothing
/// shorter-lived than the process itself is the right place to hold it.
static FILE_LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// The non-blocking writer `install_log_forwarding`'s file layer formats
/// into: daily rotation, pruned to `LOG_FILE_RETENTION` files, created
/// under `logs_dir` (and `logs_dir` itself, if it does not exist yet) on
/// first use. `None` if the directory could not be created and no file
/// could be opened either -- disk full, permissions, `logs_dir` not
/// actually writable -- in which case the file layer is simply never
/// added and the event layer above keeps working on its own. `INIT` in
/// `install_log_forwarding` only ever calls this once, so that failure is
/// for this process's whole life, matching how the rest of this function
/// already treats log forwarding as best-effort rather than something
/// worth failing `Engine::new` over.
fn build_file_layer(logs_dir: &Path) -> Option<tracing_appender::non_blocking::NonBlocking> {
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix("eimzo")
        .filename_suffix("log")
        .max_log_files(LOG_FILE_RETENTION)
        .build(logs_dir)
        .ok()?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let _ = FILE_LOG_GUARD.set(guard);
    Some(writer)
}

/// Points the process's one `tracing` subscriber at `sender`, installing
/// that subscriber the first time this runs. Safe to call more than once,
/// including from more than one `Engine::new`: later calls just repoint
/// the broadcast target, guarded by `OnceLock`'s own synchronization,
/// while a `std::sync::Once` makes sure the subscriber itself -- both
/// layers -- is built exactly once, from whichever `Engine::new` runs
/// first; a later `Engine::new` with a different `logs_dir` does not move
/// the file layer, the same way it does not change the event layer's own
/// `INFO` cutoff. Never panics: `try_init` failing -- some other code
/// already installed a subscriber -- is accepted silently rather than
/// propagated, since forwarding logs to the shell is a convenience, not
/// something worth failing engine construction over; the file layer built
/// alongside it here is not a convenience (see this module's top-level doc
/// comment), but the same handling still applies once a subscriber is
/// already installed, since there is no way to add a second one regardless.
pub(crate) fn install_log_forwarding(sender: broadcast::Sender<Event>, logs_dir: &Path) {
    *log_target().write() = Some(sender);
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // `with_max_level(Level::INFO)` is load-bearing, not cosmetic: it is
        // the one thing standing between every `debug!`/`trace!` call site
        // in this workspace and the stream the application displays.
        // `eimzo_keys::discovery`'s "skipping unreadable key file", for
        // one, logs the full path of a key file it could not read -- and a
        // person's key files live under their home directory. `debug!` and
        // `trace!` are for a local log, not a user interface; only
        // `info!`/`warn!`/`error!` are written with a person reading them
        // in mind. Raise this to `DEBUG` (or drop it) and that path -- and
        // every other one like it -- starts reaching the application
        // verbatim.
        let broadcast_layer = tracing_subscriber::fmt::layer()
            .with_writer(BroadcastMakeWriter.with_max_level(Level::INFO))
            .with_ansi(false);
        // `DEBUG` and above: exactly the lines the layer above just refused
        // to forward, captured here instead of simply lost -- that is the
        // whole point of this layer existing (this module's top-level doc
        // comment). It writes only what some call site already handed to
        // `tracing`, the same source the layer above reads from; nothing
        // in this workspace logs a password, PIN, or key today, and this
        // layer changes nothing about what is safe to log, only how much
        // of it a person can go back and read.
        let file_layer = build_file_layer(logs_dir).map(|writer| {
            tracing_subscriber::fmt::layer().with_writer(writer.with_max_level(Level::DEBUG)).with_ansi(false)
        });
        let subscriber = tracing_subscriber::registry().with(broadcast_layer).with(file_layer);
        let _ = subscriber.try_init();
    });
}

/// Drops this module's clone of the log-forwarding sender, but only if
/// `LOG_TARGET` still points at `sender` specifically. Called once from
/// `Engine`'s own teardown, with that engine's own event sender, so that
/// this module's global stops keeping the broadcast channel's sender count
/// above zero once every other clone -- the `Engine` itself, its
/// `forward_server_events` task -- is gone too. Without this, a `Receiver`
/// an `EventStream` still holds would wait on `recv` forever instead of
/// ever seeing `RecvError::Closed`: nothing would be left to send through
/// the channel, but nothing would have dropped it either.
///
/// The `same_channel` check (rather than clearing unconditionally) matters
/// when a later `Engine::new` has already repointed `LOG_TARGET` at a
/// fresher sender before this older `Engine` finishes dropping -- this must
/// leave that fresher target alone, or a still-live `Engine`'s logs would
/// suddenly stop reaching its streams.
pub(crate) fn clear_log_forwarding(sender: &broadcast::Sender<Event>) {
    let mut target = log_target().write();
    if target.as_ref().is_some_and(|current| current.same_channel(sender)) {
        *target = None;
    }
}

/// Builds one `BroadcastWriter` per formatted line, per `tracing_subscriber`'s
/// own contract for `MakeWriter`. Never handed a `DEBUG` or `TRACE` line to
/// format in the first place: `install_log_forwarding` only ever uses this
/// wrapped in `MakeWriterExt::with_max_level(Level::INFO)`, which is where
/// the level filter actually lives and why widening it belongs there, not
/// here.
struct BroadcastMakeWriter;

impl<'a> MakeWriter<'a> for BroadcastMakeWriter {
    type Writer = BroadcastWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BroadcastWriter { sender: log_target().read().clone(), buf: Vec::new() }
    }
}

/// Turns every completed request into `Event::Activity`. Installed on the
/// dispatcher by `Engine::new` via `Dispatcher::set_observer`; never blocks
/// the call it is notified about, the same as every other producer in this
/// module — sending into a broadcast channel with no receivers returns an
/// error, which is ignored here exactly like `BroadcastWriter::drop` above
/// ignores it for `Event::Log`.
pub(crate) struct ActivityObserver {
    sender: broadcast::Sender<Event>,
}

impl ActivityObserver {
    pub(crate) fn new(sender: broadcast::Sender<Event>) -> Self {
        ActivityObserver { sender }
    }
}

impl eimzo_rpc::dispatch::CallObserver for ActivityObserver {
    fn observe(&self, origin: &str, plugin: &str, name: &str, outcome: &str) {
        // The dispatcher passes `plugin` through empty for the main
        // plugin's own functions rather than substituting a word for it;
        // this is the one place that decides how to display that, joining
        // it with `name` the same way a request names a function on the
        // wire (`{"plugin":"pfx","name":"load_key",...}`) when there is a
        // plugin to join at all.
        let function = if plugin.is_empty() { name.to_string() } else { format!("{plugin}.{name}") };
        let entry = ActivityEntry { at: chrono::Utc::now().to_rfc3339(), origin: origin.to_string(), function, outcome: outcome.to_string() };
        let _ = self.sender.send(Event::Activity(entry));
    }
}

/// Buffers one formatted line. `tracing_subscriber` writes a single event's
/// output across one or more `write` calls on one instance of this, always
/// ending with a trailing newline, then drops it -- which is where the
/// whole line is sent on, complete.
struct BroadcastWriter {
    sender: Option<broadcast::Sender<Event>>,
    buf: Vec<u8>,
}

impl std::io::Write for BroadcastWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for BroadcastWriter {
    fn drop(&mut self) {
        let Some(sender) = &self.sender else { return };
        let line = String::from_utf8_lossy(&self.buf);
        let line = line.trim_end_matches(['\n', '\r']);
        if !line.is_empty() {
            // No subscriber yet, or one too far behind to keep up: dropping
            // the line is the intended behavior here, not an error.
            let _ = sender.send(Event::Log(line.to_string()));
        }
    }
}
