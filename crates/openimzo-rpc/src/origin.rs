//! The site a request came from, as seen at the WebSocket handshake, and the
//! gate that decides whether it may call anything beyond the main plugin,
//! mirroring the original's own origin check.
//!
//! The `Origin` header is read once, at the upgrade, and turned into a
//! domain string used for the api-key cache; the user's own permission
//! answers are kept by the full header text, since a dialog answered for
//! one scheme or port must not silently cover another.

use crate::ui::{PermissionAnswer, PermissionRequest, UiBroker};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `header` is the raw `Origin` header text the site sent (possibly empty).
/// `domain` is what the original compares against its allow list: the
/// literal string `null` for a missing header, a `file://` header,
/// or a header that doesn't yield a host — otherwise the header's host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub header: String,
    pub domain: String,
}

const NULL_DOMAIN: &str = "null";

/// The whole vendor exchange, connect through body, is bounded by this.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a failed vendor lookup is remembered before it is retried.
const LOOKUP_RETRY_AFTER: Duration = Duration::from_secs(10 * 60);

/// Above this many entries, `gate_for` tries to reclaim turnstiles nobody is
/// waiting on before adding one more for a domain it hasn't seen yet.
const MAX_GATES: usize = 1024;

impl Origin {
    pub fn from_header(header: &str) -> Origin {
        let domain = if header.is_empty() || header.starts_with("file://") {
            NULL_DOMAIN.to_string()
        } else {
            host_of(header).unwrap_or_else(|| NULL_DOMAIN.to_string())
        };
        Origin { header: header.to_string(), domain }
    }
}

/// The host of an absolute URL, or `None` if `text` has no scheme separator,
/// no authority, or an authority with no host part. Good enough for the
/// `scheme://[user@]host[:port][/...]` shape an `Origin` header actually has;
/// this is not a general URL parser.
fn host_of(text: &str) -> Option<String> {
    let (_scheme, rest) = text.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }
    let authority = authority.rsplit_once('@').map(|(_, host)| host).unwrap_or(authority);
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        // IPv6 literal: "[::1]" or "[::1]:port".
        bracketed.split_once(']').map(|(host, _)| host)?
    } else {
        authority.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// What `ApikeyService::decide` found for one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginDecision {
    /// The site may proceed.
    Allow,
    /// The site may not; reply `-1022` (`RpcError::OriginNotAllowed`).
    Deny,
    /// The header was missing, `file://`, or unparseable — there is no domain
    /// to gate on at all; reply `-1021` (`RpcError::FailedToIdentifyDomain`).
    NoHeader,
}

/// Settings for the unregistered-domain lookup.
#[derive(Clone, Debug)]
pub struct ApikeyConfig {
    /// Base URL the lookup is issued against; the request is
    /// `<lookup_url>/<domain>`. A field rather than a literal so tests need
    /// not reach the real vendor server.
    pub lookup_url: String,
}

impl Default for ApikeyConfig {
    fn default() -> Self {
        ApikeyConfig { lookup_url: "https://e-imzo.uz/apikey/get".to_string() }
    }
}

/// Where verified keys and "allow always" decisions outlive the process. The
/// CLI's implementation (task 7) is in-memory; the shell's own (phase 2B
/// task 10) persists to `sites.json` under the app support directory.
pub trait ApikeyStore: Send + Sync {
    /// Every verified `(domain, key)` pair known before this run.
    fn load(&self) -> Vec<(String, String)>;
    /// A newly verified pair, to keep past this run.
    fn save_key(&self, domain: &str, key: &str);
    /// The full origin (scheme, host and port) the user answered "Allow
    /// always" for.
    fn save_allowed(&self, origin: &str);
    /// Every origin previously passed to `save_allowed`.
    fn allowed(&self) -> Vec<String>;
    /// Removes `domain`'s verified key, if any, and every persisted "allow
    /// always" decision in `origins` — the full `Origin` header text of
    /// each one `ApikeyService::forget_site` found sharing that domain. A
    /// store with nothing to persist (the CLI's in-memory one) can leave
    /// this a no-op.
    fn forget(&self, domain: &str, origins: &[String]);
}

/// The api-key cache, the unregistered-domain lookup, and the per-origin
/// permission decisions that back `Dispatcher::call`'s gate.
pub struct ApikeyService {
    config: ApikeyConfig,
    store: Box<dyn ApikeyStore>,
    client: reqwest::Client,
    /// Domains with a key verified either by an explicit `apikey` call or by
    /// the vendor lookup. Mirrors the original's own map of verified origins.
    verified: RwLock<HashMap<String, String>>,
    /// Answers to the permission dialog, keyed by the full `Origin` header
    /// text rather than the bare domain — an answer for `https://site.uz`
    /// must not also cover `http://site.uz` or a different port on the same
    /// host. For this process only (persistence for "Allow always" lives in
    /// `store`, not here).
    decisions: RwLock<HashMap<String, PermissionAnswer>>,
    /// One decision at a time per domain. Without it, two calls that arrive
    /// together both find nothing on record and both ask the user.
    gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// When a failed lookup for a domain stops being remembered. A failure is
    /// not a decision the user made, so it must not refuse the domain for the
    /// life of the process; but repeating the request on every call turns one
    /// local connection into unbounded outbound traffic.
    lookup_failed: RwLock<HashMap<String, Instant>>,
}

impl ApikeyService {
    pub fn new(config: ApikeyConfig, store: Box<dyn ApikeyStore>) -> Self {
        let client = match reqwest::Client::builder().timeout(Duration::from_secs(15)).build() {
            Ok(client) => client,
            Err(e) => {
                tracing::debug!(error = %e, "apikey http client: falling back to an unconfigured client");
                // No timeout here; LOOKUP_TIMEOUT at the call site is what
                // actually guarantees the deadline regardless.
                reqwest::Client::new()
            }
        };
        let verified = store
            .load()
            .into_iter()
            .filter(|(domain, key)| {
                let ok = openimzo_crypto::apikey::verify_domain(domain, key);
                if !ok {
                    tracing::debug!(domain = %domain, "stored api key no longer verifies; dropping it");
                }
                ok
            })
            .collect::<HashMap<String, String>>();
        let decisions = store
            .allowed()
            .into_iter()
            .map(|origin| (origin, PermissionAnswer::AllowAlways))
            .collect::<HashMap<String, PermissionAnswer>>();
        ApikeyService {
            config,
            store,
            client,
            verified: RwLock::new(verified),
            decisions: RwLock::new(decisions),
            gates: Mutex::new(HashMap::new()),
            lookup_failed: RwLock::new(HashMap::new()),
        }
    }

    /// Whether `domain` already has a verified key cached.
    pub fn is_registered(&self, domain: &str) -> bool {
        self.verified.read().contains_key(domain)
    }

    /// Verifies `key` for `domain` and, if it verifies, caches and persists
    /// it. Returns whether it verified. This is the one place the crypto
    /// check (`openimzo_crypto::apikey::verify_domain`) runs, so callers such as
    /// the main plugin's `apikey` function never repeat it.
    pub fn register(&self, domain: &str, key: &str) -> bool {
        if !openimzo_crypto::apikey::verify_domain(domain, key) {
            return false;
        }
        self.verified.write().insert(domain.to_string(), key.to_string());
        self.store.save_key(domain, key);
        true
    }

    /// Fetches and verifies `domain`'s key from the vendor server. Any
    /// transport failure, or a body that is empty or does not verify, is
    /// "not authorised"; only the debug log records why.
    pub async fn lookup(&self, domain: &str) -> bool {
        let url = format!("{}/{}", self.config.lookup_url, domain);
        let fetch = async {
            let response = self.client.get(&url).send().await?;
            response.text().await
        };
        let body = match tokio::time::timeout(LOOKUP_TIMEOUT, fetch).await {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => {
                tracing::debug!(domain = %domain, error = %e, "apikey lookup: request failed");
                return false;
            }
            Err(_) => {
                tracing::debug!(domain = %domain, "apikey lookup: timed out");
                return false;
            }
        };
        let key = body.trim();
        if key.is_empty() {
            tracing::debug!(domain = %domain, "apikey lookup: empty response body");
            return false;
        }
        self.register(domain, key)
    }

    /// Records the user's answer to the permission dialog for `origin_key`,
    /// the full `Origin` header text — not the bare domain, so an answer
    /// given for one scheme or port never silently covers another. `persist`
    /// mirrors an "Allow always" into the store so it survives a restart;
    /// "Allow once" (`persist = false`) never does.
    pub fn allow(&self, origin_key: &str, persist: bool) {
        let answer = if persist { PermissionAnswer::AllowAlways } else { PermissionAnswer::AllowOnce };
        self.decisions.write().insert(origin_key.to_string(), answer);
        if persist {
            self.store.save_allowed(origin_key);
        }
    }

    fn deny(&self, origin_key: &str) {
        self.decisions.write().insert(origin_key.to_string(), PermissionAnswer::Deny);
    }

    /// The decision already on record for `origin_key` (the full `Origin`
    /// header text), if any.
    fn recorded(&self, origin_key: &str) -> Option<OriginDecision> {
        self.decisions.read().get(origin_key).copied().map(|answer| match answer {
            PermissionAnswer::AllowOnce | PermissionAnswer::AllowAlways => OriginDecision::Allow,
            PermissionAnswer::Deny => OriginDecision::Deny,
        })
    }

    /// Whether a vendor lookup for `domain` failed recently enough that it
    /// should not be repeated yet. Prunes every cooldown entry whose window
    /// has already elapsed first, so the map cannot grow without bound.
    fn lookup_recently_failed(&self, domain: &str) -> bool {
        let now = Instant::now();
        let mut failed = self.lookup_failed.write();
        failed.retain(|_, at| now.duration_since(*at) < LOOKUP_RETRY_AFTER);
        failed.contains_key(domain)
    }

    /// Records that a vendor lookup for `domain` just failed, so `decide`
    /// skips repeating it until `LOOKUP_RETRY_AFTER` has passed. Prunes
    /// expired entries first, for the same reason as `lookup_recently_failed`.
    fn record_lookup_failure(&self, domain: &str) {
        let now = Instant::now();
        let mut failed = self.lookup_failed.write();
        failed.retain(|_, at| now.duration_since(*at) < LOOKUP_RETRY_AFTER);
        failed.insert(domain.to_string(), now);
    }

    /// The per-domain turnstile. One entry per distinct domain ever seen,
    /// which is bounded by how many sites the user actually visits — but
    /// bounded loosely, since nothing ever removes an entry on its own. Once
    /// the map holds more than `MAX_GATES` and a domain not already in it
    /// needs one, first drop every turnstile nobody is currently waiting on
    /// (its `Arc` has no clone outstanding besides the map's own). If that
    /// frees nothing — every one of them is in use — proceed anyway rather
    /// than fail the request.
    fn gate_for(&self, domain: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.gates.lock();
        if gates.len() > MAX_GATES && !gates.contains_key(domain) {
            gates.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        Arc::clone(gates.entry(domain.to_string()).or_default())
    }

    /// The gate: may `origin` call a non-main-plugin function right now?
    ///
    /// A `null` domain (no header, `file://`, or an unparseable header) can
    /// never be identified to the user or cached, so it is refused outright
    /// as `NoHeader` rather than going through the steps below.
    ///
    /// Otherwise, in order: a domain with a verified key already cached is
    /// allowed with no I/O at all. Failing that, a decision already on
    /// record for this process, for this exact origin — from a previous
    /// dialog, allow or deny — is reused, so a site the user has already
    /// answered never triggers a fresh network lookup or a second prompt.
    /// Only when nothing is recorded does the vendor lookup run, behind a
    /// per-domain gate so two calls that arrive together for the same
    /// undecided origin still produce one lookup and, if it comes to that,
    /// one dialog rather than two. A lookup that fails is remembered for
    /// `LOOKUP_RETRY_AFTER`, so it is not retried until that window passes —
    /// but it is retried then, because a site that registers a valid key
    /// later must not stay refused for the rest of the process. Either way,
    /// a refusal reached with nothing recorded (developer mode off, or the
    /// lookup came back empty) is never itself recorded as a decision: it is
    /// not a choice the user made. With nothing on record and developer mode
    /// on, the dialog is shown. Only an explicit `Deny` answer is a decision
    /// the person made and worth remembering; every other outcome — the
    /// dialog cancelled, timed out, no UI available, or the broker refusing
    /// outright because it is busy — refuses this one call without
    /// recording anything, so the next call asks again.
    pub async fn decide(&self, origin: &Origin, ui: &UiBroker, developer_mode: bool) -> OriginDecision {
        if origin.domain == NULL_DOMAIN {
            return OriginDecision::NoHeader;
        }
        let domain = origin.domain.as_str();
        let origin_key = origin.header.as_str();
        // A verified key is authoritative and costs nothing to check.
        if self.is_registered(domain) {
            return OriginDecision::Allow;
        }
        if let Some(decision) = self.recorded(origin_key) {
            return decision;
        }
        let gate = self.gate_for(domain);
        let _turn = gate.lock().await;
        // Another call for this same site may have settled it while we waited.
        if self.is_registered(domain) {
            return OriginDecision::Allow;
        }
        if let Some(decision) = self.recorded(origin_key) {
            return decision;
        }
        let looked_up = if self.lookup_recently_failed(domain) {
            false
        } else {
            let verified = self.lookup(domain).await;
            if !verified {
                self.record_lookup_failure(domain);
            }
            verified
        };
        if looked_up {
            return OriginDecision::Allow;
        }
        if !developer_mode {
            // Nothing is recorded here: this is not a decision the user made,
            // and a site that registers a key later must not stay refused.
            return OriginDecision::Deny;
        }
        match ui.ask_permission(PermissionRequest { origin: origin.header.clone() }).await {
            Ok(PermissionAnswer::AllowAlways) => {
                self.allow(origin_key, true);
                OriginDecision::Allow
            }
            Ok(PermissionAnswer::AllowOnce) => {
                self.allow(origin_key, false);
                OriginDecision::Allow
            }
            // The person was actually asked and actually said no: a real
            // decision, so it is the one outcome worth remembering.
            Ok(PermissionAnswer::Deny) => {
                self.deny(origin_key);
                OriginDecision::Deny
            }
            // Cancelled, timed out, no UI available, or the broker never
            // even reached the person because it was busy: none of these is
            // a decision, so nothing is cached and the next call tries
            // again. `Busy` is why this matters most: the broker can return
            // it without the person ever seeing this site's dialog at all —
            // the queue was already full, or the turn never came free in
            // time — commonly because a *different* site was holding it.
            // Recording that as this site's answer would let one site's
            // traffic quietly and permanently deny another. Same reasoning
            // `plugins::randseed`'s `consent` applies to its own dialog.
            Err(_) => OriginDecision::Deny,
        }
    }

    /// Snapshot of every site the shell shows: `verified` (keyed by bare
    /// domain) and `decisions` (keyed by the full `Origin` header text)
    /// merged into one list by domain, since this is the one place that
    /// already has `host_of` on hand to line the two up — `Engine::sites`
    /// in `openimzo-ffi` only needs to convert each row into its own `Site`
    /// record, never reach into either map itself. Only `AllowAlways`
    /// decisions surface here: an `AllowOnce` or `Deny` answer is this
    /// process's own business (`decide` above already treats them
    /// differently) and was never persisted, so it is not a "site" worth
    /// showing or revoking.
    pub fn sites(&self) -> Vec<SiteRecord> {
        let verified = self.verified.read();
        let decisions = self.decisions.read();
        let mut rows: HashMap<String, SiteRecord> = HashMap::new();
        for domain in verified.keys() {
            rows.entry(domain.clone()).or_insert_with(|| SiteRecord {
                origin: domain.clone(),
                registered: true,
                allowed_always: false,
            });
        }
        for (origin_key, answer) in decisions.iter() {
            if *answer != PermissionAnswer::AllowAlways {
                continue;
            }
            let domain = host_of(origin_key).unwrap_or_else(|| origin_key.clone());
            let registered = verified.contains_key(&domain);
            let row = rows.entry(domain).or_insert_with(|| SiteRecord {
                origin: origin_key.clone(),
                registered,
                allowed_always: false,
            });
            // The full origin header text is the more specific identity —
            // preferred over the bare domain `verified`-only rows start
            // with — since it is what a repeat `forget_site` call for this
            // exact row would be given back.
            row.origin = origin_key.clone();
            row.allowed_always = true;
        }
        let mut out: Vec<SiteRecord> = rows.into_values().collect();
        out.sort_by(|a, b| a.origin.cmp(&b.origin));
        out
    }

    /// Forgets `domain` — a bare domain or a full `Origin` header text,
    /// whichever a `SiteRecord.origin` happened to hold — from both the
    /// api-key cache and every permission decision recorded for it (not
    /// only the persisted `AllowAlways` ones `sites()` shows: an in-memory
    /// `Deny` for the same domain is cleared too, so the person is asked
    /// fresh rather than finding a refusal they never actually revoked).
    /// Removed from the store as well, so it does not come back on the
    /// next start.
    pub fn forget_site(&self, domain: &str) {
        let bare_domain = host_of(domain).unwrap_or_else(|| domain.to_string());
        self.verified.write().remove(&bare_domain);
        let mut removed_origins = Vec::new();
        self.decisions.write().retain(|origin_key, _| {
            let matches = origin_key == domain || host_of(origin_key).as_deref() == Some(bare_domain.as_str());
            if matches {
                removed_origins.push(origin_key.clone());
            }
            !matches
        });
        self.store.forget(&bare_domain, &removed_origins);
    }
}

/// One row of what the shell shows as a "site". See `ApikeyService::sites`
/// for how the two sources behind it are merged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteRecord {
    /// The full `Origin` header text when a permission decision backs this
    /// row; the bare domain itself when only the api-key cache does.
    pub origin: String,
    /// A verified API key is cached for this domain.
    pub registered: bool,
    /// The person answered "allow always" for this origin.
    pub allowed_always: bool,
}
