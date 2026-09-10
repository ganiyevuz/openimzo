//! Routing a request to a function, and the `apidoc` document sites read.

use crate::error::{Result, RpcError};
use crate::i18n::{Lang, Messages};
use crate::model::{Request, Response};
use crate::origin::{ApikeyService, Origin, OriginDecision};
use crate::plugins::pki::Enrollment;
use crate::plugins::randseed::RandseedProvider;
use crate::ui::UiBroker;
use eimzo_keys::{Discovery, Sessions};
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type Handler = Arc<
    dyn for<'a> Fn(&'a Ctx, &'a Origin, &'a Request) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + 'a>>
        + Send
        + Sync,
>;

/// The largest message the original accepts: 64 MiB, applied alike to the
/// WebSocket protocol handler, the frame aggregator and the HTTP
/// aggregator. Phase 2B applies this at the socket, where the original
/// applies it.
pub const MAX_MESSAGE_BYTES: usize = 67_108_864;

/// The largest single argument. The original's frame decoder caps one JSON
/// string at half the message limit through Jackson's read constraints, so
/// a handler there never sees a larger one. We enforce it in the dispatcher instead of at the parser, so
/// it holds for every caller, including ones with no socket in front of them.
pub const MAX_ARGUMENT_BYTES: usize = MAX_MESSAGE_BYTES / 2;

/// Above this many entries, `Dispatcher::sweep` clears `Ctx::lang_overrides`
/// and `Ctx::randseed_consent` outright. Neither map has an expiry to prune
/// by (unlike `plugins::pki`'s enrolments) or an "in use" refcount to
/// selectively keep (unlike a turnstile map such as `origin.rs`'s own
/// `gates`), so there is nothing to retain once the cap is reached; a flat
/// cap-then-clear is what `origin.rs`'s own bounding shape reduces to
/// without either of those. Losing an entry costs a site one repeated
/// `app.change_ui_lang` call or one repeated `randseed.get` consent dialog
/// -- never a security property, since both maps back a mere preference,
/// not a permission decision. 1024 matches the cap this crate already uses
/// for its per-origin turnstiles (`Ctx::randseed_gates`, `origin.rs`'s own
/// `gates`): far more distinct sites than a real person's own browsing
/// ever touches, and cheap for a flood to reach, since `lang_overrides`'
/// key is the raw `Origin` header text a local caller fully controls.
const MAX_ORIGIN_STATE: usize = 1024;

#[derive(Clone)]
pub struct ArgSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub optional: bool,
    /// This argument soaks up every remaining value, so the dispatcher does not
    /// check the count at all and the handler validates it instead. The original
    /// does the same for its one variadic function.
    pub variadic: bool,
}

#[derive(Clone)]
pub struct FunctionSpec {
    pub plugin: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub args: Vec<ArgSpec>,
    pub handler: Handler,
}

/// Notified once per completed request, from `Dispatcher::call`, after the
/// response is built and before it is returned. A plain synchronous
/// callback rather than an `async_trait` method: the dispatcher must not
/// gain an async dependency on whatever installs one, and the one real
/// installer (`eimzo-ffi`) only ever sends into a broadcast channel, which
/// never blocks.
pub trait CallObserver: Send + Sync {
    /// `outcome` is already formatted for display: `"ok"` when the response
    /// succeeded, otherwise its status code and reason, e.g. `-5000 Ввод
    /// пароля отменен`.
    fn observe(&self, origin: &str, plugin: &str, name: &str, outcome: &str);
}

impl FunctionSpec {
    fn required_args(&self) -> usize {
        self.args.iter().filter(|a| !a.optional).count()
    }

    /// A variadic argument (only `main.apikey`, whose real argument count is
    /// any even number `>= 2`) means the count check is left to the handler,
    /// which reports the same `function.is.not.found` error itself. Every
    /// other function accepts exactly its declared range.
    fn accepts(&self, count: usize) -> bool {
        if self.args.iter().any(|a| a.variadic) {
            return true;
        }
        count >= self.required_args() && count <= self.args.len()
    }
}

#[derive(Clone)]
pub struct DispatcherConfig {
    pub lang: Lang,
    /// Version reported to sites. Must stay 6.4.7 while we claim compatibility.
    pub version: (&'static str, &'static str, &'static str),
    pub edition: &'static str,
    /// Supplies the machine's hostname and network interfaces to
    /// `randseed.get`. `eimzo-rpc` may not read the environment itself, so
    /// the app and the CLI each hand in their own; `None` means the
    /// function always answers `-1029`, the same as an unsupported source.
    pub randseed_provider: Option<Arc<dyn RandseedProvider>>,
}

/// Hand-written because `Arc<dyn RandseedProvider>` has no `Debug` of its own.
impl core::fmt::Debug for DispatcherConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DispatcherConfig")
            .field("lang", &self.lang)
            .field("version", &self.version)
            .field("edition", &self.edition)
            .field("randseed_provider", &self.randseed_provider.is_some())
            .finish()
    }
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        DispatcherConfig { lang: Lang::Ru, version: ("6", "4", "7"), edition: "Standard", randseed_provider: None }
    }
}

/// Everything a function may reach. Handlers get `&Ctx`; nothing else is global.
pub struct Ctx {
    pub config: DispatcherConfig,
    pub messages: Messages,
    pub lang: RwLock<Lang>,
    pub sessions: Arc<Sessions>,
    pub discovery: Arc<Discovery>,
    pub ui: Arc<UiBroker>,
    pub apikeys: Arc<ApikeyService>,
    pub developer_mode: RwLock<bool>,
    /// Settings' own "remember passwords" toggle. `false` makes
    /// `plugins::keystore::open_with_password` behave as `force` already
    /// does for caching purposes — never offers the checkbox, never caches
    /// a password that opens a file — without touching whether a *forced*
    /// prompt (`verify_password`'s "always prompts, never caches") ever
    /// could; the two are independent reasons to skip caching, not one
    /// subsuming the other.
    pub remember_passwords: RwLock<bool>,
    /// Settings' own "ask before seeding the random generator" toggle.
    /// `true` (the default) is this project's deliberate choice of asking
    /// once per site (`plugins::randseed::consent`); `false` answers
    /// without prompting, for someone who has chosen not to be asked.
    pub ask_before_randseed: RwLock<bool>,
    /// In-flight certificate enrolments, keyed by the site's domain AND the
    /// process identifier the site chose. The domain is part of the key
    /// because the identifier is not ours: without it, any site could finish
    /// an enrolment another site started, under certificates of its own.
    pub enrollments: Mutex<HashMap<(String, String), Enrollment>>,
    /// One `enroll_pfx_step1` at a time per (site, guid): see
    /// `plugins::pki::enroll_pfx_step1`. Reclaimed by `sweep_enrollments`,
    /// the same way `origin.rs`'s own gate map is.
    pub enrollment_gates: Gates<(String, String)>,
    /// Per-origin answer to `randseed.get`'s consent prompt: asked once per
    /// site and remembered, rather than asked again on every call — a
    /// recorded deliberate deviation.
    pub randseed_consent: Mutex<HashMap<String, bool>>,
    /// One `randseed.get` consent decision at a time per site: see
    /// `plugins::randseed::consent`.
    pub randseed_gates: Gates<String>,
    /// Per-origin override set by `app.change_ui_lang`, keyed by the full
    /// `Origin` header text — the same key `ApikeyService` uses for its own
    /// per-origin decisions (`origin.rs`'s `origin_key`), so a dialog
    /// answered for one scheme or port never leaks into another. Per-origin
    /// rather than one process-global language, so one site's change never
    /// colors another site's reply text; `lang_for` falls back to the
    /// dispatcher's own default for a site that never called it.
    pub lang_overrides: RwLock<HashMap<String, Lang>>,
}

/// A map of per-key turnstiles, as built by `gate_for` below. A type alias
/// rather than spelling this out at each field: `Mutex<HashMap<K,
/// Arc<tokio::sync::Mutex<()>>>>` on its own trips clippy's
/// `type_complexity` lint once `K` is a tuple.
type Gates<K> = Mutex<HashMap<K, Arc<tokio::sync::Mutex<()>>>>;

/// A per-key turnstile, copied from `origin.rs`'s own `gate_for`: one entry
/// per distinct key ever seen, so two calls carrying the same key never both
/// pass a check-then-act gap. Callers repeat their cheap checks once the
/// turn is held, since another caller may have settled things while this one
/// waited. Shared by `plugins::pki`'s enrolment turnstile and
/// `plugins::randseed`'s consent turnstile.
pub(crate) fn gate_for<K: std::hash::Hash + Eq + Clone>(gates: &Gates<K>, key: &K) -> Arc<tokio::sync::Mutex<()>> {
    let mut gates = gates.lock();
    Arc::clone(gates.entry(key.clone()).or_default())
}

impl Ctx {
    pub fn lang(&self) -> Lang {
        *self.lang.read()
    }

    pub fn t(&self, key: &str) -> String {
        self.messages.get(self.lang(), key).to_string()
    }

    /// `origin`'s own language, if `app.change_ui_lang` ever set one for it;
    /// the dispatcher's default otherwise.
    pub fn lang_for(&self, origin: &Origin) -> Lang {
        self.lang_overrides.read().get(&origin.header).copied().unwrap_or_else(|| self.lang())
    }

    /// Records `origin`'s own language, read back by `lang_for`. Never
    /// touches the process-wide default, so it affects only replies to this
    /// same origin.
    pub fn set_lang_for(&self, origin: &Origin, lang: Lang) {
        self.lang_overrides.write().insert(origin.header.clone(), lang);
    }
}

pub struct Dispatcher {
    ctx: Arc<Ctx>,
    functions: HashMap<(String, String), FunctionSpec>,
    order: Vec<(String, String)>,
    /// Set once, after construction, by `set_observer` — not a constructor
    /// parameter, because the engine that builds this dispatcher only has
    /// an `Arc<Engine>`-shaped thing to observe with after the fact. Read
    /// out and the guard dropped before use in `call`, the same discipline
    /// already applied to `developer_mode` there.
    observer: RwLock<Option<Arc<dyn CallObserver>>>,
}

impl Dispatcher {
    pub fn new(
        config: DispatcherConfig,
        sessions: Arc<Sessions>,
        discovery: Arc<Discovery>,
        ui: Arc<UiBroker>,
        apikeys: Arc<ApikeyService>,
    ) -> Self {
        let ctx = Arc::new(Ctx {
            lang: RwLock::new(config.lang),
            config,
            messages: Messages::load(),
            sessions,
            discovery,
            ui,
            apikeys,
            developer_mode: RwLock::new(false),
            remember_passwords: RwLock::new(true),
            ask_before_randseed: RwLock::new(true),
            enrollments: Mutex::new(HashMap::new()),
            enrollment_gates: Mutex::new(HashMap::new()),
            randseed_consent: Mutex::new(HashMap::new()),
            randseed_gates: Mutex::new(HashMap::new()),
            lang_overrides: RwLock::new(HashMap::new()),
        });
        let mut dispatcher = Dispatcher { ctx, functions: HashMap::new(), order: Vec::new(), observer: RwLock::new(None) };
        for spec in crate::plugins::all() {
            let key = (spec.plugin.to_string(), spec.name.to_string());
            dispatcher.order.push(key.clone());
            dispatcher.functions.insert(key, spec);
        }
        dispatcher
    }

    pub fn ctx(&self) -> &Arc<Ctx> {
        &self.ctx
    }

    /// Installs the observer `call` notifies after every response,
    /// replacing any previous one.
    pub fn set_observer(&self, observer: Arc<dyn CallObserver>) {
        *self.observer.write() = Some(observer);
    }

    pub fn set_lang(&self, lang: Lang) {
        *self.ctx.lang.write() = lang;
    }

    pub fn lang(&self) -> Lang {
        self.ctx.lang()
    }

    /// Drops expired sessions and expired enrolments, and bounds
    /// `lang_overrides` and `randseed_consent` (`MAX_ORIGIN_STATE`). The
    /// server calls this on a timer; nothing else does, which is why every
    /// one of these had no caller at the end of phase 2A.
    pub fn sweep(&self) {
        self.ctx.sessions.sweep();
        crate::plugins::pki::sweep_enrollments(&self.ctx);
        let mut lang_overrides = self.ctx.lang_overrides.write();
        if lang_overrides.len() > MAX_ORIGIN_STATE {
            lang_overrides.clear();
        }
        drop(lang_overrides);
        let mut randseed_consent = self.ctx.randseed_consent.lock();
        if randseed_consent.len() > MAX_ORIGIN_STATE {
            randseed_consent.clear();
        }
    }

    /// Runs one request. Never returns an error: every failure becomes a reply.
    /// Notifies the observer, if any, with the outcome of every single return
    /// path below — an activity log that silently omitted a refusal would be
    /// worse than none, since a site being denied is exactly what someone
    /// opens that screen to see.
    pub async fn call(&self, origin: &Origin, request: Request) -> Response {
        let response = self.call_inner(origin, &request).await;
        self.notify_observer(origin, &request, &response);
        response
    }

    async fn call_inner(&self, origin: &Origin, request: &Request) -> Response {
        if request.arguments.iter().any(|a| a.len() > MAX_ARGUMENT_BYTES) {
            // The original's frame decoder refuses this while parsing, so no
            // handler of its own ever sees it. Say nothing about which
            // argument or how large it was.
            return self.error(origin, RpcError::Runtime("argument too large".into()));
        }
        let key = (request.plugin.clone(), request.name.clone());
        let Some(spec) = self.functions.get(&key) else {
            return self.error(origin, RpcError::FunctionNotFound);
        };
        if !spec.accepts(request.arguments.len()) {
            return self.error(origin, RpcError::FunctionNotFound);
        }
        // Every function but the main plugin's three goes through the origin
        // gate, mirroring the original's own per-origin permission check.
        if !spec.plugin.is_empty() {
            // Read out and drop the guard before awaiting: holding a
            // parking_lot lock across an await point is a deadlock risk
            // clippy (rightly) refuses to pass.
            let developer_mode = *self.ctx.developer_mode.read();
            match self.ctx.apikeys.decide(origin, &self.ctx.ui, developer_mode).await {
                OriginDecision::Allow => {}
                OriginDecision::Deny => return self.error(origin, RpcError::OriginNotAllowed(origin.domain.clone())),
                OriginDecision::NoHeader => return self.error(origin, RpcError::FailedToIdentifyDomain),
            }
        }
        // Answered here rather than by its handler, because building the
        // document needs the whole function table, including this entry.
        // Its arguments have already been checked above.
        if request.plugin.is_empty() && request.name == "apidoc" {
            return Response::raw(self.apidoc(origin));
        }
        match (spec.handler)(&self.ctx, origin, request).await {
            Ok(response) => response,
            Err(e) => self.error(origin, e),
        }
    }

    /// `origin.header` (matching how permissions are keyed) and the
    /// request's own `plugin`/`name` — not the resolved `FunctionSpec`'s,
    /// since a function-not-found refusal never had one — with `outcome`
    /// `"ok"` on success or the status code and reason otherwise, e.g.
    /// `-5000 Ввод пароля отменен`.
    fn notify_observer(&self, origin: &Origin, request: &Request, response: &Response) {
        let observer = self.observer.read().clone();
        let Some(observer) = observer else { return };
        let outcome = if response.success {
            "ok".to_string()
        } else {
            match &response.reason {
                Some(reason) => format!("{} {reason}", response.status),
                None => response.status.to_string(),
            }
        };
        observer.observe(&origin.header, &request.plugin, &request.name, &outcome);
    }

    /// Formats `e` in the language `origin` itself is set to (`Ctx::lang_for`),
    /// so a language `app.change_ui_lang` changed for one site never colors
    /// another site's reply.
    fn error(&self, origin: &Origin, e: RpcError) -> Response {
        e.into_response(&self.ctx.messages, self.ctx.lang_for(origin))
    }

    /// The reply an unknown function gets. A frame that will not parse as a
    /// request at all gets the same one, which is what the original's
    /// streaming parser produces when it cannot build a call — no `Request`
    /// was ever built to route through `call`, so this keeps its own
    /// signature, but formats in `origin`'s own language (`Ctx::lang_for`),
    /// exactly like `error` above.
    pub fn function_not_found(&self, origin: &Origin) -> Response {
        RpcError::FunctionNotFound.into_response(&self.ctx.messages, self.ctx.lang_for(origin))
    }

    /// The array of plugin documents the `apidoc` function returns, in
    /// `origin`'s own language (`Ctx::lang_for`) rather than the
    /// dispatcher's process-wide default -- `app.change_ui_lang` moved the
    /// language itself to a per-origin override (`Ctx::set_lang_for`), and
    /// this must follow it the same way `error` already does, or a site
    /// that asks for Uzbek gets its own document back in Russian. Only the
    /// eleven plugin descriptions vary with `lang`: each function's own
    /// `description` is a fixed string from `FunctionSpec`, hard-coded
    /// Russian in the original regardless of language, and stays that way
    /// here too.
    pub fn apidoc(&self, origin: &Origin) -> Value {
        let lang = self.ctx.lang_for(origin);
        let mut plugins: Vec<(&str, Vec<Value>)> = Vec::new();
        for key in &self.order {
            let Some(spec) = self.functions.get(key) else { continue };
            if spec.description.is_empty() {
                continue; // the original omits functions with no description
            }
            let args: Vec<Value> = spec
                .args
                .iter()
                .map(|a| json!({"name": a.name, "description": a.description, "optional": a.optional}))
                .collect();
            let entry = json!({
                "plugin": spec.plugin,
                "name": spec.name,
                "description": spec.description,
                "arguments": args,
            });
            match plugins.iter_mut().find(|(p, _)| *p == spec.plugin) {
                Some((_, list)) => list.push(entry),
                None => plugins.push((spec.plugin, vec![entry])),
            }
        }
        let docs: Vec<Value> = plugins
            .into_iter()
            .map(|(plugin, functions)| {
                let description_key = crate::plugins::plugin_description_key(plugin);
                json!({
                    "name": plugin,
                    "description": self.ctx.messages.get(lang, description_key),
                    "functions": functions,
                })
            })
            .collect();
        Value::Array(docs)
    }
}
