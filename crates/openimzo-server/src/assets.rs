//! The two pages this project serves, embedded in the binary.
//!
//! Both are ours: rewritten, rebranded, and — unlike anything a website
//! reads — free to say whatever we want in whatever language the person is
//! using. Each carries `{{name}}` placeholders filled from `pages.rs`'s
//! table at request time, so the page a person opens is in the same
//! language the menu bar is already speaking.
//!
//! `e-imzo.js` is the exception and is served byte-for-byte as the original
//! serves it: it is the official browser client every integrated site
//! loads, and it is a wire contract, not a page.

use crate::pages;
use openimzo_rpc::UiLang;

pub const INDEX_HTML: &str = include_str!("../resources/html/index.html");
pub const APIDOC_HTML: &str = include_str!("../resources/html/apidoc.html");
pub const CLIENT_JS: &str = include_str!("../resources/html/e-imzo.js");
pub const LOGO_PNG: &[u8] = include_bytes!("../resources/html/openimzo-logo.png");
pub const FAVICON_ICO: &[u8] = include_bytes!("../resources/html/favicon.ico");
pub const ICON_PNG: &[u8] = include_bytes!("../resources/html/icon.png");

/// The version the pages and the `version` function both report. Sites read
/// it to decide which calls they may make, so it stays 6.4.7 while we claim
/// compatibility.
pub const VERSION: &str = "6.4.7";

/// Substitutes every `{{name}}` in `template` from `values`, in one pass.
///
/// One pass on purpose: a value that itself contains `{{...}}` is copied
/// through untouched rather than substituted again, so page text can never
/// reach back into the table. A name with no entry is left on the page
/// verbatim, which makes a typo visible instead of silently blanking the
/// text it was meant to carry.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 1024);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let (before, tail) = rest.split_at(start);
        out.push_str(before);
        let Some(end) = tail.find("}}") else {
            out.push_str(tail);
            return out;
        };
        match values.iter().find(|(name, _)| *name == &tail[2..end]) {
            Some((_, value)) => out.push_str(value),
            None => out.push_str(&tail[..end + 2]),
        }
        rest = &tail[end + 2..];
    }
    out.push_str(rest);
    out
}

/// The landing page a person sees at `http://127.0.0.1:64646/`.
pub fn index_html(lang: UiLang) -> String {
    let t = pages::text(lang);
    let banner = format!("E-IMZO-v{VERSION}");
    let status = t.status.replace("%s", VERSION);
    fill(
        INDEX_HTML,
        &[
            ("lang", t.code),
            ("version", &banner),
            ("tagline", t.tagline),
            ("status", &status),
            ("api_docs", t.api_docs),
            ("source_code", t.source_code),
        ],
    )
}

/// The API reference at `/apidoc.html`. The plugin and function text on it
/// arrives separately, over the WebSocket, from `Dispatcher::apidoc` — this
/// fills in only the page's own chrome around it.
pub fn apidoc_html(lang: UiLang) -> String {
    let t = pages::text(lang);
    let banner = format!("E-IMZO-v{VERSION}");
    fill(
        APIDOC_HTML,
        &[
            ("lang", t.code),
            ("version", &banner),
            ("api_docs", t.api_docs),
            ("compat_lead", t.compat_lead),
            ("compat_body", t.compat_body),
            ("compat_note", t.compat_note),
            ("toc_title", t.toc_title),
            ("loading", t.loading),
            ("loading_doc", t.loading_doc),
            ("copy", t.copy),
            ("copied", t.copied),
            ("optional", t.optional),
            ("load_failed", t.load_failed),
        ],
    )
}
