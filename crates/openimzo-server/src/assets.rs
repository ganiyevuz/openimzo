//! The pages the original serves, embedded in the binary.
//!
//! `index.html` carries the original's two placeholders: `{0}` is the version
//! banner and `{1}` the localized "installed and working" sentence, which the
//! original fills from the same message bundle we use. The other files are
//! served byte-for-byte as the original serves them, including `e-imzo.js`,
//! which is the official browser client every site loads.

use openimzo_rpc::i18n::{Arg, Lang, Messages};

pub const INDEX_HTML: &str = include_str!("../resources/html/index.html");
pub const APIDOC_HTML: &str = include_str!("../resources/html/apidoc.html");
pub const CLIENT_JS: &str = include_str!("../resources/html/e-imzo.js");
pub const LOGO_PNG: &[u8] = include_bytes!("../resources/html/e-imzo-logo.png");
pub const FAVICON_ICO: &[u8] = include_bytes!("../resources/html/favicon.ico");
pub const ICON_PNG: &[u8] = include_bytes!("../resources/html/icon.png");

/// The version the pages and the `version` function both report. Sites read
/// it to decide which calls they may make, so it stays 6.4.7 while we claim
/// compatibility.
pub const VERSION: &str = "6.4.7";

/// `index.html` with the original's two placeholders filled.
pub fn index_html(messages: &Messages, lang: Lang) -> String {
    let banner = format!("E-IMZO-v{VERSION}");
    let sentence = messages.format(
        lang,
        "eimzo.successfully.installed.and.working",
        &[Arg::S(VERSION.to_string()), Arg::S(VERSION.to_string())],
    );
    INDEX_HTML.replace("{0}", &banner).replace("{1}", &sentence)
}

/// `apidoc.html` with the same version banner the original fills in.
pub fn apidoc_html() -> String {
    APIDOC_HTML.replace("{0}", &format!("E-IMZO-v{VERSION}"))
}
