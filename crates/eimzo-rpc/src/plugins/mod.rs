//! The function table. Each module contributes its plugin's functions in the
//! order the original registered them.

use crate::dispatch::FunctionSpec;

pub mod app;
// `pub`, not private: `eimzo-ffi`'s `Engine::change_password` reaches
// `keystore::overwrite_key_file` directly, the one item in here it needs
// (see that function's own doc comment). Every other item stays
// `pub(super)`, so this widening exposes nothing else.
pub mod keystore;
pub mod main_;
pub mod pfx;
pub mod pki;
pub mod pkcs10;
pub mod pkcs7;
pub mod randseed;
pub mod tokens;
pub mod x509;
pub mod ytks;

/// Registration order matches the original's own: `app, pfx, pki, pkcs7,
/// x509, baikey, idcard, ckc, pkcs10, ytks, uzgrd`, with the unnamed main
/// plugin ahead of all of them and `randseed` (no `apidoc` description)
/// tacked on at the end.
pub fn all() -> Vec<FunctionSpec> {
    let mut out = Vec::new();
    out.extend(main_::functions());
    out.extend(app::functions());
    out.extend(pfx::functions());
    out.extend(pki::functions());
    out.extend(pkcs7::functions());
    out.extend(x509::functions());
    out.extend(tokens::baikey_functions());
    out.extend(tokens::idcard_functions());
    out.extend(tokens::ckc_functions());
    out.extend(pkcs10::functions());
    out.extend(ytks::functions());
    out.extend(tokens::uzgrd_functions());
    out.extend(randseed::functions());
    out
}

/// The message key the original used for each plugin's `apidoc` description.
pub fn plugin_description_key(plugin: &str) -> &'static str {
    match plugin {
        "app" => "plugin.works.with.eimzo.settings",
        "pfx" => "plugin.works.with.pfx",
        "ytks" => "plugin.works.with.yks",
        "pkcs7" => "plugin.works.with.pkcs7",
        "pkcs10" => "plugin.to.generate.pkcs10",
        "x509" => "plugin.works.with.x509.certificate",
        "pki" => "plugin.works.with.pki",
        "ckc" => "plugin.works.with.crypto.key.container",
        "baikey" => "plugin.works.with.baik.token",
        "idcard" => "plugin.works.with.id.card",
        "uzgrd" => "plugin.works.with.uzguard.token",
        _ => "",
    }
}

/// Builds a `FunctionSpec` without repeating the boxing dance in every module.
#[macro_export]
macro_rules! function {
    ($plugin:expr, $name:expr, $description:expr, [$($arg:expr),* $(,)?], $handler:expr) => {{
        use std::sync::Arc;
        $crate::dispatch::FunctionSpec {
            plugin: $plugin,
            name: $name,
            description: $description,
            args: vec![$($arg),*],
            handler: Arc::new(move |ctx, origin, request| Box::pin($handler(ctx, origin, request))),
        }
    }};
}

/// Shorthand for an argument specification.
pub fn arg(name: &'static str, description: &'static str) -> crate::dispatch::ArgSpec {
    crate::dispatch::ArgSpec { name, description, optional: false, variadic: false }
}

pub fn opt(name: &'static str, description: &'static str) -> crate::dispatch::ArgSpec {
    crate::dispatch::ArgSpec { name, description, optional: true, variadic: false }
}

/// An argument that takes every remaining value. The handler checks the count.
pub fn vararg(name: &'static str, description: &'static str) -> crate::dispatch::ArgSpec {
    crate::dispatch::ArgSpec { name, description, optional: false, variadic: true }
}
