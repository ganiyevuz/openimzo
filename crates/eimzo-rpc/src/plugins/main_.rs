//! The unnamed plugin: what a site calls before anything else.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::vararg;
use serde_json::Value;

pub fn functions() -> Vec<FunctionSpec> {
    vec![
        function!("", "version", "", [], version),
        function!("", "apikey", "", [vararg("array", "")], apikey),
        function!("", "apidoc", "", [], apidoc),
    ]
}

async fn version(ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    let (major, minor, patch) = ctx.config.version;
    Ok(Response::success()
        .with("major", Value::String(major.into()))
        .with("minor", Value::String(minor.into()))
        .with("patch", Value::String(patch.into()))
        .with("edition", Value::String(ctx.config.edition.into())))
}

/// `arguments` is `[domain, key, domain, key, …]`. Every pair must verify;
/// the reply's `message` is the caller's own Origin header, as the original
/// returns. `ApikeyService::register` (`origin.rs`) both verifies and caches
/// each pair, so the check runs exactly once.
async fn apikey(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let args = &request.arguments;
    if args.len() < 2 || !args.len().is_multiple_of(2) {
        return Err(RpcError::FunctionNotFound);
    }
    for pair in args.chunks(2) {
        let (domain, key) = (&pair[0], &pair[1]);
        if !ctx.apikeys.register(domain, key) {
            return Err(RpcError::ApiKeyInvalid(domain.clone()));
        }
    }
    Ok(Response::message(origin.header.clone()))
}

async fn apidoc(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    // The dispatcher owns the registry, so it fills this in; see the note in
    // `Dispatcher::call`: `apidoc` is answered there, not here.
    Err(RpcError::FunctionNotFound)
}
