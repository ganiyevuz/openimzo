//! The plain-HTTP half of what a website sees.

use crate::assets;
use crate::state::AppState;
use crate::ws;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

/// Chrome's Private Network Access preflight. The original answers ANY
/// `OPTIONS` with these four headers and then closes, so a page on a public
/// site is allowed to open a socket to this machine at all.
async fn preflight(headers: HeaderMap) -> Response {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("*")
        .to_string();
    let mut response = Response::new(Body::empty());
    let h = response.headers_mut();
    h.insert("Access-Control-Allow-Private-Network", HeaderValue::from_static("true"));
    if let Ok(value) = HeaderValue::from_str(&origin) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("*"));
    response
}

fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

fn binary(kind: &'static str, body: &'static [u8]) -> Response {
    ([(header::CONTENT_TYPE, kind)], body).into_response()
}

async fn index(State(state): State<AppState>) -> Response {
    let ctx = state.dispatcher.ctx();
    html(assets::index_html(&ctx.messages, ctx.lang()))
}

async fn apidoc() -> Response {
    html(assets::apidoc_html())
}

async fn eimzo_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        assets::EIMZO_JS,
    )
        .into_response()
}

/// Exactly what the original answers for an unknown path: the four words, as
/// plain text, with a 404.
async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "404 - Not Found").into_response()
}

/// `method_not_allowed_fallback` only fires for a path that has a route but
/// no handler for the method used, so on its own it would miss `OPTIONS` to
/// a path this router does not know at all. The original answers any
/// `OPTIONS` ahead of routing entirely, so every route below also gets an
/// explicit `options(preflight)`, and this catch-all fallback answers
/// `OPTIONS` the same way for every other path, and 404s everything else.
async fn fallback(method: Method, headers: HeaderMap) -> Response {
    if method == Method::OPTIONS {
        preflight(headers).await
    } else {
        not_found().await
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index).options(preflight))
        .route("/apidoc.html", get(apidoc).options(preflight))
        .route("/e-imzo.js", get(eimzo_js).options(preflight))
        .route("/e-imzo-logo.png", get(|| async { binary("image/png", assets::LOGO_PNG) }).options(preflight))
        .route("/favicon.ico", get(|| async { binary("image/x-icon", assets::FAVICON_ICO) }).options(preflight))
        .route("/icon.png", get(|| async { binary("image/png", assets::ICON_PNG) }).options(preflight))
        .route("/service/cryptapi", get(ws::upgrade).options(preflight))
        // The original answers ANY verb it does not handle on a known path
        // with the same plain "404 - Not Found" body an unknown path gets;
        // without this, axum's own default here would be a bare 405, which
        // is not what the original does.
        .method_not_allowed_fallback(not_found)
        .fallback(fallback)
        .with_state(state)
}
