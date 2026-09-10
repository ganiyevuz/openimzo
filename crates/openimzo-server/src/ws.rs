//! The WebSocket half: one JSON request per text frame, one reply per request.

use crate::state::AppState;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap};
use axum::response::Response;
use openimzo_rpc::dispatch::MAX_MESSAGE_BYTES;
use openimzo_rpc::model::Request;
use openimzo_rpc::origin::Origin;
use futures_util::SinkExt;
use std::collections::HashMap;

/// The original closes with this exact code and reason after a single reply
/// when `keepConnection` is absent.
const DONE_CODE: u16 = 1000;
const DONE_REASON: &str = "Done";

/// Sent when a receive fails, which today only happens when a frame arrives
/// past `MAX_MESSAGE_BYTES`: `1009` is the protocol's own "message too big"
/// close code. Internal error detail never goes back to the page (a
/// recorded deviation), so the reason stays short and fixed; the details
/// go to the local log instead.
const TOO_BIG_CODE: u16 = 1009;
const TOO_BIG_REASON: &str = "message too big";

/// Sent when the server is stopped while this connection is still open.
/// `1001` is the protocol's own "going away" code - there is no message in
/// this protocol for it, so the connection is simply ended.
const GOING_AWAY_CODE: u16 = 1001;
const GOING_AWAY_REASON: &str = "server stopping";

pub async fn upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    // Read once, at the handshake, exactly as the original does: the gate is
    // only meaningful if a connection cannot change which site it claims to
    // be part-way through.
    let origin = Origin::from_header(
        headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()).unwrap_or(""),
    );
    let keep = params.contains_key("keepConnection");
    ws.max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| serve(socket, state, origin, keep))
}

async fn serve(mut socket: WebSocket, state: AppState, origin: Origin, keep: bool) {
    let mut shutdown = state.shutdown.subscribe();
    // `subscribe()` treats whatever value is already in the channel as
    // already observed, so a receiver created after the sender already
    // flipped to `true` would wait on `changed()` below forever and never
    // learn the server stopped. A connection can finish its upgrade in the
    // same instant a stop is requested, landing exactly in that gap - check
    // the current value directly before ever entering the loop. Do not
    // remove this as redundant with the `changed()` arm: it is the only
    // thing that catches this particular timing.
    if *shutdown.borrow() {
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: GOING_AWAY_CODE,
                reason: GOING_AWAY_REASON.into(),
            })))
            .await;
        return;
    }
    loop {
        let incoming = tokio::select! {
            incoming = socket.recv() => incoming,
            _ = shutdown.changed() => {
                // Sent with a plain `send`, not `SinkExt::close`: nothing
                // has been seen on this connection this time around (any
                // close, ours or the peer's, ends the loop below without
                // coming back here), so it is still active, exactly like
                // the `TOO_BIG_CODE` and `DONE_CODE` sends further down.
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: GOING_AWAY_CODE,
                        reason: GOING_AWAY_REASON.into(),
                    })))
                    .await;
                return;
            }
        };
        let Some(incoming) = incoming else { return };
        let text = match incoming {
            Ok(Message::Text(text)) => text,
            // Binary, ping and pong are not part of the protocol; the
            // original ignores everything that is not a text frame.
            Ok(Message::Close(_)) => {
                // Complete the closing handshake by echoing one back. This
                // must go through `Sink::close` (`SinkExt`), not
                // `WebSocket::send`: tungstenite already queued its own
                // reply the moment it decoded the client's close frame, and
                // refuses any further `send` once a close has been seen in
                // either direction; only `close` (which flushes that queued
                // reply directly) actually puts it on the wire.
                let _ = SinkExt::close(&mut socket).await;
                return;
            }
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!(error = %e, "websocket receive failed");
                // The socket may already be dead, so a failure here is not
                // worth reporting; either way, this connection is done.
                let _ = socket
                    .send(Message::Close(Some(CloseFrame { code: TOO_BIG_CODE, reason: TOO_BIG_REASON.into() })))
                    .await;
                return;
            }
        };
        let reply = match serde_json::from_str::<Request>(&text) {
            Ok(request) => state.dispatcher.call(&origin, request).await,
            // A frame that is not a request at all gets the same answer an
            // unknown function gets, which is what the original's streaming
            // parser produces when it cannot build a call.
            Err(e) => {
                tracing::debug!(error = %e, "malformed request frame");
                state.dispatcher.function_not_found(&origin)
            }
        };
        let body = reply.to_json();
        if socket.send(Message::Text(body)).await.is_err() {
            return;
        }
        if !keep {
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: DONE_CODE,
                    reason: DONE_REASON.into(),
                })))
                .await;
            return;
        }
    }
}
