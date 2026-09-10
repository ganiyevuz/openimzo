//! `randseed.get`: AES-128 encrypts the caller's network description, the
//! AES key is wrapped for a hard-coded RSA-2048 public key, and both travel
//! back to the site as one TLV blob. Carries an empty `apidoc` description,
//! like the main plugin's own functions (`main_.rs`), so the document this
//! project publishes has the same shape as the one sites already parse.
//!
//! What the blob carries — the machine's hostname and its network
//! interfaces (`RandseedProvider`) — identifies the machine, not the key or
//! the document being signed, so this project asks the person before
//! answering: once per site rather than once per call (`consent` below).
//! A recorded deliberate deviation, and the reason this module has any
//! dialog code in it at all.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::arg;
use crate::ui::{Consent, RandseedRequest};
use aes::Aes128;
use base64::Engine as _;
use cipher::block_padding::Pkcs7;
use cipher::{BlockEncryptMut, KeyInit};
use rand_core::{OsRng, RngCore};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroize;

/// Supplies the bytes `randseed.get` packages: the machine's hostname and
/// its network interfaces, gathered however the embedder likes.
/// `openimzo-rpc` never reads the environment itself, so the app and the CLI
/// each hand in their own implementation; everything downstream of this —
/// the TLV framing, the AES and RSA steps, the base64 packing — stays in
/// this module so the two cannot diverge on the wire format.
pub trait RandseedProvider: Send + Sync {
    fn network_description(&self) -> Vec<u8>;
}

/// The RSA-2048 public key `randseed.get` wraps the AES key under, copied
/// verbatim from the original's own hard-coded constant. X.509 SPKI,
/// base64.
const RSA_PUBLIC_KEY_SPKI_BASE64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkEvIE+RqyRHlNc1uISAwT1KwuLM86PdFC+3BJWTYm/veboZnBKDEOsQtHwr6jsy/Z9JSdqOwOL2YdMzoyyCt2UzF898TZoZPpMY92EHKfVQnZSRcI66o8xcTIKy3dTboXE6x92pvR4GxoZywcLrpcV7w9ZBpOrUNOkr0vpFR1My1dmPsZ4oPxP77LYqbLd5xfptbSGB7dJetyU7pfCo03g65bXrDknG2P1bdEV7zkSt1qm6ax+z/IQuC2vwMhPmFYPB4WM5323MlLCBrb/zqlXXxu4oEXA5UF5KMlssW+NJ4Z9hfLaeuNSDk85Xzapem4y3rPQBlyOC8nFV6OOoOxQIDAQAB";

/// Above this many entries, `gate_for` tries to reclaim turnstiles nobody is
/// waiting on before adding one more for a site it hasn't seen yet. Bounds
/// `Ctx::randseed_gates`: unlike `plugins::pki`'s enrolment turnstiles
/// (reclaimed by `sweep_enrollments` on a timer) or `origin.rs`'s own gate
/// map, nothing ever sweeps this one — without a cap, every distinct site
/// that ever calls `randseed.get` would leave a permanent entry for the life
/// of the process.
const MAX_GATES: usize = 1024;

/// The per-site turnstile for `randseed.get` consent, mirroring `origin.rs`'s
/// own `gate_for`: once the map holds more than `MAX_GATES` entries and
/// `domain` isn't already one of them, first drop every turnstile nobody is
/// currently waiting on (its `Arc` has no clone outstanding besides the
/// map's own). If that frees nothing — every one of them is in use —
/// proceed anyway rather than fail the request.
fn gate_for(ctx: &Ctx, domain: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut gates = ctx.randseed_gates.lock();
    if gates.len() > MAX_GATES && !gates.contains_key(domain) {
        gates.retain(|_, gate| Arc::strong_count(gate) > 1);
    }
    Arc::clone(gates.entry(domain.to_string()).or_default())
}

pub fn functions() -> Vec<FunctionSpec> {
    // Empty description and argument text, matching the main plugin's own
    // (`main_.rs`): `apidoc` omits a function that has no description.
    vec![function!("randseed", "get", "", [arg("source", "")], get)]
}

async fn get(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let source = request.arg(0);
    if source != "netconf" {
        return Err(RpcError::InvalidArgSeed);
    }
    // No environment access wired up for this build: same status as an
    // unsupported source, since the site cannot tell the two apart anyway.
    let Some(provider) = ctx.config.randseed_provider.clone() else {
        return Err(RpcError::InvalidArgSeed);
    };
    consent(ctx, origin).await?;

    let data = provider.network_description();
    let hash = Sha256::digest(&data);

    let mut aes_key = [0u8; 16];
    OsRng.fill_bytes(&mut aes_key);
    let encryptor =
        <ecb::Encryptor<Aes128> as KeyInit>::new_from_slice(&aes_key).map_err(|e| RpcError::Runtime(e.to_string()))?;
    let encdata = encryptor.encrypt_padded_vec_mut::<Pkcs7>(&data);

    let spki_der =
        base64::engine::general_purpose::STANDARD.decode(RSA_PUBLIC_KEY_SPKI_BASE64).map_err(|e| RpcError::Runtime(e.to_string()))?;
    let public_key = RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| RpcError::Runtime(e.to_string()))?;
    let enckey = public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, &aes_key).map_err(|e| RpcError::Runtime(e.to_string()))?;
    aes_key.zeroize();

    let mut inner = Vec::new();
    inner.extend(encode_tlv(0x10, &encdata));
    inner.extend(encode_tlv(0x11, &hash));
    inner.extend(encode_tlv(0x12, &enckey));
    let outer = encode_tlv(0xF0, &inner);

    Ok(Response::success().with("seed", Value::String(base64::engine::general_purpose::STANDARD.encode(&outer))))
}

/// "Ask once per site and remember": the person is prompted on the first
/// call from a given origin, and that answer is reused for the rest of the
/// process rather than asking again on every call.
/// Whatever stops this call from succeeding — a denial, a cancellation, a
/// timed-out dialog, no UI at all, or the broker refusing outright because
/// it is `Busy` — answers `-5001`, same status as any other cancelled
/// confirmation. But only one of those is a decision the person made: an
/// explicit `Consent::Deny`. Every other outcome is cached as *nothing*
/// rather than as a denial, so the next call for that site asks again
/// instead of finding a permanent refusal it never earned. `Busy` is why
/// this matters most: the broker can return it without the person ever
/// seeing this site's dialog at all — the queue was already full, or the
/// turn never came free in time — commonly because a *different* site was
/// holding it. Recording that as this site's answer would let one site's
/// traffic quietly and permanently deny another. This is the same
/// reasoning `origin.rs`'s `decide` applies to a refusal reached without
/// ever asking the person: not a choice, so not recorded.
///
/// Gated by a per-site turnstile (this module's own `gate_for`, the same
/// pattern `origin.rs` and `plugins::pki::enroll_pfx_step1` use): without it,
/// two calls arriving together for a site with no decision yet both find
/// nothing recorded and both show the dialog
/// (a recorded follow-up).
async fn consent(ctx: &Ctx, origin: &Origin) -> Result<()> {
    // Settings' own "ask before seeding" toggle, off: answer without
    // prompting, for someone who has chosen not to be asked each time.
    if !*ctx.ask_before_randseed.read() {
        return Ok(());
    }
    if let Some(&allowed) = ctx.randseed_consent.lock().get(&origin.domain) {
        return if allowed { Ok(()) } else { Err(RpcError::OperationCanceled) };
    }
    let gate = gate_for(ctx, &origin.domain);
    let _turn = gate.lock().await;
    // Another call for this same site may have settled it while we waited.
    if let Some(&allowed) = ctx.randseed_consent.lock().get(&origin.domain) {
        return if allowed { Ok(()) } else { Err(RpcError::OperationCanceled) };
    }
    match ctx.ui.confirm_randseed(RandseedRequest { origin: origin.domain.clone() }).await {
        Ok(Consent::Allow) => {
            ctx.randseed_consent.lock().insert(origin.domain.clone(), true);
            Ok(())
        }
        // The person was actually asked and actually said no: a real
        // decision, so it is the one outcome worth remembering.
        Ok(Consent::Deny) => {
            ctx.randseed_consent.lock().insert(origin.domain.clone(), false);
            Err(RpcError::OperationCanceled)
        }
        // Cancelled, timed out, no UI available, or the broker never even
        // reached the person because it was busy: none of these is a
        // decision, so nothing is cached and the next call tries again.
        Err(_) => Err(RpcError::OperationCanceled),
    }
}

/// The original's TLV codec: one tag byte, then the length as
/// little-endian base-128 digits with the continuation bit (`0x80`) set on
/// every digit but the last. `encode_length(0) == [0]`, matching the
/// original, which encodes a zero length as a single zero byte rather than
/// as no bytes at all.
fn encode_length(mut len: usize) -> Vec<u8> {
    let mut digits = Vec::new();
    loop {
        digits.push((len % 128) as u8);
        len /= 128;
        if len == 0 {
            break;
        }
    }
    let last = digits.len() - 1;
    for d in &mut digits[..last] {
        *d |= 0x80;
    }
    digits
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + value.len());
    out.push(tag);
    out.extend(encode_length(value.len()));
    out.extend_from_slice(value);
    out
}
