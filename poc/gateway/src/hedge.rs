//! `POST /hedge` — atomic two-leg hedge: sign BOTH legs in the enclave, then
//! execute BOTH venue calls server-side in parallel.
//!
//! WHY THIS EXISTS (dispatch 2026-06-10T2330Z): for a remote arbitrageur the
//! 2-leg gap is network-RTT-dominated (~1.4 s sequential via the MCP client).
//! One round-trip to the box + parallel venue execution from the box's clean
//! IP collapses the gap to the venues' own latency spread, and fixes the OKX
//! residential geo-block as a side effect.
//!
//! EGRESS DOCTRINE CHANGE (deliberate, reviewed): everywhere else the gateway
//! is sign-only (Option A — the MCP executes venue calls). `/hedge` is the
//! FIRST endpoint where the gateway itself calls venues. Scope is strictly
//! the two whitelisted structured-order venues; signed auth headers now stay
//! on the box instead of transiting to the client — a net security gain.
//!
//! Failure semantics (the part that matters with real money):
//!   - sign phase is ALL-OR-NOTHING: if either leg fails policy/signing,
//!     NOTHING is executed and the response carries per-leg sign status.
//!   - execute phase is best-effort parallel: a leg that fails at the venue
//!     CANNOT be rolled back (market orders). The response reports per-leg
//!     truth (`executed` / `partial` / `failed`) — never fabricate, never
//!     hide a naked leg. The agent decides how to repair a partial.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::auth::{RawToken, ResolvedCustomer};
use crate::handlers::{
    binance_base_url, build_binance_signed_qs, okx_base_url, okx_is_demo, sign_structured_request,
    AgentIntentForward,
};
use crate::proto::OrderParams;
use crate::state::AppState;

/// Venue HTTP timeout. Generous vs the venues' p99 (~400 ms) but short enough
/// that a hung venue doesn't pin the hedge for the axum-layer default.
const VENUE_TIMEOUT_SECS: u64 = 10;

/// Cap on the venue response body we buffer/echo (a venue should answer in
/// <2 KiB; a megabyte body is an edge/WAF page, not an order receipt).
const MAX_VENUE_BODY_BYTES: usize = 64 * 1024;

/// Browser-like UA for venue execution — OKX's Cloudflare edge 403s
/// non-browser agents ("error code 1010"). Same value the MCP client uses.
const EXCHANGE_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

// ── Wire shapes ──

/// One leg of the hedge: same `{key_id, order}` contract as
/// `/sign/<venue>-order`, so policies/caps apply identically.
///
/// `venue` selects the signing action + endpoint and defaults to `key_id`
/// (single-tenant boxes name blobs after the venue). Operators with custom
/// blob stems (`binance_futures.enc`, future multi-tenant opaque key ids)
/// pass it explicitly: `{key_id:"binance_futures", venue:"binance"}`.
/// `deny_unknown_fields`: the gateway re-serializes the TYPED struct toward
/// the enclave, so a typo'd field (`reduceOnly`) would otherwise be silently
/// DROPPED here and never reach the enclave's own deny_unknown_fields check —
/// flipping order semantics without an error (adversarial review #12).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HedgeLegSpec {
    pub key_id: String,
    #[serde(default)]
    pub venue: Option<String>,
    pub order: OrderParams,
}

impl HedgeLegSpec {
    fn venue(&self) -> String {
        self.venue
            .as_deref()
            .unwrap_or(&self.key_id)
            .trim()
            .to_ascii_lowercase()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HedgeRequest {
    pub legs: Vec<HedgeLegSpec>,
}

/// Per-leg execution outcome. The three-way split exists because a timed-out
/// or 5xx'd venue call is NOT a rejection: the order may be LIVE on the
/// exchange with the receipt lost (Binance explicitly documents 5xx/timeout
/// as "execution status UNKNOWN"). Collapsing that into `rejected` invites
/// the agent to retry — and a retry of a live market leg doubles the
/// position (adversarial review BLOCKER #1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegOutcome {
    /// Venue returned a well-formed receipt accepting the order.
    Ok,
    /// Venue definitively rejected it (4xx / negative code / sCode≠0) —
    /// nothing is live on this leg; retry is safe.
    Rejected,
    /// Request may have reached the matching engine but the receipt is
    /// missing/unreadable (timeout, 5xx, unparseable body). DO NOT retry
    /// blindly — query order state first.
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct HedgeLegResult {
    pub venue: String,
    /// "signed" → executed; "sign_failed" → nothing executed anywhere.
    pub phase: &'static str,
    pub outcome: LegOutcome,
    /// Convenience mirror of `outcome == ok`.
    pub ok: bool,
    /// Which environment this leg actually hit ("live" | "testnet" | "demo").
    /// Surfaced so a mixed-env misconfig is visible in the receipt, not just
    /// in the gateway's env vars.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Parsed venue JSON receipt, or raw text snippet when not JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HedgeResponse {
    /// "executed" (both receipts accepted) | "partial" (ONE leg live —
    /// naked!) | "unknown" (≥1 leg in receipt-lost limbo — reconcile before
    /// ANY retry) | "failed" (both legs definitively rejected) | "rejected"
    /// (sign phase, nothing executed).
    pub status: &'static str,
    pub legs: Vec<HedgeLegResult>,
    pub sign_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_ms: Option<u64>,
}

/// A leg signed by the enclave, ready to fire. Headers carry venue auth
/// secrets — this struct must never be serialized to the client or logged.
struct SignedLeg {
    venue: &'static str,
    url: String,
    headers: BTreeMap<String, String>,
    body: String,
}

impl Drop for SignedLeg {
    /// Same hygiene as `SignBinanceOrderResponse` / `SignOkxResponse` in
    /// proto.rs: wipe the signed body and every header VALUE (X-MBX-APIKEY,
    /// OK-ACCESS-KEY/SIGN/PASSPHRASE) on drop. `url` is base + path — no
    /// secret material — skip.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.body);
        for v in self.headers.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

// ── Sign phase ──

/// Map a sign-phase error `Response` (already status-mapped by
/// `error_response`) back to a coarse per-leg label. Approximate by design:
/// the full error body is available by probing the single-leg `/sign/*`
/// route; the hedge response only needs enough to say WHY nothing executed.
fn sign_error_label(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "bad_request",
        401 => "unauthorized",
        403 => "policy_denied",
        429 => "rate_limited",
        502 => "enclave_unreachable",
        _ => "sign_failed",
    }
}

async fn sign_leg(
    state: &AppState,
    customer_id: &str,
    raw_token: &str,
    leg: &HedgeLegSpec,
) -> Result<SignedLeg, StatusCode> {
    let venue = leg.venue();
    let key_id = leg.key_id.trim().to_ascii_lowercase();
    let payload = serde_json::json!({ "order": leg.order });
    match venue.as_str() {
        "binance" => {
            // `_receipt`: `sign_structured_request` has already archived this
            // leg's receipt, so the auditor path is whole — only the
            // client-held copy is skipped. The compound hedge response has no
            // per-leg receipt field, and inventing one here would ship a shape
            // the private tree does not have. A caller who needs the proof for
            // a hedge leg reads the counter heartbeat instead: both legs are
            // decisions, so `seq` moves by two.
            let (canonical, mut headers, _receipt) = sign_structured_request(
                state,
                customer_id,
                raw_token,
                &key_id,
                "sign_binance_order",
                "POST",
                "/fapi/v1/order",
                payload,
                // AF-2 v1 does NOT cover /hedge (compound two-leg path — a
                // follow-up needs a per-leg agent signature). With no intent
                // forwarded, a policy that opts into intent (`intent_pubkey`)
                // makes this leg fail CLOSED in the enclave (deny, not bypass):
                // AF-2 keys must use the single-order endpoints in v1.
                AgentIntentForward::default(),
            )
            .await
            .map_err(|resp| resp.status())?;
            let body = build_binance_signed_qs(&canonical, &mut headers).map_err(|detail| {
                warn!(event = "hedge_binance_assembly_failed", detail = %detail);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            headers.insert(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            );
            Ok(SignedLeg {
                venue: "binance",
                url: format!("{}/fapi/v1/order", binance_base_url()),
                headers,
                body,
            })
        }
        "okx" => {
            // `_receipt`: `sign_structured_request` has already archived this
            // leg's receipt, so the auditor path is whole — only the
            // client-held copy is skipped. The compound hedge response has no
            // per-leg receipt field, and inventing one here would ship a shape
            // the private tree does not have. A caller who needs the proof for
            // a hedge leg reads the counter heartbeat instead: both legs are
            // decisions, so `seq` moves by two.
            let (canonical, mut headers, _receipt) = sign_structured_request(
                state,
                customer_id,
                raw_token,
                &key_id,
                "sign_okx_order",
                "POST",
                "/api/v5/trade/order",
                payload,
                AgentIntentForward::default(), // AF-2 v1 excludes /hedge (see binance leg)
            )
            .await
            .map_err(|resp| resp.status())?;
            if okx_is_demo() {
                headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
            }
            headers.insert("Content-Type".to_owned(), "application/json".to_owned());
            Ok(SignedLeg {
                venue: "okx",
                url: format!("{}/api/v5/trade/order", okx_base_url()),
                headers,
                // THE LANDMINE (same as /sign/okx-order): `canonical` is the
                // exact byte-string the OK-ACCESS-SIGN HMAC committed to —
                // forwarded verbatim, never parse+re-stringify.
                body: canonical,
            })
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

// ── Execute phase ──

fn venue_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(VENUE_TIMEOUT_SECS))
            .user_agent(EXCHANGE_USER_AGENT)
            // No redirects: venues never legitimately redirect signed API
            // POSTs, and reqwest only strips Authorization/Cookie on a
            // cross-host hop — our custom X-MBX-APIKEY / OK-ACCESS-* headers
            // + signed body would be replayed to whatever Location says
            // (key exfiltration lever — adversarial review #6/#9). A 3xx now
            // surfaces as a non-2xx receipt instead.
            .redirect(reqwest::redirect::Policy::none())
            // Direct egress only: ignore HTTP(S)_PROXY/ALL_PROXY env. A
            // proxy var slipped into the unit env must not be able to route
            // (or selectively delay) the box's venue traffic (#11).
            .no_proxy()
            .build()
            // Builder only fails on TLS backend misconfig — unrecoverable at
            // runtime anyway, and this runs outside the enclave (no PCR0
            // implication). Fail loud at first use.
            .expect("reqwest client init")
    })
}

/// Which environment a leg actually targets — echoed in the receipt so a
/// mixed live/demo misconfig is visible to the caller, not just in env vars.
fn leg_env(venue: &str) -> Option<&'static str> {
    match venue {
        "binance" => Some(if binance_base_url().contains("testnet") {
            "testnet"
        } else {
            "live"
        }),
        "okx" => Some(if okx_is_demo() { "demo" } else { "live" }),
        _ => None,
    }
}

/// Venue-level classification of a parsed 2xx receipt.
///
/// Binance: error receipts are `{"code": <negative>, "msg": …}`; a success is
/// an order object. A synchronous `status` of EXPIRED/REJECTED (self-trade
/// prevention etc.) means NOTHING is resting or filled — that's a rejection,
/// not an accepted order (#2).
/// OKX: top-level `code` is the REQUEST-level result; the per-order verdict
/// is `data[0].sCode` — `code:"0"` with `sCode:"51008"` is a rejected order
/// and must not count as ok (#5).
fn classify_receipt(venue: &str, parsed: &serde_json::Value) -> LegOutcome {
    match venue {
        "binance" => {
            if matches!(
                parsed.get("code").and_then(serde_json::Value::as_i64),
                Some(c) if c < 0
            ) {
                return LegOutcome::Rejected;
            }
            match parsed.get("status").and_then(serde_json::Value::as_str) {
                Some("EXPIRED") | Some("REJECTED") | Some("EXPIRED_IN_MATCH") => {
                    LegOutcome::Rejected
                }
                _ => LegOutcome::Ok,
            }
        }
        "okx" => {
            if parsed.get("code").and_then(serde_json::Value::as_str) != Some("0") {
                return LegOutcome::Rejected;
            }
            let s_code = parsed
                .get("data")
                .and_then(|d| d.get(0))
                .and_then(|o| o.get("sCode"))
                .and_then(serde_json::Value::as_str);
            match s_code {
                None | Some("0") => LegOutcome::Ok,
                Some(_) => LegOutcome::Rejected,
            }
        }
        _ => LegOutcome::Rejected,
    }
}

/// Read the response body in chunks, hard-capped at `MAX_VENUE_BODY_BYTES`.
/// `resp.bytes()` would buffer an arbitrarily large venue/WAF body BEFORE any
/// size check (OOM lever — Gemini/CodeRabbit #152 round 2); streaming lets us
/// abort the read the moment the cap is crossed.
async fn read_capped_body(resp: &mut reqwest::Response) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > MAX_VENUE_BODY_BYTES {
                    return Err(format!(
                        "venue response exceeds {MAX_VENUE_BODY_BYTES} bytes — not an order receipt"
                    ));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(buf),
            Err(e) => return Err(format!("body read failed: {e}")),
        }
    }
}

fn leg_result(
    leg: &SignedLeg,
    outcome: LegOutcome,
    http_status: Option<u16>,
    response: Option<serde_json::Value>,
    error: Option<String>,
    duration_ms: u64,
) -> HedgeLegResult {
    HedgeLegResult {
        venue: leg.venue.to_owned(),
        phase: "signed",
        outcome,
        ok: outcome == LegOutcome::Ok,
        env: leg_env(leg.venue),
        http_status,
        response,
        error,
        duration_ms: Some(duration_ms),
    }
}

async fn execute_leg(mut leg: SignedLeg) -> HedgeLegResult {
    let started = Instant::now();
    let mut req = venue_client().post(&leg.url);
    for (k, v) in &leg.headers {
        req = req.header(k, v);
    }
    // Move the signed body into the request instead of cloning it — the only
    // long-lived copy of the secret-bearing bytes is the one reqwest sends.
    // (`Drop` on SignedLeg then zeroizes the leftover empty String + headers.)
    let body = std::mem::take(&mut leg.body);
    let outcome = req.body(body).send().await;
    let duration_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(mut resp) => {
            let http_status = resp.status().as_u16();
            let bytes = match read_capped_body(&mut resp).await {
                Ok(b) => b,
                // Status arrived but the receipt is unreadable — the order
                // reached the venue; its state is UNKNOWN, not rejected.
                Err(detail) => {
                    return leg_result(
                        &leg,
                        LegOutcome::Unknown,
                        Some(http_status),
                        None,
                        Some(detail),
                        duration_ms,
                    )
                }
            };
            // 5xx = venue-documented "execution status unknown — could have
            // been a success" (BLOCKER #1). 4xx = definitive rejection.
            if !(200..300).contains(&http_status) {
                let parsed = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
                let outcome = if http_status >= 500 {
                    LegOutcome::Unknown
                } else {
                    LegOutcome::Rejected
                };
                return leg_result(
                    &leg,
                    outcome,
                    Some(http_status),
                    parsed,
                    Some(format!("venue returned HTTP {http_status}")),
                    duration_ms,
                );
            }
            // Parse the FULL buffered body (truncating before parsing could
            // corrupt a legitimately large JSON receipt — Gemini #152).
            match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(parsed) => {
                    let outcome = classify_receipt(leg.venue, &parsed);
                    leg_result(
                        &leg,
                        outcome,
                        Some(http_status),
                        Some(parsed),
                        None,
                        duration_ms,
                    )
                }
                // Non-JSON 2xx from a JSON API = edge/WAF page. The request
                // made it THROUGH to something — state is unknown, never
                // fabricate a rejection (same doctrine as MCP bug #136).
                Err(_) => leg_result(
                    &leg,
                    LegOutcome::Unknown,
                    Some(http_status),
                    Some(serde_json::Value::String(
                        String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).into_owned(),
                    )),
                    Some("non-JSON venue response (edge/WAF block?)".to_owned()),
                    duration_ms,
                ),
            }
        }
        Err(e) => {
            // Connect-phase failures (TCP/TLS never established) are the one
            // transport error where the order definitively did NOT reach the
            // venue — safe to call rejected. Everything else (timeout after
            // the request was written, broken pipe mid-response) is UNKNOWN:
            // the matching engine may have the order (BLOCKER #1).
            let outcome = if e.is_connect() {
                LegOutcome::Rejected
            } else {
                LegOutcome::Unknown
            };
            // reqwest errors don't include response bodies; safe to echo.
            leg_result(
                &leg,
                outcome,
                None,
                None,
                Some(format!("venue call failed: {e}")),
                duration_ms,
            )
        }
    }
}

// ── Handler ──

/// Pre-sign shape validation. Returns a user-facing hint on rejection.
///
/// - exactly 2 legs;
/// - market-only in v1 (#2): a resting GTC limit leg would make
///   `status:"executed"` (= receipts accepted) read as "both legs live" while
///   one leg sits unfilled — restrict until fill-state inspection exists;
/// - no pure double-down (#15): same venue + same symbol + same side is not a
///   hedge, it's 2× the per-leg policy cap in one atomic call;
/// - env coherence (#4/#13): legs must not straddle live and demo/testnet —
///   a "hedge" of one REAL and one SIMULATED position is a naked live
///   position dressed as flat.
fn validate_hedge_shape(req: &HedgeRequest) -> Result<(), String> {
    if req.legs.len() != 2 {
        return Err("hedge requires exactly 2 legs".to_owned());
    }
    let (a, b) = (&req.legs[0], &req.legs[1]);
    for (i, leg) in [a, b].iter().enumerate() {
        if !leg.order.ord_type.trim().eq_ignore_ascii_case("market") {
            return Err(format!(
                "leg {} is ord_type={:?}: /hedge is market-only in v1 — a resting \
                 limit leg cannot be distinguished from a filled one yet",
                i + 1,
                leg.order.ord_type,
            ));
        }
    }
    if a.venue() == b.venue()
        && a.order.symbol == b.order.symbol
        && a.order.side.eq_ignore_ascii_case(&b.order.side)
    {
        return Err(
            "both legs are the same venue+symbol+side — that's a double-down, not a hedge"
                .to_owned(),
        );
    }
    let envs: Vec<Option<&'static str>> = [a, b].iter().map(|l| leg_env(&l.venue())).collect();
    if let (Some(ea), Some(eb)) = (envs[0], envs[1]) {
        let live_a = ea == "live";
        let live_b = eb == "live";
        if live_a != live_b {
            return Err(format!(
                "legs straddle environments ({ea} vs {eb}) — one REAL and one \
                 SIMULATED leg is a naked live position, not a hedge. Align \
                 SIGNER_BINANCE_ENV / SIGNER_OKX_ENV first.",
            ));
        }
    }
    Ok(())
}

pub async fn post_hedge(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<HedgeRequest>,
) -> Response {
    let started = Instant::now();
    info!(
        event = "hedge_received",
        legs = req.legs.len(),
        "POST /hedge"
    );

    if let Err(hint) = validate_hedge_shape(&req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "bad_request", "hint": hint })),
        )
            .into_response();
    }

    // B3 (б): a hedge places orders — ONE daily-counter increment per hedge
    // request (its two legs are each bounded by the enclave per-order caps;
    // operators size SIGNER_DAILY_ORDER_CAP accordingly). Fail-closed BEFORE
    // any leg is signed, so a denied hedge never half-signs. Shared gate runs
    // the file I/O on the blocking pool (Gemini #223).
    if let Some((resp, _code)) = crate::handlers::order_gate(&state, &raw_token).await {
        return resp;
    }

    // ── Sign phase: both legs concurrently, all-or-nothing. ──
    // Both legs sign under the SAME authenticated customer — a hedge is one
    // tenant's two-venue position, never a cross-tenant mix.
    let (sig_a, sig_b) = tokio::join!(
        sign_leg(&state, &customer, &raw_token, &req.legs[0]),
        sign_leg(&state, &customer, &raw_token, &req.legs[1])
    );
    let sign_ms = started.elapsed().as_millis() as u64;

    let sign_results = [&sig_a, &sig_b];
    if sign_results.iter().any(|r| r.is_err()) {
        let legs: Vec<HedgeLegResult> = req
            .legs
            .iter()
            .zip(sign_results.iter())
            .map(|(spec, res)| HedgeLegResult {
                venue: spec.venue(),
                phase: "sign_failed",
                outcome: LegOutcome::Rejected,
                ok: false,
                env: None,
                http_status: res.as_ref().err().map(|s| s.as_u16()),
                response: None,
                error: match res {
                    Err(s) => Some(sign_error_label(*s).to_owned()),
                    // The OTHER leg failed; this one signed fine but was
                    // deliberately not executed (all-or-nothing gate).
                    Ok(_) => Some("not_executed_peer_leg_failed".to_owned()),
                },
                duration_ms: None,
            })
            .collect();
        // Propagate the dominant failing status so single-leg probes and the
        // hedge route agree on semantics. Dominance is by meaning, not leg
        // order (CodeRabbit #152: a leg-1 400 must not mask a leg-2 403) —
        // policy_denied is the signal callers key their probes on.
        let failing: Vec<StatusCode> = sign_results
            .iter()
            .filter_map(|r| r.as_ref().err().copied())
            .collect();
        const DOMINANCE: [StatusCode; 5] = [
            StatusCode::FORBIDDEN,
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::BAD_REQUEST,
        ];
        let status = DOMINANCE
            .iter()
            .find(|d| failing.iter().any(|f| f == *d))
            .copied()
            .or_else(|| failing.first().copied())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        warn!(event = "hedge_sign_rejected", status = %status);
        return (
            status,
            Json(HedgeResponse {
                status: "rejected",
                legs,
                sign_ms,
                exec_ms: None,
            }),
        )
            .into_response();
    }
    // Both Ok — move out of the Results.
    let (leg_a, leg_b) = match (sig_a, sig_b) {
        (Ok(a), Ok(b)) => (a, b),
        _ => unreachable!("checked above"),
    };

    // ── Execute phase: parallel fire, per-leg truth. ──
    //
    // Detached spawn, NOT an inline join: the handler future is dropped by
    // hyper on client disconnect and by the 30s TimeoutLayer (main.rs). An
    // inline join cancelled in the window between the two sends would fire
    // exactly ONE leg and report it NOWHERE (adversarial review #3/#10).
    // The spawned task always runs to completion and logs per-leg truth on
    // the box even when nobody is left to receive the HTTP response.
    let exec_started = Instant::now();
    let exec_task = tokio::spawn(async move {
        let (res_a, res_b) = tokio::join!(execute_leg(leg_a), execute_leg(leg_b));
        let exec_ms = exec_started.elapsed().as_millis() as u64;
        let outcomes = [res_a.outcome, res_b.outcome];
        let status = if outcomes.contains(&LegOutcome::Unknown) {
            // Receipt-lost limbo dominates: the caller must reconcile order
            // state BEFORE any retry — a blind retry can double a live leg.
            "unknown"
        } else {
            match outcomes.iter().filter(|o| **o == LegOutcome::Ok).count() {
                2 => "executed",
                1 => "partial",
                _ => "failed",
            }
        };
        // Logged INSIDE the task so the box has the truth even if the
        // client is gone by now.
        info!(
            event = "hedge_finished",
            status,
            exec_ms,
            leg_a_venue = %res_a.venue,
            leg_a_outcome = ?res_a.outcome,
            leg_a_ms = res_a.duration_ms.unwrap_or(0),
            leg_b_venue = %res_b.venue,
            leg_b_outcome = ?res_b.outcome,
            leg_b_ms = res_b.duration_ms.unwrap_or(0),
        );
        (status, res_a, res_b, exec_ms)
    });
    let (status, res_a, res_b, exec_ms) = match exec_task.await {
        Ok(t) => t,
        Err(e) => {
            // JoinError = the exec task panicked. Orders may or may not be
            // live — report unknown, never fabricate a clean failure.
            warn!(event = "hedge_exec_join_error", error = %e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "internal_error",
                    "status": "unknown",
                    "hint": "execution state unknown — reconcile order state before retrying",
                })),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(HedgeResponse {
            status,
            legs: vec![res_a, res_b],
            sign_ms,
            exec_ms: Some(exec_ms),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_binance_negative_code_and_dead_statuses_are_rejected() {
        let err = serde_json::json!({"code": -1102, "msg": "Mandatory parameter"});
        assert_eq!(classify_receipt("binance", &err), LegOutcome::Rejected);
        let ok = serde_json::json!({"orderId": 14660118389_u64, "status": "NEW"});
        assert_eq!(classify_receipt("binance", &ok), LegOutcome::Ok);
        // Binance success receipts can carry a non-negative code-less shape;
        // a positive "code" (some list endpoints) must not be treated as err.
        let oddly_ok = serde_json::json!({"code": 200});
        assert_eq!(classify_receipt("binance", &oddly_ok), LegOutcome::Ok);
        // Synchronous EXPIRED/REJECTED = nothing resting or filled (#2).
        for dead in ["EXPIRED", "REJECTED", "EXPIRED_IN_MATCH"] {
            let receipt = serde_json::json!({"orderId": 1, "status": dead});
            assert_eq!(classify_receipt("binance", &receipt), LegOutcome::Rejected);
        }
        assert_eq!(
            classify_receipt(
                "binance",
                &serde_json::json!({"orderId": 1, "status": "FILLED"})
            ),
            LegOutcome::Ok
        );
    }

    #[test]
    fn classify_okx_checks_per_order_s_code_not_just_top_level() {
        assert_eq!(
            classify_receipt("okx", &serde_json::json!({"code": "0", "data": []})),
            LegOutcome::Ok
        );
        assert_eq!(
            classify_receipt(
                "okx",
                &serde_json::json!({"code": "51000", "msg": "param error"})
            ),
            LegOutcome::Rejected
        );
        // Numeric 0 (wrong type) must not pass — OKX always sends strings.
        assert_eq!(
            classify_receipt("okx", &serde_json::json!({"code": 0})),
            LegOutcome::Rejected
        );
        // Top-level code 0 but per-order sCode non-zero = rejected order (#5).
        assert_eq!(
            classify_receipt(
                "okx",
                &serde_json::json!({"code": "0", "data": [{"sCode": "51008", "ordId": ""}]})
            ),
            LegOutcome::Rejected
        );
        assert_eq!(
            classify_receipt(
                "okx",
                &serde_json::json!({"code": "0", "data": [{"sCode": "0", "ordId": "123"}]})
            ),
            LegOutcome::Ok
        );
    }

    #[test]
    fn classify_unknown_venue_never_ok() {
        assert_eq!(
            classify_receipt("kucoin", &serde_json::json!({"code": "0"})),
            LegOutcome::Rejected
        );
    }

    fn leg(venue: &str, symbol: &str, side: &str, ord_type: &str) -> HedgeLegSpec {
        HedgeLegSpec {
            key_id: venue.to_owned(),
            venue: None,
            order: OrderParams {
                symbol: symbol.to_owned(),
                side: side.to_owned(),
                qty: "1".to_owned(),
                ord_type: ord_type.to_owned(),
                price: None,
                reduce_only: false,
            },
        }
    }

    #[test]
    fn validate_rejects_limit_legs_market_only_v1() {
        let req = HedgeRequest {
            legs: vec![
                leg("binance", "BTCUSDT", "buy", "market"),
                leg("okx", "BTC-USDT-SWAP", "sell", "limit"),
            ],
        };
        let err = validate_hedge_shape(&req).unwrap_err();
        assert!(err.contains("market-only"), "{err}");
    }

    #[test]
    fn validate_rejects_pure_double_down() {
        let req = HedgeRequest {
            legs: vec![
                leg("binance", "BTCUSDT", "buy", "market"),
                leg("binance", "BTCUSDT", "BUY", "market"),
            ],
        };
        let err = validate_hedge_shape(&req).unwrap_err();
        assert!(err.contains("double-down"), "{err}");
    }

    #[test]
    fn validate_accepts_cross_venue_opposite_sides() {
        let req = HedgeRequest {
            legs: vec![
                leg("binance", "BTCUSDT", "buy", "market"),
                leg("okx", "BTC-USDT-SWAP", "sell", "market"),
            ],
        };
        // binance defaults to testnet + okx defaults to demo in tests (no
        // env vars set) — both non-live, so env coherence passes too.
        assert!(validate_hedge_shape(&req).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_leg_count() {
        let req = HedgeRequest {
            legs: vec![leg("binance", "BTCUSDT", "buy", "market")],
        };
        assert!(validate_hedge_shape(&req)
            .unwrap_err()
            .contains("exactly 2"));
    }

    #[test]
    fn sign_error_label_maps_policy_denied() {
        assert_eq!(sign_error_label(StatusCode::FORBIDDEN), "policy_denied");
        assert_eq!(sign_error_label(StatusCode::BAD_REQUEST), "bad_request");
        assert_eq!(sign_error_label(StatusCode::IM_A_TEAPOT), "sign_failed");
    }
}
