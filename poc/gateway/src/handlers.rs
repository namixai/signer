//! axum HTTP handlers for the signer gateway.
//!
//! Endpoints:
//!   - `POST /sign`      — main signing endpoint.
//!   - `GET  /healthz`   — liveness probe; succeeds if a vsock ping
//!     round-trip completes within ~1s.
//!
//! Both handlers go through `vsock::round_trip`. The gateway never touches
//! the secret directly — it forwards the encrypted blob and AWS creds to
//! the enclave and returns whatever the enclave produces.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::auth::{RawToken, ResolvedCustomer};
use crate::proto::{
    enclave_action_for, err_code, http_status_for, is_withdrawal_kind, timestamp_in_window,
    ErrorResponse, HealthResponse, HealthUnavailableResponse, SignDataHttpResponse,
    SignDataRequest, SignHttpRequest, SignHttpResponse, VerifyBlobRequest, VerifyBlobResponse,
    ALLOWED_EXCHANGES,
};
use crate::state::{blob_key, AppState, DATA_SIGNING_CUSTOMER, DATA_SIGNING_STEM};
use crate::vsock::{self, AwsCredentials, VsockRequest};

/// Wall-clock now in milliseconds since the Unix epoch. Used for both the
/// timestamp window check and the auto-fill on missing `timestamp_ms`.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Convert a wire error code to an axum `Response`. Centralizes the
/// status-mapping so handler bodies stay focused on the happy path.
/// A denial mapped from an ENCLAVE reply: `decided_by: enclave` plus the receipt
/// it came with (`receipts.rs`). Use at every site that maps an enclave code.
fn enclave_error_response(code: &str, receipt: Option<serde_json::Value>) -> Response {
    let status =
        StatusCode::from_u16(http_status_for(code)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(ErrorResponse::from_enclave(code, receipt))).into_response()
}

/// Take the enclave's receipt off a reply and archive it for `customer`.
///
/// The gateway is a courier and an archivist here, never an author: it cannot
/// mint a receipt, because the signing key lives only inside the enclave.
fn take_receipt(
    resp: &mut crate::vsock::VsockResponse,
    customer: &str,
) -> Option<serde_json::Value> {
    let receipt = resp.receipt.take();
    if let Some(r) = &receipt {
        crate::receipts::record(customer, r);
    }
    receipt
}

pub(crate) fn error_response(code: &str) -> Response {
    let status =
        StatusCode::from_u16(http_status_for(code)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(ErrorResponse::new(code))).into_response()
}

/// Order-placing gate: B3.1 orders-rate bucket + B3 daily order counter.
/// Called by every order-placing handler BEFORE the signing round-trip; see
/// `limits.rs` module doc for exactly which routes count as orders and why
/// cancels / reads / x402 deliberately do not. Returns the ready deny
/// `Response` + wire code (for `finish_log`) when the order must not be signed.
///
/// Order of checks (cheap → expensive): (1) B3.1 `orders_per_min` bucket —
/// in-memory, so a rate-denied order never touches the counter file; (2) B3
/// daily counter — synchronous file I/O (write-through + fsync), run on the
/// blocking pool via `spawn_blocking` (Gemini #223; not `block_in_place`, which
/// panics on a current-thread runtime, e.g. `#[tokio::test]`). A JoinError
/// (blocking task panicked) denies fail-closed. Both no-op when their bucket is
/// unconfigured (blanket mode: the orders-rate bucket is off and the blanket
/// middleware does the rate check instead).
pub(crate) async fn order_gate(
    state: &AppState,
    raw_token: &str,
) -> Option<(Response, &'static str)> {
    // (1) B3.1 orders-rate bucket (no-op unless SIGNER_ORDERS_PER_MIN set).
    let rate = state
        .limits
        .check_orders_rate(raw_token, crate::limits::now_unix_secs());
    if let Some(resp) = crate::limits::deny_response(rate) {
        return Some((resp, crate::limits::deny_code(rate)));
    }
    // (2) B3 daily counter. Fast path: not configured → no blocking work.
    if !state.limits.daily_enabled() {
        return None;
    }
    let limits = state.limits.clone();
    let token = raw_token.to_owned();
    let decision = match tokio::task::spawn_blocking(move || {
        limits.check_and_count_order(&token, crate::limits::now_unix_secs())
    })
    .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(event = "daily_counter_join_error", error = %e);
            crate::limits::LimitDecision::CounterUnavailable
        }
    };
    crate::limits::deny_response(decision).map(|r| (r, crate::limits::deny_code(decision)))
}

/// B3.1 cancel-path gate: the `cancels_per_min` bucket. Called by every
/// cancel handler. In-memory only (no daily counter for cancels — cancels
/// reduce exposure, never create it), so it's a sync fn. No-op unless
/// `SIGNER_CANCELS_PER_MIN` is set (blanket mode: the middleware rate-limits
/// cancels alongside everything else).
pub(crate) fn cancel_gate(state: &AppState, raw_token: &str) -> Option<(Response, &'static str)> {
    let decision = state
        .limits
        .check_cancels_rate(raw_token, crate::limits::now_unix_secs());
    crate::limits::deny_response(decision).map(|r| (r, crate::limits::deny_code(decision)))
}

/// H2: charge an x402 sign against the payer key's per-UTC-day CUMULATIVE spend
/// cap (CR096). `scope` = `blob_key(customer, key_id)` (the payer key); `value`
/// = the EIP-3009 transfer amount in raw token units. Returns
/// `Some((deny_response, code))` to short-circuit, or `None` to proceed. Runs
/// the fail-closed accumulator on the blocking pool (it fsyncs), mirroring
/// `order_gate`. Fast path: no blocking work when the cap is unconfigured.
pub(crate) async fn x402_spend_gate(
    state: &AppState,
    scope: &str,
    value: u128,
) -> Option<(Response, &'static str)> {
    if !state.limits.x402_spend_enabled() {
        return None;
    }
    let limits = state.limits.clone();
    let scope = scope.to_owned();
    let decision = match tokio::task::spawn_blocking(move || {
        limits.check_and_count_x402_spend(&scope, value, crate::limits::now_unix_secs())
    })
    .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(event = "x402_spend_join_error", error = %e);
            crate::limits::LimitDecision::CounterUnavailable
        }
    };
    crate::limits::deny_response(decision).map(|r| (r, crate::limits::deny_code(decision)))
}

/// `POST /sign` — request a fresh KuCoin v2 auth header set from the enclave.
pub async fn post_sign(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<SignHttpRequest>,
) -> Response {
    let started = Instant::now();
    let path_for_log = req.path.clone(); // path is not a secret; body is.
    let exchange_for_log = req.exchange.clone();
    let method_for_log = req.method.clone();
    // Tenant-scoped routing key: (authenticated customer) × (requested venue).
    // Used for BOTH the blob lookup and the circuit-breaker so neither leaks
    // across tenants. The customer comes ONLY from the bearer token, never the
    // request body (design §3 confused-deputy guard).
    let scope = blob_key(&customer, &req.exchange);

    info!(
        event = "request_received",
        exchange = %exchange_for_log,
        method = %method_for_log,
        path = %path_for_log,
        "POST /sign"
    );

    // 1. Validate the exchange.
    if !ALLOWED_EXCHANGES.contains(&req.exchange.as_str()) {
        return finish_log(
            error_response(err_code::BAD_REQUEST),
            started,
            false,
            Some(err_code::BAD_REQUEST),
        );
    }

    // 2. Resolve / validate the timestamp.
    let now = now_ms();
    let ts = match req.timestamp_ms {
        None => now,
        Some(client_ts) => {
            if timestamp_in_window(now, client_ts).is_err() {
                return finish_log(
                    error_response(err_code::BAD_REQUEST),
                    started,
                    false,
                    Some(err_code::BAD_REQUEST),
                );
            }
            client_ts
        }
    };

    // 3. Resolve the action + apply the cheap policy gates BEFORE any
    //    credential work (CodeRabbit #223: an already-capped/denied request
    //    must not drive IMDS/STS refresh traffic first).
    //
    // Withdrawal-class kinds are NEVER signable. The enclave only ever
    // signs order/cancel, so a fund-moving action is refused up-front as an
    // explicit POLICY_DENIED (403) — independent of venue — so a compromised
    // caller cannot even request a signature that would move funds out. This is
    // the custody moat surfaced as a policy denial, not a routing error.
    if is_withdrawal_kind(req.kind.as_deref()) {
        warn!(
            event = "withdrawal_kind_denied",
            exchange = %req.exchange,
            "withdrawal-class kind is never signable — policy_denied"
        );
        return finish_log(
            error_response(err_code::POLICY_DENIED),
            started,
            false,
            Some(err_code::POLICY_DENIED),
        );
    }

    // HMAC venues pass `kind = None` and resolve to a single action per
    // exchange. EIP-712 venues like `hyperliquid_main`/`hyperliquid_testnet`
    // look at `kind` to pick `order` vs `cancel` — a missing/unknown (non-
    // withdrawal) kind returns BAD_REQUEST because the request truly is
    // malformed (we can't sign without knowing which action to commit to).
    let action = match enclave_action_for(&req.exchange, req.kind.as_deref()) {
        Some(a) => a,
        None if matches!(
            req.exchange.as_str(),
            "hyperliquid_main" | "hyperliquid_testnet"
        ) =>
        {
            // EIP-712 venue with missing/unsupported kind — caller error.
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
        None => {
            // ALLOWED_EXCHANGES already validated, this is an internal bug.
            warn!(
                event = "exchange_routing_missing",
                exchange = %req.exchange,
                "exchange in allow-list but no action mapping"
            );
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    // Per-tenant kill switch, body half. The path-classified middleware let
    // `/sign` through in CANCEL_ONLY because the class lives in `kind`; now that
    // the action is known, settle it. HL `*_order` is an order; HL `*_cancel`
    // reduces exposure; an OPAQUE HMAC body (kind=None) is unclassifiable here
    // and could place an order → denied in CANCEL_ONLY (fail-closed). HALTED
    // never reaches this point (middleware denies).
    {
        use crate::tenant_state::RouteClass;
        let class = if action.ends_with("_order") {
            RouteClass::Order
        } else if action.ends_with("_cancel") {
            RouteClass::Cancel
        } else {
            RouteClass::Unknown
        };
        if let Some((resp, code)) = crate::tenant_state::body_route_gate(&state, &customer, class) {
            return finish_log(resp, started, false, Some(code));
        }
    }

    // B3 (б): Hyperliquid ORDER actions place orders through this generic
    // route — count them against the per-token daily cap. Explicit action
    // list (not a suffix match): enclave-vouched constants from
    // `enclave_action_for`, and a new order-shaped action must consciously
    // opt in here. Cancels, reads and opaque HMAC-venue bodies are NOT
    // counted (see `limits.rs` module doc for the full rationale). Runs
    // before the creds fetch and the blob lookup — attempt-counted at the
    // earliest point the action is known.
    if matches!(
        action,
        "sign_hyperliquid_main_order" | "sign_hyperliquid_testnet_order"
    ) {
        if let Some((resp, code)) = order_gate(&state, &raw_token).await {
            return finish_log(resp, started, false, Some(code));
        }
    }
    // B3.1: Hyperliquid CANCEL actions → cancels-rate bucket (split mode).
    // No daily counter for cancels (exposure-reducing).
    if matches!(
        action,
        "sign_hyperliquid_main_cancel" | "sign_hyperliquid_testnet_cancel"
    ) {
        if let Some((resp, code)) = cancel_gate(&state, &raw_token) {
            return finish_log(resp, started, false, Some(code));
        }
    }

    // 4. Pull a fresh STS-credential copy from the cache (refreshes from
    //    IMDS if expired). On failure surface as internal_error — we never
    //    leak whether IMDS is the cause.
    let creds = match state.creds.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(event = "imds_creds_unavailable", error = %e);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    let blob = match state.blobs.get(&scope) {
        Some(b) => b,
        None => {
            // Operator did not stage a blob for this (customer, exchange).
            // Surface as bad_request so the caller knows it is not configured
            // on this gateway, but don't say WHY (operational detail). Crucially
            // there is NO fall-through to another customer's blob.
            warn!(
                event = "exchange_blob_missing",
                exchange = %req.exchange
            );
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };

    // 5. Route the query string. Three regimes:
    //    - KuCoin: signs `timestamp + METHOD + path + body` and ignores
    //      query string entirely. Pass path through, no query forwarding.
    //    - Binance/Bybit: sign `query + body` (Binance) or
    //      `ts + key + recv + (query | body)` (Bybit). Either flavour
    //      needs the query string FORWARDED SEPARATELY to the enclave so
    //      the canonical-string assembly is unambiguous.
    //    - OKX: signs `ts + METHOD + requestPath + body` where requestPath
    //      INCLUDES the query string. The enclave's handle_sign_okx merges
    //      a separate `query` field back into requestPath, so the gateway
    //      can forward query exactly the same way as Binance/Bybit and the
    //      enclave will reconstruct the canonical string correctly.
    let (path_for_enclave, query_for_enclave) = match req.exchange.as_str() {
        "binance" | "binance_futures" | "bybit" | "okx" => {
            // Prefer explicit query field; otherwise extract from path.
            let (path_only, q_from_path) = if let Some(q_idx) = req.path.find('?') {
                (
                    req.path[..q_idx].to_owned(),
                    req.path[q_idx + 1..].to_owned(),
                )
            } else {
                (req.path.clone(), String::new())
            };
            let merged_query = match req.query.as_deref() {
                Some(q) if !q.is_empty() => {
                    if q_from_path.is_empty() {
                        q.to_owned()
                    } else {
                        format!("{}&{}", q_from_path, q)
                    }
                }
                _ => q_from_path,
            };
            (path_only, Some(merged_query))
        }
        _ => (req.path.clone(), None),
    };

    // 6. Build the vsock request.
    let vsock_req = VsockRequest {
        action: action.to_owned(),
        method: Some(req.method.clone()),
        path: Some(path_for_enclave),
        body: Some(req.body.clone()),
        timestamp_ms: Some(ts),
        aws_credentials: Some(AwsCredentials {
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
        }),
        ciphertext_blob_base64: Some(B64.encode(blob.ciphertext.as_slice())),
        proto_version: 1,
        op: None,
        payload: None,
        opaque_token: Some(raw_token.to_owned()),
        key_blob_s3_key: Some(format!("secrets/{}.enc", req.exchange)),
        query: query_for_enclave,
        hl_action: req.action.clone(),
        nonce: req.nonce,
        vault_address: req.vault_address.clone(),
        x402: None,
        order: None,
        cancel: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };

    // 6b. Adaptive backoff check — reject early if circuit is open.
    // Keyed by the tenant-scoped `scope` so one customer's failures don't
    // trip the breaker for the same venue on other customers.
    if !state.backoff.allow(&scope) {
        warn!(
            event = "backoff_rejected",
            exchange = %exchange_for_log,
        );
        return finish_log(
            error_response(err_code::RATE_LIMITED),
            started,
            false,
            Some(err_code::RATE_LIMITED),
        );
    }

    // 7. Round-trip to the enclave over vsock.
    let vsock_started = Instant::now();
    let resp = vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await;
    let vsock_latency_ms = vsock_started.elapsed().as_millis() as u64;

    let mut resp = match resp {
        Ok(r) => r,
        Err(e) => {
            // Don't echo the underlying anyhow chain to logs — it can
            // contain socket details. Just the variant label.
            warn!(
                event = "vsock_call",
                latency_ms = vsock_latency_ms,
                success = false,
                error_code = "enclave_unreachable",
                detail = %e
            );
            return finish_log(
                error_response(err_code::ENCLAVE_UNREACHABLE),
                started,
                false,
                Some(err_code::ENCLAVE_UNREACHABLE),
            );
        }
    };

    // 8. Translate the enclave's response into HTTP shape. The decision
    //    receipt (if the enclave issued one) rides along on BOTH branches and
    //    is archived either way.
    let receipt = take_receipt(&mut resp, &customer);
    if let Some(code) = resp.error.as_deref() {
        info!(
            event = "enclave_response",
            success = false,
            error_code = code,
            vsock_latency_ms = vsock_latency_ms
        );
        // CR037: coerce to the allow-listed wire surface. Any future
        // enclave-side err_code that isn't explicitly in WIRE_OK_ERROR_CODES
        // collapses to `internal_error` with a warn log — forces Security
        // review on PRs that add new codes.
        let mapped = crate::proto::safe_wire_code(code);
        if mapped == err_code::RATE_LIMITED {
            state.backoff.report_rate_limited(&scope);
        }
        return finish_log(
            enclave_error_response(mapped, receipt),
            started,
            false,
            Some(mapped),
        );
    }

    // Phase 1 Stage 2 — split success path: EIP-712 venues populate
    // `hl_signature`; HMAC venues populate `headers`. Either one (but not
    // both) must be set for a successful response.
    // C21 (Gemini PR #30 round-1): VsockResponse now ZeroizeOnDrop, which
    // blocks partial moves out of fields. Use std::mem::take to swap each
    // String out with a default-empty so the wipe-on-drop still runs over
    // the now-emptied struct shell. The taken Strings are passed by value
    // into HlSignatureWire which sits in the HTTP response.
    if let Some(mut sig) = resp.hl_signature.take() {
        state.backoff.report_success(&scope);
        info!(
            event = "enclave_response",
            success = true,
            vsock_latency_ms,
            shape = "eip712"
        );
        let http_sig = crate::proto::HlSignatureWire {
            r: std::mem::take(&mut sig.r),
            s: std::mem::take(&mut sig.s),
            v: sig.v,
        };
        return finish_log(
            (
                StatusCode::OK,
                Json(SignHttpResponse {
                    headers: std::collections::BTreeMap::new(),
                    signature: Some(http_sig),
                    receipt,
                }),
            )
                .into_response(),
            started,
            true,
            None,
        );
    }

    let headers = match resp.headers.take() {
        Some(h) => h,
        None => {
            warn!(
                event = "enclave_response",
                success = false,
                error_code = "internal_error",
                reason = "no headers in success response"
            );
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    state.backoff.report_success(&scope);
    info!(
        event = "enclave_response",
        success = true,
        vsock_latency_ms,
        header_count = headers.len()
    );
    finish_log(
        (
            StatusCode::OK,
            Json(SignHttpResponse {
                headers,
                signature: None,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// `GET /healthz` — return 200 if a vsock ping completes; 503 otherwise.
///
/// We keep this distinct from `/sign` so a load balancer probing health
/// doesn't decrypt the blob or burn a KMS call per check.
/// Short commit SHA this binary was built from, or `"unknown"`.
///
/// Read at COMPILE time, deliberately not at run time: a run-time lookup would
/// report whichever tree happens to sit next to the binary, which is exactly the
/// confusion this is meant to end. An undeclared build says `"unknown"` rather
/// than guessing — a wrong build id is worse than an absent one, because it
/// would be believed.
fn build_sha() -> &'static str {
    valid_build_sha(option_env!("SIGNER_BUILD_SHA"))
}

/// The SHAPE gate for `build_sha()`, split out so it can be tested — the value
/// itself arrives at compile time and cannot be varied from a test.
///
/// The vocabulary here is as closed as `build_source()`'s, and for the same
/// reason: `/healthz` promises a short commit SHA or `"unknown"`, so a branch
/// name, a stray newline from a CI expansion, or `main` must NOT come out
/// looking like an answer. A reader would take `main` for a build id and go
/// looking for a commit that does not exist. Earlier this function accepted any
/// non-empty string — the discipline was applied to `build_source()` right
/// below and not to its neighbour (CodeRabbit, #73, raised twice).
///
/// Accepted: 7..=40 lowercase hex characters — `git rev-parse --short` at any
/// abbreviation length, up to a full SHA-1. Anything else is `"unknown"`.
fn valid_build_sha(raw: Option<&'static str>) -> &'static str {
    match raw {
        Some(s)
            if (7..=40).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            s
        }
        _ => "unknown",
    }
}

/// Which repository `build_sha()` belongs to. See `HealthResponse::source`.
///
/// The vocabulary is CLOSED: anything outside it becomes `"unknown"`. A typo
/// like `publics` must not reach `/healthz` looking like a meaningful answer —
/// a reader would take it for a third kind of tree rather than a mistake.
fn build_source() -> &'static str {
    match option_env!("SIGNER_BUILD_SOURCE") {
        Some("public") => "public",
        Some("internal") => "internal",
        _ => "unknown",
    }
}

pub async fn get_healthz(State(state): State<AppState>) -> Response {
    let req = VsockRequest {
        action: "ping".to_owned(),
        method: None,
        path: None,
        body: None,
        timestamp_ms: None,
        aws_credentials: None,
        ciphertext_blob_base64: None,
        proto_version: 1,
        op: None,
        payload: None,
        opaque_token: None,
        key_blob_s3_key: None,
        query: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: None,
        cancel: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };
    // E3: publish live-signature health (from the periodic self-sign probe)
    // alongside the vsock liveness. Read lock-free; does NOT affect the 200/503.
    let now_s = now_ms() / 1000;
    let sh = &state.sign_health;
    let sign_checked = sh.is_enabled();
    let sign_ok = sh.last_ok();
    let sign_age_s = sh.age_since_ok(now_s);

    match vsock::round_trip(state.enclave.cid, state.enclave.port, &req).await {
        Ok(resp) if resp.signature_base64 == "pong" && resp.error.is_none() => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                build: build_sha(),
                source: build_source(),
                enclave_cid: state.enclave.cid,
                enclave_port: state.enclave.port,
                sign_checked,
                sign_ok,
                sign_age_s,
            }),
        )
            .into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthUnavailableResponse {
                error: err_code::ENCLAVE_UNREACHABLE,
                build: build_sha(),
                source: build_source(),
            }),
        )
            .into_response(),
    }
}

/// `POST /verify-blob` — Path B-lite Stage 4 pre-flight verification.
///
/// Forwards a single venue's encrypted blob to the enclave with action
/// `verify_blob`. The enclave decrypts under KMS+attestation, computes
/// SHA-256 of the plaintext, zeroizes the plaintext on drop, and returns
/// the hex hash. The gateway never sees the plaintext — only the hash.
///
/// Operator workflow: invoke once per venue (script wrapper iterates the
/// 6 Phase 0 venues), confirm every venue returns `ok: true`, then
/// proceed with the Stage 4 rewrap cutover.
pub async fn post_verify_blob(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<VerifyBlobRequest>,
) -> Response {
    let started = Instant::now();
    let venue_for_log = req.venue_id.clone();
    let scope = blob_key(&customer, &req.venue_id);

    info!(
        event = "verify_blob_received",
        venue_id = %venue_for_log,
        "POST /verify-blob"
    );

    // 1. Validate the venue against the same allowlist as `/sign`.
    if !ALLOWED_EXCHANGES.contains(&req.venue_id.as_str()) {
        return finish_log(
            error_response(err_code::BAD_REQUEST),
            started,
            false,
            Some(err_code::BAD_REQUEST),
        );
    }

    // 2. Look up the loaded blob bundle for this (customer, venue).
    let blob = match state.blobs.get(&scope) {
        Some(b) => b,
        None => {
            warn!(
                event = "verify_blob_no_blob",
                venue_id = %venue_for_log,
            );
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };

    // 3. Acquire fresh AWS creds (same path as /sign).
    let creds = match state.creds.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(event = "verify_blob_creds_failed", detail = %e);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    // 4. Build the vsock request — same shape as a sign request but
    //    with action="verify_blob". PR-B: the enclave now derives the target
    //    venue from `path` to build the KMS EncryptionContext + sealed AAD and
    //    to ACL-check the resolved operator identity, so we MUST forward the
    //    venue here (a `None` path resolves to venue="" and fails ACL closed,
    //    breaking 100% of verify_blob calls — the Stage-4 pre-flight).
    let vsock_req = VsockRequest {
        action: "verify_blob".to_owned(),
        method: None,
        path: Some(req.venue_id.clone()),
        body: None,
        timestamp_ms: Some(now_ms()),
        aws_credentials: Some(AwsCredentials {
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
        }),
        ciphertext_blob_base64: Some(B64.encode(blob.ciphertext.as_slice())),
        proto_version: 1,
        op: None,
        payload: None,
        opaque_token: Some(raw_token.to_owned()),
        key_blob_s3_key: Some(format!("secrets/{}.enc", req.venue_id)),
        query: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: None,
        cancel: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };

    // 5. Round-trip to the enclave.
    let vsock_started = Instant::now();
    let resp = vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await;
    let vsock_latency_ms = vsock_started.elapsed().as_millis() as u64;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(
                event = "verify_blob_vsock_failed",
                latency_ms = vsock_latency_ms,
                detail = %e,
            );
            return finish_log(
                error_response(err_code::ENCLAVE_UNREACHABLE),
                started,
                false,
                Some(err_code::ENCLAVE_UNREACHABLE),
            );
        }
    };

    // 6. Translate enclave response to HTTP.
    if let Some(code) = resp.error.as_deref() {
        // CR037: gateway-side allow-list. The enclave-side handle_verify_blob
        // already collapsed kms_decrypt_denied / internal_error / post-KMS
        // bad_request into `verify_failed` per CR035; here we also guard
        // against any future enclave code that might slip through without
        // a Security review. Granular internal_code stays in the log.
        let mapped = crate::proto::safe_wire_code(code);
        warn!(
            event = "verify_blob_enclave_error",
            venue_id = %venue_for_log,
            internal_code = code,
            wire_code = mapped,
            vsock_latency_ms,
        );
        return finish_log(error_response(mapped), started, false, Some(mapped));
    }

    // VsockResponse implements Drop (zeroize) so we cannot move fields out —
    // borrow + clone the hash; the response is wiped on drop at end of fn.
    let sha256 = match resp.plaintext_sha256.as_deref() {
        Some(h) if h.len() == 64 => h.to_owned(),
        _ => {
            warn!(
                event = "verify_blob_missing_sha256",
                venue_id = %venue_for_log,
            );
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    // Emit epoch milliseconds — operator-side script (verify-all-blobs.sh)
    // formats human-readable timestamps with `date`. Avoids pulling in
    // chrono/time for one timestamp field.
    let decrypted_at_epoch_ms = now_ms();

    info!(
        event = "verify_blob_ok",
        venue_id = %venue_for_log,
        plaintext_sha256 = %sha256,
        vsock_latency_ms,
    );

    finish_log(
        (
            StatusCode::OK,
            Json(VerifyBlobResponse {
                ok: true,
                venue_id: req.venue_id,
                plaintext_sha256: sha256,
                // Gemini round-1 MED: enclave now surfaces plaintext_len
                // via the SignResponse wire shape — forward it through.
                plaintext_len: resp.plaintext_len,
                decrypted_at_epoch_ms,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// `POST /sign-data` — attested-signed-data (P2), OPERATOR-gated.
///
/// Signs a raw read-only market-data payload with the dedicated data-signing
/// key inside the enclave and returns `{signature, pubkey_compressed,
/// pubkey_address}`. Layer-1 isolation: this lives in the operator router, so a
/// tenant token (which reaches the `/sign` venues) is 401 here and an operator
/// token is 401 on those venues. Layer-2: the forwarded DATA-SIGNING service
/// token resolves in the enclave to the `attested-data` identity whose KMS
/// EncryptionContext is the ONLY one that decrypts the data-key blob (§5).
///
/// The operator credential gates WHO may call this; `state.data_signing_token`
/// selects WHICH key. The `data` payload is forwarded VERBATIM — the gateway
/// never parses it — so the enclave's dup-key rejection and the buyer's
/// byte-exact canonical recompute both see the producer's original bytes.
pub async fn post_sign_data(
    State(state): State<AppState>,
    Json(req): Json<SignDataRequest>,
) -> Response {
    let started = Instant::now();

    // The data-signing service token must be configured (key provisioned).
    let data_token = match state.data_signing_token.as_deref() {
        Some(t) => t,
        None => {
            warn!(
                event = "sign_data_not_provisioned",
                "SIGNER_DATA_SIGNING_TOKEN unset"
            );
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    // Shape guard. The enclave is authoritative for the 32 KiB cap + the
    // dup-key / numbers-forbidden / JCS rules; an empty body is never valid.
    if req.data.trim().is_empty() {
        return finish_log(
            error_response(err_code::BAD_REQUEST),
            started,
            false,
            Some(err_code::BAD_REQUEST),
        );
    }

    // Stage the service-owned data-key blob from the attested-data namespace.
    let scope = blob_key(DATA_SIGNING_CUSTOMER, DATA_SIGNING_STEM);
    let blob = match state.blobs.get(&scope) {
        Some(b) => b,
        None => {
            warn!(event = "sign_data_no_blob", "data-signing blob not loaded");
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    let creds = match state.creds.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(event = "sign_data_creds_failed", detail = %e);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    let vsock_req = VsockRequest {
        action: "sign_data".to_owned(),
        method: None,
        path: None,
        body: None,
        timestamp_ms: Some(now_ms()),
        aws_credentials: Some(AwsCredentials {
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
        }),
        ciphertext_blob_base64: Some(B64.encode(blob.ciphertext.as_slice())),
        proto_version: 1,
        op: None,
        payload: None,
        // NOT the operator's gateway credential — the enclave-registry token that
        // resolves to the `attested-data` data-signing identity (§5).
        opaque_token: Some(data_token.to_owned()),
        key_blob_s3_key: Some(format!(
            "secrets/{}/{}.enc",
            DATA_SIGNING_CUSTOMER, DATA_SIGNING_STEM
        )),
        query: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: None,
        cancel: None,
        // Forwarded VERBATIM (raw JSON text) — the enclave parses + canonicalizes.
        data: Some(req.data),
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };

    let vsock_started = Instant::now();
    let resp = vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await;
    let vsock_latency_ms = vsock_started.elapsed().as_millis() as u64;

    let mut resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(event = "sign_data_vsock_failed", latency_ms = vsock_latency_ms, detail = %e);
            return finish_log(
                error_response(err_code::ENCLAVE_UNREACHABLE),
                started,
                false,
                Some(err_code::ENCLAVE_UNREACHABLE),
            );
        }
    };

    if let Some(code) = resp.error.as_deref() {
        let mapped = crate::proto::safe_wire_code(code);
        warn!(
            event = "sign_data_enclave_error",
            internal_code = code,
            wire_code = mapped,
            vsock_latency_ms,
        );
        return finish_log(error_response(mapped), started, false, Some(mapped));
    }

    // Success: move the signature + pubkey out of the zeroizing VsockResponse via
    // std::mem::take (it implements Drop, blocking partial moves) so the wipe
    // still runs over the emptied shell.
    let mut attested = match resp.attested.take() {
        Some(a) => a,
        None => {
            warn!(
                event = "sign_data_missing_attested",
                "enclave ok but no attested payload"
            );
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };
    let signature = crate::proto::HlSignatureWire {
        r: std::mem::take(&mut attested.signature.r),
        s: std::mem::take(&mut attested.signature.s),
        v: attested.signature.v,
    };
    info!(
        event = "sign_data_ok",
        vsock_latency_ms, "attested-data signed"
    );
    finish_log(
        (
            StatusCode::OK,
            Json(SignDataHttpResponse {
                signature,
                pubkey_compressed: std::mem::take(&mut attested.pubkey_compressed),
                pubkey_address: std::mem::take(&mut attested.pubkey_address),
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// `POST /sign-x402` — sign an x402 / EIP-3009 `TransferWithAuthorization`.
/// Thin wrapper over the enclave `sign_x402_eip3009` action (PR #74), mirroring
/// `/verify-blob`: no exchange/method/path merging — the x402 params travel as
/// a typed object. The enclave enforces the policy cap + `from == signing-key`.
pub async fn post_sign_x402(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<crate::proto::SignX402Request>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "sign_x402_received", key_id = %key_for_log, "POST /sign-x402");
    // F1: constrain the caller-supplied key_id before it becomes a blob-key
    // half and an enclave-side namespace label.
    if !is_safe_key_id(&req.key_id) {
        warn!(event = "sign_x402_bad_key_id", key_id = %key_for_log);
        return finish_log(
            error_response(err_code::BAD_REQUEST),
            started,
            false,
            Some(err_code::BAD_REQUEST),
        );
    }
    let scope = blob_key(&customer, &req.key_id);

    // 1. Look up the provisioned payer-key blob for this (customer, key_id).
    //    (x402 keys are not trading venues, so they are NOT gated by
    //    ALLOWED_EXCHANGES — only "is this a key the gateway loaded for this
    //    customer".)
    let blob = match state.blobs.get(&scope) {
        Some(b) => b,
        None => {
            warn!(event = "sign_x402_no_blob", key_id = %key_for_log);
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };

    // 1b. H2 (CR096): charge this transfer against the payer key's per-UTC-day
    //     CUMULATIVE spend cap BEFORE any KMS/enclave work — an already-capped
    //     key must not drive IMDS/STS (parity with `order_gate`). `value` is raw
    //     token units; a value the enclave would itself reject (non-numeric or
    //     wider than u128) fails closed here as a bad request. Attempt-counted:
    //     the charge persists before the signature, so a retry can't over-spend.
    let x402_value: u128 = match req.x402.value.trim().parse() {
        Ok(v) => v,
        Err(_) => {
            warn!(event = "sign_x402_bad_value", key_id = %key_for_log);
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };
    if let Some((resp, code)) = x402_spend_gate(&state, &scope, x402_value).await {
        return finish_log(resp, started, false, Some(code));
    }

    // 2. Fresh AWS creds (same path as /sign, /verify-blob).
    let creds = match state.creds.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(event = "sign_x402_creds_failed", detail = %e);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    // 3. Forward the x402 params verbatim as an opaque object — the enclave
    //    re-deserializes into its typed, deny_unknown_fields `X402Request`.
    let x402_value = match serde_json::to_value(&req.x402) {
        Ok(v) => v,
        Err(_) => {
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            )
        }
    };

    let vsock_req = VsockRequest {
        action: "sign_x402_eip3009".to_owned(),
        method: None,
        path: None,
        body: None,
        timestamp_ms: Some(now_ms()),
        aws_credentials: Some(AwsCredentials {
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
        }),
        ciphertext_blob_base64: Some(B64.encode(blob.ciphertext.as_slice())),
        proto_version: 1,
        op: None,
        payload: None,
        opaque_token: Some(raw_token.to_owned()),
        key_blob_s3_key: Some(format!("secrets/{}.enc", req.key_id)),
        query: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: Some(x402_value),
        order: None,
        cancel: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };

    // 3b. Adaptive backoff (CodeRabbit #75 Major: parity with /sign) — reject
    //     early if this key's circuit is open, so x402 gets the same KMS-throttle
    //     protection as the HMAC sign path.
    if !state.backoff.allow(&scope) {
        warn!(event = "sign_x402_backoff_rejected", key_id = %key_for_log);
        return finish_log(
            error_response(err_code::RATE_LIMITED),
            started,
            false,
            Some(err_code::RATE_LIMITED),
        );
    }

    // 4. Round-trip to the enclave.
    let vsock_started = Instant::now();
    let resp = vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await;
    let vsock_latency_ms = vsock_started.elapsed().as_millis() as u64;

    let mut resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(event = "sign_x402_vsock_failed", latency_ms = vsock_latency_ms, detail = %e);
            return finish_log(
                error_response(err_code::ENCLAVE_UNREACHABLE),
                started,
                false,
                Some(err_code::ENCLAVE_UNREACHABLE),
            );
        }
    };

    // 5. Errors → allow-listed wire surface (CR037/CR049 parity with /sign).
    let receipt = take_receipt(&mut resp, &customer);
    if let Some(code) = resp.error.as_deref() {
        let mapped = crate::proto::safe_wire_code(code);
        if mapped == err_code::RATE_LIMITED {
            state.backoff.report_rate_limited(&scope);
        }
        warn!(
            event = "sign_x402_enclave_error",
            key_id = %key_for_log,
            internal_code = code,
            wire_code = mapped,
            vsock_latency_ms,
        );
        return finish_log(
            enclave_error_response(mapped, receipt),
            started,
            false,
            Some(mapped),
        );
    }

    // 6. Success: the enclave returns signature + payer address via headers.
    //    `take()` so the ZeroizeOnDrop response wipes its shell on drop; then
    //    MOVE the values out via `remove` (not clone) and zeroize any leftover
    //    header values we moved into this plain map (Gemini #75 HIGH).
    let mut headers = resp.headers.take().unwrap_or_default();
    let signature = headers.remove("signature");
    let from = headers.remove("from");
    for v in headers.values_mut() {
        zeroize::Zeroize::zeroize(v);
    }
    let (Some(signature), Some(from)) = (signature, from) else {
        warn!(event = "sign_x402_missing_signature", key_id = %key_for_log);
        return finish_log(
            error_response(err_code::INTERNAL_ERROR),
            started,
            false,
            Some(err_code::INTERNAL_ERROR),
        );
    };

    state.backoff.report_success(&scope);
    info!(event = "sign_x402_ok", key_id = %key_for_log, vsock_latency_ms);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignX402Response {
                ok: true,
                signature,
                from,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

// ─────────────────────────────────────────────────────────────────────────
// /sign/binance-order + /sign/binance-cancel (Option A per-venue trade signing).
//
// Pattern:
//   1. MCP POSTs structured order/cancel params + key_id.
//   2. Gateway forwards them opaquely to the enclave's `sign_binance_order` /
//      `sign_binance_cancel` actions; the enclave applies the policy `order_caps`,
//      builds the form-urlencoded canonical INSIDE itself (asterdex-T1 rule),
//      and signs it. Returns the canonical (without `&signature=`) in
//      `canonical_body` + the HMAC sig / X-MBX-APIKEY / ts / recvWindow in
//      `headers`.
//   3. Gateway assembles the wire shape: for POST order, body =
//      `canonical_body + "&timestamp=…&recvWindow=…&signature=<hex>"`; for
//      DELETE cancel, URL = `base + path + "?" + that same final querystring`.
//   4. MCP submits to the venue.
//
// Per-period rate caps are DEFERRED + DOCUMENTED (see `Policy.order_caps` doc
// in enclave/proto.rs). v0 enforces per-asset / per-signature only.
//
// `binance_base_url` is defined in the /account block below (shared with
// `/account/binance`); we reuse it here to avoid drift.
// ─────────────────────────────────────────────────────────────────────────

/// Inner helper for venue-structured signing (Binance + OKX, order + cancel).
/// Forwards the structured request to the enclave action, returns
/// `(canonical_body, headers)` or a ready error response. Concentrates blob
/// lookup / backoff / creds / vsock
/// / safe_wire_code mapping so the two thin route handlers can focus on the
/// venue-wire assembly. Action is `"sign_binance_order"` or `"_cancel"`.
///
/// Gemini #78 fix: forward the venue-canonical `method` + `path` to the
/// enclave so `enforce_policy` can check them. Passing `None` made the
/// trade-signing path bypass UPL method/path restrictions — a hole in the
/// core policy enforcement that is the signer's whole value prop.
/// AF-2 pass-through bundle: the agent-authored fields the gateway forwards
/// verbatim to the enclave for order-intent verification. All `None` when the
/// client did not supply them (opt-in-absent — the enclave then falls back to
/// the pre-AF-2 cap-only posture).
#[derive(Default)]
pub(crate) struct AgentIntentForward {
    pub timestamp_ms: Option<u64>,
    pub intent_signature: Option<String>,
    pub intent_nonce: Option<String>,
}

#[allow(clippy::result_large_err)] // Response is the canonical wire type.
#[allow(clippy::too_many_arguments)] // request-context threading (PR-B raw_token)
pub(crate) async fn sign_structured_request(
    state: &AppState,
    customer_id: &str,
    raw_token: &str,
    key_id: &str,
    action: &str,
    method: &str,
    path: &str,
    structured: serde_json::Value, // either {"order": {...}} or {"cancel": {...}}
    // AF-2: the agent-authored timestamp (bound into the signed intent — the
    // gateway MUST forward it verbatim, not stamp its own `now_ms()`, or the
    // enclave's intent reconstruction would diverge) + the agent signature and
    // (cancel-only) replay nonce. All `None` for non-AF-2 (opt-in-absent) calls.
    intent: AgentIntentForward,
) -> Result<
    (
        String,
        std::collections::BTreeMap<String, String>,
        Option<serde_json::Value>,
    ),
    Response,
> {
    // F1: constrain key_id (venue stem) before it becomes a blob-key half and
    // an enclave-side namespace label.
    if !is_safe_key_id(key_id) {
        warn!(event = "structured_sign_bad_key_id", key_id = %key_id);
        return Err(error_response(err_code::BAD_REQUEST));
    }
    // Tenant-scoped routing key — blob lookup AND circuit-breaker keyed by
    // (authenticated customer) × (venue key_id), never key_id alone.
    let scope = blob_key(customer_id, key_id);
    let blob = match state.blobs.get(&scope) {
        Some(b) => b,
        None => {
            warn!(event = "structured_sign_no_blob", key_id = %key_id);
            return Err(error_response(err_code::BAD_REQUEST));
        }
    };
    if !state.backoff.allow(&scope) {
        warn!(event = "structured_sign_backoff_rejected", key_id = %key_id);
        return Err(error_response(err_code::RATE_LIMITED));
    }
    let creds = match state.creds.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(event = "structured_sign_creds_failed", key_id = %key_id, detail = %e);
            return Err(error_response(err_code::INTERNAL_ERROR));
        }
    };

    // Gemini #78 (wave-2): a non-object `structured` is malformed. Fail loud with
    // bad_request rather than forwarding (None, None) to the enclave — that would
    // burn a vsock round-trip to sign nothing, and silently accepting a payload
    // shape we don't understand is the same class of hole as the UPL bypass.
    let (order_field, cancel_field) = match structured {
        serde_json::Value::Object(mut m) => {
            let order = m.remove("order");
            let cancel = m.remove("cancel");
            // Gemini #79: reject any unexpected top-level key. The only valid
            // shapes are `{"order": ...}` / `{"cancel": ...}`; callers build this
            // object themselves so extras never occur in practice, but rejecting
            // (rather than silently dropping) them matches the enclave's
            // `deny_unknown_fields` stance and forecloses a param-smuggling surface.
            if !m.is_empty() {
                return Err(error_response(err_code::BAD_REQUEST));
            }
            (order, cancel)
        }
        _ => return Err(error_response(err_code::BAD_REQUEST)),
    };
    // Gemini #78 (wave-2): treat an explicit JSON `null` the same as absent — a
    // client sending `{"order": null}` would otherwise yield `Some(Value::Null)`
    // and slip past the both-absent guard below, forwarding a useless payload to
    // the enclave.
    let order_field = order_field.filter(|v| !v.is_null());
    let cancel_field = cancel_field.filter(|v| !v.is_null());
    // An *object* carrying neither `order` nor `cancel` (`{}`, only unrelated
    // keys, or both explicitly null) is just as malformed as a non-object — it
    // would forward (None, None) and burn a vsock round-trip only to be rejected
    // inside the enclave. Reject it gateway-side here. (Both present is fine: the
    // enclave's `action` selects which.)
    if order_field.is_none() && cancel_field.is_none() {
        return Err(error_response(err_code::BAD_REQUEST));
    }

    let vsock_req = VsockRequest {
        action: action.to_owned(),
        // method + path forwarded so the enclave's enforce_policy honours
        // `allowed_methods` and `allowed_path_prefixes` on the trade-signing
        // path (Gemini #78). The enclave's canonical-builder reads from
        // `order`/`cancel`, not these — method/path are policy-only here.
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        body: None,
        // AF-2: forward the AGENT's timestamp verbatim when supplied (it is
        // inside the signed intent, so the enclave must reconstruct over the same
        // value); fall back to gateway `now_ms()` only for opt-in-absent calls.
        timestamp_ms: Some(intent.timestamp_ms.unwrap_or_else(now_ms)),
        aws_credentials: Some(AwsCredentials {
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
        }),
        ciphertext_blob_base64: Some(B64.encode(blob.ciphertext.as_slice())),
        proto_version: 1,
        op: None,
        payload: None,
        opaque_token: Some(raw_token.to_owned()),
        key_blob_s3_key: Some(format!("secrets/{}.enc", key_id)),
        query: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: order_field,
        cancel: cancel_field,
        data: None,
        intent_signature: intent.intent_signature,
        intent_nonce: intent.intent_nonce,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };

    let vsock_started = Instant::now();
    let resp = vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await;
    let vsock_latency_ms = vsock_started.elapsed().as_millis() as u64;
    let mut resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(event = "structured_sign_vsock_failed", key_id = %key_id, latency_ms = vsock_latency_ms, detail = %e);
            return Err(error_response(err_code::ENCLAVE_UNREACHABLE));
        }
    };

    let receipt = take_receipt(&mut resp, customer_id);
    if let Some(code) = resp.error.as_deref() {
        let mapped = crate::proto::safe_wire_code(code);
        if mapped == err_code::RATE_LIMITED {
            state.backoff.report_rate_limited(&scope);
        }
        warn!(
            event = "structured_sign_enclave_error",
            key_id = %key_id,
            internal_code = code,
            wire_code = mapped,
            vsock_latency_ms,
        );
        return Err(enclave_error_response(mapped, receipt));
    }

    let canonical = match resp.canonical_body.take() {
        Some(c) if !c.is_empty() => c,
        _ => {
            warn!(event = "structured_sign_missing_canonical", key_id = %key_id);
            return Err(error_response(err_code::INTERNAL_ERROR));
        }
    };
    let headers = resp.headers.take().unwrap_or_default();
    state.backoff.report_success(&scope);
    Ok((canonical, headers, receipt))
}

/// Assemble the final Binance signed querystring — `canonical` followed by
/// `&timestamp=…&recvWindow=…&signature=…` — i.e. exactly the bytes the venue
/// HMAC was computed over. Same shape goes in the POST body and the DELETE
/// URL query. Returns `Err` if any sentinel header is missing.
pub(crate) fn build_binance_signed_qs(
    canonical: &str,
    headers: &mut std::collections::BTreeMap<String, String>,
) -> Result<String, &'static str> {
    let signature = headers.remove("signature").ok_or("missing signature")?;
    let timestamp = headers.remove("timestamp").ok_or("missing timestamp")?;
    let recv_window = headers
        .remove("recvWindow")
        .unwrap_or_else(|| "5000".to_owned());
    // Defense in depth: anything the enclave returns should be safe to embed,
    // but if a future change widens the alphabet we want to fail loud.
    // Gemini #78 (wave-2): `signature` (hex), `timestamp` + `recvWindow` (digits)
    // are single values that must be STRICTLY alnum/`-_.` — a `&` or `=` slipping
    // in (e.g. a future enclave change that widened the alphabet) would smuggle
    // extra params into the signed querystring. `canonical` is itself a
    // querystring (legitimately contains `&`/`=`), so it keeps the weaker
    // control-char/space reject.
    for v in [signature.as_str(), timestamp.as_str(), recv_window.as_str()] {
        if !is_safe_query_value(v) {
            return Err("unsafe character in signed querystring component");
        }
    }
    if canonical.is_empty()
        || canonical
            .bytes()
            .any(|b| matches!(b, b' ' | b'\n' | b'\r' | 0))
    {
        return Err("unsafe character in canonical querystring");
    }
    Ok(format!(
        "{canonical}&timestamp={timestamp}&recvWindow={recv_window}&signature={signature}"
    ))
}

/// Lowercase `side` / `ord_type` so the order endpoints accept the venue's native
/// upper-case convention (Binance/OKX docs use `BUY`/`SELL`/`LIMIT`/`MARKET`) as
/// well as lowercase. The enclave canonical builders match lowercase and re-apply
/// each venue's required case, so this is signature-preserving — it only widens
/// the accepted input casing (B1: an agent sending upper-case got a 400).
fn normalize_order_case(order: &mut crate::proto::OrderParams) {
    order.side.make_ascii_lowercase();
    order.ord_type.make_ascii_lowercase();
}

pub async fn post_sign_binance_order(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(mut req): Json<crate::proto::SignBinanceOrderRequest>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "binance_order_received", key_id = %key_for_log, "POST /sign/binance-order");
    // Accept the venue's native upper-case side/type (`BUY`/`SELL`/`LIMIT`/
    // `MARKET`) as well as lowercase: the enclave canonical builders match
    // lowercase and re-apply the venue's required case, so normalizing here keeps
    // the signature correct. Without it, an agent sending Binance-style upper-case
    // got a 400 (B1 — the live pilot quant could not place orders).
    normalize_order_case(&mut req.order);

    // B3 (б): per-token daily order counter, fail-closed, BEFORE the signing
    // round-trip (attempt-counted; see limits.rs module doc).
    if let Some((resp, code)) = order_gate(&state, &raw_token).await {
        return finish_log(resp, started, false, Some(code));
    }

    // Serialize the typed order params to opaque Value for vsock forward; the
    // enclave's `deny_unknown_fields` `OrderRequest` is the schema check.
    // `OrderParams` impls `Serialize`; serializing a plain struct is infallible,
    // so the old `to_value` match arm was dead error-handling. Interpolate the
    // typed value straight into `json!` (Gemini #79), matching the OKX handlers.
    // The enclave rebuilds the canonical from these fields → byte-identical
    // forwarded Value, golden HMAC vectors unaffected.
    let payload = serde_json::json!({ "order": req.order });

    let (canonical, mut headers, receipt) = match sign_structured_request(
        &state,
        &customer,
        &raw_token,
        &req.key_id,
        "sign_binance_order",
        "POST",
        "/fapi/v1/order",
        payload,
        AgentIntentForward {
            timestamp_ms: req.timestamp_ms,
            intent_signature: req.intent_signature,
            intent_nonce: None, // orders use client_order_id as the replay nonce
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return finish_log(resp, started, false, None),
    };

    // For POST order: body = full signed querystring. URL is base + path only.
    let body = match build_binance_signed_qs(&canonical, &mut headers) {
        Ok(b) => b,
        Err(detail) => {
            warn!(event = "binance_order_assembly_failed", key_id = %key_for_log, detail = %detail);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };
    headers.insert(
        "Content-Type".to_owned(),
        "application/x-www-form-urlencoded".to_owned(),
    );

    info!(event = "binance_order_ok", key_id = %key_for_log);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignBinanceOrderResponse {
                venue: "binance",
                method: "POST",
                url: format!("{}/fapi/v1/order", binance_base_url()),
                headers,
                body,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// The SINGLE enclave-error → wire mapping for `/sign/binance-request`. Every
/// enclave error code flows through `safe_wire_code` here — there is no
/// verbatim passthrough. Returns the `Response` plus the mapped wire code (the
/// caller needs it for the rate-limit side-effect + `finish_log`).
///
/// This is the no-leak chokepoint for the route. explainable-denials (#227)
/// requires an allow-list violation to surface as the STATIC class
/// `action_not_allowed` (403), never the op/param name. The enclave already
/// emits the static class (`handle_sign_binance_request`; the dynamic
/// `op_not_allowed:<op>` / `param_not_allowed:<op>:<name>` reason is
/// operator-log-only), and `safe_wire_code` is the gateway's defense-in-depth:
/// a dynamic prefix, if ever re-emitted, is coerced to `action_not_allowed`
/// with the suffix DROPPED — no allow-list enumeration on the wire. #219 had
/// shipped a verbatim-surface intercept that echoed those prefixes BEFORE
/// `safe_wire_code`; #227 reversed that judgment on the enclave side but left
/// the intercept, making the coercion unreachable for this route. Routing all
/// errors through this one function keeps the coercion the sole reachable path
/// (regression-guarded by `binance_request_wire_error_never_leaks_op_param`).
fn binance_request_wire_error(
    code: &str,
    receipt: Option<serde_json::Value>,
) -> (Response, &'static str) {
    let mapped = crate::proto::safe_wire_code(code);
    (enclave_error_response(mapped, receipt), mapped)
}

//// Classify a `/sign/binance-request` op for the per-tenant kill switch.
///
/// 🔴 POSITIVE list, and only the GET reads are `Read`.
///
/// The first version of this gate read `_ => RouteClass::Read`, which was wrong
/// twice over (CTO gate on #82). An UNKNOWN op fell through to "read" and passed
/// the stop — absence voting for the permissive default, the exact class of defect
/// we keep paying for. And worse, three KNOWN ops are not reads at all: `leverage`
/// and `positionMode` are POSTs that change risk (`/fapi/v1/leverage`,
/// `/fapi/v1/positionSide/dual`), and `listenKey` opens a stream. Raising leverage
/// while the tenant is in CANCEL_ONLY is exposure-increasing by any reading of the
/// word.
///
/// So: order and cancel by name, the six GET reads by name, and EVERYTHING else —
/// writes we did not name, and ops that do not exist yet — is `Unknown`, which
/// CANCEL_ONLY refuses. A new op added to the enclave's allow-list is refused here
/// until someone classifies it deliberately; that is the safe direction to be
/// wrong in.
///
/// Names mirror the enclave's positive allow-list
/// (`enclave/src/handler.rs`, `binance_request_method_path`).
pub(crate) fn classify_binance_op(op: &str) -> crate::tenant_state::RouteClass {
    use crate::tenant_state::RouteClass;
    match op {
        "order" => RouteClass::Order,
        "cancel" | "allOpenOrders" => RouteClass::Cancel,
        "account" | "positionRisk" | "openOrders" | "orderStatus" | "userTrades" | "income" => {
            RouteClass::Read
        }
        _ => RouteClass::Unknown,
    }
}

// `POST /sign/binance-request` — the keyless-Hummingbot generic primitive.
/// Forwards `{op, payload}` to the enclave (`sign_binance_request`), which
/// allow-lists the op's params (positive per-op whitelist — refuses smuggled
/// withdraw/transfer payloads BEFORE signing), enforces the blob policy, and
/// HMACs the EXACT payload. Returns `{signature, api_key}`. An allow-list
/// violation surfaces as the STATIC class `action_not_allowed` (403) via
/// `binance_request_wire_error` (explainable-denials #227 no-leak invariant:
/// the wire never carries the allow-list boundary, so a stolen token can't
/// enumerate which ops/params a key may sign). The specific op/param stays in
/// the operator log only.
pub async fn post_sign_binance_request(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<crate::proto::SignBinanceRequestHttp>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "binance_request_received", key_id = %key_for_log, op = %req.op, "POST /sign/binance-request");

    if !is_safe_key_id(&req.key_id) {
        warn!(event = "binance_request_bad_key_id", key_id = %req.key_id);
        return finish_log(
            error_response(err_code::BAD_REQUEST),
            started,
            false,
            Some(err_code::BAD_REQUEST),
        );
    }

    // B3 (б): `op == "order"` places an order through this generic keyless
    // primitive (uncapped/dogfood keys — the enclave denies it for policy-
    // capped keys via CR051) — count it against the per-token daily cap.
    // Gating on the DECLARED op is sound because the enclave's positive
    // per-op param allow-list refuses an order-shaped payload under any
    // other declared op before signing. Reads/cancel are not counted.
    // Per-tenant kill switch, body half: gate on the DECLARED op. In
    // CANCEL_ONLY an `order` op is refused, `cancel` and read-only ops go
    // through. The enclave's per-op param allow-list is what makes gating on
    // the declared op sound (a mislabelled order-shaped payload is refused
    // there before signing).
    {
        let class = classify_binance_op(req.op.as_str());
        if let Some((resp, code)) = crate::tenant_state::body_route_gate(&state, &customer, class) {
            return finish_log(resp, started, false, Some(code));
        }
    }

    if req.op == "order" {
        if let Some((resp, code)) = order_gate(&state, &raw_token).await {
            return finish_log(resp, started, false, Some(code));
        }
    }
    // B3.1: `op == "cancel"` → cancels-rate bucket (split mode). Declared-op
    // gating is sound (enclave allow-list refuses a mislabelled payload).
    if req.op == "cancel" {
        if let Some((resp, code)) = cancel_gate(&state, &raw_token) {
            return finish_log(resp, started, false, Some(code));
        }
    }
    let scope = blob_key(&customer, &req.key_id);
    let blob = match state.blobs.get(&scope) {
        Some(b) => b,
        None => {
            warn!(event = "binance_request_no_blob", key_id = %req.key_id);
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };
    if !state.backoff.allow(&scope) {
        warn!(event = "binance_request_backoff_rejected", key_id = %req.key_id);
        return finish_log(
            error_response(err_code::RATE_LIMITED),
            started,
            false,
            Some(err_code::RATE_LIMITED),
        );
    }
    let creds = match state.creds.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(event = "binance_request_creds_failed", key_id = %key_for_log, detail = %e);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    let vsock_req = VsockRequest {
        action: "sign_binance_request".to_owned(),
        method: None,
        path: None,
        body: None,
        timestamp_ms: None,
        aws_credentials: Some(AwsCredentials {
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
        }),
        ciphertext_blob_base64: Some(B64.encode(blob.ciphertext.as_slice())),
        proto_version: 1,
        op: Some(req.op.clone()),
        payload: Some(req.payload.clone()),
        opaque_token: Some(raw_token.to_owned()),
        key_blob_s3_key: Some(format!("secrets/{}.enc", req.key_id)),
        query: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: None,
        cancel: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };

    let mut resp = match vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(event = "binance_request_vsock", success = false, error_code = "enclave_unreachable", detail = %e);
            return finish_log(
                error_response(err_code::ENCLAVE_UNREACHABLE),
                started,
                false,
                Some(err_code::ENCLAVE_UNREACHABLE),
            );
        }
    };

    let receipt = take_receipt(&mut resp, &customer);
    if let Some(code) = resp.error.as_deref() {
        // Single no-leak chokepoint — see `binance_request_wire_error`.
        let (response, mapped) = binance_request_wire_error(code, receipt);
        if mapped == err_code::RATE_LIMITED {
            state.backoff.report_rate_limited(&scope);
        }
        return finish_log(response, started, false, Some(mapped));
    }

    let Some(mut headers) = resp.headers.take() else {
        warn!(event = "binance_request_no_headers", key_id = %key_for_log);
        return finish_log(
            error_response(err_code::INTERNAL_ERROR),
            started,
            false,
            Some(err_code::INTERNAL_ERROR),
        );
    };
    // `resp.headers.take()` moved the map OUT of resp's ZeroizeOnDrop, so this
    // plain BTreeMap won't wipe its values on drop. Pull out the two fields we
    // return, then zeroize EVERY leftover value so no signature / api-key residue
    // lingers in gateway heap (CodeRabbit Major + Gemini HIGH #219). The two
    // extracted values then go into the Drop-wiped response on success, or are
    // wiped on the error path below.
    let mut signature = headers.remove("signature");
    let mut api_key = headers.remove("api_key");
    for v in headers.values_mut() {
        zeroize::Zeroize::zeroize(v);
    }
    if signature.is_none() || api_key.is_none() {
        if let Some(s) = signature.as_mut() {
            zeroize::Zeroize::zeroize(s);
        }
        if let Some(k) = api_key.as_mut() {
            zeroize::Zeroize::zeroize(k);
        }
        warn!(event = "binance_request_missing_fields", key_id = %key_for_log);
        return finish_log(
            error_response(err_code::INTERNAL_ERROR),
            started,
            false,
            Some(err_code::INTERNAL_ERROR),
        );
    }
    // Both present (checked above).
    let signature = signature.expect("signature present after None-check");
    let api_key = api_key.expect("api_key present after None-check");

    state.backoff.report_success(&scope);
    info!(event = "binance_request_ok", key_id = %key_for_log, op = %req.op);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignBinanceRequestResponse {
                signature,
                api_key,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

pub async fn post_sign_binance_cancel(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<crate::proto::SignBinanceCancelRequest>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "binance_cancel_received", key_id = %key_for_log, "POST /sign/binance-cancel");

    // B3.1: cancels-rate bucket (split mode; no-op in blanket mode).
    if let Some((resp, code)) = cancel_gate(&state, &raw_token) {
        return finish_log(resp, started, false, Some(code));
    }

    // `CancelParams` impls `Serialize`; serializing a plain struct is infallible,
    // so the old `to_value` match arm was dead error-handling. Interpolate the
    // typed value straight into `json!` (Gemini #79), matching the OKX handlers.
    // The enclave rebuilds the canonical from these fields → byte-identical
    // forwarded Value, golden HMAC vectors unaffected.
    let payload = serde_json::json!({ "cancel": req.cancel });

    let (canonical, mut headers, receipt) = match sign_structured_request(
        &state,
        &customer,
        &raw_token,
        &req.key_id,
        "sign_binance_cancel",
        "DELETE",
        "/fapi/v1/order",
        payload,
        AgentIntentForward {
            timestamp_ms: req.timestamp_ms,
            intent_signature: req.intent_signature,
            intent_nonce: req.intent_nonce,
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return finish_log(resp, started, false, None),
    };

    // For DELETE cancel: signed querystring goes in the URL; no body.
    let qs = match build_binance_signed_qs(&canonical, &mut headers) {
        Ok(b) => b,
        Err(detail) => {
            warn!(event = "binance_cancel_assembly_failed", key_id = %key_for_log, detail = %detail);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    info!(event = "binance_cancel_ok", key_id = %key_for_log);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignBinanceCancelResponse {
                venue: "binance",
                method: "DELETE",
                url: format!("{}/fapi/v1/order?{}", binance_base_url(), qs),
                headers,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

// ─────────────────────────────────────────────────────────────────────────
// /sign/binance-spot-order + /sign/binance-spot-cancel — Binance SPOT.
//
// WHY THIS NEEDS NO ENCLAVE CHANGE (and therefore no PCR0 rotation)
// The enclave never hardcodes `/fapi/` on the structured trade path. It
// (a) takes `method`/`path` from the gateway and checks them against the
// blob policy's `allowed_path_prefixes` / `denied_path_prefixes`
// (`handler.rs::enforce_policy`), and (b) BUILDS the signed querystring
// itself from the typed `OrderRequest` (`signer.rs::build_binance_order_query`).
// That builder already emits a spot-legal payload — the golden limit vector is
// `symbol=…&side=…&type=LIMIT&quantity=…&price=…&timeInForce=GTC`, every field
// of which is valid on `POST /api/v3/order`. So spot is a NEW PATH CONSTANT
// plus a policy that allows it, not new enclave code.
//
// The action strings stay `sign_binance_order` / `sign_binance_cancel`, which
// matters: `handler.rs::venue_for_action` maps them to venue `"binance"`, so the
// KMS encryption context, the sealed AAD and the tenant venue ACL are all
// unchanged — the same mainnet key (`bf01cfac`) decrypts a spot blob.
//
// WHERE THE WITHDRAWAL FLOOR ACTUALLY HOLDS
// Binance HMAC signs the query string ONLY — it binds neither method nor path.
// So the `path` we send is a POLICY INPUT, not something the signature commits
// to; a client that lies about it cannot be caught by path rules alone. The
// non-bypassable control on THIS route is that the client never supplies the
// query at all: the enclave constructs it from the typed order, so
// `coin=/address=/amount=` cannot appear in a signature no matter what path is
// claimed. The generic `/sign` route is the one that takes a raw query, and
// there a capped key is constrained by the `generic_capped_op_allowed`
// allow-list. Both layers live in the enclave; `denied_path_prefixes: ["/sapi/"]`
// is defence-in-depth on top.
//
// CAPS CAVEAT — READ BEFORE PROVISIONING
// `OrderAssetCap` is keyed by `symbol` alone (`proto.rs`), and spot `BTCUSDT`
// is the SAME STRING as futures `BTCUSDT`. A single blob whose policy allows
// both `/fapi/` and `/api/v3/` therefore applies ONE cap to BOTH markets and
// cannot express different limits per market. Provision spot as its OWN blob
// stem (its own `key_id`, e.g. `binance_spot`) with its own policy and caps —
// which needs no code change, since the blob stem is a gateway-side namespace
// (`blob_key(customer, key_id)`) while the KMS venue comes from the action.
// ─────────────────────────────────────────────────────────────────────────

/// Canonical Binance SPOT order route. Used for BOTH the policy `path` sent to
/// the enclave and the URL handed back to the client, so the two can never
/// drift apart.
pub(crate) const BINANCE_SPOT_ORDER_PATH: &str = "/api/v3/order";

pub async fn post_sign_binance_spot_order(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(mut req): Json<crate::proto::SignBinanceOrderRequest>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "binance_spot_order_received", key_id = %key_for_log, "POST /sign/binance-spot-order");
    normalize_order_case(&mut req.order);

    // `reduceOnly` is a FUTURES-only param. The enclave's canonical builder
    // appends `&reduceOnly=true` whenever the flag is set, which on spot both
    // (a) is rejected by Binance and (b) would bake a futures-only field into a
    // signature the operator believes is a spot order. Refuse up-front rather
    // than burn a vsock round-trip on a signature that cannot be used.
    if req.order.reduce_only {
        warn!(event = "binance_spot_reduce_only_rejected", key_id = %key_for_log);
        return finish_log(
            error_response(err_code::BAD_REQUEST),
            started,
            false,
            Some(err_code::BAD_REQUEST),
        );
    }

    // B3 (б): same per-token daily order counter as the futures route — a spot
    // order is an order.
    if let Some((resp, code)) = order_gate(&state, &raw_token).await {
        return finish_log(resp, started, false, Some(code));
    }

    let payload = serde_json::json!({ "order": req.order });

    let (canonical, mut headers, receipt) = match sign_structured_request(
        &state,
        &customer,
        &raw_token,
        &req.key_id,
        "sign_binance_order",
        "POST",
        BINANCE_SPOT_ORDER_PATH,
        payload,
        AgentIntentForward {
            timestamp_ms: req.timestamp_ms,
            intent_signature: req.intent_signature,
            intent_nonce: None, // orders use client_order_id as the replay nonce
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return finish_log(resp, started, false, None),
    };

    // POST order: body = full signed querystring, URL is base + path only.
    let body = match build_binance_signed_qs(&canonical, &mut headers) {
        Ok(b) => b,
        Err(detail) => {
            warn!(event = "binance_spot_order_assembly_failed", key_id = %key_for_log, detail = %detail);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };
    headers.insert(
        "Content-Type".to_owned(),
        "application/x-www-form-urlencoded".to_owned(),
    );

    info!(event = "binance_spot_order_ok", key_id = %key_for_log);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignBinanceOrderResponse {
                venue: "binance",
                method: "POST",
                url: format!("{}{}", binance_spot_base_url(), BINANCE_SPOT_ORDER_PATH),
                headers,
                body,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

pub async fn post_sign_binance_spot_cancel(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<crate::proto::SignBinanceCancelRequest>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "binance_spot_cancel_received", key_id = %key_for_log, "POST /sign/binance-spot-cancel");

    if let Some((resp, code)) = cancel_gate(&state, &raw_token) {
        return finish_log(resp, started, false, Some(code));
    }

    let payload = serde_json::json!({ "cancel": req.cancel });

    let (canonical, mut headers, receipt) = match sign_structured_request(
        &state,
        &customer,
        &raw_token,
        &req.key_id,
        "sign_binance_cancel",
        "DELETE",
        BINANCE_SPOT_ORDER_PATH,
        payload,
        AgentIntentForward {
            timestamp_ms: req.timestamp_ms,
            intent_signature: req.intent_signature,
            intent_nonce: req.intent_nonce,
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return finish_log(resp, started, false, None),
    };

    // DELETE cancel: signed querystring goes in the URL; no body.
    let qs = match build_binance_signed_qs(&canonical, &mut headers) {
        Ok(b) => b,
        Err(detail) => {
            warn!(event = "binance_spot_cancel_assembly_failed", key_id = %key_for_log, detail = %detail);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    info!(event = "binance_spot_cancel_ok", key_id = %key_for_log);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignBinanceCancelResponse {
                venue: "binance",
                method: "DELETE",
                url: format!(
                    "{}{}?{}",
                    binance_spot_base_url(),
                    BINANCE_SPOT_ORDER_PATH,
                    qs
                ),
                headers,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

// ─────────────────────────────────────────────────────────────────────────
// /sign/okx-order + /sign/okx-cancel — OKX v5 perp trade signing (Option A,
// byte-exact JSON, per-asset cap).
//
// THE LANDMINE: OKX HMAC commits to `ts + method + requestPath + body` where
// `body` is the EXACT JSON byte-string going on the wire. The enclave builds
// the JSON, signs THOSE BYTES, returns them via `canonical_body`. The gateway
// MUST forward verbatim — no parse + re-stringify, ever. The MCP must do the
// same when calling the venue.
//
// OKX cancel = POST `/api/v5/trade/cancel-order` (NOT DELETE) with a JSON
// body, so order + cancel share the same response shape `SignOkxResponse`.
// ─────────────────────────────────────────────────────────────────────────

pub async fn post_sign_okx_order(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(mut req): Json<crate::proto::SignOkxOrderRequest>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "okx_order_received", key_id = %key_for_log, "POST /sign/okx-order");
    // Accept upper-case side/type as well as lowercase (see post_sign_binance_order).
    normalize_order_case(&mut req.order);

    // B3 (б): per-token daily order counter, fail-closed, BEFORE the signing
    // round-trip (attempt-counted; see limits.rs module doc).
    if let Some((resp, code)) = order_gate(&state, &raw_token).await {
        return finish_log(resp, started, false, Some(code));
    }

    // `OrderParams` impls `Serialize`; serializing a plain struct is infallible,
    // so the old `to_value` match arm was dead error-handling. Interpolate the
    // typed value straight into `json!` (Gemini #79). The enclave rebuilds the
    // OKX canonical from these fields, so the forwarded Value is byte-identical —
    // golden HMAC vectors unaffected.
    let payload = serde_json::json!({ "order": req.order });

    let (canonical, mut headers, receipt) = match sign_structured_request(
        &state,
        &customer,
        &raw_token,
        &req.key_id,
        "sign_okx_order",
        "POST",
        "/api/v5/trade/order",
        payload,
        AgentIntentForward {
            timestamp_ms: req.timestamp_ms,
            intent_signature: req.intent_signature,
            intent_nonce: None, // orders use client_order_id as the replay nonce
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return finish_log(resp, started, false, None),
    };

    // Demo / live switch is a header, not a URL change. Inject before serialize.
    if okx_is_demo() {
        headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
    }
    headers.insert("Content-Type".to_owned(), "application/json".to_owned());

    info!(event = "okx_order_ok", key_id = %key_for_log);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignOkxResponse {
                venue: "okx",
                method: "POST",
                url: format!("{}/api/v5/trade/order", okx_base_url()),
                headers,
                body: canonical,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

pub async fn post_sign_okx_cancel(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<crate::proto::SignOkxCancelRequest>,
) -> Response {
    let started = Instant::now();
    let key_for_log = req.key_id.clone();
    info!(event = "okx_cancel_received", key_id = %key_for_log, "POST /sign/okx-cancel");

    // B3.1: cancels-rate bucket (split mode; no-op in blanket mode).
    if let Some((resp, code)) = cancel_gate(&state, &raw_token) {
        return finish_log(resp, started, false, Some(code));
    }

    // `CancelParams` impls `Serialize`; serializing a plain struct is infallible,
    // so the old `to_value` match arm was dead error-handling. Interpolate the
    // typed value straight into `json!` (Gemini #79). The enclave rebuilds the
    // OKX canonical from these fields, so the forwarded Value is byte-identical —
    // golden HMAC vectors unaffected.
    let payload = serde_json::json!({ "cancel": req.cancel });

    let (canonical, mut headers, receipt) = match sign_structured_request(
        &state,
        &customer,
        &raw_token,
        &req.key_id,
        "sign_okx_cancel",
        "POST",
        "/api/v5/trade/cancel-order",
        payload,
        AgentIntentForward {
            timestamp_ms: req.timestamp_ms,
            intent_signature: req.intent_signature,
            intent_nonce: req.intent_nonce,
        },
    )
    .await
    {
        Ok(p) => p,
        Err(resp) => return finish_log(resp, started, false, None),
    };

    if okx_is_demo() {
        headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
    }
    headers.insert("Content-Type".to_owned(), "application/json".to_owned());

    info!(event = "okx_cancel_ok", key_id = %key_for_log);
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignOkxResponse {
                venue: "okx",
                method: "POST",
                url: format!("{}/api/v5/trade/cancel-order", okx_base_url()),
                headers,
                body: canonical,
                receipt,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// Parsed + validated attestation config (read once via `OnceLock` — avoids
/// per-request global env-lock contention; Gemini #76 HIGH).
struct AttestationConfig {
    pcr0: String,
    /// Attested-data pubkey (P2), both wire forms; `None` until provisioned.
    data_pubkey_compressed: Option<String>,
    data_pubkey_address: Option<String>,
}

/// Validate `SIGNER_PCR0` is a 96-char hex SHA-384; return it lowercased.
/// Pure (testable without env mutation) — Gemini #76 HIGH (test-UB).
fn validate_pcr0(raw: &str) -> Result<String, &'static str> {
    let s = raw.trim();
    if s.len() == 96 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err("SIGNER_PCR0 must be 96 hex chars (SHA-384)")
    }
}

/// Validate an optional `0x`-hex env value of exactly `nbytes` bytes. `None`
/// when unset/empty; `Err` when present-but-malformed — FAIL LOUD (a wrong
/// pinned data-pubkey is catastrophic: every buyer verify breaks). Returns the
/// canonical lowercase `0x…` form.
fn validate_opt_hex(
    raw: Option<String>,
    nbytes: usize,
    err: &'static str,
) -> Result<Option<String>, &'static str> {
    match raw.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => {
            let hex = s.strip_prefix("0x").unwrap_or(&s);
            if hex.len() == nbytes * 2 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(Some(format!("0x{}", hex.to_ascii_lowercase())))
            } else {
                Err(err)
            }
        }
    }
}

/// Read + validate the attestation config exactly once. `Err` → the endpoint
/// returns `internal_error` rather than serving a blank/garbled PCR0.
fn attestation_config() -> &'static Result<AttestationConfig, &'static str> {
    static CFG: std::sync::OnceLock<Result<AttestationConfig, &'static str>> =
        std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let pcr0 = validate_pcr0(&std::env::var("SIGNER_PCR0").unwrap_or_default())?;
        let data_pubkey_compressed = validate_opt_hex(
            std::env::var("SIGNER_DATA_PUBKEY").ok(),
            33,
            "SIGNER_DATA_PUBKEY must be 0x + 66 hex (compressed secp256k1)",
        )?;
        let data_pubkey_address = validate_opt_hex(
            std::env::var("SIGNER_DATA_ADDRESS").ok(),
            20,
            "SIGNER_DATA_ADDRESS must be 0x + 40 hex (eth address)",
        )?;
        Ok(AttestationConfig {
            pcr0,
            data_pubkey_compressed,
            data_pubkey_address,
        })
    })
}

/// Query params for `GET /attestation`. H5: an optional caller `nonce` (hex) is
/// bound INTO the NSM document so the caller can prove freshness (an old cached
/// doc fails their nonce check).
#[derive(serde::Deserialize)]
pub struct AttestationQuery {
    pub nonce: Option<String>,
}

/// `POST /receipts/heartbeat` — the tenant asks the ENCLAVE, not the gateway,
/// how many decisions it has made for them.
///
/// The gateway is a courier here and nothing else. It cannot author the answer
/// (the enclave signs it), cannot amend it (it is forwarded verbatim as an
/// opaque value), and cannot usefully replay an old one (the caller's nonce is
/// signed inside). That ordering is the entire point: this is the one call
/// whose job is to catch the gateway hiding a decision, so every part of it
/// that the gateway could influence has to be inert.
///
/// Not an order and not a read of venue state — no daily counter, no KMS, no
/// blob. Exempt from the tenant kill switch for the same reason `/tenant/halt`
/// Is `nonce` a client-chosen freshness value this gateway will forward?
///
/// Extracted from the handler so the rule can be pinned by a test: it is the
/// part of the heartbeat that keeps the gateway from choosing the value the
/// enclave signs, and an inline check inside an async handler cannot be
/// exercised without a live enclave.
///
/// Bound first, then charset — the cheap check should not run after the one
/// that walks the bytes.
fn heartbeat_nonce_ok(nonce: &str) -> bool {
    if nonce.is_empty() || nonce.len() > 128 {
        return false;
    }
    nonce
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// is: a stopped tenant is precisely the one who needs the evidence.
#[derive(serde::Deserialize)]
pub struct ReceiptHeartbeatRequest {
    /// Caller-chosen freshness nonce. Must be something the GATEWAY did not
    /// pick — a client that lets the gateway choose it has bought nothing.
    pub client_nonce: String,
}

pub async fn post_receipt_heartbeat(
    State(state): State<AppState>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Json(req): Json<ReceiptHeartbeatRequest>,
) -> Response {
    let started = Instant::now();
    info!(event = "receipt_heartbeat_received");

    // Same bound and charset the enclave enforces. Duplicated on purpose: the
    // enclave check is the one that counts (it signs the value), this one just
    // spends no vsock round-trip on obvious junk.
    //
    // 🔴 NOT trimmed. Trimming would forward `"abc"` for a client that sent
    // `" abc "`, so the signed document would echo a value the client never
    // chose — and the echo is the entire freshness proof. Whitespace is
    // rejected, never silently repaired (CodeRabbit, #668).
    //
    // Bound before scanning: the cheap check should not run after the one that
    // walks the bytes (Gemini, #668).
    if !heartbeat_nonce_ok(req.client_nonce.as_str()) {
        return finish_log(
            error_response(err_code::BAD_REQUEST),
            started,
            false,
            Some(err_code::BAD_REQUEST),
        );
    }

    let vsock_req = VsockRequest {
        action: "receipt_heartbeat".to_owned(),
        proto_version: 1,
        opaque_token: Some(raw_token),
        method: None,
        path: None,
        body: None,
        timestamp_ms: None,
        aws_credentials: None,
        ciphertext_blob_base64: None,
        key_blob_s3_key: None,
        query: None,
        op: None,
        payload: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: None,
        cancel: None,
        attestation_nonce: None,
        attestation_user_data: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: Some(req.client_nonce.clone()),
    };

    let mut resp = match vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(event = "receipt_heartbeat_vsock", error_code = "enclave_unreachable", detail = %e);
            return finish_log(
                error_response(err_code::ENCLAVE_UNREACHABLE),
                started,
                false,
                Some(err_code::ENCLAVE_UNREACHABLE),
            );
        }
    };
    if let Some(code) = resp.error.as_deref() {
        let mapped = crate::proto::safe_wire_code(code);
        warn!(event = "receipt_heartbeat_enclave_error", code = %mapped);
        // `enclave_error_response`, not `error_response`: this refusal came from
        // the enclave and must say so. `error_response` stamps
        // `decided_by: "gateway"`, which would make an enclave
        // `receipts_unavailable` indistinguishable from a gateway refusal — on
        // the one route whose job is to tell those two apart (CodeRabbit, #668).
        return finish_log(
            enclave_error_response(mapped, None),
            started,
            false,
            Some(mapped),
        );
    }
    // `.take()` rather than a field move — VsockResponse has a manual Drop.
    let Some(hb) = resp.heartbeat.take() else {
        // A success with no document would mean the enclave answered "ok" to a
        // question it did not answer. Fail rather than serve an empty body the
        // caller might read as "zero decisions".
        warn!(event = "receipt_heartbeat_no_document");
        return finish_log(
            error_response(err_code::INTERNAL_ERROR),
            started,
            false,
            Some(err_code::INTERNAL_ERROR),
        );
    };
    finish_log(
        (StatusCode::OK, Json(serde_json::json!({ "heartbeat": hb }))).into_response(),
        started,
        true,
        None,
    )
}

/// `GET /attestation` — signer-mcp `get_attestation` proof tool.
///
/// H5: fetches a live NSM-signed COSE attestation document from the enclave,
/// parses PCR0 out of the SIGNED document, and CROSS-CHECKS that PCR0 against
/// the deploy-time `SIGNER_PCR0` env — a mismatch fails the request (never
/// silently serves a stale/forged value). The optional `?nonce=<hex>` is bound
/// into the document for anti-replay; the response carries `Cache-Control:
/// no-store` so no edge/proxy caches the signed proof. The caller verifies the
/// document against the AWS Nitro root cert (see README) — the gateway parses
/// PCR0 only, it does NOT verify the COSE signature.
pub async fn get_attestation(
    State(state): State<AppState>,
    Query(q): Query<AttestationQuery>,
) -> Response {
    let started = Instant::now();

    // Deploy-time config: `SIGNER_PCR0` (the cross-check anchor) + on-chain flag
    // + data pubkeys.
    let cfg = match attestation_config() {
        Ok(c) => c,
        Err(reason) => {
            warn!(event = "attestation_unconfigured", reason = %reason);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    // Validate the caller nonce (hex, bounded) BEFORE the enclave round-trip.
    // NSM caps the nonce at 1024 bytes (2048 hex chars); reject oversize / non-
    // hex up-front as bad_request. Lowercased so the echo is canonical.
    let nonce_hex = match q.nonce.as_deref() {
        None => None,
        Some(h) => {
            // Validate hex charset + even length WITHOUT decoding — the gateway
            // forwards the hex string to the enclave verbatim and never needs the
            // bytes, so it must not allocate a Vec for an untrusted public input.
            if h.is_empty()
                || h.len() > 2048
                || h.len() % 2 != 0
                || !h.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return finish_log(
                    error_response(err_code::BAD_REQUEST),
                    started,
                    false,
                    Some(err_code::BAD_REQUEST),
                );
            }
            Some(h.to_ascii_lowercase())
        }
    };

    // Ask the enclave for a fresh NSM-signed document. Full literal (VsockRequest
    // is `Drop`, so struct-update `..` can't move out of a Default) — every other
    // field is unused by the attestation action.
    let vsock_req = VsockRequest {
        action: "attestation".to_owned(),
        proto_version: 1,
        opaque_token: None,
        method: None,
        path: None,
        body: None,
        timestamp_ms: None,
        aws_credentials: None,
        ciphertext_blob_base64: None,
        key_blob_s3_key: None,
        query: None,
        op: None,
        payload: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: None,
        cancel: None,
        attestation_nonce: nonce_hex.clone(),
        attestation_user_data: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
    };
    let mut resp = match vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(event = "attestation_vsock", error_code = "enclave_unreachable", detail = %e);
            return finish_log(
                error_response(err_code::ENCLAVE_UNREACHABLE),
                started,
                false,
                Some(err_code::ENCLAVE_UNREACHABLE),
            );
        }
    };
    if let Some(code) = resp.error.as_deref() {
        // The gateway already validated its inputs; a bad_request from the
        // enclave stays bad_request, everything else collapses to internal_error
        // (no leak of NSM internal state).
        let mapped = if code == err_code::BAD_REQUEST {
            err_code::BAD_REQUEST
        } else {
            err_code::INTERNAL_ERROR
        };
        warn!(event = "attestation_enclave_error", code = %code);
        return finish_log(error_response(mapped), started, false, Some(mapped));
    }
    // Move the doc out of `resp` (it is not used afterwards). `.take()` — not a
    // field move — because `VsockResponse` has a manual `Drop` (zeroize), so a
    // partial move out would not compile; `.take()` swaps in `None` instead.
    let Some(doc_b64) = resp.attestation_document_b64.take() else {
        warn!(event = "attestation_no_document");
        return finish_log(
            error_response(err_code::INTERNAL_ERROR),
            started,
            false,
            Some(err_code::INTERNAL_ERROR),
        );
    };

    // Parse PCR0 out of the COSE document (parse-only — signature verification
    // against the Nitro root cert is the caller's job).
    let doc_bytes = match B64.decode(doc_b64.as_bytes()) {
        Ok(d) => d,
        Err(_) => {
            warn!(event = "attestation_doc_b64_invalid");
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };
    let pcr0_from_doc = match extract_pcr0_from_cose(&doc_bytes) {
        Ok(p) => p,
        Err(reason) => {
            warn!(event = "attestation_pcr0_parse_failed", reason = %reason);
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };

    // CROSS-CHECK: the PCR0 in the SIGNED doc MUST equal the deploy env. A
    // mismatch means the running image != the advertised image (misconfig or
    // tamper) — fail LOUD, never serve a doc whose PCR0 disagrees with env.
    // `validate_pcr0` already lowercases the env value and `pcr0_from_doc` is
    // hex::encode (lowercase), so this is defense-in-depth against a future
    // env-format change — not a live-path mismatch today.
    if !pcr0_from_doc.eq_ignore_ascii_case(&cfg.pcr0) {
        tracing::error!(
            event = "attestation_pcr0_mismatch",
            doc_pcr0 = %&pcr0_from_doc[..pcr0_from_doc.len().min(16)],
            env_pcr0 = %&cfg.pcr0[..cfg.pcr0.len().min(16)],
            "COSE PCR0 != SIGNER_PCR0 env — refusing to serve",
        );
        return finish_log(
            error_response(err_code::INTERNAL_ERROR),
            started,
            false,
            Some(err_code::INTERNAL_ERROR),
        );
    }

    info!(
        event = "attestation_served",
        pcr0_short = %&pcr0_from_doc[..16],
        nonce_present = nonce_hex.is_some(),
    );
    let mut response = (
        StatusCode::OK,
        Json(crate::proto::AttestationResponse {
            pcr0_sha384: pcr0_from_doc,
            attestation_doc_b64: Some(doc_b64),
            nonce: nonce_hex,
            data_pubkey_compressed: cfg.data_pubkey_compressed.clone(),
            data_pubkey_address: cfg.data_pubkey_address.clone(),
            timestamp_ms: now_ms(),
        }),
    )
        .into_response();
    // H5: the signed doc binds a fresh nonce + NSM timestamp, so it must NOT be
    // edge/proxy cached — a stale doc would fail a new nonce's freshness check.
    // (`/attestation` also rides the `app` tier, OFF the shared /sign pool, so a
    // no-store flood cannot starve signing — see main.rs.)
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    finish_log(response, started, true, None)
}

/// Extract PCR0 (96-hex) from an NSM `COSE_Sign1` attestation document.
/// PARSE-ONLY: the caller verifies the COSE signature against the AWS Nitro
/// root certificate — the gateway reads PCR0 solely to cross-check the deploy
/// env. Structure: `COSE_Sign1` = CBOR array `[protected, unprotected,
/// payload(bstr), signature]`; the payload decodes to the AttestationDocument
/// map, whose `pcrs` map holds index `0` → the 48-byte SHA-384 measurement.
fn extract_pcr0_from_cose(doc: &[u8]) -> Result<String, &'static str> {
    use ciborium::value::Value;
    let outer: Value = ciborium::from_reader(doc).map_err(|_| "cose: not CBOR")?;
    let arr = outer.as_array().ok_or("cose: not a Sign1 array")?;
    let payload = arr
        .get(2)
        .and_then(Value::as_bytes)
        .ok_or("cose: no payload")?;
    let doc_val: Value =
        ciborium::from_reader(payload.as_slice()).map_err(|_| "doc: payload not CBOR")?;
    let map = doc_val.as_map().ok_or("doc: not a map")?;
    let pcrs = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("pcrs"))
        .map(|(_, v)| v)
        .ok_or("doc: no pcrs")?;
    let pcrs_map = pcrs.as_map().ok_or("pcrs: not a map")?;
    let pcr0 = pcrs_map
        .iter()
        .find(|(k, _)| matches!(k.as_integer(), Some(i) if i == 0u8.into()))
        .map(|(_, v)| v)
        .ok_or("pcrs: no index 0")?;
    let bytes = pcr0.as_bytes().ok_or("pcr0: not bytes")?;
    if bytes.len() != 48 {
        return Err("pcr0: not 48 bytes");
    }
    Ok(hex::encode(bytes))
}

// ─────────────────────────────────────────────────────────────────────────
// /account/<venue> — signer-mcp `get_account` (Option A signed read).
//
// Pattern: the gateway returns a *signed* venue-native read request
// `{venue, method, url, headers}`; the MCP (TS) executes the fetch + parses.
// Keeps signer in zero-egress mode: the enclave/gateway never call venues.
// ─────────────────────────────────────────────────────────────────────────

/// Binance Futures base URL. Default **testnet** — operators must explicitly
/// opt into mainnet via `SIGNER_BINANCE_ENV=mainnet`. Cached in `OnceLock` so
/// per-request env lookups don't take the global env lock.
pub(crate) fn binance_base_url() -> &'static str {
    static CACHED: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    CACHED.get_or_init(|| {
        match std::env::var("SIGNER_BINANCE_ENV")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("mainnet") | Some("live") | Some("prod") => "https://fapi.binance.com",
            _ => "https://testnet.binancefuture.com",
        }
    })
}

/// Binance **SPOT** base URL. Separate from `binance_base_url()` (futures) on
/// purpose — spot lives on a different host AND a different testnet host
/// (`testnet.binance.vision`, not `testnet.binancefuture.com`), so folding the
/// two into one function would silently point spot at a futures testnet that
/// does not serve `/api/v3/`.
///
/// ⚠️ SECURITY NOTE — this host also serves `/sapi/v1/capital/withdraw/apply`.
/// Futures got a free structural separation (`fapi.binance.com` serves no
/// withdrawal route at all); spot does NOT. That separation was never OUR
/// control though: the gateway does not send the request (the client does, see
/// the `/hedge` doctrine note), so the host has always been the client's choice.
/// The control that actually binds is the enclave never PRODUCING a signature
/// over withdrawal-shaped params — see the module note on the spot handlers
/// below. Keep `denied_path_prefixes: ["/sapi/"]` in every spot policy as the
/// defence-in-depth layer, not as the primary one.
pub(crate) fn binance_spot_base_url() -> &'static str {
    static CACHED: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    CACHED.get_or_init(|| {
        match std::env::var("SIGNER_BINANCE_ENV")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("mainnet") | Some("live") | Some("prod") => "https://api.binance.com",
            _ => "https://testnet.binance.vision",
        }
    })
}

/// OKX base URL (always the same host; demo trading is selected by a header,
/// not a URL switch).
pub(crate) fn okx_base_url() -> &'static str {
    "https://www.okx.com"
}

/// Whether the OKX requests should target demo trading (`x-simulated-trading: 1`).
/// Default **demo** for v0 — set `SIGNER_OKX_ENV=live` to flip to mainnet.
pub(crate) fn okx_is_demo() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        !matches!(
            std::env::var("SIGNER_OKX_ENV")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("live") | Some("mainnet") | Some("prod"),
        )
    })
}

/// Run the existing HMAC sign path through the enclave and return the
/// resulting header map. Centralizes blob lookup + backoff + AWS creds + vsock
/// round-trip + error-to-wire-code mapping so `/account/<venue>` and future
/// per-venue read endpoints don't each re-implement them. `Err(Response)` is
/// a ready-to-return HTTP response the caller should pass to `finish_log`.
#[allow(clippy::result_large_err)]
// Response is the canonical wire type — boxing adds indirection (same allow as enclave's enforce_policy).
#[allow(clippy::too_many_arguments)] // request-context threading (PR-B raw_token)
pub(crate) async fn sign_account_read(
    state: &AppState,
    customer_id: &str,
    raw_token: &str,
    venue: &str,
    method: &str,
    path: &str,
    body: &str,
    query: &str,
) -> Result<std::collections::BTreeMap<String, String>, Response> {
    // 1. Resolve the enclave action for this venue (Some unknown venue → 400).
    //    /account is signed-read only; `kind` is None.
    let action = match enclave_action_for(venue, None) {
        Some(a) => a,
        None => return Err(error_response(err_code::BAD_REQUEST)),
    };

    // 2. Blob lookup — tenant-scoped (customer × venue), no cross-customer
    //    fall-through. Backoff keyed identically below.
    let scope = blob_key(customer_id, venue);
    let blob = match state.blobs.get(&scope) {
        Some(b) => b,
        None => {
            warn!(event = "account_blob_missing", venue = %venue);
            return Err(error_response(err_code::BAD_REQUEST));
        }
    };

    // 3. Adaptive backoff (parity with /sign and /sign-x402).
    if !state.backoff.allow(&scope) {
        warn!(event = "account_backoff_rejected", venue = %venue);
        return Err(error_response(err_code::RATE_LIMITED));
    }

    // 4. Fresh AWS creds.
    let creds = match state.creds.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(event = "account_creds_failed", venue = %venue, detail = %e);
            return Err(error_response(err_code::INTERNAL_ERROR));
        }
    };

    // 5. Build the vsock request. Body and query are caller-supplied so the
    //    helper stays generic across read endpoints.
    let vsock_req = VsockRequest {
        action: action.to_owned(),
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        body: Some(body.to_owned()),
        timestamp_ms: Some(now_ms()),
        aws_credentials: Some(AwsCredentials {
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
        }),
        ciphertext_blob_base64: Some(B64.encode(blob.ciphertext.as_slice())),
        proto_version: 1,
        op: None,
        payload: None,
        opaque_token: Some(raw_token.to_owned()),
        key_blob_s3_key: Some(format!("secrets/{}.enc", venue)),
        query: if query.is_empty() {
            None
        } else {
            Some(query.to_owned())
        },
        hl_action: None,
        nonce: None,
        vault_address: None,
        x402: None,
        order: None,
        cancel: None,
        data: None,
        intent_signature: None,
        intent_nonce: None,
        client_nonce: None,
        attestation_nonce: None,
        attestation_user_data: None,
    };

    // 6. Round-trip.
    let vsock_started = Instant::now();
    let resp = vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await;
    let vsock_latency_ms = vsock_started.elapsed().as_millis() as u64;
    let mut resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(event = "account_vsock_failed", venue = %venue, latency_ms = vsock_latency_ms, detail = %e);
            return Err(error_response(err_code::ENCLAVE_UNREACHABLE));
        }
    };

    // 7. Errors → allow-listed wire surface (CR037/CR049 parity). The receipt is
    //    ARCHIVED here for reads too — every enclave decision leaves one, and a
    //    read that was refused is a decision. Returning it to the caller on these
    //    routes (SignedVenueRequest) is a follow-up; the archive is complete.
    let receipt = take_receipt(&mut resp, customer_id);
    if let Some(code) = resp.error.as_deref() {
        let mapped = crate::proto::safe_wire_code(code);
        if mapped == err_code::RATE_LIMITED {
            state.backoff.report_rate_limited(&scope);
        }
        warn!(
            event = "account_enclave_error",
            venue = %venue,
            internal_code = code,
            wire_code = mapped,
            vsock_latency_ms,
        );
        return Err(enclave_error_response(mapped, receipt));
    }

    state.backoff.report_success(&scope);
    Ok(resp.headers.take().unwrap_or_default())
}

/// Defense-in-depth: a value being embedded into a signed query string must be
/// ASCII alnum or `-_.` — Binance signature/timestamp/recvWindow are all
/// hex-or-digits. A future enclave change that widened the alphabet would
/// caller-side fail-loud here. Pure (testable), no `Result<_, Response>`
/// (Response is large; keep this side cheap).
fn is_safe_query_value(v: &str) -> bool {
    // Charset MUST match the enclave token rule (handler.rs `params_subset_of` /
    // `single_filter`: ASCII alnum + `-` + `_`). NO `.` — the enclave rejects it,
    // so a dotted value would pass here then fail closed in the enclave (divergent
    // validation, CodeRabbit). Real values — symbols / hex sigs / ms timestamps /
    // ids — never contain `.`.
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Defense-in-depth on a caller-supplied `key_id` (the venue or x402 payer-key
/// stem). It becomes the second half of the composite blob key AND is forwarded
/// to the enclave as `key_blob_s3_key` (the TOFU pin + rate-limit bucket label,
/// `tofu.rs` / `rate_limiter.rs`). Constrain it to a tight stem alphabet so a
/// crafted value (`../`, embedded `/`, control chars, an over-long string)
/// cannot poison those enclave-side namespaces (review F1). Charset matches a
/// venue/key stem: ASCII alnum + `-_.`, 1..=64 bytes. NO `/` (blob-key
/// separator) and NO `:`. Also reused by the Pass-3 loader to validate a
/// per-customer subdirectory name before it becomes a blob-key prefix.
pub(crate) fn is_safe_key_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

async fn get_account_binance_inner(
    state: AppState,
    customer: String,
    raw_token: String,
) -> Response {
    let started = Instant::now();
    info!(
        event = "account_received",
        venue = "binance",
        "GET /account/binance"
    );

    // Binance USD-M Futures: GET /fapi/v2/account, HMAC over query (no body).
    // The enclave appends timestamp+recvWindow to the canonical query, signs it,
    // and returns those values back in `headers` for us to embed in the URL.
    let mut headers = match sign_account_read(
        &state,
        &customer,
        &raw_token,
        "binance",
        "GET",
        "/fapi/v2/account",
        "",
        "",
    )
    .await
    {
        Ok(h) => h,
        Err(resp) => return finish_log(resp, started, false, None),
    };

    let signature = match headers.remove("signature") {
        Some(s) => s,
        None => {
            warn!(event = "account_missing_signature", venue = "binance");
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };
    let timestamp = match headers.remove("timestamp") {
        Some(t) => t,
        None => {
            warn!(event = "account_missing_timestamp", venue = "binance");
            return finish_log(
                error_response(err_code::INTERNAL_ERROR),
                started,
                false,
                Some(err_code::INTERNAL_ERROR),
            );
        }
    };
    let recv_window = headers
        .remove("recvWindow")
        .unwrap_or_else(|| "5000".to_owned());

    // Validate the values before embedding in the URL (defense in depth).
    if ![&signature, &timestamp, &recv_window]
        .iter()
        .all(|v| is_safe_query_value(v))
    {
        warn!(event = "account_unsafe_query_value", venue = "binance");
        return finish_log(
            error_response(err_code::INTERNAL_ERROR),
            started,
            false,
            Some(err_code::INTERNAL_ERROR),
        );
    }

    let url = format!(
        "{base}/fapi/v2/account?timestamp={timestamp}&recvWindow={recv_window}&signature={signature}",
        base = binance_base_url(),
    );

    info!(event = "account_ok", venue = "binance");
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::AccountBinanceResponse {
                venue: "binance",
                method: "GET",
                url,
                headers, // only X-MBX-APIKEY remains after the removes above
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// Build one signed leaf (`{method, url, headers}`) for an OKX read endpoint.
/// Encapsulates the per-leaf signing + URL construction so both `/balance` and
/// `/positions` use the same path. Returns an error response on failure.
async fn build_okx_signed_read(
    state: &AppState,
    customer_id: &str,
    raw_token: &str,
    path: &'static str,
) -> Result<crate::proto::SignedReadRequest, Response> {
    let mut headers =
        sign_account_read(state, customer_id, raw_token, "okx", "GET", path, "", "").await?;
    if okx_is_demo() {
        headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
    }
    Ok(crate::proto::SignedReadRequest {
        method: "GET",
        url: format!("{}{}", okx_base_url(), path),
        headers,
    })
}

async fn get_account_okx_inner(state: AppState, customer: String, raw_token: String) -> Response {
    let started = Instant::now();
    info!(
        event = "account_received",
        venue = "okx",
        "GET /account/okx"
    );

    // A1 composite (per marketplace coordination): sign BOTH /balance and
    // /positions in one /account hit so the MCP fires them in parallel without
    // a second round-trip to the gateway. Sequential here (only 2 calls, one
    // enclave at a time anyway via vsock) keeps the code linear.
    let balance =
        match build_okx_signed_read(&state, &customer, &raw_token, "/api/v5/account/balance").await
        {
            Ok(b) => b,
            Err(resp) => return finish_log(resp, started, false, None),
        };
    let positions =
        match build_okx_signed_read(&state, &customer, &raw_token, "/api/v5/account/positions")
            .await
        {
            Ok(p) => p,
            Err(resp) => return finish_log(resp, started, false, None),
        };

    info!(event = "account_ok", venue = "okx");
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::AccountOkxResponse {
                venue: "okx",
                balance,
                positions,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// `GET /account/<venue>` — dispatches to the per-venue builder. v0 supports
/// `binance` (USD-M Futures `/fapi/v2/account`) and `okx` (composite
/// `/balance`+`/positions`). `asterdex` is intentionally **not** wired: account
/// state lives on-chain and the indexer shape is owned by the marketplace
/// parser, not the signer.
pub async fn get_account(
    Path(venue): Path<String>,
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
) -> Response {
    match venue.as_str() {
        "binance" => get_account_binance_inner(state, customer, raw_token).await,
        "okx" => get_account_okx_inner(state, customer, raw_token).await,
        // Explicit allow-list: asterdex is **defined** but unsupported on /account
        // (on-chain reads — marketplace owns the indexer shape); any other venue
        // is unknown. Both surface as bad_request.
        _ => {
            warn!(event = "account_unsupported_venue", venue = %venue);
            error_response(err_code::BAD_REQUEST)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// /open-orders/<venue> + /cancel-all/<venue> — signed enumerate + mass-cancel.
//
// Both reuse the GENERIC `sign_binance` / `sign_okx` enclave action via
// `sign_account_read` (no new enclave action → no PCR0 change). Exact requests:
//   open-orders binance: GET    /fapi/v1/openOrders          (optional ?symbol=)
//   open-orders okx:     GET    /api/v5/trade/orders-pending (optional ?instId=)
//   cancel-all  binance: DELETE /fapi/v1/allOpenOrders       (?symbol= required)
//
// POLICY (enclave-side `enforce_policy`: `allowed_methods` + `allowed_path_prefixes`):
// the pilot blobs use the broad `/fapi/` , `/api/v5/` prefixes (which already had
// to permit account-reads + order/cancel), so these pass unchanged. CAVEATS:
//   • A TIGHTER prefix (e.g. `/api/v5/trade/order`) does NOT match
//     `/api/v5/trade/orders-pending` (boundary-safe check) → policy_denied. Widen
//     by RE-WRAPPING the blob (cheap; NOT a PCR0 cutover).
//   • cancel-all is DESTRUCTIVE. A legacy POLICY-LESS blob has NO enclave method/
//     path gate (the no-policy branch is permissive), so DELETE would sign ungated
//     — destructive ops REQUIRE a policy-wrapped blob (verify per tenant). A
//     dedicated structured `sign_*_cancel_all` action (own allow-list + cap) is the
//     future hardening; deferred to the next planned PCR0 cutover.
// ─────────────────────────────────────────────────────────────────────────

/// Assemble a Binance signed URL from the enclave's returned `headers`: pull out
/// `signature` / `timestamp` / `recvWindow`, validate them (defense-in-depth),
/// and rebuild the query in the EXACT order the enclave signed
/// (`compute_binance_headers`: `user_query`, then `timestamp`, then `recvWindow`).
/// Leaves only `X-MBX-APIKEY` in `headers`. Wrong order = invalid signature.
/// Returns the `err_code` (`&'static str`) on failure — the caller maps it to the
/// wire response (avoids returning a heavy `Response` from a small helper).
pub(crate) fn binance_signed_url(
    path: &str,
    user_query: &str,
    headers: &mut std::collections::BTreeMap<String, String>,
) -> Result<String, &'static str> {
    // `Zeroizing` so signature/timestamp/recvWindow are wiped on EVERY return path
    // (incl. the validation-failure error path) — defense-in-depth secret hygiene.
    let signature = zeroize::Zeroizing::new(
        headers
            .remove("signature")
            .ok_or(err_code::INTERNAL_ERROR)?,
    );
    let timestamp = zeroize::Zeroizing::new(
        headers
            .remove("timestamp")
            .ok_or(err_code::INTERNAL_ERROR)?,
    );
    let recv_window = zeroize::Zeroizing::new(
        headers
            .remove("recvWindow")
            .unwrap_or_else(|| "5000".to_owned()),
    );
    for v in [signature.as_str(), timestamp.as_str(), recv_window.as_str()] {
        if !is_safe_query_value(v) {
            return Err(err_code::INTERNAL_ERROR);
        }
    }
    let prefix = if user_query.is_empty() {
        String::new()
    } else {
        format!("{user_query}&")
    };
    Ok(format!(
        "{base}{path}?{prefix}timestamp={ts}&recvWindow={rw}&signature={sig}",
        base = binance_base_url(),
        ts = *timestamp,
        rw = *recv_window,
        sig = *signature,
    ))
}

/// Zeroize every header VALUE in place (X-MBX-APIKEY etc.) before the map is
/// dropped on an error path — so signed material doesn't linger in freed memory.
/// (The success path moves the map into `SignedVenueRequest`, whose `Drop` does this.)
fn zeroize_header_values(headers: &mut std::collections::BTreeMap<String, String>) {
    for v in headers.values_mut() {
        zeroize::Zeroize::zeroize(v);
    }
}

/// Validate an optional venue filter (`symbol` / `instId`) and render it as a
/// query fragment — the single place for the open-orders / cancel-all filter
/// check. `Ok("key=value")` when present + `is_safe_query_value`; `Ok("")` when
/// absent (open-orders → unfiltered); `Err(())` when present but unsafe (caller
/// → bad_request). cancel-all treats an empty result as the required-symbol error.
fn validated_filter(value: Option<&str>, key: &str) -> Result<String, ()> {
    match value {
        Some(v) if !v.is_empty() => {
            if is_safe_query_value(v) {
                Ok(format!("{key}={v}"))
            } else {
                Err(())
            }
        }
        _ => Ok(String::new()),
    }
}

/// Optional filter for `GET /open-orders/:venue`. Binance reads `symbol`
/// (omit = all open orders); OKX reads `instId` (omit = all pending).
#[derive(serde::Deserialize)]
pub struct OpenOrdersQuery {
    symbol: Option<String>,
    #[serde(rename = "instId")]
    inst_id: Option<String>,
}

/// `GET /open-orders/<venue>` — signed enumerate of resting orders so an agent
/// that lost an order_id can reconcile through the signer (preserves zero-egress).
pub async fn get_open_orders(
    Path(venue): Path<String>,
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Query(q): Query<OpenOrdersQuery>,
) -> Response {
    match venue.as_str() {
        "binance" => open_orders_binance_inner(state, customer, raw_token, q.symbol).await,
        "okx" => open_orders_okx_inner(state, customer, raw_token, q.inst_id).await,
        _ => {
            warn!(event = "open_orders_unsupported_venue", venue = %venue);
            error_response(err_code::BAD_REQUEST)
        }
    }
}

async fn open_orders_binance_inner(
    state: AppState,
    customer: String,
    raw_token: String,
    symbol: Option<String>,
) -> Response {
    let started = Instant::now();
    info!(
        event = "open_orders_received",
        venue = "binance",
        "GET /open-orders/binance"
    );
    // Optional `symbol` filter. Validate BEFORE it enters the signed query.
    let user_query = match validated_filter(symbol.as_deref(), "symbol") {
        Ok(q) => q,
        Err(()) => {
            warn!(event = "open_orders_bad_symbol", venue = "binance");
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };
    let mut headers = match sign_account_read(
        &state,
        &customer,
        &raw_token,
        "binance",
        "GET",
        "/fapi/v1/openOrders",
        "",
        &user_query,
    )
    .await
    {
        Ok(h) => h,
        Err(resp) => return finish_log(resp, started, false, None),
    };
    let url = match binance_signed_url("/fapi/v1/openOrders", &user_query, &mut headers) {
        Ok(u) => u,
        Err(code) => {
            zeroize_header_values(&mut headers);
            return finish_log(error_response(code), started, false, Some(code));
        }
    };
    info!(event = "open_orders_ok", venue = "binance");
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignedVenueRequest {
                venue: "binance",
                method: "GET",
                url,
                headers,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

async fn open_orders_okx_inner(
    state: AppState,
    customer: String,
    raw_token: String,
    inst_id: Option<String>,
) -> Response {
    let started = Instant::now();
    info!(
        event = "open_orders_received",
        venue = "okx",
        "GET /open-orders/okx"
    );
    // OKX signs the requestPath INCLUDING the query, so the URL must carry the
    // exact same query string the enclave merged + signed.
    let query = match validated_filter(inst_id.as_deref(), "instId") {
        Ok(q) => q,
        Err(()) => {
            warn!(event = "open_orders_bad_instid", venue = "okx");
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };
    let mut headers = match sign_account_read(
        &state,
        &customer,
        &raw_token,
        "okx",
        "GET",
        "/api/v5/trade/orders-pending",
        "",
        &query,
    )
    .await
    {
        Ok(h) => h,
        Err(resp) => return finish_log(resp, started, false, None),
    };
    if okx_is_demo() {
        headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
    }
    let url = if query.is_empty() {
        format!("{}/api/v5/trade/orders-pending", okx_base_url())
    } else {
        format!("{}/api/v5/trade/orders-pending?{}", okx_base_url(), query)
    };
    info!(event = "open_orders_ok", venue = "okx");
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignedVenueRequest {
                venue: "okx",
                method: "GET",
                url,
                headers,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

// ─────────────────────────────────────────────────────────────────────────
// /user-trades/<venue> — gate-2 signed read of own FILLED-trade history, so a
// quant audits their trade-log with NO raw key (closes "verified-on-testnet").
// Reuses the GENERIC `sign_binance` enclave action via `sign_account_read`; the
// enclave gates a capped key through `generic_capped_op_allowed` (userTrades arm:
// `symbol` required + read-only filters). v0: Binance only; OKX fills-history
// fast-follows. No new enclave ACTION, but the allow-list arm IS a PCR0 change.
// ─────────────────────────────────────────────────────────────────────────

/// Filters for `GET /user-trades/:venue`. Binance `GET /fapi/v1/userTrades`
/// REQUIRES `symbol`; the rest are read-only filters / pagination. Every value
/// is re-validated (`is_safe_query_value`) before it enters the signed query.
#[derive(serde::Deserialize)]
pub struct UserTradesQuery {
    symbol: Option<String>,
    #[serde(rename = "orderId")]
    order_id: Option<String>,
    #[serde(rename = "startTime")]
    start_time: Option<String>,
    #[serde(rename = "endTime")]
    end_time: Option<String>,
    #[serde(rename = "fromId")]
    from_id: Option<String>,
    // OKX fills-history filters (`instType` is required for that venue).
    #[serde(rename = "instType")]
    inst_type: Option<String>,
    #[serde(rename = "instId")]
    inst_id: Option<String>,
    #[serde(rename = "ordId")]
    ord_id: Option<String>,
    after: Option<String>,
    before: Option<String>,
    begin: Option<String>,
    end: Option<String>,
    limit: Option<String>,
}

/// `GET /user-trades/<venue>` — signed read of own filled-trade history.
pub async fn get_user_trades(
    Path(venue): Path<String>,
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Query(q): Query<UserTradesQuery>,
) -> Response {
    match venue.as_str() {
        "binance" => user_trades_binance_inner(state, customer, raw_token, q).await,
        "okx" => user_trades_okx_inner(state, customer, raw_token, q).await,
        _ => {
            warn!(event = "user_trades_unsupported_venue", venue = %venue);
            error_response(err_code::BAD_REQUEST)
        }
    }
}

async fn user_trades_binance_inner(
    state: AppState,
    customer: String,
    raw_token: String,
    q: UserTradesQuery,
) -> Response {
    let started = Instant::now();
    info!(
        event = "user_trades_received",
        venue = "binance",
        "GET /user-trades/binance"
    );
    // Build the signed query in a FIXED order (the enclave signs `user_query +
    // timestamp + recvWindow`, and `binance_signed_url` rebuilds it the same way).
    // `symbol` is REQUIRED; each present filter is validated BEFORE it is signed.
    let mut fragments: Vec<String> = Vec::new();
    match q.symbol.as_deref() {
        Some(s) if !s.is_empty() && is_safe_query_value(s) => fragments.push(format!("symbol={s}")),
        _ => {
            warn!(event = "user_trades_bad_symbol", venue = "binance");
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    }
    for (val, key) in [
        (q.order_id.as_deref(), "orderId"),
        (q.start_time.as_deref(), "startTime"),
        (q.end_time.as_deref(), "endTime"),
        (q.from_id.as_deref(), "fromId"),
        (q.limit.as_deref(), "limit"),
    ] {
        match validated_filter(val, key) {
            Ok(f) if !f.is_empty() => fragments.push(f),
            Ok(_) => {}
            Err(()) => {
                warn!(
                    event = "user_trades_bad_filter",
                    venue = "binance",
                    filter = key
                );
                return finish_log(
                    error_response(err_code::BAD_REQUEST),
                    started,
                    false,
                    Some(err_code::BAD_REQUEST),
                );
            }
        }
    }
    let user_query = fragments.join("&");
    let mut headers = match sign_account_read(
        &state,
        &customer,
        &raw_token,
        "binance",
        "GET",
        "/fapi/v1/userTrades",
        "",
        &user_query,
    )
    .await
    {
        Ok(h) => h,
        Err(resp) => return finish_log(resp, started, false, None),
    };
    let url = match binance_signed_url("/fapi/v1/userTrades", &user_query, &mut headers) {
        Ok(u) => u,
        Err(code) => {
            zeroize_header_values(&mut headers);
            return finish_log(error_response(code), started, false, Some(code));
        }
    };
    info!(event = "user_trades_ok", venue = "binance");
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignedVenueRequest {
                venue: "binance",
                method: "GET",
                url,
                headers,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

async fn user_trades_okx_inner(
    state: AppState,
    customer: String,
    raw_token: String,
    q: UserTradesQuery,
) -> Response {
    let started = Instant::now();
    info!(
        event = "user_trades_received",
        venue = "okx",
        "GET /user-trades/okx"
    );
    // OKX `GET /api/v5/trade/fills-history` REQUIRES `instType`; the rest are
    // read-only filters / pagination. OKX signs the requestPath INCLUDING the
    // query, so the URL must carry the exact same query the enclave merged + signed.
    let mut fragments: Vec<String> = Vec::new();
    match q.inst_type.as_deref() {
        Some(s) if !s.is_empty() && is_safe_query_value(s) => {
            fragments.push(format!("instType={s}"))
        }
        _ => {
            warn!(event = "user_trades_bad_inst_type", venue = "okx");
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    }
    for (val, key) in [
        (q.inst_id.as_deref(), "instId"),
        (q.ord_id.as_deref(), "ordId"),
        (q.after.as_deref(), "after"),
        (q.before.as_deref(), "before"),
        (q.begin.as_deref(), "begin"),
        (q.end.as_deref(), "end"),
        (q.limit.as_deref(), "limit"),
    ] {
        match validated_filter(val, key) {
            Ok(f) if !f.is_empty() => fragments.push(f),
            Ok(_) => {}
            Err(()) => {
                warn!(
                    event = "user_trades_bad_filter",
                    venue = "okx",
                    filter = key
                );
                return finish_log(
                    error_response(err_code::BAD_REQUEST),
                    started,
                    false,
                    Some(err_code::BAD_REQUEST),
                );
            }
        }
    }
    let query = fragments.join("&");
    let mut headers = match sign_account_read(
        &state,
        &customer,
        &raw_token,
        "okx",
        "GET",
        "/api/v5/trade/fills-history",
        "",
        &query,
    )
    .await
    {
        Ok(h) => h,
        Err(resp) => return finish_log(resp, started, false, None),
    };
    if okx_is_demo() {
        headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
    }
    let url = if query.is_empty() {
        format!("{}/api/v5/trade/fills-history", okx_base_url())
    } else {
        format!("{}/api/v5/trade/fills-history?{}", okx_base_url(), query)
    };
    info!(event = "user_trades_ok", venue = "okx");
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignedVenueRequest {
                venue: "okx",
                method: "GET",
                url,
                headers,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// `POST /cancel-all/:venue` filter. Binance `allOpenOrders` REQUIRES a `symbol`.
#[derive(serde::Deserialize)]
pub struct CancelAllQuery {
    symbol: Option<String>,
}

/// `POST /cancel-all/<venue>` — signed mass-cancel. v0: **Binance only**
/// (`DELETE /fapi/v1/allOpenOrders?symbol=`). OKX has no single
/// cancel-all-for-instrument endpoint; the reconcile path there is
/// `GET /open-orders/okx` → `/sign/okx-cancel` per id.
pub async fn post_cancel_all(
    Path(venue): Path<String>,
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Extension(RawToken(raw_token)): Extension<RawToken>,
    Query(q): Query<CancelAllQuery>,
) -> Response {
    // B3.1: the cancels-rate bucket is enforced INSIDE cancel_all_binance_inner
    // (after its cancel_all_received log), not here — so a rate-limited cancel-all
    // still emits the full request lifecycle (cancel_all_received + request_finished
    // with the deny code), consistent with the order/cancel paths (Gemini #224).
    match venue.as_str() {
        "binance" => cancel_all_binance_inner(state, customer, raw_token, q.symbol).await,
        _ => {
            warn!(event = "cancel_all_unsupported_venue", venue = %venue);
            error_response(err_code::BAD_REQUEST)
        }
    }
}

async fn cancel_all_binance_inner(
    state: AppState,
    customer: String,
    raw_token: String,
    symbol: Option<String>,
) -> Response {
    let started = Instant::now();
    info!(
        event = "cancel_all_received",
        venue = "binance",
        "POST /cancel-all/binance"
    );
    // B3.1: cancels-rate bucket. Enforced here (not the dispatcher) so a rate-
    // limited cancel-all still emits request_finished with the deny code — the
    // dispatcher-level check bypassed all lifecycle logging (Gemini #224).
    if let Some((resp, code)) = cancel_gate(&state, &raw_token) {
        return finish_log(resp, started, false, Some(code));
    }
    // Binance `DELETE /fapi/v1/allOpenOrders` REQUIRES `symbol` — cancel-all is
    // scoped per-symbol, not account-wide. An empty (absent) filter is an error.
    let user_query = match validated_filter(symbol.as_deref(), "symbol") {
        Ok(q) if !q.is_empty() => q,
        _ => {
            warn!(event = "cancel_all_bad_symbol", venue = "binance");
            return finish_log(
                error_response(err_code::BAD_REQUEST),
                started,
                false,
                Some(err_code::BAD_REQUEST),
            );
        }
    };
    let mut headers = match sign_account_read(
        &state,
        &customer,
        &raw_token,
        "binance",
        "DELETE",
        "/fapi/v1/allOpenOrders",
        "",
        &user_query,
    )
    .await
    {
        Ok(h) => h,
        Err(resp) => return finish_log(resp, started, false, None),
    };
    let url = match binance_signed_url("/fapi/v1/allOpenOrders", &user_query, &mut headers) {
        Ok(u) => u,
        Err(code) => {
            zeroize_header_values(&mut headers);
            return finish_log(error_response(code), started, false, Some(code));
        }
    };
    info!(event = "cancel_all_ok", venue = "binance");
    finish_log(
        (
            StatusCode::OK,
            Json(crate::proto::SignedVenueRequest {
                venue: "binance",
                method: "DELETE",
                url,
                headers,
            }),
        )
            .into_response(),
        started,
        true,
        None,
    )
}

/// Helper: emit a single structured log line for the request and return
/// the response unchanged. Keeps every exit branch from `post_sign`
/// consistently traced without repeating the format string.
fn finish_log(
    resp: Response,
    started: Instant,
    success: bool,
    error_code: Option<&str>,
) -> Response {
    let latency_ms = started.elapsed().as_millis() as u64;
    info!(
        event = "request_finished",
        latency_ms,
        success,
        error_code = error_code.unwrap_or("")
    );
    resp
}

#[allow(clippy::too_many_arguments)] // request-context threading (PR-B raw_token)
#[cfg(test)]
mod tests {

    /// The nonce is what stops the GATEWAY from choosing the freshness value
    /// the enclave signs, so each way of loosening it is pinned by name.
    ///
    /// The whitespace case is the one that matters: the handler's comment says
    /// whitespace is rejected rather than trimmed, because trimming would
    /// forward `"abc"` for a client that sent `" abc "` — the signed document
    /// would then echo a value the client never chose, and the echo IS the
    /// freshness proof. A later `trim()` would break that silently; this test
    /// makes it fail loudly instead.
    /// Every op the enclave will accept must be classified DELIBERATELY, and an
    /// unknown one must land in `Unknown` — which `CANCEL_ONLY` refuses.
    ///
    /// Two defects this locks out, both found on #82 by the CTO gate:
    ///  * `_ => Read` let an UNKNOWN op through a stopped tenant — absence voting
    ///    for the permissive default;
    ///  * it also called `leverage`, `positionMode` and `listenKey` reads. The
    ///    first two are POSTs that change risk. Raising leverage on a tenant in
    ///    CANCEL_ONLY is exposure-increasing by any reading of the word.
    ///
    /// If a new op is added to the enclave and not here, this test does not fail —
    /// but the gate refuses it, which is the safe direction.
    #[test]
    fn binance_request_ops_are_classified_by_a_positive_list() {
        use crate::tenant_state::RouteClass;
        // The handler's own function, not a copy of it: a copy would keep passing
        // after the gate itself changed.
        let classify = super::classify_binance_op;
        assert_eq!(classify("order"), RouteClass::Order);
        for op in ["cancel", "allOpenOrders"] {
            assert_eq!(classify(op), RouteClass::Cancel, "{op} reduces exposure");
        }
        for op in [
            "account",
            "positionRisk",
            "openOrders",
            "orderStatus",
            "userTrades",
            "income",
        ] {
            assert_eq!(classify(op), RouteClass::Read, "{op} is a GET read");
        }
        // The three that used to be miscounted as reads.
        for op in ["leverage", "positionMode", "listenKey"] {
            assert_eq!(
                classify(op),
                RouteClass::Unknown,
                "{op} is a POST that changes risk or opens a stream — it must NOT be \
                 classified as a read, or a CANCEL_ONLY tenant could still use it"
            );
        }
        // And anything nobody has thought about yet.
        for op in ["", "withdraw", "transfer", "futureOpNobodyWroteYet"] {
            assert_eq!(
                classify(op),
                RouteClass::Unknown,
                "an unclassified op must be Unknown, never Read"
            );
        }
    }

    #[test]
    fn heartbeat_nonce_rule_is_pinned_including_the_no_trim_promise() {
        assert!(heartbeat_nonce_ok("aZ0-_"), "the allowed charset must pass");
        assert!(
            heartbeat_nonce_ok(&"a".repeat(128)),
            "128 bytes is the bound"
        );

        assert!(
            !heartbeat_nonce_ok(""),
            "an empty nonce proves no freshness"
        );
        assert!(
            !heartbeat_nonce_ok(&"a".repeat(129)),
            "129 bytes is over it"
        );
        assert!(
            !heartbeat_nonce_ok(" abc"),
            "leading whitespace is REJECTED, never trimmed: forwarding a \
             repaired value would echo something the client never chose"
        );
        assert!(!heartbeat_nonce_ok("abc "), "trailing whitespace likewise");
        assert!(!heartbeat_nonce_ok("ab.c"), "'.' is outside the charset");
    }

    /// `/healthz` promises a short commit SHA or `"unknown"`. Anything else
    /// would be BELIEVED — a reader seeing `main` goes looking for a commit
    /// that does not exist, which is worse than being told nothing.
    #[test]
    fn build_sha_is_a_sha_or_it_is_unknown() {
        assert_eq!(
            valid_build_sha(Some("a81e99e")),
            "a81e99e",
            "short SHA passes"
        );
        assert_eq!(
            valid_build_sha(Some("3bf4f62c99be3cef529e4dc9e78d96d8ac1d3c89")),
            "3bf4f62c99be3cef529e4dc9e78d96d8ac1d3c89",
            "a full SHA-1 passes"
        );

        for bad in [
            "main",      // a branch name is the case that motivated this
            "",          // empty
            " a81e99e",  // whitespace from a CI expansion
            "a81e99e\n", // trailing newline, same source
            "A81E99E",   // uppercase is not what rev-parse emits
            "a81e99",    // 6 chars — below any abbreviation git produces
            "zzzzzzz",   // right length, not hex
            "a81e99e-dirty",
        ] {
            assert_eq!(
                valid_build_sha(Some(bad)),
                "unknown",
                "must not publish {bad:?} as a build id"
            );
        }
        assert_eq!(valid_build_sha(None), "unknown", "undeclared build");
    }
    use super::*;

    // ── H5: PCR0 extraction from a COSE_Sign1 attestation document ──────────
    // We build a minimal CBOR document with the SAME structure the NSM emits —
    // `COSE_Sign1 = [protected, unprotected, payload(bstr), signature]`, payload
    // = `{ "pcrs": { 0: <48 bytes> } }` — then round-trip it through
    // `extract_pcr0_from_cose`. This is a golden vector for the parse path
    // (signature verification is the caller's job, out of scope here).
    fn build_cose_doc(pcr0: &[u8]) -> Vec<u8> {
        use ciborium::value::Value;
        let pcrs = Value::Map(vec![(
            Value::Integer(0u8.into()),
            Value::Bytes(pcr0.to_vec()),
        )]);
        let payload_doc = Value::Map(vec![
            (
                Value::Text("module_id".into()),
                Value::Text("enc-test".into()),
            ),
            (Value::Text("pcrs".into()), pcrs),
        ]);
        let mut payload = Vec::new();
        ciborium::into_writer(&payload_doc, &mut payload).expect("encode payload");
        let cose = Value::Array(vec![
            Value::Bytes(vec![]),      // protected header
            Value::Map(vec![]),        // unprotected header
            Value::Bytes(payload),     // payload = AttestationDocument
            Value::Bytes(vec![0; 64]), // signature (unverified here)
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&cose, &mut out).expect("encode cose");
        out
    }

    // ── Binance SPOT route constants ────────────────────────────────────────
    // These pin the two mistakes that would silently break the spot lane's
    // safety story. No env is touched: nothing in this crate sets
    // `SIGNER_BINANCE_ENV`, so both base-URL helpers resolve to their testnet
    // arm deterministically.

    #[test]
    fn binance_spot_and_futures_hosts_are_distinct() {
        // Spot testnet is `testnet.binance.vision`, NOT `testnet.binancefuture.com`
        // — folding the two helpers into one would point spot at a futures host
        // that serves no `/api/v3/` at all.
        assert_ne!(binance_spot_base_url(), binance_base_url());
        assert!(
            !binance_spot_base_url().contains("binancefuture"),
            "spot base URL must not be the futures host: {}",
            binance_spot_base_url()
        );
        assert!(
            binance_spot_base_url().starts_with("https://"),
            "spot base URL must be https: {}",
            binance_spot_base_url()
        );
    }

    #[test]
    fn binance_spot_order_path_is_not_a_withdrawal_path() {
        // The spot host also serves `/sapi/v1/capital/withdraw/apply`, so the
        // route constant must stay inside `/api/v3/` and never collide with the
        // `/sapi/` prefix that every spot policy denies. If someone ever
        // "generalises" this constant, this test is the tripwire.
        assert_eq!(BINANCE_SPOT_ORDER_PATH, "/api/v3/order");
        assert!(!BINANCE_SPOT_ORDER_PATH.starts_with("/sapi/"));
        assert!(!BINANCE_SPOT_ORDER_PATH.starts_with("/fapi/"));
        // The enclave's allow-list check is prefix-based with a boundary rule,
        // so a spot policy granting `/api/v3/` must NOT thereby grant `/sapi/`.
        assert!(!"/sapi/v1/capital/withdraw/apply".starts_with("/api/v3/"));
    }

    #[test]
    fn extract_pcr0_from_cose_roundtrip() {
        let pcr0 = [0xABu8; 48];
        let doc = build_cose_doc(&pcr0);
        assert_eq!(
            extract_pcr0_from_cose(&doc).expect("parse"),
            hex::encode(pcr0)
        );
    }

    #[test]
    fn extract_pcr0_from_cose_rejects_wrong_pcr_len() {
        // A 32-byte "pcr0" (SHA-256 not SHA-384) must be rejected, not truncated.
        let doc = build_cose_doc(&[0x01u8; 32]);
        assert!(extract_pcr0_from_cose(&doc).is_err());
    }

    #[test]
    fn extract_pcr0_from_cose_rejects_non_cbor() {
        assert!(extract_pcr0_from_cose(b"definitely not cbor").is_err());
    }

    #[test]
    fn extract_pcr0_from_cose_rejects_missing_pcrs() {
        use ciborium::value::Value;
        let payload_doc = Value::Map(vec![(
            Value::Text("module_id".into()),
            Value::Text("no-pcrs".into()),
        )]);
        let mut payload = Vec::new();
        ciborium::into_writer(&payload_doc, &mut payload).unwrap();
        let cose = Value::Array(vec![
            Value::Bytes(vec![]),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(vec![0; 64]),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&cose, &mut out).unwrap();
        assert!(extract_pcr0_from_cose(&out).is_err());
    }

    /// B1: the order endpoints accept the venue's native upper-case `side`/`type`
    /// (Binance/OKX use `BUY`/`LIMIT`) by lowercasing them before the enclave's
    /// canonical builders (which match lowercase) — otherwise upper-case → 400.
    #[test]
    fn normalize_order_case_lowercases_side_and_type() {
        let mut o: crate::proto::OrderParams = serde_json::from_str(
            r#"{"symbol":"BTCUSDT","side":"BUY","qty":"0.001","ord_type":"LIMIT","price":"54000"}"#,
        )
        .unwrap();
        normalize_order_case(&mut o);
        assert_eq!(o.side, "buy");
        assert_eq!(o.ord_type, "limit");
        assert_eq!(o.symbol, "BTCUSDT", "symbol must be untouched");
        // already-lowercase / mixed-case are idempotent
        let mut o2: crate::proto::OrderParams = serde_json::from_str(
            r#"{"symbol":"ETHUSDT","side":"Sell","qty":"1","ord_type":"market"}"#,
        )
        .unwrap();
        normalize_order_case(&mut o2);
        assert_eq!(o2.side, "sell");
        assert_eq!(o2.ord_type, "market");
    }

    /// `binance_signed_url` rebuilds the query in the EXACT order the enclave
    /// signed (`compute_binance_headers`: user_query, then timestamp, then
    /// recvWindow, then the appended signature) — any other order would make the
    /// Binance HMAC invalid. Consumes signature/timestamp/recvWindow, leaving only
    /// `X-MBX-APIKEY` as a real header.
    #[test]
    fn binance_signed_url_orders_query_as_enclave_signed() {
        let mut h = std::collections::BTreeMap::new();
        h.insert("X-MBX-APIKEY".to_owned(), "thekey".to_owned());
        h.insert("signature".to_owned(), "deadbeef".to_owned());
        h.insert("timestamp".to_owned(), "1718900000000".to_owned());
        h.insert("recvWindow".to_owned(), "5000".to_owned());
        let url = binance_signed_url("/fapi/v1/openOrders", "symbol=BTCUSDT", &mut h).unwrap();
        assert!(
            url.ends_with(
                "/fapi/v1/openOrders?symbol=BTCUSDT&timestamp=1718900000000&recvWindow=5000&signature=deadbeef"
            ),
            "url={url}"
        );
        assert_eq!(h.len(), 1, "only X-MBX-APIKEY should remain: {h:?}");
        assert_eq!(h.get("X-MBX-APIKEY").map(String::as_str), Some("thekey"));
    }

    /// Regression for the removed #219 verbatim-surface intercept: the ONLY
    /// enclave-error → wire mapping the binance-request handler uses is
    /// `binance_request_wire_error`, and it must send EVERY code (including a
    /// dynamic `op_not_allowed:<op>` / `param_not_allowed:<op>:<name>` that a
    /// future enclave regression could re-emit) through `safe_wire_code`. A
    /// dynamic prefix must surface as the STATIC class `action_not_allowed`
    /// (403) with the suffix DROPPED — no op/param name, no `:` on the wire.
    /// A re-introduced verbatim intercept would echo the suffix and fail here.
    #[test]
    fn binance_request_wire_error_never_leaks_op_param() {
        for enclave_code in [
            "op_not_allowed:withdraw",
            "param_not_allowed:account:coin",
            "action_not_allowed", // the current static emit — passes through unchanged
        ] {
            let (resp, mapped) = binance_request_wire_error(enclave_code, None);
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{enclave_code} must map to 403"
            );
            assert_eq!(
                mapped,
                err_code::ACTION_NOT_ALLOWED,
                "{enclave_code} must coerce to the static class"
            );
            assert!(
                !mapped.contains(':'),
                "wire code must not carry the op/param suffix: {mapped}"
            );
        }
        // A non-denial code still routes through safe_wire_code (unknown → 500),
        // proving there is no denial-only special-case left in the handler.
        let (resp, mapped) = binance_request_wire_error("some_unmapped_diag", None);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(mapped, err_code::INTERNAL_ERROR);
    }

    /// No `symbol`/user query → the query starts straight at `timestamp`; an
    /// absent `recvWindow` defaults to 5000 (matches the enclave default).
    #[test]
    fn binance_signed_url_without_user_query_omits_prefix() {
        let mut h = std::collections::BTreeMap::new();
        h.insert("signature".to_owned(), "ab".to_owned());
        h.insert("timestamp".to_owned(), "1".to_owned());
        let url = binance_signed_url("/fapi/v1/allOpenOrders", "", &mut h).unwrap();
        assert!(
            url.ends_with("/fapi/v1/allOpenOrders?timestamp=1&recvWindow=5000&signature=ab"),
            "url={url}"
        );
    }

    /// Defense-in-depth: a signed value carrying a query-breaker (`&`, `=`, `?`)
    /// must fail-loud rather than corrupt the URL it is embedded into.
    #[test]
    fn binance_signed_url_rejects_unsafe_signed_value() {
        let mut h = std::collections::BTreeMap::new();
        h.insert("signature".to_owned(), "ab&injected=1".to_owned());
        h.insert("timestamp".to_owned(), "1".to_owned());
        assert!(binance_signed_url("/fapi/v1/openOrders", "", &mut h).is_err());
    }

    /// `build_binance_signed_qs` produces the canonical querystring exactly
    /// matching the enclave's openssl-validated golden vector for the BTCUSDT
    /// BUY MARKET 0.001 order. Pure function — no enclave or AWS needed.
    #[test]
    fn build_binance_signed_qs_matches_openssl_golden_vector() {
        let canonical = "symbol=BTCUSDT&side=BUY&type=MARKET&quantity=0.001";
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("X-MBX-APIKEY".to_owned(), "k".to_owned());
        headers.insert(
            "signature".to_owned(),
            "6cbb8dba71cafef7614f26fd26c7fc995f23b73c4e6381030abfc92213279ade".to_owned(),
        );
        headers.insert("timestamp".to_owned(), "1714997000000".to_owned());
        headers.insert("recvWindow".to_owned(), "5000".to_owned());

        let qs = build_binance_signed_qs(canonical, &mut headers).unwrap();
        assert_eq!(
            qs,
            "symbol=BTCUSDT&side=BUY&type=MARKET&quantity=0.001\
             &timestamp=1714997000000\
             &recvWindow=5000\
             &signature=6cbb8dba71cafef7614f26fd26c7fc995f23b73c4e6381030abfc92213279ade"
        );
        // build_binance_signed_qs MOVED signature/timestamp/recvWindow out;
        // only X-MBX-APIKEY remains as a real outgoing header.
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("X-MBX-APIKEY"));
    }

    /// Missing the signature header → fail-loud, do not emit an unsigned query.
    #[test]
    fn build_binance_signed_qs_rejects_missing_signature() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("timestamp".to_owned(), "1714997000000".to_owned());
        assert!(build_binance_signed_qs("symbol=BTCUSDT", &mut headers).is_err());
    }

    /// Pure attestation validators (no env mutation — Gemini #76 HIGH test-UB).
    #[test]
    fn validate_pcr0_accepts_96_hex_rejects_rest() {
        let good = "7255eb64108d6c865e71b199376595ff3b0ca93b44a2f5a8549f8b1186df68489fb36b935ea574a30c65781ce0b7fbb7";
        assert_eq!(validate_pcr0(good).unwrap(), good);
        assert_eq!(validate_pcr0(&good.to_uppercase()).unwrap(), good);
        assert!(validate_pcr0("deadbeef").is_err());
        assert!(validate_pcr0("").is_err());
        assert!(validate_pcr0(&"z".repeat(96)).is_err());
        assert!(validate_pcr0(&format!("{}0", good)).is_err());
    }

    /// F1: `is_safe_key_id` admits venue/key stems and rejects anything that
    /// could poison the composite blob key or the enclave's TOFU/rate-limit
    /// namespace (`/`, `..`, control chars, over-long).
    #[test]
    fn is_safe_key_id_admits_stems_rejects_separators_and_overlong() {
        assert!(is_safe_key_id("binance"));
        assert!(is_safe_key_id("okx"));
        assert!(is_safe_key_id("x402-payer.1_v2"));
        assert!(!is_safe_key_id("")); // empty
        assert!(!is_safe_key_id("../fund-b/binance")); // dotdot + slash
        assert!(!is_safe_key_id("fund-b/binance")); // embedded slash
        assert!(!is_safe_key_id("a:b")); // colon
        assert!(!is_safe_key_id("has space"));
        assert!(!is_safe_key_id("nul\0byte"));
        assert!(!is_safe_key_id(&"x".repeat(65))); // over 64 bytes
        assert!(is_safe_key_id(&"x".repeat(64))); // exactly 64 ok
    }

    /// `is_safe_query_value` accepts the alphabet of values the enclave produces
    /// for the signed query (hex sig, decimal ts/recvWindow). Anything that
    /// could break URL boundaries (`&`, `=`, space, NUL) is rejected.
    #[test]
    fn is_safe_query_value_admits_hex_digits_rejects_url_breakers() {
        // Real binance.com vectors.
        assert!(is_safe_query_value(
            "3df88afae4e27449e667c69a1eb683c551d5af1ffc0b1e29f5172546f83fb660"
        ));
        assert!(is_safe_query_value("1714997000000"));
        assert!(is_safe_query_value("5000"));
        // Boundary-breakers.
        assert!(!is_safe_query_value(""));
        assert!(!is_safe_query_value("abc&def=ghi"));
        assert!(!is_safe_query_value("foo bar"));
        assert!(!is_safe_query_value("\0"));
        assert!(!is_safe_query_value("a/b"));
        // `.` is rejected — charset matches the enclave token rule (no dotted
        // value reaches the enclave only to fail closed there).
        assert!(!is_safe_query_value("BTC.USDT"));
    }

    /// PR-A multi-tenant isolation: customer A's token can NEVER reach a blob
    /// staged for customer B, even for the same venue. The blob lookup is keyed
    /// `{customer}/{venue}` with no cross-customer fall-through, so A's request
    /// fails at the routing layer (bad_request) before any creds/enclave call.
    #[tokio::test]
    async fn customer_a_cannot_reach_customer_b_blob() {
        use crate::state::{blob_key, EnclaveTarget};
        let cust_a = "aaaaaaaa-0000-0000-0000-000000000001";
        let cust_b = "bbbbbbbb-0000-0000-0000-000000000002";
        // Only customer B has a binance blob staged.
        let mut blobs = std::collections::HashMap::new();
        blobs.insert(
            blob_key(cust_b, "binance"),
            crate::state::BlobBundle {
                ciphertext: b"cust-b-binance".to_vec(),
                encryption_context: None,
            },
        );
        let state = AppState::new(blobs, EnclaveTarget { cid: 0, port: 0 });

        // Customer A (no A/binance blob) → bad_request, never touches B's blob.
        let req = crate::proto::VerifyBlobRequest {
            venue_id: "binance".to_owned(),
        };
        let resp = post_verify_blob(
            State(state.clone()),
            Extension(ResolvedCustomer(cust_a.to_owned())),
            Extension(RawToken("op-tok".to_owned())),
            Json(req),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "customer A must be denied customer B's blob (no cross-tenant fall-through)"
        );
    }

    /// D8 collision: two customers using the SAME venue resolve to DISTINCT
    /// scope keys, so neither their blob lookup NOR their circuit-breaker
    /// bucket can collide.
    #[test]
    fn two_customers_same_venue_distinct_scope() {
        use crate::state::blob_key;
        let a = blob_key("aaaa-0000", "binance");
        let b = blob_key("bbbb-0000", "binance");
        assert_ne!(a, b, "same venue, different customer → different scope");
        assert!(a.ends_with("/binance") && b.ends_with("/binance"));
    }

    // Shared fixture for the per-site isolation tests: a state where ONLY
    // customer B has a blob for `stem`.
    fn state_with_only_b(cust_b: &str, stem: &str) -> AppState {
        use crate::state::{blob_key, BlobBundle, EnclaveTarget};
        let mut blobs = std::collections::HashMap::new();
        blobs.insert(
            blob_key(cust_b, stem),
            BlobBundle {
                ciphertext: b"cust-b".to_vec(),
                encryption_context: None,
            },
        );
        AppState::new(blobs, EnclaveTarget { cid: 0, port: 0 })
    }

    const CUST_A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
    const CUST_B: &str = "bbbbbbbb-0000-0000-0000-000000000002";

    /// Site `sign_structured_request` (binance/okx order/cancel + hedge):
    /// customer A is denied B's venue blob BEFORE any creds/enclave call.
    #[tokio::test]
    async fn structured_sign_customer_isolation() {
        let state = state_with_only_b(CUST_B, "binance");
        let payload = serde_json::json!({ "order": {} });
        // A → bad_request (no A/binance blob, no fall-through to B's).
        let err = sign_structured_request(
            &state,
            CUST_A,
            "tok-a",
            "binance",
            "sign_binance_order",
            "POST",
            "/fapi/v1/order",
            payload.clone(),
            AgentIntentForward::default(),
        )
        .await
        .expect_err("A must be denied B's blob");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        // B → gets PAST the blob lookup (fails later on creds, NOT bad_request).
        let b_resp = sign_structured_request(
            &state,
            CUST_B,
            "tok-b",
            "binance",
            "sign_binance_order",
            "POST",
            "/fapi/v1/order",
            payload,
            AgentIntentForward::default(),
        )
        .await;
        if let Err(resp) = b_resp {
            assert_ne!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "B owns the blob — must pass routing and fail later (creds), not bad_request"
            );
        }
    }

    /// `reduceOnly` is futures-only: on the SPOT route it must be refused up
    /// front, before any vsock round-trip, so no signature carrying a
    /// futures-only field can exist for an order the operator believes is spot.
    ///
    /// The control case is the point. `bad_request` alone would also be produced
    /// by a missing blob or a broken enclave target, so a single assertion could
    /// pass with the guard deleted. The same request with `reduce_only: false`
    /// must therefore reach PAST the guard and fail LATER (no enclave at cid 0)
    /// with a different code — proving the first refusal came from the guard.
    #[tokio::test]
    async fn binance_spot_order_refuses_reduce_only_before_signing() {
        use axum::extract::{Json, State};
        use axum::Extension;

        let cust = CUST_B;
        let state = state_with_only_b(cust, "binance");
        let req = |reduce_only: bool| {
            serde_json::from_value::<crate::proto::SignBinanceOrderRequest>(serde_json::json!({
                "key_id": "binance",
                // snake_case on purpose: `OrderParams` is `deny_unknown_fields`,
                // so `ordType`/`reduceOnly` are REJECTED rather than silently
                // dropped — that guard is what keeps a typo'd caller field from
                // flipping order semantics. Writing the fixture in camelCase
                // fails here loudly, which is the intended behaviour.
                "order": {
                    "symbol": "BTCUSDT",
                    "side": "BUY",
                    "qty": "0.001",
                    "ord_type": "MARKET",
                    "reduce_only": reduce_only,
                }
            }))
            .expect("request fixture must deserialize")
        };

        let denied = post_sign_binance_spot_order(
            State(state.clone()),
            Extension(ResolvedCustomer(cust.to_owned())),
            Extension(RawToken("tok-b".to_owned())),
            Json(req(true)),
        )
        .await;
        assert_eq!(
            denied.status(),
            StatusCode::BAD_REQUEST,
            "reduceOnly on the spot route must be refused"
        );

        let allowed = post_sign_binance_spot_order(
            State(state),
            Extension(ResolvedCustomer(cust.to_owned())),
            Extension(RawToken("tok-b".to_owned())),
            Json(req(false)),
        )
        .await;
        assert_ne!(
            allowed.status(),
            StatusCode::BAD_REQUEST,
            "without reduceOnly the request must get past the guard and fail later"
        );
    }

    /// Site `sign_account_read` (get_account binance/okx): same isolation.
    #[tokio::test]
    async fn account_read_customer_isolation() {
        let state = state_with_only_b(CUST_B, "binance");
        let err = sign_account_read(
            &state,
            CUST_A,
            "tok-a",
            "binance",
            "GET",
            "/fapi/v2/account",
            "",
            "",
        )
        .await
        .expect_err("A must be denied B's account blob");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    /// Circuit-breaker isolation: customer A tripping the breaker for a venue
    /// does NOT open it for customer B on the same venue (composite scope).
    #[test]
    fn circuit_breaker_isolated_per_customer() {
        use crate::backoff::BackoffManager;
        use crate::state::blob_key;
        let bm = BackoffManager::new();
        let a = blob_key(CUST_A, "binance");
        let b = blob_key(CUST_B, "binance");
        bm.report_rate_limited(&a);
        assert!(!bm.allow(&a), "A's binance circuit is open");
        assert!(bm.allow(&b), "B's binance circuit is UNAFFECTED");
    }

    /// All 5 lookup-site key shapes are customer-scoped: for each site's stem,
    /// A's composite key differs from B's and resolves to None when only B is
    /// staged. Documents the routing keys for post_sign (exchange),
    /// verify_blob (venue_id), x402 (key_id), structured (key_id), account
    /// (venue) all funnel through `blob_key(customer, stem)`.
    #[test]
    fn all_lookup_sites_keyed_by_customer() {
        use crate::state::blob_key;
        for stem in ["kucoin", "binance", "okx", "x402-payer", "asterdex"] {
            let state = state_with_only_b(CUST_B, stem);
            assert!(
                state.blobs.get(&blob_key(CUST_A, stem)).is_none(),
                "A must not resolve B's {stem} blob"
            );
            assert!(
                state.blobs.get(&blob_key(CUST_B, stem)).is_some(),
                "B resolves its own {stem} blob"
            );
        }
    }

    /// `/account/<venue>` dispatch: any venue outside the {binance, okx}
    /// allow-list must return bad_request *without* touching the enclave or
    /// blob state. asterdex is the intentional exclusion (on-chain pattern;
    /// marketplace owns the parser shape).
    #[tokio::test]
    async fn get_account_rejects_unsupported_venues() {
        use crate::state::EnclaveTarget;
        let state = AppState::new(
            std::collections::HashMap::new(),
            EnclaveTarget { cid: 0, port: 0 },
        );
        for bad in ["asterdex", "kucoin", "bybit", "hyperliquid_main", "unknown"] {
            let resp = get_account(
                Path(bad.to_owned()),
                State(state.clone()),
                Extension(ResolvedCustomer(
                    crate::state::DEFAULT_CUSTOMER_ID.to_owned(),
                )),
                Extension(RawToken("op-tok".to_owned())),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "venue {bad} must dispatch to bad_request before any enclave call"
            );
        }
    }

    #[test]
    fn now_ms_is_after_2024() {
        // Sanity: now_ms returns ms since epoch and we're past 2024.
        // 2024-01-01 = 1704067200 sec = 1.7e12 ms.
        assert!(now_ms() > 1_704_067_200_000);
    }
}
