//! axum HTTP handlers for the signer gateway.
//!
//! Endpoints:
//!   - `POST /sign`      — main signing endpoint.
//!   - `GET  /healthz`   — liveness probe; succeeds if a vsock ping
//!                         round-trip completes within ~1s.
//!
//! Both handlers go through `vsock::round_trip`. The gateway never touches
//! the secret directly — it forwards the encrypted blob and AWS creds to
//! the enclave and returns whatever the enclave produces.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::proto::{
    enclave_action_for, err_code, http_status_for, timestamp_in_window, ErrorResponse,
    HealthResponse, SignHttpRequest, SignHttpResponse, ALLOWED_EXCHANGES,
};
use crate::state::AppState;
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
fn error_response(code: &str) -> Response {
    let status =
        StatusCode::from_u16(http_status_for(code)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(ErrorResponse::new(code))).into_response()
}

/// `POST /sign` — request a fresh KuCoin v2 auth header set from the enclave.
pub async fn post_sign(
    State(state): State<AppState>,
    Json(req): Json<SignHttpRequest>,
) -> Response {
    let started = Instant::now();
    let path_for_log = req.path.clone(); // path is not a secret; body is.
    let exchange_for_log = req.exchange.clone();
    let method_for_log = req.method.clone();

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

    // 3. Pull a fresh STS-credential copy from the cache (refreshes from
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

    // 4. Look up the action + ciphertext blob for this exchange.
    //
    // HMAC venues pass `kind = None` and resolve to a single action per
    // exchange. EIP-712 venues like `hyperliquid_main` look at `kind` to
    // pick `order` vs `cancel` — missing/unknown kind returns BAD_REQUEST
    // because the request truly is malformed (we can't sign without
    // knowing which action template to commit to).
    let action = match enclave_action_for(&req.exchange, req.kind.as_deref()) {
        Some(a) => a,
        None if req.exchange == "hyperliquid_main" => {
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

    let blob = match state.blobs.get(&req.exchange) {
        Some(b) => b,
        None => {
            // Operator did not stage a blob for this exchange. Surface as
            // bad_request so the caller knows the exchange is not configured
            // on this gateway, but don't say WHY (operational detail).
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
        ciphertext_blob_base64: Some(B64.encode(blob.as_slice())),
        query: query_for_enclave,
        // Phase 1 Stage 2 — EIP-712 fields. Forwarded verbatim for
        // Hyperliquid family, `None` for HMAC venues. The enclave
        // validates presence/shape per action; the gateway just forwards.
        hl_action: req.action.clone(),
        nonce: req.nonce,
        vault_address: req.vault_address.clone(),
    };

    // 7. Round-trip to the enclave over vsock.
    let vsock_started = Instant::now();
    let resp = vsock::round_trip(state.enclave.cid, state.enclave.port, &vsock_req).await;
    let vsock_latency_ms = vsock_started.elapsed().as_millis() as u64;

    let resp = match resp {
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

    // 8. Translate the enclave's response into HTTP shape.
    if let Some(code) = resp.error.as_deref() {
        info!(
            event = "enclave_response",
            success = false,
            error_code = code,
            vsock_latency_ms = vsock_latency_ms
        );
        // Map the wire code; unknown codes fall through to internal_error.
        let mapped = match code {
            err_code::BAD_REQUEST => err_code::BAD_REQUEST,
            err_code::PAYLOAD_TOO_LARGE => err_code::PAYLOAD_TOO_LARGE,
            err_code::KMS_DECRYPT_DENIED => err_code::KMS_DECRYPT_DENIED,
            _ => err_code::INTERNAL_ERROR,
        };
        return finish_log(error_response(mapped), started, false, Some(mapped));
    }

    // Phase 1 Stage 2 — split success path: EIP-712 venues populate
    // `hl_signature`; HMAC venues populate `headers`. Either one (but not
    // both) must be set for a successful response.
    if let Some(sig) = resp.hl_signature {
        info!(
            event = "enclave_response",
            success = true,
            vsock_latency_ms,
            shape = "eip712"
        );
        let http_sig = crate::proto::HlSignatureWire {
            r: sig.r,
            s: sig.s,
            v: sig.v,
        };
        return finish_log(
            (
                StatusCode::OK,
                Json(SignHttpResponse {
                    headers: std::collections::BTreeMap::new(),
                    signature: Some(http_sig),
                }),
            )
                .into_response(),
            started,
            true,
            None,
        );
    }

    let headers = match resp.headers {
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
pub async fn get_healthz(State(state): State<AppState>) -> Response {
    let req = VsockRequest {
        action: "ping".to_owned(),
        method: None,
        path: None,
        body: None,
        timestamp_ms: None,
        aws_credentials: None,
        ciphertext_blob_base64: None,
        query: None,
        hl_action: None,
        nonce: None,
        vault_address: None,
    };
    match vsock::round_trip(state.enclave.cid, state.enclave.port, &req).await {
        Ok(resp) if resp.signature_base64 == "pong" && resp.error.is_none() => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                enclave_cid: state.enclave.cid,
                enclave_port: state.enclave.port,
            }),
        )
            .into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new(err_code::ENCLAVE_UNREACHABLE)),
        )
            .into_response(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ms_is_after_2024() {
        // Sanity: now_ms returns ms since epoch and we're past 2024.
        // 2024-01-01 = 1704067200 sec = 1.7e12 ms.
        assert!(now_ms() > 1_704_067_200_000);
    }
}
