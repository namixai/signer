//! HTTP-facing wire types for the signer gateway.
//!
//! Two layers live here:
//!   - The HTTP request shape clients POST to `/sign`.
//!   - The HTTP response shape we return on success / error.
//!
//! Vsock-side types (the enclave's `SignRequest` / `SignResponse`) are
//! defined in `vsock.rs` so the boundary between "HTTP" and "vsock" stays
//! visible at the file level.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum permitted timestamp skew between the gateway clock and a caller-
/// supplied `timestamp_ms`. KuCoin's own server enforces ~5s; we mirror that
/// so a request signed by us is accepted at the venue.
pub const MAX_TIMESTAMP_SKEW_MS: u64 = 5_000;

/// Allow-list of supported exchanges.
/// `kucoin`           — KuCoin Spot (Day 3, live).
/// `binance`          — Binance Spot (Phase 1 Week 4).
/// `binance_futures`  — Binance USDT-M Futures (Phase 1 Week 4).
/// `bybit`            — Bybit V5 unified (Phase 1 Week 4).
/// `okx`              — OKX V5 unified (Phase 1 Stage 1, 2026-05-10).
pub const ALLOWED_EXCHANGES: &[&str] =
    &["kucoin", "binance", "binance_futures", "bybit", "okx"];

/// Map an HTTP-side exchange name to the enclave-side action string.
pub fn enclave_action_for(exchange: &str) -> Option<&'static str> {
    match exchange {
        "kucoin" => Some("sign_kucoin"),
        "binance" | "binance_futures" => Some("sign_binance"),
        "bybit" => Some("sign_bybit"),
        "okx" => Some("sign_okx"),
        _ => None,
    }
}

/// Inbound HTTP request body for `POST /sign`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignHttpRequest {
    pub exchange: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: String,
    /// Optional. If absent, gateway substitutes the current epoch time.
    /// If present, it must be within `MAX_TIMESTAMP_SKEW_MS` of the gateway
    /// clock or the request is rejected with `bad_request`.
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// Optional query string for Binance/Bybit signing (without leading `?`).
    /// KuCoin signs path+body and ignores this. Binance/Bybit sign the query
    /// string separately, so caller must provide user params here. The
    /// gateway appends its own `timestamp`/`recvWindow` before signing.
    #[serde(default)]
    pub query: Option<String>,
}

/// Response for `POST /sign` on success — just the headers map.
#[derive(Debug, Clone, Serialize)]
pub struct SignHttpResponse {
    pub headers: BTreeMap<String, String>,
}

/// Response shape for `POST /sign` errors and similar.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl ErrorResponse {
    pub fn new(code: &str) -> Self {
        Self {
            error: code.to_owned(),
        }
    }
}

/// Response for `GET /healthz` on success.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub enclave_cid: u32,
    pub enclave_port: u32,
}

/// Generic error codes returned to HTTP clients.
///
/// We keep this list short and intentionally vague — the gateway never
/// echoes internal AWS / KMS / vsock error strings to the wire (see the
/// adversarial-mindset notes in the Day 3 brief).
pub mod err_code {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const PAYLOAD_TOO_LARGE: &str = "payload_too_large";
    pub const KMS_DECRYPT_DENIED: &str = "kms_decrypt_denied";
    pub const INTERNAL_ERROR: &str = "internal_error";
    pub const ENCLAVE_UNREACHABLE: &str = "enclave_unreachable";
}

/// Map a wire error code -> HTTP status. Pure function, easy to unit test.
pub fn http_status_for(code: &str) -> u16 {
    match code {
        err_code::BAD_REQUEST => 400,
        err_code::PAYLOAD_TOO_LARGE => 413,
        // We surface KMS denial as 503 (not 403) so the caller cannot tell
        // from the HTTP shape whether the policy denied them or whether
        // KMS is down — the failure modes are operationally equivalent.
        err_code::KMS_DECRYPT_DENIED => 503,
        err_code::ENCLAVE_UNREACHABLE => 503,
        _ => 500,
    }
}

/// Validate that a caller-supplied timestamp is within the accepted window
/// of `now_ms`. Returns `Ok(())` on accept and `Err(())` on reject.
///
/// Both arguments are in milliseconds since the Unix epoch. We use saturating
/// arithmetic so an underflow at the start of the epoch can't cause a wrap.
pub fn timestamp_in_window(now_ms: u64, ts_ms: u64) -> Result<(), ()> {
    let delta = if now_ms > ts_ms {
        now_ms - ts_ms
    } else {
        ts_ms - now_ms
    };
    if delta <= MAX_TIMESTAMP_SKEW_MS {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_mapping_covers_known_codes() {
        assert_eq!(http_status_for(err_code::BAD_REQUEST), 400);
        assert_eq!(http_status_for(err_code::PAYLOAD_TOO_LARGE), 413);
        assert_eq!(http_status_for(err_code::KMS_DECRYPT_DENIED), 503);
        assert_eq!(http_status_for(err_code::ENCLAVE_UNREACHABLE), 503);
        assert_eq!(http_status_for(err_code::INTERNAL_ERROR), 500);
    }

    #[test]
    fn http_status_for_unknown_code_is_500() {
        assert_eq!(http_status_for("totally_made_up_code"), 500);
    }

    #[test]
    fn timestamp_in_window_accepts_exact() {
        assert!(timestamp_in_window(1_000_000, 1_000_000).is_ok());
    }

    #[test]
    fn timestamp_in_window_accepts_within_5s() {
        assert!(timestamp_in_window(1_000_000, 1_000_000 + 4_999).is_ok());
        assert!(timestamp_in_window(1_000_000 + 4_999, 1_000_000).is_ok());
        assert!(timestamp_in_window(1_000_000, 1_000_000 + 5_000).is_ok());
    }

    #[test]
    fn timestamp_in_window_rejects_outside_5s() {
        assert!(timestamp_in_window(1_000_000, 1_000_000 + 5_001).is_err());
        assert!(timestamp_in_window(1_000_000 + 5_001, 1_000_000).is_err());
    }

    #[test]
    fn http_request_parses_minimal_body() {
        let json = r#"{"exchange":"kucoin","method":"GET","path":"/api/v1/accounts"}"#;
        let req: SignHttpRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.exchange, "kucoin");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/v1/accounts");
        assert_eq!(req.body, "");
        assert!(req.timestamp_ms.is_none());
    }

    #[test]
    fn http_request_parses_full_body() {
        let json = r#"{
            "exchange":"kucoin",
            "method":"POST",
            "path":"/api/v1/orders",
            "body":"{\"clientOid\":\"x\"}",
            "timestamp_ms":1714997000000
        }"#;
        let req: SignHttpRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.exchange, "kucoin");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v1/orders");
        assert!(req.body.contains("clientOid"));
        assert_eq!(req.timestamp_ms, Some(1714997000000));
    }

    #[test]
    fn allowed_exchanges_covers_all_supported() {
        assert_eq!(
            ALLOWED_EXCHANGES,
            &["kucoin", "binance", "binance_futures", "bybit", "okx"]
        );
    }

    #[test]
    fn enclave_action_routes_correctly() {
        assert_eq!(enclave_action_for("kucoin"), Some("sign_kucoin"));
        assert_eq!(enclave_action_for("binance"), Some("sign_binance"));
        assert_eq!(enclave_action_for("binance_futures"), Some("sign_binance"));
        assert_eq!(enclave_action_for("bybit"), Some("sign_bybit"));
        assert_eq!(enclave_action_for("okx"), Some("sign_okx"));
        assert_eq!(enclave_action_for("unknown"), None);
    }
}
