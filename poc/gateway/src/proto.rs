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
/// `kucoin`            — KuCoin Spot (Day 3, live).
/// `binance`           — Binance Spot (Phase 1 Week 4).
/// `binance_futures`   — Binance USDT-M Futures (Phase 1 Week 4).
/// `bybit`             — Bybit V5 unified (Phase 1 Week 4).
/// `okx`               — OKX V5 unified (Phase 1 Stage 1, 2026-05-10).
/// `hyperliquid_main`  — Hyperliquid mainnet DEX, EIP-712 family
///                       (Phase 1 Stage 2, 2026-05-11). HIP-3 deployer
///                       venues (xyz/km/cash/etc) follow as separate
///                       per-venue entries.
pub const ALLOWED_EXCHANGES: &[&str] = &[
    "kucoin",
    "binance",
    "binance_futures",
    "bybit",
    "okx",
    "hyperliquid_main",
    "asterdex",
];

/// Map an `(exchange, kind)` pair to the enclave-side action string.
///
/// HMAC venues only have one signing flow per request (the action is
/// implicit in the canonical-string assembly), so `kind` is ignored.
/// EIP-712 venues like `hyperliquid_main` have multiple distinct actions
/// (`order`, `cancel`, future `usdClassTransfer`, etc.) — the gateway
/// reads `kind` from the HTTP request and dispatches to the right
/// enclave action.
///
/// Returns `None` if the exchange is not registered or the kind is not
/// supported for that exchange.
pub fn enclave_action_for(exchange: &str, kind: Option<&str>) -> Option<&'static str> {
    match exchange {
        "kucoin" => Some("sign_kucoin"),
        "binance" | "binance_futures" => Some("sign_binance"),
        "bybit" => Some("sign_bybit"),
        "okx" => Some("sign_okx"),
        "hyperliquid_main" => match kind {
            Some("order") => Some("sign_hyperliquid_main_order"),
            Some("cancel") => Some("sign_hyperliquid_main_cancel"),
            _ => None,
        },
        "asterdex" => Some("sign_asterdex"),
        _ => None,
    }
}

/// Inbound HTTP request body for `POST /sign`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignHttpRequest {
    pub exchange: String,
    /// HMAC venues fill this with the HTTP method (`GET`/`POST`/...).
    /// EIP-712 venues like `hyperliquid_main` ignore the field — the
    /// signature commits to the action JSON, not the HTTP request line.
    /// The field stays required (default empty) for backwards compat with
    /// the HMAC-only wire format.
    #[serde(default)]
    pub method: String,
    /// HMAC venues fill this with the API path. Ignored by EIP-712 venues.
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub body: String,
    /// Optional. If absent, gateway substitutes the current epoch time.
    /// If present, it must be within `MAX_TIMESTAMP_SKEW_MS` of the gateway
    /// clock or the request is rejected with `bad_request`.
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// Optional query string for Binance/Bybit/OKX signing (without leading `?`).
    /// KuCoin signs path+body and ignores this. Binance/Bybit sign the query
    /// string separately. OKX merges it back into `requestPath`. The
    /// gateway appends `timestamp`/`recvWindow` before signing where needed.
    #[serde(default)]
    pub query: Option<String>,

    // ──────────── Phase 1 Stage 2 — EIP-712 (Hyperliquid family) ────────────
    /// EIP-712 kind: `"order"` or `"cancel"` for Hyperliquid. Required for
    /// `hyperliquid_main` and ignored for HMAC venues.
    #[serde(default)]
    pub kind: Option<String>,
    /// EIP-712 action JSON forwarded to the enclave verbatim. Required for
    /// `hyperliquid_main`.
    #[serde(default)]
    pub action: Option<serde_json::Value>,
    /// EIP-712 nonce (Unix ms). Required for `hyperliquid_main`. Distinct
    /// from `timestamp_ms` so HMAC and EIP-712 skew windows stay separate.
    #[serde(default)]
    pub nonce: Option<u64>,
    /// EIP-712 optional vault address (`0x` + 40 hex). `None` for the
    /// common non-vault case. Validated as hex inside the enclave; the
    /// gateway just forwards the string.
    #[serde(default)]
    pub vault_address: Option<String>,
}

/// Response for `POST /sign` on success.
///
/// HMAC venues populate `headers` and leave `signature` empty.
/// EIP-712 venues (`hyperliquid_main`) populate `signature` and leave
/// `headers` empty.
#[derive(Debug, Clone, Serialize)]
pub struct SignHttpResponse {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HlSignatureWire>,
}

/// `(r, s, v)` triple for EIP-712 venues. JSON shape matches what the
/// Hyperliquid HTTP API expects under `body.signature`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HlSignatureWire {
    pub r: String,
    pub s: String,
    pub v: u8,
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
    let delta = now_ms.abs_diff(ts_ms);
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
        assert_eq!(req.body, "{\"clientOid\":\"x\"}");
        assert_eq!(req.timestamp_ms, Some(1714997000000));
    }

    #[test]
    fn allowed_exchanges_covers_all_supported() {
        assert_eq!(
            ALLOWED_EXCHANGES,
            &[
                "kucoin",
                "binance",
                "binance_futures",
                "bybit",
                "okx",
                "hyperliquid_main",
                "asterdex",
            ]
        );
    }

    #[test]
    fn enclave_action_routes_correctly() {
        assert_eq!(enclave_action_for("kucoin", None), Some("sign_kucoin"));
        assert_eq!(enclave_action_for("binance", None), Some("sign_binance"));
        assert_eq!(
            enclave_action_for("binance_futures", None),
            Some("sign_binance")
        );
        assert_eq!(enclave_action_for("bybit", None), Some("sign_bybit"));
        assert_eq!(enclave_action_for("okx", None), Some("sign_okx"));
        assert_eq!(
            enclave_action_for("hyperliquid_main", Some("order")),
            Some("sign_hyperliquid_main_order")
        );
        assert_eq!(
            enclave_action_for("hyperliquid_main", Some("cancel")),
            Some("sign_hyperliquid_main_cancel")
        );
        // No kind / unknown kind on EIP-712 venue → None.
        assert_eq!(enclave_action_for("hyperliquid_main", None), None);
        assert_eq!(
            enclave_action_for("hyperliquid_main", Some("approveAgent")),
            None
        );
        // Unknown exchange → None regardless of kind.
        assert_eq!(enclave_action_for("unknown", None), None);
        assert_eq!(enclave_action_for("unknown", Some("order")), None);
    }
}
