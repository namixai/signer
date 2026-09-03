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
// Zeroize on the HTTP-side HlSignatureWire so the EIP-712 r,s strings
// that travel from HlSignatureVsock (via std::mem::take) are wiped when
// the HTTP response drops. Gemini PR #30 round-2 L281 catch.
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    // HL TESTNET (source="b", api.hyperliquid-testnet.xyz) — a separate venue
    // from mainnet, with its own sealed agent-wallet blob and its own grant.
    "hyperliquid_testnet",
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
        // HL TESTNET (source="b") — the ALLOWED demo path; same kinds as mainnet.
        "hyperliquid_testnet" => match kind {
            Some("order") => Some("sign_hyperliquid_testnet_order"),
            Some("cancel") => Some("sign_hyperliquid_testnet_cancel"),
            _ => None,
        },
        "asterdex" => Some("sign_asterdex"),
        _ => None,
    }
}

/// Fund-moving action kinds that the signer must NEVER sign. The enclave only
/// ever produces order/cancel signatures, so any withdrawal- OR transfer-class
/// kind is rejected up-front (as `policy_denied`) before it can reach the
/// enclave. This is the custody moat: even a fully compromised caller cannot
/// request a signature that would move funds out of — or between — the
/// account's balances. Matched case-sensitively against the venue-native action
/// `type` names:
///   - withdrawals / peer sends: `withdraw` / `withdraw3` / `withdrawal`,
///     `usdSend` / `spotSend`, `cWithdraw` (HL cold-wallet withdraw);
///   - internal transfers (still fund movement — denied fail-closed, Gemini
///     #215 HIGH): `usdClassTransfer` (spot↔perp), `vaultTransfer`,
///     `subAccountTransfer`, `hip3LiquidatorTransfer`.
pub fn is_withdrawal_kind(kind: Option<&str>) -> bool {
    matches!(
        kind,
        Some(
            "withdraw"
                | "withdraw3"
                | "withdrawal"
                | "usdSend"
                | "spotSend"
                | "usdClassTransfer"
                | "vaultTransfer"
                | "subAccountTransfer"
                | "hip3LiquidatorTransfer"
                | "cWithdraw"
        )
    )
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
///
/// Gemini PR #30 round-5 HIGH: this struct is the destination of
/// `VsockResponse.headers.take()` — moving the BTreeMap out of the
/// zeroizing VsockResponse into here would leak HMAC header values
/// (KC-API-SIGN etc.) once axum serializes and drops SignHttpResponse.
/// Manual Drop below wipes the BTreeMap value strings, matching the
/// behaviour on VsockResponse.
#[derive(Clone, Serialize)]
pub struct SignHttpResponse {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HlSignatureWire>,
    /// The enclave's signed decision receipt for this allow (receipt.rs);
    /// absent before the receipt epoch starts on this enclave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

impl std::fmt::Debug for SignHttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignHttpResponse")
            .field(
                "headers",
                &format!("[REDACTED {} headers]", self.headers.len()),
            )
            .field("signature", &self.signature.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl Drop for SignHttpResponse {
    /// Wipe HMAC header VALUES on drop (KC-API-SIGN, KC-API-PASSPHRASE).
    /// `signature` is HlSignatureWire (ZeroizeOnDrop) — wipes itself.
    /// Gemini PR #30 round-5 HIGH catch.
    fn drop(&mut self) {
        for v in self.headers.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

/// `(r, s, v)` triple for EIP-712 venues. JSON shape matches what the
/// Hyperliquid HTTP API expects under `body.signature`.
///
/// Zeroize + ZeroizeOnDrop so the r,s bytes are wiped when the HTTP
/// response drops — they were moved into this struct from the zeroizing
/// HlSignatureVsock via std::mem::take and would otherwise persist in
/// heap memory through the axum response serialization phase. Gemini
/// PR #30 round-2 L281 catch.
///
/// Manual Debug to keep the same redaction policy as HlSignatureVsock.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HlSignatureWire {
    pub r: String,
    pub s: String,
    pub v: u8,
}

impl std::fmt::Debug for HlSignatureWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HlSignatureWire")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .field("v", &self.v)
            .finish()
    }
}

/// Path B-lite (Stage 4 pre-flight) input shape for `POST /verify-blob`.
/// One venue per request; the script wrapper iterates the 6 venues.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct VerifyBlobRequest {
    pub venue_id: String,
}

/// Successful response shape for `POST /verify-blob`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct VerifyBlobResponse {
    pub ok: bool,
    pub venue_id: String,
    pub plaintext_sha256: String,
    pub plaintext_len: Option<u64>,
    /// Wall-clock at which the gateway received the enclave's response.
    /// Epoch milliseconds — operator-side script formats as needed.
    pub decrypted_at_epoch_ms: u64,
}

/// Response shape for `GET /attestation` (signer-mcp `get_attestation` proof
/// tool). H5: `pcr0_sha384` is now parsed OUT of the NSM-signed COSE document
/// (`attestation_doc_b64`) and cross-checked against the `SIGNER_PCR0` deploy
/// env — a mismatch fails the request rather than serving a stale/forged value.
/// The document is the source of truth; the legacy `pcr0_sha384`/
/// `registered_onchain` fields stay for backward-compatible callers.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AttestationResponse {
    /// PCR0 (SHA-384 of the enclave image) as 96-char lowercase hex. H5: parsed
    /// from the COSE document's `pcrs[0]`, cross-checked against `SIGNER_PCR0`.
    pub pcr0_sha384: String,
    /// H5: base64 of the NSM-signed COSE_Sign1 attestation document (AWS Nitro
    /// Attestation PKI). The caller verifies it against the Nitro root cert (see
    /// README) and reads PCR0 / nonce / cert chain from it. `None` only if the
    /// enclave NSM fetch is unavailable (never on a healthy prod enclave).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_doc_b64: Option<String>,
    /// H5: the caller nonce echoed back (hex), bound INTO the COSE document for
    /// anti-replay. `None` when the caller supplied no `?nonce=`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// True once the operator has registered this PCR0 on the Base registry
    /// (the cutover flow does this). Sourced from `SIGNER_PCR0_ONCHAIN`.
    pub registered_onchain: bool,
    /// Attested-signed-data (P2): the data-signing pubkey in BOTH wire forms
    /// (compressed secp256k1 + ETH address). Buyers pin these and ecrecover the
    /// signer. `None` until the data key is provisioned + `SIGNER_DATA_PUBKEY` set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_pubkey_compressed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_pubkey_address: Option<String>,
    /// Epoch milliseconds when the origin generated this response. H5:
    /// `/attestation` now carries `Cache-Control: no-store` (no edge cache), and
    /// true freshness is proven by the caller `nonce` bound into the COSE doc —
    /// this field stays informational (do NOT treat it as a liveness clock).
    pub timestamp_ms: u64,
}

/// Inbound body for `POST /sign-data` (operator-gated, attested-signed-data P2).
///
/// `data` is the RAW JSON TEXT of the read-only market-data payload, forwarded
/// to the enclave VERBATIM (never parsed/re-serialized here) so the enclave's
/// duplicate-key rejection and the buyer's byte-exact canonical recompute both
/// operate on the producer's original bytes. The marketplace produces these
/// bytes (the exact bytes it will serve buyers) and the buyer recomputes
/// canonical-v1 over them. Public market data only — no key material.
#[derive(Debug, Clone, Deserialize)]
pub struct SignDataRequest {
    pub data: String,
}

/// `POST /sign-data` success body: the recoverable secp256k1 signature plus the
/// data-signing public key in BOTH wire forms. A buyer ecrecovers the signer
/// from `keccak256(domain ‖ canonical-v1(data))` + `signature` and asserts the
/// recovered address == `pubkey_address` (also pinned from `/attestation`).
#[derive(Clone, Serialize)]
pub struct SignDataHttpResponse {
    pub signature: HlSignatureWire,
    pub pubkey_compressed: String,
    pub pubkey_address: String,
}

/// One signed venue-native read request (Option A pattern). signer-mcp
/// `fetch(url, {method, headers})` and parses the response. Used as a
/// composite leaf inside `AccountOkxResponse` (balance + positions).
#[derive(Clone, Debug, serde::Serialize)]
pub struct SignedReadRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

/// `GET /account/binance` response — single signed read (USD-M Futures
/// `/fapi/v2/account`). The HMAC `signature` value is embedded in the URL
/// query (per Binance's signing scheme) and stripped from `headers`; only
/// `X-MBX-APIKEY` rides as a real header.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AccountBinanceResponse {
    pub venue: &'static str,
    pub method: &'static str,
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

/// `GET /account/okx` response — composite (A1 per marketplace coordination):
/// OKX splits balance + positions into two endpoints, both signed in one shot
/// here so the MCP can fire them in parallel without a second round-trip to
/// the gateway. Each leaf is `{method, url, headers}`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AccountOkxResponse {
    pub venue: &'static str,
    pub balance: SignedReadRequest,
    pub positions: SignedReadRequest,
}

/// `GET /open-orders/:venue` (signed enumerate — lets an agent reconcile orders
/// it lost the id for) and `POST /cancel-all/:venue` (signed mass-cancel)
/// response — a single signed venue-native request (Option A): the signer returns
/// the signed `{method, url, headers}`; the MCP/client executes it and parses the
/// venue's reply (zero-egress — the gateway never calls the venue). Reuses the
/// GENERIC `sign_binance` / `sign_okx` enclave action (no new enclave code / no
/// PCR0 change): Binance embeds the HMAC `signature` in the URL query and carries
/// only `X-MBX-APIKEY` as a header; OKX carries `OK-ACCESS-SIGN` et al. in headers.
// No `Clone`: `Json(..)` consumes the value, so a clone is never needed — and a
// derived field-by-field Clone would make an un-zeroized heap copy that outlives
// the original's `Drop` (a secret-hygiene footgun).
#[derive(serde::Serialize)]
pub struct SignedVenueRequest {
    pub venue: &'static str,
    pub method: &'static str,
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

impl std::fmt::Debug for SignedVenueRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Unlike the structured order responses (signature in `body`, clean `url`),
        // here the Binance HMAC `signature` rides in the `url` query and the
        // `headers` carry X-MBX-APIKEY / OK-ACCESS-SIGN — redact BOTH. The path is
        // already in the structured request logs, so nothing debuggable is lost.
        f.debug_struct("SignedVenueRequest")
            .field("venue", &self.venue)
            .field("method", &self.method)
            .field("url", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignedVenueRequest {
    /// Wipe the signed `url` (Binance `&signature=<hex>`) and every header VALUE
    /// (X-MBX-APIKEY / OK-ACCESS-SIGN/-KEY/-PASSPHRASE) on drop — defense-in-depth
    /// so signed material doesn't linger in freed gateway memory after the
    /// response is serialized (mirrors `SignBinanceOrderResponse`/`SignOkxResponse`).
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.url);
        for v in self.headers.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

/// x402 / EIP-3009 payment-authorization params for `POST /sign-x402`. Mirrors
/// the enclave's `X402Request` field-for-field; serialized verbatim into the
/// vsock request's `x402` object (the enclave re-deserializes into its typed
/// struct). `value` is a decimal uint256 string; `nonce` a `0x`-bytes32.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct X402Params {
    pub token_name: String,
    pub token_version: String,
    pub chain_id: u64,
    pub token_address: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: String,
}

/// Input shape for `POST /sign-x402`. `key_id` selects the provisioned payer
/// key blob (loaded into the gateway like a venue blob); the enclave verifies
/// `x402.from` equals that key's address before signing.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SignX402Request {
    pub key_id: String,
    pub x402: X402Params,
}

/// Successful response shape for `POST /sign-x402`.
///
/// Gemini #75 HIGH: `signature` is sensitive (a spendable payment
/// authorization) — `Zeroize, ZeroizeOnDrop` wipes it after axum serializes
/// the response, matching `HlSignatureWire`. `ok`/`from` are public metadata
/// (skip). Manual `Debug` redacts the signature so a stray `?resp` log can't
/// leak it.
#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct SignX402Response {
    #[zeroize(skip)]
    pub ok: bool,
    /// 0x-prefixed 65-byte r||s||v signature for the EIP-3009 authorization.
    pub signature: String,
    /// The payer address the enclave signed as (derived from the key).
    #[zeroize(skip)]
    pub from: String,
    /// The enclave's signed decision receipt for this allow (receipt.rs);
    /// absent before the receipt epoch starts on this enclave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub receipt: Option<serde_json::Value>,
}

impl std::fmt::Debug for SignX402Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignX402Response")
            .field("ok", &self.ok)
            .field("signature", &"[REDACTED]")
            .field("from", &self.from)
            .finish()
    }
}

/// Structured perp-order params (the gateway forwards verbatim to the enclave,
/// which deserializes into its typed `OrderRequest`, applies the policy cap,
/// and builds the canonical signed-string INSIDE the enclave). Mirrors the
/// enclave's `proto::OrderRequest` field-for-field.
///
/// `deny_unknown_fields` HERE, not just in the enclave: the gateway
/// re-serializes this TYPED struct toward the enclave, so without it a typo'd
/// caller field (`reduceOnly`, `ordType`) would be silently dropped at this
/// boundary and the enclave's own deny_unknown_fields could never see it —
/// flipping order semantics (e.g. reduce_only defaulting to false) without
/// any error (adversarial review 2026-06-11 #12).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderParams {
    pub symbol: String,
    pub side: String,
    pub qty: String,
    pub ord_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    #[serde(default)]
    pub reduce_only: bool,
}

/// Same dropped-typo'd-field rationale as `OrderParams`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelParams {
    pub symbol: String,
    pub order_id: String,
}

/// `POST /sign/binance-order` input. `key_id` selects the binance API-key blob;
/// `order` carries the structured params.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SignBinanceOrderRequest {
    pub key_id: String,
    pub order: OrderParams,
    /// AF-2: the agent-authored timestamp bound into the signed intent. Required
    /// when the policy enables intent enforcement (the enclave reconstructs over
    /// it); ignored otherwise (gateway falls back to `now_ms()`).
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// AF-2: the agent's Ed25519 signature (hex) over the canonical order intent.
    #[serde(default)]
    pub intent_signature: Option<String>,
}

/// `POST /sign/binance-cancel` input.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SignBinanceCancelRequest {
    pub key_id: String,
    pub cancel: CancelParams,
    /// AF-2: agent-authored timestamp bound into the signed cancel intent.
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// AF-2: the agent's Ed25519 signature (hex) over the canonical cancel intent.
    #[serde(default)]
    pub intent_signature: Option<String>,
    /// AF-2: per-intent replay nonce (UUID) — cancels have no client_order_id.
    #[serde(default)]
    pub intent_nonce: Option<String>,
}

/// `POST /sign/binance-order` response. `body` is the EXACT
/// form-urlencoded body (incl `&signature=<hex>`) the MCP must POST to the
/// venue verbatim. `headers` carries `X-MBX-APIKEY` + `Content-Type`.
///
/// Gemini #78: manual `Drop` zeroizes `body` + every header VALUE (X-MBX-APIKEY
/// is the long-lived secret here). The `Zeroize`-derive route fails for
/// `BTreeMap<String,String>` (no `Zeroize` impl on the map type), so we use
/// the same manual-Drop pattern as `SignHttpResponse`.
#[derive(Clone, Serialize)]
pub struct SignBinanceOrderResponse {
    pub venue: &'static str,
    pub method: &'static str,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// The enclave's signed decision receipt for this allow (receipt.rs);
    /// absent before the receipt epoch starts on this enclave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

impl std::fmt::Debug for SignBinanceOrderResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignBinanceOrderResponse")
            .field("venue", &self.venue)
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignBinanceOrderResponse {
    /// Wipe the form-urlencoded body (contains `&signature=<hex>`) and every
    /// header VALUE (X-MBX-APIKEY) on drop. `url` is just the base + path —
    /// no secret material — skip.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.body);
        for v in self.headers.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

/// `POST /sign/binance-request` input — the keyless generic primitive. `key_id`
/// selects the binance API-key blob; `op` is the allow-listed operation
/// (`account` / `order` / `cancel` / …); `payload` is the EXACT urlencoded param
/// string to HMAC (params + timestamp, NO signature). The enclave allow-lists
/// `op`'s params, enforces the blob policy, and signs `payload` byte-for-byte.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SignBinanceRequestHttp {
    pub key_id: String,
    pub op: String,
    pub payload: String,
}

/// `POST /sign/binance-request` response: the hex HMAC `signature` the client
/// appends to its request, plus the transient `api_key` (X-MBX-APIKEY header).
/// The keyless bot holds no key on disk — it sets both from this response.
/// Manual Drop wipes both on drop (same pattern as `SignBinanceOrderResponse`).
#[derive(Clone, Serialize)]
pub struct SignBinanceRequestResponse {
    pub signature: String,
    pub api_key: String,
    /// The enclave's signed decision receipt for this allow (receipt.rs);
    /// absent before the receipt epoch starts on this enclave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

impl std::fmt::Debug for SignBinanceRequestResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignBinanceRequestResponse")
            .field("signature", &"[REDACTED]")
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignBinanceRequestResponse {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.signature);
        zeroize::Zeroize::zeroize(&mut self.api_key);
    }
}

/// `POST /sign/binance-cancel` response. Cancel is `DELETE` with everything in
/// the URL querystring (including the signature); no body.
///
/// Gemini #78: manual `Drop` zeroizes the URL (querystring carries the
/// signature) and every header VALUE (X-MBX-APIKEY).
#[derive(Clone, Serialize)]
pub struct SignBinanceCancelResponse {
    pub venue: &'static str,
    pub method: &'static str,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    /// The enclave's signed decision receipt for this allow (receipt.rs);
    /// absent before the receipt epoch starts on this enclave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

impl std::fmt::Debug for SignBinanceCancelResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignBinanceCancelResponse")
            .field("venue", &self.venue)
            .field("method", &self.method)
            .field("url", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignBinanceCancelResponse {
    /// The cancel URL embeds the signed querystring (`&signature=<hex>`); wipe
    /// it alongside the X-MBX-APIKEY header value.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.url);
        for v in self.headers.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

/// `POST /sign/okx-order` input. Same `OrderParams` shape as Binance — the
/// enclave's `deny_unknown_fields` `OrderRequest` is the schema check.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SignOkxOrderRequest {
    pub key_id: String,
    pub order: OrderParams,
    /// AF-2: agent-authored timestamp bound into the signed intent.
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// AF-2: the agent's Ed25519 signature (hex) over the canonical order intent.
    #[serde(default)]
    pub intent_signature: Option<String>,
}

/// `POST /sign/okx-cancel` input.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SignOkxCancelRequest {
    pub key_id: String,
    pub cancel: CancelParams,
    /// AF-2: agent-authored timestamp bound into the signed cancel intent.
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// AF-2: the agent's Ed25519 signature (hex) over the canonical cancel intent.
    #[serde(default)]
    pub intent_signature: Option<String>,
    /// AF-2: per-intent replay nonce (UUID) — cancels have no client_order_id.
    #[serde(default)]
    pub intent_nonce: Option<String>,
}

/// `POST /sign/okx-order` and `POST /sign/okx-cancel` response. OKX cancel
/// uses POST (not DELETE) with a JSON body, so both endpoints have the same
/// shape: `{venue, method:"POST", url, headers, body}`. `body` is the EXACT
/// JSON byte-string the enclave signed — the MCP MUST send it verbatim
/// (no parse+re-stringify) or the OK-ACCESS-SIGN HMAC will mismatch.
///
/// Gemini #78 zeroize fix (applied here for #79 too): manual `Drop` zeroizes
/// `body` (signed JSON) + every header VALUE (OK-ACCESS-KEY/SIGN/PASSPHRASE
/// are all secret-material). The `Zeroize`-derive route can't reach the
/// `BTreeMap<String,String>` values.
#[derive(Clone, Serialize)]
pub struct SignOkxResponse {
    pub venue: &'static str,
    pub method: &'static str,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// The enclave's signed decision receipt for this allow (receipt.rs);
    /// absent before the receipt epoch starts on this enclave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

impl std::fmt::Debug for SignOkxResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignOkxResponse")
            .field("venue", &self.venue)
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignOkxResponse {
    /// Wipe the signed body and every header VALUE — OK-ACCESS-SIGN,
    /// OK-ACCESS-KEY, and OK-ACCESS-PASSPHRASE are all sensitive. `url` is
    /// the constant venue endpoint (no signature) — skip.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.body);
        for v in self.headers.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

/// Response shape for `POST /sign` errors and similar.
///
/// explainable-denials (2026-07-10): structured so a design-partner SDK can tell
/// WHY a call was denied and self-correct. `error` is the raw wire code (kept for
/// back-compat); `denied`/`reason_code`/`rule_class` are the explainable layer.
/// NO-LEAK: every field is a static class string — never a value, threshold, or
/// allow-list content (those stay in operator logs only).
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// True for a policy/rate/auth/attestation DENIAL; false for a request-shape
    /// or infra error (bad_request, internal_error, …).
    pub denied: bool,
    /// Machine-readable failure CLASS. Equals the wire code for a known class;
    /// an unmapped (but allow-listed) code fail-closes to `policy_denied`.
    pub reason_code: String,
    /// Coarse category: policy | rate | auth | attestation | request | infra.
    pub rule_class: String,
    /// Raw wire code (existing SDK field — unchanged for back-compat).
    pub error: String,
    /// WHICH LAYER decided: `enclave` when this response was built from an
    /// enclave reply (`from_enclave`), `gateway` when the gateway refused on its
    /// own (`new`).
    ///
    /// Without this field the layer was not determinable from a response at all:
    /// `rule_class: "policy"` is set by the gateway's classifier and says nothing
    /// about who ruled. An attested-looking denial could have been decided
    /// outside the attested boundary, and a reader had no way to tell.
    pub decided_by: &'static str,
    /// The enclave's signed decision receipt, when one was issued
    /// (`enclave/src/receipt.rs`). Verify it against the `public_key` carried by
    /// the attestation document — that is what makes an enclave-decided refusal
    /// checkable without trusting us.
    ///
    /// Absent by construction on gateway-decided denials, and absent before the
    /// receipt epoch starts on an enclave (no resident key → no receipts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

impl ErrorResponse {
    /// A denial the GATEWAY decided on its own (auth, tenant state, limits,
    /// request shape, its withdrawal pre-check). No receipt by construction.
    pub fn new(code: &str) -> Self {
        let (denied, reason_code, rule_class) = denial_meta(code);
        Self {
            denied,
            reason_code: reason_code.to_owned(),
            rule_class: rule_class.to_owned(),
            error: code.to_owned(),
            decided_by: "gateway",
            receipt: None,
        }
    }

    /// A denial mapped from an ENCLAVE reply, carrying the receipt it came with.
    pub fn from_enclave(code: &str, receipt: Option<serde_json::Value>) -> Self {
        let mut r = Self::new(code);
        r.decided_by = "enclave";
        r.receipt = receipt;
        r
    }
}

/// explainable-denials classifier: wire code → `(denied, reason_code, rule_class)`
/// for the structured body. Pure, total, and NO-LEAK (outputs are static class
/// strings only). Kept byte-in-lockstep with `http_status_for` below.
///
/// Tiers (per CR037 reconciliation, CTO 2026-07-10):
///   1. known denial class     → its own `reason_code` + category.
///   2. allow-listed-but-unmapped code → fail-closed generic `policy_denied`/403.
///   3. NOT allow-listed        → already collapsed to `internal_error` upstream
///      by `safe_wire_code` → hits the `internal_error` arm here (infra/500).
///
/// So a forgotten/rogue code never leaks a raw "reason" and never reads as a 500
/// denial: real infra errors are `denied:false`, everything else fail-closes to
/// a 403 policy denial.
pub fn denial_meta(code: &str) -> (bool, &'static str, &'static str) {
    match code {
        err_code::ACTION_NOT_ALLOWED => (true, err_code::ACTION_NOT_ALLOWED, "policy"),
        err_code::SIZE_OVER_CAP => (true, err_code::SIZE_OVER_CAP, "policy"),
        err_code::NOTIONAL_OVER_CAP => (true, err_code::NOTIONAL_OVER_CAP, "policy"),
        err_code::WITHDRAWAL_NOT_SIGNABLE => (true, err_code::WITHDRAWAL_NOT_SIGNABLE, "policy"),
        err_code::POLICY_DENIED => (true, err_code::POLICY_DENIED, "policy"),
        err_code::POLICY_REQUIRED => (true, err_code::POLICY_REQUIRED, "policy"),
        err_code::CONTEXT_REQUIRED => (true, err_code::CONTEXT_REQUIRED, "policy"),
        err_code::UNIMPLEMENTED_POLICY_FIELD => {
            (true, err_code::UNIMPLEMENTED_POLICY_FIELD, "policy")
        }
        err_code::RATE_LIMITED => (true, err_code::RATE_LIMITED, "rate"),
        err_code::DAILY_CAP => (true, err_code::DAILY_CAP, "rate"),
        err_code::UNAUTHORIZED => (true, err_code::UNAUTHORIZED, "auth"),
        err_code::KMS_DECRYPT_DENIED => (true, err_code::KMS_DECRYPT_DENIED, "attestation"),
        // Non-denial: request-shape / infra. `denied:false`.
        err_code::BAD_REQUEST => (false, err_code::BAD_REQUEST, "request"),
        err_code::PAYLOAD_TOO_LARGE => (false, err_code::PAYLOAD_TOO_LARGE, "request"),
        err_code::VERIFY_FAILED => (false, err_code::VERIFY_FAILED, "infra"),
        // NOT a denial: the enclave has no resident receipt key, so it issues
        // no heartbeats. Without this arm the default-deny fallback would
        // report `denied: true` / `policy_denied` / `rule_class: "policy"` — a
        // provisioning gap dressed as an attested policy refusal, which is the
        // exact confusion the explainable layer exists to remove
        // (CodeRabbit, #668).
        err_code::RECEIPTS_UNAVAILABLE => (false, err_code::RECEIPTS_UNAVAILABLE, "infra"),
        err_code::ENCLAVE_UNREACHABLE => (false, err_code::ENCLAVE_UNREACHABLE, "infra"),
        err_code::INTERNAL_ERROR => (false, err_code::INTERNAL_ERROR, "infra"),
        // Tier-2 fail-closed: an allow-listed code with no explicit arm → generic
        // policy denial (never a raw-code "reason", never `denied:false`).
        _ => (true, err_code::POLICY_DENIED, "policy"),
    }
}

/// Response for `GET /healthz` on success.
///
/// The `sign_*` fields (E3) publish live-signature health from the periodic
/// self-sign probe. `sign_checked=false` on venue-only boxes where the
/// attested-data key isn't provisioned — a monitor must ignore `sign_ok` /
/// `sign_age_s` then. The 200/503 status of `/healthz` itself stays purely a
/// function of the enclave vsock `ping`; a stale/failed sign probe is surfaced
/// here for alerting but does NOT flip the liveness code (a signing outage must
/// page an operator, not make a load balancer kill/restart the gateway).
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub enclave_cid: u32,
    pub enclave_port: u32,
    /// Whether the periodic self-sign probe is active (attested-data provisioned).
    pub sign_checked: bool,
    /// Whether the most recent self-sign probe passed (meaningful only if `sign_checked`).
    pub sign_ok: bool,
    /// Seconds since the last SUCCESSFUL self-sign; `null` if it never succeeded yet.
    pub sign_age_s: Option<u64>,
    /// Short commit SHA the running gateway was built from, or `"unknown"`.
    ///
    /// WHY THIS IS PUBLIC. Nothing here used to identify the running build, and
    /// the consequence was not theoretical: we could not tell which gateway code
    /// production was running, and there was no way to find out short of an
    /// authenticated request. A system whose own operators cannot name what is
    /// running cannot honestly ask anyone else to verify it.
    ///
    /// WHY DISCLOSING IT IS ACCEPTABLE. This threat model already treats the
    /// gateway as untrusted — the signing key never leaves the enclave, so a
    /// fully backdoored gateway is assumed not to yield keys. Hiding its version
    /// would be obscurity protecting a component we publicly say is not trusted.
    /// `/healthz` already discloses more operationally sensitive things:
    /// `sign_age_s` reveals how recently this deployment last signed.
    pub build: &'static str,
    /// Which tree that commit belongs to: `"public"`, `"internal"`, `"unknown"`.
    ///
    /// 🔴 The SHA alone is ambiguous: two 40-hex strings from two different
    /// repositories look identical, and without this field a reader cannot tell
    /// which history to look the commit up in.
    pub source: &'static str,
}

/// `/healthz` when the enclave is unreachable.
///
/// Carries the build identity even though the probe failed — and that is the
/// point. The failure state is exactly when an operator asks "which binary is
/// this?", and answering only in the healthy case would withhold it precisely
/// when it is needed.
///
/// Deliberately NOT folded into the shared `ErrorResponse`: that type answers
/// every denial on every route, and build identity has no business travelling
/// with a policy refusal.
#[derive(Debug, Serialize)]
pub struct HealthUnavailableResponse {
    pub error: &'static str,
    pub build: &'static str,
    pub source: &'static str,
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
    /// C22 (ZLODEY 2026-05-18): bearer token missing, malformed, or unknown.
    /// Returned with HTTP 401. We do not distinguish "missing" vs "wrong"
    /// to avoid an oracle that lets attackers tell whether tokens are
    /// enforced at all.
    pub const UNAUTHORIZED: &str = "unauthorized";
    /// Phase 0 Active Denial: enclave or gateway-side rate limit hit.
    pub const RATE_LIMITED: &str = "rate_limited";
    /// UPL v0 — co-encrypted policy denies request.
    pub const POLICY_DENIED: &str = "policy_denied";
    /// C18 — SIGNER_REQUIRE_POLICY=1 + legacy blob.
    pub const POLICY_REQUIRED: &str = "policy_required";
    /// ZN-200 — SIGNER_REQUIRE_CONTEXT=1 + missing context.
    pub const CONTEXT_REQUIRED: &str = "context_required";
    /// C27 — policy carries an unimplemented field; fail-loud.
    pub const UNIMPLEMENTED_POLICY_FIELD: &str = "unimplemented_policy_field";
    /// Mirror of the enclave code: this enclave has no resident receipt key,
    /// so it issues neither receipts nor counter heartbeats.
    pub const RECEIPTS_UNAVAILABLE: &str = "receipts_unavailable";
    /// CR035 (red-team, 2026-05-29): collapsed code on the verify_blob
    /// path that hides "wrong key" vs "wrong inner ciphertext" vs
    /// "decrypted-but-wrong-shape" from the external caller.
    pub const VERIFY_FAILED: &str = "verify_failed";

    // explainable-denials (2026-07-10): typed policy-denial subclasses emitted
    // by the enclave. Gateway is a dumb `code → HTTP+body` mapper; the enclave
    // is the only policy authority. Class only, never a value (no-leak). These
    // map to HTTP 403 with `rule_class: "policy"`. (No `venue_not_allowed`:
    // venue-ACL denial stays a uniform BadRequest to avoid a venue-scope oracle
    // — see enclave/src/proto.rs err_code.)
    pub const ACTION_NOT_ALLOWED: &str = "action_not_allowed";
    pub const SIZE_OVER_CAP: &str = "size_over_cap";
    pub const NOTIONAL_OVER_CAP: &str = "notional_over_cap";
    pub const WITHDRAWAL_NOT_SIGNABLE: &str = "withdrawal_not_signable";
    /// Gateway-emitted: per-token per-UTC-day order counter exhausted (B3).
    /// `rule_class: "rate"`, HTTP 429 (a budget signal, like rate_limited).
    pub const DAILY_CAP: &str = "daily_cap";
}

/// CR037 (red-team, 2026-05-29): allow-list of error codes that the
/// gateway is permitted to surface on the HTTP wire. Any enclave-emitted
/// code outside this list is collapsed to `internal_error` and logged
/// as `non_allow_listed_error_code_collapsed`. Forces Security review on
/// future PRs that add new wire codes — adding a const here is the
/// explicit hook for "does this leak diag detail to external callers?".
pub const WIRE_OK_ERROR_CODES: &[&str] = &[
    err_code::BAD_REQUEST,
    err_code::PAYLOAD_TOO_LARGE,
    err_code::KMS_DECRYPT_DENIED,
    err_code::INTERNAL_ERROR,
    err_code::ENCLAVE_UNREACHABLE,
    err_code::UNAUTHORIZED,
    err_code::RATE_LIMITED,
    err_code::POLICY_DENIED,
    err_code::POLICY_REQUIRED,
    err_code::CONTEXT_REQUIRED,
    err_code::UNIMPLEMENTED_POLICY_FIELD,
    err_code::RECEIPTS_UNAVAILABLE,
    err_code::VERIFY_FAILED,
    // explainable-denials: typed denial subclasses (wire-safe, class-only).
    err_code::ACTION_NOT_ALLOWED,
    err_code::SIZE_OVER_CAP,
    err_code::NOTIONAL_OVER_CAP,
    err_code::WITHDRAWAL_NOT_SIGNABLE,
    err_code::DAILY_CAP,
];

/// Coerce an enclave-supplied error code to a wire-safe value. Unknown
/// codes collapse to `internal_error` and emit a tracing warn so the
/// operator sees a leak attempt during PR review.
pub fn safe_wire_code(code: &str) -> &'static str {
    for known in WIRE_OK_ERROR_CODES {
        if *known == code {
            // `known` is `&&str`; deref coercion at the return site yields
            // `&'static str`. (Gemini PR #69 review flagged this as a type
            // mismatch — false positive; explicit `*known` trips
            // clippy::explicit_auto_deref under -D warnings.)
            return known;
        }
    }
    // explainable-denials defense-in-depth (Gemini #227 HIGH). The enclave's
    // binance-request allow-list historically emitted DYNAMIC codes carrying the
    // op/param name (`op_not_allowed:<op>`, `param_not_allowed:<op>:<name>`). The
    // enclave now emits the static `action_not_allowed`, but coerce the dynamic
    // prefixes here too (belt-and-suspenders): the SUFFIX (which names the op /
    // param) is dropped — no allow-list enumeration on the wire — and the result
    // is a 403 denial, never an opaque 500. A denial must read as a denial.
    if code.starts_with("op_not_allowed:") || code.starts_with("param_not_allowed:") {
        tracing::warn!(
            event = "dynamic_denial_code_coerced",
            original_code = code,
            "coerced dynamic op/param denial code to action_not_allowed (no suffix on wire)"
        );
        return err_code::ACTION_NOT_ALLOWED;
    }
    tracing::warn!(
        event = "non_allow_listed_error_code_collapsed",
        original_code = code,
        "gateway collapsed unknown enclave error_code to internal_error (CR037)"
    );
    err_code::INTERNAL_ERROR
}

/// Map a wire error code -> HTTP status. Pure function, easy to unit test.
pub fn http_status_for(code: &str) -> u16 {
    match code {
        err_code::BAD_REQUEST => 400,
        err_code::UNAUTHORIZED => 401,
        err_code::PAYLOAD_TOO_LARGE => 413,
        // We surface KMS denial as 503 (not 403) so the caller cannot tell
        // from the HTTP shape whether the policy denied them or whether
        // KMS is down — the failure modes are operationally equivalent.
        err_code::KMS_DECRYPT_DENIED => 503,
        err_code::ENCLAVE_UNREACHABLE => 503,
        err_code::RATE_LIMITED => 429,
        // CR035: verify_blob's collapsed failure code maps to 502 (bad
        // gateway) — the failure happened post-validation, downstream of
        // the gateway boundary. Same opacity intent as KMS_DECRYPT_DENIED.
        err_code::VERIFY_FAILED => 502,
        err_code::POLICY_DENIED => 403,
        err_code::POLICY_REQUIRED => 403,
        err_code::CONTEXT_REQUIRED => 400,
        err_code::UNIMPLEMENTED_POLICY_FIELD => 501,
        // "this enclave issues no receipts" — a capability absence the
        // operator fixes by provisioning a data key, not something the
        // caller can retry into existence.
        err_code::RECEIPTS_UNAVAILABLE => 501,
        // explainable-denials: typed policy-denial subclasses → 403 (class only).
        err_code::ACTION_NOT_ALLOWED => 403,
        err_code::SIZE_OVER_CAP => 403,
        err_code::NOTIONAL_OVER_CAP => 403,
        err_code::WITHDRAWAL_NOT_SIGNABLE => 403,
        // Daily order budget exhausted — a rate signal, like rate_limited.
        err_code::DAILY_CAP => 429,
        // Real infra error stays 500 (explicit, so it does NOT fall into the
        // fail-closed 403 default below). Rogue/non-allow-listed codes are
        // collapsed to `internal_error` upstream by `safe_wire_code`, so they
        // land HERE → 500 (CR037 opacity preserved).
        err_code::INTERNAL_ERROR => 500,
        // CR037 reconciliation (CTO 2026-07-10): default-deny. An allow-listed
        // code with no explicit arm fail-closes to 403 (a denial), NEVER 500 —
        // a forgotten denial class must not read as a server error. This is NOT
        // an unknown-code path (those became `internal_error` upstream → 500).
        _ => 403,
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
    fn health_response_serializes_sign_liveness_fields() {
        // Provisioned + healthy.
        let ok = HealthResponse {
            status: "ok",
            build: "testsha",
            source: "internal",
            enclave_cid: 16,
            enclave_port: 5005,
            sign_checked: true,
            sign_ok: true,
            sign_age_s: Some(42),
        };
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["sign_checked"], serde_json::json!(true));
        assert_eq!(v["sign_ok"], serde_json::json!(true));
        assert_eq!(v["sign_age_s"], serde_json::json!(42));

        // Never-succeeded → sign_age_s is JSON null (monitor treats as stale).
        let never = HealthResponse {
            status: "ok",
            build: "testsha",
            source: "internal",
            enclave_cid: 16,
            enclave_port: 5005,
            sign_checked: true,
            sign_ok: false,
            sign_age_s: None,
        };
        let v: serde_json::Value = serde_json::to_value(&never).unwrap();
        assert!(v["sign_age_s"].is_null());

        // Venue-only box (data key not provisioned) → sign_checked false.
        let venue_only = HealthResponse {
            status: "ok",
            build: "testsha",
            source: "internal",
            enclave_cid: 16,
            enclave_port: 5005,
            sign_checked: false,
            sign_ok: false,
            sign_age_s: None,
        };
        let v: serde_json::Value = serde_json::to_value(&venue_only).unwrap();
        assert_eq!(v["sign_checked"], serde_json::json!(false));
    }

    #[test]
    fn http_status_mapping_covers_known_codes() {
        assert_eq!(http_status_for(err_code::BAD_REQUEST), 400);
        assert_eq!(http_status_for(err_code::PAYLOAD_TOO_LARGE), 413);
        assert_eq!(http_status_for(err_code::KMS_DECRYPT_DENIED), 503);
        assert_eq!(http_status_for(err_code::ENCLAVE_UNREACHABLE), 503);
        assert_eq!(http_status_for(err_code::INTERNAL_ERROR), 500);
        assert_eq!(http_status_for(err_code::RATE_LIMITED), 429);
        assert_eq!(http_status_for(err_code::POLICY_DENIED), 403);
        assert_eq!(http_status_for(err_code::POLICY_REQUIRED), 403);
        assert_eq!(http_status_for(err_code::CONTEXT_REQUIRED), 400);
        assert_eq!(http_status_for(err_code::UNIMPLEMENTED_POLICY_FIELD), 501);
    }

    // explainable-denials + CR037 reconciliation (CTO 2026-07-10). Three tiers:
    //   1. known denial class → its explicit 403/429 + typed body.
    //   2. allow-listed-but-unmapped code → fail-closed 403 policy_denied.
    //   3. NOT allow-listed → safe_wire_code collapses to internal_error → 500.
    #[test]
    fn explainable_status_tier1_known_denial_classes() {
        assert_eq!(http_status_for(err_code::ACTION_NOT_ALLOWED), 403);
        assert_eq!(http_status_for(err_code::SIZE_OVER_CAP), 403);
        assert_eq!(http_status_for(err_code::NOTIONAL_OVER_CAP), 403);
        assert_eq!(http_status_for(err_code::WITHDRAWAL_NOT_SIGNABLE), 403);
        assert_eq!(http_status_for(err_code::DAILY_CAP), 429);
    }

    #[test]
    fn explainable_status_tier2_unmapped_failcloses_to_403_not_500() {
        // A code the mapper doesn't know explicitly must fail-closed to a 403
        // denial, NEVER 500. (Real infra error `internal_error` stays 500.)
        assert_eq!(http_status_for("some_future_denial_code"), 403);
        assert_eq!(http_status_for(err_code::INTERNAL_ERROR), 500);
    }

    #[test]
    fn explainable_status_tier3_non_allowlisted_collapses_to_500() {
        // CR037 intact: a code NOT on the wire allow-list is collapsed to
        // internal_error BEFORE http_status_for, so it reads 500 (opaque),
        // not a 403 denial — a rogue enclave code cannot masquerade as a
        // typed policy denial on the wire.
        let mapped = safe_wire_code("totally_made_up_rogue_code");
        assert_eq!(mapped, err_code::INTERNAL_ERROR);
        assert_eq!(http_status_for(mapped), 500);
    }

    #[test]
    fn explainable_binance_request_dynamic_denial_coerced_no_leak() {
        // Gemini #227 HIGH: the binance-request allow-list once emitted DYNAMIC
        // codes naming the op/param (`op_not_allowed:<op>`, `param_not_allowed:..`).
        // safe_wire_code must coerce those to the static `action_not_allowed`
        // (403) and NEVER surface the suffix — no allow-list enumeration on wire.
        //
        // Guards the coercion itself; the live binance-request handler routes
        // every enclave error through this safe_wire_code call (the #219
        // verbatim-surface INTERCEPT that echoed the op/param name was removed —
        // the coercion stayed), so a regression here re-opens the leak directly.
        // The handler-side guard is `binance_request_wire_error_never_leaks_op_param`.
        for dynamic in [
            "op_not_allowed:universalTransfer",
            "param_not_allowed:order:reduceOnly",
        ] {
            let coerced = safe_wire_code(dynamic);
            assert_eq!(coerced, err_code::ACTION_NOT_ALLOWED, "coerce {dynamic}");
            assert_eq!(http_status_for(coerced), 403);
            assert!(
                !coerced.contains(':'),
                "coerced wire code must drop the suffix"
            );
            let body = ErrorResponse::new(coerced);
            assert!(!body.reason_code.contains(':') && !body.error.contains(':'));
        }
    }

    #[test]
    fn explainable_c2_fold_kms_attestation_denial_is_503() {
        // C2-fold: an attestation / KMS-decrypt denial surfaces as 503
        // (attestation class) end-to-end — NOT silently 403 (tier-2 default),
        // NOT 500. kms_decrypt_denied is allow-listed + explicitly mapped.
        assert_eq!(
            safe_wire_code(err_code::KMS_DECRYPT_DENIED),
            err_code::KMS_DECRYPT_DENIED
        );
        assert_eq!(http_status_for(err_code::KMS_DECRYPT_DENIED), 503);
        assert_eq!(
            denial_meta(err_code::KMS_DECRYPT_DENIED),
            (true, err_code::KMS_DECRYPT_DENIED, "attestation")
        );
    }

    #[test]
    fn explainable_body_denial_meta_is_typed_and_consistent() {
        for (code, denied, rc, class) in [
            (
                err_code::SIZE_OVER_CAP,
                true,
                err_code::SIZE_OVER_CAP,
                "policy",
            ),
            (
                err_code::WITHDRAWAL_NOT_SIGNABLE,
                true,
                err_code::WITHDRAWAL_NOT_SIGNABLE,
                "policy",
            ),
            (err_code::DAILY_CAP, true, err_code::DAILY_CAP, "rate"),
            (err_code::UNAUTHORIZED, true, err_code::UNAUTHORIZED, "auth"),
            (
                err_code::KMS_DECRYPT_DENIED,
                true,
                err_code::KMS_DECRYPT_DENIED,
                "attestation",
            ),
            (
                err_code::BAD_REQUEST,
                false,
                err_code::BAD_REQUEST,
                "request",
            ),
            (
                err_code::INTERNAL_ERROR,
                false,
                err_code::INTERNAL_ERROR,
                "infra",
            ),
        ] {
            assert_eq!(denial_meta(code), (denied, rc, class), "meta for {code}");
        }
        // Tier-2 fail-closed: unmapped code → generic policy denial, denied=true.
        assert_eq!(
            denial_meta("future_code"),
            (true, err_code::POLICY_DENIED, "policy")
        );
    }

    #[test]
    fn explainable_body_never_leaks_values_no_digits() {
        // NO-LEAK invariant: the structured body carries ONLY class strings —
        // never a numeric threshold, cap, or allow-list value. Assert every
        // reason_code/rule_class is lowercase-ascii with no digits.
        for code in WIRE_OK_ERROR_CODES.iter().chain(["future_code"].iter()) {
            let ErrorResponse {
                denied: _,
                reason_code,
                rule_class,
                error,
                decided_by: _,
                receipt: _,
            } = ErrorResponse::new(code);
            for field in [&reason_code, &rule_class, &error] {
                assert!(
                    field.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                    "explainable body field {field:?} for {code} must be class-only (no digits/values)"
                );
            }
        }
    }

    #[test]
    fn withdrawal_kinds_are_recognized() {
        for k in [
            "withdraw",
            "withdraw3",
            "withdrawal",
            "usdSend",
            "spotSend",
            // Gemini #215 HIGH: transfer-class fund movement is denied too.
            "usdClassTransfer",
            "vaultTransfer",
            "subAccountTransfer",
            "hip3LiquidatorTransfer",
            "cWithdraw",
        ] {
            assert!(is_withdrawal_kind(Some(k)), "{k} must be a withdrawal kind");
        }
    }

    #[test]
    fn order_cancel_and_none_are_not_withdrawal_kinds() {
        assert!(!is_withdrawal_kind(Some("order")));
        assert!(!is_withdrawal_kind(Some("cancel")));
        assert!(!is_withdrawal_kind(None));
        // Case-sensitive: only the exact venue-native names are denied here.
        assert!(!is_withdrawal_kind(Some("Withdraw")));
    }

    /// A missing receipt capability must not read as an attested policy refusal.
    /// Without an explicit arm the default-deny fallback reports
    /// `denied: true` / `policy_denied` / `rule_class: "policy"` — a
    /// provisioning gap presented as a ruling from inside the enclave.
    #[test]
    fn receipts_unavailable_is_infra_not_a_denial() {
        let (denied, reason, class) = denial_meta(err_code::RECEIPTS_UNAVAILABLE);
        assert!(!denied, "no receipt key is an absence, not a refusal");
        assert_eq!(reason, err_code::RECEIPTS_UNAVAILABLE);
        assert_eq!(class, "infra");
        assert_eq!(http_status_for(err_code::RECEIPTS_UNAVAILABLE), 501);
        assert!(
            WIRE_OK_ERROR_CODES.contains(&err_code::RECEIPTS_UNAVAILABLE),
            "must survive safe_wire_code, else it collapses to internal_error"
        );
    }

    #[test]
    fn http_status_for_verify_failed_is_502() {
        assert_eq!(http_status_for(err_code::VERIFY_FAILED), 502);
    }

    #[test]
    fn safe_wire_code_passes_known_codes_through() {
        for code in WIRE_OK_ERROR_CODES {
            assert_eq!(safe_wire_code(code), *code);
        }
    }

    #[test]
    fn safe_wire_code_collapses_unknown_to_internal_error() {
        assert_eq!(
            safe_wire_code("something_diag_leak"),
            err_code::INTERNAL_ERROR
        );
        assert_eq!(safe_wire_code(""), err_code::INTERNAL_ERROR);
    }

    #[test]
    fn safe_wire_code_includes_cr035_verify_failed() {
        // Regression: if anyone removes VERIFY_FAILED from the allow-list,
        // the verify_blob path would collapse it to internal_error and
        // start re-leaking the oracle. Catch that in CI.
        assert_eq!(
            safe_wire_code(err_code::VERIFY_FAILED),
            err_code::VERIFY_FAILED
        );
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
                "hyperliquid_testnet",
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
        // HL TESTNET (source="b") — the allowed demo path, same kinds as mainnet.
        assert_eq!(
            enclave_action_for("hyperliquid_testnet", Some("order")),
            Some("sign_hyperliquid_testnet_order")
        );
        assert_eq!(
            enclave_action_for("hyperliquid_testnet", Some("cancel")),
            Some("sign_hyperliquid_testnet_cancel")
        );
        assert_eq!(enclave_action_for("hyperliquid_testnet", None), None);
        assert!(ALLOWED_EXCHANGES.contains(&"hyperliquid_testnet"));
        // Unknown exchange → None regardless of kind.
        assert_eq!(enclave_action_for("unknown", None), None);
        assert_eq!(enclave_action_for("unknown", Some("order")), None);
    }
}
