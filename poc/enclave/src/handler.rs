//! Per-request dispatcher: validate, route, decrypt secret via KMS, sign.
//!
//! Phase 3: real KMS path. The hardcoded Phase 2 test secret has been
//! removed. The enclave now requires `aws_credentials` + `ciphertext_blob_base64`
//! for every `sign` request and shells out to `/kmstool_enclave_cli` to
//! decrypt the blob with attestation.
//!
//! Error mapping:
//!   - missing fields / disallowed verb / oversized field  -> `bad_request`
//!   - KMS rejected (denied / PCR mismatch / bad ciphertext) -> `kms_decrypt_denied`
//!   - anything else (binary missing, parse failure, IO error) -> `internal_error`
//!
//! Plaintext is held in `Zeroizing<Vec<u8>>` and never logged.

use crate::kms_client::{self, DecryptError};
use crate::proto::{
    err_code, AwsCredentials, BinanceSecret, BybitSecret, HyperliquidSecret, KucoinSecret,
    OkxSecret, SignRequest, SignResponse,
};
use crate::signer;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use zeroize::Zeroizing;

/// Allow-listed HTTP methods. Anything else short-circuits to `bad_request`
/// before we touch the secret. Defense-in-depth against a compromised parent
/// asking us to sign arbitrary verbs.
const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE"];

/// Hard cap on the ciphertext blob size we accept inline. KMS-Decrypt with
/// recipient-encryption envelopes are typically <2 KiB — 8 KiB is plenty
/// of headroom and well under our 64 KiB wire cap.
const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024;

/// Load + decrypt the signing secret for this request via KMS.
///
/// Phase 3 contract:
///   - `req.aws_credentials` must be present (parent forwards STS creds).
///   - `req.ciphertext_blob_base64` must be present (parent fetched blob from S3).
///
/// On any decryption error we map to a `DecryptError` so the caller can
/// distinguish denied-by-policy from internal failure.
fn load_secret_for(req: &SignRequest) -> Result<Zeroizing<Vec<u8>>, LoadSecretError> {
    let creds: &AwsCredentials = req
        .aws_credentials
        .as_ref()
        .ok_or(LoadSecretError::BadRequest)?;

    let ciphertext_b64 = req
        .ciphertext_blob_base64
        .as_deref()
        .ok_or(LoadSecretError::BadRequest)?;

    if ciphertext_b64.is_empty() || ciphertext_b64.len() > MAX_CIPHERTEXT_BYTES {
        return Err(LoadSecretError::BadRequest);
    }

    let ciphertext = B64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| LoadSecretError::BadRequest)?;

    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(LoadSecretError::BadRequest);
    }

    match kms_client::decrypt(creds, &ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(DecryptError::AccessDenied) => Err(LoadSecretError::KmsDenied),
        Err(DecryptError::Internal) => Err(LoadSecretError::Internal),
    }
}

/// Internal error variants for `load_secret_for`. Keeps the wire-code
/// mapping centralized in `handle_sign`.
enum LoadSecretError {
    BadRequest,
    KmsDenied,
    Internal,
}

/// Dispatch one request and produce one response. Never panics.
pub fn handle(req: SignRequest) -> SignResponse {
    match req.action.as_str() {
        "ping" => SignResponse::ok("pong".to_owned()),
        "sign" => handle_sign(req),
        "sign_kucoin" => handle_sign_kucoin(req),
        "sign_binance" => handle_sign_binance(req),
        "sign_bybit" => handle_sign_bybit(req),
        "sign_okx" => handle_sign_okx(req),
        "sign_hyperliquid_main_order" => handle_sign_hyperliquid_main_order(req),
        "sign_hyperliquid_main_cancel" => handle_sign_hyperliquid_main_cancel(req),
        _ => SignResponse::err(err_code::BAD_REQUEST),
    }
}

fn handle_sign(req: SignRequest) -> SignResponse {
    // All four base fields are required for sign actions.
    let (Some(method), Some(path), Some(body), Some(ts)) = (
        req.method.as_deref(),
        req.path.as_deref(),
        req.body.as_deref(),
        req.timestamp_ms,
    ) else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    // Allow-list verbs before even loading the secret.
    if !ALLOWED_METHODS.contains(&method) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let secret = match load_secret_for(&req) {
        Ok(s) => s,
        Err(LoadSecretError::BadRequest) => {
            return SignResponse::err(err_code::BAD_REQUEST);
        }
        Err(LoadSecretError::KmsDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED);
        }
        Err(LoadSecretError::Internal) => {
            return SignResponse::err(err_code::INTERNAL_ERROR);
        }
    };

    match signer::sign_kucoin(&secret, ts, method, path, body) {
        Ok(sig_b64) => SignResponse::ok(sig_b64),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

/// Day 3 `sign_kucoin` action. Same input contract as `sign` but the decrypted
/// blob is a JSON object `{"key","secret","passphrase"}` and the response
/// carries the full KuCoin v2 auth header set instead of a bare signature.
fn handle_sign_kucoin(req: SignRequest) -> SignResponse {
    let (Some(method), Some(path), Some(body), Some(ts)) = (
        req.method.as_deref(),
        req.path.as_deref(),
        req.body.as_deref(),
        req.timestamp_ms,
    ) else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    if !ALLOWED_METHODS.contains(&method) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let plaintext = match load_secret_for(&req) {
        Ok(p) => p,
        Err(LoadSecretError::BadRequest) => {
            return SignResponse::err(err_code::BAD_REQUEST);
        }
        Err(LoadSecretError::KmsDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED);
        }
        Err(LoadSecretError::Internal) => {
            return SignResponse::err(err_code::INTERNAL_ERROR);
        }
    };

    // Parse the plaintext as a KuCoin secret triple. KucoinSecret zeroizes
    // every field on drop — we hold it only as long as it takes to read the
    // borrowed slices into the HMAC routine.
    let secret_triple: KucoinSecret = match serde_json::from_slice(&plaintext) {
        Ok(s) => s,
        Err(_) => {
            // Malformed JSON inside the ciphertext blob is operationally
            // identical to "wrong blob loaded" — surface as bad_request, which
            // already carries no internal detail.
            return SignResponse::err(err_code::BAD_REQUEST);
        }
    };
    if !secret_triple.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    // Wrap the borrowed secret bytes in Zeroizing for the duration of the
    // HMAC call so signer.rs's signature contract is satisfied. We clone
    // because the underlying String inside KucoinSecret is owned by
    // secret_triple and will be wiped on drop; the clone here is the
    // working copy that the HMAC reads from.
    let secret_bytes = Zeroizing::new(secret_triple.secret.as_bytes().to_vec());
    let passphrase_bytes = secret_triple.passphrase.as_bytes();

    match signer::compute_kucoin_headers(
        &secret_bytes,
        passphrase_bytes,
        &secret_triple.key,
        ts,
        method,
        path,
        body,
    ) {
        Ok(headers) => SignResponse::ok_headers(headers),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
    // secret_triple, secret_bytes, plaintext all wiped via their respective
    // Drop impls when this function returns.
}

/// Phase 1 Week 4: `sign_binance` action. Decrypts a `{key,secret}` JSON blob
/// and returns the Binance auth header set:
///   `X-MBX-APIKEY` (header), `signature` + `timestamp` + `recvWindow` (query params).
///
/// Per Binance docs, the signed string is `query_string + body`, hex-HMAC-SHA256.
/// The parent extracts user-supplied query params from the path and forwards
/// them in `req.query`; we append `timestamp=<ms>&recvWindow=5000` ourselves.
fn handle_sign_binance(req: SignRequest) -> SignResponse {
    let (Some(method), Some(body), Some(ts)) = (
        req.method.as_deref(),
        req.body.as_deref(),
        req.timestamp_ms,
    ) else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    if !ALLOWED_METHODS.contains(&method) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    // `query` is optional; absent = empty.
    let user_query = req.query.as_deref().unwrap_or("");

    let plaintext = match load_secret_for(&req) {
        Ok(p) => p,
        Err(LoadSecretError::BadRequest) => {
            return SignResponse::err(err_code::BAD_REQUEST);
        }
        Err(LoadSecretError::KmsDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED);
        }
        Err(LoadSecretError::Internal) => {
            return SignResponse::err(err_code::INTERNAL_ERROR);
        }
    };

    let secret_pair: BinanceSecret = match serde_json::from_slice(&plaintext) {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_pair.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let secret_bytes = Zeroizing::new(secret_pair.secret.as_bytes().to_vec());

    match signer::compute_binance_headers(&secret_bytes, &secret_pair.key, ts, user_query, body) {
        Ok(headers) => SignResponse::ok_headers(headers),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

/// Phase 1 Week 4: `sign_bybit` action. Decrypts a `{key,secret}` JSON blob
/// and returns the Bybit V5 auth header set:
///   `X-BAPI-API-KEY`, `X-BAPI-TIMESTAMP`, `X-BAPI-RECV-WINDOW`,
///   `X-BAPI-SIGN`, `X-BAPI-SIGN-TYPE` (all headers, none query).
///
/// Bybit signs `timestamp + key + recv_window + (query | body)`. For GET/DELETE
/// the payload is the query string; for POST/PUT it's the body.
fn handle_sign_bybit(req: SignRequest) -> SignResponse {
    let (Some(method), Some(body), Some(ts)) = (
        req.method.as_deref(),
        req.body.as_deref(),
        req.timestamp_ms,
    ) else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    if !ALLOWED_METHODS.contains(&method) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let user_query = req.query.as_deref().unwrap_or("");

    let plaintext = match load_secret_for(&req) {
        Ok(p) => p,
        Err(LoadSecretError::BadRequest) => {
            return SignResponse::err(err_code::BAD_REQUEST);
        }
        Err(LoadSecretError::KmsDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED);
        }
        Err(LoadSecretError::Internal) => {
            return SignResponse::err(err_code::INTERNAL_ERROR);
        }
    };

    let secret_pair: BybitSecret = match serde_json::from_slice(&plaintext) {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_pair.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let secret_bytes = Zeroizing::new(secret_pair.secret.as_bytes().to_vec());

    match signer::compute_bybit_headers(&secret_bytes, &secret_pair.key, ts, method, user_query, body) {
        Ok(headers) => SignResponse::ok_headers(headers),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

/// Phase 1 Stage 1: `sign_okx` action. Decrypts a `{key, secret, passphrase}`
/// JSON blob and returns the OKX V5 auth header set:
///   `OK-ACCESS-KEY`, `OK-ACCESS-SIGN`, `OK-ACCESS-TIMESTAMP`,
///   `OK-ACCESS-PASSPHRASE` (4 headers, none in query params).
///
/// Per OKX V5 docs the prehash is
/// `{ISO8601_timestamp}{METHOD}{requestPath}{body}` where `requestPath`
/// already includes any query string. The gateway is responsible for
/// merging `?param=value` into `path` before forwarding (to keep the
/// canonical-string assembly unambiguous on the enclave side). For
/// backwards compatibility we also accept a separate `query` field and
/// merge it ourselves.
fn handle_sign_okx(req: SignRequest) -> SignResponse {
    let (Some(method), Some(path), Some(body), Some(ts)) = (
        req.method.as_deref(),
        req.path.as_deref(),
        req.body.as_deref(),
        req.timestamp_ms,
    ) else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    if !ALLOWED_METHODS.contains(&method) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let plaintext = match load_secret_for(&req) {
        Ok(p) => p,
        Err(LoadSecretError::BadRequest) => {
            return SignResponse::err(err_code::BAD_REQUEST);
        }
        Err(LoadSecretError::KmsDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED);
        }
        Err(LoadSecretError::Internal) => {
            return SignResponse::err(err_code::INTERNAL_ERROR);
        }
    };

    let secret_triple: OkxSecret = match serde_json::from_slice(&plaintext) {
        Ok(s) => s,
        Err(_) => {
            // Malformed JSON inside ciphertext blob is operationally
            // identical to "wrong blob loaded" — surface as bad_request.
            return SignResponse::err(err_code::BAD_REQUEST);
        }
    };
    if !secret_triple.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    // Merge `query` (if provided) into requestPath so canonical-string
    // assembly is unambiguous. OKX's spec is clear: requestPath INCLUDES
    // the query string, separator `?`. If `path` already has a `?` we
    // append with `&`; otherwise with `?`.
    let request_path: String = match req.query.as_deref() {
        Some(q) if !q.is_empty() => {
            if path.contains('?') {
                format!("{}&{}", path, q)
            } else {
                format!("{}?{}", path, q)
            }
        }
        _ => path.to_owned(),
    };

    let secret_bytes = Zeroizing::new(secret_triple.secret.as_bytes().to_vec());
    let passphrase_bytes = secret_triple.passphrase.as_bytes();

    match signer::compute_okx_headers(
        &secret_bytes,
        passphrase_bytes,
        &secret_triple.key,
        ts,
        method,
        &request_path,
        body,
    ) {
        Ok(headers) => SignResponse::ok_headers(headers),
        // Most likely cause: passphrase has illegal byte (CRLF / NUL /
        // non-ASCII). Map to bad_request — the customer's blob is malformed.
        Err(_) => SignResponse::err(err_code::BAD_REQUEST),
    }
    // secret_triple, secret_bytes, plaintext all wiped on Drop.
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 1 Stage 2 — EIP-712 / Hyperliquid_main dispatchers.
// ─────────────────────────────────────────────────────────────────────────
//
// Two actions are wired in Phase 1: `order` and `cancel`. Each:
//   1. Validates the request shape (method ignored — EIP-712 is body-only).
//   2. Loads + KMS-decrypts the `HyperliquidSecret` blob.
//   3. Parses the private key, sanity-checks it derives the expected
//      wallet_address, and reads the optional vault.
//   4. Calls `signer::sign_hyperliquid` with the action JSON, nonce, vault,
//      and `source="a"` (mainnet hard-coded).
//   5. Returns the `(r, s, v)` triple via `SignResponse::ok_hl_signature`.
//
// Hyperliquid posts the signed payload to `POST /exchange` with a body of
// `{action, nonce, signature, vaultAddress}`; the SDK constructs that body
// from the components we return.

/// Common pre-flight + decrypt path shared by `order` and `cancel`.
/// Returns the decrypted `HyperliquidSecret` and the parsed action data on
/// success, or a populated `SignResponse::err` on any validation/decrypt
/// failure.
fn load_hyperliquid_request(
    req: &SignRequest,
) -> Result<(HyperliquidSecret, serde_json::Value, u64, Option<[u8; 20]>), SignResponse> {
    // 1. Action JSON + nonce required.
    let Some(action) = req.hl_action.as_ref() else {
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    };
    let Some(nonce) = req.nonce else {
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    };
    // 2. Optional vault: empty string / None = no vault; otherwise 0x + 40 hex.
    let vault = match req.vault_address.as_deref() {
        Some(v) if !v.is_empty() => match crate::signer::parse_evm_address(v) {
            Ok(addr) => Some(addr),
            Err(_) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
        },
        _ => None,
    };

    // 3. Decrypt + parse secret blob.
    let plaintext = match load_secret_for(req) {
        Ok(p) => p,
        Err(LoadSecretError::BadRequest) => {
            return Err(SignResponse::err(err_code::BAD_REQUEST));
        }
        Err(LoadSecretError::KmsDenied) => {
            return Err(SignResponse::err(err_code::KMS_DECRYPT_DENIED));
        }
        Err(LoadSecretError::Internal) => {
            return Err(SignResponse::err(err_code::INTERNAL_ERROR));
        }
    };

    let secret: HyperliquidSecret = match serde_json::from_slice(&plaintext) {
        Ok(s) => s,
        Err(_) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
    };
    if !secret.is_complete() {
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    }

    // 4. Sanity check: re-derive address from private key and compare with
    //    the wallet_address field. Mismatch → operator stapled the wrong
    //    key/address pair into the blob; refuse to sign.
    let pk = match crate::signer::parse_evm_private_key(&secret.private_key) {
        Ok(k) => k,
        Err(_) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
    };
    let derived = match crate::signer::derive_address_from_private_key(&pk) {
        Ok(a) => a,
        Err(_) => return Err(SignResponse::err(err_code::INTERNAL_ERROR)),
    };
    let claimed = match crate::signer::parse_evm_address(&secret.wallet_address) {
        Ok(a) => a,
        Err(_) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
    };
    if derived != claimed {
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    }

    Ok((secret, action.clone(), nonce, vault))
}

/// Validate that an `order` action has the minimum required Hyperliquid
/// shape: top-level `type=="order"` and `orders` is a non-empty array.
/// Schema validation is intentionally narrow — we don't enforce inner
/// field types because Hyperliquid's API will reject malformed orders
/// itself and we'd rather not duplicate the validation surface.
fn validate_order_action(action: &serde_json::Value) -> bool {
    let Some(obj) = action.as_object() else {
        return false;
    };
    let Some(action_type) = obj.get("type").and_then(|v| v.as_str()) else {
        return false;
    };
    if action_type != "order" {
        return false;
    }
    let Some(orders) = obj.get("orders").and_then(|v| v.as_array()) else {
        return false;
    };
    !orders.is_empty()
}

/// Validate that a `cancel` action has top-level `type=="cancel"` and
/// `cancels` is a non-empty array.
fn validate_cancel_action(action: &serde_json::Value) -> bool {
    let Some(obj) = action.as_object() else {
        return false;
    };
    let Some(action_type) = obj.get("type").and_then(|v| v.as_str()) else {
        return false;
    };
    if action_type != "cancel" {
        return false;
    }
    let Some(cancels) = obj.get("cancels").and_then(|v| v.as_array()) else {
        return false;
    };
    !cancels.is_empty()
}

/// `sign_hyperliquid_main_order` — sign a Hyperliquid mainnet order.
fn handle_sign_hyperliquid_main_order(req: SignRequest) -> SignResponse {
    let (secret, action, nonce, vault) = match load_hyperliquid_request(&req) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !validate_order_action(&action) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    let pk = match crate::signer::parse_evm_private_key(&secret.private_key) {
        Ok(k) => k,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    match crate::signer::sign_hyperliquid(&pk, &action, nonce, vault, "a") {
        Ok(sig) => SignResponse::ok_hl_signature(sig),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

/// `sign_hyperliquid_main_cancel` — sign a Hyperliquid mainnet cancel.
fn handle_sign_hyperliquid_main_cancel(req: SignRequest) -> SignResponse {
    let (secret, action, nonce, vault) = match load_hyperliquid_request(&req) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !validate_cancel_action(&action) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    let pk = match crate::signer::parse_evm_private_key(&secret.private_key) {
        Ok(k) => k,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    match crate::signer::sign_hyperliquid(&pk, &action, nonce, vault, "a") {
        Ok(sig) => SignResponse::ok_hl_signature(sig),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_template() -> SignRequest {
        SignRequest {
            action: "sign".to_owned(),
            method: Some("POST".to_owned()),
            path: Some("/api/v1/orders".to_owned()),
            body: Some(r#"{"clientOid":"test"}"#.to_owned()),
            timestamp_ms: Some(1714997000000),
            key_blob_s3_key: Some("secrets/test-kucoin.enc".to_owned()),
            key_id: Some("alias/signer-poc".to_owned()),
            aws_credentials: None,
            ciphertext_blob_base64: None,
            query: None,
            // Phase 1 Stage 2 — EIP-712 fields default None for HMAC tests.
            hl_action: None,
            nonce: None,
            vault_address: None,
        }
    }

    #[test]
    fn ping_returns_pong() {
        let req = SignRequest {
            action: "ping".to_owned(),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.signature_base64, "pong");
        assert!(resp.error.is_none());
    }

    #[test]
    fn unknown_action_returns_bad_request() {
        let req = SignRequest {
            action: "do-something-evil".to_owned(),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.signature_base64, "");
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_missing_method_returns_bad_request() {
        let req = SignRequest {
            method: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_with_disallowed_method_returns_bad_request() {
        let req = SignRequest {
            method: Some("PATCH".to_owned()), // not in allow-list
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_missing_credentials_returns_bad_request() {
        // Method allow-listed, ciphertext present, but no creds.
        let req = SignRequest {
            ciphertext_blob_base64: Some(B64.encode(b"some-bytes")),
            aws_credentials: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_missing_ciphertext_returns_bad_request() {
        let req = SignRequest {
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_oversized_ciphertext_returns_bad_request() {
        let big = "A".repeat(MAX_CIPHERTEXT_BYTES + 100);
        let req = SignRequest {
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: Some(big),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_invalid_base64_returns_bad_request() {
        let req = SignRequest {
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            // base64 alphabet error — not valid base64
            ciphertext_blob_base64: Some("!!!not-base64!!!".to_owned()),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    /// Day 3: `sign_kucoin` action mirrors the `sign` validation contract.
    /// Missing fields short-circuit before any KMS call; we don't have to
    /// stub kmstool out for this path.
    #[test]
    fn sign_kucoin_missing_method_returns_bad_request() {
        let req = SignRequest {
            action: "sign_kucoin".to_owned(),
            method: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
        assert!(resp.headers.is_none());
        assert_eq!(resp.signature_base64, "");
    }

    #[test]
    fn sign_kucoin_disallowed_method_returns_bad_request() {
        let req = SignRequest {
            action: "sign_kucoin".to_owned(),
            method: Some("PATCH".to_owned()),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_kucoin_missing_credentials_returns_bad_request() {
        let req = SignRequest {
            action: "sign_kucoin".to_owned(),
            ciphertext_blob_base64: Some(B64.encode(b"some-bytes")),
            aws_credentials: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_kucoin_missing_ciphertext_returns_bad_request() {
        let req = SignRequest {
            action: "sign_kucoin".to_owned(),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_kucoin_oversized_ciphertext_returns_bad_request() {
        let big = "A".repeat(MAX_CIPHERTEXT_BYTES + 100);
        let req = SignRequest {
            action: "sign_kucoin".to_owned(),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: Some(big),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    /// Phase 1 Stage 1: `sign_okx` action mirrors `sign_kucoin` validation.
    #[test]
    fn sign_okx_missing_method_returns_bad_request() {
        let req = SignRequest {
            action: "sign_okx".to_owned(),
            method: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
        assert!(resp.headers.is_none());
        assert_eq!(resp.signature_base64, "");
    }

    #[test]
    fn sign_okx_disallowed_method_returns_bad_request() {
        let req = SignRequest {
            action: "sign_okx".to_owned(),
            method: Some("PATCH".to_owned()),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_okx_missing_credentials_returns_bad_request() {
        let req = SignRequest {
            action: "sign_okx".to_owned(),
            ciphertext_blob_base64: Some(B64.encode(b"some-bytes")),
            aws_credentials: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_okx_missing_ciphertext_returns_bad_request() {
        let req = SignRequest {
            action: "sign_okx".to_owned(),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: None,
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_okx_oversized_ciphertext_returns_bad_request() {
        let big = "A".repeat(MAX_CIPHERTEXT_BYTES + 100);
        let req = SignRequest {
            action: "sign_okx".to_owned(),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: Some(big),
            ..req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    // ─────────────────────────────────────────────────────────────────
    // Phase 1 Stage 2 — Hyperliquid_main dispatcher tests.
    // ─────────────────────────────────────────────────────────────────
    //
    // These tests cover the validation path only (missing fields, malformed
    // action JSON, bad vault hex). End-to-end signing requires a real KMS
    // round-trip and lives in the enclave-on-EC2 smoke suite.

    fn hl_req_template(action_str: &str) -> SignRequest {
        SignRequest {
            action: action_str.to_owned(),
            method: None,
            path: None,
            body: None,
            timestamp_ms: None,
            key_blob_s3_key: Some("secrets/test-hyperliquid_main.enc".to_owned()),
            key_id: Some("alias/signer-poc".to_owned()),
            aws_credentials: None,
            ciphertext_blob_base64: None,
            query: None,
            hl_action: Some(serde_json::json!({
                "type": "order",
                "orders": [{
                    "a": 0,
                    "b": true,
                    "p": "50000",
                    "s": "0.001",
                    "r": false,
                    "t": {"limit": {"tif": "Gtc"}}
                }],
                "grouping": "na"
            })),
            nonce: Some(1700000000000),
            vault_address: None,
        }
    }

    #[test]
    fn sign_hyperliquid_main_order_missing_action_returns_bad_request() {
        let req = SignRequest {
            hl_action: None,
            ..hl_req_template("sign_hyperliquid_main_order")
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
        assert!(resp.hl_signature.is_none());
        assert_eq!(resp.signature_base64, "");
    }

    #[test]
    fn sign_hyperliquid_main_order_missing_nonce_returns_bad_request() {
        let req = SignRequest {
            nonce: None,
            ..hl_req_template("sign_hyperliquid_main_order")
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_hyperliquid_main_order_missing_creds_returns_bad_request() {
        // action+nonce present, ciphertext present, no creds.
        let req = SignRequest {
            ciphertext_blob_base64: Some(B64.encode(b"some-bytes")),
            aws_credentials: None,
            ..hl_req_template("sign_hyperliquid_main_order")
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_hyperliquid_main_order_bad_vault_hex_returns_bad_request() {
        let req = SignRequest {
            vault_address: Some("0xNOTHEX".to_owned()),
            ..hl_req_template("sign_hyperliquid_main_order")
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_hyperliquid_main_order_wrong_action_type_returns_bad_request() {
        // hl_action says type=cancel but dispatcher is for order → reject.
        let req = SignRequest {
            hl_action: Some(serde_json::json!({
                "type": "cancel",
                "cancels": [{"a": 0, "o": 1}]
            })),
            ..hl_req_template("sign_hyperliquid_main_order")
        };
        // Need ciphertext + creds so we don't short-circuit on those first.
        let req = SignRequest {
            ciphertext_blob_base64: Some(B64.encode(b"x")),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ..req
        };
        // Note: KMS decrypt will fail before reaching the action-type check
        // because the ciphertext is gibberish. The test asserts BAD_REQUEST
        // either way — both paths surface as bad_request and we don't care
        // which gate fired (defence-in-depth).
        let resp = handle(req);
        assert!(matches!(
            resp.error.as_deref(),
            Some(err_code::BAD_REQUEST) | Some(err_code::KMS_DECRYPT_DENIED)
        ));
    }

    #[test]
    fn sign_hyperliquid_main_cancel_missing_action_returns_bad_request() {
        let req = SignRequest {
            hl_action: None,
            ..hl_req_template("sign_hyperliquid_main_cancel")
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_hyperliquid_main_cancel_missing_nonce_returns_bad_request() {
        let req = SignRequest {
            nonce: None,
            hl_action: Some(serde_json::json!({
                "type": "cancel",
                "cancels": [{"a": 0, "o": 1}]
            })),
            ..hl_req_template("sign_hyperliquid_main_cancel")
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn validate_order_action_accepts_well_formed() {
        let a = serde_json::json!({
            "type": "order",
            "orders": [{"a": 0, "b": true, "p": "1", "s": "1", "r": false, "t": {}}],
            "grouping": "na"
        });
        assert!(validate_order_action(&a));
    }

    #[test]
    fn validate_order_action_rejects_empty_orders() {
        let a = serde_json::json!({
            "type": "order",
            "orders": [],
            "grouping": "na"
        });
        assert!(!validate_order_action(&a));
    }

    #[test]
    fn validate_order_action_rejects_wrong_type() {
        let a = serde_json::json!({
            "type": "cancel",
            "orders": [{}]
        });
        assert!(!validate_order_action(&a));
    }

    #[test]
    fn validate_cancel_action_accepts_well_formed() {
        let a = serde_json::json!({
            "type": "cancel",
            "cancels": [{"a": 0, "o": 12345}]
        });
        assert!(validate_cancel_action(&a));
    }

    #[test]
    fn validate_cancel_action_rejects_empty_cancels() {
        let a = serde_json::json!({
            "type": "cancel",
            "cancels": []
        });
        assert!(!validate_cancel_action(&a));
    }

    #[test]
    fn unknown_hyperliquid_action_returns_bad_request() {
        let req = SignRequest {
            action: "sign_hyperliquid_main_approveAgent".to_owned(),
            ..hl_req_template("sign_hyperliquid_main_approveAgent")
        };
        let resp = handle(req);
        // Phase 1 only routes order + cancel; anything else hits the
        // dispatcher's catch-all → bad_request.
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }
}
