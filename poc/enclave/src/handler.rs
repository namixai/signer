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
    err_code, AwsCredentials, BinanceSecret, BybitSecret, KucoinSecret, OkxSecret, SignRequest,
    SignResponse,
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
}
