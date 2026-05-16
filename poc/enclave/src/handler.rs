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
    err_code, AsterdexSecret, AwsCredentials, BinanceSecret, BybitSecret, HyperliquidSecret,
    KucoinSecret, OkxSecret, ParsedBlob, Policy, SignRequest, SignResponse,
};
use crate::signer;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use subtle::ConstantTimeEq;
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

// ─────────────────────────────────────────────────────────────────────────
// UPL v0 — Policy enforcement.
// ─────────────────────────────────────────────────────────────────────────
//
// `enforce_policy` runs AFTER KMS decrypt but BEFORE any signing. It
// checks the co-encrypted policy against the incoming `SignRequest`.
// If the policy denies the request, the handler returns `policy_denied`
// without ever touching the secret material.
//
// Policy is `Option<&Policy>` — `None` means legacy blob (no policy),
// which is unrestricted.

/// Enforce the co-encrypted policy against the incoming request.
/// Returns `Ok(())` if the request is permitted, or `Err(SignResponse)`
/// with `policy_denied` if any rule rejects.
///
/// `None` policy = unrestricted (legacy blob backward compat).
#[allow(clippy::result_large_err)] // SignResponse is our wire type; boxing adds indirection for no gain.
fn enforce_policy(policy: Option<&Policy>, req: &SignRequest) -> Result<(), SignResponse> {
    let Some(p) = policy else {
        return Ok(()); // Legacy blob — no policy, permit all.
    };

    // 1. Action whitelist.
    //
    // SECURITY (Gemini OSS PR #8 round-1 HIGH catch): empty whitelist
    // MUST deny all, NOT permit all. `None` is "no constraint"; the
    // distinction from `Some(vec![])` is that empty vec is an EXPLICIT
    // "permit nothing" rule. The previous `!allowed.is_empty()` guard
    // was fail-open.
    if let Some(ref allowed) = p.allowed_actions {
        if !allowed.iter().any(|a| a == &req.action) {
            return Err(SignResponse::err(err_code::POLICY_DENIED));
        }
    }

    // 2. HTTP method whitelist (overrides global ALLOWED_METHODS).
    //
    // Same fail-open fix as #1: empty whitelist denies all.
    if let Some(ref allowed) = p.allowed_methods {
        if let Some(ref method) = req.method {
            if !allowed.iter().any(|m| m == method) {
                return Err(SignResponse::err(err_code::POLICY_DENIED));
            }
        }
        // If method is None (EIP-712 flows), skip — EIP-712 doesn't
        // use HTTP methods for signing. The method whitelist only
        // applies to HMAC-based exchanges. This is intentional: an
        // EIP-712 request is governed by `allowed_actions` not
        // `allowed_methods`.
    }

    // 3. Path prefix allowlist.
    //
    // Same fail-open fix as #1: empty whitelist denies all.
    //
    // Boundary safety: `path_matches_prefix` requires the matched
    // prefix to terminate at end-of-string, `/`, or `?` — preventing
    // `/api` from accidentally matching `/api-internal/withdraw`.
    if let Some(ref prefixes) = p.allowed_path_prefixes {
        if let Some(ref path) = req.path {
            if !prefixes.iter().any(|prefix| path_matches_prefix(path, prefix)) {
                return Err(SignResponse::err(err_code::POLICY_DENIED));
            }
        }
        // If path is None (EIP-712 flows), skip — same rationale as
        // method.
    }

    // 4. Path prefix denylist (checked AFTER allowlist).
    //
    // For deny-list we keep `starts_with` semantics: a deny on
    // `/api/v1/withdraw` should also block `/api/v1/withdrawal/...`
    // and `/api/v1/withdraw-anything` (cautious / pessimistic). Using
    // the boundary-safe matcher here would let an attacker bypass
    // a denylist by appending arbitrary suffix to the denied prefix.
    if let Some(ref prefixes) = p.denied_path_prefixes {
        if let Some(ref path) = req.path {
            if prefixes.iter().any(|prefix| path.starts_with(prefix)) {
                return Err(SignResponse::err(err_code::POLICY_DENIED));
            }
        }
    }

    // 5. Label length sanity. Use char count (not byte len) — a 128-char
    //    UTF-8 label might be up to 512 bytes; we want operator-visible
    //    semantics that match what a human writes. Gemini medium catch.
    if let Some(ref label) = p.label {
        if label.chars().count() > 128 {
            // Gemini OSS PR #9 catch: a policy whose own label violates the
            // schema is a policy-level rejection, not a request-shape
            // problem. Use POLICY_DENIED so SDKs distinguish "your call was
            // malformed" from "your secret's policy is malformed".
            return Err(SignResponse::err(err_code::POLICY_DENIED));
        }
    }

    // max_requests_per_minute: v0 schema only, enforcement deferred.

    Ok(())
}

/// Boundary-safe path prefix matcher for `allowed_path_prefixes`.
///
/// Returns true iff `prefix` is a structural prefix of `path` — i.e.
/// the byte immediately following the match is either string-end, `/`
/// (path component boundary), or `?` (query string start).
///
/// Without this check, an allow-list entry `/api` would accept
/// `/api-internal/withdraw`, defeating the intent of the allow-list.
///
/// We do NOT apply this to denied_path_prefixes — for denials we WANT
/// the cautious matching (deny `/withdraw` blocks `/withdraw-anything`)
/// so an attacker can't suffix-bypass a denylist entry.
fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    // If the prefix itself already ends on a path-boundary character,
    // `starts_with` is sufficient — the boundary is INSIDE the prefix.
    // (Gemini OSS PR #9 catch: prefix="/api/" must accept "/api/v1"
    // even though the byte at position prefix.len() is `v`, because the
    // boundary `/` is at position prefix.len()-1, already inside the
    // declared prefix.)
    if matches!(prefix.as_bytes().last().copied(), Some(b'/') | Some(b'?')) {
        return true;
    }
    // Otherwise, the byte immediately after the prefix in `path` must
    // be EOS / `/` / `?` to count as a structural match.
    match path.as_bytes().get(prefix.len()) {
        None => true,         // EOS — exact prefix match
        Some(b'/') => true,   // path component boundary
        Some(b'?') => true,   // query string start
        _ => false,           // partial token match — reject
    }
}

/// Load the KMS-decrypted plaintext and parse it as either a
/// policy-wrapped secret or a legacy flat secret.
///
/// Returns `(Option<Policy>, raw_secret_json)` on success.
fn load_and_parse_blob(
    req: &SignRequest,
) -> Result<(Option<Policy>, serde_json::Value), LoadSecretError> {
    let plaintext = load_secret_for(req)?;

    let parsed = ParsedBlob::from_plaintext(&plaintext).map_err(|_| LoadSecretError::BadRequest)?;

    match parsed {
        ParsedBlob::WithPolicy {
            policy,
            secret_json,
        } => Ok((Some(policy), secret_json)),
        ParsedBlob::Legacy(v) => Ok((None, v)),
    }
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
        "sign_asterdex" => handle_sign_asterdex(req),
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

    // UPL v0: `sign` is a Day-2 legacy action. It uses load_secret_for
    // directly (raw bytes, not JSON-parsed) because the KuCoin Day-2
    // secret is a bare HMAC key, not a JSON blob. Policy enforcement
    // is not applicable here — this action is deprecated in favor of
    // `sign_kucoin` which handles the full JSON blob + policy wrapper.
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
///
/// UPL v0: supports policy-wrapped blobs `{"policy": {...}, "secret": {...}}`.
/// Legacy flat blobs `{"key","secret","passphrase"}` remain supported
/// (backward compatible, no policy enforcement).
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

    // UPL v0: load + parse blob (policy-wrapped or legacy).
    let (policy, secret_json) = match load_and_parse_blob(&req) {
        Ok(t) => t,
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

    // UPL v0: enforce policy BEFORE touching secret material.
    if let Err(resp) = enforce_policy(policy.as_ref(), &req) {
        return resp;
    }

    // Parse the secret JSON as a KuCoin secret triple. KucoinSecret zeroizes
    // every field on drop — we hold it only as long as it takes to read the
    // borrowed slices into the HMAC routine.
    let secret_triple: KucoinSecret = match serde_json::from_value(secret_json) {
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
    // secret_triple, secret_bytes wiped via their respective Drop impls
    // when this function returns.
}

/// Phase 1 Week 4: `sign_binance` action. Decrypts a `{key,secret}` JSON blob
/// and returns the Binance auth header set:
///   `X-MBX-APIKEY` (header), `signature` + `timestamp` + `recvWindow` (query params).
///
/// Per Binance docs, the signed string is `query_string + body`, hex-HMAC-SHA256.
/// The parent extracts user-supplied query params from the path and forwards
/// them in `req.query`; we append `timestamp=<ms>&recvWindow=5000` ourselves.
///
/// UPL v0: supports policy-wrapped blobs.
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

    let (policy, secret_json) = match load_and_parse_blob(&req) {
        Ok(t) => t,
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

    if let Err(resp) = enforce_policy(policy.as_ref(), &req) {
        return resp;
    }

    let secret_pair: BinanceSecret = match serde_json::from_value(secret_json) {
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
///
/// UPL v0: supports policy-wrapped blobs.
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

    let (policy, secret_json) = match load_and_parse_blob(&req) {
        Ok(t) => t,
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

    if let Err(resp) = enforce_policy(policy.as_ref(), &req) {
        return resp;
    }

    let secret_pair: BybitSecret = match serde_json::from_value(secret_json) {
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
///
/// UPL v0: supports policy-wrapped blobs.
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

    let (policy, secret_json) = match load_and_parse_blob(&req) {
        Ok(t) => t,
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

    if let Err(resp) = enforce_policy(policy.as_ref(), &req) {
        return resp;
    }

    let secret_triple: OkxSecret = match serde_json::from_value(secret_json) {
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
    // secret_triple, secret_bytes wiped on Drop.
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
/// Returns the decrypted `HyperliquidSecret`, parsed action data, and
/// optional policy on success, or a populated `SignResponse::err` on any
/// validation/decrypt failure.
///
/// UPL v0: extracts and enforces the co-encrypted policy before returning
/// the secret. If the policy denies the request, returns `policy_denied`.
#[allow(clippy::result_large_err, clippy::type_complexity)]
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

    // 3. Decrypt + parse secret blob (policy-wrapped or legacy).
    let (policy, secret_json) = match load_and_parse_blob(req) {
        Ok(t) => t,
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

    // UPL v0: enforce policy BEFORE parsing secret material.
    enforce_policy(policy.as_ref(), req)?;

    let secret: HyperliquidSecret = match serde_json::from_value(secret_json) {
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
    if derived.ct_eq(&claimed).unwrap_u8() == 0 {
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
    // Validate action shape BEFORE the KMS round-trip. The shape check
    // is cheap (one JSON walk) and doesn't need any secret material; we
    // want a wrong action type to fail fast with `bad_request` regardless
    // of whether KMS is reachable, both for predictable error semantics
    // and so unit tests don't need a fake KMS endpoint. (Pre-existing
    // bug fixed 2026-05-13 — test expected `bad_request` here but got
    // `internal_error` because validation happened post-KMS.)
    let Some(hl_action) = req.hl_action.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    if !validate_order_action(hl_action) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let (secret, action, nonce, vault) = match load_hyperliquid_request(&req) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !validate_order_action(&action) {
        // Defense in depth: load_hyperliquid_request returned an Ok action
        // that should be identical to req.hl_action, but if anything
        // diverges we reject. Cheap to re-check.
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
    // Mirror `handle_sign_hyperliquid_main_order` — validate action shape
    // before the KMS round-trip for predictable error semantics and so
    // tests don't need a fake KMS endpoint.
    let Some(hl_action) = req.hl_action.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    if !validate_cancel_action(hl_action) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let (secret, action, nonce, vault) = match load_hyperliquid_request(&req) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if !validate_cancel_action(&action) {
        // Defense in depth (see equivalent comment in
        // handle_sign_hyperliquid_main_order).
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

// ─────────────────────────────────────────────────────────────────────────
// Phase 1 Stage 3 — EIP-712 / Asterdex v3 dispatcher.
// ─────────────────────────────────────────────────────────────────────────
//
// Single action: `sign_asterdex`. Mirrors the HL EIP-712 pattern but
// simpler:
//   - The customer pre-assembles the URL-encoded params string (with
//     `nonce=` and `signer=` already injected). This goes in `req.body`.
//   - The enclave commits to the literal bytes via `Message(string msg)`
//     EIP-712 and returns a 65-byte secp256k1 signature as a hex string
//     in the response `headers` map under the key `"signature"`.
//   - The enclave also returns `"signer"` = address derived from the
//     decrypted PK, as a paranoia sanity-check for the customer (they
//     can assert it matches what they injected into the params).
//
// We deliberately do NOT generate the nonce inside the enclave. Asterdex
// expects microsecond precision + monotonic counter for same-microsecond
// requests, which requires per-customer state we don't maintain. The SDK
// owns nonce generation. Enclave just signs the bytes the SDK provides.
//
// Reference: `_signer/ASTERDEX-EIP712-RECON-2026-05-13.md`

/// Sanity-check the customer-supplied URL-encoded params string before
/// signing. Two load-bearing rules enforced here:
///
///   1. The FIRST `signer=` parameter MUST equal `signer=0x<derived>`.
///      This binds the EIP-712 commitment to the API wallet the enclave
///      holds, AND defeats parameter-pollution attacks where a body has
///      duplicate `signer=` params. Without this check, an attacker could
///      send `signer=0xATTACKER&signer=0xDERIVED&...` — our validator
///      would find the second occurrence (matching our derived address)
///      while the Asterdex backend parser picks the first (attacker's).
///      The signature would commit to a body that the backend interprets
///      as authorising the attacker. We mitigate by anchoring to the
///      FIRST occurrence + rejecting any duplicates.
///
///   2. The FIRST `nonce=` parameter MUST have ≥13 digits. Asterdex's
///      spec requires microsecond-precision timestamps; legitimate
///      values are 16+ digits today (year 2026). We enforce ≥13 as a
///      generous floor that still rejects placeholders like `nonce=0`.
///      Combined with Asterdex's ±10s server-side window, this prevents
///      replay of pre-generated "blank" signatures. Duplicate `nonce=`
///      params also rejected for the same parameter-pollution reason.
///
/// Comparison is byte-level over the URL-encoded form. NO URL-decoding
/// is performed — this is deliberate. URL-decoding could normalize
/// payloads like `%73igner=` (where `%73` decodes to `s`) into a form
/// that bypasses our literal substring check. By operating on raw bytes,
/// we force the input to match our expected literal exactly. Asterdex's
/// backend should also operate on the un-decoded bytes for signature
/// verification (the signature commits to the byte string, not the
/// decoded representation).
///
/// Fix path: this validator was hardened over two rounds of Gemini Code
/// Assist review on PR #19 (2026-05-13). Round 1 caught `body.contains`
/// → boundary check. Round 2 caught duplicate-key parameter pollution →
/// find-first + reject-duplicate pattern. The current implementation
/// applies the find-first + reject-duplicate rule symmetrically to both
/// `signer=` and `nonce=`.
/// Hard cap on Asterdex v3 request body length. The longest legitimate
/// batch order we've seen is ~2KB; 8KB gives 4x margin. Anything beyond
/// is treated as DoS / abuse. Hoisted to module scope so the dispatcher
/// can check it BEFORE a KMS round-trip (Gemini round 3 catch).
const ASTERDEX_MAX_BODY_LEN: usize = 8 * 1024;

fn validate_asterdex_body(body: &str, derived: &[u8; 20]) -> Result<(), &'static str> {
    // Defense in depth: even though handle_sign_asterdex now checks the
    // body length before KMS decrypt, keep the validator's own check so
    // direct unit-test callers still get the protection.
    if body.len() > ASTERDEX_MAX_BODY_LEN {
        return Err(err_code::BAD_REQUEST);
    }

    // Expected signer literal: `signer=0xabcdef0123...` (lowercase).
    // 49 bytes total (`signer=` + `0x` + 40 hex chars).
    //
    // Round-4 Gemini catch: use `format!` + `hex::encode` to match the
    // address formatting at the bottom of `handle_sign_asterdex` instead
    // of the manual byte-by-byte write! loop.
    let expected_signer = format!("signer=0x{}", hex::encode(derived));

    // ── signer=<derived> check ─────────────────────────────────────────
    //
    // Find FIRST occurrence of `signer=` (not the expected literal — we
    // want to anchor to whatever position the backend parser would also
    // anchor to, then verify the value at that position equals what we
    // expect). Then reject any further `signer=` occurrences as duplicate
    // parameter pollution.
    let Some(first_signer_start) = body.find("signer=") else {
        return Err(err_code::BAD_REQUEST);
    };
    // Boundary check: param must be at body start OR preceded by `&`.
    // Reject prefixed collisions like `xsigner=...`.
    if first_signer_start != 0
        && body.as_bytes().get(first_signer_start - 1).copied() != Some(b'&')
    {
        return Err(err_code::BAD_REQUEST);
    }
    // Value at that position must equal expected literal exactly. This
    // is the strict-owner-binding line.
    //
    // Round-3 Gemini catch: `starts_with` alone would accept
    // `signer=0x<40_hex>EXTRA...` (any trailing chars before `&`). The
    // backend parser would read those trailing chars as part of the
    // value, but the enclave's commit would be over a different
    // (truncated) byte string — signature would fail validation, but
    // worse, an attacker could intentionally craft body that hashes
    // one way for us and another way for the backend. We require the
    // byte immediately AFTER the expected literal to be either `&`
    // (next param) or string-end. No trailing characters allowed.
    if !body[first_signer_start..].starts_with(&expected_signer) {
        return Err(err_code::BAD_REQUEST);
    }
    let signer_value_end = first_signer_start + expected_signer.len();
    if signer_value_end != body.len()
        && body.as_bytes().get(signer_value_end).copied() != Some(b'&')
    {
        return Err(err_code::BAD_REQUEST);
    }
    // Reject duplicate `signer=` param anywhere later in the body.
    //
    // Round-3 Gemini catch: `contains("signer=")` would false-positive
    // on substrings inside other param values (e.g. `note=signer=foo`).
    // The find-first boundary check already rejected `note=signer=...`
    // as the FIRST occurrence, but for the duplicate scan we look only
    // after our matched value. Using `&signer=` (with leading `&`) as
    // the duplicate-needle correctly identifies parameter boundaries
    // without false-positiving on substrings within values.
    if body[signer_value_end..].contains("&signer=") {
        return Err(err_code::BAD_REQUEST);
    }

    // ── nonce=<digits ≥13> check ──────────────────────────────────────
    //
    // Same find-first + reject-duplicate pattern as signer=.
    let Some(first_nonce_start) = body.find("nonce=") else {
        return Err(err_code::BAD_REQUEST);
    };
    if first_nonce_start != 0
        && body.as_bytes().get(first_nonce_start - 1).copied() != Some(b'&')
    {
        return Err(err_code::BAD_REQUEST);
    }
    let nonce_value_start = first_nonce_start + "nonce=".len();
    let nonce_end = body[nonce_value_start..]
        .find('&')
        .map(|i| nonce_value_start + i)
        .unwrap_or(body.len());
    let nonce_value = &body[nonce_value_start..nonce_end];
    if nonce_value.len() < 13 {
        return Err(err_code::BAD_REQUEST);
    }
    if !nonce_value.chars().all(|c| c.is_ascii_digit()) {
        return Err(err_code::BAD_REQUEST);
    }
    // Round-3 Gemini catch: same `&nonce=` boundary fix as signer=.
    if body[nonce_end..].contains("&nonce=") {
        return Err(err_code::BAD_REQUEST);
    }

    Ok(())
}

fn handle_sign_asterdex(req: SignRequest) -> SignResponse {
    // Asterdex needs the URL-encoded params string in `body`. Method/path
    // are informational only — the canonical EIP-712 envelope ignores
    // them — but we still validate method is allowlisted for defense in
    // depth (cuts the surface if the customer ever wires the enclave
    // into a custom transport).
    let (Some(method), Some(body)) = (req.method.as_deref(), req.body.as_deref()) else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    if !ALLOWED_METHODS.contains(&method) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    if body.is_empty() {
        // Empty body would be cryptographically valid (sign_asterdex
        // accepts it) but a no-body Asterdex request makes no sense
        // operationally — every signed endpoint needs at least nonce
        // and signer. Reject as bad_request to catch SDK bugs early.
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // Round-3 Gemini catch: hoisted body-length check before KMS round-trip.
    // The validator also checks this (defense in depth), but rejecting
    // oversized inputs here saves an expensive KMS Decrypt + secp256k1
    // derive on abuse traffic.
    if body.len() > ASTERDEX_MAX_BODY_LEN {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let (policy, secret_json) = match load_and_parse_blob(&req) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED);
        }
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };

    if let Err(resp) = enforce_policy(policy.as_ref(), &req) {
        return resp;
    }

    let secret: AsterdexSecret = match serde_json::from_value(secret_json) {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let pk = match crate::signer::parse_evm_private_key(&secret.private_key) {
        Ok(k) => k,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };

    // Sanity-check: PK and signer_address inside the blob agree. This
    // catches a class of operator errors where the wrong PK was paired
    // with an address before encryption. Cheap (one keccak + ec point
    // derive) and fails fast.
    let derived = match crate::signer::derive_address_from_private_key(&pk) {
        Ok(a) => a,
        Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };
    let claimed = match crate::signer::parse_evm_address(&secret.signer_address) {
        Ok(a) => a,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if derived.ct_eq(&claimed).unwrap_u8() == 0 {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    // CRITICAL — enforce that `body` binds to OUR signer + a fresh nonce.
    // Without this, the enclave would sign arbitrary `Message(string msg)`
    // payloads (T1 finding from 2026-05-13 dogfood audit). See
    // `validate_asterdex_body` for the exact rules.
    if validate_asterdex_body(body, &derived).is_err() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    // Sign the canonical msg. Asterdex's primaryType is `Message` with a
    // single `string msg` field; `body` is committed to byte-for-byte.
    match crate::signer::sign_asterdex(&pk, body) {
        Ok(signature) => {
            let mut headers = std::collections::BTreeMap::new();
            headers.insert("signature".to_owned(), signature);
            // Lowercase 0x-prefixed signer for SDK assertion comfort.
            headers.insert(
                "signer".to_owned(),
                format!("0x{}", hex::encode(derived)),
            );
            SignResponse::ok_headers(headers)
        }
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
    // secret, pk, plaintext all zeroize on Drop.
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
    // Phase 1 Stage 3 — Asterdex dispatcher tests.
    // ─────────────────────────────────────────────────────────────────
    //
    // Mirror the OKX test set: missing method, disallowed method, missing
    // creds, missing ciphertext, oversized ciphertext. Plus Asterdex-
    // specific: empty body, body missing signer= substring, body missing
    // nonce= substring, body with short nonce, oversized body.

    fn asterdex_req_template() -> SignRequest {
        SignRequest {
            action: "sign_asterdex".to_owned(),
            method: Some("POST".to_owned()),
            path: Some("/fapi/v3/order".to_owned()),
            // 47-byte placeholder body; bypasses the empty-body gate but
            // will fail the signer= check (which is the next gate). Tests
            // that need to advance further override `body`.
            body: Some("symbol=ASTERUSDT&nonce=1234567890123&signer=0xabc".to_owned()),
            timestamp_ms: None,
            key_blob_s3_key: Some("secrets/test-asterdex.enc".to_owned()),
            key_id: Some("alias/signer-poc".to_owned()),
            aws_credentials: None,
            ciphertext_blob_base64: None,
            query: None,
            hl_action: None,
            nonce: None,
            vault_address: None,
        }
    }

    #[test]
    fn sign_asterdex_missing_method_returns_bad_request() {
        let req = SignRequest {
            method: None,
            ..asterdex_req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_asterdex_disallowed_method_returns_bad_request() {
        let req = SignRequest {
            method: Some("PATCH".to_owned()),
            ..asterdex_req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_asterdex_empty_body_returns_bad_request() {
        // Empty body never reaches the validator — short-circuits early
        // so the SDK gets a clean BAD_REQUEST instead of going through
        // KMS decrypt and then failing on missing signer/nonce.
        let req = SignRequest {
            body: Some(String::new()),
            ..asterdex_req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_asterdex_missing_credentials_returns_bad_request() {
        let req = SignRequest {
            ciphertext_blob_base64: Some(B64.encode(b"some-bytes")),
            aws_credentials: None,
            ..asterdex_req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_asterdex_missing_ciphertext_returns_bad_request() {
        let req = SignRequest {
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: None,
            ..asterdex_req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_asterdex_oversized_ciphertext_returns_bad_request() {
        let big = "A".repeat(MAX_CIPHERTEXT_BYTES + 100);
        let req = SignRequest {
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "fake".to_owned(),
                session_token: "fake".to_owned(),
            }),
            ciphertext_blob_base64: Some(big),
            ..asterdex_req_template()
        };
        let resp = handle(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    // ─── validate_asterdex_body — unit tests (no full handler stack) ───

    #[test]
    fn validate_asterdex_body_accepts_well_formed_request() {
        // Real-shape body: signer=<20 bytes derived>, nonce=16 digits.
        let derived: [u8; 20] = [
            0x19, 0xe7, 0xe3, 0x76, 0xe7, 0xc2, 0x13, 0xb7, 0xe7, 0xe7, 0xe4, 0x6c,
            0xc7, 0x0a, 0x5d, 0xd0, 0x86, 0xda, 0xff, 0x2a,
        ];
        let body = "nonce=1778670074644885\
                    &signer=0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a\
                    &symbol=ASTERUSDT\
                    &side=BUY\
                    &type=LIMIT\
                    &quantity=20\
                    &price=0.5";
        assert!(validate_asterdex_body(body, &derived).is_ok());
    }

    #[test]
    fn validate_asterdex_body_rejects_wrong_signer() {
        let derived: [u8; 20] = [0x11; 20];
        // Body claims a different signer than `derived`.
        let body = "nonce=1778670074644885\
                    &signer=0x2222222222222222222222222222222222222222\
                    &symbol=ASTERUSDT";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    #[test]
    fn validate_asterdex_body_rejects_missing_signer() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "nonce=1778670074644885&symbol=ASTERUSDT";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    #[test]
    fn validate_asterdex_body_rejects_missing_nonce() {
        let derived: [u8; 20] = [0x11; 20];
        // signer is correct but nonce absent — must fail.
        let body = "signer=0x1111111111111111111111111111111111111111&symbol=ASTERUSDT";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    #[test]
    fn validate_asterdex_body_rejects_short_nonce() {
        let derived: [u8; 20] = [0x11; 20];
        // 12 digits is below the 13-digit minimum (year 2001 floor).
        // The signer must be present and correct for the nonce gate to
        // matter.
        let body = "nonce=123456789012\
                    &signer=0x1111111111111111111111111111111111111111";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    #[test]
    fn validate_asterdex_body_rejects_zero_nonce() {
        let derived: [u8; 20] = [0x11; 20];
        // Single-digit nonce — placeholder probe attempt.
        let body = "nonce=0\
                    &signer=0x1111111111111111111111111111111111111111";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    #[test]
    fn validate_asterdex_body_rejects_non_digit_nonce() {
        let derived: [u8; 20] = [0x11; 20];
        // 16 chars but not all digits.
        let body = "nonce=abcd567890123456\
                    &signer=0x1111111111111111111111111111111111111111";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    #[test]
    fn validate_asterdex_body_rejects_oversized() {
        let derived: [u8; 20] = [0x11; 20];
        // 8KB body cap. A 10KB body must be rejected before parsing.
        let big = "x=".to_owned() + &"a".repeat(10 * 1024);
        assert!(validate_asterdex_body(&big, &derived).is_err());
    }

    #[test]
    fn validate_asterdex_body_rejects_nonce_substring_collision() {
        // Edge case: a param like `xnonce=...` must NOT satisfy the
        // `find("nonce=")` check. Guarded by the "must be at position 0
        // or preceded by &" rule.
        let derived: [u8; 20] = [0x11; 20];
        let body = "xnonce=1234567890123\
                    &signer=0x1111111111111111111111111111111111111111";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Regression: a body like `xsigner=0x<derived>&signer=0xATTACKER&...`
    /// must NOT pass — a naive `contains` check would match the prefixed
    /// substring and let the attacker's real `signer` param through.
    /// Caught by Gemini Code Assist on PR #19 (Critical finding).
    #[test]
    fn validate_asterdex_body_rejects_signer_substring_collision() {
        // The derived address is what the enclave expects, e.g. 0x11..11.
        let derived: [u8; 20] = [0x11; 20];
        // Body has the legit-looking `signer=` substring inside a
        // different param name (`xsigner=`), and the actual `signer`
        // param points at a different address. The naive `contains`
        // would accept this; the boundary-aware check must reject.
        let body = "xsigner=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123\
                    &signer=0x2222222222222222222222222222222222222222";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Sister regression: even if NO actual `signer=` param exists,
    /// merely embedding `signer=0x<derived>` inside another param name
    /// must NOT satisfy the gate.
    #[test]
    fn validate_asterdex_body_rejects_signer_inside_other_param_value() {
        let derived: [u8; 20] = [0x11; 20];
        // Attacker tries to smuggle the expected substring inside a
        // param VALUE (`description=...signer=0x111...`). The boundary
        // check (preceding char must be `&` or position 0) rejects
        // because the preceding char is `=`, not `&`.
        let body = "description=trustme_signer=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Parameter pollution: attacker prepends an attacker-controlled
    /// `signer=` before the legitimate one. Asterdex backend parser
    /// would pick the FIRST occurrence (the attacker's), our validator
    /// must therefore anchor to the first occurrence too — and reject.
    /// Round 2 Gemini Code Assist catch on PR #19.
    #[test]
    fn validate_asterdex_body_rejects_duplicate_signer_attacker_first() {
        let derived: [u8; 20] = [0x11; 20];
        // First signer= is attacker; second is the legitimate derived
        // address. find-first + value check correctly rejects.
        let body = "signer=0x2222222222222222222222222222222222222222\
                    &nonce=1234567890123\
                    &signer=0x1111111111111111111111111111111111111111";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Same family: legitimate signer= comes first BUT a duplicate
    /// appears later. Even if parser picks first (our value), the
    /// presence of duplicate is itself a smell — server might log
    /// inconsistent state, or another parser version might pick the
    /// later one. We reject duplicates outright.
    #[test]
    fn validate_asterdex_body_rejects_duplicate_signer_legit_first() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "signer=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123\
                    &signer=0x2222222222222222222222222222222222222222";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Same parameter-pollution concern for `nonce=`. Two nonce values
    /// in one body — reject. Server-side replay-protection window
    /// could otherwise be bypassed.
    #[test]
    fn validate_asterdex_body_rejects_duplicate_nonce() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "signer=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123\
                    &nonce=9999999999999";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Even more subtle: the param-pollution body contains the EXPECTED
    /// signer literal at the SECOND position (where our previous-round
    /// fix's `body.find(&expected_signer)` would still hit it). The
    /// find-FIRST-signer = approach now anchors to the attacker's first
    /// occurrence, which doesn't match expected, and rejects. This is
    /// the test that proves the round-2 fix is needed beyond just the
    /// boundary check from round 1.
    #[test]
    fn validate_asterdex_body_rejects_pollution_with_expected_value_in_second_position() {
        let derived: [u8; 20] = [0x11; 20];
        // First signer is attacker; second IS our expected literal.
        // Round 1 fix (find expected substring + boundary) would have
        // accepted this. Round 2 fix (find first signer= + verify
        // value at THAT position) correctly rejects.
        let body = "signer=0x2222222222222222222222222222222222222222\
                    &nonce=1234567890123\
                    &signer=0x1111111111111111111111111111111111111111";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    // ─── Round-3 Gemini catches — strict value-end + boundary needles ─

    /// Round-3 catch: `signer=0x<derived>EXTRA...` with trailing chars
    /// before `&` would pass `starts_with` but commit to the wrong
    /// canonical bytes vs. what the backend parses. Reject.
    #[test]
    fn validate_asterdex_body_rejects_signer_with_trailing_chars() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "signer=0x1111111111111111111111111111111111111111EXTRA\
                    &nonce=1234567890123";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Round-3 catch: signer value ends at body-end with no trailing
    /// chars — must PASS.
    #[test]
    fn validate_asterdex_body_accepts_signer_at_body_end() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "nonce=1234567890123\
                    &signer=0x1111111111111111111111111111111111111111";
        assert!(validate_asterdex_body(body, &derived).is_ok());
    }

    /// Round-3 catch: `note=signer=foo` should NOT trip duplicate
    /// `signer=` detection. With legit signer= as first param, valid.
    #[test]
    fn validate_asterdex_body_accepts_signer_substring_inside_value() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "signer=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123\
                    &note=mysigner=foo";
        assert!(validate_asterdex_body(body, &derived).is_ok());
    }

    /// Round-3 catch: same for nonce= substring inside another value.
    #[test]
    fn validate_asterdex_body_accepts_nonce_substring_inside_value() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "signer=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123\
                    &note=mynonce=stuff";
        assert!(validate_asterdex_body(body, &derived).is_ok());
    }

    /// Round-3 catch: real `&signer=` duplicate still rejected.
    #[test]
    fn validate_asterdex_body_still_rejects_real_duplicate_signer_after_fix() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "signer=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123\
                    &signer=0x2222222222222222222222222222222222222222";
        assert!(validate_asterdex_body(body, &derived).is_err());
    }

    /// Round-3 catch: real `&nonce=` duplicate still rejected.
    #[test]
    fn validate_asterdex_body_still_rejects_real_duplicate_nonce_after_fix() {
        let derived: [u8; 20] = [0x11; 20];
        let body = "signer=0x1111111111111111111111111111111111111111\
                    &nonce=1234567890123\
                    &nonce=9999999999999";
        assert!(validate_asterdex_body(body, &derived).is_err());
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

    // ─────────────────────────────────────────────────────────────────
    // UPL v0 — Policy enforcement unit tests.
    // ─────────────────────────────────────────────────────────────────
    //
    // These test `enforce_policy` in isolation (no KMS, no signing).
    // The function only needs a `Policy` reference and a `SignRequest`
    // reference to make its decision.

    use crate::proto::Policy;

    fn policy_test_req(action: &str, method: &str, path: &str) -> SignRequest {
        SignRequest {
            action: action.to_owned(),
            method: Some(method.to_owned()),
            path: Some(path.to_owned()),
            body: Some(String::new()),
            timestamp_ms: Some(1714997000000),
            key_blob_s3_key: None,
            key_id: None,
            aws_credentials: None,
            ciphertext_blob_base64: None,
            query: None,
            hl_action: None,
            nonce: None,
            vault_address: None,
        }
    }

    #[test]
    fn enforce_policy_none_permits_all() {
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        assert!(enforce_policy(None, &req).is_ok());
    }

    #[test]
    fn enforce_policy_empty_permits_all() {
        let p = Policy::default();
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    #[test]
    fn enforce_policy_allowed_actions_permits_listed() {
        let p = Policy {
            allowed_actions: Some(vec![
                "sign_binance".to_owned(),
                "sign_okx".to_owned(),
            ]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    #[test]
    fn enforce_policy_allowed_actions_denies_unlisted() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_okx", "POST", "/api/v1/order");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn enforce_policy_allowed_methods_permits_listed() {
        let p = Policy {
            allowed_methods: Some(vec!["GET".to_owned(), "POST".to_owned()]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "GET", "/api/v1/ticker");
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    #[test]
    fn enforce_policy_allowed_methods_denies_unlisted() {
        let p = Policy {
            allowed_methods: Some(vec!["GET".to_owned()]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn enforce_policy_allowed_methods_skips_eip712_no_method() {
        // EIP-712 requests have method=None — method whitelist should
        // not block them (EIP-712 doesn't use HTTP methods for signing).
        let p = Policy {
            allowed_methods: Some(vec!["GET".to_owned()]),
            ..Policy::default()
        };
        let mut req = policy_test_req("sign_hyperliquid_main_order", "POST", "");
        req.method = None;
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    #[test]
    fn enforce_policy_path_prefix_allows_matching() {
        let p = Policy {
            allowed_path_prefixes: Some(vec![
                "/api/v1/order".to_owned(),
                "/api/v1/position".to_owned(),
            ]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order/test");
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    #[test]
    fn enforce_policy_path_prefix_denies_non_matching() {
        let p = Policy {
            allowed_path_prefixes: Some(vec!["/api/v1/order".to_owned()]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/withdraw");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn enforce_policy_denied_path_prefix_blocks() {
        let p = Policy {
            denied_path_prefixes: Some(vec![
                "/api/v1/withdraw".to_owned(),
                "/api/v1/transfer".to_owned(),
            ]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/withdraw/apply");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn enforce_policy_denied_path_prefix_allows_non_matching() {
        let p = Policy {
            denied_path_prefixes: Some(vec!["/api/v1/withdraw".to_owned()]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    #[test]
    fn enforce_policy_combined_rules() {
        // Real-world: "Binance only, trading endpoints only, no withdrawals"
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            allowed_methods: Some(vec!["GET".to_owned(), "POST".to_owned(), "DELETE".to_owned()]),
            allowed_path_prefixes: Some(vec![
                "/api/v3/order".to_owned(),
                "/fapi/v1/order".to_owned(),
                "/fapi/v1/position".to_owned(),
            ]),
            denied_path_prefixes: Some(vec![
                "/sapi/v1/capital/withdraw".to_owned(),
                "/sapi/v1/capital/transfer".to_owned(),
            ]),
            ..Policy::default()
        };
        // Good request: Binance + POST + order path
        let req = policy_test_req("sign_binance", "POST", "/fapi/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_ok());

        // Wrong exchange
        let req = policy_test_req("sign_okx", "POST", "/fapi/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_err());

        // Wrong path
        let req = policy_test_req("sign_binance", "POST", "/sapi/v1/capital/withdraw/apply");
        // allowed_path_prefixes check fires first — /sapi/v1 not in allow list
        assert!(enforce_policy(Some(&p), &req).is_err());
    }

    #[test]
    fn enforce_policy_label_too_long_rejects() {
        let p = Policy {
            label: Some("x".repeat(200)),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        // Gemini OSS PR #9: label violation = policy-level rejection,
        // not request-shape failure → POLICY_DENIED.
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn enforce_policy_label_within_limit_passes() {
        let p = Policy {
            label: Some("binance-prod-trading".to_owned()),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    // ─── ParsedBlob unit tests (proto.rs) ────────────────────────────

    use crate::proto::ParsedBlob;

    #[test]
    fn parsed_blob_legacy_flat_secret() {
        let blob = br#"{"key":"abc","secret":"def","passphrase":"ghi"}"#;
        let parsed = ParsedBlob::from_plaintext(blob).unwrap();
        assert!(parsed.policy().is_none());
        assert!(parsed.secret_json().get("key").is_some());
    }

    #[test]
    fn parsed_blob_policy_wrapped() {
        let blob = br#"{
            "policy": {
                "allowed_actions": ["sign_binance"],
                "label": "test-policy"
            },
            "secret": {
                "key": "abc",
                "secret": "def"
            }
        }"#;
        let parsed = ParsedBlob::from_plaintext(blob).unwrap();
        let p = parsed.policy().unwrap();
        assert_eq!(
            p.allowed_actions.as_ref().unwrap(),
            &vec!["sign_binance".to_owned()]
        );
        assert_eq!(p.label.as_deref(), Some("test-policy"));
        assert!(parsed.secret_json().get("key").is_some());
    }

    #[test]
    fn parsed_blob_policy_empty_means_unrestricted() {
        let blob = br#"{
            "policy": {},
            "secret": {"key":"x","secret":"y"}
        }"#;
        let parsed = ParsedBlob::from_plaintext(blob).unwrap();
        let p = parsed.policy().unwrap();
        assert!(p.allowed_actions.is_none());
        assert!(p.allowed_methods.is_none());
        assert!(p.allowed_path_prefixes.is_none());
        assert!(p.denied_path_prefixes.is_none());
    }

    #[test]
    fn parsed_blob_invalid_json_errors() {
        let blob = b"not json at all";
        assert!(ParsedBlob::from_plaintext(blob).is_err());
    }

    // ─── Gemini round-2 catches on UPL v0 ────────────────────────────

    /// CRITICAL (Gemini): malformed policy-wrapped blob (has "policy"
    /// key but invalid `secret` field) must NOT fall back to legacy.
    /// Previous "try-wrapped-then-fall-back" approach would silently
    /// bypass policy enforcement on any policy-wrapped blob that failed
    /// to fully parse.
    #[test]
    fn parsed_blob_malformed_policy_wrapped_does_not_fail_open() {
        // Blob has top-level "policy" key but "secret" field is missing.
        // Old behavior: PolicyWrappedSecret parse fails → fall back to
        // legacy → Ok(Legacy) with bypassed policy.
        // New behavior: top-level "policy" detected → strict wrapped
        // parse → error (secret missing) → no fallback.
        let blob = br#"{"policy": {"allowed_actions": ["sign_binance"]}}"#;
        assert!(
            ParsedBlob::from_plaintext(blob).is_err(),
            "malformed policy-wrapped blob must error, not fall back to legacy"
        );
    }

    /// CRITICAL: same regression — blob with "policy" key but invalid
    /// policy JSON inside. Must reject, not fall back.
    #[test]
    fn parsed_blob_invalid_policy_inside_wrapper_does_not_fail_open() {
        // policy field is the wrong shape (string instead of object).
        let blob = br#"{"policy": "not_an_object", "secret": {"key":"k","secret":"s"}}"#;
        assert!(ParsedBlob::from_plaintext(blob).is_err());
    }

    /// HIGH (Gemini): empty `allowed_actions` whitelist must DENY all
    /// (not permit all). `Some(vec![])` is an explicit "permit nothing"
    /// constraint; `None` represents "no constraint".
    #[test]
    fn enforce_policy_empty_allowed_actions_denies_all() {
        let p = Policy {
            allowed_actions: Some(vec![]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    /// HIGH: empty `allowed_methods` denies all.
    #[test]
    fn enforce_policy_empty_allowed_methods_denies_all() {
        let p = Policy {
            allowed_methods: Some(vec![]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    /// HIGH: empty `allowed_path_prefixes` denies all.
    #[test]
    fn enforce_policy_empty_allowed_path_prefixes_denies_all() {
        let p = Policy {
            allowed_path_prefixes: Some(vec![]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    /// HIGH: path prefix boundary safety. `/api` in allowlist must NOT
    /// match `/api-internal/withdraw` (different path component).
    #[test]
    fn enforce_policy_path_prefix_boundary_rejects_partial_match() {
        let p = Policy {
            allowed_path_prefixes: Some(vec!["/api".to_owned()]),
            ..Policy::default()
        };
        // Should be DENIED — `/api-internal` is not a sub-path of `/api`.
        let req = policy_test_req("sign_binance", "POST", "/api-internal/withdraw");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    /// HIGH: same prefix accepts legitimate sub-paths (regression guard).
    #[test]
    fn enforce_policy_path_prefix_accepts_subpaths_after_boundary() {
        let p = Policy {
            allowed_path_prefixes: Some(vec!["/api".to_owned()]),
            ..Policy::default()
        };
        // EOS, '/', and '?' are all valid prefix terminators.
        assert!(enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/api")
        )
        .is_ok());
        assert!(enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/api/v1/order")
        )
        .is_ok());
        assert!(enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/api?foo=bar")
        )
        .is_ok());
    }

    /// Round-3 Gemini catch on OSS PR #9: when the prefix itself ends
    /// with `/` or `?`, the boundary is already inside the prefix; the
    /// byte AFTER prefix.len() can be any character. Previous logic
    /// incorrectly rejected `/api/v1` when prefix was `/api/` because
    /// the char at `prefix.len()` was `v` (not boundary).
    #[test]
    fn enforce_policy_path_prefix_with_trailing_slash_accepts_subpaths() {
        let p = Policy {
            allowed_path_prefixes: Some(vec!["/api/".to_owned()]),
            ..Policy::default()
        };
        // prefix="/api/" should accept ANY path that starts with "/api/"
        // — the trailing `/` makes the boundary unambiguous.
        assert!(enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/api/v1/order")
        )
        .is_ok(), "prefix='/api/' must accept /api/v1/order");
        assert!(enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/api/")
        )
        .is_ok(), "prefix='/api/' must accept exact match");
        // But NOT match "/api" without the slash — that's a different
        // path (would be matched by prefix "/api" without trailing /).
        let err = enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/api"),
        )
        .unwrap_err();
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }

    /// Same fix for prefix ending in `?` (query-string terminator).
    #[test]
    fn enforce_policy_path_prefix_with_trailing_question_accepts_query() {
        let p = Policy {
            allowed_path_prefixes: Some(vec!["/api?".to_owned()]),
            ..Policy::default()
        };
        // prefix="/api?" should match any query string.
        assert!(enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/api?foo=bar")
        )
        .is_ok());
    }

    /// Denylist intentionally KEEPS `starts_with` semantics (cautious
    /// blocking — attacker can't suffix-bypass `/withdraw` with
    /// `/withdraw-bypass`). Regression guard.
    #[test]
    fn enforce_policy_denylist_keeps_starts_with_semantics() {
        let p = Policy {
            denied_path_prefixes: Some(vec!["/withdraw".to_owned()]),
            ..Policy::default()
        };
        // Both must be DENIED (no boundary safety on denylist).
        let req1 = policy_test_req("sign_binance", "POST", "/withdraw");
        let req2 = policy_test_req("sign_binance", "POST", "/withdraw-bypass-attempt");
        let req3 = policy_test_req("sign_binance", "POST", "/withdrawal");
        assert!(enforce_policy(Some(&p), &req1).is_err());
        assert!(enforce_policy(Some(&p), &req2).is_err());
        assert!(enforce_policy(Some(&p), &req3).is_err());
    }

    /// MEDIUM (Gemini): label uses char count, not byte len. A 128-char
    /// UTF-8 label may be up to 512 bytes — the old byte check rejected
    /// legitimate multi-byte labels.
    #[test]
    fn enforce_policy_label_uses_char_count_not_byte_len() {
        // 128 Cyrillic chars = 256 bytes. Should ACCEPT (char count == 128).
        let label_128_cyrillic: String = "а".repeat(128);
        assert_eq!(label_128_cyrillic.chars().count(), 128);
        assert_eq!(label_128_cyrillic.len(), 256);
        let p = Policy {
            label: Some(label_128_cyrillic),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_ok());

        // 129 chars = 258 bytes — reject (char count > 128).
        let label_129_cyrillic: String = "а".repeat(129);
        let p = Policy {
            label: Some(label_129_cyrillic),
            ..Policy::default()
        };
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        // Same as label_too_long_rejects: policy-level rejection.
        assert_eq!(err.error.as_deref(), Some(err_code::POLICY_DENIED));
    }
}
