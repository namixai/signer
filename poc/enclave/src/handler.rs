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
    err_code, zeroize_json_value, AsterdexSecret, AwsCredentials, BinanceSecret, BybitSecret,
    HyperliquidSecret, KucoinSecret, OkxSecret, ParsedBlob, Policy, SecretJson, SignRequest,
    SignResponse,
};
use crate::signer;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Historical note: the recursive Value-wipe helper `zeroize_json_value`
// was originally defined here for the Gemini PR #55 round-5 SEC-HIGH fix
// inside `handle_verify_blob`. It has since moved to `proto.rs` so both
// the verify path and the new `SecretJson` newtype (sign path) share one
// implementation. The doc-comment block is kept here because the
// architectural rationale applies to both call sites and Gemini's
// round-5 review anchored on the variable name in this module.
//
// `serde_json::Value` does NOT implement Zeroize on drop, so naive
// `drop(value)` leaves API-key / passphrase / private-key strings in
// freed-but-unwiped heap memory — readable via post-mortem dump or
// use-after-free oracles. The implementation in `proto.rs` walks values
// and `std::mem::take`s each `String`, pushes the bytes through
// `Zeroize`, and drops the wiped `Vec<u8>`. Map keys are NOT wiped —
// they are structural field names ("key", "secret", "passphrase",
// "policy") chosen by the wrapper schema, not customer data. Same
// compromise the existing `KucoinSecret` / `BinanceSecret` / etc.
// structs accept implicitly: per-field Zeroize attribute targets
// values only.
//
// Sign-path follow-up (this PR): the same transient-heap-leak existed
// in every sign handler — `load_and_parse_blob` returned the raw
// `serde_json::Value` to per-venue handlers, then `enforce_policy` ran,
// then `serde_json::from_value` consumed the Value into a Zeroize-derived
// `*Secret` struct. Three leak windows existed:
//   1. Steady-state between load_and_parse_blob → from_value (multi-line,
//      includes enforce_policy).
//   2. Early-return on enforce_policy denial.
//   3. Early-return on from_value failure.
// Closed in this PR by changing `load_and_parse_blob`'s return type to
// `(Option<Policy>, SecretJson)`. `SecretJson::Drop` wipes inner Value
// strings on every early-return path (closes 1 + 2). `SecretJson::
// deserialize_into` deserializes via `T::deserialize(&self.0)` (no
// clone, no move-out; `&serde_json::Value: Deserializer`) and wipes
// `self.0` explicitly after. Closes (3) except for serde's per-field
// partial-T allocations on Err — strictly smaller leak surface than
// full-Value clone. Critically, deserializing from `&self.0` (not from
// a moved-out local) means a panic in `T::deserialize` triggers
// `SecretJson::Drop` during stack unwinding, wiping the Value before
// its heap pages are freed.
//
// Gemini rounds: r1 SEC-HIGH (clone → reference), r2 SEC-CRITICAL
// (move-out + Null swap → in-place deserialize so Drop still runs on
// panic).

/// Allow-listed HTTP methods. Anything else short-circuits to `bad_request`
/// before we touch the secret. Defense-in-depth against a compromised parent
/// asking us to sign arbitrary verbs.
const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE"];

/// Hard cap on the ciphertext blob size we accept inline. KMS-Decrypt with
/// recipient-encryption envelopes are typically <2 KiB — 8 KiB is plenty
/// of headroom and well under our 64 KiB wire cap.
const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024;

/// Explicit byte ceiling on a `sign_data` (attested-data) payload. A
/// funding/OI/basis bundle across all venues is a few KiB; 32 KiB is generous
/// headroom while still bounding enclave parse/canonicalize RAM and staying
/// under the 64 KiB wire frame. Larger payloads → `BadRequest`.
const MAX_ATTESTED_DATA_BYTES: usize = 32 * 1024;

/// Load + decrypt the signing secret for this request via KMS.
///
/// Phase 3 contract:
///   - `req.aws_credentials` must be present (parent forwards STS creds).
///   - `req.ciphertext_blob_base64` must be present (parent fetched blob from S3).
///
/// On any decryption error we map to a `DecryptError` so the caller can
/// distinguish denied-by-policy from internal failure.
/// Per-blob key generation bound into the sealed-identity AAD. Constant `1` for
/// the initial wrap; a key rotation bumps it (which is itself a blob re-wrap).
/// `rewrap-with-context.sh` MUST seal blobs with the matching value.
const KEY_VERSION: u32 = 1;

/// Minimum wire-protocol version a signing request must declare. A gateway that
/// predates PR-B sends `proto_version = 0` (serde default) and no opaque token;
/// rejecting it here prevents silently signing without tenant isolation (R4).
const REQUIRED_PROTO_VERSION: u8 = 1;

/// KMS EncryptionContext the tenant-registry blob is wrapped under. Fixed system
/// namespace (not a tenant) — the registry is decrypted only on `registry_refresh`.
fn registry_blob_context() -> std::collections::HashMap<String, String> {
    let mut c = std::collections::HashMap::with_capacity(2);
    c.insert("customer_id".to_owned(), "registry-system".to_owned());
    c.insert("venue_id".to_owned(), "registry".to_owned());
    c
}

/// `registry_challenge` — issue a fresh nonce for the parent to relay to the
/// control plane. Returned in `signature_base64` (generic ok payload).
fn handle_registry_challenge() -> SignResponse {
    SignResponse::ok(crate::registry::challenge())
}

/// `registry_refresh` — KMS-decrypt the registry blob, then validate + install
/// it (signature over the fresh nonce + version + content hash). The KMS
/// decrypt requires the attested enclave (PCR0), so the registry's tokens are
/// confidential to the enclave; the Ed25519 signature provides freshness +
/// anti-rollback (design §5.2 Ruling 3). Distinct action with NO shared code
/// path with the signing handlers (round-1 C9).
fn handle_registry_refresh(req: SignRequest) -> SignResponse {
    let params = match &req.registry_refresh {
        Some(p) => p,
        None => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let creds = match req.aws_credentials.as_ref() {
        Some(c) => c,
        None => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let ciphertext = match req
        .ciphertext_blob_base64
        .as_deref()
        .and_then(|b| B64.decode(b.as_bytes()).ok())
    {
        Some(c) if !c.is_empty() && c.len() <= MAX_CIPHERTEXT_BYTES => c,
        _ => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let ctx = registry_blob_context();
    let entries_json = match kms_client::decrypt(creds, &ciphertext, Some(&ctx)) {
        Ok(p) => p,
        Err(_) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
    };
    match crate::registry::refresh(
        &entries_json,
        &params.nonce_hex,
        params.version,
        &params.signature_hex,
    ) {
        Ok(version) => {
            tracing::info!(event = "registry_refreshed", version);
            SignResponse::ok(version.to_string())
        }
        Err(e) => {
            tracing::warn!(event = "registry_refresh_rejected", error = %e);
            SignResponse::err(err_code::BAD_REQUEST)
        }
    }
}

/// Reserved system identity for the x402 payer key (CTO decision). NOT a secret
/// (it's a fixed namespace id, fine as an EIF constant); the x402 TOKEN lives in
/// the KMS-encrypted registry blob, not the EIF. The registry entry for this id
/// has `allowed_venues = ["x402"]`, and NO real tenant carries `"x402"` — so the
/// venue ACL keeps x402 isolated even before KMS context (defense-in-depth).
pub const X402_CUSTOMER_ID: &str = "x402-00000000-0000-0000-0000-0000000x402";

/// Map a signing `action` to the venue whose blob + context it uses. Returns
/// `None` for non-blob actions (ping / registry_*) and `verify_blob` (which
/// takes its venue from `req.venue_id`, the operator picks it). x402 maps to the
/// reserved `"x402"` venue so its ACL gate is uniform with tenant venues.
fn venue_for_action(action: &str) -> Option<&'static str> {
    match action {
        "sign_binance" | "sign_binance_order" | "sign_binance_cancel" | "sign_binance_request" => {
            Some("binance")
        }
        "sign_okx" | "sign_okx_order" | "sign_okx_cancel" => Some("okx"),
        "sign_kucoin" => Some("kucoin"),
        "sign_bybit" => Some("bybit"),
        "sign_hyperliquid_main_order" | "sign_hyperliquid_main_cancel" => Some("hyperliquid_main"),
        // HL TESTNET (source="b", no real funds) — a SEPARATE venue from mainnet
        // (which is hard-denied). Its own blob/key (the sealed demo agent wallet)
        // + its own tenant grant `allowed_venues:["hyperliquid_testnet"]`.
        "sign_hyperliquid_testnet_order" | "sign_hyperliquid_testnet_cancel" => {
            Some("hyperliquid_testnet")
        }
        "sign_asterdex" => Some("asterdex"),
        "sign_x402_eip3009" => Some("x402"),
        // Attested-signed-data (P2). The data-signing key is a service-owned
        // secp256k1 key, NOT a tenant venue key. Its sealed KMS context is the
        // fixed `{customer_id:"attested-data", venue_id:"data-signing"}` — so the
        // caller's resolved identity MUST be the data-signing service identity
        // (customer_id == "attested-data", allowed_venues == ["data-signing"]).
        // Any tenant identity fails BOTH the venue ACL (no grant) AND, even if
        // that were bypassed, the KMS context match (their customer_id ≠
        // "attested-data" → AccessDenied). Operator-tier gating at the gateway
        // is the primary gate; this is enclave-side defense-in-depth.
        "sign_data" => Some("data-signing"),
        _ => None,
    }
}

/// Enforce the venue ACL for an ALREADY-resolved identity — BEFORE any blob/KMS
/// work (CTO x402 condition: ACL deny must precede any KMS call). The identity
/// is resolved exactly once per request in `handle` (round-1 TOCTOU fix), so the
/// signing path never re-resolves; this only checks the venue grant. Fail-closed:
/// a venue outside the tenant's grant returns a uniform `BadRequest` (no
/// blob-existence oracle).
fn authorize_venue(
    identity: &crate::registry::ResolvedIdentity,
    venue: &str,
    action: &str,
) -> Result<(), LoadSecretError> {
    if !identity.venue_allowed(venue) {
        tracing::warn!(event = "venue_acl_denied", action = %action, "tenant not granted this venue");
        return Err(LoadSecretError::BadRequest);
    }
    Ok(())
}

fn load_secret_for(
    req: &SignRequest,
    identity: &crate::registry::ResolvedIdentity,
    venue: &str,
) -> Result<Zeroizing<Vec<u8>>, LoadSecretError> {
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

    let raw_blob = B64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| LoadSecretError::BadRequest)?;

    if raw_blob.is_empty() || raw_blob.len() > MAX_CIPHERTEXT_BYTES {
        return Err(LoadSecretError::BadRequest);
    }

    // PR-B: the EncryptionContext is built ENTIRELY in-enclave from the
    // resolved identity (design §5.4 / D3) — the gateway no longer supplies a
    // context field, so there is no `SIGNER_REQUIRE_CONTEXT` migration gate and
    // no path that reads a gateway-supplied context. The DEK-cache key folds in
    // THIS context, so a cache hit can only occur for the exact resolved
    // (customer_id, venue) — closing the cache-layer confused-deputy.
    let ctx = identity.encryption_context(venue);
    let enc_ctx = Some(&ctx);
    // Sealed-identity AAD (Option A / D4): bound as real GCM AAD below so a blob
    // wrapped for another customer fails the tag under this resolved identity.
    let aad = identity.sealed_aad(venue, KEY_VERSION);

    if crate::envelope::is_envelope(&raw_blob) {
        let env = crate::envelope::parse_envelope(&raw_blob)
            .map_err(|_| LoadSecretError::BadRequest)?;

        // The wrapped DEK is KMS *ciphertext* (not secret material), so it does
        // not need Zeroizing — keeping it plain avoids a needless wipe pass.
        let wrapped_dek = B64
            .decode(&env.wrapped_dek)
            .map_err(|_| LoadSecretError::BadRequest)?;

        // DEK cache: the first sign on a blob KMS-decrypts the wrapped DEK (as
        // before) and caches the *DEK* (never the venue secret) for a short
        // TTL; subsequent signs within TTL skip the kmstool round-trip and only
        // do the local AES-GCM envelope unwrap below. The cache key folds in the
        // encryption_context, so a hit can only occur for the exact
        // (wrapped_dek, context) pair KMS itself binds — caching never bypasses
        // KMS's cross-customer-substitution protection. Disable with
        // SIGNER_DEK_CACHE_TTL_SECS=0. See dek_cache.rs for the full model.
        let cache = crate::dek_cache::global();
        let cache_key = crate::dek_cache::derive_key(&wrapped_dek, enc_ctx);
        // A hit returns the DEK directly. A miss — OR a poisoned cache (never
        // serve from a possibly-corrupted map↔order) — falls through to a real
        // KMS decrypt. `fresh` marks the KMS-decrypt path so we cache the DEK
        // *after* using it below (minimizes the window where two copies exist).
        let (dek, fresh) = match cache.get(&cache_key) {
            Ok(Some(dek)) => {
                tracing::debug!(event = "dek_cache_hit");
                (dek, false)
            }
            Ok(None) => (dek_cache_miss_decrypt(creds, &wrapped_dek, enc_ctx)?, true),
            Err(_) => {
                tracing::warn!(
                    event = "dek_cache_poisoned",
                    "DEK cache lock poisoned — falling through to KMS decrypt"
                );
                (dek_cache_miss_decrypt(creds, &wrapped_dek, enc_ctx)?, true)
            }
        };

        // Use the DEK while it is still the sole copy on the fresh path, THEN
        // cache a clone — minimizes the concurrent-copy residency window.
        let plaintext = crate::envelope::decrypt_with_dek(&dek, &env, &aad).map_err(|e| {
            tracing::error!(event = "envelope_decrypt_failed", error = %e);
            LoadSecretError::Internal
        })?;
        if fresh {
            // Caching is best-effort: a poisoned cache just means the next sign
            // pays the KMS round-trip again.
            let _ = cache.put(cache_key, dek.clone());
        }

        tracing::info!(event = "envelope_decrypted", version = 2);
        Ok(plaintext)
    } else {
        tracing::debug!(event = "legacy_kms_decrypt");
        kms_decrypt(creds, &raw_blob, enc_ctx)
    }
}

fn kms_decrypt(
    creds: &AwsCredentials,
    ciphertext: &[u8],
    enc_ctx: Option<&std::collections::HashMap<String, String>>,
) -> Result<Zeroizing<Vec<u8>>, LoadSecretError> {
    match kms_client::decrypt(creds, ciphertext, enc_ctx) {
        Ok(plaintext) => Ok(plaintext),
        Err(DecryptError::AccessDenied) => Err(LoadSecretError::KmsDenied),
        Err(DecryptError::Internal) => Err(LoadSecretError::Internal),
    }
}

/// KMS-decrypt a wrapped DEK on a cache miss, with timing instrumentation that
/// isolates the KMS round-trip cost (the ~140ms box-internal floor the cache
/// removes on subsequent signs). Never logs key bytes.
fn dek_cache_miss_decrypt(
    creds: &AwsCredentials,
    wrapped_dek: &[u8],
    enc_ctx: Option<&std::collections::HashMap<String, String>>,
) -> Result<Zeroizing<Vec<u8>>, LoadSecretError> {
    let t0 = std::time::Instant::now();
    let dek = kms_decrypt(creds, wrapped_dek, enc_ctx)?;
    tracing::info!(
        event = "dek_cache_miss",
        kms_decrypt_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    );
    Ok(dek)
}

/// Internal error variants for `load_secret_for`. Keeps the wire-code
/// mapping centralized at each per-venue sign handler.
enum LoadSecretError {
    BadRequest,
    KmsDenied,
    Internal,
    /// C18 (ZLODEY 2026-05-18): operator-set `SIGNER_REQUIRE_POLICY=1`
    /// and the blob is a legacy flat secret. Distinct from PolicyDenied
    /// (that's a runtime UPL rule rejection); this is "your blob shape
    /// is forbidden on this enclave instance".
    PolicyRequired,
}

/// Returns `true` when the enclave was started with `SIGNER_REQUIRE_POLICY=1`.
///
/// Reading the env var on every request is microsecond-cheap and keeps tests
/// trivial (set var → call → unset). For production this is set once via the
/// enclave systemd unit (`Environment=SIGNER_REQUIRE_POLICY=1`) once all
/// staged blobs have been migrated to policy-wrapped form. Leaving the var
/// unset preserves Phase 1 backward compatibility — legacy blobs continue to
/// decrypt and sign as before, but with a warn-log every time so operators
/// see migration drift.
///
/// C18 mitigation (ZLODEY threat hunt 2026-05-18).
///
/// Caching (Gemini PR #28 round-2): `std::env::var` acquires a global
/// process-wide env lock and allocates a String on every call. Per-request
/// reads were a real overhead. Cache via `OnceLock<bool>` so the env is
/// read exactly once at first use — operator wants to flip the value, they
/// restart the enclave (which is the deploy unit anyway — flag change
/// would coincide with a new PCR0 baseline).
///
/// Gemini PR #28 round-4 HIGH catch: the OnceLock would be poisoned across
/// tests if a production-path test ran in parallel with an env-mutating
/// test and locked the cache to a stale value. Fix: `#[cfg(not(test))]`
/// gate on the cache itself. Production gets the cached fast path; test
/// builds always read fresh. Same `policy_required()` symbol both ways
/// so callers don't branch. Drops the separate `policy_required_for_test`
/// helper — tests now call `policy_required()` directly and it Does The
/// Right Thing under each cfg.
#[cfg(not(test))]
fn policy_required() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(parse_require_policy_env)
}

/// Test-build variant: always read env, no cache. Cargo's parallel runner
/// can mutate the var via `EnvVarGuard` without poisoning a singleton.
#[cfg(test)]
fn policy_required() -> bool {
    parse_require_policy_env()
}

/// Pure parser separated from the cache so test-only callers and the
/// production cache initializer share one truth-table.
///
/// Gemini PR #28 round-2: switched to eq_ignore_ascii_case so all
/// mixed-case truthy values (True, TrUe, YES, yEs etc.) are accepted
/// uniformly. Whitespace deliberately NOT trimmed — `" 1"` and `"1 "`
/// must be rejected (operator should write the literal value, not pad
/// it). The previous ad-hoc exact-case list (`"1"|"true"|"TRUE"|"yes"`)
/// silently rejected `"True"` and `"YES"` which a careful operator
/// could easily produce.
fn parse_require_policy_env() -> bool {
    /// All "this means on" spellings, compared case-insensitively. Listed
    /// in one place so adding/removing values is a single-line change.
    /// Gemini PR #28 round-3: replaced the previous `||` chain with an
    /// iterator over this slice for readability.
    const TRUTHY_VALUES: &[&str] = &["1", "true", "yes", "on"];
    std::env::var("SIGNER_REQUIRE_POLICY")
        .ok()
        .map(|s| TRUTHY_VALUES.iter().any(|v| s.eq_ignore_ascii_case(v)))
        .unwrap_or(false)
}

// Gemini PR #28 round-4: dropped the dedicated `policy_required_for_test`
// helper. Under `#[cfg(test)]` the production `policy_required()` itself
// is now an alias for `parse_require_policy_env()` (no cache), so tests
// can call the same symbol the dispatch code does. One symbol, two
// truth-tables per cfg.

// PR-B: the `SIGNER_REQUIRE_CONTEXT` guard is GONE — the enclave always builds
// the EncryptionContext from its own resolved identity, so there is no
// gateway-supplied context to require-or-not (design §5.4 / D7).

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
/// Returns `Ok(policy_hash)` if the request is permitted, or `Err(SignResponse)`
/// with `policy_denied` if any rule rejects. The hash is `Some(hex_sha256)`
/// for policy-wrapped blobs, `None` for legacy blobs (C24).
///
/// `None` policy = unrestricted (legacy blob backward compat).
#[allow(clippy::result_large_err)] // SignResponse is our wire type; boxing adds indirection for no gain.
fn enforce_policy(policy: Option<&Policy>, req: &SignRequest) -> Result<Option<String>, SignResponse> {
    let Some(p) = policy else {
        return Ok(None); // Legacy blob — no policy, no hash.
    };

    // AF-2 floor invariant (rust-auditor 2026-07-11 HIGH): agent-signed-intent is
    // wired into the STRUCTURED order/cancel handlers, but the GENERIC HMAC routes
    // (`sign_binance` / `sign_binance_request` / `sign_okx`) gate order-placement
    // only on `order_caps`. So an `intent_pubkey` policy WITHOUT `order_caps` would
    // leave a compromised gateway a trivial AF-2 bypass: route the trade through a
    // generic route (no intent check, no cap). Requiring `order_caps` whenever
    // `intent_pubkey` is set — enforced HERE, on the path every handler already
    // runs before signing — makes every existing `order_caps` generic-route gate
    // apply to an AF-2 key too, closing the bypass fail-closed at the policy shape.
    // (An AF-2 trading key must be capped anyway — defence in depth, not a cost.)
    if p.intent_pubkey.is_some() && p.order_caps.is_none() {
        tracing::error!(event = "intent_pubkey_without_order_caps");
        return Err(SignResponse::err(err_code::POLICY_REQUIRED));
    }

    // 1. Action whitelist.
    //
    // SECURITY (Gemini OSS PR #8 round-1 HIGH catch): empty whitelist
    // MUST deny all, NOT permit all. `None` is "no constraint"; the
    // distinction from `Some(vec![])` is that empty vec is an EXPLICIT
    // "permit nothing" rule. The previous `!allowed.is_empty()` guard
    // was fail-open.
    if let Some(ref allowed) = p.allowed_actions {
        if !allowed.iter().any(|a| a == &req.action) {
            // explainable-denials: typed subclass of POLICY_DENIED (no value leaked).
            return Err(SignResponse::err(err_code::ACTION_NOT_ALLOWED));
        }
    }

    // 2. HTTP method whitelist (FURTHER RESTRICTS the global
    //    `ALLOWED_METHODS` — cannot widen it).
    //
    // Every sign handler validates `req.method` against the static
    // `ALLOWED_METHODS` set BEFORE calling `load_and_parse_blob`, so by
    // the time we get here, `req.method` is already a global-allowed verb.
    // Policy then narrows the set further (e.g., a read-only key can
    // restrict to `["GET"]` even though the exchange allows POST/DELETE).
    // Gemini OSS PR #9 round-4 wording catch.
    //
    // Same fail-open fix as #1: empty whitelist denies all.
    if let Some(ref allowed) = p.allowed_methods {
        if let Some(ref method) = req.method {
            if !allowed.iter().any(|m| m == method) {
                return Err(SignResponse::err(err_code::ACTION_NOT_ALLOWED));
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
                return Err(SignResponse::err(err_code::ACTION_NOT_ALLOWED));
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
                // explainable-denials: the denied-path-prefix list is the
                // withdrawal-deny primitive (the floor blocks /withdraw etc.).
                // A safe, useful signal — never leaks WHICH prefix matched.
                return Err(SignResponse::err(err_code::WITHDRAWAL_NOT_SIGNABLE));
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

    // C27 (ZLODEY 2026-05-18): max_requests_per_minute is accepted in the
    // policy schema but NOT enforced. Fail-loud: reject rather than silently
    // ignoring the customer's rate-limit intent. Remove this guard once
    // stateful rate-limiting is implemented in the enclave.
    if p.max_requests_per_minute.is_some() {
        return Err(SignResponse::err(err_code::UNIMPLEMENTED_POLICY_FIELD));
    }

    // C24 (ZLODEY 2026-05-18): compute SHA-256 of canonical policy JSON.
    // Same canonical form as TOFU signing: strip signer_pubkey and
    // policy_signature, then serde_json::to_vec. Field order follows
    // Rust struct declaration order (preserve_order feature active).
    let hash = compute_policy_hash(p).map_err(|e| {
        tracing::error!(event = "policy_hash_failed", error = %e);
        SignResponse::err(err_code::INTERNAL_ERROR)
    })?;

    Ok(Some(hash))
}

/// Canonical policy bytes that EVERY policy signature is computed over — the
/// TOFU `policy_signature`, the baked-authority `policy_authority_sig` (PR-D1),
/// and the C24 hash. The policy is serialized with ALL signature-carrying
/// fields cleared (a signature cannot cover itself).
///
/// Field order is Rust struct declaration order (NOT alphabetical) because
/// `serde_json` is compiled with `preserve_order`. External signers MUST
/// serialize fields in the exact order declared in the `Policy` struct
/// (proto.rs). `skip_serializing_if = Option::is_none` already omits absent
/// fields, so clearing `policy_authority_sig` is a no-op for any pre-PR-D1
/// blob (they never carry it) — this refactor does not change any existing
/// hash or TOFU signature.
fn canonical_policy_signable(policy: &Policy) -> Result<Vec<u8>, serde_json::Error> {
    let mut canonical = policy.clone();
    canonical.signer_pubkey = None;
    canonical.policy_signature = None;
    canonical.policy_authority_sig = None;
    serde_json::to_vec(&canonical)
}

/// C24: SHA-256 of the canonical policy JSON, hex-encoded.
fn compute_policy_hash(policy: &Policy) -> Result<String, serde_json::Error> {
    use sha2::{Digest, Sha256};
    let bytes = canonical_policy_signable(policy)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

/// Env holding the hex Ed25519 public key of the off-box policy-authority (our
/// control-plane). Baked into the enclave image (Dockerfile), mirroring the
/// STORAGE pattern of `SIGNER_REGISTRY_PUBKEY` ONLY — the private half never
/// touches the box, cron, or the auto-refresh path (rare manual signing
/// ceremony, vault-only). Absent on a strict-regime box ⇒ money-venue signing
/// fails closed. Rotating this baked value is a PCR0-changing re-attestation
/// event (see kill-switch/ops runbook).
const POLICY_PUBKEY_ENV: &str = "SIGNER_POLICY_PUBKEY";

/// Domain-separation tag for the baked policy-authority signature. Prefixing
/// the signed message makes a policy-authority signature structurally
/// non-interchangeable with any other Ed25519 signature the system produces
/// (registry refresh, TOFU policy_signature) even if a key were ever reused by
/// mistake. Versioned so a future scheme change is unambiguous.
const POLICY_AUTHORITY_DOMAIN: &[u8] = b"signer-policy-authority-v1\0";

/// Money-signing venues subject to the baked-authority floor-gate under
/// `SIGNER_REQUIRE_POLICY=1`. Excludes `x402` (its own MANDATORY fail-closed
/// spend-cap clause governs that withdrawal primitive) and the service
/// `data-signing` key (provisioned in-enclave, not a tenant venue key).
fn is_money_venue(venue: &str) -> bool {
    matches!(
        venue,
        "binance"
            | "binance_futures"
            | "okx"
            | "bybit"
            | "kucoin"
            | "asterdex"
            | "hyperliquid_main"
            | "hyperliquid_testnet"
    )
}

/// Bytes the policy-authority signs: the domain tag, then LENGTH-PREFIXED
/// `customer_id` and `venue` (so `{cust:"a",venue:"bc"}` cannot collide with
/// `{cust:"ab",venue:"c"}`), then the canonical policy JSON. Binding the tenant
/// context means a policy template signed for one `{customer,venue}` cannot be
/// replayed under another tenant's blob.
fn policy_authority_message(customer_id: &str, venue: &str, canonical_policy: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        POLICY_AUTHORITY_DOMAIN.len()
            + 12
            + customer_id.len()
            + venue.len()
            + canonical_policy.len(),
    );
    msg.extend_from_slice(POLICY_AUTHORITY_DOMAIN);
    msg.extend_from_slice(&(customer_id.len() as u32).to_be_bytes());
    msg.extend_from_slice(customer_id.as_bytes());
    msg.extend_from_slice(&(venue.len() as u32).to_be_bytes());
    msg.extend_from_slice(venue.as_bytes());
    msg.extend_from_slice(&(canonical_policy.len() as u32).to_be_bytes());
    msg.extend_from_slice(canonical_policy);
    msg
}

// ════════════════════════════════════════════════════════════════════════════
// AF-2 — agent-signed order intent (gateway-tamper defence).
//
// enforce_order_cap bounds only symbol/qty/notional; side/price/reduce_only/
// ord_type/client_order_id ride into the SIGNED venue canonical unchecked, so a
// compromised gateway can flip direction, set a self-trade price, or turn
// reduce→open — all within the qty cap. The fix: the AGENT signs the FULL order
// intent with its own Ed25519 key, and the enclave reconstructs those exact
// bytes from the same parsed OrderRequest and verifies the agent signature
// BEFORE the venue signature. Any gateway edit of any field breaks the
// signature → deny. The agent pubkey is bound in the policy (`intent_pubkey`),
// itself covered by the authority signature, so the gateway can't swap it.
//
// The canonical serialisation below is the CRUX (CTO 2026-07-11): it MUST be
// byte-exact and deterministic across the agent SDK and this enclave, or a
// tampered field could fail to change the reconstructed bytes (verify passes on
// a tamper) or a legit request could falsely fail. The wire spec is pinned by
// golden vectors (`af2_intent_golden_*`) and a Rust-reference differential
// fuzzer; the agent SDK implements the same spec. See
// `_signer/poc/docs/AF2-INTENT-CANONICAL.md`.
// ════════════════════════════════════════════════════════════════════════════

/// Domain tag for the agent order-intent signature. Domain-separated from the
/// policy-authority tag (`signer-policy-authority-v1\0`) so an agent signature
/// can never be cross-used as a policy-authority signature or vice-versa. The
/// trailing NUL is a hard delimiter (no other domain is a prefix of this one).
const AGENT_INTENT_DOMAIN: &[u8] = b"signer-agent-intent-v1\0";

/// Append a length-prefixed byte string: `u32` BE length, then the bytes. Same
/// framing as `policy_authority_message` — every variable-length field is
/// length-prefixed so no concatenation of two fields can collide with a
/// different split (`{a:"x",b:"yz"}` ≠ `{a:"xy",b:"z"}`).
fn intent_push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Append an optional string: a presence byte (`0x00` absent / `0x01` present),
/// then — only if present — the length-prefixed value. The presence byte
/// disambiguates `None` from `Some("")` (both would otherwise encode identically
/// as a zero-length field, letting a gateway flip one to the other undetected).
fn intent_push_opt(buf: &mut Vec<u8>, val: Option<&str>) {
    match val {
        None => buf.push(0x00),
        Some(v) => {
            buf.push(0x01);
            intent_push_lp(buf, v.as_bytes());
        }
    }
}

/// Canonical ORDER-intent bytes (the agent signs THESE; the enclave rebuilds
/// them from the same parsed `OrderRequest`). FIXED field order:
///   AGENT_INTENT_DOMAIN
///   ‖ lp(customer_id) ‖ lp(venue) ‖ lp(action)
///   ‖ u64_be(timestamp_ms)
///   ‖ lp(nonce)                       // == client_order_id (double-duty)
///   ‖ lp(symbol) ‖ lp(side) ‖ lp(qty) ‖ lp(ord_type)
///   ‖ opt(price) ‖ u8(reduce_only ? 1 : 0)
/// `nonce` IS the order's `client_order_id`, so binding it here also protects
/// the coid from tampering — no separate coid field is needed.
fn build_agent_intent_msg_order(
    customer_id: &str,
    venue: &str,
    action: &str,
    timestamp_ms: u64,
    nonce: &str,
    order: &crate::proto::OrderRequest,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(AGENT_INTENT_DOMAIN);
    intent_push_lp(&mut buf, customer_id.as_bytes());
    intent_push_lp(&mut buf, venue.as_bytes());
    intent_push_lp(&mut buf, action.as_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    intent_push_lp(&mut buf, nonce.as_bytes());
    intent_push_lp(&mut buf, order.symbol.as_bytes());
    intent_push_lp(&mut buf, order.side.as_bytes());
    intent_push_lp(&mut buf, order.qty.as_bytes());
    intent_push_lp(&mut buf, order.ord_type.as_bytes());
    intent_push_opt(&mut buf, order.price.as_deref());
    buf.push(u8::from(order.reduce_only));
    buf
}

/// Canonical CANCEL-intent bytes. FIXED field order:
///   AGENT_INTENT_DOMAIN
///   ‖ lp(customer_id) ‖ lp(venue) ‖ lp(action)
///   ‖ u64_be(timestamp_ms)
///   ‖ lp(nonce)                       // == intent_nonce (client UUID)
///   ‖ lp(symbol) ‖ lp(order_id)
fn build_agent_intent_msg_cancel(
    customer_id: &str,
    venue: &str,
    action: &str,
    timestamp_ms: u64,
    nonce: &str,
    cancel: &crate::proto::CancelRequest,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(AGENT_INTENT_DOMAIN);
    intent_push_lp(&mut buf, customer_id.as_bytes());
    intent_push_lp(&mut buf, venue.as_bytes());
    intent_push_lp(&mut buf, action.as_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    intent_push_lp(&mut buf, nonce.as_bytes());
    intent_push_lp(&mut buf, cancel.symbol.as_bytes());
    intent_push_lp(&mut buf, cancel.order_id.as_bytes());
    buf
}

/// AF-2 core: verify the agent's Ed25519 signature over `intent_msg` against the
/// policy-bound `intent_pubkey`, then dedup the intent in the RAM replay ledger.
/// Fail-closed:
///   - `intent_pubkey` malformed / bad curve ⇒ INTERNAL_ERROR (policy/deploy bug)
///   - `intent_signature` absent / bad hex     ⇒ BAD_REQUEST
///   - signature does not verify (tamper/wrong key) ⇒ BAD_REQUEST
///   - intent already seen (replay)            ⇒ BAD_REQUEST
///
/// The replay record is taken ONLY AFTER the signature verifies, so an
/// unauthenticated caller cannot poison the ledger. The ledger key is the
/// SHA-256 of the (already tenant/venue/nonce-bound, length-prefixed)
/// `intent_msg` — not a delimiter-joined string — so two distinct signed
/// intents can never collide onto one key (rust-auditor 2026-07-11 M: a raw
/// `cust/venue/nonce` join could collide if an agent's nonce contained `/`).
#[allow(clippy::result_large_err)] // SignResponse is the wire type — match enforce_order_cap's allow.
fn verify_agent_intent(
    intent_pubkey_hex: &str,
    intent_signature_hex: Option<&str>,
    intent_msg: &[u8],
) -> Result<(), SignResponse> {
    // Decode directly into stack arrays (Gemini #233): `decode_to_slice` errors
    // on any wrong length or bad hex — no heap alloc on this per-order hot path.
    let mut vk_bytes = [0u8; 32];
    if hex::decode_to_slice(intent_pubkey_hex, &mut vk_bytes).is_err() {
        tracing::error!(event = "intent_pubkey_malformed");
        return Err(SignResponse::err(err_code::INTERNAL_ERROR));
    }
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).map_err(|_| {
        tracing::error!(event = "intent_pubkey_invalid_curve");
        SignResponse::err(err_code::INTERNAL_ERROR)
    })?;
    let Some(sig_hex) = intent_signature_hex else {
        tracing::warn!(event = "intent_signature_missing");
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    };
    let mut sig_bytes = [0u8; 64];
    if hex::decode_to_slice(sig_hex, &mut sig_bytes).is_err() {
        tracing::warn!(event = "intent_signature_malformed");
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    }
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    vk.verify(intent_msg, &sig).map_err(|_| {
        tracing::warn!(event = "intent_signature_rejected");
        SignResponse::err(err_code::BAD_REQUEST)
    })?;
    // Replay dedup keyed on the intent bytes themselves (collision-free).
    let ledger_key = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(intent_msg))
    };
    if !crate::intent_ledger::record_if_new(&ledger_key) {
        tracing::warn!(event = "intent_replay_denied");
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    }
    Ok(())
}

/// AF-2 opt-in enforcement for a structured ORDER. If the policy carries an
/// `intent_pubkey`, the agent MUST have signed the full order intent (nonce =
/// `client_order_id`, double-duty). If it does NOT, the venue is left at the
/// pre-AF-2 posture (cap-only) and tracked as AF-2-exposed via a warn. Ok(())
/// means "proceed to venue-sign".
#[allow(clippy::result_large_err)]
fn enforce_agent_intent_order(
    policy: Option<&Policy>,
    identity: &crate::registry::ResolvedIdentity,
    venue: &str,
    action: &str,
    timestamp_ms: u64,
    order: &crate::proto::OrderRequest,
    req: &SignRequest,
) -> Result<(), SignResponse> {
    let Some(pk) = policy.and_then(|p| p.intent_pubkey.as_deref()) else {
        tracing::warn!(event = "money_venue_intent_unprotected", venue = %venue, action = %action);
        return Ok(());
    };
    let Some(coid) = order.client_order_id.as_deref() else {
        tracing::warn!(event = "intent_order_missing_coid", venue = %venue);
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    };
    let intent_msg =
        build_agent_intent_msg_order(&identity.customer_id, venue, action, timestamp_ms, coid, order);
    verify_agent_intent(pk, req.intent_signature.as_deref(), &intent_msg)
}

/// AF-2 opt-in enforcement for a structured CANCEL. Cancels carry no
/// `client_order_id`, so the replay nonce is the client-supplied `intent_nonce`
/// (a UUID). Replaying a cancel is idempotent at the venue, but the signature
/// still binds every field so a gateway cannot re-target the cancel.
#[allow(clippy::result_large_err)]
fn enforce_agent_intent_cancel(
    policy: Option<&Policy>,
    identity: &crate::registry::ResolvedIdentity,
    venue: &str,
    action: &str,
    timestamp_ms: u64,
    cancel: &crate::proto::CancelRequest,
    req: &SignRequest,
) -> Result<(), SignResponse> {
    let Some(pk) = policy.and_then(|p| p.intent_pubkey.as_deref()) else {
        tracing::warn!(event = "money_venue_intent_unprotected", venue = %venue, action = %action);
        return Ok(());
    };
    let Some(nonce) = req.intent_nonce.as_deref() else {
        tracing::warn!(event = "intent_cancel_missing_nonce", venue = %venue);
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    };
    let intent_msg =
        build_agent_intent_msg_cancel(&identity.customer_id, venue, action, timestamp_ms, nonce, cancel);
    verify_agent_intent(pk, req.intent_signature.as_deref(), &intent_msg)
}

/// Parse the baked `SIGNER_POLICY_PUBKEY` into a stable `Ok(vk)` / `Err(tag)`.
/// `"unset"` = env absent/blank; `"malformed"` = present but bad hex/curve.
fn parse_policy_authority_vk() -> Result<ed25519_dalek::VerifyingKey, &'static str> {
    let hex_str = std::env::var(POLICY_PUBKEY_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("unset")?;
    let bytes: [u8; 32] = hex::decode(&hex_str)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("malformed")?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| "malformed")
}

/// Map the (cached) key-parse tag to a wire error + a PER-REQUEST log so
/// operators still see every rejection even though the parse itself is cached.
/// `"unset"` ⇒ `PolicyRequired` (no authority root — fail closed); malformed ⇒
/// `Internal` (a bad BAKED key is OUR deploy error — never blame the client;
/// Gemini #216 HIGH).
fn map_policy_authority_key_err(tag: &str, venue: &str) -> LoadSecretError {
    if tag == "unset" {
        tracing::warn!(
            event = "policy_authority_no_pubkey",
            venue = %venue,
            "money-venue under SIGNER_REQUIRE_POLICY=1 but SIGNER_POLICY_PUBKEY unset — fail closed"
        );
        LoadSecretError::PolicyRequired
    } else {
        tracing::error!(
            event = "policy_authority_bad_pubkey",
            venue = %venue,
            "SIGNER_POLICY_PUBKEY set but malformed — DEPLOY ERROR, money-venue signing disabled"
        );
        LoadSecretError::Internal
    }
}

/// The baked policy-authority verifying key. Reading the env var on every money
/// -venue signing request would take a process-wide lock + allocate a String on
/// the hot path (Gemini #216 HIGH), so production parses it ONCE via `OnceLock`
/// (mirrors `policy_required()`).
#[cfg(not(test))]
fn policy_authority_vk(venue: &str) -> Result<ed25519_dalek::VerifyingKey, LoadSecretError> {
    static CACHED: std::sync::OnceLock<Result<ed25519_dalek::VerifyingKey, &'static str>> =
        std::sync::OnceLock::new();
    match CACHED.get_or_init(parse_policy_authority_vk) {
        Ok(vk) => Ok(*vk),
        Err(tag) => Err(map_policy_authority_key_err(tag, venue)),
    }
}

/// Test build: read+parse on every call (no cache) so `EnvVarGuard` can toggle
/// `SIGNER_POLICY_PUBKEY` between parallel tests, exactly like `policy_required()`.
#[cfg(test)]
fn policy_authority_vk(venue: &str) -> Result<ed25519_dalek::VerifyingKey, LoadSecretError> {
    parse_policy_authority_vk().map_err(|tag| map_policy_authority_key_err(tag, venue))
}

/// Floor-gate for money-venues under the strict regime: the policy MUST carry a
/// `policy_authority_sig` that verifies against the BAKED `SIGNER_POLICY_PUBKEY`
/// over the tenant-bound message above. This is what makes the withdrawal-deny
/// / caps floor un-forgeable in the Option-1 import flow, where the partner
/// controls the ciphertext and could otherwise TOFU-pin their OWN key on first
/// use, then ship a policy without the floor. Fail-closed:
///   - baked pubkey env absent/blank ⇒ PolicyRequired (no authority root)
///   - baked pubkey present but malformed ⇒ Internal (our deploy error)
///   - `policy_authority_sig` absent  ⇒ PolicyRequired (policy not authority-signed)
///   - malformed sig, or signature that does not verify ⇒ BadRequest
fn verify_policy_authority(
    policy: &Policy,
    customer_id: &str,
    venue: &str,
) -> Result<(), LoadSecretError> {
    let vk = policy_authority_vk(venue)?;
    let Some(sig_hex) = policy.policy_authority_sig.as_deref() else {
        tracing::warn!(
            event = "policy_authority_unsigned",
            venue = %venue,
            "money-venue policy lacks policy_authority_sig under strict regime"
        );
        return Err(LoadSecretError::PolicyRequired);
    };
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(LoadSecretError::BadRequest)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let canonical = canonical_policy_signable(policy).map_err(|_| LoadSecretError::Internal)?;
    let msg = policy_authority_message(customer_id, venue, &canonical);

    use ed25519_dalek::Verifier;
    vk.verify(&msg, &sig).map_err(|_| {
        tracing::warn!(
            event = "policy_authority_rejected",
            venue = %venue,
            "policy_authority_sig failed against baked SIGNER_POLICY_PUBKEY"
        );
        LoadSecretError::BadRequest
    })
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
    // Gemini round-4 catch (HIGH): empty prefix would bypass the allowlist.
    // `path.starts_with("")` is unconditionally true, so a policy with
    // `allowed_path_prefixes: [""]` would silently match any request path.
    // An empty prefix has no security meaning — treat as "matches nothing".
    // The CLI sanity-check rejects empty prefixes at wrap time, but defense
    // in depth: the enclave is the source of truth and must enforce this
    // regardless of what produced the blob (legacy operator scripts,
    // attacker-crafted ciphertext that survives KMS, etc.).
    if prefix.is_empty() {
        return false;
    }
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
    identity: &crate::registry::ResolvedIdentity,
) -> Result<(Option<Policy>, SecretJson), LoadSecretError> {
    // PR-B: enforce the venue ACL on the request's pre-resolved identity BEFORE
    // any blob/KMS work. The identity is resolved exactly once in `handle`
    // (round-1 TOCTOU fix) and threaded in; the venue comes from the action
    // discriminator.
    let venue = venue_for_action(&req.action).ok_or(LoadSecretError::BadRequest)?;
    authorize_venue(identity, venue, &req.action)?;
    // Customer-scoped TOFU/rate namespace (D8) — replaces the gateway-supplied
    // `s3_key.unwrap_or("_default")` shared bucket (cross-tenant oracle + DoS).
    let tofu_key = format!("{}/{}", identity.customer_id, venue);
    let plaintext = load_secret_for(req, identity, venue)?;

    let parsed = ParsedBlob::from_plaintext(&plaintext).map_err(|_| LoadSecretError::BadRequest)?;

    match parsed {
        ParsedBlob::WithPolicy {
            policy,
            secret_json,
        } => {
            // PR-D1 floor-gate: under the strict regime (`SIGNER_REQUIRE_POLICY=1`),
            // a MONEY-venue policy must be signed by the BAKED policy-authority —
            // not merely TOFU-pinnable. In the Option-1 import flow the partner
            // controls the ciphertext and could TOFU-pin their OWN key on first
            // use, then ship a policy without the withdrawal-deny / caps floor.
            // Requiring OUR baked-key signature (tenant-bound, domain-separated)
            // closes that. Non-money venues and the permissive regime keep the
            // existing TOFU behavior untouched.
            if policy_required() && is_money_venue(venue) {
                verify_policy_authority(&policy, &identity.customer_id, venue)?;
                return Ok((Some(policy), SecretJson::new(secret_json)));
            }
            if policy.signer_pubkey.is_some() || policy.policy_signature.is_some() {
                let (pk_hex, sig_hex) = match (&policy.signer_pubkey, &policy.policy_signature) {
                    (Some(pk), Some(sig)) => (pk, sig),
                    _ => {
                        tracing::warn!(
                            event = "tofu_incomplete",
                            has_pubkey = policy.signer_pubkey.is_some(),
                            has_signature = policy.policy_signature.is_some(),
                            "policy has one TOFU field but not both"
                        );
                        return Err(LoadSecretError::BadRequest);
                    }
                };
                let canonical =
                    canonical_policy_signable(&policy).map_err(|_| LoadSecretError::BadRequest)?;
                crate::tofu::verify_and_pin(&tofu_key, &canonical, pk_hex, sig_hex).map_err(|e| {
                    tracing::warn!(event = "tofu_rejected", tofu_key = %tofu_key, error = %e);
                    LoadSecretError::BadRequest
                })?;
            } else {
                crate::tofu::require_if_pinned(&tofu_key).map_err(|e| {
                    tracing::warn!(event = "tofu_unsigned_bypass_blocked", tofu_key = %tofu_key, error = %e);
                    LoadSecretError::BadRequest
                })?;
            }
            Ok((Some(policy), SecretJson::new(secret_json)))
        }
        ParsedBlob::Legacy(v) => {
            // C18 (ZLODEY threat hunt 2026-05-18): a legacy flat-secret blob
            // bypasses UPL entirely (no policy → enforce_policy returns Ok).
            // An attacker with `kms:Encrypt` rights (a permission separate
            // from `kms:Decrypt` and NOT gated on PCR0 attestation) can mint
            // such a blob, swap it on the gateway, and the enclave will sign
            // arbitrarily.
            //
            // Two layers of mitigation:
            //   1. Operator opt-in `SIGNER_REQUIRE_POLICY=1` flips legacy
            //      handling from "permit" to "reject" once production blobs
            //      have been migrated to policy-wrapped form. Until that
            //      migration is complete this MUST stay unset to preserve
            //      backward compat with already-staged Phase 1 blobs.
            //   2. Even when allowed, every legacy decrypt now emits a WARN
            //      log so operators see migration drift in real time.
            //      Telemetry → CloudWatch → alert when count > threshold.
            // C18 telemetry: include the S3 key (when the request carries it)
            // so operators can pinpoint exactly which staged blob is still
            // unmigrated. The key itself is non-sensitive — it's only an S3
            // object name like `secrets/binance.enc` — but we still default
            // to "<unset>" if the field is missing so logs stay structured.
            // Gemini round-1 PR #28 catch.
            let s3_key = req.key_blob_s3_key.as_deref().unwrap_or("<unset>");
            if policy_required() {
                tracing::warn!(
                    event = "legacy_blob_rejected",
                    s3_key = %s3_key,
                    action = %req.action,
                    "SIGNER_REQUIRE_POLICY=1 — legacy blob (no policy) rejected"
                );
                return Err(LoadSecretError::PolicyRequired);
            }
            tracing::warn!(
                event = "legacy_blob_accepted",
                s3_key = %s3_key,
                action = %req.action,
                "legacy blob (no policy) decrypted — migrate to policy-wrapped before next pilot"
            );
            Ok((None, SecretJson::new(v)))
        }
    }
}

/// H5 (`action == "attestation"`): fetch an NSM-signed COSE attestation doc
/// binding the caller nonce. Carries no token and no secret — the document
/// exposes only the enclave's own PUBLIC measurement (PCR0) + cert chain, so it
/// bypasses the tenant/rate gates. The gateway parses PCR0 out of the returned
/// doc and cross-checks it against its deploy-time `SIGNER_PCR0` env.
fn handle_attestation(req: SignRequest) -> SignResponse {
    // Bound the caller inputs BEFORE the NSM ioctl. The NSM API caps each of
    // user_data / nonce / public_key at 1024 bytes; reject oversize or non-hex
    // here so a malformed request fails fast + explicitly as `bad_request`,
    // never as an opaque NSM error. Empty (`Some("")`) is rejected too — a
    // caller that sends the field must mean it.
    const MAX_ATTEST_FIELD: usize = 1024;
    fn decode_bounded(field: Option<&str>) -> Result<Option<Vec<u8>>, ()> {
        match field {
            None => Ok(None),
            Some(h) => {
                // Validate charset + length BEFORE hex::decode so an oversized or
                // non-hex input is rejected WITHOUT allocating a large Vec (DoS
                // hardening — /attestation is public + unauth). 2 hex chars/byte,
                // so the decoded bytes are guaranteed ≤ MAX_ATTEST_FIELD.
                if h.is_empty()
                    || h.len() > MAX_ATTEST_FIELD * 2
                    || h.len() % 2 != 0
                    || !h.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(());
                }
                hex::decode(h).map(Some).map_err(|_| ())
            }
        }
    }
    let nonce = match decode_bounded(req.attestation_nonce.as_deref()) {
        Ok(n) => n,
        Err(()) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let user_data = match decode_bounded(req.attestation_user_data.as_deref()) {
        Ok(u) => u,
        Err(()) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    match crate::attestation::nsm_attestation(nonce, user_data) {
        Ok(doc) => SignResponse::ok_attestation(B64.encode(doc)),
        Err(e) => {
            tracing::error!(
                event = "nsm_attestation_failed",
                detail = ?e,
                "NSM attestation fetch failed"
            );
            SignResponse::err(err_code::INTERNAL_ERROR)
        }
    }
}

/// Dispatch one request and produce one response. Never panics.
pub fn handle(req: SignRequest) -> SignResponse {
    // Registry management + ping bypass the proto-version gate and the
    // per-customer rate limiter (they carry no opaque token and do not sign).
    // `provision_data_key` (attested-data Option-1) also bypasses: it carries no
    // tenant token and uses the FIXED data-signing service identity — its gate is
    // the IAM role (kms:GenerateDataKey, ephemeral scoped), not the registry.
    match req.action.as_str() {
        "ping" => return SignResponse::ok("pong".to_owned()),
        "registry_challenge" => return handle_registry_challenge(),
        "registry_refresh" => return handle_registry_refresh(req),
        "provision_data_key" => return handle_provision_data_key(req),
        // H5: NSM attestation. Bypasses the tenant / rate / proto-version gates
        // below — it carries no opaque token and no secret, and publishes only
        // the enclave's own PUBLIC image measurement (PCR0) inside a COSE doc.
        "attestation" => return handle_attestation(req),
        _ => {}
    }

    // Wire-version gate (D7 / R4): an old gateway (proto_version 0) that does
    // not forward an opaque token would otherwise reach the signing path with
    // no tenant isolation. Reject it with a distinct error rather than sign.
    if req.proto_version < REQUIRED_PROTO_VERSION {
        tracing::warn!(
            event = "proto_version_too_low",
            got = req.proto_version,
            required = REQUIRED_PROTO_VERSION,
            "gateway too old — refusing to sign without enclave-resolved identity"
        );
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    // Resolve the tenant identity EXACTLY ONCE per request (round-1 SHOULD-FIX:
    // a second `registry::resolve` in the signing path opened a TOCTOU window —
    // a concurrent `registry_refresh` (each connection runs in its own task)
    // could swap the registry between the rate-key resolve here and a signing-
    // path resolve, so a request could be rate-limited as one customer and
    // signed as another). The single ResolvedIdentity is threaded through the
    // whole signing path below — there is no second resolve anywhere downstream.
    let identity = req.opaque_token.as_deref().and_then(crate::registry::resolve);

    // Rate-limit per RESOLVED customer (D8) — never a gateway-supplied key. An
    // unresolvable token shares one bounded "unauthenticated" bucket so a
    // bad-token flood can't exhaust a real customer's budget, then fails closed
    // below.
    let rate_key = identity
        .as_ref()
        .map(|id| id.customer_id.as_str())
        .unwrap_or("unauthenticated");
    if !crate::rate_limiter::check(rate_key) {
        tracing::warn!(event = "rate_limited", action = req.action.as_str());
        return SignResponse::err(err_code::RATE_LIMITED);
    }

    // Every remaining action (all sign_* + verify_blob) decrypts a blob under a
    // resolved identity. An unresolvable token never reaches a blob/KMS path —
    // fail closed uniformly with the same BadRequest the venue-ACL emits (no
    // token-validity oracle).
    let Some(identity) = identity.as_ref() else {
        tracing::warn!(event = "unresolved_identity", action = req.action.as_str());
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    match req.action.as_str() {
        "sign" => SignResponse::err(err_code::BAD_REQUEST),
        "sign_kucoin" => handle_sign_kucoin(req, identity),
        "sign_binance" => handle_sign_binance(req, identity),
        "sign_binance_request" => handle_sign_binance_request(req, identity),
        "sign_bybit" => handle_sign_bybit(req, identity),
        "sign_okx" => handle_sign_okx(req, identity),
        "sign_hyperliquid_main_order" => handle_sign_hyperliquid_main_order(req, identity),
        "sign_hyperliquid_main_cancel" => handle_sign_hyperliquid_main_cancel(req, identity),
        "sign_hyperliquid_testnet_order" => handle_sign_hyperliquid_testnet_order(req, identity),
        "sign_hyperliquid_testnet_cancel" => handle_sign_hyperliquid_testnet_cancel(req, identity),
        "sign_asterdex" => handle_sign_asterdex(req, identity),
        "sign_data" => handle_sign_data(req, identity),
        "sign_x402_eip3009" => handle_sign_x402_eip3009(req, identity),
        "sign_binance_order" => handle_sign_binance_order(req, identity),
        "sign_binance_cancel" => handle_sign_binance_cancel(req, identity),
        "sign_okx_order" => handle_sign_okx_order(req, identity),
        "sign_okx_cancel" => handle_sign_okx_cancel(req, identity),
        // Path B-lite (Stage 4 pre-flight): decrypt the blob, emit SHA-256
        // of the plaintext, zeroize. Operator-side proof that the attested
        // enclave can recover every production secret BEFORE Stage 4 cutover.
        // Plaintext NEVER leaves the enclave — only the hex hash on the wire.
        "verify_blob" => handle_verify_blob(req, identity),
        _ => SignResponse::err(err_code::BAD_REQUEST),
    }
}

/// Path B-lite: decrypt the blob via the existing KMS+attestation path,
/// SHA-256 the plaintext, return the hex hash. The plaintext lives in a
/// `Zeroizing<Vec<u8>>` which wipes its bytes on drop — there is no log
/// line, no debug print, no field that surfaces the plaintext outside
/// this function's stack frame.
fn handle_verify_blob(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    use sha2::{Digest, Sha256};

    // CR035 (red-team, 2026-05-29): collapse post-KMS failure modes into a
    // single `verify_failed` wire code so an external caller cannot use the
    // response code as an oracle to distinguish "wrong KMS key" vs "wrong
    // inner ciphertext" vs "decrypted-but-wrong-shape". Granular reason
    // stays in tracing::warn for operator debugging.
    //
    // Pre-KMS BadRequest (missing field, bad base64, oversize) is NOT
    // collapsed — that's caller-supplied malformed input, not a probe oracle.
    // Operator-flag signal (PolicyRequired) also stays distinct: it reveals
    // enclave config but only when the operator explicitly enabled the gate,
    // and that's the intended diagnostic for the operator-side cutover script.
    // PR-B: verify_blob resolves an OPERATOR identity (same registry machinery,
    // not a gateway field). The gateway forwards the target venue in `path`, and
    // the on-disk blob decrypts under the resolved (operator-customer, venue)
    // context + AAD or fails closed — the operator-credential separation lives
    // in the gateway's operator_router (NOT a tenant token). The resolved
    // identity must grant the venue (ACL), so an operator can only verify blobs
    // in its own namespace.
    let venue = req.path.clone().unwrap_or_default();
    if authorize_venue(identity, &venue, &req.action).is_err() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    let plaintext = match load_secret_for(&req, identity, &venue) {
        Ok(pt) => pt,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => {
            tracing::warn!(
                event = "verify_blob_failed",
                internal_code = "kms_decrypt_denied",
                s3_key = req.key_blob_s3_key.as_deref().unwrap_or("<unset>"),
                "verify_blob: KMS rejected decrypt — collapsing to verify_failed on wire (CR035)"
            );
            return SignResponse::err(err_code::VERIFY_FAILED);
        }
        Err(LoadSecretError::Internal) => {
            tracing::warn!(
                event = "verify_blob_failed",
                internal_code = "internal_error",
                s3_key = req.key_blob_s3_key.as_deref().unwrap_or("<unset>"),
                "verify_blob: post-KMS internal failure (envelope AEAD, etc.) — collapsing to verify_failed (CR035)"
            );
            return SignResponse::err(err_code::VERIFY_FAILED);
        }
        // load_secret_for itself never emits PolicyRequired today (the C18
        // gate lives in load_and_parse_blob), but keep the arm so a future
        // refactor that pushes the check earlier doesn't silently mismatch.
        Err(LoadSecretError::PolicyRequired) => return SignResponse::err(err_code::POLICY_REQUIRED),
    };

    // Gemini round-3 HIGH (refined in round-4): always parse the decrypted
    // plaintext, regardless of `policy_required()`. Sign handlers go
    // through `load_and_parse_blob` which rejects unparseable plaintext
    // unconditionally — verify_blob must mirror that so an operator's
    // pre-flight hash never gives false confidence on a blob that the
    // actual sign path would reject.
    //
    // Then, if `policy_required()` is set, additionally reject Legacy
    // blobs (C18 mitigation: prevent verify_blob from being a back door
    // to hash legacy blobs on a strict-policy enclave).
    let mut parsed = match ParsedBlob::from_plaintext(&plaintext) {
        Ok(p) => p,
        Err(_) => {
            // CR035: post-KMS plaintext shape rejection collapses to
            // `verify_failed` rather than `bad_request`. The latter would
            // confirm to an attacker that decrypt succeeded but inner JSON
            // shape was wrong — a powerful signal that "you have access,
            // your wrapper is wrong". Internal log keeps the granular
            // reason for operator debugging.
            tracing::warn!(
                event = "verify_blob_failed",
                internal_code = "post_kms_plaintext_unparseable",
                s3_key = req.key_blob_s3_key.as_deref().unwrap_or("<unset>"),
                "verify_blob: decrypted plaintext failed ParsedBlob::from_plaintext — collapsing to verify_failed (CR035)"
            );
            drop(plaintext);
            return SignResponse::err(err_code::VERIFY_FAILED);
        }
    };
    // Gemini round-5 SEC-HIGH: serde_json::Value does NOT implement
    // Zeroize on drop. The parsed copy of the plaintext lives in heap
    // pages that survive `drop(parsed)` un-wiped. Walk every nested
    // String inside `parsed.secret_json` and zeroize before dropping.
    match &mut parsed {
        ParsedBlob::WithPolicy { secret_json, .. } => zeroize_json_value(secret_json),
        ParsedBlob::Legacy(v) => zeroize_json_value(v),
    }

    if policy_required() && matches!(parsed, ParsedBlob::Legacy(_)) {
        tracing::warn!(
            event = "verify_blob_legacy_rejected",
            s3_key = req.key_blob_s3_key.as_deref().unwrap_or("<unset>"),
            "SIGNER_REQUIRE_POLICY=1 — legacy blob (no policy) rejected in verify_blob"
        );
        drop(parsed);
        drop(plaintext);
        return SignResponse::err(err_code::POLICY_REQUIRED);
    }
    // `parsed` dropped here — the secret_json Strings were just zeroized
    // above so the heap pages backing them are wiped before free.
    drop(parsed);

    // Capture length BEFORE digest so we can drop the plaintext immediately
    // after hashing. Gemini round-1 SEC-MED: previous code re-used `plaintext`
    // for the .len() log AFTER the digest, leaving the Zeroizing buffer
    // alive longer than necessary. Drop explicitly to minimise the window
    // where the bytes sit in enclave memory.
    let plaintext_len = plaintext.len() as u64;
    let digest = Sha256::digest(plaintext.as_slice());
    drop(plaintext); // Zeroizing wipes the bytes on this drop.
    let hex = hex::encode(digest);

    tracing::info!(
        event = "verify_blob_ok",
        plaintext_len,
        plaintext_sha256 = %hex,
        s3_key = req.key_blob_s3_key.as_deref().unwrap_or("<unset>"),
    );

    SignResponse::ok_verify_blob(hex, plaintext_len)
}

/// Day 3 `sign_kucoin` action. Same input contract as `sign` but the decrypted
/// blob is a JSON object `{"key","secret","passphrase"}` and the response
/// carries the full KuCoin v2 auth header set instead of a bare signature.
///
/// UPL v0: supports policy-wrapped blobs `{"policy": {...}, "secret": {...}}`.
/// Legacy flat blobs `{"key","secret","passphrase"}` remain supported
/// (backward compatible, no policy enforcement).
fn handle_sign_kucoin(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
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
    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
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
        Err(LoadSecretError::PolicyRequired) => {
            return SignResponse::err(err_code::POLICY_REQUIRED);
        }
    };

    // UPL v0: enforce policy BEFORE touching secret material.
    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // CR051: kucoin has no sanctioned generic read/cancel route AND no structured
    // (cap-enforced) order route, so a capped kucoin key cannot use the generic
    // path at all — fail-closed (better than signing an uncapped kucoin order).
    if policy.as_ref().and_then(|p| p.order_caps.as_ref()).is_some() {
        tracing::warn!(event = "generic_capped_denied", venue = "kucoin");
        return SignResponse::err(err_code::POLICY_DENIED);
    }

    // Parse the secret JSON as a KuCoin secret triple. KucoinSecret zeroizes
    // every field on drop — we hold it only as long as it takes to read the
    // borrowed slices into the HMAC routine.
    let secret_triple: KucoinSecret = match secret_json.deserialize_into() {
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
        Ok(headers) => SignResponse::ok_headers(headers).with_policy_hash(policy_hash),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
    // secret_triple, secret_bytes wiped via their respective Drop impls
    // when this function returns.
}

/// Payload-aware allow-list for the generic `/sign/binance-request` primitive
/// (`sign_binance_request`). Binance's HMAC covers ONLY the request PARAMS —
/// never the URL path or host — so a `{path, method}` allow-list is bypassable:
/// a client could declare `op="account"` but hand us a WITHDRAWAL payload
/// (`coin=…&address=…&amount=…`) and replay the returned signature against the
/// SAPI withdraw endpoint it forwards to itself. Defense = a POSITIVE per-op
/// param-NAME whitelist: every param in the payload must belong to the named
/// op's schema, else deny BEFORE signing. Withdrawal/transfer params
/// (`address`, `coin`, `amount`, `asset`, `fromSymbol`, …) are in NO trading /
/// read op's schema, so a smuggled withdraw payload is refused up-front.
///
/// MUST match the reference `ALLOWED_PARAMS` in
/// `_spikes/hummingbot-signer/PATCH-READY/mock_sign_binance_request.py`; the
/// golden-vector test (`binance_request_golden_vectors`) pins it byte-identical.
fn binance_request_allowed_params(op: &str) -> Option<&'static [&'static str]> {
    Some(match op {
        "account" => &["recvWindow", "timestamp"],
        "positionRisk" => &["symbol", "recvWindow", "timestamp"],
        "openOrders" => &["symbol", "recvWindow", "timestamp"],
        "orderStatus" => {
            &["symbol", "orderId", "origClientOrderId", "recvWindow", "timestamp"]
        }
        "userTrades" => &[
            "symbol", "startTime", "endTime", "fromId", "limit", "recvWindow", "timestamp",
        ],
        "income" => &[
            "symbol", "incomeType", "startTime", "endTime", "limit", "recvWindow", "timestamp",
        ],
        // USER_STREAM: APIKEY-only (Binance ignores any signature). recvWindow /
        // timestamp are optional and harmless.
        "listenKey" => &["recvWindow", "timestamp"],
        "order" => &[
            "symbol",
            "side",
            "positionSide",
            "type",
            "timeInForce",
            "quantity",
            "reduceOnly",
            "price",
            "newClientOrderId",
            "stopPrice",
            "closePosition",
            "activationPrice",
            "callbackRate",
            "workingType",
            "priceProtect",
            "newOrderRespType",
            "recvWindow",
            "timestamp",
        ],
        "cancel" => &["symbol", "orderId", "origClientOrderId", "recvWindow", "timestamp"],
        "allOpenOrders" => &["symbol", "recvWindow", "timestamp"],
        "leverage" => &["symbol", "leverage", "recvWindow", "timestamp"],
        "positionMode" => &["dualSidePosition", "recvWindow", "timestamp"],
        // Explicitly absent (denied): every withdraw / transfer / sub-account /
        // universal-transfer op. Falls through to `op_not_allowed`.
        _ => return None,
    })
}

/// Ok(()) iff `op` is allow-listed AND every param name in `payload` is in the
/// op's whitelist. Err carries the exact wire reason (`op_not_allowed:<op>` or
/// `param_not_allowed:<op>:<name>`). NEVER signs on Err. Param names are checked
/// against a POSITIVE whitelist, so any encoding trick just yields a name that
/// is not in the set → denied (a positive list has no suffix/decode bypass).
/// AF-1 money-path mitigation for the generic op-based route: a CAPPED key
/// (one whose policy declares `order_caps`) must NEVER place an order through
/// `/sign/binance-request`, because that route HMACs the opaque `payload`
/// verbatim and does NOT parse it against the qty cap — so an over-cap size
/// could not be bounded here. Capped keys route orders through the semantic,
/// cap-enforcing `/sign/binance-order`; READ ops + cancel stay available. This
/// is the guard that keeps the "no cap bypass" invariant on this route; it is
/// extracted (not inline) so it can be pinned directly by a golden test
/// (`golden_binance_request_capped_order_denied`).
fn binance_request_order_denied_for_capped(op: &str, policy: Option<&Policy>) -> bool {
    // Deny `op=order` for a capped key (cap can't be applied to the opaque
    // payload) OR an AF-2 key (this generic route does no intent verification —
    // rust-auditor 2026-07-11 HIGH defence-in-depth; the enforce_policy floor
    // already guarantees an intent key is capped, so this is belt-and-suspenders).
    op == "order"
        && policy
            .map(|p| p.order_caps.is_some() || p.intent_pubkey.is_some())
            .unwrap_or(false)
}

fn check_binance_request_allow(op: &str, payload: &str) -> Result<(), String> {
    let allowed =
        binance_request_allowed_params(op).ok_or_else(|| format!("op_not_allowed:{op}"))?;
    for pair in payload.split('&') {
        if pair.is_empty() {
            continue; // trailing/empty '&' segment, or an empty payload
        }
        let name = pair.split('=').next().unwrap_or("");
        if !allowed.contains(&name) {
            return Err(format!("param_not_allowed:{op}:{name}"));
        }
    }
    Ok(())
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
fn handle_sign_binance(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
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

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
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
        Err(LoadSecretError::PolicyRequired) => {
            return SignResponse::err(err_code::POLICY_REQUIRED);
        }
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // CR051: a capped key may use the generic HMAC path only for enclave-vouched
    // safe reads/cancels — never to obtain an (uncapped) order signature.
    if policy.as_ref().and_then(|p| p.order_caps.as_ref()).is_some()
        && !generic_capped_op_allowed(
            "binance",
            method,
            req.path.as_deref().unwrap_or(""),
            user_query,
            body,
        )
    {
        tracing::warn!(event = "generic_capped_denied", venue = "binance");
        return SignResponse::err(err_code::POLICY_DENIED);
    }

    let secret_pair: BinanceSecret = match secret_json.deserialize_into() {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_pair.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let secret_bytes = Zeroizing::new(secret_pair.secret.as_bytes().to_vec());

    match signer::compute_binance_headers(&secret_bytes, &secret_pair.key, ts, user_query, body) {
        Ok(headers) => SignResponse::ok_headers(headers).with_policy_hash(policy_hash),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

/// `/sign/binance-request` — the keyless generic Binance signer (collapses the 9
/// authed operations a stock Hummingbot connector needs into one primitive).
/// Signs the client's EXACT `payload` string so the signature is byte-identical
/// to a local-HMAC connector — but ONLY after the payload's params pass the
/// POSITIVE per-op allow-list (`check_binance_request_allow`). That allow-list
/// is the mainnet security boundary: it refuses any withdrawal/transfer payload
/// BEFORE signing, independent of the endpoint the client forwards to (Binance
/// HMAC covers params only, not the path). Returns `{signature, api_key}` in the
/// headers map.
/// Canonical `(HTTP method, Binance path)` for an allow-listed op. The enclave
/// derives this ITSELF from the op — it never trusts a gateway-supplied
/// method/path — so `enforce_policy` checks the TRUE Binance route the op maps
/// to. Without this the policy's `allowed_methods` / `allowed_path_prefixes` /
/// `denied_path_prefixes` would be un-checkable on this generic endpoint. The
/// op set MUST stay in lock-step with `binance_request_allowed_params`
/// (`binance_request_op_tables_consistent` pins it). Values mirror the golden
/// vectors.
fn binance_request_method_path(op: &str) -> Option<(&'static str, &'static str)> {
    Some(match op {
        "account" => ("GET", "/fapi/v2/account"),
        "positionRisk" => ("GET", "/fapi/v2/positionRisk"),
        "openOrders" => ("GET", "/fapi/v1/openOrders"),
        "orderStatus" => ("GET", "/fapi/v1/order"),
        "userTrades" => ("GET", "/fapi/v1/userTrades"),
        "income" => ("GET", "/fapi/v1/income"),
        // POST — this op carries `dualSidePosition`, i.e. it SETS the position
        // mode (`POST /fapi/v1/positionSide/dual`). Mapping it to GET would let a
        // write-denying method-policy pass a mode change (Gemini #218 HIGH). A
        // pure GET read of the mode, if ever needed, is a SEPARATE op.
        "positionMode" => ("POST", "/fapi/v1/positionSide/dual"),
        "listenKey" => ("POST", "/fapi/v1/listenKey"),
        "leverage" => ("POST", "/fapi/v1/leverage"),
        "order" => ("POST", "/fapi/v1/order"),
        "cancel" => ("DELETE", "/fapi/v1/order"),
        "allOpenOrders" => ("DELETE", "/fapi/v1/allOpenOrders"),
        _ => return None,
    })
}

fn handle_sign_binance_request(
    mut req: SignRequest,
    identity: &crate::registry::ResolvedIdentity,
) -> SignResponse {
    // Take `op`/`payload` OUT of `req` (owned) so we can mutate `req.method` /
    // `req.path` below without a borrow conflict.
    let (Some(op), Some(payload)) = (req.op.take(), req.payload.take()) else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    // Allow-list BEFORE loading any secret — an op/param violation never touches
    // key material. explainable-denials (Gemini #227 HIGH): emit a STATIC wire
    // class (`action_not_allowed` → 403), NOT the dynamic `op_not_allowed:<op>` /
    // `param_not_allowed:<op>:<name>` reason. The dynamic reason (which names the
    // op/param) stays in the operator log below ONLY — surfacing it verbatim
    // would (a) miss the wire allow-list → collapse to 500, and (b) leak the
    // policy boundary (allow-list enumeration), breaking the no-leak invariant.
    if let Err(reason) = check_binance_request_allow(&op, &payload) {
        tracing::warn!(event = "binance_request_denied", op = %op, reason = %reason);
        return SignResponse::err(err_code::ACTION_NOT_ALLOWED);
    }

    // Derive the canonical route from the (allow-listed) op INSIDE the enclave —
    // never from a gateway-supplied field — and stamp it on `req` so
    // `enforce_policy` below checks the true Binance method + path for this op.
    let Some((method, path)) = binance_request_method_path(&op) else {
        // Unreachable: every op that passes the param allow-list has a route
        // (pinned by `binance_request_op_tables_consistent`). Fail closed.
        tracing::error!(event = "binance_request_no_route", op = %op);
        return SignResponse::err(err_code::INTERNAL_ERROR);
    };
    req.method = Some(method.to_owned());
    req.path = Some(path.to_owned());

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => {
            return SignResponse::err(err_code::POLICY_REQUIRED)
        }
    };

    // CRITICAL (Gemini): this endpoint MUST run `enforce_policy` like every other
    // signing handler — otherwise the attested per-blob floor (allowed_actions /
    // allowed_methods / allowed_/denied_path_prefixes, D1/D2) is bypassed exactly
    // here. It checks `req.action = "sign_binance_request"` + the derived
    // method/path above, and returns the policy_hash so the caller can verify the
    // attested policy loaded.
    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // A CAPPED key (`order_caps`) must not PLACE orders through this generic path
    // — the qty cap lives on the semantic `/sign/binance-order` route and the
    // opaque `payload` here isn't parsed against it. Deny `op="order"` for capped
    // keys (they route orders through the cap-enforcing endpoint); all the READ
    // ops + cancel remain available so a capped mainnet key still runs keyless.
    // Per-op cap enforcement here is a B3 follow-up; uncapped dogfood/import keys
    // sign every op.
    if binance_request_order_denied_for_capped(&op, policy.as_ref()) {
        tracing::warn!(
            event = "generic_capped_denied",
            venue = "binance",
            path = "sign_binance_request"
        );
        return SignResponse::err(err_code::POLICY_DENIED);
    }

    let mut secret_pair: BinanceSecret = match secret_json.deserialize_into() {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_pair.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // Move the secret's buffer into the zeroizing Vec (no lingering plaintext
    // copy in `secret_pair.secret`); only `secret_pair.key` is used afterwards.
    let secret_bytes = Zeroizing::new(std::mem::take(&mut secret_pair.secret).into_bytes());

    // Sign the client's EXACT payload: `binance_canonical(payload, "")` == payload,
    // so this is hmac_sha256(secret, payload) — byte-identical to a local connector.
    let sig = match signer::sign_binance(&secret_bytes, &payload, "") {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("signature".to_owned(), sig);
    headers.insert("api_key".to_owned(), secret_pair.key.clone());
    SignResponse::ok_headers(headers).with_policy_hash(policy_hash)
}

/// Enforce `Policy.order_caps` against a structured order/cancel target.
/// Returns `Err(POLICY_DENIED)` if (a) the policy has an `order_caps` allow-list
/// AND the symbol is not in it, OR (b) the supplied qty exceeds the entry's
/// `max_qty`, OR (c — B2) the entry carries `max_notional` and `qty × price`
/// exceeds it, OR (d — B2, fail-closed) the entry carries `max_notional` and
/// the order has NO price (market-shaped: the enclave has no market data, so
/// the notional is unboundable). Absent `order_caps` (or absent policy) means
/// "no order-level cap from this policy" — the wider action whitelist +
/// path/method rules still apply via `enforce_policy`. Per-period caps are NOT
/// enforced here (deferred to stateful UPL; see `Policy.order_caps` doc).
///
/// `price` is trusted to be the order's LIMIT price string exactly as it will
/// be signed into the canonical: the structured builders
/// (`build_binance_order_query` / `build_okx_order_body`) refuse a market
/// order carrying a price and a limit order missing one, so a decorative
/// price can never reach a signature. Cancels pass `qty=None, price=None` —
/// they create no exposure; only the symbol allow-list applies.
#[allow(clippy::result_large_err)] // SignResponse is the wire type — match enforce_policy's allow.
fn enforce_order_cap(
    policy: Option<&Policy>,
    symbol: &str,
    qty: Option<&str>,
    price: Option<&str>,
) -> Result<(), SignResponse> {
    let Some(p) = policy else { return Ok(()) };
    let Some(caps) = p.order_caps.as_ref() else { return Ok(()) };
    let entry = match caps.iter().find(|c| c.symbol == symbol) {
        Some(e) => e,
        None => {
            tracing::warn!(event = "order_cap_symbol_denied", symbol = %symbol);
            return Err(SignResponse::err(err_code::POLICY_DENIED));
        }
    };
    if let Some(q) = qty {
        match crate::signer::cmp_positive_decimals(q, &entry.max_qty) {
            Ok(std::cmp::Ordering::Greater) => {
                tracing::warn!(
                    event = "order_cap_qty_exceeded",
                    symbol = %symbol,
                    qty = %q,
                    max_qty = %entry.max_qty,
                );
                // explainable-denials: cap CLASS only; the value stays in the log.
                return Err(SignResponse::err(err_code::SIZE_OVER_CAP));
            }
            Ok(_) => {}
            Err(_) => {
                // The compare failed on one of the two operands. Attribute it
                // correctly (Gemini #78 wave-2): a malformed *policy* `max_qty`
                // is a server-side config error (→ INTERNAL_ERROR / 500), not a
                // client error — blaming the client with BAD_REQUEST (400) for a
                // bad policy they didn't supply is misleading. Probe `max_qty`
                // against itself (only on this rare error path, so no hot-path
                // cost); if that errors the policy is the culprit, otherwise the
                // client `qty` is.
                if crate::signer::cmp_positive_decimals(&entry.max_qty, &entry.max_qty)
                    .is_err()
                {
                    tracing::error!(
                        event = "order_cap_max_qty_malformed",
                        symbol = %symbol,
                        max_qty = %entry.max_qty,
                    );
                    return Err(SignResponse::err(err_code::INTERNAL_ERROR));
                }
                tracing::warn!(
                    event = "order_cap_qty_malformed",
                    symbol = %symbol,
                    qty = %q,
                );
                return Err(SignResponse::err(err_code::BAD_REQUEST));
            }
        }
        // B2: per-order notional bound. Checked only for sized targets (a
        // cancel has qty=None and skips this whole block).
        if let Some(max_notional) = entry.max_notional.as_deref() {
            let Some(px) = price else {
                tracing::warn!(
                    event = "order_cap_notional_market_denied",
                    symbol = %symbol,
                );
                return Err(SignResponse::err(err_code::NOTIONAL_OVER_CAP));
            };
            match crate::signer::notional_exceeds(q, px, max_notional) {
                Ok(true) => {
                    tracing::warn!(
                        event = "order_cap_notional_exceeded",
                        symbol = %symbol,
                        qty = %q,
                        price = %px,
                        max_notional = %max_notional,
                    );
                    return Err(SignResponse::err(err_code::NOTIONAL_OVER_CAP));
                }
                Ok(false) => {}
                Err(_) => {
                    // Same blame attribution as max_qty: probe the POLICY
                    // operand in isolation — if it fails, this is a server-side
                    // config error; otherwise the client's qty/price is bad.
                    if crate::signer::notional_exceeds("1", "1", max_notional).is_err() {
                        tracing::error!(
                            event = "order_cap_max_notional_malformed",
                            symbol = %symbol,
                            max_notional = %max_notional,
                        );
                        return Err(SignResponse::err(err_code::INTERNAL_ERROR));
                    }
                    tracing::warn!(
                        event = "order_cap_notional_malformed",
                        symbol = %symbol,
                        qty = %q,
                        price = %px,
                    );
                    return Err(SignResponse::err(err_code::BAD_REQUEST));
                }
            }
        }
    }
    Ok(())
}

/// CR051: when a policy carries `order_caps`, the generic HMAC sign path
/// (`sign_<venue>`) must NOT be usable as a cap-bypassing signing oracle. The
/// generic handlers sign the caller-supplied request without consulting
/// `order_caps`, and a Binance HMAC signature commits only to query+body (not
/// method/path) and is returned to the caller — so a signature obtained via the
/// generic path for an order-shaped query is directly usable / replayable as an
/// uncapped order. (OKX binds method+path, but a capped key can still obtain an
/// order signature directly via the generic path.)
///
/// So for a CAPPED key the generic path is permitted ONLY for a hardcoded set of
/// enclave-vouched SAFE read/cancel operations, with the query constrained to an
/// optional single `symbol`/`instId` filter — no order parameters can be
/// smuggled in. Everything else (notably order placement) is denied; callers
/// must use the structured, cap-enforced `sign_<venue>_order` / `_cancel`
/// routes. Non-capped keys are unaffected (they have no cap to bypass).
///
/// This is the enclave-side realization of the "dedicated read/cancel" decision:
/// it needs NO new action strings, NO gateway rewiring and NO policy re-wrap, so
/// the existing `/account`, `/open-orders`, `/cancel-all` HTTP routes (and the
/// signer-mcp client / Sashko's recovery flow) keep working unchanged.
///
/// `path` may carry an embedded `?query` (OKX merges it); `query` is the
/// separate field (Binance). bybit/kucoin have no sanctioned generic read/cancel
/// route wired in the gateway, so this returns false for them — a capped
/// bybit/kucoin key cannot use the generic path at all (fail-closed; they have
/// no structured order route either). Note: the gateway maps BOTH `binance`
/// and `binance_futures` to the same `sign_binance` action, so the `"binance"`
/// arm covers either exchange name; `/fapi/` is the correct set for both.
///
/// CRITICAL: `body` MUST be constrained too. Binance HMAC signs `query+body`
/// (OKX prehash includes `body`), so an order-shaped BODY on an otherwise-safe
/// GET would be smuggled into the signature — and for Binance (which binds
/// neither method nor path) that signature is replayable to the order endpoint.
/// Every sanctioned read/cancel op has NO body, so we require it empty.
/// Multi-param read-query filter for capped-key safe reads (gate-2: userTrades).
/// Every `key=value` segment in `q` must have a key in `allowed` and a safe token
/// value (alnum / `-` / `_`, the same rule as `single_filter`); NO duplicate keys;
/// and every key in `required` must be present. Rejects unknown keys (can't append
/// `&side=BUY&quantity=…` order fields), duplicate keys (param pollution), empty
/// values, and any non-`key=value` segment. `q` must be the already-merged
/// single-source query — the body-empty + no-double-query guards in
/// `generic_capped_op_allowed` still apply upstream.
fn params_subset_of(q: &str, allowed: &[&str], required: &[&str]) -> bool {
    // An empty query is valid only when nothing is required (e.g. an all-optional
    // reuse). `"".split('&')` yields `[""]`, which would otherwise fail the
    // `key=value` parse below and wrongly reject a no-required call (Gemini).
    if q.is_empty() {
        return required.is_empty();
    }
    let mut seen: Vec<&str> = Vec::new();
    for pair in q.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => return false,
        };
        if !allowed.contains(&k) || seen.contains(&k) {
            return false;
        }
        if v.is_empty()
            || !v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
        seen.push(k);
    }
    required.iter().all(|r| seen.contains(r))
}

fn generic_capped_op_allowed(venue: &str, method: &str, path: &str, query: &str, body: &str) -> bool {
    // No sanctioned read/cancel op carries a body — reject any body outright so
    // order params can't be smuggled past the (method, path, query) checks.
    if !body.is_empty() {
        return false;
    }
    // Self-sufficiency at the trust boundary (CR051-OKX-QUERY-SMUGGLE): never
    // validate when the request carries a query in TWO places (path-embedded
    // `?...` AND a separate `query`). The signer would MERGE both into the
    // canonical string, so the gate must not silently validate only one source.
    // Callers must pass the already-merged request string with an empty
    // separate `query` (handle_sign_okx builds `request_path` before this call).
    if path.contains('?') && !query.is_empty() {
        return false;
    }
    // Normalize: OKX embeds the query in `path` (?instId=...); Binance passes it
    // separately. Prefer the path-embedded query when present.
    let (path_only, embedded) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };
    let q = if !embedded.is_empty() { embedded } else { query };
    let empty = q.is_empty();
    // Exactly `key=<token>` (safe alphanumeric / `-` / `_`), no extra params —
    // rejects appending order fields (`&side=BUY&quantity=...`) to a read query.
    let single_filter = |key: &str| -> bool {
        match q.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            Some(v) => {
                !v.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }
            None => false,
        }
    };
    match venue {
        "binance" => match (method, path_only) {
            ("GET", "/fapi/v2/account") => empty,
            ("GET", "/fapi/v1/openOrders") => empty || single_filter("symbol"),
            // gate-2: signed read of own filled-trade history (audit). `symbol` is
            // REQUIRED; the rest are read-only filters / pagination. params_subset_of
            // rejects unknown/dup keys + non-token values (no order-field smuggle).
            ("GET", "/fapi/v1/userTrades") => params_subset_of(
                q,
                &["symbol", "orderId", "startTime", "endTime", "fromId", "limit"],
                &["symbol"],
            ),
            ("DELETE", "/fapi/v1/allOpenOrders") => single_filter("symbol"),
            _ => false,
        },
        "okx" => match (method, path_only) {
            ("GET", "/api/v5/account/balance") => empty,
            ("GET", "/api/v5/account/positions") => empty,
            ("GET", "/api/v5/trade/orders-pending") => empty || single_filter("instId"),
            // gate-2: signed read of own filled-trade history (audit). OKX mandates
            // `instType`; the rest are read-only filters / pagination. params_subset_of
            // rejects unknown/dup keys + non-token values (no order smuggle).
            ("GET", "/api/v5/trade/fills-history") => params_subset_of(
                q,
                &["instType", "instId", "ordId", "after", "before", "begin", "end", "limit"],
                &["instType"],
            ),
            _ => false,
        },
        _ => false,
    }
}

/// CR050: enforce the MANDATORY x402 spend cap + recipient allow-list for a
/// `sign_x402_eip3009` request. x402 signs an EIP-3009
/// `transferWithAuthorization` — a withdrawal primitive — so unlike
/// `enforce_order_cap` (which no-ops when the policy omits caps, because an
/// order can only move the customer's own position) this is **fail-CLOSED**:
/// a missing policy / x402 clause / `max_value` / `allowed_recipients` is
/// `policy_required` (refuse — "no clause" ≠ "no limit"); and `to` not in
/// `allowed_recipients`, `value` over `max_value`, a wrong pinned chain/token,
/// or a malformed allow-list entry is `policy_denied`.
///
/// Address/token compares are constant-time (`ct_eq`), mirroring the existing
/// token pin; the recipient scan does not early-break, for timing uniformity.
#[allow(clippy::result_large_err)] // SignResponse is the wire type — match enforce_order_cap's allow.
fn enforce_x402_cap(
    policy: Option<&Policy>,
    req_chain_id: u64,
    token_address: &[u8; 20],
    to: &[u8; 20],
    value: &[u8; 32],
) -> Result<(), SignResponse> {
    let Some(p) = policy else {
        tracing::warn!(event = "x402_policy_required", reason = "no_policy");
        return Err(SignResponse::err(err_code::POLICY_REQUIRED));
    };
    let Some(cap) = p.x402.as_ref() else {
        tracing::warn!(event = "x402_policy_required", reason = "no_x402_clause");
        return Err(SignResponse::err(err_code::POLICY_REQUIRED));
    };

    // chain_id + token_address: MANDATORY (final-review LOW). `value` is in raw
    // token units, so a `max_value` cap is meaningless without pinning WHICH
    // token on WHICH chain — otherwise a compromised gateway could present a
    // different (more valuable / fewer-decimals) ERC-20 at the allowed `to` and
    // a value ≤ max_value. Pin both, fail-closed, like max_value/recipients.
    let Some(cid) = cap.chain_id else {
        tracing::warn!(event = "x402_policy_required", reason = "no_chain_id");
        return Err(SignResponse::err(err_code::POLICY_REQUIRED));
    };
    if cid != req_chain_id {
        return Err(SignResponse::err(err_code::POLICY_DENIED));
    }
    let Some(ref tok) = cap.token_address else {
        tracing::warn!(event = "x402_policy_required", reason = "no_token_address");
        return Err(SignResponse::err(err_code::POLICY_REQUIRED));
    };
    match crate::signer::parse_evm_address(tok) {
        Ok(allowed) if allowed.ct_eq(token_address).unwrap_u8() == 1 => {}
        // Mismatch OR malformed policy token → deny (fail closed).
        _ => return Err(SignResponse::err(err_code::POLICY_DENIED)),
    }

    // max_value: MANDATORY. A missing ceiling on a withdrawal path is a hole,
    // not "unlimited".
    let Some(max) = cap.max_value.as_ref() else {
        tracing::warn!(event = "x402_policy_required", reason = "no_max_value");
        return Err(SignResponse::err(err_code::POLICY_REQUIRED));
    };
    match crate::signer::parse_u256_be_decimal(max) {
        // [u8;32] Ord is lexicographic = big-endian numeric order.
        Ok(max_bytes) if *value <= max_bytes => {}
        _ => return Err(SignResponse::err(err_code::POLICY_DENIED)),
    }

    // allowed_recipients: MANDATORY + fail-closed. Absent ⇒ policy_required (a
    // withdrawal key MUST declare its recipients); present but `to` ∉ list ⇒
    // policy_denied. Empty list therefore denies all. Scan the whole list (no
    // early break) for timing uniformity; a malformed entry is an operator
    // config error → fail closed.
    let Some(recipients) = cap.allowed_recipients.as_ref() else {
        tracing::warn!(event = "x402_policy_required", reason = "no_allowed_recipients");
        return Err(SignResponse::err(err_code::POLICY_REQUIRED));
    };
    let mut recipient_ok = false;
    let mut malformed = false;
    for r in recipients.iter() {
        match crate::signer::parse_evm_address(r) {
            Ok(allowed) => {
                if allowed.ct_eq(to).unwrap_u8() == 1 {
                    recipient_ok = true;
                }
            }
            // Do NOT early-return (matches the doc's "no early-break"): a
            // malformed entry is an operator config error; record it and decide
            // after the full scan so control flow doesn't depend on which entry
            // is bad. Malformed takes precedence → deny even if a later entry
            // matched (a broken allow-list must fail closed).
            Err(_) => malformed = true,
        }
    }
    if malformed {
        tracing::error!(event = "x402_allowed_recipient_malformed");
        return Err(SignResponse::err(err_code::POLICY_DENIED));
    }
    if !recipient_ok {
        tracing::warn!(event = "x402_recipient_denied");
        return Err(SignResponse::err(err_code::POLICY_DENIED));
    }
    Ok(())
}

/// CR053: enforce the Hyperliquid policy constraints that the symbol-keyed
/// `order_caps` cannot express, because a HL action identifies the coin by an
/// integer asset index, not a symbol.
///
/// (1) ZN-202 vault binding: if `allowed_vaults` is set and the request carries
/// a `vault`, that vault MUST be in the list (constant-time, parse-normalized);
/// a no-vault (main-account) request is unaffected. (2) Per-asset size caps: if
/// `hl_order_caps` is set AND `action` is order-shaped, every `orders[].a` must
/// be listed and its size `orders[].s` ≤ `max_size`; entries carrying
/// `max_notional` (B2) additionally bound `s × p` and accept plain limit
/// orders only. Unlisted asset / oversize / malformed entry → denied
/// fail-closed. Absent fields = no constraint (so legacy policies and cancel
/// actions pass unchanged).
#[allow(clippy::result_large_err)] // SignResponse is the wire type — match enforce_order_cap's allow.
fn enforce_hl_caps(
    policy: Option<&Policy>,
    action: &serde_json::Value,
    vault: Option<&[u8; 20]>,
) -> Result<(), SignResponse> {
    let Some(p) = policy else { return Ok(()) };

    // (1) ZN-202 — vault allow-list. Only constrains an EXPLICIT vault; a
    // None vault is the key's own main account and is always permitted.
    if let Some(allowed) = p.allowed_vaults.as_ref() {
        if let Some(v) = vault {
            let mut ok = false;
            let mut malformed = false;
            for entry in allowed.iter() {
                match crate::signer::parse_evm_address(entry) {
                    Ok(a) => {
                        if a.ct_eq(v).unwrap_u8() == 1 {
                            ok = true;
                        }
                    }
                    Err(_) => malformed = true, // no early-return: decide after scan
                }
            }
            if malformed {
                tracing::error!(event = "hl_allowed_vault_malformed");
                return Err(SignResponse::err(err_code::POLICY_DENIED));
            }
            if !ok {
                tracing::warn!(event = "hl_vault_denied");
                return Err(SignResponse::err(err_code::POLICY_DENIED));
            }
        }
    }

    // (2) Per-asset size caps — order actions only (cancels carry no size).
    if let Some(caps) = p.hl_order_caps.as_ref() {
        if let Some(orders) = action.get("orders").and_then(|v| v.as_array()) {
            for order in orders {
                // `a` (asset index) + `s` (size string) are REQUIRED to size-cap;
                // missing them under an active cap is fail-closed bad_request.
                let Some(asset) = order.get("a").and_then(|v| v.as_u64()) else {
                    tracing::warn!(event = "hl_order_missing_asset");
                    return Err(SignResponse::err(err_code::BAD_REQUEST));
                };
                let Some(size) = order.get("s").and_then(|v| v.as_str()) else {
                    tracing::warn!(event = "hl_order_missing_size", asset = asset);
                    return Err(SignResponse::err(err_code::BAD_REQUEST));
                };
                let Some(cap) = caps.iter().find(|c| c.asset == asset) else {
                    tracing::warn!(event = "hl_order_cap_asset_denied", asset = asset);
                    return Err(SignResponse::err(err_code::POLICY_DENIED));
                };
                match crate::signer::cmp_positive_decimals(size, &cap.max_size) {
                    Ok(std::cmp::Ordering::Greater) => {
                        tracing::warn!(
                            event = "hl_order_cap_size_exceeded",
                            asset = asset,
                            size = %size,
                            max_size = %cap.max_size,
                        );
                        return Err(SignResponse::err(err_code::POLICY_DENIED));
                    }
                    Ok(_) => {}
                    Err(_) => {
                        // Attribute the parse failure (mirrors enforce_order_cap):
                        // a malformed policy max_size is a server config error.
                        if crate::signer::cmp_positive_decimals(&cap.max_size, &cap.max_size)
                            .is_err()
                        {
                            tracing::error!(
                                event = "hl_order_cap_max_size_malformed",
                                asset = asset,
                                max_size = %cap.max_size,
                            );
                            return Err(SignResponse::err(err_code::INTERNAL_ERROR));
                        }
                        tracing::warn!(event = "hl_order_cap_size_malformed", asset = asset);
                        return Err(SignResponse::err(err_code::BAD_REQUEST));
                    }
                }
                // B2: per-order notional (s × p ≤ max_notional). Only plain
                // limit orders (`t.limit`) are notionally boundable — a
                // trigger order's `p` is not the execution bound when
                // `isMarket` fires market-side, so trigger-shaped orders are
                // denied fail-closed under a notional cap.
                if let Some(max_notional) = cap.max_notional.as_deref() {
                    if order.get("t").and_then(|t| t.get("limit")).is_none() {
                        tracing::warn!(
                            event = "hl_order_cap_notional_nonlimit_denied",
                            asset = asset,
                        );
                        return Err(SignResponse::err(err_code::POLICY_DENIED));
                    }
                    let Some(px) = order.get("p").and_then(|v| v.as_str()) else {
                        tracing::warn!(event = "hl_order_missing_price", asset = asset);
                        return Err(SignResponse::err(err_code::BAD_REQUEST));
                    };
                    match crate::signer::notional_exceeds(size, px, max_notional) {
                        Ok(true) => {
                            tracing::warn!(
                                event = "hl_order_cap_notional_exceeded",
                                asset = asset,
                                size = %size,
                                price = %px,
                                max_notional = %max_notional,
                            );
                            return Err(SignResponse::err(err_code::POLICY_DENIED));
                        }
                        Ok(false) => {}
                        Err(_) => {
                            // Blame attribution mirrors max_size above.
                            if crate::signer::notional_exceeds("1", "1", max_notional)
                                .is_err()
                            {
                                tracing::error!(
                                    event = "hl_order_cap_max_notional_malformed",
                                    asset = asset,
                                    max_notional = %max_notional,
                                );
                                return Err(SignResponse::err(err_code::INTERNAL_ERROR));
                            }
                            tracing::warn!(
                                event = "hl_order_cap_notional_malformed",
                                asset = asset,
                            );
                            return Err(SignResponse::err(err_code::BAD_REQUEST));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// `sign_binance_order` — Binance USD-M Futures `POST /fapi/v1/order`. The
/// enclave receives a structured `OrderRequest`, applies `Policy.order_caps`,
/// builds the form-urlencoded canonical INSIDE the enclave (asterdex-T1 rule),
/// signs it, and returns the canonical bytes alongside the auth headers so the
/// gateway can append `&signature=<hex>` to form the final wire body.
fn handle_sign_binance_order(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    let Some(order) = req.order.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    let Some(ts) = req.timestamp_ms else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => return SignResponse::err(err_code::POLICY_REQUIRED),
    };

    // Action whitelist + method/path checks. The gateway forwards the venue-
    // canonical `method` (POST for order, DELETE for cancel) + `path`
    // (`/fapi/v1/order`) so this trade-signing path honours
    // `Policy.allowed_methods` / `allowed_path_prefixes` (Gemini #78 —
    // previously these were None, letting trade signatures bypass the
    // policy's path/method whitelists, a hole in the signer's core value prop).
    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // Per-asset cap (symbol must be in order_caps; qty ≤ max_qty).
    if let Err(resp) = enforce_order_cap(policy.as_ref(), &order.symbol, Some(&order.qty), order.price.as_deref()) {
        return resp;
    }

    // AF-2: verify the agent's signature over the FULL order intent (side/price/
    // reduce_only/ord_type/coid — the dimensions the cap does NOT bound) before
    // the venue signature, when the policy opts in via `intent_pubkey`.
    if let Err(resp) = enforce_agent_intent_order(
        policy.as_ref(), identity, "binance", "sign_binance_order", ts, order, &req,
    ) {
        return resp;
    }

    let canonical = match crate::signer::build_binance_order_query(order) {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };

    let mut secret_pair: BinanceSecret = match secret_json.deserialize_into() {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_pair.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // Move the secret's buffer straight into the zeroizing Vec instead of
    // copying it (`as_bytes().to_vec()` left a second plaintext copy in the
    // `secret_pair.secret` String until its own drop). `secret` is not used
    // again after this — only `secret_pair.key` (the API key) is. Gemini #78.
    let secret_bytes = Zeroizing::new(std::mem::take(&mut secret_pair.secret).into_bytes());
    match signer::compute_binance_headers(&secret_bytes, &secret_pair.key, ts, &canonical, "") {
        Ok(headers) => SignResponse::ok_headers(headers)
            .with_policy_hash(policy_hash)
            .with_canonical_body(canonical),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

/// `sign_binance_cancel` — Binance USD-M Futures `DELETE /fapi/v1/order`.
/// Same shape as the order builder, structured `CancelRequest` in, canonical
/// querystring out. The symbol must still be in `order_caps` (allow-list
/// reused so a key restricted to `BTCUSDT` cannot cancel `ETHUSDT` orders).
fn handle_sign_binance_cancel(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    let Some(cancel) = req.cancel.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    let Some(ts) = req.timestamp_ms else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => return SignResponse::err(err_code::POLICY_REQUIRED),
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // Cancel must target a symbol that the key is allowed to trade. qty=None.
    if let Err(resp) = enforce_order_cap(policy.as_ref(), &cancel.symbol, None, None) {
        return resp;
    }

    // AF-2: agent-signed-intent (opt-in) — bind symbol/order_id so a gateway
    // cannot re-target the cancel. Nonce = intent_nonce (UUID).
    if let Err(resp) = enforce_agent_intent_cancel(
        policy.as_ref(), identity, "binance", "sign_binance_cancel", ts, cancel, &req,
    ) {
        return resp;
    }

    let canonical = match crate::signer::build_binance_cancel_query(cancel) {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };

    let mut secret_pair: BinanceSecret = match secret_json.deserialize_into() {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_pair.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // Move the secret's buffer straight into the zeroizing Vec instead of
    // copying it (`as_bytes().to_vec()` left a second plaintext copy in the
    // `secret_pair.secret` String until its own drop). `secret` is not used
    // again after this — only `secret_pair.key` (the API key) is. Gemini #78.
    let secret_bytes = Zeroizing::new(std::mem::take(&mut secret_pair.secret).into_bytes());
    match signer::compute_binance_headers(&secret_bytes, &secret_pair.key, ts, &canonical, "") {
        Ok(headers) => SignResponse::ok_headers(headers)
            .with_policy_hash(policy_hash)
            .with_canonical_body(canonical),
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
}

/// `sign_okx_order` — OKX v5 `POST /api/v5/trade/order`. The enclave receives
/// a structured `OrderRequest`, applies `Policy.order_caps`, builds the OKX
/// canonical JSON body INSIDE the enclave (insertion-order, compact, byte-
/// exact), and signs that EXACT byte string. The same byte string is returned
/// via `SignResponse.canonical_body` for the gateway to forward verbatim —
/// re-serialization downstream would invalidate the HMAC.
fn handle_sign_okx_order(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    let Some(order) = req.order.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    let Some(ts) = req.timestamp_ms else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => return SignResponse::err(err_code::POLICY_REQUIRED),
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    if let Err(resp) = enforce_order_cap(policy.as_ref(), &order.symbol, Some(&order.qty), order.price.as_deref()) {
        return resp;
    }

    // AF-2: agent-signed-intent (opt-in) — verify full order intent pre-venue-sign.
    if let Err(resp) = enforce_agent_intent_order(
        policy.as_ref(), identity, "okx", "sign_okx_order", ts, order, &req,
    ) {
        return resp;
    }

    let canonical = match crate::signer::build_okx_order_body(order) {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };

    let mut secret_triple: OkxSecret = match secret_json.deserialize_into() {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_triple.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // Move the secret's buffer into the zeroizing Vec instead of copying it
    // (`as_bytes().to_vec()` left a second plaintext copy in `secret_triple.secret`
    // until its own drop). Gemini #79 — same fix as the Binance path (#78). The
    // passphrase below is borrowed via `as_bytes()` (no copy) and wiped by
    // `OkxSecret`'s `Drop`, so it needs no move. `secret` is not read again.
    let secret_bytes =
        Zeroizing::new(std::mem::take(&mut secret_triple.secret).into_bytes());
    let passphrase_bytes = secret_triple.passphrase.as_bytes();
    match signer::compute_okx_headers(
        &secret_bytes,
        passphrase_bytes,
        &secret_triple.key,
        ts,
        "POST",
        "/api/v5/trade/order",
        &canonical,
    ) {
        Ok(headers) => SignResponse::ok_headers(headers)
            .with_policy_hash(policy_hash)
            .with_canonical_body(canonical),
        // Malformed passphrase byte (CRLF / NUL / non-ASCII) — operator blob bug.
        Err(_) => SignResponse::err(err_code::BAD_REQUEST),
    }
}

/// `sign_okx_cancel` — OKX `POST /api/v5/trade/cancel-order` (yes, POST, not
/// DELETE — that's the documented OKX cancel surface). Body is the same byte-
/// exact JSON treatment as the order builder. Symbol must still be in the
/// policy's `order_caps` allow-list (the key restricted to BTC-USDT-SWAP
/// can't cancel ETH-USDT-SWAP orders).
fn handle_sign_okx_cancel(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    let Some(cancel) = req.cancel.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    let Some(ts) = req.timestamp_ms else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => return SignResponse::err(err_code::POLICY_REQUIRED),
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    if let Err(resp) = enforce_order_cap(policy.as_ref(), &cancel.symbol, None, None) {
        return resp;
    }

    // AF-2: agent-signed-intent (opt-in) — nonce = intent_nonce (UUID).
    if let Err(resp) = enforce_agent_intent_cancel(
        policy.as_ref(), identity, "okx", "sign_okx_cancel", ts, cancel, &req,
    ) {
        return resp;
    }

    let canonical = match crate::signer::build_okx_cancel_body(cancel) {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };

    let mut secret_triple: OkxSecret = match secret_json.deserialize_into() {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_triple.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // Move the secret's buffer into the zeroizing Vec instead of copying it
    // (`as_bytes().to_vec()` left a second plaintext copy in `secret_triple.secret`
    // until its own drop). Gemini #79 — same fix as the Binance path (#78). The
    // passphrase below is borrowed via `as_bytes()` (no copy) and wiped by
    // `OkxSecret`'s `Drop`, so it needs no move. `secret` is not read again.
    let secret_bytes =
        Zeroizing::new(std::mem::take(&mut secret_triple.secret).into_bytes());
    let passphrase_bytes = secret_triple.passphrase.as_bytes();
    match signer::compute_okx_headers(
        &secret_bytes,
        passphrase_bytes,
        &secret_triple.key,
        ts,
        "POST",
        "/api/v5/trade/cancel-order",
        &canonical,
    ) {
        Ok(headers) => SignResponse::ok_headers(headers)
            .with_policy_hash(policy_hash)
            .with_canonical_body(canonical),
        Err(_) => SignResponse::err(err_code::BAD_REQUEST),
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
fn handle_sign_bybit(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
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

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
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
        Err(LoadSecretError::PolicyRequired) => {
            return SignResponse::err(err_code::POLICY_REQUIRED);
        }
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // CR051: bybit has no sanctioned generic read/cancel route AND no structured
    // (cap-enforced) order route, so a capped bybit key cannot use the generic
    // path at all — fail-closed (better than signing an uncapped bybit order).
    if policy.as_ref().and_then(|p| p.order_caps.as_ref()).is_some() {
        tracing::warn!(event = "generic_capped_denied", venue = "bybit");
        return SignResponse::err(err_code::POLICY_DENIED);
    }

    let secret_pair: BybitSecret = match secret_json.deserialize_into() {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if !secret_pair.is_complete() {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let secret_bytes = Zeroizing::new(secret_pair.secret.as_bytes().to_vec());

    match signer::compute_bybit_headers(&secret_bytes, &secret_pair.key, ts, method, user_query, body) {
        Ok(headers) => SignResponse::ok_headers(headers).with_policy_hash(policy_hash),
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
fn handle_sign_okx(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
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

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
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
        Err(LoadSecretError::PolicyRequired) => {
            return SignResponse::err(err_code::POLICY_REQUIRED);
        }
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // Merge `query` (if provided) into requestPath so canonical-string
    // assembly is unambiguous. OKX's spec is clear: requestPath INCLUDES
    // the query string, separator `?`. If `path` already has a `?` we
    // append with `&`; otherwise with `?`. Built BEFORE the CR051 gate so the
    // gate validates EXACTLY the string the signer signs (CR051-OKX-QUERY-
    // SMUGGLE: a split between gate-view and signer-view was a cap bypass).
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

    // CR051: capped key → generic path limited to enclave-vouched safe ops.
    // Validate the FULLY-MERGED request_path with an empty separate query, so
    // any query smuggled via req.query is now inside request_path and seen by
    // the gate's filter check (a smuggled `&sz=...` fails single_filter). The
    // query arg is intentionally "" here — req.query was already folded into
    // request_path above; the gate's path-contains-? && query-non-empty guard is
    // therefore a dead-but-deliberate safety net for any future caller that
    // forgets to merge first.
    if policy.as_ref().and_then(|p| p.order_caps.as_ref()).is_some()
        && !generic_capped_op_allowed("okx", method, &request_path, "", body)
    {
        tracing::warn!(event = "generic_capped_denied", venue = "okx");
        return SignResponse::err(err_code::POLICY_DENIED);
    }

    let secret_triple: OkxSecret = match secret_json.deserialize_into() {
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
        Ok(headers) => SignResponse::ok_headers(headers).with_policy_hash(policy_hash),
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
/// Returns the decrypted `HyperliquidSecret` and parsed action data on
/// success, or a populated `SignResponse::err` on any validation, decrypt,
/// or policy-enforcement failure.
///
/// Note: the co-encrypted UPL policy is enforced INTERNALLY (inside
/// `enforce_policy(...)`) before the secret is returned to the caller —
/// callers do not see the policy because no decision they could make
/// after this function returns would need it. If you ever need the
/// policy at the call site (e.g., to log the matched action+label),
/// thread it through here explicitly.
///
/// UPL v0: extracts and enforces the co-encrypted policy before returning
/// the secret. If the policy denies the request, returns `policy_denied`.
// The load/decrypt/cap-enforce path shared by the HL TESTNET dispatcher
// (`sign_hyperliquid_testnet` below, source="b"). deny-HL-main (2026-06-26)
// removed the mainnet callers — they now hard-deny BEFORE any secret load — and
// this was retained for the testnet ticket; it is now wired.
#[allow(clippy::result_large_err, clippy::type_complexity)]
fn load_hyperliquid_request(
    req: &SignRequest,
    identity: &crate::registry::ResolvedIdentity,
) -> Result<(HyperliquidSecret, serde_json::Value, u64, Option<[u8; 20]>, Option<String>), SignResponse> {
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
    let (policy, secret_json) = match load_and_parse_blob(req, identity) {
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
        Err(LoadSecretError::PolicyRequired) => {
            return Err(SignResponse::err(err_code::POLICY_REQUIRED));
        }
    };

    // UPL v0: enforce policy BEFORE parsing secret material.
    let policy_hash = enforce_policy(policy.as_ref(), req)?;

    // CR053: HL vault allow-list (ZN-202) + per-asset size caps — constraints
    // the symbol-keyed order_caps cannot express for HL's index-based action.
    // Enforced here so BOTH order and cancel paths get the vault check (the
    // size caps apply only to order-shaped actions, gated inside the helper).
    enforce_hl_caps(policy.as_ref(), action, vault.as_ref())?;

    let secret: HyperliquidSecret = match secret_json.deserialize_into() {
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

    Ok((secret, action.clone(), nonce, vault, policy_hash))
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
fn handle_sign_hyperliquid_main_order(req: SignRequest, _identity: &crate::registry::ResolvedIdentity) -> SignResponse {
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

    // SECURITY (deny-HL-main, 2026-06-26): `sign_hyperliquid` is hardcoded to
    // source="a" (Hyperliquid MAINNET — real funds on Arbitrum). A testnet/demo
    // signer must NEVER emit a real-money HL signature, so we HARD-DENY here,
    // BEFORE loading or decrypting any secret. This also covers the generic
    // `/sign` and `/hedge` paths — both dispatch this action to this handler
    // (see `handle_sign`). HL testnet (source="b") is a separate, gated ticket.
    tracing::warn!(event = "hyperliquid_main_denied", op = "order");
    SignResponse::err(err_code::POLICY_DENIED)
}

/// `sign_hyperliquid_main_cancel` — sign a Hyperliquid mainnet cancel.
fn handle_sign_hyperliquid_main_cancel(req: SignRequest, _identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    // Mirror `handle_sign_hyperliquid_main_order` — validate action shape
    // before the KMS round-trip for predictable error semantics and so
    // tests don't need a fake KMS endpoint.
    let Some(hl_action) = req.hl_action.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    if !validate_cancel_action(hl_action) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    // SECURITY (deny-HL-main, 2026-06-26): mainnet HL signing hard-disabled
    // (source="a" = real Arbitrum funds). HARD-DENY before any secret load;
    // covers the generic `/sign` + `/hedge` paths. HL testnet (source="b") is a
    // separate, deliberately-gated ticket.
    tracing::warn!(event = "hyperliquid_main_denied", op = "cancel");
    SignResponse::err(err_code::POLICY_DENIED)
}

// ─────────────────────────────────────────────────────────────────────────
// HL TESTNET dispatcher (source="b") — the ALLOWED Hyperliquid path.
// ─────────────────────────────────────────────────────────────────────────
//
// Same crypto as the (hard-denied) mainnet handlers — `signer::sign_hyperliquid`
// with the SHARED L1 phantom-agent domain (chainId 1337, "Exchange"). The ONLY
// difference is the phantom-agent `source`: "b" = Hyperliquid TESTNET (mock
// funds, api.hyperliquid-testnet.xyz), vs "a" = mainnet (real Arbitrum funds,
// hard-denied). No crypto is duplicated. The sealed key is the demo AGENT wallet
// (its own `hyperliquid_testnet` venue blob + tenant grant); the agent can
// place/cancel but L1 rejects agent withdrawals — the DEX-demo isolation proof.

/// `sign_hyperliquid_testnet_order` — sign a Hyperliquid TESTNET order (source="b").
fn handle_sign_hyperliquid_testnet_order(
    req: SignRequest,
    identity: &crate::registry::ResolvedIdentity,
) -> SignResponse {
    // Validate shape before the KMS round-trip (predictable errors; tests need
    // no fake-KMS endpoint), mirroring the mainnet handler.
    let Some(hl_action) = req.hl_action.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    if !validate_order_action(hl_action) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    sign_hyperliquid_testnet(req, identity)
}

/// `sign_hyperliquid_testnet_cancel` — sign a Hyperliquid TESTNET cancel (source="b").
fn handle_sign_hyperliquid_testnet_cancel(
    req: SignRequest,
    identity: &crate::registry::ResolvedIdentity,
) -> SignResponse {
    let Some(hl_action) = req.hl_action.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    if !validate_cancel_action(hl_action) {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    sign_hyperliquid_testnet(req, identity)
}

/// Shared testnet sign tail: load+decrypt+policy/cap-enforce (`load_hyperliquid_request`),
/// then sign with `source="b"`. The venue ACL (`hyperliquid_testnet`) + KMS context
/// keep this bound to the demo agent identity.
fn sign_hyperliquid_testnet(
    req: SignRequest,
    identity: &crate::registry::ResolvedIdentity,
) -> SignResponse {
    let (secret, action, nonce, vault, policy_hash) = match load_hyperliquid_request(&req, identity)
    {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let pk = match crate::signer::parse_evm_private_key(&secret.private_key) {
        Ok(k) => k,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    // source="b" = Hyperliquid TESTNET. This is the ONLY HL signing path the
    // enclave permits; mainnet (source="a") is hard-denied above.
    let sig = match crate::signer::sign_hyperliquid(&pk, &action, nonce, vault, "b") {
        Ok(s) => s,
        Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };
    SignResponse::ok_hl_signature(sig).with_policy_hash(policy_hash)
}

// ─────────────────────────────────────────────────────────────────────────
// Attested-signed market data (P2): sign_data.
//
// Signs an arbitrary READ-ONLY market-data payload with the dedicated
// data-signing key (a secp256k1 key in an operator-staged blob — NOT a
// tenant/venue key). Operator-gated at the gateway (operator router); here,
// isolation is ALSO enforced by the KMS EncryptionContext — only the operator
// identity's context decrypts the data-key blob (#5, bounded blast-radius).
// canonical-v1 (JCS) is computed in-enclave; the buyer ecrecovers the address.
// No caps / no funds. EIP-712 disjointness is in signer::ATTESTED_DATA_DOMAIN_V1.
// ─────────────────────────────────────────────────────────────────────────
fn handle_sign_data(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    let Some(data_raw) = req.data.as_deref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    // Explicit byte cap on the payload (the 64 KiB vsock frame bounds the whole
    // request, but `data` gets its own ceiling — defense + a clear enclave-RAM
    // bound). Checked BEFORE the KMS round-trip so oversized junk fails fast.
    if data_raw.len() > MAX_ATTESTED_DATA_BYTES {
        tracing::warn!(event = "attested_data_too_large", len = data_raw.len());
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // Parse the RAW JSON ourselves (the enclave is the trust boundary): reject
    // duplicate object keys fail-closed so the signed canonical is provably
    // dup-free. Done BEFORE the KMS decrypt so malformed data never spends a KMS
    // call. canonical-v1 additionally forbids JSON numbers (numerics-as-strings).
    let data = match crate::signer::parse_json_no_dup_keys(data_raw) {
        Ok(v) => v,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    // Decrypt the operator-staged data-signing key blob. The KMS context is
    // derived from the resolved identity → only the operator can decrypt it.
    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => {
            return SignResponse::err(err_code::POLICY_REQUIRED)
        }
    };
    // Enforce any policy on the data-key blob (e.g. an action allow-list). No
    // caps apply — sign_data moves no funds.
    if let Err(resp) = enforce_policy(policy.as_ref(), &req) {
        return resp;
    }
    // The data-key blob carries the secp256k1 key in the EVM-secret shape.
    let secret: HyperliquidSecret = match secret_json.deserialize_into() {
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
    // canonical-v1 -> keccak256(domain ‖ canonical) -> recoverable secp256k1.
    let signature = match crate::signer::sign_attested_data(&pk, &data) {
        Ok(sig) => sig,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let (pubkey_compressed, pubkey_address) = match crate::signer::attested_data_pubkey(&pk) {
        Ok(p) => p,
        Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };
    SignResponse::ok_attested_data(crate::proto::AttestedDataResponse {
        signature,
        pubkey_compressed,
        pubkey_address,
    })
}

// Attested-data PROVISIONING (Option-1): provision_data_key.
//
// One-shot KEY FACTORY — the data-signing key is BORN inside the enclave and
// only ever leaves sealed under KMS (Q1a). Steps: generate secp256k1 in-enclave
// → KMS GenerateDataKey (kmstool genkey) under the FIXED data-signing context →
// AES-GCM-seal the secret plaintext with the DEK + the data-signing sealed AAD →
// return the v2 envelope blob + the public key.
//
// Runs BEFORE the tenant-identity gate (no tenant token): the gate is the IAM
// role — only the EPHEMERAL scoped provisioning role carries kms:GenerateDataKey,
// so on the prod (decrypt-only) role this fails closed (AccessDenied). Context +
// AAD come from `ResolvedIdentity::for_data_signing()` — byte-identical to what
// the prod sign_data path reconstructs, so the prod enclave can decrypt the blob.
fn handle_provision_data_key(req: SignRequest) -> SignResponse {
    let Some(creds) = req.aws_credentials.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };
    let Some(key_id) = req.key_id.as_deref().filter(|s| !s.is_empty()) else {
        tracing::warn!(event = "provision_no_key_id");
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    // The data-signing service identity — SINGLE source for the KMS context +
    // sealed AAD (must match what the prod sign_data path reconstructs).
    let id = crate::registry::ResolvedIdentity::for_data_signing();
    let ctx = id.encryption_context("data-signing");
    let aad = id.sealed_aad("data-signing", KEY_VERSION);

    // 1. Birth the key in-enclave + derive its published pubkey.
    let pk = crate::signer::generate_secp256k1_private_key();
    let (pubkey_compressed, pubkey_address) = match crate::signer::attested_data_pubkey(&pk) {
        Ok(p) => p,
        Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };

    // 2. Legacy (no-policy → no caps on sign_data) secret plaintext, assembled so
    //    EVERY copy of the key is zeroized (Gemini security-HIGH): `hex::encode`
    //    would allocate an un-zeroized String holding the RAW key hex on the heap.
    //    Instead hex-encode into a Zeroizing buffer and build the JSON directly in
    //    a Zeroizing Vec — the only off-enclave copy is then the SEALED ciphertext.
    let mut priv_hex = Zeroizing::new([0u8; 64]);
    if hex::encode_to_slice(pk.as_slice(), &mut priv_hex[..]).is_err() {
        return SignResponse::err(err_code::INTERNAL_ERROR);
    }
    // Capacity MUST exceed the assembled size (≤ ~173 B: 45 prefix + 64 hex + 20
    // mid + 42 address + 2 close) so the `extend_from_slice` calls NEVER
    // reallocate — a realloc would free an OLD heap buffer still holding the key
    // hex WITHOUT zeroizing it (Zeroizing only wipes the FINAL buffer on drop).
    // Gemini security (3rd of the key-plaintext class).
    let mut plaintext = Zeroizing::new(Vec::with_capacity(256));
    plaintext.extend_from_slice(br#"{"exchange":"attested-data","private_key":"0x"#);
    plaintext.extend_from_slice(&priv_hex[..]);
    plaintext.extend_from_slice(br#"","wallet_address":""#);
    plaintext.extend_from_slice(pubkey_address.as_bytes());
    plaintext.extend_from_slice(br#""}"#);

    // 3. KMS GenerateDataKey under the data-signing context (needs the scoped
    //    provisioning role; prod decrypt-only role → AccessDenied).
    let genkey = match crate::kms_client::generate_data_key(creds, key_id, Some(&ctx)) {
        Ok(g) => g,
        Err(crate::kms_client::GenKeyError::AccessDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED)
        }
        Err(crate::kms_client::GenKeyError::Internal) => {
            return SignResponse::err(err_code::INTERNAL_ERROR)
        }
    };

    // 4. AES-GCM-seal under the DEK + sealed AAD → v2 envelope (the prod path
    //    KMS-decrypts wrapped_dek then GCM-decrypts under the identical AAD).
    let envelope =
        match crate::envelope::seal_with_dek(&genkey.plaintext, &genkey.wrapped, &plaintext, &aad) {
            Ok(e) => e,
            Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
        };

    let blob = match serde_json::to_vec(&envelope) {
        Ok(b) => b,
        Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };

    tracing::info!(event = "provision_data_key_ok", address = %pubkey_address);
    SignResponse::ok_provision(crate::proto::ProvisionDataKeyResponse {
        envelope_b64: B64.encode(&blob),
        pubkey_compressed,
        pubkey_address,
    })
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

/// Find the FIRST value of url-param `key` (which MUST include the trailing
/// `=`) in an Asterdex body, byte-level — NO url-decode (same rationale as
/// `validate_asterdex_body`: decoding could normalise `%71uantity=` past the
/// check, and the signature commits to the raw bytes). Returns:
///   `Ok(Some(value))` — present exactly once at a param boundary,
///   `Ok(None)`        — absent,
///   `Err(())`         — malformed (mid-token match, e.g. `note=symbol=`) OR a
///                       duplicate `&key` (parameter pollution).
/// Mirrors the find-first + reject-duplicate hardening used for `signer=`/`nonce=`.
fn asterdex_first_param<'a>(body: &'a str, key: &str) -> Result<Option<&'a str>, ()> {
    let Some(start) = body.find(key) else {
        return Ok(None);
    };
    // Boundary: at body start OR immediately after '&'. Rejects prefixed
    // collisions like `note=symbol=` / `xquantity=`.
    if start != 0 && body.as_bytes().get(start - 1).copied() != Some(b'&') {
        return Err(());
    }
    let value_start = start + key.len();
    let value_end = body[value_start..]
        .find('&')
        .map(|i| value_start + i)
        .unwrap_or(body.len());
    // Reject a duplicate `&key` later in the body (parameter pollution).
    if body[value_end..].contains(&format!("&{key}")) {
        return Err(());
    }
    Ok(Some(&body[value_start..value_end]))
}

/// True if the flag-style url-param `name` (NO trailing `=`) appears in `body`
/// at a param boundary (body start or after `&`), terminated by `=`, `&`, or
/// end-of-string. Catches BOTH `name=true` and a bare valueless `name` /
/// `name&...` — a permissive backend could honour a valueless flag as true
/// (Gemini final-review: `closePosition` without `=`). Byte-level, no url-decode.
/// Scans all occurrences so a mid-token hit (e.g. `xclosePosition`) doesn't
/// short-circuit a real later boundary match.
fn asterdex_flag_present(body: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = body[from..].find(name) {
        let start = from + rel;
        let at_boundary = start == 0 || body.as_bytes().get(start - 1).copied() == Some(b'&');
        let after = body.as_bytes().get(start + name.len()).copied();
        let terminated = matches!(after, None | Some(b'=') | Some(b'&'));
        if at_boundary && terminated {
            return true;
        }
        from = start + name.len();
    }
    false
}

/// H1 (AF-1 Asterdex): POSITIVE body param-name allow-list — the analogue of
/// `check_binance_request_allow` for the raw-body Asterdex route. Asterdex (a
/// Binance USD-M futures fork) signs the URL-encoded `body` verbatim, and the
/// size cap below is a byte-level `quantity=` extractor. A byte extractor +
/// two-flag deny-list is not self-sufficient: a param the venue reads but the
/// extractor doesn't (a case variant like `Quantity=`, or any alt sizing /
/// exposure param) sizes an order the cap never sees. A POSITIVE whitelist
/// closes that class INDEPENDENTLY of confirming Asterdex's exact case-rules or
/// param-space (CTO 2026-07-10): every param name in the body must be a known
/// safe one, or the whole request is refused. Only `quantity` is a sizing param
/// here, and it is the one the cap parses — every other legit param is
/// non-sizing (side/type/price/tif/reduceOnly/…) or read/cancel metadata.
/// `closePosition` / `batchOrders` are DELIBERATELY absent — they hit their own
/// presence-deny above with a clearer `policy_denied` before this runs.
const ASTERDEX_ALLOWED_PARAMS: &[&str] = &[
    // EIP-712 owner-binding (validate_asterdex_body checks their values).
    "signer",
    "nonce",
    // Order params (Binance-fork camelCase; case-sensitive by construction —
    // any case variant is NOT in this set → denied).
    "symbol",
    "side",
    "type",
    "quantity",
    "price",
    "timeInForce",
    "reduceOnly",
    "positionSide",
    "newClientOrderId",
    "stopPrice",
    "workingType",
    "priceProtect",
    "newOrderRespType",
    "activationPrice",
    "callbackRate",
    // Read / cancel / pagination metadata (create no exposure).
    "orderId",
    "origClientOrderId",
    "startTime",
    "endTime",
    "limit",
    "fromId",
    "incomeType",
    "recvWindow",
    "timestamp",
];

/// Ok(()) iff EVERY `&`-delimited segment is `name=value` with `name` in
/// `ASTERDEX_ALLOWED_PARAMS`. Names are the bytes before the first `=` — the
/// same boundaries the venue's querystring parser uses. A positive list has no
/// case/suffix/decode bypass: an unrecognized name (case variant, alt sizing
/// param, typo) is refused, not signed. Requiring the `=` also refuses a BARE
/// flag repeat like `quantity=1&quantity` (a valueless second `quantity` that
/// the size cap's `&quantity=` dup-guard doesn't catch — rust-auditor
/// 2026-07-11 L). Byte-level, no url-decode (the caller's charset gate already
/// banned percent and alt-separator bytes on the capped path).
fn check_asterdex_body_allow(body: &str) -> Result<(), &'static str> {
    for pair in body.split('&') {
        if pair.is_empty() {
            continue; // trailing/empty '&' segment
        }
        // Require `name=value` shape — a segment with no `=` is a bare flag.
        let Some((name, _value)) = pair.split_once('=') else {
            return Err("asterdex_bare_flag_not_allowed");
        };
        if !ASTERDEX_ALLOWED_PARAMS.contains(&name) {
            return Err("asterdex_param_not_allowed");
        }
    }
    Ok(())
}

/// H1 (AF-1 Asterdex) enclave-floor predicate: under the strict regime a money-
/// venue with no `order_caps` is an un-bounded signer (the size cap no-ops), so
/// it must be refused. Pure over an explicit `require_policy` flag (not reading
/// the env) so it is testable without env-var races; the handler passes
/// `policy_required()`. Pinned by `asterdex_floor_denies_uncapped_under_strict`.
fn asterdex_floor_denies(require_policy: bool, policy: Option<&Policy>) -> bool {
    require_policy && policy.and_then(|p| p.order_caps.as_ref()).is_none()
}

/// CR053 / ZN-204: bound Asterdex ORDER SIZE by parsing the signed body. The
/// EIP-712 signature commits to `body` (not path), so this — not the path
/// allow-list — is the cryptographically sound size bound. Reuses `order_caps`
/// (CTO sign-off 2026-06-22 Q1a). Fail-closed ONLY when the policy declares
/// `order_caps`; legacy / no-cap blobs are unchanged (the H1 enclave-floor in
/// `handle_sign_asterdex` is what makes `order_caps` mandatory for a money-venue
/// under the strict regime, so this path is the ONLY path there).
#[allow(clippy::result_large_err)] // SignResponse is the wire type — match enforce_order_cap's allow.
fn enforce_asterdex_size_cap(policy: Option<&Policy>, body: &str) -> Result<(), SignResponse> {
    let Some(p) = policy else { return Ok(()) };
    if p.order_caps.is_none() {
        return Ok(());
    }
    // H1 (AF-1 Asterdex) — capped-body CHARSET gate (supersedes the CR053
    // percent-only reject). The positive allow-list below checks param NAMES,
    // but a name-only check can't protect the VALUE half of an allowed pair from
    // an embedded ALTERNATE SEPARATOR: e.g. `price=50;quantity=999` allow-lists
    // as name `price`, the `quantity=` byte-search still reads the real
    // `&quantity=1` (so the cap sees 1), yet a backend that treats `;` (or `,`,
    // whitespace, …) as a param separator would ALSO read `quantity=999`
    // (rust-auditor 2026-07-11 M). Legit Asterdex params are plain ASCII —
    // alnum plus `& = . _ - : /` (the last two cover Binance clientOrderId) —
    // so reject any other byte (`% ; , +` space control …) fail-closed, closing
    // the whole alt-separator / percent-decode class independently of the
    // venue's exact parser rules. Scoped to the capped path (un-capped legacy
    // flows unchanged).
    if body
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'&' | b'=' | b'.' | b'_' | b'-' | b':' | b'/')))
    {
        tracing::warn!(event = "asterdex_unsafe_char_in_capped_body");
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    }
    // CR053 final-review (HIGH, ASTERDEX-CLOSEPOS): `closePosition` (the
    // Binance-fork Close-All flag) closes the ENTIRE position with NO
    // `quantity`, so a flat quantity= parse can't bound it AND it can target a
    // symbol absent from order_caps. DENY on PRESENCE of the flag when capped
    // (value-agnostic — backend truthiness is opaque — and even a bare valueless
    // `closePosition` is denied, Gemini final-review).
    if asterdex_flag_present(body, "closePosition") {
        tracing::warn!(event = "asterdex_closeposition_denied_capped");
        return Err(SignResponse::err(err_code::POLICY_DENIED));
    }
    // Q2: a batch place (`batchOrders` body-param) carries a JSON array of orders
    // that a flat `quantity=` parse can't bound → DENY on flag presence when
    // capped (fail-closed) until per-element batch parsing ships. Detected by
    // BODY, never by path (path is untrusted).
    if asterdex_flag_present(body, "batchOrders") {
        tracing::warn!(event = "asterdex_batch_denied_capped");
        return Err(SignResponse::err(err_code::POLICY_DENIED));
    }
    // H1 (AF-1 Asterdex): POSITIVE body param-name allow-list. Runs AFTER the
    // two specific presence-denies (so closePosition/batchOrders keep their
    // clearer policy_denied) and AFTER the charset gate (so names/values are
    // already free of percent/alt-separator bytes). Any param the venue would
    // read but this enclave doesn't recognize — a case variant (`Quantity=`), an
    // alt sizing/exposure param, a typo, a bare flag — refuses the whole
    // request. Closes the case-smuggle + alt-param classes without depending on
    // Asterdex's exact case-rules or param-space.
    if check_asterdex_body_allow(body).is_err() {
        tracing::warn!(event = "asterdex_param_not_allowed_capped");
        return Err(SignResponse::err(err_code::BAD_REQUEST));
    }
    // Single-order size. No `quantity=` → a read / cancel-by-id (no size to
    // cap) → allow (the path allow-list + signer/nonce binding still apply).
    let qty = match asterdex_first_param(body, "quantity=") {
        Ok(Some(q)) => q,
        Ok(None) => return Ok(()),
        Err(()) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
    };
    // A sized order we can't attribute to a symbol can't be capped → deny.
    let symbol = match asterdex_first_param(body, "symbol=") {
        Ok(Some(s)) => s,
        Ok(None) => {
            tracing::warn!(event = "asterdex_size_without_symbol_denied");
            return Err(SignResponse::err(err_code::POLICY_DENIED));
        }
        Err(()) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
    };
    // B2: when the matched entry carries `max_notional`, this opaque-body path
    // must not trust `price=` alone — a MARKET order with a decorative low
    // `price=` param would pass the arithmetic while executing at market
    // (whether the venue rejects the stray param is venue behavior, not an
    // attested bound). So a notional-capped symbol may place ONLY `type=LIMIT`
    // orders here; every other/absent `type` is denied fail-closed. The
    // camelCase Binance-fork param space means a literal lowercase `type=` /
    // `price=` byte-search cannot collide with `workingType=` / `stopPrice=` /
    // `priceProtect=` (capital letters break the match).
    let notional_capped = p
        .order_caps
        .as_ref()
        .and_then(|caps| caps.iter().find(|c| c.symbol == symbol))
        .is_some_and(|c| c.max_notional.is_some());
    let price = if notional_capped {
        match asterdex_first_param(body, "type=") {
            Ok(Some("LIMIT")) => {}
            Ok(_) => {
                tracing::warn!(event = "asterdex_notional_nonlimit_denied", symbol = %symbol);
                return Err(SignResponse::err(err_code::POLICY_DENIED));
            }
            Err(()) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
        }
        match asterdex_first_param(body, "price=") {
            // Present → enforce_order_cap does the notional math; a LIMIT
            // order with no price is venue-invalid anyway → same fail-closed
            // deny lands there (price=None under an active notional cap).
            Ok(px) => px,
            Err(()) => return Err(SignResponse::err(err_code::BAD_REQUEST)),
        }
    } else {
        None
    };
    // Reuse the structured-path enforcement: symbol ∉ caps → policy_denied;
    // qty > max_qty → policy_denied; notional (B2) when the entry declares it;
    // malformed attribution identical to binance/okx.
    enforce_order_cap(policy, symbol, Some(qty), price)
}

fn handle_sign_asterdex(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
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

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => {
            return SignResponse::err(err_code::KMS_DECRYPT_DENIED);
        }
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => {
            return SignResponse::err(err_code::POLICY_REQUIRED);
        }
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // H1 (AF-1 Asterdex) enclave-floor: Asterdex is a money-venue, and its size
    // cap (`enforce_asterdex_size_cap`) SILENTLY no-ops when the policy carries
    // no `order_caps`. Under the strict regime (`SIGNER_REQUIRE_POLICY=1`, the
    // mainnet profile), a money-venue signature with no order_caps is therefore
    // an un-bounded order — refuse it fail-closed. This makes the capped path
    // (which runs the positive param allow-list + size/notional cap) the ONLY
    // path for a real Asterdex key. Dev/legacy (REQUIRE_POLICY off) is unchanged.
    if asterdex_floor_denies(policy_required(), policy.as_ref()) {
        tracing::warn!(event = "asterdex_money_venue_missing_order_caps");
        return SignResponse::err(err_code::POLICY_REQUIRED);
    }

    if let Some(ref p) = policy {
        if let Some(ref allowed) = p.allowed_asterdex_endpoints {
            // SECURITY CAVEAT (Gemini PR #46 round-3 HIGH): the Asterdex
            // signature commits to the request `body`, NOT the `path`. A
            // compromised gateway can therefore send an allowed `path`
            // alongside a malicious `body` (e.g. withdrawal parameters)
            // and this whitelist will pass even though the signed
            // operation is forbidden. This check remains as a useful
            // misconfiguration / accidental-misuse guard (defense in
            // depth), but the cryptographically sound mitigation against
            // body-smuggling requires parsing & validating the signed
            // `body` itself. That body-content validation is tracked as
            // a follow-up (out of scope for this PR — touches signing
            // protocol).
            //
            // Gemini PR #46 round-2: Asterdex forwards the full path
            // including query string. The whitelist must match the
            // route portion only. Split at first `?`.
            //
            // Gemini PR #46 round-3 SEC-HIGH: consolidate the warn-pass
            // and the match-pass into one loop. Previous two-pass form
            // (a) used `contains('?')` which is substring-search style
            // per repo guidelines; switched to `split_once('?')` for
            // explicit position-aware parsing, and (b) the looser warn
            // loop diverged stylistically from the strict `==` match
            // loop — risk of one being right and the other wrong.
            let path = req.path.as_deref().unwrap_or("");
            let path_only = path.split('?').next().unwrap_or("");
            let mut endpoint_allowed = false;
            for ep in allowed.iter() {
                // Misconfigured entries (with embedded query string) can
                // never match a stripped request path — warn and skip.
                if ep.split_once('?').is_some() {
                    tracing::warn!(
                        event = "asterdex_policy_entry_contains_query",
                        entry = %ep,
                        "policy whitelist entry contains '?'; will never match (paths are stripped before compare)"
                    );
                    continue;
                }
                if ep == path_only {
                    endpoint_allowed = true;
                    break;
                }
            }
            if !endpoint_allowed {
                tracing::warn!(
                    event = "asterdex_endpoint_denied",
                    path = %path,
                    path_only = %path_only,
                    allowed = ?allowed,
                );
                return SignResponse::err(err_code::POLICY_DENIED);
            }
        }
    }

    // CR053 / ZN-204: bound order SIZE from the SIGNED body (the path allow-list
    // above is defense-in-depth only — the signature commits to body, not path).
    // No-op unless the policy declares order_caps. Runs before the KMS-derived
    // secret is touched (fail-fast, no secret needed).
    if let Err(resp) = enforce_asterdex_size_cap(policy.as_ref(), body) {
        return resp;
    }

    let secret: AsterdexSecret = match secret_json.deserialize_into() {
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
            SignResponse::ok_headers(headers).with_policy_hash(policy_hash)
        }
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
    // secret, pk, plaintext all zeroize on Drop.
}

/// x402 / EIP-3009 `TransferWithAuthorization` signing. The enclave holds the
/// payer's EVM key (same blob shape as the EVM DEX adapters: `private_key` +
/// `signer_address`) and produces a gasless USDC-transfer authorization
/// signature. UPL policy can additionally bind chain / token / amount cap.
///
/// EIP-712 flow (no HTTP method/path) — governed by `allowed_actions` +
/// the `x402` policy clause, not method/path whitelists.
fn handle_sign_x402_eip3009(req: SignRequest, identity: &crate::registry::ResolvedIdentity) -> SignResponse {
    let Some(x402) = req.x402.as_ref() else {
        return SignResponse::err(err_code::BAD_REQUEST);
    };

    // EIP-3009 validity-window sanity (CodeRabbit PR #74). An authorization is
    // valid only while `validAfter < now < validBefore`; if
    // `valid_after >= valid_before` the window is empty/inverted and the
    // signature can NEVER settle on-chain. Reject fail-closed BEFORE the KMS
    // decrypt + sign, rather than emit a guaranteed-dead authorization.
    // (Both are u64 seconds; equality is also rejected — a zero-width window
    // is never satisfiable since the settlement check is strict.)
    if x402.valid_after >= x402.valid_before {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    let (policy, secret_json) = match load_and_parse_blob(&req, identity) {
        Ok(t) => t,
        Err(LoadSecretError::BadRequest) => return SignResponse::err(err_code::BAD_REQUEST),
        Err(LoadSecretError::KmsDenied) => return SignResponse::err(err_code::KMS_DECRYPT_DENIED),
        Err(LoadSecretError::Internal) => return SignResponse::err(err_code::INTERNAL_ERROR),
        Err(LoadSecretError::PolicyRequired) => return SignResponse::err(err_code::POLICY_REQUIRED),
    };

    let policy_hash = match enforce_policy(policy.as_ref(), &req) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // Parse the public authorization fields.
    let token_address = match crate::signer::parse_evm_address(&x402.token_address) {
        Ok(a) => a,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let from = match crate::signer::parse_evm_address(&x402.from) {
        Ok(a) => a,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let to = match crate::signer::parse_evm_address(&x402.to) {
        Ok(a) => a,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let value = match crate::signer::parse_u256_be_decimal(&x402.value) {
        Ok(v) => v,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    let nonce = match crate::signer::parse_bytes32_hex(&x402.nonce) {
        Ok(n) => n,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };

    // CR050: x402 is a WITHDRAWAL primitive (moves USDC out of the payer key),
    // so the spend cap + recipient allow-list are MANDATORY and fail-closed —
    // "no clause" must never mean "no limit". Enforced in `enforce_x402_cap`.
    if let Err(resp) =
        enforce_x402_cap(policy.as_ref(), x402.chain_id, &token_address, &to, &value)
    {
        return resp;
    }

    // Load the payer EVM key (reuses the EVM secret shape).
    let secret: AsterdexSecret = match secret_json.deserialize_into() {
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
    let derived = match crate::signer::derive_address_from_private_key(&pk) {
        Ok(a) => a,
        Err(_) => return SignResponse::err(err_code::INTERNAL_ERROR),
    };
    // Blob self-consistency: the stapled address matches the PK.
    let claimed = match crate::signer::parse_evm_address(&secret.signer_address) {
        Ok(a) => a,
        Err(_) => return SignResponse::err(err_code::BAD_REQUEST),
    };
    if derived.ct_eq(&claimed).unwrap_u8() == 0 {
        return SignResponse::err(err_code::BAD_REQUEST);
    }
    // CRITICAL: the enclave may only authorize transfers FROM its own key.
    // A facilitator's `ecrecover` would reject a mismatched `from` anyway,
    // but enforce it here so the enclave never emits a signature whose
    // `from` ≠ the signing key.
    if derived.ct_eq(&from).unwrap_u8() == 0 {
        return SignResponse::err(err_code::BAD_REQUEST);
    }

    match crate::signer::sign_x402_eip3009(
        &pk,
        &x402.token_name,
        &x402.token_version,
        x402.chain_id,
        &token_address,
        &from,
        &to,
        &value,
        x402.valid_after,
        x402.valid_before,
        &nonce,
    ) {
        Ok(signature) => {
            let mut headers = std::collections::BTreeMap::new();
            headers.insert("signature".to_owned(), signature);
            headers.insert("from".to_owned(), format!("0x{}", hex::encode(derived)));
            SignResponse::ok_headers(headers).with_policy_hash(policy_hash)
        }
        Err(_) => SignResponse::err(err_code::INTERNAL_ERROR),
    }
    // secret, pk all zeroize on Drop.
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── H5: attestation input validation ────────────────────────────────────
    // These assert the gate that runs BEFORE the NSM ioctl, so they never touch
    // `/dev/nsm` and are safe on any CI host. The success path needs a real
    // enclave and is exercised on-box during the cutover verify.
    #[test]
    fn attestation_rejects_non_hex_nonce() {
        let req: SignRequest =
            serde_json::from_str(r#"{"action":"attestation","attestation_nonce":"zznothex"}"#)
                .unwrap();
        assert_eq!(handle(req).error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn attestation_rejects_empty_nonce() {
        let req: SignRequest =
            serde_json::from_str(r#"{"action":"attestation","attestation_nonce":""}"#).unwrap();
        assert_eq!(handle(req).error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn attestation_rejects_oversize_nonce() {
        // 1025 bytes (2050 hex chars) — over the 1024-byte NSM field cap.
        let big = "00".repeat(1025);
        let json = format!(r#"{{"action":"attestation","attestation_nonce":"{big}"}}"#);
        let req: SignRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(handle(req).error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn attestation_rejects_bad_user_data() {
        let req: SignRequest = serde_json::from_str(
            r#"{"action":"attestation","attestation_user_data":"nothexZZ"}"#,
        )
        .unwrap();
        assert_eq!(handle(req).error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    // Off-enclave (darwin dev / no NSM device) a well-formed request fails
    // closed via the stub → internal_error. Gated to non-linux so CI's linux
    // runner (which would ioctl a non-existent /dev/nsm) doesn't run it.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn attestation_valid_nonce_fails_closed_off_enclave() {
        let req: SignRequest =
            serde_json::from_str(r#"{"action":"attestation","attestation_nonce":"deadbeef"}"#)
                .unwrap();
        assert_eq!(handle(req).error.as_deref(), Some(err_code::INTERNAL_ERROR));
    }

    /// PR-B §3-invariant enforcement: a signing request is rejected (a) below
    /// the required wire version, (b) with no opaque token, and (c) when the
    /// resolved tenant is not granted the venue — the ACL deny happens in
    /// `authorize_venue` (on the once-resolved identity) BEFORE any blob/KMS work
    /// (CTO x402 condition).
    #[test]
    fn signing_requires_proto_version_token_and_venue_acl() {
        // Hold the shared registry test lock for the whole body so a concurrent
        // registry-test reset can't wipe `tok-a` between seed and resolve.
        let _gl = crate::registry::GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Seed: tenant "tok-a" → cust-a, granted only binance (NOT x402).
        crate::registry::test_install(&[("tok-a", "cust-a", &["binance"])]);

        let base = || SignRequest {
            action: "sign_binance_order".to_owned(),
            proto_version: REQUIRED_PROTO_VERSION,
            opaque_token: Some("tok-a".to_owned()),
            method: None,
            path: None,
            body: None,
            timestamp_ms: None,
            key_blob_s3_key: None,
            key_id: None,
            aws_credentials: None,
            ciphertext_blob_base64: None,
            query: None,
            op: None,
            payload: None,
            hl_action: None,
            nonce: None,
            vault_address: None,
            x402: None,
            order: None,
            cancel: None,
            data: None,
            registry_refresh: None,
            intent_signature: None,
            intent_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
        };

        // (a) proto_version too low → BAD_REQUEST (the gate, before dispatch).
        let mut old = base();
        old.proto_version = 0;
        assert_eq!(handle(old).error.as_deref(), Some(err_code::BAD_REQUEST));

        // (b) no opaque token → resolve fails → BAD_REQUEST.
        let mut no_tok = base();
        no_tok.opaque_token = None;
        assert_eq!(handle(no_tok).error.as_deref(), Some(err_code::BAD_REQUEST));

        // (c) venue ACL on the resolved identity: tok-a (binance only) is denied
        // the x402 venue but granted binance. authorize_venue — and thus the whole
        // signing path — consults ONLY this resolved identity, never a gateway
        // field. The identity is resolved exactly once per request in handle().
        let id = crate::registry::resolve("tok-a").expect("tok-a was seeded");
        assert!(!id.venue_allowed("x402"), "binance-only tenant must be denied x402");
        assert!(id.venue_allowed("binance"), "binance must be granted");
    }

    /// Broad test tenant seeded into the registry so handle()-level tests pass
    /// the proto-version gate AND identity-resolution AND the venue ACL — so the
    /// DOWNSTREAM validation under test (method/creds/ciphertext/window) is what
    /// actually runs, not the gate (round-1 BLOCKING: tests were shadow-passing
    /// on the gate). Grants every venue the handle() tests exercise. ADDITIVE
    /// upsert, so it coexists with the integration test's `tok-a` under the
    /// parallel runner.
    const TEST_SEED_TOKEN: &str = "test-seed-token";
    fn seed_test_tenant() -> &'static str {
        crate::registry::test_install(&[(
            TEST_SEED_TOKEN,
            "test-cust",
            &[
                "kucoin",
                "binance",
                "okx",
                "bybit",
                "hyperliquid_main",
                "asterdex",
                "x402",
            ],
        )]);
        TEST_SEED_TOKEN
    }

    /// Run `handle` with the broad test tenant guaranteed seeded, under the shared
    /// registry test lock held across seed→dispatch. This closes the race where a
    /// concurrent registry-test `reset_registry()` could wipe the seed between
    /// `req_template()`'s seed and `handle()`, silently turning a signing test into
    /// a shadow of the identity gate (round-1 self-review finding E). All
    /// handle()-level signing tests go through this.
    fn handle_seeded(req: SignRequest) -> SignResponse {
        let _gl = crate::registry::GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        seed_test_tenant();
        handle(req)
    }

    fn req_template() -> SignRequest {
        SignRequest {
            // KuCoin-shaped template (path /api/v1/orders, test-kucoin.enc): a
            // real signing action so the dispatch reaches the actual handler.
            action: "sign_kucoin".to_owned(),
            proto_version: REQUIRED_PROTO_VERSION,
            opaque_token: Some(seed_test_tenant().to_owned()),
            method: Some("POST".to_owned()),
            path: Some("/api/v1/orders".to_owned()),
            body: Some(r#"{"clientOid":"test"}"#.to_owned()),
            timestamp_ms: Some(1714997000000),
            key_blob_s3_key: Some("secrets/test-kucoin.enc".to_owned()),
            key_id: Some("alias/signer-poc".to_owned()),
            aws_credentials: None,
            ciphertext_blob_base64: None,
            registry_refresh: None,
            query: None,
            op: None,
            payload: None,
            // Phase 1 Stage 2 — EIP-712 fields default None for HMAC tests.
            hl_action: None,
            nonce: None,
            vault_address: None,
            x402: None,
            order: None,
            cancel: None,
            data: None,
            intent_signature: None,
            intent_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
        }
    }

    #[test]
    fn ping_returns_pong() {
        let req = SignRequest {
            action: "ping".to_owned(),
            ..req_template()
        };
        let resp = handle_seeded(req);
        assert_eq!(resp.signature_base64, "pong");
        assert!(resp.error.is_none());
    }

    #[test]
    fn unknown_action_returns_bad_request() {
        let req = SignRequest {
            action: "do-something-evil".to_owned(),
            ..req_template()
        };
        let resp = handle_seeded(req);
        assert_eq!(resp.signature_base64, "");
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    /// CodeRabbit PR #74: an x402 authorization with `valid_after >= valid_before`
    /// is unsatisfiable on-chain and must be rejected fail-closed BEFORE signing
    /// (before any KMS decrypt — so this test needs no blob). A *valid* window
    /// producing a real signature is covered by
    /// `signer::tests::x402_eip3009_matches_cast_reference`.
    #[test]
    fn x402_inverted_or_empty_window_returns_bad_request() {
        let mk = |after: u64, before: u64| SignRequest {
            action: "sign_x402_eip3009".to_owned(),
            x402: Some(crate::proto::X402Request {
                token_name: "USD Coin".to_owned(),
                token_version: "2".to_owned(),
                chain_id: 8453,
                token_address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_owned(),
                from: "0x15a88A4D4975Ad355E89204107BbDD176570810F".to_owned(),
                to: "0x000000000000000000000000000000000000dEaD".to_owned(),
                value: "1000000".to_owned(),
                valid_after: after,
                valid_before: before,
                nonce: "0x0000000000000000000000000000000000000000000000000000000000000001"
                    .to_owned(),
            }),
            ..req_template()
        };
        // Inverted window.
        assert_eq!(
            handle_seeded(mk(200, 100)).error.as_deref(),
            Some(err_code::BAD_REQUEST)
        );
        // Zero-width window (equal bounds) — also unsatisfiable.
        assert_eq!(
            handle_seeded(mk(100, 100)).error.as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    // ─── CR050: x402 mandatory cap + recipient allow-list ───────────────────
    //
    // Direct unit tests of `enforce_x402_cap` (a pure function — no KMS), the
    // way order_caps logic is tested. A withdrawal primitive must fail CLOSED:
    // no policy/clause/cap ⇒ policy_required; off-list recipient / over-cap /
    // wrong pin ⇒ policy_denied.

    const X402_USDC_BASE: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const X402_FACILITATOR: &str = "0x000000000000000000000000000000000000bEEF";
    const X402_ATTACKER: &str = "0x000000000000000000000000000000000000dEaD";

    fn evm_addr(h: &str) -> [u8; 20] {
        crate::signer::parse_evm_address(h).expect("test evm address")
    }
    fn u256_be(dec: &str) -> [u8; 32] {
        crate::signer::parse_u256_be_decimal(dec).expect("test u256")
    }
    /// A fully-specified, valid x402 cap: chain 8453 / USDC / max 1_000_000 /
    /// recipient = facilitator.
    fn x402_capped_policy() -> Policy {
        Policy {
            x402: Some(crate::proto::X402Policy {
                chain_id: Some(8453),
                token_address: Some(X402_USDC_BASE.to_owned()),
                max_value: Some("1000000".to_owned()),
                allowed_recipients: Some(vec![X402_FACILITATOR.to_owned()]),
            }),
            ..Policy::default()
        }
    }
    /// Returns the err_code (owned) or `None` on allow. `chain` lets a couple
    /// of tests pin a mismatching request chain.
    fn x402_check_chain(p: Option<&Policy>, chain: u64, token: &str, to: &str, value: &str) -> Option<String> {
        // SignResponse impls Drop (zeroizes) → can't move `error` out; clone it.
        enforce_x402_cap(p, chain, &evm_addr(token), &evm_addr(to), &u256_be(value))
            .err()
            .and_then(|r| r.error.clone())
    }
    fn x402_check(p: Option<&Policy>, to: &str, value: &str) -> Option<String> {
        x402_check_chain(p, 8453, X402_USDC_BASE, to, value)
    }

    #[test]
    fn cr050_no_policy_is_policy_required() {
        assert_eq!(
            x402_check(None, X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_REQUIRED)
        );
    }

    #[test]
    fn cr050_no_x402_clause_is_policy_required() {
        // A policy that exists but omits the x402 clause used to sign UNBOUNDED.
        let p = Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".to_owned()]),
            ..Policy::default()
        };
        assert_eq!(
            x402_check(Some(&p), X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_REQUIRED)
        );
    }

    #[test]
    fn cr050_no_max_value_is_policy_required() {
        let mut p = x402_capped_policy();
        p.x402.as_mut().unwrap().max_value = None;
        assert_eq!(
            x402_check(Some(&p), X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_REQUIRED)
        );
    }

    #[test]
    fn cr050_no_allowed_recipients_is_policy_required() {
        let mut p = x402_capped_policy();
        p.x402.as_mut().unwrap().allowed_recipients = None;
        assert_eq!(
            x402_check(Some(&p), X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_REQUIRED)
        );
    }

    #[test]
    fn cr050_empty_allowed_recipients_denies_all() {
        // Some(vec![]) is present (not policy_required) but matches nobody.
        let mut p = x402_capped_policy();
        p.x402.as_mut().unwrap().allowed_recipients = Some(vec![]);
        assert_eq!(
            x402_check(Some(&p), X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr050_recipient_off_list_is_policy_denied() {
        // The headline exploit: injected agent signs transfer(to = attacker).
        assert_eq!(
            x402_check(Some(&x402_capped_policy()), X402_ATTACKER, "1").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr050_happy_path_allows_capped_transfer_to_listed_recipient() {
        assert_eq!(
            x402_check(Some(&x402_capped_policy()), X402_FACILITATOR, "1000000"),
            None
        );
    }

    #[test]
    fn cr050_value_over_cap_is_policy_denied() {
        assert_eq!(
            x402_check(Some(&x402_capped_policy()), X402_FACILITATOR, "1000001").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr050_wrong_chain_is_policy_denied() {
        // policy pins 8453; request chain 1.
        assert_eq!(
            x402_check_chain(Some(&x402_capped_policy()), 1, X402_USDC_BASE, X402_FACILITATOR, "1")
                .as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr050_wrong_token_is_policy_denied() {
        // request token ≠ pinned USDC.
        assert_eq!(
            x402_check_chain(Some(&x402_capped_policy()), 8453, X402_ATTACKER, X402_FACILITATOR, "1")
                .as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr050_recipient_match_is_case_insensitive() {
        // List entry lower-case, request `to` checksummed — both parse to the
        // same 20 bytes, so membership holds (no checksum dependence).
        let mut p = x402_capped_policy();
        p.x402.as_mut().unwrap().allowed_recipients =
            Some(vec![X402_FACILITATOR.to_lowercase()]);
        assert_eq!(x402_check(Some(&p), X402_FACILITATOR, "1"), None);
    }

    #[test]
    fn cr050_malformed_recipient_entry_is_policy_denied() {
        let mut p = x402_capped_policy();
        p.x402.as_mut().unwrap().allowed_recipients = Some(vec!["not-an-address".to_owned()]);
        assert_eq!(
            x402_check(Some(&p), X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr050_no_chain_id_is_policy_required() {
        // chain_id is mandatory (final-review LOW): a value cap without a chain
        // pin is meaningless.
        let mut p = x402_capped_policy();
        p.x402.as_mut().unwrap().chain_id = None;
        assert_eq!(
            x402_check(Some(&p), X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_REQUIRED)
        );
    }

    #[test]
    fn cr050_no_token_address_is_policy_required() {
        // token_address is mandatory: value is in raw token units.
        let mut p = x402_capped_policy();
        p.x402.as_mut().unwrap().token_address = None;
        assert_eq!(
            x402_check(Some(&p), X402_FACILITATOR, "1").as_deref(),
            Some(err_code::POLICY_REQUIRED)
        );
    }

    // ─── CR053: Hyperliquid asset-index size caps + vault allow-list ────────

    const HL_VAULT: &str = "0x00000000000000000000000000000000000000A1";
    const HL_VAULT_OTHER: &str = "0x00000000000000000000000000000000000000B2";

    fn hl_cap(asset: u64, max_size: &str) -> crate::proto::HlOrderCap {
        crate::proto::HlOrderCap { asset, max_size: max_size.to_owned(), max_notional: None }
    }
    fn hl_order(a: u64, s: &str) -> serde_json::Value {
        serde_json::json!({"type": "order", "orders": [{"a": a, "b": true, "s": s, "p": "1"}]})
    }
    fn hl_check(p: Option<&Policy>, action: &serde_json::Value, vault: Option<&[u8; 20]>) -> Option<String> {
        enforce_hl_caps(p, action, vault).err().and_then(|r| r.error.clone())
    }

    #[test]
    fn cr053_hl_no_policy_or_no_caps_allows_any_size() {
        let big = hl_order(0, "999999");
        assert_eq!(hl_check(None, &big, None), None);
        let p = Policy { allowed_actions: Some(vec!["sign_hyperliquid_main_order".into()]), ..Policy::default() };
        assert_eq!(hl_check(Some(&p), &big, None), None);
    }

    #[test]
    fn cr053_hl_order_within_cap_ok() {
        let p = Policy { hl_order_caps: Some(vec![hl_cap(0, "5")]), ..Policy::default() };
        assert_eq!(hl_check(Some(&p), &hl_order(0, "3"), None), None);
        // boundary: equal to cap is allowed (inclusive).
        assert_eq!(hl_check(Some(&p), &hl_order(0, "5"), None), None);
    }

    #[test]
    fn cr053_hl_order_over_cap_denied() {
        let p = Policy { hl_order_caps: Some(vec![hl_cap(0, "5")]), ..Policy::default() };
        assert_eq!(hl_check(Some(&p), &hl_order(0, "5.0001"), None).as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn cr053_hl_unlisted_asset_denied() {
        // caps only for asset 0; an order for asset 1 is fail-closed denied.
        let p = Policy { hl_order_caps: Some(vec![hl_cap(0, "5")]), ..Policy::default() };
        assert_eq!(hl_check(Some(&p), &hl_order(1, "1"), None).as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn cr053_hl_order_missing_size_is_bad_request_when_capped() {
        let p = Policy { hl_order_caps: Some(vec![hl_cap(0, "5")]), ..Policy::default() };
        let no_size = serde_json::json!({"type": "order", "orders": [{"a": 0, "b": true}]});
        assert_eq!(hl_check(Some(&p), &no_size, None).as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn cr053_hl_multi_order_one_over_cap_denies_whole() {
        let p = Policy { hl_order_caps: Some(vec![hl_cap(0, "5")]), ..Policy::default() };
        let batch = serde_json::json!({"type": "order", "orders": [{"a": 0, "s": "3"}, {"a": 0, "s": "99"}]});
        assert_eq!(hl_check(Some(&p), &batch, None).as_deref(), Some(err_code::POLICY_DENIED));
    }

    #[test]
    fn cr053_hl_cancel_action_skips_size_caps() {
        // A cancel action has no orders[]; size caps must not fire (vault check
        // still applies, but none set here).
        let p = Policy { hl_order_caps: Some(vec![hl_cap(0, "5")]), ..Policy::default() };
        let cancel = serde_json::json!({"type": "cancel", "cancels": [{"a": 0, "o": 123}]});
        assert_eq!(hl_check(Some(&p), &cancel, None), None);
    }

    #[test]
    fn cr053_hl_vault_in_allowlist_ok() {
        let p = Policy { allowed_vaults: Some(vec![HL_VAULT.into()]), ..Policy::default() };
        assert_eq!(hl_check(Some(&p), &hl_order(0, "1"), Some(&evm_addr(HL_VAULT))), None);
    }

    #[test]
    fn cr053_hl_vault_off_allowlist_denied() {
        let p = Policy { allowed_vaults: Some(vec![HL_VAULT.into()]), ..Policy::default() };
        assert_eq!(
            hl_check(Some(&p), &hl_order(0, "1"), Some(&evm_addr(HL_VAULT_OTHER))).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr053_hl_vault_none_main_account_unaffected() {
        // allowed_vaults present but request has NO vault (main account) → allowed.
        let p = Policy { allowed_vaults: Some(vec![HL_VAULT.into()]), ..Policy::default() };
        assert_eq!(hl_check(Some(&p), &hl_order(0, "1"), None), None);
    }

    #[test]
    fn cr053_hl_vault_match_case_insensitive() {
        let p = Policy { allowed_vaults: Some(vec![HL_VAULT.to_lowercase()]), ..Policy::default() };
        assert_eq!(hl_check(Some(&p), &hl_order(0, "1"), Some(&evm_addr(HL_VAULT))), None);
    }

    #[test]
    fn cr053_hl_vault_malformed_entry_denied() {
        let p = Policy { allowed_vaults: Some(vec!["not-an-address".into()]), ..Policy::default() };
        assert_eq!(
            hl_check(Some(&p), &hl_order(0, "1"), Some(&evm_addr(HL_VAULT))).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr053_hl_cancel_vault_binding_enforced() {
        // Vault check applies to cancel actions too (loader covers order+cancel).
        let p = Policy { allowed_vaults: Some(vec![HL_VAULT.into()]), ..Policy::default() };
        let cancel = serde_json::json!({"type": "cancel", "cancels": [{"a": 0, "o": 123}]});
        assert_eq!(
            hl_check(Some(&p), &cancel, Some(&evm_addr(HL_VAULT_OTHER))).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        assert_eq!(hl_check(Some(&p), &cancel, Some(&evm_addr(HL_VAULT))), None);
    }

    #[test]
    fn cr053_hl_empty_vault_allowlist_denies_explicit_vault() {
        // Some(vec![]) = explicit "no vault permitted" (≠ None = no constraint).
        let p = Policy { allowed_vaults: Some(vec![]), ..Policy::default() };
        assert_eq!(
            hl_check(Some(&p), &hl_order(0, "1"), Some(&evm_addr(HL_VAULT))).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        // …but a None vault (main account) is still unaffected.
        assert_eq!(hl_check(Some(&p), &hl_order(0, "1"), None), None);
    }

    #[test]
    fn cr053_hl_vault_malformed_sibling_still_denied() {
        // A valid matching entry alongside a malformed one must STILL deny
        // (fail-closed; a refactor must not let ok=true win over malformed).
        let p = Policy {
            allowed_vaults: Some(vec![HL_VAULT.into(), "not-an-address".into()]),
            ..Policy::default()
        };
        assert_eq!(
            hl_check(Some(&p), &hl_order(0, "1"), Some(&evm_addr(HL_VAULT))).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    // ─── CR053 Asterdex ZN-204: body order-size cap (reuses order_caps) ──────

    fn aster_policy() -> Policy {
        Policy {
            order_caps: Some(vec![crate::proto::OrderAssetCap {
                symbol: "ASTERUSDT".to_owned(),
                max_qty: "5".to_owned(),
                max_notional: None,
            }]),
            ..Policy::default()
        }
    }
    fn aster_check(p: Option<&Policy>, body: &str) -> Option<String> {
        enforce_asterdex_size_cap(p, body).err().and_then(|r| r.error.clone())
    }

    #[test]
    fn cr053_asterdex_size_within_cap_ok() {
        assert_eq!(
            aster_check(Some(&aster_policy()), "symbol=ASTERUSDT&quantity=3&signer=0xa&nonce=1700000000000"),
            None
        );
    }

    #[test]
    fn cr053_asterdex_size_over_cap_denied() {
        assert_eq!(
            aster_check(Some(&aster_policy()), "symbol=ASTERUSDT&quantity=6&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::SIZE_OVER_CAP)
        );
    }

    #[test]
    fn cr053_asterdex_symbol_not_in_caps_denied() {
        assert_eq!(
            aster_check(Some(&aster_policy()), "symbol=BTCUSDT&quantity=1").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr053_asterdex_batch_denied_when_capped() {
        // Q2: batchOrders body-param → deny when capped (can't bound array size).
        // Plain (non-%) value → POLICY_DENIED via the batchOrders guard.
        assert_eq!(
            aster_check(Some(&aster_policy()), "batchOrders=2&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        // Mid-token collision (xbatchOrders=) also denies (fail-closed). H1:
        // `xbatchOrders` is not a boundary match for the batchOrders flag, so it
        // falls through to the POSITIVE param allow-list, which refuses the
        // unknown name with BAD_REQUEST (still fail-closed, caught earlier than
        // the old size-without-symbol path).
        assert_eq!(
            aster_check(Some(&aster_policy()), "xbatchOrders=1&quantity=1").as_deref(),
            Some(err_code::BAD_REQUEST)
        );
        // A url-encoded batch body ([]=%5B%5D) is still denied — the percent-guard
        // catches it first as BAD_REQUEST (also fail-closed, different code).
        assert_eq!(
            aster_check(Some(&aster_policy()), "batchOrders=%5B%5D&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn cr053_asterdex_no_quantity_is_read_or_cancel_ok() {
        // No size in the body (read / cancel-by-id) → nothing to size-cap.
        assert_eq!(aster_check(Some(&aster_policy()), "symbol=ASTERUSDT&signer=0xa&nonce=1700000000000"), None);
    }

    #[test]
    fn cr053_asterdex_quantity_without_symbol_denied() {
        // A sized order we can't attribute to a symbol can't be capped → deny.
        assert_eq!(
            aster_check(Some(&aster_policy()), "quantity=1&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn cr053_asterdex_no_caps_is_legacy_passthrough() {
        // No order_caps declared → no size enforcement (unchanged behaviour).
        assert_eq!(aster_check(Some(&Policy::default()), "symbol=ASTERUSDT&quantity=99999"), None);
        assert_eq!(aster_check(None, "symbol=ASTERUSDT&quantity=99999"), None);
    }

    #[test]
    fn cr053_asterdex_duplicate_quantity_bad_request() {
        // Parameter pollution on the size field → bad_request (fail-closed).
        assert_eq!(
            aster_check(Some(&aster_policy()), "symbol=ASTERUSDT&quantity=1&quantity=99").as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn cr053_asterdex_symbol_param_pollution_via_note_denied() {
        // `note=symbol=...` — the first `symbol=` is mid-token (after `note=`),
        // not at a param boundary → malformed → bad_request.
        assert_eq!(
            aster_check(Some(&aster_policy()), "note=symbol=ASTERUSDT&quantity=1").as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn cr053_asterdex_close_position_denied_when_capped() {
        // ASTERDEX-CLOSEPOS (final-review HIGH): closePosition= closes the ENTIRE
        // position with NO quantity → deny on presence, value-agnostic, even for
        // a symbol NOT in the caps.
        for body in [
            "symbol=ASTERUSDT&closePosition=true&type=STOP_MARKET&signer=0xa&nonce=1700000000000",
            "symbol=BTCUSDT&closePosition=true&signer=0xa&nonce=1700000000000", // off-cap symbol
            "closePosition=TRUE&signer=0xa&nonce=1700000000000",
            "closePosition=1&signer=0xa&nonce=1700000000000",
        ] {
            assert_eq!(
                aster_check(Some(&aster_policy()), body).as_deref(),
                Some(err_code::POLICY_DENIED),
                "closePosition body must be denied: {body}"
            );
        }
    }

    #[test]
    fn cr053_asterdex_valueless_flag_denied() {
        // Gemini final-review: a bare valueless `closePosition` / `batchOrders`
        // (no `=`) must also be denied — a permissive backend could honour it.
        assert_eq!(
            aster_check(Some(&aster_policy()), "symbol=ASTERUSDT&closePosition&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        assert_eq!(
            aster_check(Some(&aster_policy()), "batchOrders&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        // boundary correctness: real flag matches, mid-token does not.
        assert!(asterdex_flag_present("a&closePosition&b", "closePosition"));
        assert!(asterdex_flag_present("closePosition=true", "closePosition"));
        assert!(!asterdex_flag_present("xclosePosition=1", "closePosition"));
        assert!(!asterdex_flag_present("symbol=ASTERUSDT&quantity=1", "closePosition"));
    }

    #[test]
    fn cr053_asterdex_percent_encoded_key_rejected() {
        // %71uantity= (%71='q') would slip past the literal quantity= search; the
        // percent-guard rejects any % in a capped body (final-review MEDIUM).
        assert_eq!(
            aster_check(Some(&aster_policy()), "%71uantity=3&symbol=ASTERUSDT&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::BAD_REQUEST)
        );
        // …and a percent-encoded VALUE is likewise rejected (was already caught
        // by cmp_positive_decimals, now caught earlier).
        assert_eq!(
            aster_check(Some(&aster_policy()), "symbol=ASTERUSDT&quantity=%35&signer=0xa&nonce=1700000000000").as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn cr053_asterdex_empty_quantity_bad_request() {
        // quantity= with no value → cmp_positive_decimals("") errors; attribution
        // probe confirms policy max_qty valid → BAD_REQUEST (not INTERNAL_ERROR).
        assert_eq!(
            aster_check(Some(&aster_policy()), "symbol=ASTERUSDT&quantity=&nonce=1700000000000").as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    // ─── H1 (AF-1 Asterdex): positive body allow-list + enclave-floor ───────

    #[test]
    fn h1_asterdex_body_allow_accepts_legit_order_and_read() {
        // A full legit order + auth params — every name is whitelisted.
        assert!(check_asterdex_body_allow(
            "symbol=ASTERUSDT&side=BUY&type=LIMIT&quantity=1&price=50&timeInForce=GTC&reduceOnly=false&newClientOrderId=abc&recvWindow=5000&timestamp=1700000000000&signer=0xa&nonce=1700000000000"
        )
        .is_ok());
        // A read / cancel shape (no sizing params).
        assert!(check_asterdex_body_allow(
            "symbol=ASTERUSDT&orderId=42&origClientOrderId=abc&limit=100&signer=0xa&nonce=1700000000000"
        )
        .is_ok());
        // Trailing/empty segments are skipped, not treated as a bad name.
        assert!(check_asterdex_body_allow("symbol=ASTERUSDT&signer=0xa&nonce=1&").is_ok());
    }

    #[test]
    fn h1_asterdex_body_allow_denies_case_smuggle_and_alt_params() {
        // Case-smuggle: the whitelist is lowercase-`quantity` only, so a case
        // variant the venue MIGHT read case-insensitively is refused (closes the
        // case-smuggle class without confirming Asterdex's case rules).
        for name in ["Quantity", "QUANTITY", "quantitY"] {
            assert!(
                check_asterdex_body_allow(&format!(
                    "symbol=ASTERUSDT&{name}=1000&signer=0xa&nonce=1"
                ))
                .is_err(),
                "{name} must be refused"
            );
        }
        // Alt sizing / exposure params the byte extractor never knew about.
        for name in ["quoteOrderQty", "leverage", "notional", "closeAll", "sz", "amount"] {
            assert!(
                check_asterdex_body_allow(&format!(
                    "symbol=ASTERUSDT&{name}=999&signer=0xa&nonce=1"
                ))
                .is_err(),
                "alt-param {name} must be refused"
            );
        }
    }

    #[test]
    fn h1_asterdex_size_cap_denies_case_smuggle_via_allow_list() {
        // End-to-end through the size cap: a `Quantity=` case-smuggle body (no
        // lowercase `quantity=`, so the OLD byte extractor saw "no size" → allow)
        // is now refused BAD_REQUEST by the positive allow-list.
        assert_eq!(
            aster_check(
                Some(&aster_policy()),
                "symbol=ASTERUSDT&side=BUY&type=MARKET&Quantity=1000&signer=0xa&nonce=1700000000000"
            )
            .as_deref(),
            Some(err_code::BAD_REQUEST)
        );
        // An alt sizing param with no lowercase `quantity=` — same class, denied.
        assert_eq!(
            aster_check(
                Some(&aster_policy()),
                "symbol=ASTERUSDT&side=BUY&type=MARKET&quoteOrderQty=1000&signer=0xa&nonce=1700000000000"
            )
            .as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn h1_asterdex_charset_gate_bans_alt_separators_and_bare_flags() {
        // rust-auditor M: an alt-separator embedded in an ALLOWED param's value
        // (`price=50;quantity=999`) allow-lists as name `price`, and the
        // `&quantity=` byte-search reads only the real `quantity=1` — but a
        // `;`-splitting backend would read quantity=999. The charset gate rejects
        // the `;` outright (fail-closed) before any of that matters.
        for body in [
            "symbol=ASTERUSDT&quantity=1&price=50;quantity=999&signer=0xa&nonce=1700000000000",
            "symbol=ASTERUSDT&quantity=1,quantity=999&signer=0xa&nonce=1700000000000", // comma sep
            "symbol=ASTERUSDT&quantity=1 quantity=999&signer=0xa&nonce=1700000000000", // space sep
            "symbol=ASTERUSDT&quantity=%31&signer=0xa&nonce=1700000000000",            // percent
        ] {
            assert_eq!(
                aster_check(Some(&aster_policy()), body).as_deref(),
                Some(err_code::BAD_REQUEST),
                "unsafe-char body must be denied: {body}"
            );
        }
        // rust-auditor L: a bare `quantity` (no `=`) repeat evades the size cap's
        // `&quantity=` dup-guard; the allow-list's `name=value` requirement now
        // refuses it.
        assert_eq!(
            aster_check(
                Some(&aster_policy()),
                "symbol=ASTERUSDT&quantity=1&quantity&signer=0xa&nonce=1700000000000"
            )
            .as_deref(),
            Some(err_code::BAD_REQUEST)
        );
        // A legit clientOrderId using `:` `/` `-` `_` (all valid Binance-fork id
        // bytes) is NOT a false-positive — the charset gate and the allow-list
        // both accept it.
        assert!(check_asterdex_body_allow(
            "symbol=ASTERUSDT&quantity=1&newClientOrderId=x-1_2:3/4&signer=0xa&nonce=1"
        )
        .is_ok());
        assert_eq!(
            aster_check(
                Some(&aster_policy()),
                "symbol=ASTERUSDT&quantity=3&newClientOrderId=x-1_2:3/4&signer=0xa&nonce=1700000000000"
            ),
            None
        );
    }

    #[test]
    fn h1_asterdex_floor_denies_uncapped_under_strict() {
        let capped = aster_policy(); // has order_caps
        let uncapped = Policy::default(); // no order_caps
        // Strict regime: a money-venue policy with no order_caps is refused; with
        // caps it passes the floor. Non-strict (dev): never floors.
        assert!(asterdex_floor_denies(true, None), "strict + no policy → deny");
        assert!(
            asterdex_floor_denies(true, Some(&uncapped)),
            "strict + no caps → deny"
        );
        assert!(
            !asterdex_floor_denies(true, Some(&capped)),
            "strict + caps → allow"
        );
        assert!(
            !asterdex_floor_denies(false, None),
            "dev regime never floors"
        );
        assert!(!asterdex_floor_denies(false, Some(&uncapped)));
    }

    // ─── AF-2: agent-signed order-intent canonical (byte-exact) ─────────────

    fn af2_order(
        symbol: &str,
        side: &str,
        qty: &str,
        ord_type: &str,
        price: Option<&str>,
        reduce_only: bool,
        coid: Option<&str>,
    ) -> crate::proto::OrderRequest {
        crate::proto::OrderRequest {
            symbol: symbol.to_owned(),
            side: side.to_owned(),
            qty: qty.to_owned(),
            ord_type: ord_type.to_owned(),
            price: price.map(str::to_owned),
            reduce_only,
            client_order_id: coid.map(str::to_owned),
        }
    }

    /// GOLDEN VECTORS — the exact intent bytes, computed by an INDEPENDENT
    /// Python reference encoder (the spec the agent SDK implements). Pinning the
    /// hex here makes agent↔enclave byte-exactness a cross-implementation
    /// guarantee: if either side drifts, the hex diverges and this fails.
    #[test]
    fn af2_intent_golden_order_limit() {
        let o = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), false, Some("coid-abc-001"));
        let msg = build_agent_intent_msg_order(
            "cust1", "binance", "sign_binance_order", 1714997000000, "coid-abc-001", &o,
        );
        assert_eq!(
            hex::encode(&msg),
            "7369676e65722d6167656e742d696e74656e742d7631000000000563757374310000000762696e616e6365000000127369676e5f62696e616e63655f6f726465720000018f4dc977400000000c636f69642d6162632d30303100000007425443555344540000000362757900000005302e303031000000056c696d69740100000005353030303000"
        );
    }

    #[test]
    fn af2_intent_golden_order_market_reduce_only() {
        let o = af2_order("BTC-USDT-SWAP", "sell", "1", "market", None, true, Some("coid-xyz-9"));
        let msg = build_agent_intent_msg_order(
            "cust1", "okx", "sign_okx_order", 1714997000000, "coid-xyz-9", &o,
        );
        assert_eq!(
            hex::encode(&msg),
            "7369676e65722d6167656e742d696e74656e742d763100000000056375737431000000036f6b780000000e7369676e5f6f6b785f6f726465720000018f4dc977400000000a636f69642d78797a2d390000000d4254432d555344542d535741500000000473656c6c0000000131000000066d61726b65740001"
        );
    }

    #[test]
    fn af2_intent_golden_cancel() {
        let c = crate::proto::CancelRequest {
            symbol: "BTCUSDT".to_owned(),
            order_id: "123456789".to_owned(),
        };
        let msg = build_agent_intent_msg_cancel(
            "cust1", "binance", "sign_binance_cancel", 1714997000000,
            "550e8400-e29b-41d4-a716-446655440000", &c,
        );
        assert_eq!(
            hex::encode(&msg),
            "7369676e65722d6167656e742d696e74656e742d7631000000000563757374310000000762696e616e6365000000137369676e5f62696e616e63655f63616e63656c0000018f4dc977400000002435353065383430302d653239622d343164342d613731362d343436363535343430303030000000074254435553445400000009313233343536373839"
        );
    }

    /// The presence byte MUST make `None` price distinct from `Some("")` — else a
    /// gateway could flip an absent price to an empty one (or vice-versa) without
    /// changing the signed bytes.
    #[test]
    fn af2_intent_none_vs_empty_price_differ() {
        let o_none = af2_order("BTCUSDT", "buy", "1", "market", None, false, Some("n"));
        let o_empty = af2_order("BTCUSDT", "buy", "1", "market", Some(""), false, Some("n"));
        let m_none = build_agent_intent_msg_order("c", "binance", "sign_binance_order", 1, "n", &o_none);
        let m_empty = build_agent_intent_msg_order("c", "binance", "sign_binance_order", 1, "n", &o_empty);
        assert_ne!(m_none, m_empty);
    }

    /// TAMPER FUZZER — flipping ANY intent-relevant field must change the bytes
    /// (no two distinct intents collide), so a gateway edit always breaks the
    /// agent signature. Deterministic; mirrors the AF-1 fuzzer style.
    #[test]
    fn af2_intent_every_field_change_alters_bytes() {
        let base_o = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), false, Some("c1"));
        let base = build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c1", &base_o);
        // Each variant differs from base in exactly one dimension.
        let variants = vec![
            build_agent_intent_msg_order("cust2", "binance", "sign_binance_order", 1000, "c1", &base_o), // customer
            build_agent_intent_msg_order("cust1", "okx", "sign_binance_order", 1000, "c1", &base_o),     // venue
            build_agent_intent_msg_order("cust1", "binance", "sign_okx_order", 1000, "c1", &base_o),      // action
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1001, "c1", &base_o), // timestamp
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c2", &base_o), // nonce
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c1",
                &af2_order("ETHUSDT", "buy", "0.001", "limit", Some("50000"), false, Some("c1"))),        // symbol
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c1",
                &af2_order("BTCUSDT", "sell", "0.001", "limit", Some("50000"), false, Some("c1"))),       // side
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c1",
                &af2_order("BTCUSDT", "buy", "0.002", "limit", Some("50000"), false, Some("c1"))),        // qty
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c1",
                &af2_order("BTCUSDT", "buy", "0.001", "market", None, false, Some("c1"))),                // ord_type+price
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c1",
                &af2_order("BTCUSDT", "buy", "0.001", "limit", Some("49999"), false, Some("c1"))),        // price
            build_agent_intent_msg_order("cust1", "binance", "sign_binance_order", 1000, "c1",
                &af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), true, Some("c1"))),         // reduce_only
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(&base, v, "variant {i} collided with base — a tamper would be invisible");
        }
        // And no two variants collide with each other (distinct field spaces).
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j], "variants {i}/{j} collided");
            }
        }
    }

    // ─── AF-2: end-to-end intent verification (real Ed25519) ────────────────

    fn af2_keypair(seed: u8) -> (ed25519_dalek::SigningKey, String) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }

    fn af2_sign(sk: &ed25519_dalek::SigningKey, msg: &[u8]) -> String {
        use ed25519_dalek::Signer;
        hex::encode(sk.sign(msg).to_bytes())
    }

    fn af2_policy(intent_pubkey: Option<&str>) -> Policy {
        Policy {
            intent_pubkey: intent_pubkey.map(str::to_owned),
            ..Policy::default()
        }
    }

    fn af2_req(sig: Option<&str>, nonce: Option<&str>) -> SignRequest {
        SignRequest {
            intent_signature: sig.map(str::to_owned),
            intent_nonce: nonce.map(str::to_owned),
            ..req_template()
        }
    }

    #[test]
    fn af2_verify_intent_valid_then_tamper_and_replay() {
        let (sk, pk) = af2_keypair(11);
        // Unique per-test message so the global ledger (sha256-keyed) doesn't
        // collide with other tests.
        let msg = b"af2-verify-test-message-unique-A-2026".to_vec();
        let sig = af2_sign(&sk, &msg);
        // Valid signature + first sight → Ok.
        assert!(verify_agent_intent(&pk, Some(&sig), &msg).is_ok());
        // The SAME intent bytes again (replay) → BAD_REQUEST even with a valid sig.
        assert_eq!(
            verify_agent_intent(&pk, Some(&sig), &msg).err().and_then(|r| r.error.clone()),
            Some(err_code::BAD_REQUEST.to_owned())
        );
        // Tampered message (same sig, distinct bytes → fresh ledger key) → BAD_REQUEST.
        let mut tampered = msg.clone();
        tampered[0] ^= 0xFF;
        assert!(verify_agent_intent(&pk, Some(&sig), &tampered).is_err());
        // Missing signature → BAD_REQUEST.
        assert!(verify_agent_intent(&pk, None, b"af2-verify-nosig-B").is_err());
        // Malformed pubkey → INTERNAL_ERROR (policy/deploy bug, not client).
        assert_eq!(
            verify_agent_intent("zz", Some(&sig), b"af2-verify-badpk-C").err().and_then(|r| r.error.clone()),
            Some(err_code::INTERNAL_ERROR.to_owned())
        );
    }

    #[test]
    fn af2_enforce_order_valid_and_field_tamper_denied() {
        let (sk, pk) = af2_keypair(22);
        let id = crate::registry::ResolvedIdentity::for_data_signing(); // customer_id = "attested-data"
        let cust = &id.customer_id;
        let ts = 1_700_000_000_000u64;
        let coid = "af2-coid-order-1";
        let order = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), false, Some(coid));
        // Agent signs the exact intent the enclave will reconstruct.
        let msg = build_agent_intent_msg_order(cust, "binance", "sign_binance_order", ts, coid, &order);
        let sig = af2_sign(&sk, &msg);
        let pol = af2_policy(Some(&pk));
        // Untampered → Ok.
        assert!(enforce_agent_intent_order(
            Some(&pol), &id, "binance", "sign_binance_order", ts, &order, &af2_req(Some(&sig), None)
        ).is_ok());
        // TAMPER: gateway flips side buy→sell (within qty cap) — same signature,
        // reconstructed msg differs → BAD_REQUEST. (fresh coid to avoid replay.)
        let flipped = af2_order("BTCUSDT", "sell", "0.001", "limit", Some("50000"), false, Some("af2-coid-order-1b"));
        assert_eq!(
            enforce_agent_intent_order(
                Some(&pol), &id, "binance", "sign_binance_order", ts, &flipped, &af2_req(Some(&sig), None)
            ).err().and_then(|r| r.error.clone()),
            Some(err_code::BAD_REQUEST.to_owned())
        );
        // TAMPER: price change → denied.
        let repriced = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("1"), false, Some("af2-coid-order-1c"));
        assert!(enforce_agent_intent_order(
            Some(&pol), &id, "binance", "sign_binance_order", ts, &repriced, &af2_req(Some(&sig), None)
        ).is_err());
        // TAMPER: reduce_only flip → denied.
        let ro = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), true, Some("af2-coid-order-1d"));
        assert!(enforce_agent_intent_order(
            Some(&pol), &id, "binance", "sign_binance_order", ts, &ro, &af2_req(Some(&sig), None)
        ).is_err());
    }

    #[test]
    fn af2_enforce_order_optin_absent_is_ok() {
        // No intent_pubkey → opt-in not enabled → Ok (AF-2-exposed, current behaviour).
        let id = crate::registry::ResolvedIdentity::for_data_signing();
        let order = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), false, Some("x"));
        assert!(enforce_agent_intent_order(
            Some(&af2_policy(None)), &id, "binance", "sign_binance_order", 1, &order, &af2_req(None, None)
        ).is_ok());
        // Also Ok with no policy at all.
        assert!(enforce_agent_intent_order(
            None, &id, "binance", "sign_binance_order", 1, &order, &af2_req(None, None)
        ).is_ok());
    }

    #[test]
    fn af2_enforce_order_missing_coid_or_sig_denied() {
        let (sk, pk) = af2_keypair(33);
        let id = crate::registry::ResolvedIdentity::for_data_signing();
        let pol = af2_policy(Some(&pk));
        // Order with NO client_order_id under intent enforcement → BAD_REQUEST
        // (there is no nonce to bind / dedup).
        let no_coid = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), false, None);
        assert!(enforce_agent_intent_order(
            Some(&pol), &id, "binance", "sign_binance_order", 1, &no_coid, &af2_req(Some("00"), None)
        ).is_err());
        // Order with coid but NO signature → BAD_REQUEST.
        let with_coid = af2_order("BTCUSDT", "buy", "0.001", "limit", Some("50000"), false, Some("af2-coid-nosig"));
        assert!(enforce_agent_intent_order(
            Some(&pol), &id, "binance", "sign_binance_order", 1, &with_coid, &af2_req(None, None)
        ).is_err());
        let _ = sk;
    }

    #[test]
    fn af2_floor_intent_pubkey_requires_order_caps() {
        // rust-auditor HIGH: an intent_pubkey policy with NO order_caps would let
        // the generic HMAC routes (which gate order-placement on order_caps only)
        // bypass AF-2. enforce_policy — run by EVERY handler before signing —
        // refuses such a policy fail-closed, so the bypass cannot be reached.
        let req = req_template();
        let intent_no_caps = Policy {
            intent_pubkey: Some("aa".repeat(32)),
            ..Policy::default()
        };
        assert_eq!(
            enforce_policy(Some(&intent_no_caps), &req).err().and_then(|r| r.error.clone()),
            Some(err_code::POLICY_REQUIRED.to_owned()),
            "intent_pubkey without order_caps must be refused"
        );
        // With order_caps present, the floor passes (other checks may still run).
        let intent_with_caps = Policy {
            intent_pubkey: Some("aa".repeat(32)),
            order_caps: Some(vec![crate::proto::OrderAssetCap {
                symbol: "BTCUSDT".to_owned(),
                max_qty: "1".to_owned(),
                max_notional: None,
            }]),
            ..Policy::default()
        };
        assert!(enforce_policy(Some(&intent_with_caps), &req).is_ok());
        // Defence-in-depth: the generic binance-request route denies op=order for
        // an intent key (independent of the floor).
        assert!(binance_request_order_denied_for_capped("order", Some(&intent_with_caps)));
        assert!(binance_request_order_denied_for_capped(
            "order",
            Some(&Policy { intent_pubkey: Some("aa".repeat(32)), ..Policy::default() })
        ));
        // A non-intent, non-capped policy is unaffected (op=order allowed on generic).
        assert!(!binance_request_order_denied_for_capped("order", Some(&Policy::default())));
    }

    #[test]
    fn af2_enforce_cancel_valid_and_missing_nonce_denied() {
        let (sk, pk) = af2_keypair(44);
        let id = crate::registry::ResolvedIdentity::for_data_signing();
        let cust = &id.customer_id;
        let ts = 1_700_000_000_000u64;
        let nonce = "af2-cancel-uuid-1";
        let cancel = crate::proto::CancelRequest { symbol: "BTCUSDT".to_owned(), order_id: "999".to_owned() };
        let msg = build_agent_intent_msg_cancel(cust, "binance", "sign_binance_cancel", ts, nonce, &cancel);
        let sig = af2_sign(&sk, &msg);
        let pol = af2_policy(Some(&pk));
        // Valid cancel intent → Ok.
        assert!(enforce_agent_intent_cancel(
            Some(&pol), &id, "binance", "sign_binance_cancel", ts, &cancel, &af2_req(Some(&sig), Some(nonce))
        ).is_ok());
        // Missing intent_nonce (no coid to fall back on for cancels) → BAD_REQUEST.
        assert!(enforce_agent_intent_cancel(
            Some(&pol), &id, "binance", "sign_binance_cancel", ts, &cancel, &af2_req(Some(&sig), None)
        ).is_err());
    }

    // ─── B2: per-order notional cap (qty × price ≤ max_notional) ────────────

    /// order_caps entry: BTCUSDT, max_qty 1, max_notional 1000.
    fn notional_policy() -> Policy {
        Policy {
            order_caps: Some(vec![crate::proto::OrderAssetCap {
                symbol: "BTCUSDT".to_owned(),
                max_qty: "1".to_owned(),
                max_notional: Some("1000".to_owned()),
            }]),
            ..Policy::default()
        }
    }
    fn cap_check(p: &Policy, qty: Option<&str>, price: Option<&str>) -> Option<String> {
        enforce_order_cap(Some(p), "BTCUSDT", qty, price)
            .err()
            .and_then(|r| r.error.clone())
    }

    #[test]
    fn b2_notional_limit_under_cap_ok() {
        // 0.01 × 50000 = 500 ≤ 1000; also exactly at the cap (inclusive).
        assert_eq!(cap_check(&notional_policy(), Some("0.01"), Some("50000")), None);
        assert_eq!(cap_check(&notional_policy(), Some("0.02"), Some("50000")), None);
    }

    #[test]
    fn b2_notional_over_cap_denied() {
        // 0.021 × 50000 = 1050 > 1000.
        assert_eq!(
            cap_check(&notional_policy(), Some("0.021"), Some("50000")).as_deref(),
            Some(err_code::NOTIONAL_OVER_CAP)
        );
        // Fractional-scale exactness: 0.02 × 50000.01 = 1000.0002 > 1000.
        assert_eq!(
            cap_check(&notional_policy(), Some("0.02"), Some("50000.01")).as_deref(),
            Some(err_code::NOTIONAL_OVER_CAP)
        );
    }

    #[test]
    fn b2_notional_market_order_denied_fail_closed() {
        // No price (market-shaped) under a notional cap → deny: the enclave
        // has no market data, so the notional is unboundable.
        assert_eq!(
            cap_check(&notional_policy(), Some("0.01"), None).as_deref(),
            Some(err_code::NOTIONAL_OVER_CAP)
        );
    }

    #[test]
    fn b2_no_notional_market_order_unchanged() {
        // max_notional absent → market orders behave exactly as before B2.
        let mut p = notional_policy();
        p.order_caps.as_mut().unwrap()[0].max_notional = None;
        assert_eq!(cap_check(&p, Some("0.01"), None), None);
    }

    #[test]
    fn b2_notional_cancel_unaffected() {
        // qty=None (cancel): no exposure; only the symbol allow-list applies.
        assert_eq!(cap_check(&notional_policy(), None, None), None);
    }

    #[test]
    fn b2_notional_qty_cap_still_enforced_first() {
        // qty over max_qty is denied regardless of a tiny notional.
        assert_eq!(
            cap_check(&notional_policy(), Some("1.5"), Some("1")).as_deref(),
            Some(err_code::SIZE_OVER_CAP)
        );
    }

    #[test]
    fn b2_notional_malformed_price_bad_request() {
        // Client-supplied garbage price → BAD_REQUEST (policy operand valid).
        assert_eq!(
            cap_check(&notional_policy(), Some("0.01"), Some("5e4")).as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn b2_notional_malformed_policy_internal_error() {
        // Malformed POLICY max_notional → server config error, not client blame.
        let mut p = notional_policy();
        p.order_caps.as_mut().unwrap()[0].max_notional = Some("10,00".to_owned());
        assert_eq!(
            cap_check(&p, Some("0.01"), Some("50000")).as_deref(),
            Some(err_code::INTERNAL_ERROR)
        );
    }

    // B2 on the HL path (s × p, limit-only).

    fn hl_notional_policy() -> Policy {
        Policy {
            hl_order_caps: Some(vec![crate::proto::HlOrderCap {
                asset: 0,
                max_size: "1".to_owned(),
                max_notional: Some("1000".to_owned()),
            }]),
            ..Policy::default()
        }
    }
    fn hl_limit_order(a: u64, s: &str, p: &str) -> serde_json::Value {
        serde_json::json!({"type": "order", "orders": [
            {"a": a, "b": true, "s": s, "p": p, "t": {"limit": {"tif": "Gtc"}}}
        ]})
    }

    #[test]
    fn b2_hl_notional_under_cap_ok() {
        let p = hl_notional_policy();
        assert_eq!(hl_check(Some(&p), &hl_limit_order(0, "0.01", "50000"), None), None);
        // inclusive boundary.
        assert_eq!(hl_check(Some(&p), &hl_limit_order(0, "0.02", "50000"), None), None);
    }

    #[test]
    fn b2_hl_notional_over_cap_denied() {
        let p = hl_notional_policy();
        assert_eq!(
            hl_check(Some(&p), &hl_limit_order(0, "0.021", "50000"), None).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn b2_hl_notional_trigger_order_denied() {
        // A trigger order's `p` is not the execution bound (isMarket triggers
        // execute market-side) → denied under a notional cap, fail-closed.
        let p = hl_notional_policy();
        let trigger = serde_json::json!({"type": "order", "orders": [
            {"a": 0, "b": true, "s": "0.01", "p": "50000",
             "t": {"trigger": {"isMarket": true, "triggerPx": "50000", "tpsl": "tp"}}}
        ]});
        assert_eq!(
            hl_check(Some(&p), &trigger, None).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        // The bare `t`-less shape (legacy test helper) is likewise non-limit → denied.
        assert_eq!(
            hl_check(Some(&p), &hl_order(0, "0.01"), None).as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn b2_hl_no_notional_trigger_unchanged() {
        // Without max_notional, trigger orders remain size-capped only (no
        // behavior change for existing policies).
        let p = Policy { hl_order_caps: Some(vec![hl_cap(0, "5")]), ..Policy::default() };
        let trigger = serde_json::json!({"type": "order", "orders": [
            {"a": 0, "b": true, "s": "3", "p": "50000",
             "t": {"trigger": {"isMarket": true, "triggerPx": "50000", "tpsl": "tp"}}}
        ]});
        assert_eq!(hl_check(Some(&p), &trigger, None), None);
    }

    #[test]
    fn b2_hl_notional_missing_price_bad_request() {
        let p = hl_notional_policy();
        let no_p = serde_json::json!({"type": "order", "orders": [
            {"a": 0, "b": true, "s": "0.01", "t": {"limit": {"tif": "Gtc"}}}
        ]});
        assert_eq!(
            hl_check(Some(&p), &no_p, None).as_deref(),
            Some(err_code::BAD_REQUEST)
        );
        // Non-string p (number) is likewise bad_request under an active cap.
        let num_p = serde_json::json!({"type": "order", "orders": [
            {"a": 0, "b": true, "s": "0.01", "p": 50000, "t": {"limit": {"tif": "Gtc"}}}
        ]});
        assert_eq!(
            hl_check(Some(&p), &num_p, None).as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn b2_hl_notional_malformed_policy_internal_error() {
        let mut p = hl_notional_policy();
        p.hl_order_caps.as_mut().unwrap()[0].max_notional = Some("1_000".to_owned());
        assert_eq!(
            hl_check(Some(&p), &hl_limit_order(0, "0.01", "50000"), None).as_deref(),
            Some(err_code::INTERNAL_ERROR)
        );
    }

    // B2 on the asterdex opaque-body path (LIMIT-only + price=).

    fn aster_notional_policy() -> Policy {
        Policy {
            order_caps: Some(vec![crate::proto::OrderAssetCap {
                symbol: "ASTERUSDT".to_owned(),
                max_qty: "5".to_owned(),
                max_notional: Some("10".to_owned()),
            }]),
            ..Policy::default()
        }
    }

    #[test]
    fn b2_asterdex_limit_under_cap_ok() {
        // 4 × 2 = 8 ≤ 10.
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&side=BUY&type=LIMIT&quantity=4&price=2&signer=0xa&nonce=1700000000000",
            ),
            None
        );
    }

    #[test]
    fn b2_asterdex_over_notional_denied() {
        // 5 × 2.1 = 10.5 > 10 (qty itself is within max_qty).
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&side=BUY&type=LIMIT&quantity=5&price=2.1&signer=0xa&nonce=1700000000000",
            )
            .as_deref(),
            Some(err_code::NOTIONAL_OVER_CAP)
        );
    }

    #[test]
    fn b2_asterdex_market_denied_decorative_price_ignored() {
        // A MARKET order with a decorative low price= must NOT pass: only
        // type=LIMIT is accepted under a notional cap on this opaque-body path.
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&side=BUY&type=MARKET&quantity=4&price=0.01&signer=0xa&nonce=1700000000000",
            )
            .as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        // Absent type= is likewise denied (can't prove limit semantics).
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&side=BUY&quantity=4&price=2&signer=0xa&nonce=1700000000000",
            )
            .as_deref(),
            Some(err_code::POLICY_DENIED)
        );
        // STOP_MARKET (stopPrice, no limit semantics) is denied too.
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&side=BUY&type=STOP_MARKET&quantity=4&stopPrice=2&signer=0xa&nonce=1700000000000",
            )
            .as_deref(),
            Some(err_code::POLICY_DENIED)
        );
    }

    #[test]
    fn b2_asterdex_limit_without_price_denied() {
        // type=LIMIT but no price= → enforce_order_cap sees price=None under an
        // active notional cap → policy_denied (venue-invalid order anyway).
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&side=BUY&type=LIMIT&quantity=4&signer=0xa&nonce=1700000000000",
            )
            .as_deref(),
            Some(err_code::NOTIONAL_OVER_CAP)
        );
    }

    #[test]
    fn b2_asterdex_duplicate_type_or_price_bad_request() {
        // Param pollution on the fields the notional gate reads → bad_request.
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&type=LIMIT&type=MARKET&quantity=4&price=2&signer=0xa",
            )
            .as_deref(),
            Some(err_code::BAD_REQUEST)
        );
        assert_eq!(
            aster_check(
                Some(&aster_notional_policy()),
                "symbol=ASTERUSDT&type=LIMIT&quantity=4&price=2&price=99&signer=0xa",
            )
            .as_deref(),
            Some(err_code::BAD_REQUEST)
        );
    }

    #[test]
    fn b2_asterdex_no_notional_market_unchanged() {
        // Entries WITHOUT max_notional keep the pre-B2 behavior: market orders
        // pass on qty alone (no type=/price= requirements).
        assert_eq!(
            aster_check(
                Some(&aster_policy()),
                "symbol=ASTERUSDT&side=BUY&type=MARKET&quantity=3&signer=0xa&nonce=1700000000000",
            ),
            None
        );
    }

    #[test]
    fn b2_policy_with_notional_roundtrips_and_changes_hash() {
        // (1) A policy JSON carrying max_notional parses (deny_unknown_fields
        // stays satisfied) and survives re-serialization.
        let p: Policy = serde_json::from_str(
            r#"{"order_caps":[{"symbol":"BTCUSDT","max_qty":"1","max_notional":"1000"}]}"#,
        )
        .expect("max_notional must parse");
        assert_eq!(
            p.order_caps.as_ref().unwrap()[0].max_notional.as_deref(),
            Some("1000")
        );
        let back = serde_json::to_value(&p).unwrap();
        assert_eq!(back["order_caps"][0]["max_notional"], "1000");
        // (2) Absent max_notional serializes to byte-identical canonical bytes
        // as a pre-B2 policy (skip_serializing_if) → existing policy hashes,
        // TOFU and authority signatures stay valid.
        let pre_b2: Policy = serde_json::from_str(
            r#"{"order_caps":[{"symbol":"BTCUSDT","max_qty":"1"}]}"#,
        )
        .unwrap();
        let bytes = canonical_policy_signable(&pre_b2).unwrap();
        assert!(!String::from_utf8(bytes.clone()).unwrap().contains("max_notional"));
        // (3) Adding max_notional CHANGES the canonical bytes → a policy that
        // gains a notional cap requires an authority re-sign (no silent reuse).
        assert_ne!(bytes, canonical_policy_signable(&p).unwrap());
    }

    // ─── CR051: generic-path safe-op allow-list for capped keys ─────────────
    // Signature: generic_capped_op_allowed(venue, method, path, query, body).

    #[test]
    fn binance_request_golden_vectors() {
        // Cross-language pin against the backtester reference
        // (`_spikes/hummingbot-signer/PATCH-READY/golden_vectors.json`): the Rust
        // enclave allow-list + HMAC MUST be byte-identical to the Python mock the
        // keyless Hummingbot patch was proven against. `hash = hmac-sha256(secret,
        // payload) hex`.
        let secret = Zeroizing::new(b"TEST_SECRET_NOT_A_REAL_KEY_0000".to_vec());

        // (op, exact payload, expected hmac-sha256 hex)
        let allow: &[(&str, &str, &str)] = &[
            ("account", "timestamp=1783003070821", "856ae26b36aa2a14ab7766692f8e67c5f49665d94e3c73eea2f813522aeac997"),
            ("positionRisk", "symbol=BTCUSDT&timestamp=1783003070821", "7cb85ce01d30e5412b66de0b005d37549138d3081527402f2f8d1a0f66e97ac9"),
            ("openOrders", "symbol=BTCUSDT&timestamp=1783003070821", "7cb85ce01d30e5412b66de0b005d37549138d3081527402f2f8d1a0f66e97ac9"),
            ("orderStatus", "symbol=BTCUSDT&orderId=1&timestamp=1783003070821", "6f8ff637d5680850705591a07e17ffcd6a9647b83f921e6b7192de7ddac89212"),
            ("userTrades", "symbol=BTCUSDT&timestamp=1783003070821", "7cb85ce01d30e5412b66de0b005d37549138d3081527402f2f8d1a0f66e97ac9"),
            ("income", "timestamp=1783003070821", "856ae26b36aa2a14ab7766692f8e67c5f49665d94e3c73eea2f813522aeac997"),
            ("leverage", "symbol=BTCUSDT&leverage=5&timestamp=1783003070821", "77d95270957dd79de1cc1fd35b8172e81962ecd924dedcd89b5a40b56bc965f2"),
            ("positionMode", "timestamp=1783003070821", "856ae26b36aa2a14ab7766692f8e67c5f49665d94e3c73eea2f813522aeac997"),
            ("listenKey", "timestamp=1783003070821", "856ae26b36aa2a14ab7766692f8e67c5f49665d94e3c73eea2f813522aeac997"),
            ("order", "symbol=BTCUSDT&side=BUY&type=LIMIT&timeInForce=GTC&quantity=0.002&price=49345&timestamp=1783003070821", "398ba1c8f2a66153206f791d7421e42b4ea034403ba50ebb20ac52eedc2f1dc0"),
            ("cancel", "symbol=BTCUSDT&orderId=1&timestamp=1783003070821", "6f8ff637d5680850705591a07e17ffcd6a9647b83f921e6b7192de7ddac89212"),
            ("allOpenOrders", "symbol=BTCUSDT&timestamp=1783003070821", "7cb85ce01d30e5412b66de0b005d37549138d3081527402f2f8d1a0f66e97ac9"),
        ];
        for (op, payload, sig) in allow {
            assert!(
                check_binance_request_allow(op, payload).is_ok(),
                "op {op} / {payload} must be allowed"
            );
            let got = crate::signer::sign_binance(&secret, payload, "").expect("hmac");
            assert_eq!(&got.as_str(), sig, "signature mismatch for op {op}");
        }

        // (op, payload, expected error prefix) — never signs on the deny path.
        let deny: &[(&str, &str, &str)] = &[
            ("account", "coin=USDT&address=0xattacker&amount=1000&timestamp=1783003070821", "param_not_allowed"),
            ("order", "asset=USDT&amount=1000&type=1&timestamp=1783003070821", "param_not_allowed"),
            ("withdraw", "timestamp=1783003070821", "op_not_allowed"),
        ];
        for (op, payload, prefix) in deny {
            let err = check_binance_request_allow(op, payload)
                .expect_err(&format!("op {op} / {payload} must be denied"));
            assert!(err.starts_with(prefix), "op {op}: want {prefix}, got {err}");
        }
    }

    #[test]
    fn binance_request_withdraw_smuggle_is_denied() {
        // MANDATORY merge-gate: a withdrawal payload smuggled under an allowed op
        // is refused BEFORE any signing — the params aren't in the op's schema.
        let e = check_binance_request_allow(
            "account",
            "coin=USDT&address=0xattacker&amount=1000&timestamp=1",
        )
        .expect_err("withdraw smuggle must be denied");
        assert_eq!(e, "param_not_allowed:account:coin");
        // op-level: a withdraw op is not in the table at all.
        assert_eq!(
            check_binance_request_allow("withdraw", "timestamp=1").unwrap_err(),
            "op_not_allowed:withdraw"
        );
    }

    #[test]
    fn binance_request_op_tables_consistent() {
        // Every op that passes the param allow-list MUST have a canonical route,
        // else the handler would fail closed on a phantom op. Keep the two tables
        // in lock-step.
        for op in [
            "account", "positionRisk", "openOrders", "orderStatus", "userTrades",
            "income", "listenKey", "order", "cancel", "allOpenOrders", "leverage",
            "positionMode",
        ] {
            assert!(binance_request_allowed_params(op).is_some(), "{op} params");
            assert!(binance_request_method_path(op).is_some(), "{op} route");
        }
        assert!(binance_request_allowed_params("withdraw").is_none());
        assert!(binance_request_method_path("withdraw").is_none());
    }

    #[test]
    fn binance_request_op_method_matches_true_binance_method() {
        // Locks the bug class (Gemini #218 HIGH: positionMode mapped GET while it
        // SETS the mode → a write-deny method-policy would be bypassed). Each op's
        // derived (method, path) MUST equal the TRUE Binance route — a WRITE op
        // (POST/DELETE) must never be labelled a read (GET), or the enclave-side
        // enforce_policy method check protects nothing.
        let truth: &[(&str, &str, &str)] = &[
            ("account", "GET", "/fapi/v2/account"),
            ("positionRisk", "GET", "/fapi/v2/positionRisk"),
            ("openOrders", "GET", "/fapi/v1/openOrders"),
            ("orderStatus", "GET", "/fapi/v1/order"),
            ("userTrades", "GET", "/fapi/v1/userTrades"),
            ("income", "GET", "/fapi/v1/income"),
            ("listenKey", "POST", "/fapi/v1/listenKey"),
            ("leverage", "POST", "/fapi/v1/leverage"),
            ("order", "POST", "/fapi/v1/order"),
            ("positionMode", "POST", "/fapi/v1/positionSide/dual"),
            ("cancel", "DELETE", "/fapi/v1/order"),
            ("allOpenOrders", "DELETE", "/fapi/v1/allOpenOrders"),
        ];
        for (op, method, path) in truth {
            assert_eq!(
                binance_request_method_path(op),
                Some((*method, *path)),
                "op {op}: method/path must equal the true Binance route"
            );
        }
    }

    #[test]
    fn binance_request_enforces_policy_not_just_op_allowlist() {
        // CRITICAL (Gemini): /sign/binance-request must honour the attested per-blob
        // policy, not only the op allow-list. Exercise `enforce_policy` on the exact
        // `(action, derived method/path)` the handler builds for op="order".
        let (m, p) = binance_request_method_path("order").unwrap();
        let req = policy_test_req("sign_binance_request", m, p);

        // (a) denied ACTION: a policy that does not list sign_binance_request rejects.
        let deny_action = Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            ..Policy::default()
        };
        assert!(
            enforce_policy(Some(&deny_action), &req).is_err(),
            "denied action must reject via the generic endpoint"
        );

        // (b) denied PATH: the derived /fapi/v1/order route is denied.
        let deny_path = Policy {
            denied_path_prefixes: Some(vec!["/fapi/v1/order".to_owned()]),
            ..Policy::default()
        };
        assert!(
            enforce_policy(Some(&deny_path), &req).is_err(),
            "denied path must reject via the generic endpoint"
        );

        // (c) control: a policy allowing the action + route passes.
        let allow = Policy {
            allowed_actions: Some(vec!["sign_binance_request".to_owned()]),
            allowed_path_prefixes: Some(vec!["/fapi/".to_owned()]),
            ..Policy::default()
        };
        assert!(
            enforce_policy(Some(&allow), &req).is_ok(),
            "a policy allowing the action + route must pass"
        );
    }

    #[test]
    fn cr051_binance_safe_reads_and_cancel_allowed() {
        assert!(generic_capped_op_allowed("binance", "GET", "/fapi/v2/account", "", ""));
        assert!(generic_capped_op_allowed("binance", "GET", "/fapi/v1/openOrders", "", ""));
        assert!(generic_capped_op_allowed("binance", "GET", "/fapi/v1/openOrders", "symbol=BTCUSDT", ""));
        assert!(generic_capped_op_allowed("binance", "DELETE", "/fapi/v1/allOpenOrders", "symbol=BTCUSDT", ""));
    }

    #[test]
    fn cr051_binance_order_placement_denied() {
        assert!(!generic_capped_op_allowed(
            "binance",
            "POST",
            "/fapi/v1/order",
            "symbol=BTCUSDT&side=BUY&type=MARKET&quantity=1000",
            ""
        ));
        assert!(!generic_capped_op_allowed("binance", "POST", "/fapi/v1/batchOrders", "", ""));
    }

    #[test]
    fn cr051_binance_account_with_smuggled_order_query_is_denied() {
        // THE ORACLE ATTACK (query vector): GET account but order params in the
        // query — a Binance HMAC sig over this is replayable to the order
        // endpoint. Denied via separate query…
        assert!(!generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v2/account",
            "symbol=BTCUSDT&side=BUY&type=MARKET&quantity=1000",
            ""
        ));
        // …and via a query embedded in the path.
        assert!(!generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v2/account?symbol=BTC&side=BUY&quantity=1000",
            "",
            ""
        ));
    }

    #[test]
    fn cr051_binance_account_with_smuggled_order_body_is_denied() {
        // THE ORACLE ATTACK (body vector): GET account, empty query, but an
        // order-shaped BODY. Binance HMAC signs query+BODY, so the enclave would
        // otherwise produce a sig over "timestamp&recvWindow"+body that is a
        // valid order query replayable to /fapi/v1/order. Body must be empty.
        assert!(!generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v2/account",
            "",
            "&symbol=BTCUSDT&side=BUY&type=MARKET&quantity=1000"
        ));
        // Same for open-orders + cancel-all with a body.
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/openOrders", "symbol=BTCUSDT", "x"));
        assert!(!generic_capped_op_allowed("binance", "DELETE", "/fapi/v1/allOpenOrders", "symbol=BTCUSDT", "x"));
    }

    #[test]
    fn cr051_binance_filter_edge_cases() {
        assert!(!generic_capped_op_allowed("binance", "DELETE", "/fapi/v1/allOpenOrders", "", "")); // symbol required
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/openOrders", "symbol=BTC&quantity=1000", "")); // extra param
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/openOrders", "symbol=", "")); // empty value
    }

    #[test]
    fn params_subset_of_empty_query_only_when_nothing_required() {
        // Gemini: empty query allowed iff nothing required (robust for reuse).
        assert!(params_subset_of("", &["a", "b"], &[]));
        assert!(!params_subset_of("", &["a"], &["a"]));
        assert!(params_subset_of("a=1", &["a", "b"], &[]));
    }

    #[test]
    fn gate2_binance_user_trades_allowed_and_guarded() {
        // symbol REQUIRED, plus read-only filters / pagination.
        assert!(generic_capped_op_allowed("binance", "GET", "/fapi/v1/userTrades", "symbol=BTCUSDT", ""));
        assert!(generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v1/userTrades",
            "symbol=BTCUSDT&startTime=1719331200000&endTime=1719417600000&limit=500",
            ""
        ));
        assert!(generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v1/userTrades",
            "symbol=BTCUSDT&orderId=12345&fromId=67890&limit=1000",
            ""
        ));
        // symbol is REQUIRED — absent (empty or only other filters) is denied.
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/userTrades", "", ""));
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/userTrades", "limit=500", ""));
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/userTrades", "symbol=", ""));
        // Unknown / order params rejected (no smuggle past the read gate).
        assert!(!generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v1/userTrades",
            "symbol=BTCUSDT&side=BUY&quantity=1000",
            ""
        ));
        // Duplicate key (param pollution) rejected.
        assert!(!generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v1/userTrades",
            "symbol=BTCUSDT&symbol=ETHUSDT",
            ""
        ));
        // Non-token value (path / encoding tricks) rejected.
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/userTrades", "symbol=BTC/USDT", ""));
        // Body must be empty (Binance HMAC signs query+body → body-smuggle guard).
        assert!(!generic_capped_op_allowed("binance", "GET", "/fapi/v1/userTrades", "symbol=BTCUSDT", "x"));
        // Double-query (path-embedded ? AND a separate query) rejected.
        assert!(!generic_capped_op_allowed(
            "binance",
            "GET",
            "/fapi/v1/userTrades?symbol=BTC",
            "limit=500",
            ""
        ));
    }

    #[test]
    fn gate2_okx_fills_history_allowed_and_guarded() {
        // instType REQUIRED (OKX); plus read-only filters / pagination. OKX embeds
        // the query in the path (?instType=…), so exercise that shape.
        assert!(generic_capped_op_allowed("okx", "GET", "/api/v5/trade/fills-history?instType=SWAP", "", ""));
        assert!(generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/fills-history?instType=SWAP&instId=BTC-USDT-SWAP&limit=100",
            "",
            ""
        ));
        assert!(generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/fills-history?instType=SWAP&before=123&after=456&begin=1&end=2&ordId=789",
            "",
            ""
        ));
        // instType REQUIRED — absent / empty is denied.
        assert!(!generic_capped_op_allowed("okx", "GET", "/api/v5/trade/fills-history", "", ""));
        assert!(!generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/fills-history?instId=BTC-USDT-SWAP",
            "",
            ""
        ));
        // Unknown / order params rejected.
        assert!(!generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/fills-history?instType=SWAP&sz=999&side=buy",
            "",
            ""
        ));
        // Duplicate key rejected.
        assert!(!generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/fills-history?instType=SWAP&instType=SPOT",
            "",
            ""
        ));
        // Body must be empty.
        assert!(!generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/fills-history?instType=SWAP",
            "",
            "{\"x\":1}"
        ));
        // Double-source query (path ? AND separate query) rejected.
        assert!(!generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/fills-history?instType=SWAP",
            "limit=100",
            ""
        ));
    }

    #[test]
    fn cr051_okx_safe_reads_allowed_incl_embedded_query() {
        assert!(generic_capped_op_allowed("okx", "GET", "/api/v5/account/balance", "", ""));
        assert!(generic_capped_op_allowed("okx", "GET", "/api/v5/account/positions", "", ""));
        assert!(generic_capped_op_allowed("okx", "GET", "/api/v5/trade/orders-pending", "", ""));
        // OKX merges the filter into the path (?instId=…):
        assert!(generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/orders-pending?instId=BTC-USDT-SWAP",
            "",
            ""
        ));
    }

    #[test]
    fn cr051_okx_order_and_smuggle_denied() {
        assert!(!generic_capped_op_allowed("okx", "POST", "/api/v5/trade/order", "", ""));
        assert!(!generic_capped_op_allowed("okx", "POST", "/api/v5/trade/batch-orders", "", ""));
        // balance path but smuggled order params embedded → denied
        assert!(!generic_capped_op_allowed("okx", "GET", "/api/v5/account/balance?instId=X&sz=999", "", ""));
        // safe okx read but with a body → denied (okx prehash includes body)
        assert!(!generic_capped_op_allowed("okx", "GET", "/api/v5/account/balance", "", "{\"sz\":\"999\"}"));
    }

    #[test]
    fn cr051_okx_double_source_query_denied() {
        // CR051-OKX-QUERY-SMUGGLE (review BLOCKER): a query in BOTH the
        // path-embedded `?...` AND the separate field must be rejected — the
        // signer merges both, so the gate must not validate only one source.
        assert!(!generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/orders-pending?instId=BTC-USDT-SWAP",
            "sz=999&side=buy",
            ""
        ));
        // The merged form (how handle_sign_okx now calls the gate): smuggled
        // order params inside the single embedded query fail single_filter.
        assert!(!generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/orders-pending?instId=BTC-USDT-SWAP&sz=999&side=buy",
            "",
            ""
        ));
        // The legit merged form (filter only, empty separate query) still passes.
        assert!(generic_capped_op_allowed(
            "okx",
            "GET",
            "/api/v5/trade/orders-pending?instId=BTC-USDT-SWAP",
            "",
            ""
        ));
    }

    #[test]
    fn cr051_binance_non_fapi_write_denied() {
        // A capped binance key must not reach a Spot /sapi withdraw via the
        // generic path — not in the /fapi allow-list → denied.
        assert!(!generic_capped_op_allowed(
            "binance",
            "POST",
            "/sapi/v1/capital/withdraw/apply",
            "",
            ""
        ));
        assert!(!generic_capped_op_allowed(
            "binance",
            "GET",
            "/sapi/v1/capital/config/getall",
            "",
            ""
        ));
    }

    #[test]
    fn cr051_bybit_kucoin_unknown_have_no_safe_generic_ops() {
        assert!(!generic_capped_op_allowed("bybit", "GET", "/v5/account/wallet-balance", "", ""));
        assert!(!generic_capped_op_allowed("kucoin", "GET", "/api/v1/accounts", "", ""));
        assert!(!generic_capped_op_allowed("unknown", "GET", "/anything", "", ""));
    }

    #[test]
    fn sign_missing_method_returns_bad_request() {
        let req = SignRequest {
            method: None,
            ..req_template()
        };
        let resp = handle_seeded(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_with_disallowed_method_returns_bad_request() {
        let req = SignRequest {
            method: Some("PATCH".to_owned()), // not in allow-list
            ..req_template()
        };
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
            proto_version: REQUIRED_PROTO_VERSION,
            opaque_token: Some(seed_test_tenant().to_owned()),
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
            registry_refresh: None,
            query: None,
            op: None,
            payload: None,
            hl_action: None,
            nonce: None,
            vault_address: None,
            x402: None,
            order: None,
            cancel: None,
            data: None,
            intent_signature: None,
            intent_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
        }
    }

    #[test]
    fn sign_asterdex_missing_method_returns_bad_request() {
        let req = SignRequest {
            method: None,
            ..asterdex_req_template()
        };
        let resp = handle_seeded(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_asterdex_disallowed_method_returns_bad_request() {
        let req = SignRequest {
            method: Some("PATCH".to_owned()),
            ..asterdex_req_template()
        };
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_asterdex_missing_credentials_returns_bad_request() {
        let req = SignRequest {
            ciphertext_blob_base64: Some(B64.encode(b"some-bytes")),
            aws_credentials: None,
            ..asterdex_req_template()
        };
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
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
            proto_version: REQUIRED_PROTO_VERSION,
            opaque_token: Some(seed_test_tenant().to_owned()),
            method: None,
            path: None,
            body: None,
            timestamp_ms: None,
            key_blob_s3_key: Some("secrets/test-hyperliquid_main.enc".to_owned()),
            key_id: Some("alias/signer-poc".to_owned()),
            aws_credentials: None,
            ciphertext_blob_base64: None,
            registry_refresh: None,
            query: None,
            op: None,
            payload: None,
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
            x402: None,
            order: None,
            cancel: None,
            data: None,
            intent_signature: None,
            intent_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
        }
    }

    #[test]
    fn sign_data_dispatch_requires_data_payload() {
        // The `sign_data` action routes to handle_sign_data, which rejects a
        // missing `data` payload with bad_request BEFORE any blob load. The full
        // sign-success path is proven by signer::sign_attested_data_ecrecover_
        // roundtrip + the demo verify (a live data-key blob is provisioned
        // separately, CTO decision c).
        let req = SignRequest {
            action: "sign_data".to_owned(),
            data: None,
            ..hl_req_template("sign_data")
        };
        assert_eq!(handle_seeded(req).error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_hyperliquid_main_order_missing_action_returns_bad_request() {
        let req = SignRequest {
            hl_action: None,
            ..hl_req_template("sign_hyperliquid_main_order")
        };
        let resp = handle_seeded(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
        assert!(resp.hl_signature.is_none());
        assert_eq!(resp.signature_base64, "");
    }

    #[test]
    fn sign_hyperliquid_main_order_hard_denied() {
        // deny-HL-main: a well-formed HL MAINNET order is HARD-DENIED before any
        // secret load — never signed (source="a" = real Arbitrum funds). This is
        // also the chokepoint for the generic /sign and /hedge paths.
        // (Replaces the former missing-nonce / missing-creds / bad-vault tests:
        // those exercised loader-stage validation the deny now short-circuits.)
        let resp = handle_seeded(hl_req_template("sign_hyperliquid_main_order"));
        assert_eq!(resp.error.as_deref(), Some(err_code::POLICY_DENIED));
        assert!(resp.hl_signature.is_none());
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
        let resp = handle_seeded(req);
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
        let resp = handle_seeded(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_hyperliquid_main_cancel_hard_denied() {
        // deny-HL-main: a well-formed HL MAINNET cancel is HARD-DENIED.
        let req = SignRequest {
            hl_action: Some(serde_json::json!({
                "type": "cancel",
                "cancels": [{"a": 0, "o": 1}]
            })),
            ..hl_req_template("sign_hyperliquid_main_cancel")
        };
        let resp = handle_seeded(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::POLICY_DENIED));
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
        let resp = handle_seeded(req);
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
            proto_version: 0,
            opaque_token: None,
            method: Some(method.to_owned()),
            path: Some(path.to_owned()),
            body: Some(String::new()),
            timestamp_ms: Some(1714997000000),
            key_blob_s3_key: None,
            key_id: None,
            aws_credentials: None,
            ciphertext_blob_base64: None,
            registry_refresh: None,
            query: None,
            op: None,
            payload: None,
            hl_action: None,
            nonce: None,
            vault_address: None,
            x402: None,
            order: None,
            cancel: None,
            data: None,
            intent_signature: None,
            intent_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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
        assert_eq!(err.error.as_deref(), Some(err_code::WITHDRAWAL_NOT_SIGNABLE));
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
    }

    /// HIGH (Gemini round-4): empty prefix in allowed_path_prefixes
    /// must NOT silently bypass the allowlist. `path.starts_with("")`
    /// is unconditionally true; without the empty-prefix guard a policy
    /// of `allowed_path_prefixes: [""]` (typo, copy-paste error, or
    /// attacker-crafted blob that survives KMS) would permit every path.
    #[test]
    fn enforce_policy_empty_prefix_does_not_bypass_allowlist() {
        let p = Policy {
            allowed_path_prefixes: Some(vec!["".to_owned()]),
            ..Policy::default()
        };
        // With only an empty prefix, NOTHING should match.
        for path in &["/", "/fapi/v1/order", "/anything", "/sapi/v1/capital/withdraw"] {
            let req = policy_test_req("sign_binance", "POST", path);
            let err = enforce_policy(Some(&p), &req).unwrap_err();
            assert_eq!(
                err.error.as_deref(),
                Some(err_code::ACTION_NOT_ALLOWED),
                "empty prefix must deny {}",
                path
            );
        }
    }

    /// HIGH (Gemini round-4): mixed list with empty + valid entry —
    /// the valid one must still match (empty is ignored, not poisonous).
    #[test]
    fn enforce_policy_empty_prefix_ignored_in_mixed_list() {
        let p = Policy {
            allowed_path_prefixes: Some(vec!["".to_owned(), "/fapi".to_owned()]),
            ..Policy::default()
        };
        // `/fapi/v1/order` matches the second entry → ok.
        assert!(enforce_policy(
            Some(&p),
            &policy_test_req("sign_binance", "POST", "/fapi/v1/order")
        )
        .is_ok());
        // `/sapi/v1/withdraw` matches neither (empty doesn't bypass) → denied.
        let req = policy_test_req("sign_binance", "POST", "/sapi/v1/withdraw");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        // Denied by the ALLOW-list miss (not the deny-list) → action class.
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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
        assert_eq!(err.error.as_deref(), Some(err_code::ACTION_NOT_ALLOWED));
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

    // ─── C27 (ZLODEY 2026-05-18): max_requests_per_minute fail-loud ──────

    #[test]
    fn enforce_policy_rejects_max_requests_per_minute() {
        let p = Policy {
            max_requests_per_minute: Some(60),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let err = enforce_policy(Some(&p), &req).unwrap_err();
        assert_eq!(
            err.error.as_deref(),
            Some(err_code::UNIMPLEMENTED_POLICY_FIELD)
        );
    }

    #[test]
    fn enforce_policy_permits_absent_max_requests_per_minute() {
        let p = Policy {
            max_requests_per_minute: None,
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        assert!(enforce_policy(Some(&p), &req).is_ok());
    }

    // ─── C24 (ZLODEY 2026-05-18): policy hash in response ────────────────

    #[test]
    fn enforce_policy_returns_hash_for_policy() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            label: Some("test-label".to_owned()),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let hash = enforce_policy(Some(&p), &req).unwrap();
        assert!(hash.is_some());
        let h = hash.unwrap();
        assert_eq!(h.len(), 64); // SHA-256 hex = 64 chars
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn enforce_policy_returns_none_hash_for_legacy() {
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let hash = enforce_policy(None, &req).unwrap();
        assert!(hash.is_none());
    }

    #[test]
    fn enforce_policy_hash_is_deterministic() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            ..Policy::default()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let h1 = enforce_policy(Some(&p), &req).unwrap();
        let h2 = enforce_policy(Some(&p), &req).unwrap();
        assert_eq!(h1, h2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // PR-D1: baked policy-authority floor-gate (`verify_policy_authority`).
    // These exercise the crypto + every fail-closed branch directly. The gate
    // CONDITION in `load_and_parse_blob` (`policy_required() && is_money_venue`)
    // is two lines of glue over these primitives.
    // ──────────────────────────────────────────────────────────────────────

    fn authority_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }
    fn authority_pubkey_hex(sk: &ed25519_dalek::SigningKey) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }
    fn sign_authority(
        policy: &Policy,
        cust: &str,
        venue: &str,
        sk: &ed25519_dalek::SigningKey,
    ) -> String {
        use ed25519_dalek::Signer;
        let canonical = canonical_policy_signable(policy).unwrap();
        let msg = policy_authority_message(cust, venue, &canonical);
        hex::encode(sk.sign(&msg).to_bytes())
    }
    /// A realistic money-venue floor: withdrawal-deny + a per-order qty cap.
    fn floor_policy() -> Policy {
        Policy {
            allowed_actions: Some(vec![
                "sign_binance".to_owned(),
                "sign_binance_order".to_owned(),
                "sign_binance_cancel".to_owned(),
            ]),
            denied_path_prefixes: Some(vec![
                "/sapi/v1/capital/withdraw".to_owned(),
                "/fapi/v1/withdraw".to_owned(),
            ]),
            order_caps: Some(vec![crate::proto::OrderAssetCap {
                symbol: "BTCUSDT".to_owned(),
                max_qty: "0.01".to_owned(),
                max_notional: None,
            }]),
            ..Policy::default()
        }
    }

    #[test]
    fn policy_authority_our_signed_template_accepts() {
        let sk = authority_key(7);
        let mut p = floor_policy();
        p.policy_authority_sig = Some(sign_authority(&p, "cust-1", "binance", &sk));
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, &authority_pubkey_hex(&sk));
        assert!(verify_policy_authority(&p, "cust-1", "binance").is_ok());
    }

    #[test]
    fn policy_authority_partner_key_rejected() {
        // The whole point: a partner who controls the ciphertext can produce a
        // perfectly valid Ed25519 signature with THEIR key — it must still fail
        // against our BAKED pubkey, so they cannot self-authorize a floorless
        // policy on first use (the TOFU-first-use hole this PR closes).
        let ours = authority_key(7);
        let partner = authority_key(9);
        let mut p = floor_policy();
        p.policy_authority_sig = Some(sign_authority(&p, "cust-1", "binance", &partner));
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, &authority_pubkey_hex(&ours));
        assert!(matches!(
            verify_policy_authority(&p, "cust-1", "binance"),
            Err(LoadSecretError::BadRequest)
        ));
    }

    #[test]
    fn policy_authority_unsigned_is_policy_required() {
        let sk = authority_key(7);
        let p = floor_policy(); // no policy_authority_sig set
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, &authority_pubkey_hex(&sk));
        assert!(matches!(
            verify_policy_authority(&p, "cust-1", "binance"),
            Err(LoadSecretError::PolicyRequired)
        ));
    }

    #[test]
    fn policy_authority_env_absent_is_policy_required() {
        // Fail-closed: strict-regime money-venue but no baked authority root.
        let sk = authority_key(7);
        let mut p = floor_policy();
        p.policy_authority_sig = Some(sign_authority(&p, "cust-1", "binance", &sk));
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, ""); // empty ⇒ treated as absent
        assert!(matches!(
            verify_policy_authority(&p, "cust-1", "binance"),
            Err(LoadSecretError::PolicyRequired)
        ));
    }

    #[test]
    fn policy_authority_tenant_context_bound() {
        // A template signed for one {customer,venue} cannot be replayed under
        // another tenant's blob (length-prefixed context in the signed message).
        let sk = authority_key(7);
        let mut p = floor_policy();
        p.policy_authority_sig = Some(sign_authority(&p, "cust-A", "binance", &sk));
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, &authority_pubkey_hex(&sk));
        assert!(verify_policy_authority(&p, "cust-A", "binance").is_ok());
        assert!(verify_policy_authority(&p, "cust-B", "binance").is_err());
        assert!(verify_policy_authority(&p, "cust-A", "okx").is_err());
    }

    #[test]
    fn policy_authority_tampered_policy_rejected() {
        // Strip the withdrawal-deny AFTER signing — signature must no longer verify.
        let sk = authority_key(7);
        let mut p = floor_policy();
        p.policy_authority_sig = Some(sign_authority(&p, "cust-1", "binance", &sk));
        p.denied_path_prefixes = None;
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, &authority_pubkey_hex(&sk));
        assert!(verify_policy_authority(&p, "cust-1", "binance").is_err());
    }

    #[test]
    fn policy_authority_malformed_sig_bad_request() {
        let sk = authority_key(7);
        let mut p = floor_policy();
        p.policy_authority_sig = Some("zz".to_owned()); // not 128 hex chars
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, &authority_pubkey_hex(&sk));
        assert!(matches!(
            verify_policy_authority(&p, "cust-1", "binance"),
            Err(LoadSecretError::BadRequest)
        ));
    }

    #[test]
    fn policy_authority_malformed_baked_pubkey_is_internal() {
        // A malformed BAKED pubkey is OUR deploy error, not the caller's — must
        // map to internal_error (fail-closed), never bad_request (Gemini #216).
        let sk = authority_key(7);
        let mut p = floor_policy();
        p.policy_authority_sig = Some(sign_authority(&p, "cust-1", "binance", &sk));
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, "not-valid-hex-zz");
        assert!(matches!(
            verify_policy_authority(&p, "cust-1", "binance"),
            Err(LoadSecretError::Internal)
        ));
    }

    #[test]
    fn policy_authority_domain_separation_rejects_raw_sig() {
        // A signature over the RAW canonical policy (registry/TOFU style — no
        // domain tag, no tenant framing) must NOT pass as a policy-authority
        // signature. This is what makes the two signature kinds non-interchangeable.
        use ed25519_dalek::Signer;
        let sk = authority_key(7);
        let mut p = floor_policy();
        let canonical = canonical_policy_signable(&p).unwrap();
        p.policy_authority_sig = Some(hex::encode(sk.sign(&canonical).to_bytes()));
        let _g = EnvVarGuard::set(POLICY_PUBKEY_ENV, &authority_pubkey_hex(&sk));
        assert!(verify_policy_authority(&p, "cust-1", "binance").is_err());
    }

    #[test]
    fn is_money_venue_covers_trading_not_service() {
        for v in [
            "binance",
            "binance_futures",
            "okx",
            "bybit",
            "kucoin",
            "asterdex",
            "hyperliquid_main",
            "hyperliquid_testnet",
        ] {
            assert!(is_money_venue(v), "{v} should be a money venue");
        }
        for v in ["x402", "data-signing", "unknown", ""] {
            assert!(!is_money_venue(v), "{v} must NOT be a money venue");
        }
    }

    #[test]
    fn policy_authority_message_golden() {
        // Cross-crate pin: policy-cli's `policy_authority_golden_matches_enclave`
        // asserts this SAME hex for the SAME fixed input (empty policy,
        // customer_id="c1", venue="binance"). If either crate's canonical/message
        // framing drifts, one of the two tests fails — catching a silent break of
        // the money-venue floor gate BEFORE it ships.
        const GOLDEN: &str = "7369676e65722d706f6c6963792d617574686f726974792d7631000000000263310000000762696e616e6365000000027b7d";
        let canonical = canonical_policy_signable(&Policy::default()).unwrap();
        assert_eq!(canonical, b"{}");
        let msg = policy_authority_message("c1", "binance", &canonical);
        assert_eq!(hex::encode(&msg), GOLDEN);
    }

    #[test]
    fn canonical_policy_signable_strips_all_signature_fields() {
        // The refactored canonical form must ignore all three sig-carrying
        // fields — otherwise the authority signature couldn't cover itself and
        // existing hashes would shift.
        let base = floor_policy();
        let mut with_sigs = base.clone();
        with_sigs.signer_pubkey = Some("aa".to_owned());
        with_sigs.policy_signature = Some("bb".to_owned());
        with_sigs.policy_authority_sig = Some("cc".to_owned());
        assert_eq!(
            canonical_policy_signable(&base).unwrap(),
            canonical_policy_signable(&with_sigs).unwrap()
        );
    }

    #[test]
    fn enforce_policy_hash_strips_tofu_fields() {
        let base = Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            ..Policy::default()
        };
        let with_tofu = Policy {
            signer_pubkey: Some("aabbcc".to_owned()),
            policy_signature: Some("ddeeff".to_owned()),
            ..base.clone()
        };
        let req = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let h_base = enforce_policy(Some(&base), &req).unwrap();
        let h_tofu = enforce_policy(Some(&with_tofu), &req).unwrap();
        assert_eq!(h_base, h_tofu);
    }

    #[test]
    fn enforce_policy_different_policies_different_hashes() {
        let p1 = Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            ..Policy::default()
        };
        let p2 = Policy {
            allowed_actions: Some(vec!["sign_okx".to_owned()]),
            ..Policy::default()
        };
        let req1 = policy_test_req("sign_binance", "POST", "/api/v1/order");
        let req2 = policy_test_req("sign_okx", "POST", "/api/v1/order");
        let h1 = enforce_policy(Some(&p1), &req1).unwrap();
        let h2 = enforce_policy(Some(&p2), &req2).unwrap();
        assert_ne!(h1, h2);
    }

    // ─── C18 (ZLODEY 2026-05-18): SIGNER_REQUIRE_POLICY flag ─────────────
    //
    // These tests cover the env-var helper directly. The full integration
    // (env=1 + legacy blob in load_and_parse_blob → PolicyRequired) cannot
    // be tested without KMS plumbing — see signer-policy-cli unit tests
    // for ParsedBlob coverage at the proto level.
    //
    // Env-var tests use SetEnvVarGuard to ensure no leak between tests
    // (cargo runs tests in parallel; a leaked SIGNER_REQUIRE_POLICY would
    // wreck the other 175 tests).

    /// Process-wide mutex serializing the SIGNER_REQUIRE_POLICY env-var
    /// tests below. Cargo runs unit tests in parallel by default, so two
    /// concurrent tests touching the same env var would race (test A sets
    /// "1", test B reads "1" expecting unset, both flake non-deterministically).
    /// Hold this lock for the lifetime of the test body.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Guard that sets an env var on construction and unsets on drop.
    /// Holds the process-wide ENV_LOCK so tests using it never race.
    struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
        // Held to keep the mutex locked for the lifetime of the guard.
        // Dropped after the env-var restoration in Drop::drop.
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            // If another test poisoned the mutex, recover silently — the
            // env-var state may be slightly off but the lock semantics
            // still serialize us against parallel access.
            let lock = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let prev = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self {
                key,
                prev,
                _lock: lock,
            }
        }
    }
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
            // _lock dropped automatically after this — release in correct order.
        }
    }

    #[test]
    fn policy_required_default_false_no_env() {
        // Default state must be permissive — production currently runs
        // unset because all staged blobs are legacy.
        let _g = EnvVarGuard::set("SIGNER_REQUIRE_POLICY", "");
        // empty string is not a recognized "on" value
        // policy_required() caches via OnceLock for production. Tests use
        // policy_required() to bypass the cache and pick up the
        // env-var change set by EnvVarGuard.
        assert!(!policy_required());
    }

    // Gemini PR #28 round-3: removed `policy_required_recognizes_1` and
    // `policy_required_recognizes_true_caseinsensitive` — both subsumed by
    // the more comprehensive `policy_required_accepts_all_truthy_cases`
    // test below which covers all 11 mixed-case spellings of {1, true,
    // yes, on}.

    #[test]
    fn policy_required_rejects_garbage() {
        // 0, false, no, garbage — all NOT considered "on"
        for v in &["0", "false", "no", "off", "FALSE", "asdf", " 1", "1 "] {
            let _g = EnvVarGuard::set("SIGNER_REQUIRE_POLICY", v);
            assert!(!policy_required(), "value {:?} should NOT be on", v);
        }
    }

    /// Gemini PR #28 round-2: mixed-case truthy values must be accepted
    /// uniformly via eq_ignore_ascii_case (not the old hard-coded list
    /// of `"1"|"true"|"TRUE"|"yes"` which rejected `True`, `YES`, etc).
    #[test]
    fn policy_required_accepts_all_truthy_cases() {
        for v in &["1", "true", "True", "TRUE", "TrUe", "yes", "YES", "yEs", "on", "ON", "On"] {
            let _g = EnvVarGuard::set("SIGNER_REQUIRE_POLICY", v);
            assert!(
                policy_required(),
                "value {:?} should be accepted as truthy",
                v
            );
        }
    }
    #[test]
    fn verify_blob_unknown_action_routes_correctly() {
        // Sanity: dispatch table sees "verify_blob" and calls the new handler.
        // PR-B: verify_blob takes its venue from `path` (the operator picks it),
        // so we set a venue the seeded operator identity grants — the request
        // then passes the venue ACL and fails at load_secret_for (no creds),
        // proving routing reaches the handler. We can't decrypt without real KMS.
        let req = SignRequest {
            action: "verify_blob".to_owned(),
            path: Some("binance".to_owned()),
            ..req_template()
        };
        let resp = handle_seeded(req);
        // load_secret_for returns BadRequest because aws_credentials is None.
        assert!(resp.error.is_some(), "verify_blob without creds must error");
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
        // Critically: NO plaintext_sha256 on the error path.
        assert!(resp.plaintext_sha256.is_none());
    }

    #[test]
    fn verify_blob_missing_ciphertext_is_bad_request() {
        // creds present but ciphertext absent — still BadRequest, never panic.
        // `path` carries a venue the seeded operator identity grants so the
        // request clears the venue ACL and reaches the ciphertext check.
        let req = SignRequest {
            action: "verify_blob".to_owned(),
            path: Some("binance".to_owned()),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIA...".to_owned(),
                secret_access_key: "secret".to_owned(),
                session_token: "session".to_owned(),
            }),
            ciphertext_blob_base64: None,
            ..req_template()
        };
        let resp = handle_seeded(req);
        assert_eq!(resp.error.as_deref(), Some(err_code::BAD_REQUEST));
        assert!(resp.plaintext_sha256.is_none());
    }

    #[test]
    fn verify_blob_response_shape_has_sha256_field() {
        // Direct constructor test: ok_verify_blob populates the field.
        let resp = SignResponse::ok_verify_blob(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
            287,
        );
        assert!(resp.error.is_none());
        assert_eq!(resp.signature_base64, "");
        assert!(resp.headers.is_none());
        assert!(resp.hl_signature.is_none());
        assert!(resp.policy_hash.is_none());
        assert_eq!(
            resp.plaintext_sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(resp.plaintext_len, Some(287));
    }

    // ───────────────── attested-signed-data (sign_data) ─────────────────
    // Exercises the REAL data=Some path (not just the data:None early exit the
    // crypto panel flagged as false-green): the venue arm makes sign_data
    // reachable, and the presence / size-cap / dup-key guards all run on a
    // populated payload BEFORE any KMS work. The sign→ecrecover crypto itself is
    // proven in `signer::tests::sign_attested_data_ecrecover_roundtrip`; the full
    // through-KMS decrypt→sign→ecrecover path is verified LIVE at the P3 demo
    // cutover (the test harness has no KMS-decrypt mock, same as every venue).
    #[test]
    fn sign_data_venue_arm_and_payload_guards() {
        // The dead-handler root fix: sign_data resolves to the data-signing
        // venue, so load_and_parse_blob is reached instead of venue==None.
        assert_eq!(venue_for_action("sign_data"), Some("data-signing"));

        // (presence) data:None → BAD_REQUEST.
        let mut none = req_template();
        none.action = "sign_data".to_owned();
        none.data = None;
        assert_eq!(handle_seeded(none).error.as_deref(), Some(err_code::BAD_REQUEST));

        // (size-cap) an oversized populated payload → BAD_REQUEST, before KMS.
        let mut big = req_template();
        big.action = "sign_data".to_owned();
        big.data = Some(format!(r#"{{"x":"{}"}}"#, "a".repeat(MAX_ATTESTED_DATA_BYTES)));
        assert_eq!(handle_seeded(big).error.as_deref(), Some(err_code::BAD_REQUEST));

        // (dup-key) duplicate object keys in a populated payload → fail-closed.
        let mut dup = req_template();
        dup.action = "sign_data".to_owned();
        dup.data = Some(r#"{"a":"1","a":"2"}"#.to_owned());
        assert_eq!(handle_seeded(dup).error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn sign_data_venue_acl_isolates_the_data_key() {
        let _gl = crate::registry::GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // §5: the data-signing SERVICE identity is customer_id == "attested-data"
        // granted ONLY "data-signing" — its encryption_context("data-signing") is
        // exactly the `{customer_id:"attested-data", venue_id:"data-signing"}` the
        // data-key blob is sealed under, so the KMS context match (and the GCM
        // AAD) bind decryption to THIS identity.
        crate::registry::test_install(&[("tok-ds", "attested-data", &["data-signing"])]);
        let ds = crate::registry::resolve("tok-ds").expect("data-signing identity seeded");
        assert_eq!(ds.customer_id, "attested-data");
        assert!(ds.venue_allowed("data-signing"));
        let ctx = ds.encryption_context("data-signing");
        assert_eq!(ctx.get("customer_id").map(String::as_str), Some("attested-data"));
        assert_eq!(ctx.get("venue_id").map(String::as_str), Some("data-signing"));
        // Invariant (c) (crypto-panel #211 regression-guard): the data-signing
        // identity can ONLY sign data-signing — never a money/venue key
        // (authorize_venue denies it; the KMS context also wouldn't decrypt a
        // venue blob). So even a money-shaped payload through /sign-data can never
        // reach a venue key.
        assert!(!ds.venue_allowed("binance"), "data-signing identity must never sign money");
        assert!(!ds.venue_allowed("hyperliquid_main"));
        assert!(!ds.venue_allowed("x402"));

        // A normal tenant is NEVER granted data-signing → authorize_venue denies
        // it (and even if bypassed, its context customer_id ≠ "attested-data"
        // → KMS AccessDenied). Defense-in-depth behind the gateway operator route.
        crate::registry::test_install(&[("tok-t", "cust-t", &["binance"])]);
        let t = crate::registry::resolve("tok-t").expect("tenant seeded");
        assert!(!t.venue_allowed("data-signing"), "a tenant must never reach the data key");
    }

    // ───────────────── HL testnet dispatcher (source="b") ─────────────────
    #[test]
    fn hyperliquid_testnet_dispatched_and_not_denied() {
        // venue arm exists (separate from mainnet).
        assert_eq!(venue_for_action("sign_hyperliquid_testnet_order"), Some("hyperliquid_testnet"));
        assert_eq!(venue_for_action("sign_hyperliquid_testnet_cancel"), Some("hyperliquid_testnet"));

        let order = serde_json::json!({"type": "order", "orders": [{}]});
        let mk = |action: &str| {
            let mut r = req_template();
            r.action = action.to_owned();
            r.hl_action = Some(order.clone());
            r.nonce = Some(1);
            r
        };
        // Testnet is NOT hard-denied (unlike mainnet): with a valid shape but the
        // broad seed token lacking the `hyperliquid_testnet` grant it stops at the
        // venue ACL (BAD_REQUEST) — it reaches the normal load path, never the
        // POLICY_DENIED hard-deny. Mainnet with the same shape stays DENIED.
        let testnet = handle_seeded(mk("sign_hyperliquid_testnet_order"));
        assert_ne!(
            testnet.error.as_deref(),
            Some(err_code::POLICY_DENIED),
            "testnet must NOT be hard-denied"
        );
        assert_eq!(
            handle_seeded(mk("sign_hyperliquid_main_order")).error.as_deref(),
            Some(err_code::POLICY_DENIED),
            "mainnet stays hard-denied"
        );

        // Wrong action shape → BAD_REQUEST before any KMS work.
        let mut bad = req_template();
        bad.action = "sign_hyperliquid_testnet_order".to_owned();
        bad.hl_action = Some(serde_json::json!({"type": "cancel"}));
        bad.nonce = Some(1);
        assert_eq!(handle_seeded(bad).error.as_deref(), Some(err_code::BAD_REQUEST));

        // A tenant granted ONLY hyperliquid_testnet can reach it, and is NOT
        // granted mainnet (venue isolation).
        let _gl = crate::registry::GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        crate::registry::test_install(&[("tok-hl", "cust-hl", &["hyperliquid_testnet"])]);
        let id = crate::registry::resolve("tok-hl").expect("seeded");
        assert!(id.venue_allowed("hyperliquid_testnet"));
        assert!(!id.venue_allowed("hyperliquid_main"), "testnet grant must not imply mainnet");
    }

    // ───────────────── attested-data provisioning (Option-1) ─────────────────
    #[test]
    fn provision_data_key_rejects_missing_creds_and_key_id() {
        // Both guards fire BEFORE any KMS round-trip (which a unit test can't
        // reach anyway). provision_data_key bypasses the tenant-identity gate.
        let mut no_creds = req_template();
        no_creds.action = "provision_data_key".to_owned();
        no_creds.aws_credentials = None;
        assert_eq!(handle(no_creds).error.as_deref(), Some(err_code::BAD_REQUEST));

        let mut no_key = req_template();
        no_key.action = "provision_data_key".to_owned();
        no_key.aws_credentials = Some(crate::proto::AwsCredentials {
            access_key_id: "AKIA".to_owned(),
            secret_access_key: "sk".to_owned(),
            session_token: "tok".to_owned(),
        });
        no_key.key_id = None;
        assert_eq!(handle(no_key).error.as_deref(), Some(err_code::BAD_REQUEST));
    }

    #[test]
    fn provisioning_output_decryptable_and_signable_by_prod_path() {
        // Full attested-data provisioning crypto loop MINUS the KMS genkey
        // round-trip (genkey needs a live enclave): a fixed DEK stands in for
        // genkey's output; every other step is the REAL provisioning seal + the
        // REAL prod decrypt + sign. Proves the provisioned blob is byte-compatible
        // with the prod sign_data path and recovers the EXACT key born in-enclave.
        let pk = crate::signer::generate_secp256k1_private_key();
        let (_compressed, provisioned_addr) = crate::signer::attested_data_pubkey(&pk).unwrap();
        let id = crate::registry::ResolvedIdentity::for_data_signing();
        let aad = id.sealed_aad("data-signing", KEY_VERSION);

        // The exact plaintext handle_provision_data_key builds.
        let plaintext = format!(
            r#"{{"exchange":"attested-data","private_key":"0x{}","wallet_address":"{}"}}"#,
            hex::encode(pk.as_slice()),
            provisioned_addr
        )
        .into_bytes();
        let dek = Zeroizing::new(vec![0x42u8; 32]); // stands in for the genkey DEK
        let envelope =
            crate::envelope::seal_with_dek(&dek, b"wrapped-dek", &plaintext, &aad).unwrap();
        let blob = serde_json::to_vec(&envelope).unwrap();

        // ── PROD path ──
        assert!(crate::envelope::is_envelope(&blob));
        let env = crate::envelope::parse_envelope(&blob).unwrap();
        // A different identity's AAD must fail the GCM tag (cross-identity guard).
        let wrong_aad = b"customer_id=cust-x\nvenue_id=data-signing\nkey_version=1";
        assert!(crate::envelope::decrypt_with_dek(&dek, &env, wrong_aad).is_err());
        // The data-signing identity's AAD decrypts it (as the prod path rebuilds).
        let pt = crate::envelope::decrypt_with_dek(&dek, &env, &aad).unwrap();

        let parsed = crate::proto::ParsedBlob::from_plaintext(&pt).unwrap();
        let secret: crate::proto::HyperliquidSecret =
            serde_json::from_value(parsed.secret_json().clone()).unwrap();
        assert!(secret.is_complete());
        let signing_pk = crate::signer::parse_evm_private_key(&secret.private_key).unwrap();

        // The prod-decrypted key IS the key born at provisioning, and it signs.
        let (_c, recovered_addr) = crate::signer::attested_data_pubkey(&signing_pk).unwrap();
        assert_eq!(recovered_addr, provisioned_addr);
        let _sig =
            crate::signer::sign_attested_data(&signing_pk, &serde_json::json!({"funding": "0.01"}))
                .unwrap();
    }

    // ════════════════════════════════════════════════════════════════════════
    // AF-1 — cap-parser / canonicalization differential fuzzer.
    //
    // External-audit hypothesis (2026-07-10): the enclave's parser for the cap
    // check might diverge from what the venue actually executes, letting a
    // crafted payload (duplicate keys, URL-dup, JSON-number-edge, extra fields,
    // percent-encoded keys, alt-separators) slip an over-cap size past the gate.
    //
    // INVARIANT UNDER TEST — "checked == signed": the qty/symbol/price the cap
    // gate evaluated must be byte-for-byte what lands in the SIGNED canonical
    // (structured venues), and on the raw-body venues (Asterdex) the enclave
    // must DENY whenever the venue's reading of the size is ambiguous. Anything
    // ambiguous or non-canonical → fail-closed. These are deterministic,
    // CI-runnable property tests (seeded xorshift, no external fuzz harness).
    // ════════════════════════════════════════════════════════════════════════
    mod af1_capparser_fuzz {
        use super::*;
        use std::cmp::Ordering;

        /// Deterministic xorshift64* PRNG. Seeded per test with a fixed constant
        /// so failures reproduce exactly (no wall-clock / no OS entropy — those
        /// are unavailable in the enclave test env and would break replay).
        struct Rng(u64);
        impl Rng {
            fn new(seed: u64) -> Self {
                Rng(seed | 1)
            }
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
                &xs[(self.next_u64() as usize) % xs.len()]
            }
            // `% == 0` (not `u64::is_multiple_of`, stable only since Rust 1.87)
            // so this test helper builds on the workspace MSRV floor
            // (rust-version = 1.83); the enclave EIF pins 1.92, but keeping the
            // declared floor honest costs nothing here.
            #[allow(clippy::manual_is_multiple_of)]
            fn chance(&mut self, denom: u64) -> bool {
                self.next_u64() % denom == 0
            }
        }

        /// Reference query-string reader: split on `&`, then `split_once('=')`.
        /// Returns every value whose key equals `key` at a param boundary. This
        /// is what a stock querystring consumer sees — the yardstick for "what
        /// the venue reads". More than one hit = ambiguous.
        fn ref_qs_values<'a>(body: &'a str, key: &str) -> Vec<&'a str> {
            body.split('&')
                .filter_map(|seg| seg.split_once('='))
                .filter(|(k, _)| *k == key)
                .map(|(_, v)| v)
                .collect()
        }

        /// Reference flag presence: a bare `name`, `name=…`, or `name&…` at a
        /// param boundary (mirrors a permissive backend honouring valueless
        /// flags). Yardstick for closePosition / batchOrders.
        fn ref_flag_present(body: &str, name: &str) -> bool {
            body.split('&')
                .any(|seg| seg == name || seg.split_once('=').map(|(k, _)| k) == Some(name))
        }

        fn capped_policy() -> Policy {
            Policy {
                order_caps: Some(vec![
                    crate::proto::OrderAssetCap {
                        symbol: "BTCUSDT".to_owned(),
                        max_qty: "5".to_owned(),
                        max_notional: None,
                    },
                    crate::proto::OrderAssetCap {
                        symbol: "ASTERUSDT".to_owned(),
                        max_qty: "5".to_owned(),
                        max_notional: None,
                    },
                ]),
                ..Policy::default()
            }
        }

        // Fragment pools mixing legal values with every smuggling class CTO named.
        const SYMBOLS: &[&str] = &["BTCUSDT", "ASTERUSDT", "ETHUSDT", "BTC-USDT-SWAP"];
        const SIDES: &[&str] = &["buy", "sell", "BUY", "long", ""];
        const TYPES: &[&str] = &["market", "limit", "fok", "MARKET", "swap", ""];
        const QTYS: &[&str] = &[
            // legal decimals (within / over the max_qty=5 cap). NB: "01" and
            // "5.0" are LEGAL (cmp_positive_decimals strips leading/trailing
            // zeros → 1 and 5) — listed for pool variety, not as fail-closed.
            "1", "5", "5.0", "4.999", "6", "10", "0.001", ".5", "5.", "01",
            // JSON-number-edge that MUST be fail-closed by cmp_positive_decimals
            // (exponent / sign / space / hex / underscore / multi-dot / empty).
            "1e3", "1E3", "+1", "-1", "1.0e2", "0x10", " 1", "1 ", "1_000",
            "1.2.3", "", ".", "..", "5&quantity=9999", "5;quantity=9999", "5=9",
            "999999999999999999999999999999",
        ];
        const PRICES: &[&str] = &["50000", "0.1", "1e3", "", "5=9", "abc"];

        fn fuzz_order(rng: &mut Rng) -> crate::proto::OrderRequest {
            crate::proto::OrderRequest {
                symbol: (*rng.pick(SYMBOLS)).to_owned(),
                side: (*rng.pick(SIDES)).to_owned(),
                qty: (*rng.pick(QTYS)).to_owned(),
                ord_type: (*rng.pick(TYPES)).to_owned(),
                price: if rng.chance(2) {
                    Some((*rng.pick(PRICES)).to_owned())
                } else {
                    None
                },
                reduce_only: rng.chance(2),
                client_order_id: if rng.chance(3) {
                    Some((*rng.pick(&["cid1", "c-i_d", "5&x=9", ""])).to_owned())
                } else {
                    None
                },
            }
        }

        /// STRUCTURED venues (Binance + OKX): the enclave rebuilds the canonical
        /// from the SAME parsed struct it cap-checks. Prove the builder embeds
        /// the cap-checked qty/symbol/price BYTE-FOR-BYTE — a signed order can
        /// never carry a size other than the one the gate evaluated.
        #[test]
        fn structured_canonical_embeds_capchecked_values() {
            let pol = capped_policy();
            let mut rng = Rng::new(0xA1F1_0000_0001);
            for _ in 0..40_000 {
                let o = fuzz_order(&mut rng);
                let cap_ok =
                    enforce_order_cap(Some(&pol), &o.symbol, Some(&o.qty), o.price.as_deref())
                        .is_ok();

                // ── Binance: form-urlencoded canonical ──
                if let Ok(c) = crate::signer::build_binance_order_query(&o) {
                    let q = ref_qs_values(&c, "quantity");
                    assert_eq!(q.len(), 1, "binance canonical dup/again quantity: {c}");
                    assert_eq!(q[0], o.qty, "binance signed qty != cap-checked qty: {c}");
                    assert_eq!(
                        ref_qs_values(&c, "symbol"),
                        vec![o.symbol.as_str()],
                        "binance signed symbol != struct symbol: {c}"
                    );
                    if let Some(px) = o.price.as_deref() {
                        // price only lands in the canonical for limit orders.
                        if c.contains("&price=") {
                            assert_eq!(ref_qs_values(&c, "price"), vec![px]);
                        }
                    }
                    if cap_ok {
                        // SAFETY: enforce_order_cap returned Ok, which for a
                        // policy that HAS order_caps means the symbol matched an
                        // entry AND cmp_positive_decimals(qty, max_qty) succeeded
                        // and was not Greater. So the find() is Some and the
                        // cmp() re-run (pure fn, identical inputs) is Ok.
                        let cap = pol
                            .order_caps
                            .as_ref()
                            .unwrap()
                            .iter()
                            .find(|c| c.symbol == o.symbol)
                            .expect("cap_ok ⟹ symbol is capped");
                        assert_ne!(
                            crate::signer::cmp_positive_decimals(&o.qty, &cap.max_qty).unwrap(),
                            Ordering::Greater,
                            "binance allowed an over-cap qty {} > {}",
                            o.qty,
                            cap.max_qty
                        );
                    }
                }

                // ── OKX: hand-built compact JSON body ──
                if let Ok(c) = crate::signer::build_okx_order_body(&o) {
                    // SAFETY: build_okx_order_body hand-constructs compact JSON
                    // from a sanitised alphabet (is_safe_okx_value), so a Ok(c)
                    // is always parseable — this only fails if the builder ever
                    // emits malformed JSON, which is itself a bug worth failing.
                    let v: serde_json::Value =
                        serde_json::from_str(&c).expect("okx builder emits valid JSON");
                    assert_eq!(
                        v.get("sz").and_then(|s| s.as_str()),
                        Some(o.qty.as_str()),
                        "okx signed sz != cap-checked qty: {c}"
                    );
                    assert_eq!(
                        v.get("instId").and_then(|s| s.as_str()),
                        Some(o.symbol.as_str()),
                        "okx signed instId != struct symbol: {c}"
                    );
                    // Price: a limit order embeds `px` — assert it's the exact
                    // struct price (the notional cap multiplies THIS value).
                    if let Some(px) = v.get("px").and_then(|s| s.as_str()) {
                        assert_eq!(
                            Some(px),
                            o.price.as_deref(),
                            "okx signed px != struct price: {c}"
                        );
                    }
                }
            }
        }

        // Asterdex raw-body fragment pools.
        const A_QTY: &[&str] = &["1", "3", "5", "6", "10", "0.5", ""];
        const A_SUFFIX: &[&str] = &["signer=0xabc&nonce=1700000000000"];

        /// Assemble an Asterdex body from randomly-ordered fragments, injecting
        /// duplicate keys, percent-encoding, alt-separators, and close/batch
        /// flags — the raw-body smuggling surface.
        fn fuzz_asterdex_body(rng: &mut Rng) -> String {
            let mut parts: Vec<String> = Vec::new();
            if rng.chance(2) {
                parts.push(format!("symbol={}", rng.pick(SYMBOLS)));
            }
            if rng.chance(2) {
                parts.push(format!("quantity={}", rng.pick(A_QTY)));
            }
            // duplicate quantity (URL parameter pollution)
            if rng.chance(3) {
                parts.push(format!("quantity={}", rng.pick(A_QTY)));
            }
            // duplicate symbol
            if rng.chance(4) {
                parts.push(format!("symbol={}", rng.pick(SYMBOLS)));
            }
            // percent-encoded key (%71 = 'q')
            if rng.chance(5) {
                parts.push(format!("%71uantity={}", rng.pick(A_QTY)));
            }
            // close-all / batch flags
            if rng.chance(6) {
                parts.push("closePosition=true".to_owned());
            }
            if rng.chance(6) {
                parts.push("batchOrders=%5B%5D".to_owned());
            }
            // alt-separator smuggle inside a value
            if rng.chance(6) {
                parts.push(format!("quantity=1;quantity={}", rng.pick(A_QTY)));
            }
            parts.push((*rng.pick(A_SUFFIX)).to_owned());
            // shuffle order (Fisher–Yates with the same rng)
            for i in (1..parts.len()).rev() {
                let j = (rng.next_u64() as usize) % (i + 1);
                parts.swap(i, j);
            }
            parts.join("&")
        }

        /// ASTERDEX (raw-body sign): the EIP-712 signature commits to the body
        /// verbatim, so the size cap parses the SAME bytes the venue will. Prove
        /// the enclave ALLOWS a sized order ONLY when the venue's reading of the
        /// size is UNAMBIGUOUS — exactly one `quantity`, one capped `symbol`, no
        /// percent-encoding, no close/batch flag, within cap. Any ambiguity that
        /// could make the venue execute a different size MUST be denied.
        #[test]
        fn asterdex_allows_only_unambiguous_within_cap_size() {
            let pol = capped_policy();
            let mut rng = Rng::new(0xA1F1_0000_0002);
            for _ in 0..60_000 {
                let body = fuzz_asterdex_body(&mut rng);
                if enforce_asterdex_size_cap(Some(&pol), &body).is_ok() {
                    // Percent-encoding on a capped body is always denied.
                    assert!(!body.contains('%'), "allowed a percent-encoded body: {body}");
                    // Close-all / batch flags are presence-denied.
                    assert!(
                        !ref_flag_present(&body, "closePosition"),
                        "allowed closePosition: {body}"
                    );
                    assert!(
                        !ref_flag_present(&body, "batchOrders"),
                        "allowed batchOrders: {body}"
                    );
                    let qvals = ref_qs_values(&body, "quantity");
                    if !qvals.is_empty() {
                        // A sized order the venue could read two ways must never pass.
                        assert_eq!(qvals.len(), 1, "allowed an ambiguous quantity: {body}");
                        let svals = ref_qs_values(&body, "symbol");
                        assert_eq!(svals.len(), 1, "allowed sized order w/o single symbol: {body}");
                        // SAFETY: enforce_asterdex_size_cap returned Ok with a
                        // quantity present ⟹ the symbol resolved to a capped
                        // entry and cmp_positive_decimals(qty, max_qty) was Ok
                        // and not Greater. ref_qs_values agreeing on a single
                        // value (asserted just above) means we read the same
                        // string the enclave's boundary parser did.
                        let cap = pol
                            .order_caps
                            .as_ref()
                            .unwrap()
                            .iter()
                            .find(|c| c.symbol == svals[0])
                            .expect("allowed sized order ⟹ symbol is capped");
                        assert_ne!(
                            crate::signer::cmp_positive_decimals(qvals[0], &cap.max_qty).unwrap(),
                            Ordering::Greater,
                            "allowed an over-cap size {} > {}: {body}",
                            qvals[0],
                            cap.max_qty
                        );
                    }
                }
            }
        }

        /// BINANCE-REQUEST (raw-payload sign): the per-op param allow-list is a
        /// POSITIVE whitelist. Fuzz op/param combinations and prove deny-by-
        /// default: every withdraw/transfer op is refused, and any param name
        /// the venue would read but the whitelist doesn't recognize is refused
        /// (no encoding/suffix bypass).
        ///
        /// NOTE (scope): this is a REGRESSION PIN, not a fully independent
        /// oracle — its `all_known` reference reproduces production's own
        /// name-split, so a bug SHARED by both (e.g. a future change to how
        /// duplicate param names are treated) would be invisible here. The
        /// actual money-path mitigation for capped keys on this route (deny
        /// `op=order`) is pinned separately by
        /// `golden_binance_request_capped_order_denied`.
        #[test]
        fn binance_request_allowlist_is_deny_by_default() {
            const OPS: &[&str] = &[
                "order", "cancel", "account", "openOrders", "leverage",
                // denied ops (withdraw/transfer/sub-account family)
                "withdraw", "transfer", "universalTransfer", "sapiWithdraw", "",
            ];
            const NAMES: &[&str] = &[
                "symbol", "quantity", "side", "type", "price", "recvWindow", "timestamp",
                // hostile names the whitelist must reject
                "amount", "address", "coin", "%71uantity", "quantity ", "wapi", "sub",
            ];
            let mut rng = Rng::new(0xA1F1_0000_0003);
            for _ in 0..40_000 {
                let op = *rng.pick(OPS);
                let n = 1 + (rng.next_u64() as usize % 4);
                let payload = (0..n)
                    .map(|_| format!("{}={}", rng.pick(NAMES), rng.next_u64() % 100))
                    .collect::<Vec<_>>()
                    .join("&");
                let res = check_binance_request_allow(op, &payload);

                match binance_request_allowed_params(op) {
                    None => assert!(res.is_err(), "denied op {op} slipped through"),
                    Some(allowed) => {
                        // Names the reference parser sees the venue reading.
                        let all_known = payload.split('&').filter(|p| !p.is_empty()).all(|pair| {
                            let name = pair.split('=').next().unwrap_or("");
                            allowed.contains(&name)
                        });
                        assert_eq!(
                            res.is_ok(),
                            all_known,
                            "allow-list disagreed with positive whitelist on op={op} payload={payload}"
                        );
                    }
                }
            }
        }

        // ── Hyperliquid: index-keyed cap over a serde_json::Value action. ──

        fn hl_capped_policy() -> Policy {
            Policy {
                hl_order_caps: Some(vec![
                    crate::proto::HlOrderCap {
                        asset: 0,
                        max_size: "5".to_owned(),
                        max_notional: None,
                    },
                    crate::proto::HlOrderCap {
                        asset: 1,
                        max_size: "5".to_owned(),
                        max_notional: None,
                    },
                ]),
                ..Policy::default()
            }
        }

        const HL_ASSETS: &[&str] = &["0", "1", "2", "7"];
        const HL_SIZES: &[&str] = &["1", "5", "5.0", "6", "10", "1e3", "+1", "", "0.5"];

        /// Assemble a Hyperliquid order action as a JSON string (HL-SDK key
        /// insertion order `a,b,p,s,r,t`) with fuzzed asset/size and optional
        /// DUPLICATE `s`/`a` keys, then parse to a `serde_json::Value`. Unlike
        /// the `deny_unknown_fields` structs, `serde_json::Value` (preserve_order
        /// / IndexMap) does NOT reject duplicate keys — it keeps the last value
        /// at the original position — so this exercises the dup-key surface the
        /// struct paths don't have.
        fn fuzz_hl_action_json(rng: &mut Rng) -> String {
            let a = rng.pick(HL_ASSETS);
            let s = rng.pick(HL_SIZES);
            let dup_s = if rng.chance(3) {
                format!(r#","s":"{}""#, rng.pick(HL_SIZES))
            } else {
                String::new()
            };
            let dup_a = if rng.chance(4) {
                format!(r#","a":{}"#, rng.pick(HL_ASSETS))
            } else {
                String::new()
            };
            format!(
                r#"{{"type":"order","orders":[{{"a":{a},"b":true,"p":"50000","s":"{s}","r":false,"t":{{"limit":{{"tif":"Gtc"}}}}{dup_s}{dup_a}}}]}}"#
            )
        }

        /// HYPERLIQUID (msgpack-signed action): `enforce_hl_caps` reads
        /// `orders[].a`/`orders[].s` out of the SAME `serde_json::Value` that
        /// `msgpack_action` then encodes into the signed actionHash. Prove the
        /// invariant end-to-end by round-tripping the signed bytes: encode the
        /// action to msgpack, decode it back, and assert the size the venue will
        /// execute is byte-identical to the size the cap gate evaluated — and
        /// that an allowed order is within cap. Covers the venue whose msgpack
        /// key-order the project has been bitten by before.
        #[test]
        fn hl_capchecked_size_survives_msgpack_roundtrip() {
            let pol = hl_capped_policy();
            let mut rng = Rng::new(0xA1F1_0000_0004);
            for _ in 0..40_000 {
                let json = fuzz_hl_action_json(&mut rng);
                let Ok(action) = serde_json::from_str::<serde_json::Value>(&json) else {
                    continue; // a fuzzed body that isn't valid JSON — skip
                };
                if !validate_order_action(&action) {
                    continue;
                }
                let allowed = enforce_hl_caps(Some(&pol), &action, None).is_ok();

                // The signed bytes ARE msgpack(action). Verify two ways:
                //  (a) BYTE-LEVEL, decoder-independent — the size string must be
                //      present in the raw msgpack as a fixstr (`0xa0|len` prefix
                //      + ASCII), so a self-consistent-but-wrong rmp_serde encode
                //      that a same-library decode would mask is still caught.
                //  (b) round-trip decode — the whole order survives structurally.
                let buf = crate::signer::msgpack_action(&action).expect("valid action encodes");
                let orig_orders = action["orders"].as_array().unwrap();
                for order in orig_orders {
                    // SAFETY: validate_order_action guarantees `orders` is a
                    // non-empty array; the fuzzer always emits a string `s`.
                    let s = order["s"].as_str().unwrap();
                    if !s.is_empty() && s.len() <= 31 {
                        // fixstr for len ≤ 31: first byte 0xa0|len, then the bytes.
                        let mut needle = Vec::with_capacity(s.len() + 1);
                        needle.push(0xa0 | s.len() as u8);
                        needle.extend_from_slice(s.as_bytes());
                        assert!(
                            buf.windows(needle.len()).any(|w| w == needle.as_slice()),
                            "hl size {s} not present as a msgpack fixstr in signed bytes: {json}"
                        );
                    }
                }
                let decoded: serde_json::Value =
                    rmp_serde::from_slice(&buf).expect("msgpack round-trips");
                let dec_orders = decoded["orders"].as_array().expect("orders survive msgpack");
                assert_eq!(orig_orders.len(), dec_orders.len());
                for (orig, dec) in orig_orders.iter().zip(dec_orders.iter()) {
                    assert_eq!(
                        orig.get("s"),
                        dec.get("s"),
                        "hl signed size diverged from cap-checked size after msgpack: {json}"
                    );
                    assert_eq!(orig.get("a"), dec.get("a"), "hl asset diverged: {json}");
                    // Price is part of the notional surface — it must survive too.
                    assert_eq!(orig.get("p"), dec.get("p"), "hl price diverged: {json}");
                }
                if allowed {
                    for order in orig_orders {
                        // SAFETY: enforce_hl_caps allowed ⟹ every order has a
                        // u64 `a` in caps and a str `s` that cmp'd ≤ max_size.
                        let a = order["a"].as_u64().unwrap();
                        let s = order["s"].as_str().unwrap();
                        let cap = pol
                            .hl_order_caps
                            .as_ref()
                            .unwrap()
                            .iter()
                            .find(|c| c.asset == a)
                            .expect("allowed ⟹ asset is capped");
                        assert_ne!(
                            crate::signer::cmp_positive_decimals(s, &cap.max_size).unwrap(),
                            Ordering::Greater,
                            "hl allowed an over-cap size {s} > {}: {json}",
                            cap.max_size
                        );
                    }
                }
            }
        }

        // ── Notional caps (B2, qty × price): the price surface of the invariant. ──

        fn aster_notional_policy() -> Policy {
            Policy {
                order_caps: Some(vec![crate::proto::OrderAssetCap {
                    symbol: "ASTERUSDT".to_owned(),
                    max_qty: "100".to_owned(),
                    max_notional: Some("500".to_owned()),
                }]),
                ..Policy::default()
            }
        }

        /// ASTERDEX under a NOTIONAL cap: the price surface the size-only tests
        /// leave dead. A notional-capped symbol may place LIMIT orders only, and
        /// `price=` must be single/unambiguous — prove the enclave ALLOWS only
        /// when `type=LIMIT`, exactly one `price`, and qty × price ≤ max_notional.
        #[test]
        fn asterdex_notional_allows_only_unambiguous_limit_within_notional() {
            let pol = aster_notional_policy();
            const N_TYPE: &[&str] = &["LIMIT", "MARKET", "", "limit"];
            const N_PRICE: &[&str] = &["1", "10", "6", "5", "1;price=9999", ""];
            const N_QTY: &[&str] = &["1", "50", "100", "200"];
            let mut rng = Rng::new(0xA1F1_0000_0005);
            for _ in 0..40_000 {
                let mut parts = vec![
                    "symbol=ASTERUSDT".to_owned(),
                    format!("quantity={}", rng.pick(N_QTY)),
                    format!("type={}", rng.pick(N_TYPE)),
                    format!("price={}", rng.pick(N_PRICE)),
                    "signer=0xa&nonce=1700000000000".to_owned(),
                ];
                if rng.chance(4) {
                    parts.push(format!("price={}", rng.pick(N_PRICE))); // dup price
                }
                if rng.chance(4) {
                    parts.push(format!("type={}", rng.pick(N_TYPE))); // dup/ambiguous type
                }
                for i in (1..parts.len()).rev() {
                    let j = (rng.next_u64() as usize) % (i + 1);
                    parts.swap(i, j);
                }
                let body = parts.join("&");
                if enforce_asterdex_size_cap(Some(&pol), &body).is_ok() {
                    // Allowed under a notional cap ⟹ LIMIT + single price + the
                    // notional holds. A MARKET / missing-type order is denied
                    // (unboundable), and an ambiguous/dup price is denied.
                    assert_eq!(
                        ref_qs_values(&body, "type"),
                        vec!["LIMIT"],
                        "notional cap allowed a non-LIMIT order: {body}"
                    );
                    let px = ref_qs_values(&body, "price");
                    assert_eq!(px.len(), 1, "notional cap allowed ambiguous price: {body}");
                    let qty = ref_qs_values(&body, "quantity");
                    assert_eq!(qty.len(), 1);
                    // Division of labor: this asserts the STRUCTURAL invariant
                    // (LIMIT-only + single unambiguous price) via the independent
                    // ref_qs_values parser. The arithmetic itself (notional_exceeds)
                    // is pinned separately by signer.rs `notional_exceeds_vectors`
                    // (known-answer vectors) — reusing it here is not an oracle for
                    // its own correctness, only a consistency cross-check.
                    assert!(
                        !crate::signer::notional_exceeds(qty[0], px[0], "500").unwrap(),
                        "notional cap allowed qty×price over 500: {body}"
                    );
                }
            }
        }

        // ── Golden vectors: the exact smuggling classes CTO named, pinned. ──

        #[test]
        fn golden_structured_duplicate_key_is_rejected_at_parse() {
            // STRONGER than last-wins: serde-derived struct deserialization
            // REJECTS a duplicate field outright ("duplicate field `qty`"), on
            // BOTH the enclave's `from_slice::<SignRequest>` and the gateway's
            // `Json<...>`. So the classic dup-key size-smuggle
            // (`{"qty":"1","qty":"1000"}`) never even reaches the cap gate — it
            // fails closed at parse. There is no ambiguous value to diverge.
            assert!(serde_json::from_str::<crate::proto::OrderRequest>(
                r#"{"symbol":"BTCUSDT","side":"buy","qty":"1","qty":"1000","ord_type":"market"}"#,
            )
            .is_err());
            // A single-valued over-cap qty (the only shape that parses) is the
            // exact string the canonical would carry → caught by the cap.
            assert_eq!(
                enforce_order_cap(Some(&capped_policy()), "BTCUSDT", Some("1000"), None)
                    .err()
                    .and_then(|r| r.error.clone()),
                Some(err_code::SIZE_OVER_CAP.to_owned())
            );
        }

        #[test]
        fn golden_structured_extra_field_is_rejected() {
            // deny_unknown_fields: a smuggled field never reaches the enclave.
            assert!(serde_json::from_str::<crate::proto::OrderRequest>(
                r#"{"symbol":"BTCUSDT","side":"buy","qty":"1","ord_type":"market","evil":"1000"}"#,
            )
            .is_err());
        }

        #[test]
        fn golden_number_edge_is_failclosed_under_cap() {
            // Exponent / sign / leading-space / hex are NOT plain decimals: the
            // cap comparison errors → the order is refused, never signed.
            for edge in ["1e3", "+6", " 6", "0x6", "6 ", "1_0"] {
                let r =
                    enforce_order_cap(Some(&capped_policy()), "BTCUSDT", Some(edge), None);
                assert!(r.is_err(), "number-edge qty {edge} was not fail-closed");
            }
        }

        #[test]
        fn golden_asterdex_url_dup_and_encoded_key_denied() {
            let pol = capped_policy();
            // URL parameter pollution on quantity → BAD_REQUEST (dup rejected).
            assert!(enforce_asterdex_size_cap(
                Some(&pol),
                "symbol=ASTERUSDT&quantity=1&quantity=9999&signer=0xa&nonce=1700000000000"
            )
            .is_err());
            // Percent-encoded key on a capped body → BAD_REQUEST.
            assert!(enforce_asterdex_size_cap(
                Some(&pol),
                "symbol=ASTERUSDT&%71uantity=9999&signer=0xa&nonce=1700000000000"
            )
            .is_err());
            // Alt-separator smuggle lands inside the single value → non-decimal
            // → cmp errors → BAD_REQUEST.
            assert!(enforce_asterdex_size_cap(
                Some(&pol),
                "symbol=ASTERUSDT&quantity=1;quantity=9999&signer=0xa&nonce=1700000000000"
            )
            .is_err());
        }

        #[test]
        fn golden_binance_request_withdraw_op_denied() {
            assert!(check_binance_request_allow("withdraw", "coin=USDT&amount=1").is_err());
            assert!(binance_request_allowed_params("withdraw").is_none());
            // A hostile param on an allowed op is refused (positive whitelist).
            assert!(check_binance_request_allow("account", "address=0xattacker").is_err());
        }

        #[test]
        fn golden_binance_request_capped_order_denied() {
            // The money-path mitigation: a CAPPED key can never place an order
            // through the generic verbatim-sign route (order caps aren't parsed
            // there). Pins the extracted guard directly.
            let capped = capped_policy();
            assert!(binance_request_order_denied_for_capped("order", Some(&capped)));
            // Reads/cancels stay available for a capped key.
            assert!(!binance_request_order_denied_for_capped("cancel", Some(&capped)));
            assert!(!binance_request_order_denied_for_capped("account", Some(&capped)));
            // An UNCAPPED key (no order_caps) signs every op incl. order.
            assert!(!binance_request_order_denied_for_capped("order", Some(&Policy::default())));
            assert!(!binance_request_order_denied_for_capped("order", None));
        }

        #[test]
        fn golden_hl_duplicate_key_value_is_last_wins_and_consistent() {
            // serde_json::Value (preserve_order / IndexMap) does NOT reject a
            // duplicate key — it keeps the LAST value at the original position.
            // Because enforce_hl_caps AND msgpack_action read the SAME Value,
            // "checked" and "signed" both see that last value → no divergence.
            let action: serde_json::Value = serde_json::from_str(
                r#"{"type":"order","orders":[{"a":0,"b":true,"p":"50000","s":"1","r":false,"s":"9999","t":{"limit":{"tif":"Gtc"}}}]}"#,
            )
            .unwrap();
            assert_eq!(
                action["orders"][0]["s"].as_str(),
                Some("9999"),
                "serde_json::Value must keep the last duplicate value"
            );
            // The over-cap last value is what the cap gate sees → denied, and it
            // is also what msgpack would sign (same Value) → consistent.
            assert_eq!(
                enforce_hl_caps(Some(&hl_capped_policy()), &action, None)
                    .err()
                    .and_then(|r| r.error.clone()),
                Some(err_code::POLICY_DENIED.to_owned())
            );
            let buf = crate::signer::msgpack_action(&action).unwrap();
            let decoded: serde_json::Value = rmp_serde::from_slice(&buf).unwrap();
            assert_eq!(decoded["orders"][0]["s"].as_str(), Some("9999"));
        }

        #[test]
        fn golden_hl_notional_limit_within_over_and_nonlimit() {
            // HL per-order notional (B2): size × price ≤ max_notional, LIMIT-only.
            let pol = Policy {
                hl_order_caps: Some(vec![crate::proto::HlOrderCap {
                    asset: 0,
                    max_size: "100".to_owned(),
                    max_notional: Some("500".to_owned()),
                }]),
                ..Policy::default()
            };
            let act = |body: &str| -> Option<String> {
                let v: serde_json::Value = serde_json::from_str(body).unwrap();
                enforce_hl_caps(Some(&pol), &v, None)
                    .err()
                    .and_then(|r| r.error.clone())
            };
            // limit, 5 × 50 = 250 ≤ 500 → allowed.
            assert_eq!(
                act(r#"{"type":"order","orders":[{"a":0,"b":true,"p":"50","s":"5","r":false,"t":{"limit":{"tif":"Gtc"}}}]}"#),
                None
            );
            // limit, 5 × 150 = 750 > 500 → denied.
            assert_eq!(
                act(r#"{"type":"order","orders":[{"a":0,"b":true,"p":"150","s":"5","r":false,"t":{"limit":{"tif":"Gtc"}}}]}"#),
                Some(err_code::POLICY_DENIED.to_owned())
            );
            // trigger order (no t.limit) under a notional cap → unboundable → denied.
            assert_eq!(
                act(r#"{"type":"order","orders":[{"a":0,"b":true,"p":"50","s":"5","r":false,"t":{"trigger":{"isMarket":true,"triggerPx":"50","tpsl":"tp"}}}]}"#),
                Some(err_code::POLICY_DENIED.to_owned())
            );
        }

        #[test]
        fn golden_asterdex_notional_market_denied() {
            // Under a notional cap, a MARKET order is unboundable (no reliable
            // execution price) → fail-closed deny, regardless of a decorative
            // low `price=`.
            let pol = aster_notional_policy();
            assert_eq!(
                enforce_asterdex_size_cap(
                    Some(&pol),
                    "symbol=ASTERUSDT&quantity=1&type=MARKET&price=1&signer=0xa&nonce=1700000000000"
                )
                .err()
                .and_then(|r| r.error.clone()),
                Some(err_code::POLICY_DENIED.to_owned())
            );
        }
    }

}
