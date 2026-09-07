//! C22 mitigation (ZLODEY threat hunt 2026-05-18): bearer token authentication
//! middleware for the `/sign` endpoint.
//!
//! Threat: gateway had ZERO authentication. If the EC2 origin IP
//! (`54.224.183.120:8443`) was discovered by an attacker — via reverse DNS,
//! CT logs for `signer-demo.usenami.io`, or EC2 IP range scans — they could
//! curl `/sign` directly, bypassing Cloudflare entirely. Once Cloudflare is
//! bypassed there is no rate limit, no WAF, no DDoS shielding, no auth — the
//! enclave will sign whatever the (decryptable) blobs allow.
//!
//! Mitigation: this middleware enforces an HTTP `Authorization: Bearer <token>`
//! header on every request to `/sign`. Tokens are configured via the
//! `SIGNER_API_TOKENS` env var (format: `token1:customer1,token2:customer2`).
//!
//! Defense-in-depth: this is layered *with* the EC2 Security Group rule that
//! restricts inbound 8443 to the AWS-managed Cloudflare prefix list
//! (`pl-03089356febfc669f`, deployed 2026-05-18). Even if a Cloudflare IP
//! impersonator slips past the SG, they still face the bearer check here.
//!
//! Why bearer tokens, not mTLS or signed envelopes:
//!  - **mTLS** would require Cloudflare's mTLS feature (paid tier) AND each
//!    customer to provision a client cert with their bot. Setup friction high.
//!  - **Signed envelope** (HMAC over request body with a shared secret) is
//!    closer to what the SDK already does for exchange APIs and would be a
//!    proper replay-protected scheme. But it's heavier engineering and
//!    overkill for Phase 1 PoC where each signer instance serves one customer.
//!  - **Bearer token** is one HTTP header on the customer side, one env var
//!    on the operator side, and easily upgraded to per-customer multi-token
//!    later. Standard, well-understood, supported by every HTTP client.
//!
//! Fail-closed by default (design §5.5 / round-1 R11 — this doc updated for
//! CR097; the old "unset ⇒ warn + pass through" behaviour is GONE):
//!  - If `SIGNER_API_TOKENS` is **set** with ≥1 token, the middleware strictly
//!    enforces — `unauthorized` (HTTP 401) on missing/mismatched.
//!  - If it is **unset/empty**, `from_env` REFUSES TO BOOT (`AuthRequired`)
//!    unless `SIGNER_ALLOW_NO_AUTH=1` explicitly opts into dev/legacy no-auth.
//!  - CR097 (mainnet): `SIGNER_REQUIRE_AUTH=1` (the strict/mainnet profile)
//!    OVERRIDES the no-auth hatch — the box refuses to boot without tokens even
//!    if `SIGNER_ALLOW_NO_AUTH` was set, and `require_bearer` denies every
//!    request in the (then unreachable) no-auth branch. Never serves unauthed.

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::proto::{err_code, ErrorResponse};
use crate::state::DEFAULT_CUSTOMER_ID;

// Note: we used to keep a FORBIDDEN_TOKEN_CHARS constant here for the
// validation loop. Gemini round-3 pointed out that:
//   - `,` is consumed by raw.split(','), so neither token nor customer
//     can contain it after the entry is extracted.
//   - `:` is consumed by trimmed.split_once(':') for the token half,
//     so only the customer half can contain it.
// The only case we still validate is `:` in the customer label —
// returned as AuthConfigError::CustomerLabelHasDelimiter at parse time.
// No need for a separate constant.

/// Configuration error raised by `AuthState::from_env` when the env value
/// is set but invalid. Gemini PR #29 round-4: typed error instead of
/// `assert!` panic for idiomatic propagation through `main()` via `?`.
///
/// Manual Display + std::error::Error impls (workspace has no thiserror
/// dep and we don't want to add one for two variants).
#[derive(Debug)]
pub enum AuthConfigError {
    /// `SIGNER_API_TOKENS` was set but no `token:customer` pair parsed
    /// successfully out of it.
    NoValidEntries,
    /// Customer label contained the `:` delimiter.
    CustomerLabelHasDelimiter(String),
    /// `SIGNER_API_TOKENS` was set but its value is not valid UTF-8. The
    /// operator intended to configure something but produced garbage —
    /// don't silently fall back to no-auth. Gemini PR #29 round-6 catch.
    NotUnicode(std::ffi::OsString),
    /// `SIGNER_API_TOKENS` is unset/empty AND `SIGNER_ALLOW_NO_AUTH` is not
    /// set — fail-CLOSED (design §5.5, round-1 R11). With real tenants a
    /// gateway that signs for "no one" is a cross-tenant hole, so no-auth is
    /// now opt-IN via an explicit flag rather than the silent default.
    AuthRequired,
}

impl std::fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthConfigError::NoValidEntries => write!(
                f,
                "SIGNER_API_TOKENS is set but no valid `token:customer` entries parsed. \
                 Either fix the format (e.g. `tok123:fund-a,tok456:fund-b`) or unset \
                 the variable to run in no-auth mode."
            ),
            AuthConfigError::CustomerLabelHasDelimiter(s) => write!(
                f,
                "SIGNER_API_TOKENS: customer label must not contain `:` (parser delimiter) \
                 or `/` (composite blob-key separator). Got: {:?}",
                s
            ),
            AuthConfigError::NotUnicode(raw) => write!(
                f,
                "SIGNER_API_TOKENS contains non-UTF-8 bytes. The variable is set but \
                 unreadable — likely a shell quoting/encoding error in the systemd \
                 unit. Fix the value or unset the variable to run in no-auth mode. \
                 Raw lossy: {:?}",
                raw.to_string_lossy()
            ),
            AuthConfigError::AuthRequired => write!(
                f,
                "SIGNER_API_TOKENS is unset/empty and SIGNER_ALLOW_NO_AUTH is not set — \
                 refusing to boot in no-auth mode. Set SIGNER_API_TOKENS=token:customer \
                 (per-tenant) for normal operation, or set SIGNER_ALLOW_NO_AUTH=1 to \
                 explicitly opt into the legacy unauthenticated mode (dev only)."
            ),
        }
    }
}

/// The customer id resolved from the bearer token (or [`DEFAULT_CUSTOMER_ID`]
/// in no-auth mode). Inserted into request extensions by [`require_bearer`]
/// and read by every blob-lookup handler to scope blob selection to the
/// authenticated tenant. This is the gateway-side identity used for routing
/// (PR-A); the enclave re-derives identity independently in PR-B.
#[derive(Debug, Clone)]
pub struct ResolvedCustomer(pub String);

/// The RAW bearer token, forwarded to the enclave (PR-B) so the enclave
/// resolves identity ITSELF from its resident registry (the §3 invariant — the
/// gateway never asserts identity; it only relays the opaque token). Distinct
/// from `ResolvedCustomer` (the gateway-side label used for blob ROUTING). In
/// no-auth mode the token is empty and the enclave fails closed (multi-tenant
/// requires auth; no-auth is dev-only).
#[derive(Debug, Clone)]
pub struct RawToken(pub String);

impl std::error::Error for AuthConfigError {}

/// Configured bearer tokens loaded from `SIGNER_API_TOKENS` env at startup.
/// Keyed by token string for O(1) lookup; value is the customer label used
/// only for logging.
///
/// Empty list = no enforcement (backward compat). Operators must populate
/// this to switch the gateway to authenticated mode.
///
/// Storage: Vec<(SHA-256(token), customer_label)> instead of HashMap<String,
/// String>. Gemini PR #29 round-2: HashMap key equality returns early on
/// first byte mismatch, leaking token-prefix information through timing.
/// The new layout iterates ALL stored hashes for every incoming token
/// (O(n) where n is small — 1-3 customers per signer instance per
/// project_signer_pilot_quant_company.md) and uses subtle::ConstantTimeEq
/// for each comparison so per-byte timing cannot be probed.
#[derive(Debug, Clone, Default)]
pub struct AuthState {
    /// (SHA-256(token), customer label). Plain Vec — iteration order is
    /// deterministic, lookup is O(n) but n is tiny.
    hashes: Arc<Vec<([u8; 32], String)>>,
}

impl AuthState {
    /// Construct AuthState by parsing the `SIGNER_API_TOKENS` env var.
    /// Format: `token1:customer-name,token2:another-customer`.
    /// A leading/trailing whitespace on either side of `:` or `,` is trimmed.
    /// Entries without a `:` separator are skipped with a warning (we refuse
    /// to "guess" a customer label — silently is worse than fail-loud here).
    ///
    /// Returns `Err(AuthConfigError)` if `SIGNER_API_TOKENS` is set but:
    ///  - No valid `token:customer` entries parse out of it, OR
    ///  - Any customer label contains `:` (the parser delimiter).
    ///
    /// Gemini PR #29 round-4: switched from `assert!` panic to typed
    /// `Result` so `main()` propagates via `?` and anyhow attaches a
    /// proper context chain, more idiomatic than panic-on-config.
    pub fn from_env() -> Result<Self, AuthConfigError> {
        Self::from_env_var("SIGNER_API_TOKENS")
    }

    /// PR-B: a SEPARATE operator credential tier for `/verify-blob` — operator
    /// tokens, NOT tenant tokens (decision H-severity: tenant tokens reaching
    /// /verify-blob would be a cross-tenant blob-existence oracle). Same parse
    /// + fail-closed semantics as `from_env`, distinct env var.
    pub fn operator_from_env() -> Result<Self, AuthConfigError> {
        Self::from_env_var("SIGNER_OPERATOR_TOKENS")
    }

    /// Parse an AuthState from a named env var (`token:label,…`).
    pub fn from_env_var(var_name: &str) -> Result<Self, AuthConfigError> {
        // Gemini PR #29 round-6: distinguish env::VarError variants. NotPresent
        // (env unset) and Ok("") legitimately mean "no-auth fallback" —
        // operator hasn't configured tokens yet. NotUnicode means the env
        // contains non-UTF8 bytes — operator INTENDED to set the value but
        // produced garbage. Fail-loud rather than silently no-auth.
        let raw = match std::env::var(var_name) {
            Ok(v) if !v.trim().is_empty() => v,
            Ok(_) | Err(std::env::VarError::NotPresent) => {
                // Fail-CLOSED (design §5.5 / round-1 R11): no-auth is opt-IN.
                // `SIGNER_ALLOW_NO_AUTH=1` is the explicit, safe-default-absent
                // escape hatch for legacy/dev; anything else (unset, "0", "")
                // means "auth required" and we refuse to boot.
                //
                // CR097 (mainnet fail-closed): `SIGNER_REQUIRE_AUTH=1` — the
                // mainnet/strict profile — OVERRIDES the no-auth hatch. A
                // strict-regime box must NEVER run unauthenticated, even if
                // `SIGNER_ALLOW_NO_AUTH` was set by mistake: REQUIRE_AUTH wins
                // and we refuse to boot without tokens.
                if env_flag_enabled("SIGNER_ALLOW_NO_AUTH")
                    && !env_flag_enabled("SIGNER_REQUIRE_AUTH")
                {
                    tracing::warn!(
                        event = "auth_disabled",
                        "SIGNER_API_TOKENS unset and SIGNER_ALLOW_NO_AUTH=1 — gateway \
                         running in NO-AUTH mode. Anyone who can reach :8443 directly \
                         can request signing. Dev only; never in a tenant deployment."
                    );
                    return Ok(Self::default());
                }
                return Err(AuthConfigError::AuthRequired);
            }
            Err(std::env::VarError::NotUnicode(raw)) => {
                return Err(AuthConfigError::NotUnicode(raw));
            }
        };
        let mut hashes: Vec<([u8; 32], String)> = Vec::new();
        for entry in raw.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (token, customer) = match trimmed.split_once(':') {
                Some((t, c)) => (t.trim().to_owned(), c.trim().to_owned()),
                None => {
                    tracing::warn!(
                        event = "auth_token_no_label",
                        entry = %trimmed,
                        "SIGNER_API_TOKENS entry without `:customer` label — skipped"
                    );
                    continue;
                }
            };
            if token.is_empty() || customer.is_empty() {
                tracing::warn!(
                    event = "auth_token_empty_field",
                    "SIGNER_API_TOKENS entry has empty token or customer — skipped"
                );
                continue;
            }
            // Gemini PR #29 round-2 parser-fragility catch: validate that
            // only the customer label needs an explicit check. The split
            // pipeline already guarantees the others (Gemini round-3):
            //   raw.split(',') → no entry can contain ','
            //   trimmed.split_once(':') → token (the left half) cannot
            //     contain ':' (the splitter consumes the first ':')
            //   customer (the right half) MAY still contain ':' if the
            //     operator wrote `tok:cust:wat` — that's the only case
            //     this check is for.
            // `:` is the parser delimiter; `/` is the composite blob-key
            // separator (`blob_key` = `{customer}/{stem}`). A label containing
            // either would silently mis-route — a `/` label resolves to a
            // never-loaded composite key (all-400, no boot error). Reject both
            // loudly at parse time (review F2).
            if customer.contains(':') || customer.contains('/') {
                return Err(AuthConfigError::CustomerLabelHasDelimiter(customer));
            }
            // F3: a token mapping to the legacy default namespace shares the
            // flat single-tenant blobs — almost always an operator mistake in
            // enforcing mode. Warn loudly (don't hard-fail: a migration might
            // intend it).
            if customer == DEFAULT_CUSTOMER_ID {
                tracing::warn!(
                    event = "auth_customer_is_default",
                    "a SIGNER_API_TOKENS entry maps to DEFAULT_CUSTOMER_ID — it will \
                     share the legacy flat single-tenant blobs; intended only during \
                     migration"
                );
            }
            // Hash the token once at parse time. The plaintext token is
            // dropped before this function returns — only the SHA-256
            // digest sits in memory thereafter. Smaller blast radius if a
            // memory dump leaks AuthState.
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            hashes.push((digest, customer));
        }
        // Gemini PR #29 round-1 HIGH catch: fail-loud if env was SET but
        // every entry was malformed → silently falling back to no-auth
        // mode is a fail-open bug. Round-4 swapped this from assert! to
        // typed Result so main() handles via anyhow's `?` rather than
        // a panic.
        if hashes.is_empty() {
            return Err(AuthConfigError::NoValidEntries);
        }
        tracing::info!(
            event = "auth_enabled",
            token_count = hashes.len(),
            "SIGNER_API_TOKENS loaded — bearer auth ENFORCED on /sign"
        );
        Ok(Self {
            hashes: Arc::new(hashes),
        })
    }

    /// Returns true if auth is enforced (at least one token configured).
    pub fn enforcing(&self) -> bool {
        !self.hashes.is_empty()
    }

    /// Returns the customer label for a matching token, or None.
    ///
    /// Constant-time: hashes the incoming token, then iterates ALL stored
    /// hashes (never early-exit) calling subtle::ConstantTimeEq on each.
    /// Match index is selected branch-free via a bitmask on a sentinel
    /// `usize::MAX`, so no conditional branch leaks "which slot matched"
    /// via timing inside the loop. The single post-loop branch on "did
    /// any match" is unavoidable (we must return `Option<&str>`), but
    /// that's the same signal the HTTP response code reveals anyway
    /// (200 vs 401) — no additional information leak. Gemini PR #29
    /// round-2 (CT compare) + round-3 (branch-free update).
    pub fn lookup(&self, token: &str) -> Option<&str> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let incoming: [u8; 32] = hasher.finalize().into();

        // Branch-free conditional update. `eq` is 1 if hash matches, 0
        // otherwise. `mask = (eq).wrapping_neg()` is all-ones if eq=1,
        // all-zeros if eq=0. Then:
        //   matched_idx = (matched_idx & !mask) | (i & mask)
        // is "i if eq else matched_idx" with no branch — same number of
        // instructions every iteration, no path divergence.
        //
        // SENTINEL: usize::MAX means "no match yet". We use the bottom
        // bits of i so usize::MAX & !mask masks out the previous sentinel
        // when a match happens. n ≤ 3 in practice (1-3 customers per
        // signer instance), so we never approach usize::MAX as a real i.
        let mut matched_idx: usize = usize::MAX;
        for (i, (h, _label)) in self.hashes.iter().enumerate() {
            let eq: u8 = h.ct_eq(&incoming).unwrap_u8();
            let mask: usize = (eq as usize).wrapping_neg();
            matched_idx = (matched_idx & !mask) | (i & mask);
        }
        if matched_idx == usize::MAX {
            None
        } else {
            Some(self.hashes[matched_idx].1.as_str())
        }
    }

    /// Boot-time hygiene (crypto-panel #211 LOW#2): true if ANY configured token
    /// is present in BOTH this and `other`. A token that is simultaneously a
    /// tenant and an operator credential collapses the two-tier isolation (it
    /// could reach the `/sign` venues AND `/sign-data` + `/verify-blob`), so
    /// `main()` refuses to boot on an overlap. Boot-time config check over
    /// trusted input — a plain hash compare, not the per-request constant-time
    /// path (there is no attacker-supplied token here).
    pub fn shares_token_with(&self, other: &AuthState) -> bool {
        self.hashes
            .iter()
            .any(|(h, _)| other.hashes.iter().any(|(o, _)| h == o))
    }
}

/// Axum middleware: require a valid `Authorization: Bearer <token>` header.
///
/// Auth is enforced only when `AuthState::enforcing()` is true (at least one
/// token configured). When not enforcing, every request passes through with
/// a one-shot WARN log per startup — see AuthState::from_env.
pub async fn require_bearer(
    State(auth): State<AuthState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if !auth.enforcing() {
        // CR097 defense-in-depth: a strict/mainnet-profile box
        // (`SIGNER_REQUIRE_AUTH=1`) must NEVER serve unauthenticated. `from_env`
        // already refuses to boot without tokens under REQUIRE_AUTH, so this
        // branch is normally unreachable there — but if the AuthState is ever
        // empty at runtime under the strict profile, DENY every request rather
        // than passing it through. Cold path only (enforcing mode skips it), so
        // the per-request env read is not on the hot path.
        if env_flag_enabled("SIGNER_REQUIRE_AUTH") {
            tracing::warn!(
                event = "auth_denied_strict_no_auth",
                "no-auth mode rejected under SIGNER_REQUIRE_AUTH — SIGNER_API_TOKENS required"
            );
            return unauthorized();
        }
        // No-auth mode (only reachable when SIGNER_ALLOW_NO_AUTH=1 — from_env
        // fails-closed otherwise). Resolve every request to the legacy default
        // customer so the composite-key blob lookup still finds the flat
        // single-tenant blobs.
        req.extensions_mut()
            .insert(ResolvedCustomer(DEFAULT_CUSTOMER_ID.to_owned()));
        // No bearer token in no-auth mode → empty opaque token → the enclave
        // (PR-B) fails closed (no tenant resolves). Multi-tenant needs auth.
        req.extensions_mut().insert(RawToken(String::new()));
        return next.run(req).await;
    }

    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    // Gemini PR #29 round-1: accept the scheme case-insensitively per
    // Postel's Law (RFC 7235 §2.1 — auth scheme is case-insensitive).
    // Position-aware match on the 7-char "Bearer " prefix instead of
    // contains/find so we keep boundary safety: only the literal at the
    // start of the header counts.
    let token = match header {
        Some(h) if h.len() > 7 && h[..7].eq_ignore_ascii_case("Bearer ") => h[7..].trim(),
        Some(_) => {
            tracing::warn!(event = "auth_header_malformed", "missing Bearer prefix");
            return unauthorized();
        }
        None => {
            tracing::warn!(event = "auth_header_missing", "no Authorization header");
            return unauthorized();
        }
    };

    if token.is_empty() {
        tracing::warn!(event = "auth_token_empty", "Bearer with empty token");
        return unauthorized();
    }

    // Resolve to an OWNED label first so the immutable borrow of `req` (via
    // `token`/`header`) ends before we mutate `req`'s extensions below.
    let customer = match auth.lookup(token) {
        Some(customer) => customer.to_owned(),
        None => {
            // Do NOT log the token string — a leaked log lets an attacker
            // see what they actually sent.
            tracing::warn!(
                event = "auth_token_unknown",
                "bearer token did not match any configured customer"
            );
            return unauthorized();
        }
    };
    tracing::debug!(event = "auth_ok", customer = %customer, "bearer token accepted");
    // Capture the RAW token (owned) BEFORE mutating req — forwarded to the
    // enclave for its own identity resolution (PR-B §3).
    let raw = token.to_owned();
    // Hand the resolved tenant id to the handlers. This is the ONLY source of
    // the customer dimension for blob routing — the request body never
    // supplies it (confused-deputy guard, design §3).
    req.extensions_mut().insert(ResolvedCustomer(customer));
    req.extensions_mut().insert(RawToken(raw));
    next.run(req).await
}

/// True iff `var` is set to an explicit truthy value (`1`/`true`/`yes`, case-
/// insensitive). Unset, empty, `0`, `false` → false. Used for boolean opt-in
/// flags where the safe default is "off".
fn env_flag_enabled(var: &str) -> bool {
    std::env::var(var)
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

fn unauthorized() -> Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        Json(ErrorResponse::new(err_code::UNAUTHORIZED)),
    )
        .into_response()
}

/// The raw bearer token for a customer label, read from the gateway's OWN
/// environment (`SIGNER_API_TOKENS`, the same value `from_env` hashed at boot).
///
/// Why this exists: the enclave resolves identity from the OPAQUE TOKEN it is
/// handed (registry.rs) — there is no "operator signs on behalf of tenant"
/// identity, by design. So a gateway-side job that must cancel a tenant's
/// orders (the kill-switch reconcile, PR-2) can only do so AS the tenant, with
/// the tenant's token. The gateway already holds that token in its unit
/// environment — this reads it back, matching on the customer label (never
/// "the first entry": the 08-19 box script took the first token and hit a
/// wrong-tenant `exchange_blob_missing`). Returned zeroized-on-drop; callers
/// must not log or persist it. `None` when the label has no token.
pub fn raw_token_for_customer(label: &str) -> Option<zeroize::Zeroizing<String>> {
    use zeroize::Zeroize;
    // The whole variable holds EVERY tenant's token: keep it in a buffer we wipe
    // on the way out, not a plain String left on the heap (Gemini).
    let mut raw = zeroize::Zeroizing::new(std::env::var("SIGNER_API_TOKENS").ok()?);
    let mut found = None;
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        // Same split as `from_env_var` (`split_once`, not `rsplit_once`): the
        // boot parser refuses labels containing ':', so both derive identical
        // fields; sharing the direction removes the implicit dependency on
        // that rule (CodeRabbit). Empty token or label: skipped exactly as the
        // boot parser skips them — an entry like `:alice` must not yield an
        // empty opaque token that fails at the enclave instead of here.
        let Some((token, cust)) = trimmed.split_once(':') else {
            continue;
        };
        let (token, cust) = (token.trim(), cust.trim());
        if token.is_empty() || cust.is_empty() {
            continue;
        }
        if cust == label {
            found = Some(zeroize::Zeroizing::new(token.to_owned()));
            break;
        }
    }
    raw.zeroize();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same env-lock pattern as enclave/handler.rs C18 tests — env vars are
    /// process-wide, cargo runs tests in parallel.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Apply `key=value` (or remove on `None`) WITHOUT taking the lock — caller
    /// must already hold ENV_LOCK. SAFETY: ENV_LOCK serializes all env access
    /// in this module so no other thread observes the mutation.
    fn apply_env(key: &str, value: Option<&str>) {
        unsafe {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            Self::set_many(&[(key, value)])
        }

        /// Set several env vars under ONE lock acquisition. A single test that
        /// needs `SIGNER_API_TOKENS` AND `SIGNER_ALLOW_NO_AUTH` must use this —
        /// calling `set` twice would re-lock the non-reentrant ENV_LOCK and
        /// deadlock.
        fn set_many(pairs: &[(&'static str, Option<&str>)]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let mut saved = Vec::with_capacity(pairs.len());
            for (key, value) in pairs {
                saved.push((*key, std::env::var(key).ok()));
                apply_env(key, *value);
            }
            Self { saved, _lock: lock }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // _lock is still held (field drop order: `saved` before `_lock`).
            for (key, prev) in &self.saved {
                apply_env(key, prev.as_deref());
            }
        }
    }

    #[test]
    fn operator_and_tenant_credentials_are_disjoint() {
        // crypto-panel #211 regression-guard for isolation invariants (a)+(b):
        // a tenant token must NOT authenticate as operator (→ 401 on /sign-data,
        // /verify-blob) and an operator token must NOT authenticate as tenant
        // (→ 401 on the /sign venues). The routers wire each tier to its own
        // AuthState; this locks the credential disjointness those 401s rest on.
        let _g = EnvGuard::set_many(&[
            ("SIGNER_ALLOW_NO_AUTH", None),
            ("SIGNER_API_TOKENS", Some("tenant-tok:cust-a")),
            ("SIGNER_OPERATOR_TOKENS", Some("operator-tok:ops")),
        ]);
        let tenant = AuthState::from_env().expect("tenant auth");
        let operator = AuthState::operator_from_env().expect("operator auth");

        assert_eq!(tenant.lookup("tenant-tok"), Some("cust-a"));
        assert_eq!(
            tenant.lookup("operator-tok"),
            None,
            "operator token must NOT pass tenant auth"
        );
        assert_eq!(operator.lookup("operator-tok"), Some("ops"));
        assert_eq!(
            operator.lookup("tenant-tok"),
            None,
            "tenant token must NOT pass operator auth"
        );

        // LOW#2: disjoint sets do not overlap.
        assert!(!tenant.shares_token_with(&operator));
        assert!(!operator.shares_token_with(&tenant));
    }

    #[test]
    fn require_auth_overrides_allow_no_auth_cr097() {
        // CR097: on the mainnet/strict profile, `SIGNER_REQUIRE_AUTH=1` overrides
        // the `SIGNER_ALLOW_NO_AUTH` dev hatch — the gateway refuses to boot
        // without tokens even if ALLOW_NO_AUTH was set by mistake.
        {
            let _g = EnvGuard::set_many(&[
                ("SIGNER_API_TOKENS", None),
                ("SIGNER_ALLOW_NO_AUTH", Some("1")),
                ("SIGNER_REQUIRE_AUTH", Some("1")),
            ]);
            assert!(
                matches!(AuthState::from_env(), Err(AuthConfigError::AuthRequired)),
                "REQUIRE_AUTH must override ALLOW_NO_AUTH — refuse to boot without tokens"
            );
        }
        // Control: WITHOUT REQUIRE_AUTH, ALLOW_NO_AUTH still opens the dev hatch.
        {
            let _g = EnvGuard::set_many(&[
                ("SIGNER_API_TOKENS", None),
                ("SIGNER_ALLOW_NO_AUTH", Some("1")),
                ("SIGNER_REQUIRE_AUTH", None),
            ]);
            let st = AuthState::from_env().expect("dev no-auth allowed without REQUIRE_AUTH");
            assert!(!st.enforcing(), "no-auth mode → not enforcing");
        }
    }

    #[test]
    fn overlapping_operator_and_tenant_token_is_detected() {
        // LOW#2: a token configured in BOTH tiers collapses the isolation —
        // main() refuses to boot on this. Detection is order-independent.
        let _g = EnvGuard::set_many(&[
            ("SIGNER_ALLOW_NO_AUTH", None),
            (
                "SIGNER_API_TOKENS",
                Some("shared-tok:cust-a,tenant-only:cust-b"),
            ),
            ("SIGNER_OPERATOR_TOKENS", Some("shared-tok:ops")),
        ]);
        let tenant = AuthState::from_env().expect("tenant auth");
        let operator = AuthState::operator_from_env().expect("operator auth");
        assert!(
            tenant.shares_token_with(&operator),
            "must detect the shared token"
        );
        assert!(operator.shares_token_with(&tenant));
    }

    #[test]
    fn unset_env_without_flag_fails_closed() {
        // Fail-CLOSED (design §5.5 / round-1 R11): unset tokens + no
        // SIGNER_ALLOW_NO_AUTH → refuse to boot, not silent no-auth.
        let _g = EnvGuard::set_many(&[("SIGNER_ALLOW_NO_AUTH", None), ("SIGNER_API_TOKENS", None)]);
        let err = AuthState::from_env().expect_err("unset tokens must fail closed");
        assert!(
            matches!(err, AuthConfigError::AuthRequired),
            "got {:?}",
            err
        );
    }

    #[test]
    fn empty_env_without_flag_fails_closed() {
        let _g = EnvGuard::set_many(&[
            ("SIGNER_ALLOW_NO_AUTH", None),
            ("SIGNER_API_TOKENS", Some("   ")),
        ]);
        let err = AuthState::from_env().expect_err("empty tokens must fail closed");
        assert!(
            matches!(err, AuthConfigError::AuthRequired),
            "got {:?}",
            err
        );
    }

    #[test]
    fn unset_env_with_allow_no_auth_flag_runs_open() {
        // Explicit opt-in to legacy no-auth mode (dev only).
        let _g = EnvGuard::set_many(&[
            ("SIGNER_ALLOW_NO_AUTH", Some("1")),
            ("SIGNER_API_TOKENS", None),
        ]);
        let auth = AuthState::from_env().expect("flag set → no-auth allowed");
        assert!(!auth.enforcing());
    }

    #[test]
    fn single_token_parsed() {
        let _g = EnvGuard::set("SIGNER_API_TOKENS", Some("tok123:quant-corp"));
        let auth = AuthState::from_env().expect("from_env should succeed in this test");
        assert!(auth.enforcing());
        assert_eq!(auth.lookup("tok123"), Some("quant-corp"));
        assert_eq!(auth.lookup("tok123 "), None); // exact match, no whitespace tolerance
        assert_eq!(auth.lookup("nope"), None);
    }

    #[test]
    fn multiple_tokens_parsed() {
        let _g = EnvGuard::set(
            "SIGNER_API_TOKENS",
            Some("alpha:fund-a, beta:fund-b ,  gamma:fund-c"),
        );
        let auth = AuthState::from_env().expect("from_env should succeed in this test");
        assert_eq!(auth.lookup("alpha"), Some("fund-a"));
        assert_eq!(auth.lookup("beta"), Some("fund-b"));
        assert_eq!(auth.lookup("gamma"), Some("fund-c"));
    }

    #[test]
    fn malformed_entries_skipped() {
        // 2 valid + 2 malformed (no colon, empty parts) = 2 tokens loaded
        let _g = EnvGuard::set(
            "SIGNER_API_TOKENS",
            Some("valid1:cust-a,no-colon-here,:empty-token,valid2:cust-b,empty-cust:"),
        );
        let auth = AuthState::from_env().expect("from_env should succeed in this test");
        assert!(auth.enforcing());
        assert_eq!(auth.lookup("valid1"), Some("cust-a"));
        assert_eq!(auth.lookup("valid2"), Some("cust-b"));
        // Malformed entries did not pollute the map:
        assert_eq!(auth.lookup("no-colon-here"), None);
        assert_eq!(auth.lookup(""), None);
        assert_eq!(auth.lookup("empty-cust"), None);
    }

    /// Gemini PR #29 round-1 HIGH: env set but every entry malformed
    /// → silent fail-open before this fix. Now MUST panic so the
    /// gateway boot fails loudly.
    /// Gemini PR #29 round-1+round-4: env set but every entry malformed →
    /// Err(NoValidEntries). Previously asserted panic; round-4 typed Result.
    #[test]
    fn all_malformed_entries_returns_error() {
        let _g = EnvGuard::set(
            "SIGNER_API_TOKENS",
            Some("no-colon-1,no-colon-2,:empty-token,empty-cust:"),
        );
        let err = AuthState::from_env().expect_err("should fail with NoValidEntries");
        assert!(
            matches!(err, AuthConfigError::NoValidEntries),
            "got {:?}",
            err
        );
    }

    /// Gemini PR #29 round-2 parser-fragility catch: customer label
    /// containing `:` (a parser delimiter) must panic so the operator
    /// sees the misconfiguration at boot rather than getting silently
    /// wrong customer-label associations later.
    /// Gemini PR #29 round-2+round-4: customer label containing `:` →
    /// Err(CustomerLabelHasDelimiter). split_once(':') splits at FIRST
    /// colon so customer="cust:wat" contains `:`.
    #[test]
    fn customer_label_with_delimiter_returns_error() {
        let _g = EnvGuard::set("SIGNER_API_TOKENS", Some("tok:cust:wat"));
        let err = AuthState::from_env().expect_err("should fail with CustomerLabelHasDelimiter");
        assert!(
            matches!(err, AuthConfigError::CustomerLabelHasDelimiter(ref s) if s == "cust:wat"),
            "got {:?}",
            err
        );
    }

    /// F2: a `/` in the customer label would mis-route via the composite
    /// blob key — must fail loudly at parse time, not silently all-400.
    #[test]
    fn customer_label_with_slash_returns_error() {
        let _g = EnvGuard::set("SIGNER_API_TOKENS", Some("tok:fund/a"));
        let err = AuthState::from_env().expect_err("slash in label must fail closed");
        assert!(
            matches!(err, AuthConfigError::CustomerLabelHasDelimiter(ref s) if s == "fund/a"),
            "got {:?}",
            err
        );
    }

    /// Gemini PR #29 round-2: lookup must be constant-time over the SET
    /// of stored hashes. We can't directly probe timing here (unit tests
    /// don't have nanosecond precision), but we can verify the FUNCTIONAL
    /// shape — a non-matching token of any prefix length returns None.
    #[test]
    fn constant_time_lookup_returns_none_on_mismatch() {
        let _g = EnvGuard::set("SIGNER_API_TOKENS", Some("real-token-xyz:fund-a"));
        let auth = AuthState::from_env().expect("from_env should succeed in this test");
        // Empty token
        assert_eq!(auth.lookup(""), None);
        // Prefix of stored
        assert_eq!(auth.lookup("real"), None);
        assert_eq!(auth.lookup("real-token"), None);
        assert_eq!(auth.lookup("real-token-xy"), None);
        // Full match
        assert_eq!(auth.lookup("real-token-xyz"), Some("fund-a"));
        // One char off
        assert_eq!(auth.lookup("real-token-xyZ"), None);
    }

    /// PR-B round-1 BLOCKING: /verify-blob lives behind a SEPARATE operator
    /// credential tier (`SIGNER_OPERATOR_TOKENS`) in its own router, so a TENANT
    /// token (valid on /sign via `SIGNER_API_TOKENS`) must be REJECTED on
    /// /verify-blob, and an OPERATOR token must pass through. Driven through the
    /// real `require_bearer` middleware on a router wired exactly like
    /// `operator_router` in main.rs — proving the credential split end-to-end,
    /// not just that two AuthStates parse different env vars.
    #[tokio::test]
    async fn operator_router_rejects_tenant_token_accepts_operator() {
        use axum::http::StatusCode;
        use axum::routing::post;
        use axum::Router;
        use tower::ServiceExt;

        async fn stub() -> &'static str {
            "ok"
        }

        let _g = EnvGuard::set_many(&[
            ("SIGNER_API_TOKENS", Some("tenant-tok:fund-a")),
            ("SIGNER_OPERATOR_TOKENS", Some("operator-tok:ops")),
        ]);
        let tenant_auth = AuthState::from_env().expect("tenant tier parses");
        let operator_auth = AuthState::operator_from_env().expect("operator tier parses");
        // Sanity: the two tiers are genuinely disjoint credential sets.
        assert_eq!(tenant_auth.lookup("tenant-tok"), Some("fund-a"));
        assert_eq!(operator_auth.lookup("tenant-tok"), None);

        let app = Router::new().route("/verify-blob", post(stub)).route_layer(
            axum::middleware::from_fn_with_state(operator_auth, require_bearer),
        );

        let call = |bearer: Option<&str>| {
            let mut b = Request::builder().method("POST").uri("/verify-blob");
            if let Some(tok) = bearer {
                b = b.header("authorization", format!("Bearer {tok}"));
            }
            app.clone().oneshot(b.body(Body::empty()).unwrap())
        };

        // (1) A TENANT token is rejected on /verify-blob (the oracle is closed).
        assert_eq!(
            call(Some("tenant-tok")).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "a tenant token must NOT authenticate on /verify-blob"
        );
        // (2) An OPERATOR token passes the middleware through to the handler.
        assert_eq!(
            call(Some("operator-tok")).await.unwrap().status(),
            StatusCode::OK,
            "an operator token must reach /verify-blob"
        );
        // (3) No credential → rejected.
        assert_eq!(call(None).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
}
