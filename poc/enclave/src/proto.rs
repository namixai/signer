//! Wire protocol types for the parent <-> enclave vsock channel.
//!
//! Length-prefix framing: every message on the wire is a 4-byte big-endian
//! `u32` length followed by exactly that many bytes of UTF-8 JSON. The hard
//! cap is enforced by [`MAX_MESSAGE_BYTES`].
//!
//! The `parent` crate carries an identical shape (intentional duplication —
//! we keep the workspace minimal and never ship a "shared types" crate).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroize;

/// Hard ceiling per single framed message (request OR response).
/// 64 KiB is comfortably above any realistic KuCoin order body.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Width of the length prefix on the wire, in bytes.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// AWS SigV4 credentials forwarded by the parent for use inside the enclave.
///
/// Phase 2 ignores these. Phase 3 will use them to call KMS Decrypt and
/// S3 GetObject from inside the enclave (via the vsock-proxy on the parent).
///
/// `Debug` is implemented MANUALLY (not derived) so that accidental
/// `tracing::debug!(?creds, ...)` or panic-message formatting cannot leak
/// the secret access key or session token. Adversarial-mindset doc P0.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .finish()
    }
}

/// Request from parent -> enclave.
///
/// `action` discriminates between flows:
/// - `"ping"` — reply with the literal `"pong"` (smoke test, no signing).
/// - `"sign"` — compute HMAC-SHA256 over the canonical KuCoin string and
///   return only `signature_base64` (Day 2 shape).
/// - `"sign_kucoin"` — Day 3: decrypt a JSON blob `{"key","secret","passphrase"}`
///   and return the full set of KuCoin v2 auth headers in `headers`.
///
/// All non-`action` fields are optional in JSON to keep `ping` payloads tiny.
///
/// `Debug` is MANUAL: `body` and `aws_credentials` are redacted so they can
/// never reach the debug-mode console even if a future caller does
/// `tracing::debug!(?req, ...)`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub action: String,

    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub timestamp_ms: Option<u64>,

    /// Phase 3: S3 object key holding the KMS-encrypted secret blob.
    /// Currently informational only — the parent fetches this from S3 itself
    /// and inlines the bytes via `ciphertext_blob_base64`.
    #[serde(default)]
    pub key_blob_s3_key: Option<String>,
    /// Phase 3: KMS key ID / alias used to decrypt the blob.
    /// Currently informational — kmstool_enclave_cli reads the key id from
    /// the CMS envelope itself.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Phase 3: AWS credentials forwarded by the parent (instance role STS).
    #[serde(default)]
    pub aws_credentials: Option<AwsCredentials>,
    /// Phase 3: ciphertext blob (base64-encoded) of the KMS-encrypted secret.
    /// The parent fetches this from S3 and forwards inline so the enclave
    /// doesn't need its own S3 SigV4 path on Day 2.
    #[serde(default)]
    pub ciphertext_blob_base64: Option<String>,

    /// Phase 1 Week 4: query string for Binance/Bybit signing (no leading `?`).
    /// KuCoin signs over path + body; Binance/Bybit sign over the query
    /// string separately. The parent extracts user-provided query params
    /// and passes them here so canonical-string assembly is unambiguous.
    #[serde(default)]
    pub query: Option<String>,

    /// Phase 1 Stage 2: EIP-712 (Hyperliquid family) action payload.
    ///
    /// Hyperliquid signs over `keccak256(msgpack(action) || nonce || vault)`,
    /// not over the HTTP request line. The gateway forwards the action JSON
    /// here verbatim — the enclave is the only component that ever sees the
    /// canonical msgpack encoding the signature commits to.
    ///
    /// We take a `serde_json::Value` (not a free-form `String`) so the
    /// enclave deserialises with strict JSON semantics before re-encoding
    /// as msgpack, eliminating an entire class of "string-mutation in
    /// transit" attacks where the gateway re-emits the JSON differently.
    ///
    /// Named `hl_action` (not `action`) to avoid clashing with the existing
    /// `action: String` discriminator field above.
    #[serde(default)]
    pub hl_action: Option<serde_json::Value>,

    /// Phase 1 Stage 2: Hyperliquid nonce — wall-clock milliseconds since
    /// the Unix epoch, encoded big-endian over 8 bytes during actionHash
    /// assembly. Distinct from `timestamp_ms` so HMAC and EIP-712 venues
    /// can be skew-validated separately by future code paths.
    #[serde(default)]
    pub nonce: Option<u64>,

    /// Phase 1 Stage 2: optional vault address for sub-vault signing.
    /// `None` or `Some("")` means non-vault — encoded as 20 zero bytes
    /// during actionHash. `Some("0x<40 hex chars>")` encodes those bytes.
    #[serde(default)]
    pub vault_address: Option<String>,
}

impl fmt::Debug for SignRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignRequest")
            .field("action", &self.action)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body", &"[REDACTED]")
            .field("timestamp_ms", &self.timestamp_ms)
            .field("key_blob_s3_key", &self.key_blob_s3_key)
            .field("key_id", &self.key_id)
            .field(
                "aws_credentials",
                &self.aws_credentials.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "ciphertext_blob_base64",
                &self
                    .ciphertext_blob_base64
                    .as_ref()
                    .map(|b| format!("[REDACTED {} chars]", b.len())),
            )
            // Phase 1 Stage 2: action JSON may contain wallet identifiers,
            // sub-account IDs, or order details — redact unconditionally.
            .field(
                "hl_action",
                &self.hl_action.as_ref().map(|_| "[REDACTED]"),
            )
            .field("nonce", &self.nonce)
            .field("vault_address", &self.vault_address)
            .finish()
    }
}

/// Response from enclave -> parent.
///
/// One flat shape covers both Day 2 (`sign`) and Day 3 (`sign_kucoin`):
/// - `signature_base64` is populated by the Day 2 `sign` action and stays
///   present (empty string on Day 3 / on errors) so the wire layout never
///   gains a backwards-incompatible field.
/// - `headers` is populated by the Day 3 `sign_kucoin` action with the full
///   KuCoin v2 auth header set, and is omitted from the JSON otherwise.
/// - `error` is `None` on success, or a short generic code on failure
///   (never internal details — see adversarial-mindset doc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    /// Phase 1 Stage 2: EIP-712 signature components for Hyperliquid family
    /// venues. `None` for HMAC actions, `Some(HlSignature { r, s, v })` for
    /// `sign_hyperliquid_main_*` actions. Kept as a separate optional field
    /// (rather than overloading `headers`) so JSON consumers see a typed
    /// shape and we can grow EIP-712-specific fields without breaking HMAC
    /// callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hl_signature: Option<HlSignature>,
    pub error: Option<String>,
}

/// EIP-712 signature triple `{r, s, v}` for Hyperliquid (and any other
/// EIP-712 venue we add later). Each component is hex-encoded with the
/// `0x` prefix to match the wire shape consumed by the Hyperliquid HTTP
/// API: `{"signature": {"r": "0x...", "s": "0x...", "v": 27|28}}`.
///
/// `Debug` is derived (no secrets in here — these bytes are publicly
/// visible by definition once the request is submitted to Hyperliquid).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HlSignature {
    /// 32-byte r component as `0x`-prefixed lowercase hex (66 chars total).
    pub r: String,
    /// 32-byte s component as `0x`-prefixed lowercase hex (66 chars total).
    pub s: String,
    /// Recovery id, Ethereum-style: 27 or 28 (NOT 0/1).
    pub v: u8,
}

impl SignResponse {
    pub fn ok(signature_base64: String) -> Self {
        Self {
            signature_base64,
            headers: None,
            hl_signature: None,
            error: None,
        }
    }

    /// Day 3 success shape for `sign_kucoin`. The signature itself is one of
    /// the header values, so `signature_base64` stays empty to avoid double
    /// emission and so callers don't accidentally consume the bare HMAC
    /// without the surrounding headers.
    pub fn ok_headers(headers: BTreeMap<String, String>) -> Self {
        Self {
            signature_base64: String::new(),
            headers: Some(headers),
            hl_signature: None,
            error: None,
        }
    }

    pub fn err(code: &str) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            hl_signature: None,
            error: Some(code.to_owned()),
        }
    }

    /// Phase 1 Stage 2 success shape for `sign_hyperliquid_main_*` actions.
    /// `signature_base64` is left empty (the EIP-712 signature is exposed via
    /// `hl_signature`, not as a base64 blob) and `headers` is `None` (the
    /// caller submits a JSON body, not auth headers).
    pub fn ok_hl_signature(sig: HlSignature) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            hl_signature: Some(sig),
            error: None,
        }
    }
}

/// Plaintext KuCoin secret, decoded from the JSON blob inside the KMS
/// ciphertext. Only ever lives inside the enclave for the duration of one
/// `sign_kucoin` request.
///
/// Zeroization: `Drop` walks every secret field and overwrites the heap
/// allocation with zeros via `Zeroize` on the underlying `Vec<u8>`. We don't
/// rely on `String::clear()` (it only resets the length, leaving the
/// allocation contents intact) and we don't derive `Zeroize` because deriving
/// it on `String` requires the `serde` feature to take a different code path
/// across crate versions; the explicit impl is auditable.
#[derive(Deserialize)]
pub struct KucoinSecret {
    pub key: String,
    pub secret: String,
    pub passphrase: String,
}

impl KucoinSecret {
    /// True if every field is non-empty. The decryption path uses this to
    /// reject malformed blobs before signing.
    pub fn is_complete(&self) -> bool {
        !self.key.is_empty() && !self.secret.is_empty() && !self.passphrase.is_empty()
    }
}

impl Drop for KucoinSecret {
    fn drop(&mut self) {
        zeroize_string(&mut self.key);
        zeroize_string(&mut self.secret);
        zeroize_string(&mut self.passphrase);
    }
}

impl fmt::Debug for KucoinSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KucoinSecret")
            .field("key", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}

/// Plaintext Binance secret pair `{key, secret}`. No passphrase.
/// Same zeroization contract as `KucoinSecret`.
#[derive(Deserialize)]
pub struct BinanceSecret {
    pub key: String,
    pub secret: String,
}

impl BinanceSecret {
    pub fn is_complete(&self) -> bool {
        !self.key.is_empty() && !self.secret.is_empty()
    }
}

impl Drop for BinanceSecret {
    fn drop(&mut self) {
        zeroize_string(&mut self.key);
        zeroize_string(&mut self.secret);
    }
}

impl fmt::Debug for BinanceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinanceSecret")
            .field("key", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Plaintext Bybit V5 secret pair `{key, secret}`. Identical wire shape to
/// Binance but kept as a separate type so request mis-routing (sending a
/// Binance blob to the Bybit signer) yields a parse error during dev
/// rather than a silent wrong-signature.
#[derive(Deserialize)]
pub struct BybitSecret {
    pub key: String,
    pub secret: String,
}

impl BybitSecret {
    pub fn is_complete(&self) -> bool {
        !self.key.is_empty() && !self.secret.is_empty()
    }
}

impl Drop for BybitSecret {
    fn drop(&mut self) {
        zeroize_string(&mut self.key);
        zeroize_string(&mut self.secret);
    }
}

impl fmt::Debug for BybitSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BybitSecret")
            .field("key", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Plaintext OKX V5 secret triple `{key, secret, passphrase}`.
///
/// OKX V5 uses HMAC-SHA256 like KuCoin / Bybit, but unlike Binance / Bybit
/// (2-field) it requires a third field — `passphrase` — that the customer
/// sets when creating the API key in the OKX UI. Unlike KuCoin where the
/// passphrase is HMAC-encrypted, OKX sends it raw in the
/// `OK-ACCESS-PASSPHRASE` header. From OUR enclave's perspective the field
/// shape is identical to KuCoin (3 strings) but the passphrase semantics
/// differ — we keep a separate type so a mis-routed blob (KuCoin secret
/// posted to OKX or vice versa) produces a parse error rather than a
/// silent wrong-signature.
#[derive(Deserialize)]
pub struct OkxSecret {
    pub key: String,
    pub secret: String,
    pub passphrase: String,
}

impl OkxSecret {
    /// True if every field is non-empty. The decryption path uses this to
    /// reject malformed blobs before signing.
    pub fn is_complete(&self) -> bool {
        !self.key.is_empty() && !self.secret.is_empty() && !self.passphrase.is_empty()
    }
}

impl Drop for OkxSecret {
    fn drop(&mut self) {
        zeroize_string(&mut self.key);
        zeroize_string(&mut self.secret);
        zeroize_string(&mut self.passphrase);
    }
}

impl fmt::Debug for OkxSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OkxSecret")
            .field("key", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}

/// Plaintext Hyperliquid (EIP-712 family) secret. Phase 1 Stage 2.
///
/// The shape carried inside the KMS-encrypted blob is:
/// ```json
/// {
///   "exchange": "hyperliquid_main",
///   "private_key": "0x<64 hex chars>",
///   "wallet_address": "0x<40 hex chars>",
///   "vault_address": null
/// }
/// ```
///
/// `private_key` is a 32-byte secp256k1 private key as `0x`-prefixed hex
/// (66 chars total). `wallet_address` is the Ethereum-style 20-byte address
/// derived from the key — we re-derive it in the enclave and reject the
/// blob if it disagrees (sanity check that the operator put the right key
/// next to the right wallet ID).
///
/// `vault_address` is `None` for non-vault signing (most common case) and
/// `Some("0x<40 hex>")` if the operator is signing on behalf of a vault.
///
/// `exchange` is informational and currently always `"hyperliquid_main"`;
/// future HIP-3 venues would set their own value (e.g. `"hyperliquid_xyz"`).
/// The enclave does NOT consume this field at parse time — the dispatcher
/// in `handler.rs` picks the venue from the action name. We keep it in the
/// blob purely so a human can tell at a glance which exchange a blob was
/// minted for. NOTE: this label is cosmetic and does NOT affect signing — the
/// EIP-712 domain (chainId 1337, phantom agent) is IDENTICAL for every
/// Hyperliquid venue incl. HIP-3 builder dexes; only the asset index differs.
///
/// Zeroization: same model as the HMAC secrets — explicit `Drop` walks the
/// heap and overwrites the backing bytes via `Zeroize` on the `Vec<u8>`.
#[derive(Deserialize)]
pub struct HyperliquidSecret {
    /// Informational venue tag. Not validated.
    #[serde(default)]
    pub exchange: String,
    /// 32-byte secp256k1 private key as `0x`-prefixed hex (66 chars total).
    pub private_key: String,
    /// 20-byte Ethereum-style address as `0x`-prefixed hex (42 chars total).
    /// MUST match `keccak256(uncompressed_pubkey[1..])[12..]` of
    /// `private_key`. Mismatch yields a parse rejection.
    pub wallet_address: String,
    /// Optional vault address as `0x`-prefixed hex. `None` for non-vault
    /// signing.
    #[serde(default)]
    pub vault_address: Option<String>,
}

impl HyperliquidSecret {
    /// True if the secret has the required shape. Reject malformed blobs
    /// before any HMAC / signing work begins.
    pub fn is_complete(&self) -> bool {
        // Private key is exactly 0x + 64 hex chars = 66.
        // Wallet address is 0x + 40 hex chars = 42.
        // Vault, if present, must also be 0x + 40 = 42.
        if self.private_key.len() != 66 || !self.private_key.starts_with("0x") {
            return false;
        }
        if !self.private_key[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        if self.wallet_address.len() != 42 || !self.wallet_address.starts_with("0x") {
            return false;
        }
        if !self.wallet_address[2..]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        {
            return false;
        }
        if let Some(v) = self.vault_address.as_deref() {
            if !v.is_empty() {
                if v.len() != 42 || !v.starts_with("0x") {
                    return false;
                }
                if !v[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                    return false;
                }
            }
        }
        true
    }
}

impl Drop for HyperliquidSecret {
    fn drop(&mut self) {
        zeroize_string(&mut self.exchange);
        zeroize_string(&mut self.private_key);
        zeroize_string(&mut self.wallet_address);
        if let Some(v) = self.vault_address.as_mut() {
            zeroize_string(v);
        }
    }
}

impl fmt::Debug for HyperliquidSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HyperliquidSecret")
            .field("exchange", &self.exchange)
            .field("private_key", &"[REDACTED]")
            // The wallet address is publicly visible by definition once the
            // signed payload reaches Hyperliquid, but we still redact at the
            // log line — it makes a hash trace of decrypted blobs much
            // harder to follow if the KMS path ever leaks log lines into
            // long-term retention.
            .field("wallet_address", &"[REDACTED]")
            .field("vault_address", &self.vault_address.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Asterdex v3 (BNB-chain perp DEX) signing secret.
///
/// Asterdex uses EIP-712 typed-data signing with a `Message(string msg)`
/// envelope (see `_signer/ASTERDEX-EIP712-RECON-2026-05-13.md`). The
/// signing key is a plain secp256k1 PK; the `signer_address` field is
/// the address derived from that PK, stored explicitly so the enclave
/// can sanity-check the blob (drift here = wrong PK/address paired).
///
/// Phase 1 deliberately only supports the case where the signer IS the
/// user (single-account API key). Multi-account / agent setups will
/// require an extension with a separate `user_address` field; not now.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsterdexSecret {
    /// Informational venue tag. Not validated.
    #[serde(default)]
    pub exchange: String,
    /// 32-byte secp256k1 private key as `0x`-prefixed hex (66 chars total).
    pub private_key: String,
    /// 20-byte Ethereum-style address as `0x`-prefixed hex (42 chars total).
    /// MUST match `keccak256(uncompressed_pubkey[1..])[12..]` of
    /// `private_key`. Mismatch yields a parse rejection at handler level.
    pub signer_address: String,
}

impl AsterdexSecret {
    /// True if the secret has the required shape. Reject malformed blobs
    /// before any cryptographic work. Same length / hex-charset checks as
    /// `HyperliquidSecret`.
    pub fn is_complete(&self) -> bool {
        if self.private_key.len() != 66 || !self.private_key.starts_with("0x") {
            return false;
        }
        if !self.private_key[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        if self.signer_address.len() != 42 || !self.signer_address.starts_with("0x") {
            return false;
        }
        if !self.signer_address[2..]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        {
            return false;
        }
        true
    }
}

impl Drop for AsterdexSecret {
    fn drop(&mut self) {
        zeroize_string(&mut self.exchange);
        zeroize_string(&mut self.private_key);
        zeroize_string(&mut self.signer_address);
    }
}

impl fmt::Debug for AsterdexSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsterdexSecret")
            .field("exchange", &self.exchange)
            .field("private_key", &"[REDACTED]")
            .field("signer_address", &"[REDACTED]")
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// UPL v0 — Usenami Policy Language (JSON policy co-encrypted with secret).
// ─────────────────────────────────────────────────────────────────────────
//
// The policy is stored INSIDE the KMS ciphertext alongside the exchange
// secret. This is the critical security invariant: an attacker who
// compromises the gateway (but not KMS) cannot forge, weaken, or swap
// a policy without also re-encrypting the secret with KMS attestation.
//
// The outer KMS plaintext shape becomes:
// ```json
// {
//   "policy": { ... },       // UPL v0 policy — may be absent for legacy blobs
//   "secret": { ... }        // exchange-specific secret (KucoinSecret, etc.)
// }
// ```
//
// Legacy blobs (Phase 1 Stage 1–3) that contain a flat secret without a
// `"policy"` wrapper are treated as UNRESTRICTED — the handler enforces
// no policy constraints. This preserves backward compatibility during the
// migration window. A future flag `require_policy: true` on the gateway
// will make policy mandatory.
//
// Design constraints:
//   - Policy is validated INSIDE the enclave after KMS decrypt, never on
//     the gateway. The gateway is untrusted and could forge a policy if
//     it were sent separately.
//   - All policy fields are optional. Absent field = no constraint. This
//     makes the schema additive — new fields can be added without breaking
//     existing policies.
//   - `allowed_actions` is the primary enforcement lever. A policy that
//     says `["sign_binance"]` will refuse to sign Hyperliquid requests
//     even though the underlying secret might technically support it
//     (defense in depth: wrong blob loaded for wrong exchange).
//   - Size limits are expressed in the asset's native unit (not USD) for
//     v0. USD conversion requires an oracle feed we don't have inside
//     the enclave yet.

/// UPL v0 policy. Co-encrypted with the exchange secret inside a single
/// KMS ciphertext blob. Validated by the enclave after decryption;
/// never touches the gateway.
///
/// Every field is optional. Absent = no constraint (permit all).
///
/// `Debug` is derived: policies contain no secret material (they describe
/// WHAT is allowed, not WHO — the secret half is the WHO). Logging the
/// policy on enforcement failures is actively helpful for debugging
/// mis-configured blobs without leaking keys.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    /// Allowed `action` values for `SignRequest.action`. If present and
    /// non-empty, the enclave rejects any action not in this list BEFORE
    /// touching the secret material.
    ///
    /// Example: `["sign_binance", "sign_okx"]` — this key can only be
    /// used for Binance and OKX HMAC signing. A `sign_hyperliquid_main_order`
    /// request with this blob will get `policy_denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_actions: Option<Vec<String>>,

    /// Allowed HTTP methods. Overrides the global `ALLOWED_METHODS` const.
    /// If absent, the global list applies. Useful for read-only keys that
    /// should only sign GET requests.
    ///
    /// Example: `["GET"]` — key can only be used for signed read endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_methods: Option<Vec<String>>,

    /// Allowed URL path prefixes. If present, the request's `path` must
    /// start with at least one of these prefixes. Absent = all paths.
    ///
    /// Example: `["/api/v1/orders", "/api/v1/position"]` — key can only
    /// hit order and position endpoints, not withdrawal/transfer endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_path_prefixes: Option<Vec<String>>,

    /// Denied URL path prefixes. If present, the request's `path` must NOT
    /// start with any of these. Checked AFTER `allowed_path_prefixes`.
    /// Designed for "allow everything EXCEPT withdrawals" use cases.
    ///
    /// Example: `["/api/v1/withdraw", "/api/v1/transfer"]`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_path_prefixes: Option<Vec<String>>,

    /// Maximum requests per minute. v0: tracked per-key inside the enclave
    /// with a simple sliding window counter. Absent = unlimited.
    ///
    /// NOTE: v0 defines the schema only; enforcement is deferred to v0.1
    /// because stateful rate-limiting inside a stateless enclave requires
    /// a decision on counter persistence (in-memory with restart reset,
    /// or vsock-reported to gateway for durable tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_minute: Option<u32>,

    /// Human-readable label for this policy. Not enforced, just logged
    /// on policy violations for operator debugging. Max 128 chars.
    ///
    /// Example: `"binance-readonly-prod"`, `"okx-trading-pilot-quant1"`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Wrapper that co-locates a `Policy` with the raw secret JSON. This is
/// the shape inside the KMS ciphertext blob for UPL-enabled keys.
///
/// The `secret` field is a raw `serde_json::Value` because the enclave
/// doesn't know which exchange-specific type to deserialize into until
/// it reads `SignRequest.action`. Handler code first extracts the policy,
/// then passes `secret` to the exchange-specific parser (which IS
/// `Zeroize`-on-drop).
///
/// SECURITY NOTE (Gemini OSS PR #8 round-1 catch, deferred to UPL v0.1):
/// `serde_json::Value` (and its internal `String`/`Map` types) does NOT
/// implement `Zeroize` on drop. While `serde_json::from_value::<T>` MOVES
/// the inner allocation into the target type (no clone) — so the Value's
/// String becomes T's String which IS zeroized — the brief window during
/// which the Value sits in memory is technically a leak. In the Nitro
/// Enclave model, memory is isolated per-instance and freed pages are
/// not reachable to co-tenants, so the practical impact is minimal. A
/// proper fix uses `serde_json::value::RawValue` with `#[serde(borrow)]`
/// to reference bytes from the underlying `Zeroizing<Vec<u8>>` buffer
/// directly. Tracked as UPL v0.1.
#[derive(Debug, Deserialize)]
pub struct PolicyWrappedSecret {
    pub policy: Policy,
    pub secret: serde_json::Value,
}

/// Result of parsing a KMS-decrypted plaintext: either a policy-wrapped
/// secret (new format) or a raw secret blob (legacy format, no policy).
pub enum ParsedBlob {
    /// New format: policy + secret extracted from wrapper.
    WithPolicy {
        policy: Policy,
        secret_json: serde_json::Value,
    },
    /// Legacy format: flat secret blob, no policy constraints.
    Legacy(serde_json::Value),
}

impl ParsedBlob {
    /// Parse the decrypted KMS plaintext.
    ///
    /// CRITICAL (Gemini OSS PR #8 round-1 review of UPL v0): the previous
    /// "try-wrapped-then-fall-back-to-legacy" approach was fail-open. A
    /// malformed policy-intended blob (e.g., missing `secret` field, or
    /// invalid `policy` JSON) would silently fall through to the legacy
    /// path and bypass policy enforcement entirely.
    ///
    /// The new approach parses once to `serde_json::Value`, inspects the
    /// top-level `"policy"` key, and dispatches to strict deserialization
    /// for the indicated format. If the format is policy-wrapped but the
    /// blob is malformed, we return an error — NEVER fall back to legacy.
    pub fn from_plaintext(plaintext: &[u8]) -> Result<Self, serde_json::Error> {
        let val: serde_json::Value = serde_json::from_slice(plaintext)?;
        if val.get("policy").is_some() {
            // Policy-wrapped format: BOTH `policy` and `secret` MUST parse.
            // If `secret` is missing or `policy` is malformed → error,
            // not fallback.
            let wrapped: PolicyWrappedSecret = serde_json::from_value(val)?;
            Ok(ParsedBlob::WithPolicy {
                policy: wrapped.policy,
                secret_json: wrapped.secret,
            })
        } else {
            // No `"policy"` key at top level → legacy flat secret.
            Ok(ParsedBlob::Legacy(val))
        }
    }

    /// Extract the policy if present.
    pub fn policy(&self) -> Option<&Policy> {
        match self {
            ParsedBlob::WithPolicy { policy, .. } => Some(policy),
            ParsedBlob::Legacy(_) => None,
        }
    }

    /// Extract the raw secret JSON for exchange-specific parsing.
    pub fn secret_json(&self) -> &serde_json::Value {
        match self {
            ParsedBlob::WithPolicy { secret_json, .. } => secret_json,
            ParsedBlob::Legacy(v) => v,
        }
    }
}

/// Best-effort wipe of the heap bytes backing a `String`. We move the bytes
/// out into a `Vec<u8>`, zeroize that, drop it, and assign an empty `String`
/// back so that subsequent uses observe an empty string rather than freed
/// memory. Safe + no `unsafe`.
fn zeroize_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
    // bytes is dropped here, freeing zeroized backing storage.
}

/// Generic error codes returned over the wire.
///
/// We keep this list short and intentionally vague. Internal stack traces,
/// AWS error messages, and decrypt failure reasons must NEVER be echoed
/// back to the caller (per `_signer/06-АТАКУЕМ-СЕБЯ.md`).
pub mod err_code {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const PAYLOAD_TOO_LARGE: &str = "payload_too_large";
    pub const INTERNAL_ERROR: &str = "internal_error";
    /// Phase 3 only — emitted when KMS rejects Decrypt (wrong key/policy).
    pub const KMS_DECRYPT_DENIED: &str = "kms_decrypt_denied";
    /// UPL v0: the co-encrypted policy denies this request. The wire code
    /// is intentionally distinct from `bad_request` so SDK consumers can
    /// distinguish "malformed request" from "well-formed but not permitted
    /// by policy". The response body carries no detail about WHICH rule
    /// fired (adversarial-mindset doc: don't help attackers enumerate the
    /// policy boundary).
    pub const POLICY_DENIED: &str = "policy_denied";
}
