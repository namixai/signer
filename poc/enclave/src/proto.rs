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
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub action: String,

    /// Wire-protocol version (PR-B / D7). `0` = legacy gateway that does not
    /// yet resolve identity in the enclave. The enclave rejects requests below
    /// the required version with a distinct error rather than silently signing
    /// without tenant isolation (R4) once the identity-resolution path lands.
    /// `#[serde(default)]` keeps an old gateway (no field) deserializing as 0.
    #[serde(default)]
    pub proto_version: u8,

    /// Opaque bearer token the gateway forwards UNCHANGED. The enclave hashes
    /// it and resolves `{customer_id, allowed_venues}` from its own resident
    /// registry (`registry::resolve`) — this is the SOLE source of the customer
    /// dimension (design §3 / §5.1). The gateway never asserts identity.
    #[serde(default)]
    pub opaque_token: Option<String>,

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

    // PR-B (D7): the gateway-supplied `encryption_context` field is DELETED.
    // The enclave now builds the KMS EncryptionContext ENTIRELY from the
    // identity it resolves from `opaque_token` (registry::ResolvedIdentity::
    // encryption_context). Any reintroduction of a gateway-supplied context is
    // a confused-deputy regression — do NOT re-add this field. `SignRequest`
    // carries `#[serde(deny_unknown_fields)]` so an old gateway that still
    // sends `encryption_context` is REJECTED, not silently ignored.
    /// Phase 1 Week 4: query string for Binance/Bybit signing (no leading `?`).
    /// KuCoin signs over path + body; Binance/Bybit sign over the query
    /// string separately. The parent extracts user-provided query params
    /// and passes them here so canonical-string assembly is unambiguous.
    #[serde(default)]
    pub query: Option<String>,

    /// `/sign/binance-request` (keyless generic primitive): the allow-listed
    /// operation name (`account`, `order`, `cancel`, …). The enclave checks the
    /// `payload` params against a POSITIVE per-op whitelist keyed on this.
    /// `None` for every other action.
    #[serde(default)]
    pub op: Option<String>,
    /// `/sign/binance-request`: the EXACT urlencoded param string to HMAC
    /// (params + timestamp, no signature). Signed byte-for-byte so the result
    /// is identical to a local-HMAC connector. `None` for every other action.
    #[serde(default)]
    pub payload: Option<String>,

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

    /// x402 / EIP-3009 payment-authorization parameters. Present only for
    /// `action == "sign_x402_eip3009"`. Carries only public payment fields
    /// (no key material), so no special zeroization is required.
    #[serde(default)]
    pub x402: Option<X402Request>,

    /// Structured perp-order params (for `sign_<venue>_order` actions). The
    /// canonical string the venue HMAC commits to is built **inside the
    /// enclave** from these fields — the gateway is NEVER trusted with a
    /// pre-built canonical (asterdex-T1 rule: enclave-supplied policy check
    /// must align with the bytes that get signed).
    #[serde(default)]
    pub order: Option<OrderRequest>,

    /// Structured cancel-order params (for `sign_<venue>_cancel` actions).
    #[serde(default)]
    pub cancel: Option<CancelRequest>,

    /// Attested-signed-data (P2): the read-only payload to sign with the
    /// dedicated data-signing key (for `action == "sign_data"`), carried as the
    /// RAW JSON TEXT (not a pre-parsed `Value`). The enclave parses it itself via
    /// `signer::parse_json_no_dup_keys` so it — the trust boundary — both rejects
    /// duplicate object keys (a pre-parsed `Value` would have silently collapsed
    /// them last-wins) and enforces an explicit byte cap before canonicalizing
    /// (canonical-v1 / JCS). The gateway forwards the bytes verbatim. Carries only
    /// public market data — no key material, no zeroization needed.
    #[serde(default)]
    pub data: Option<String>,

    /// Registry-refresh freshness envelope (for `action == "registry_refresh"`).
    /// The signed registry CONTENT arrives KMS-encrypted in
    /// `ciphertext_blob_base64`; this carries the nonce/version/signature the
    /// enclave checks against the challenge it issued (design §5.2 Ruling 3).
    #[serde(default)]
    pub registry_refresh: Option<RegistryRefreshParams>,

    /// AF-2: the agent's Ed25519 signature (64 bytes, hex) over the canonical
    /// order-intent bytes (`handler::build_agent_intent_msg_*`). Verified against
    /// the policy's `intent_pubkey` before the venue signature. Only consulted
    /// for `sign_<venue>_order`/`_cancel` when the policy carries an
    /// `intent_pubkey`; ignored otherwise.
    #[serde(default)]
    pub intent_signature: Option<String>,

    /// AF-2: the per-intent replay nonce for CANCELS (a client-generated UUID —
    /// cancels have no `client_order_id` to double-duty as the nonce). Orders
    /// reuse `order.client_order_id` as the nonce, so this stays `None` for them.
    /// Bound into the canonical intent and deduped in the enclave RAM ledger.
    #[serde(default)]
    pub intent_nonce: Option<String>,

    /// H5 (`action == "attestation"`): hex of the caller-supplied challenge
    /// nonce, bound INTO the NSM attestation document so the caller can prove
    /// freshness (an old cached doc fails their nonce check). Optional — a
    /// nonce-less request still yields a valid (timestamped) doc. `None` for
    /// every other action.
    #[serde(default)]
    pub attestation_nonce: Option<String>,

    /// H5 (`action == "attestation"`): optional hex user-data bound into the
    /// NSM document (e.g. the registry pubkey/version, so the attestation
    /// commits to the running trust root). `None` for every other action.
    #[serde(default)]
    pub attestation_user_data: Option<String>,
}

/// Freshness envelope for a `registry_refresh` request. The Ed25519 signature
/// is over `canonical(nonce ‖ version ‖ sha256(registry_plaintext))`; the
/// enclave KMS-decrypts the registry blob to recover the plaintext it hashes.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RegistryRefreshParams {
    /// Hex of the 32-byte nonce the enclave issued via `registry_challenge`.
    pub nonce_hex: String,
    /// Monotonic registry version (must exceed the last validated version).
    pub version: u64,
    /// Hex of the 64-byte Ed25519 signature by the baked control-plane key.
    pub signature_hex: String,
}

/// Structured perp-order request. Venue-specific units (Binance quantity is in
/// the base asset; OKX `sz` is in contracts) — the **MCP** is responsible for
/// converting from the agent's natural units; the enclave commits to whatever
/// `qty` string arrives, but enforces it against `Policy.order_caps`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OrderRequest {
    /// Venue symbol exactly as the venue expects it (`BTCUSDT` for Binance
    /// futures; `BTC-USDT-SWAP` for OKX perp). The enclave does not normalize.
    pub symbol: String,
    /// `"buy"` or `"sell"` (lowercased for ergonomics; the canonical builder
    /// uppercases for Binance and keeps lowercase for OKX).
    pub side: String,
    /// Decimal string. For Binance futures = base-asset quantity; for OKX
    /// perp = number of contracts.
    pub qty: String,
    /// `"market"`, `"limit"`, `"fok"`, `"ioc"`, or `"post_only"`.
    pub ord_type: String,
    /// Decimal string price. Required for non-`market` types, rejected otherwise.
    #[serde(default)]
    pub price: Option<String>,
    /// One-way-mode reduce-only flag (Binance). Hedge mode (positionSide) is
    /// out of scope for v0 — operators stay in one-way.
    #[serde(default)]
    pub reduce_only: bool,

    /// Client-supplied idempotency key (PR-B — closes the /hedge retry
    /// double-fire escalation). Bound INTO the canonical signed body
    /// (Binance `newClientOrderId`, OKX `clOrdId`), so a retried order with
    /// the same id is deduplicated by the venue instead of opening a second
    /// position. Optional + `#[serde(default)]` so pre-idempotency callers and
    /// venues that don't support it are unaffected.
    #[serde(default)]
    pub client_order_id: Option<String>,
}

/// Structured cancel-order request. Both Binance (DELETE querystring) and OKX
/// (POST JSON body) require `symbol` alongside `order_id`, so the field is
/// mandatory here.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub symbol: String,
    pub order_id: String,
}

/// x402 / EIP-3009 `TransferWithAuthorization` signing parameters. `value` is
/// a decimal `uint256` string and `nonce` a `0x`-prefixed bytes32 — neither
/// fits a native integer, so both travel as strings and are parsed in the
/// enclave. The token domain (`token_name`/`token_version`/`chain_id`/
/// `token_address`) is caller-supplied because it differs per token+chain
/// (USDC-on-Base ≠ USDC-on-Ethereum).
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct X402Request {
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
            .field("proto_version", &self.proto_version)
            .field("has_opaque_token", &self.opaque_token.is_some())
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

/// Attested-signed-data response: the data signature + the attested data-signing
/// public key in BOTH wire forms (CTO decision b). Buyers ecrecover the signer
/// from `(digest, signature)` and assert the recovered address == `pubkey_address`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedDataResponse {
    pub signature: HlSignature,
    pub pubkey_compressed: String,
    pub pubkey_address: String,
}

/// Attested-data PROVISIONING (Option-1) success shape for
/// `action == "provision_data_key"`. The data key is born + sealed inside the
/// enclave; this is what the one-shot provisioning client persists: the sealed
/// envelope blob (base64 of the v2 `{version,wrapped_dek,nonce,ciphertext}` JSON
/// → written to `secrets/attested-data/data-signing.enc`) plus the public key in
/// both wire forms (recorded as `SIGNER_DATA_PUBKEY` / `SIGNER_DATA_ADDRESS` and
/// published at `/attestation`). The private key NEVER leaves the enclave except
/// sealed under KMS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionDataKeyResponse {
    /// Base64 of the sealed v2 envelope JSON blob.
    pub envelope_b64: String,
    pub pubkey_compressed: String,
    pub pubkey_address: String,
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
    /// Attested-signed-data (P2): the data signature + the attested data-signing
    /// public key (both wire forms). `Some` only for `action == "sign_data"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested: Option<AttestedDataResponse>,
    /// Attested-data provisioning (Option-1): the sealed data-key envelope +
    /// pubkey. `Some` only for `action == "provision_data_key"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provision: Option<ProvisionDataKeyResponse>,
    pub error: Option<String>,
    /// C24 (adversarial review 2026-05-18): SHA-256 of the canonical policy JSON,
    /// hex-encoded. Customers verify the enclave loaded their intended
    /// policy, not a swapped permissive one. `None` for legacy blobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Path B-lite (Stage 4 pre-flight): SHA-256 of the decrypted plaintext
    /// for the `verify_blob` action. Hex-encoded. Operator-side verification
    /// that the blob can be decrypted by the attested enclave WITHOUT ever
    /// exporting the plaintext (forensic-safe). `None` for sign actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_sha256: Option<String>,
    /// Path B-lite: length in bytes of the plaintext that produced
    /// `plaintext_sha256`. Surfaced to the operator so the verify script
    /// can sanity-check obvious truncation (e.g., 0 bytes ≠ valid secret).
    /// `None` for sign actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_len: Option<u64>,

    /// For `sign_<venue>_order` / `sign_<venue>_cancel` flows: the canonical
    /// venue-native string the enclave built and signed. Returned so the
    /// gateway can forward it on the wire byte-for-byte — critical for OKX
    /// where re-serializing the JSON body invalidates the HMAC, and for
    /// Binance where the gateway appends `&signature=<hex>` to this exact
    /// string to form the final POST body / DELETE querystring. `None` for
    /// header-only sign flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_body: Option<String>,

    /// H5 (`action == "attestation"`): base64 of the NSM-signed COSE
    /// attestation document (AWS Nitro Attestation PKI). PUBLIC — carries
    /// PCRs + certificate chain, no secret material — so it is NOT wiped in
    /// `Drop`. `None` for every other action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_document_b64: Option<String>,
}

/// Gemini #78 (wave-2): the enclave's own `SignResponse` holds sensitive
/// material — `headers` (X-MBX-APIKEY + the HMAC signature), `signature_base64`,
/// and `canonical_body` (order qty/price). `String`/`BTreeMap` don't zeroize on
/// drop, so once serde has serialized the response onto the vsock wire and the
/// struct is dropped, those bytes linger in enclave heap (readable via a
/// post-mortem dump / use-after-free oracle). The gateway-side mirror structs
/// already wipe on drop (`SignHttpResponse`, `SignBinance*Response`); this
/// closes the same hole one layer deeper, inside the enclave. Pattern mirrors
/// the `*Secret` `Drop` impls below.
impl Drop for SignResponse {
    fn drop(&mut self) {
        zeroize_string(&mut self.signature_base64);
        if let Some(headers) = self.headers.as_mut() {
            for v in headers.values_mut() {
                zeroize_string(v);
            }
        }
        if let Some(canonical) = self.canonical_body.as_mut() {
            zeroize_string(canonical);
        }
        if let Some(hl) = self.hl_signature.as_mut() {
            // r/s become public once the order reaches Hyperliquid, but wipe them
            // anyway for defense-in-depth + parity with the gateway-side
            // `HlSignatureWire`/`HlSignatureVsock` (both `ZeroizeOnDrop`). `v` is
            // a 1-byte recovery id, not sensitive. (Always `None` on HMAC venues
            // like the Binance trade-signing path.)
            zeroize_string(&mut hl.r);
            zeroize_string(&mut hl.s);
        }
    }
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
            policy_hash: None,
            plaintext_sha256: None,
            plaintext_len: None,
            canonical_body: None,
            attested: None,
            provision: None,
            attestation_document_b64: None,
        }
    }

    /// Path B-lite (Stage 4 pre-flight): success shape for `verify_blob`.
    /// Plaintext is computed inside the enclave, hashed, then dropped
    /// (Zeroizing wipes it). Only the hex SHA-256 reaches the wire.
    pub fn ok_verify_blob(plaintext_sha256_hex: String, plaintext_len: u64) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            hl_signature: None,
            error: None,
            policy_hash: None,
            plaintext_sha256: Some(plaintext_sha256_hex),
            plaintext_len: Some(plaintext_len),
            canonical_body: None,
            attested: None,
            provision: None,
            attestation_document_b64: None,
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
            policy_hash: None,
            plaintext_sha256: None,
            plaintext_len: None,
            canonical_body: None,
            attested: None,
            provision: None,
            attestation_document_b64: None,
        }
    }

    pub fn err(code: &str) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            hl_signature: None,
            error: Some(code.to_owned()),
            policy_hash: None,
            plaintext_sha256: None,
            plaintext_len: None,
            canonical_body: None,
            attested: None,
            provision: None,
            attestation_document_b64: None,
        }
    }

    /// H5 success shape for `action == "attestation"`: the base64 NSM-signed
    /// COSE document. `signature_base64` stays empty (this response carries no
    /// venue signature) and no secret material is present.
    pub fn ok_attestation(attestation_document_b64: String) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            hl_signature: None,
            error: None,
            policy_hash: None,
            plaintext_sha256: None,
            plaintext_len: None,
            canonical_body: None,
            attested: None,
            provision: None,
            attestation_document_b64: Some(attestation_document_b64),
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
            policy_hash: None,
            plaintext_sha256: None,
            plaintext_len: None,
            canonical_body: None,
            attested: None,
            provision: None,
            attestation_document_b64: None,
        }
    }

    /// Attested-signed-data (P2) success shape for `action == "sign_data"`.
    /// `signature_base64` empty; the signature + attested pubkey live in `attested`.
    pub fn ok_attested_data(attested: AttestedDataResponse) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            hl_signature: None,
            error: None,
            policy_hash: None,
            plaintext_sha256: None,
            plaintext_len: None,
            canonical_body: None,
            attested: Some(attested),
            provision: None,
            attestation_document_b64: None,
        }
    }

    /// Attested-data PROVISIONING success shape for `action == "provision_data_key"`.
    pub fn ok_provision(provision: ProvisionDataKeyResponse) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            hl_signature: None,
            error: None,
            policy_hash: None,
            plaintext_sha256: None,
            plaintext_len: None,
            canonical_body: None,
            attested: None,
            provision: Some(provision),
            attestation_document_b64: None,
        }
    }

    pub fn with_policy_hash(mut self, hash: Option<String>) -> Self {
        self.policy_hash = hash;
        self
    }

    /// Attach the venue-canonical body string the enclave just signed (Binance
    /// urlencoded query, OKX exact JSON, etc) so the gateway can forward it
    /// byte-for-byte to the venue.
    pub fn with_canonical_body(mut self, body: String) -> Self {
        self.canonical_body = Some(body);
        self
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// minted for. NOTE: this label is purely cosmetic and does NOT affect
/// signing — the EIP-712 domain (chainId 1337, phantom agent) is IDENTICAL
/// for every Hyperliquid venue including HIP-3 builder dexes; only the order's
/// asset index differs. See `hyperliquid_main_domain_separator`.
///
/// Zeroization: same model as the HMAC secrets — explicit `Drop` walks the
/// heap and overwrites the backing bytes via `Zeroize` on the `Vec<u8>`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
/// envelope (see the internal Asterdex EIP-712 recon notes). The
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

    /// ZN-204: Allowed Asterdex API endpoints (exact path match).
    /// If present, the enclave rejects any `sign_asterdex` request whose
    /// `path` is not in this list. Absent = all endpoints allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_asterdex_endpoints: Option<Vec<String>>,

    /// x402 / EIP-3009 spend-cap clause. **MANDATORY + fail-closed (CR050):**
    /// `sign_x402_eip3009` signs a withdrawal primitive, so an ABSENT clause (or
    /// a clause missing `max_value` / `allowed_recipients`) makes the enclave
    /// refuse with `policy_required` — never "unbounded". When present and
    /// complete, the request is constrained: `chain_id` / `token_address` must
    /// match (if set), `value` ≤ `max_value`, and `to` ∈ `allowed_recipients`.
    /// Covered by the policy signature (it sits before the signature fields), so
    /// the caps cannot be stripped without invalidating the TOFU signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x402: Option<X402Policy>,

    /// Per-asset / per-signature order caps. A `sign_<venue>_order` request
    /// must (1) target a symbol that appears in this list, and (2) have
    /// `qty` ≤ the entry's `max_qty`. **Per-period rate caps (`max_orders_per_hour`
    /// etc.) are intentionally NOT enforced in v0** — stateful counters in a
    /// stateless enclave need the same persistence design that UPL's
    /// `max_requests_per_minute` is deferred on. Documented gap: an attacker
    /// with a compromised gateway can replay up to the per-signature cap as
    /// fast as the enclave can sign; rate-limit at the gateway is the v0
    /// mitigation until stateful UPL ships.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_caps: Option<Vec<OrderAssetCap>>,

    /// CR053 (ZN-202): allow-list of Hyperliquid vault addresses this key may
    /// trade. EVM addresses (`0x` + 40 hex). When present, a HL order/cancel
    /// whose `vault_address` is set MUST be in this list (constant-time,
    /// parse-normalized) — closes the "vault taken from the request, not
    /// policy-bound" gap. A request with NO vault (the key's own main account)
    /// is unaffected. Absent = no vault constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_vaults: Option<Vec<String>>,

    /// CR053: per-asset Hyperliquid order-size caps. HL orders identify the coin
    /// by integer ASSET INDEX (`orders[].a`), not a symbol — so the symbol-keyed
    /// `order_caps` (HMAC venues) cannot bind a HL order. When present, every
    /// order in a `sign_hyperliquid_main_order` action must have its `a` listed
    /// here and its size `orders[].s` ≤ `max_size`; an order for an unlisted
    /// asset (or oversize) is denied fail-closed. Absent = no HL size cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hl_order_caps: Option<Vec<HlOrderCap>>,

    /// Phase 0 TOFU: Ed25519 public key (32 bytes, hex-encoded) of the
    /// customer who signed this policy. When present alongside
    /// `policy_signature`, the enclave verifies the signature and pins
    /// the pubkey on first use per S3 key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey: Option<String>,

    /// Phase 0 TOFU: Ed25519 signature (64 bytes, hex-encoded) over the
    /// canonical policy JSON (serde_json with preserve_order, excluding
    /// `signer_pubkey`, `policy_signature` and `policy_authority_sig`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_signature: Option<String>,

    /// PR-D1 (mainnet floor-gate): Ed25519 signature (64 bytes, hex) by the
    /// enclave's BAKED policy-authority key (`SIGNER_POLICY_PUBKEY`) over a
    /// DOMAIN-SEPARATED, tenant-bound message (see
    /// `handler::policy_authority_message`). Distinct from the TOFU
    /// `policy_signature` (customer-supplied, trust-on-first-use): this proves
    /// the policy came from OUR off-box control-plane, so a partner who
    /// KMS-encrypts their own blob (Option-1 import) cannot swap in a policy
    /// that drops the withdrawal-deny / caps floor. REQUIRED for money-venues
    /// when `SIGNER_REQUIRE_POLICY=1`; ignored otherwise. Excluded from the
    /// canonical signable bytes (a signature cannot cover itself).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_authority_sig: Option<String>,

    /// AF-2 (gateway-tamper defence): the AGENT's Ed25519 public key (32 bytes,
    /// hex), bound in the policy so it is un-forgeable under the authority
    /// signature (this field IS covered by `policy_authority_sig` — it is not in
    /// the excluded set, so a gateway cannot swap it without invalidating the
    /// authority sig). When PRESENT, `sign_<venue>_order`/`_cancel` requires a
    /// valid agent signature (`SignRequest.intent_signature`) over the FULL
    /// canonical order intent (symbol/side/qty/price/reduce_only/ord_type/
    /// client_order_id + tenant/venue/action/timestamp/nonce) BEFORE the venue
    /// signature — so a compromised gateway that flips side/price/reduce_only
    /// within the qty cap is refused. ABSENT = opt-in not enabled: current
    /// behaviour (the cap alone bounds the order); such a money-venue policy is
    /// tracked as AF-2-EXPOSED (a warn is emitted). `#[serde(default,
    /// skip_serializing_if)]` keeps pre-AF-2 policies' canonical bytes — and
    /// hence their authority signatures — byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_pubkey: Option<String>,
}

/// x402 / EIP-3009 spend-cap clause (see `Policy.x402`).
///
/// CR050: x402 signs a `transferWithAuthorization` — a **withdrawal/transfer
/// primitive** (moves the payer key's USDC out), unlike a trading order which
/// only changes positions on the customer's own venue account. For this path
/// the cap is therefore **MANDATORY, not advisory**: `handle_sign_x402_eip3009`
/// requires a present `x402` clause carrying ALL of `chain_id`, `token_address`,
/// `max_value`, AND a non-empty `allowed_recipients`, or it refuses with
/// `policy_required`. "No clause" / "no field" must never mean "no limit" on a
/// money-movement primitive. `chain_id` + `token_address` are mandatory because
/// `value` is in raw token units — a `max_value` cap is meaningless without
/// pinning which token on which chain (final-review LOW). `max_value` is a
/// decimal `uint256` string compared against the request's `value`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct X402Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<String>,
    /// CR050.A: allow-list of permitted EIP-3009 recipients (`to`). EVM
    /// addresses (`0x` + 40 hex); compared constant-time after parsing to
    /// `[u8;20]` (case-insensitive — addresses are normalised by parse, no
    /// checksum dependence). MANDATORY + fail-closed: an absent or empty list
    /// means "sign nothing" (→ `policy_required` / `policy_denied`), never
    /// "any recipient". This is the one control that turns a leaked / prompt-
    /// injected x402 token into "can only pay the real facilitators".
    ///
    /// CAVEAT (same per-signature limitation as `order_caps`, extended to a
    /// withdrawal path): `max_value` is a PER-SIGNATURE ceiling and the enclave
    /// does NOT track nonces or cumulative spend, so N fresh EIP-3009 nonces ×
    /// `max_value` is unbounded TOTAL spend — but only ever to an address in
    /// THIS list, throttled by the gateway's per-key adaptive backoff. Pin
    /// `allowed_recipients` to trusted facilitator(s) that cannot forward to an
    /// attacker, and set `max_value` to a realistic single-payment ceiling. A
    /// cumulative/per-period cap is the real fix (deferred with stateful UPL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_recipients: Option<Vec<String>>,
}

/// One entry in a policy's `order_caps` allow-list. The enclave rejects any
/// `sign_<venue>_order` whose `symbol` is not present here, OR whose `qty`
/// (parsed as a positive decimal) exceeds `max_qty`. Per-period caps are NOT
/// part of this struct — see the comment on `Policy.order_caps`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OrderAssetCap {
    /// Exact venue symbol (`BTCUSDT`, `BTC-USDT-SWAP`, etc). String-equal,
    /// case-sensitive — symbol naming is the customer's responsibility.
    pub symbol: String,
    /// Inclusive upper bound on `OrderRequest.qty`, decimal string. Compared
    /// numerically (lexicographic comparison after normalising sign + zero-
    /// padding the integer part) so `"0.01" ≤ "0.1"` works correctly.
    pub max_qty: String,
    /// B2 (mainnet gate): inclusive upper bound on the PER-ORDER notional
    /// `qty × price`, decimal string, computed exactly in the enclave (no
    /// floats). Absent = no notional bound (max_qty alone applies — existing
    /// policies are unchanged and their canonical bytes/signatures stay
    /// byte-identical via `skip_serializing_if`).
    ///
    /// Semantics when present (fail-closed):
    /// - Orders WITHOUT a price (market-shaped) are DENIED — the enclave has
    ///   no market data, so a market order's notional is unboundable. A
    ///   notional-capped key trades limit-type orders only.
    /// - The bound is `qty × limit price`. For BUY fills this is an upper
    ///   bound on spend (fills at ≤ price); for SELL the base size is already
    ///   bounded by the mandatory `max_qty`. Both dimensions together bound
    ///   the exposure a single signature can create.
    /// - Units are `qty-units × price-units` of the venue: for Binance
    ///   futures that is quote currency (USDT); for OKX perp `sz` is in
    ///   CONTRACTS, so the policy author must scale by the instrument's
    ///   contract value (same "venue-specific units" caveat as
    ///   `OrderRequest.qty`).
    /// - Cancels carry no size and are unaffected.
    ///
    /// Same per-signature limitation as `max_qty`: N signatures × cap is
    /// unbounded cumulative exposure until stateful UPL / the B3 gateway
    /// daily-counter ships.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_notional: Option<String>,
}

/// CR053: one entry in a policy's `hl_order_caps`. Hyperliquid orders carry the
/// coin as an integer ASSET INDEX (`orders[].a`), so this caps by index, not
/// symbol. `max_size` is a decimal string (`orders[].s`) compared numerically
/// via the same `cmp_positive_decimals` used for `OrderAssetCap.max_qty`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HlOrderCap {
    /// Hyperliquid perp asset index — matches `orders[].a` in the signed action.
    pub asset: u64,
    /// Inclusive upper bound on order size (`orders[].s`), decimal string.
    pub max_size: String,
    /// B2 (mainnet gate): inclusive upper bound on the PER-ORDER notional
    /// `orders[].s × orders[].p` (size × limit price, quote units), decimal
    /// string, exact enclave arithmetic. Absent = no notional bound (existing
    /// policies unchanged, canonical bytes identical via `skip_serializing_if`).
    ///
    /// Fail-closed when present: only plain limit orders
    /// (`orders[].t.limit`) are accepted — a TRIGGER order's `p` is not a
    /// reliable execution bound (`isMarket` triggers execute market-side), so
    /// trigger-shaped orders are denied under a notional cap. Missing/non-string
    /// `p` under an active cap is `bad_request` (mirrors the `s` handling).
    /// Same per-signature limitation as `max_size` — cumulative exposure is
    /// B3/UPL scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_notional: Option<String>,
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
// `Policy` is intentionally a large inline struct (many Option whitelists +
// the x402 clause); the variant-size gap vs `Legacy` is expected. This value
// is short-lived on the decrypt path and is matched-and-consumed immediately,
// so boxing would only add an allocation + indirection for no real gain
// (same rationale as the `result_large_err` allow on `enforce_policy`).
#[allow(clippy::large_enum_variant)]
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

/// Recursively wipe heap-allocated string bytes inside a
/// `serde_json::Value`. `serde_json::Value` does NOT implement Zeroize
/// on drop, so naive `drop(value)` leaves API-key / passphrase /
/// private-key strings in freed-but-unwiped heap memory — readable via
/// post-mortem dump or use-after-free oracles.
///
/// Used by:
///   - `SecretJson::Drop` (below) — every early-return path on the sign
///     handlers benefits automatically.
///   - `handler::handle_verify_blob` — explicit wipe before returning the
///     SHA-256 hash to the caller (Gemini PR #55 round-5 SEC-HIGH fix).
///
/// Field names like `"key"` / `"secret"` / `"passphrase"` are wrapper
/// schema chosen by us, not customer data — values only get wiped.
/// Per-field Zeroize attribute on the destination `*Secret` structs has
/// the same scope.
pub(crate) fn zeroize_json_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::String(s) => {
            let mut bytes = std::mem::take(s).into_bytes();
            bytes.zeroize();
            // bytes drops here — backing heap zeroized.
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                zeroize_json_value(v);
            }
        }
        serde_json::Value::Object(obj) => {
            // BTreeMap iter_mut yields (&String, &mut Value) — keys are
            // borrowed immutably and cannot be mutated through the
            // iterator. Wipe values only (see fn doc).
            for (_, v) in obj.iter_mut() {
                zeroize_json_value(v);
            }
        }
        _ => {} // Null / Bool / Number — no heap bytes worth wiping.
    }
}

/// Owned `serde_json::Value` wrapper that wipes its inner heap-allocated
/// strings via `zeroize_json_value` on drop.
///
/// This is the sign-path analogue of the PR #55 round-5 SEC-HIGH fix that
/// landed in `handle_verify_blob`. The sign handlers receive a parsed
/// `serde_json::Value` from `load_and_parse_blob`, then run
/// `enforce_policy` against it, then deserialize into a Zeroize-derived
/// `*Secret` struct. Three leak windows existed:
///
///   1. **Steady-state**: between `load_and_parse_blob` returning and
///      `from_value` consuming the Value — multiple lines, including
///      the entire `enforce_policy` call. The Value's heap pages held
///      raw API keys / passphrases / private keys un-wiped.
///   2. **Early-return on enforce_policy denial**: the raw Value was
///      dropped by the implicit return path without wiping — same
///      heap-page leak, just shorter window.
///   3. **Early-return on `from_value` failure**: malformed secret JSON
///      inside the ciphertext blob caused the Value to be dropped by
///      serde_json's internals without wiping.
///
/// `SecretJson` closes (1), (2), AND panic-unwind paths entirely via
/// `Drop`. The key design choice is that `deserialize_into` deserializes
/// from `&self.0` (no clone, no move-out), so if `T::deserialize` panics,
/// `self` is dropped during stack unwinding and `SecretJson::Drop` fires
/// on the original Value — wiping the strings before the heap pages are
/// freed.
///
/// On the success path we wipe `self.0` explicitly via
/// `zeroize_json_value`, then replace it with `Value::Null` so the
/// implicit `Drop` at function-end is a cheap no-op. On the `Err` path
/// the wipe still runs (zeroize is called before the early return
/// implicit in `?`-style propagation, though here we just return the
/// `Result`). Serde may have constructed partial `T` allocations
/// internally before failing — those are dropped by serde without wipe
/// — but the leak surface is strictly per-field (the few `String`s
/// allocated for individual struct fields before failure), not full-
/// Value heap pages.
///
/// Two rounds of Gemini hardening landed here:
///   - Round 1 (SEC-HIGH): replaced `serde_json::from_value(clone)` with
///     `T::deserialize(&taken)` — eliminated the doubled allocation.
///   - Round 2 (SEC-CRITICAL): replaced the local-`taken` move-out with
///     direct `&self.0` access — eliminated the panic-unwind leak where
///     `taken` was dropped raw while `self.0` had already been swapped
///     to `Null`, neutralising the `Drop` wipe.
pub struct SecretJson(serde_json::Value);

impl SecretJson {
    /// Wrap an owned `serde_json::Value`. Used by `load_and_parse_blob`
    /// after `ParsedBlob` destructure.
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// Deserialize the inner Value into `T`. The wrapper is consumed; the
    /// inner Value's heap pages are wiped before this function returns,
    /// regardless of whether deserialization succeeded, panicked, or
    /// short-circuited via stack unwinding.
    ///
    /// On `Ok(t)`: serde walked `&self.0` and produced `t` with per-field
    /// copies. We wipe `self.0` explicitly via `zeroize_json_value`,
    /// then null it so the implicit `Drop` is a cheap no-op. `t`'s
    /// fields wipe on its own drop (Zeroize-derived `*Secret`).
    ///
    /// On `Err(_)`: same wipe path runs before return. Serde-internal
    /// partial-T allocations may have leaked per-field bytes during the
    /// failing parse; this surface is strictly smaller than the
    /// previous clone-first design.
    ///
    /// On panic inside `T::deserialize`: stack unwinds, `self` is
    /// dropped, `SecretJson::Drop` calls `zeroize_json_value(&mut
    /// self.0)`. The wipe happens even though our explicit calls below
    /// never run. This is the key reason we no longer move-out into a
    /// local `taken` variable — that pattern left `taken` as a raw
    /// `Value` that drop-unwound without wiping.
    pub fn deserialize_into<T: serde::de::DeserializeOwned>(
        mut self,
    ) -> Result<T, serde_json::Error> {
        // Deserialize from a reference to `self.0`. No clone, no move-
        // out: if `T::deserialize` panics, `self` is still in scope and
        // its `Drop` impl will wipe `self.0` during stack unwinding.
        // `&serde_json::Value` implements `serde::Deserializer`, so
        // this is allocation-free for the JSON structure itself.
        let result = T::deserialize(&self.0);
        // Wipe inner Value strings explicitly. On success path this is
        // the primary wipe; on Drop-via-unwind path it's redundant but
        // never reached.
        zeroize_json_value(&mut self.0);
        // Replace with Null so the implicit `Drop` at function end is
        // a single Null-arm no-op (rather than re-walking the already-
        // wiped structure).
        self.0 = serde_json::Value::Null;
        result
    }
}

impl Drop for SecretJson {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

/// Generic error codes returned over the wire.
///
/// We keep this list short and intentionally vague. Internal stack traces,
/// AWS error messages, and decrypt failure reasons must NEVER be echoed
/// back to the caller (per the internal adversarial-review notes).
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
    /// C18 (adversarial review 2026-05-18): emitted when the enclave is
    /// running with `SIGNER_REQUIRE_POLICY=1` and the decrypted blob is
    /// a legacy flat secret (no top-level `"policy"` key). Distinct from
    /// `policy_denied` so operators and SDKs can distinguish "your policy
    /// rejected the request" from "your blob has no policy and this enclave
    /// build forbids that".
    pub const POLICY_REQUIRED: &str = "policy_required";
    /// Emitted when `SIGNER_REQUIRE_CONTEXT=1` and the request has no
    /// `encryption_context` or the map is empty. Prevents cross-customer
    /// DEK substitution via context-stripping attacks.
    pub const CONTEXT_REQUIRED: &str = "context_required";
    /// Phase 0 Active Denial: per-venue token-bucket exhausted.
    pub const RATE_LIMITED: &str = "rate_limited";
    /// C27 (adversarial review 2026-05-18): policy contains a field the enclave
    /// accepts in schema but does not yet enforce. Fail-loud prevents
    /// wire-level deception where the customer believes a constraint
    /// is active but the enclave silently ignores it.
    pub const UNIMPLEMENTED_POLICY_FIELD: &str = "unimplemented_policy_field";
    /// CR035 (Security otdel red-team, 2026-05-29): collapsed wire code
    /// for the `verify_blob` path. Returned in place of `kms_decrypt_denied`,
    /// `internal_error` (envelope AEAD), and post-KMS `bad_request`
    /// (unparseable plaintext) so the wire surface gives an external caller
    /// the same response for "wrong key", "wrong inner ciphertext", and
    /// "decrypted but bad shape". Internal log lines still carry the
    /// granular failure mode for operator debugging — the gateway log
    /// emits the original code via `tracing::warn!(internal_code = ...)`
    /// before collapsing to `verify_failed` on the HTTP wire.
    pub const VERIFY_FAILED: &str = "verify_failed";

    // ─── explainable-denials (2026-07-10) ───────────────────────────────
    // Typed subclasses of `POLICY_DENIED`. The enclave is the ONLY authority
    // on WHY a request was denied (it evaluated the policy; the gateway does
    // not see it), so it emits a typed class code and the gateway stays a dumb
    // `code → HTTP + body` mapper (minimal leak surface).
    //
    // NO-LEAK INVARIANT (money-path): a code names ONLY the rule CLASS, NEVER a
    // value / threshold / allow-list content. `SIZE_OVER_CAP` — yes; the actual
    // cap number — never on the wire (operator logs still carry it). This is a
    // deliberate, scoped reversal of the historical "opaque policy_denied"
    // stance (see POLICY_DENIED above): design-partner integrations need to know
    // the class of failure to self-correct; the no-value rule keeps an attacker
    // from reading exact thresholds off the wire (they can still binary-search a
    // cap, but a valid-token holder is already capped, and probes are rate-
    // limited + logged). Classes kept to a meaningful minimum.
    //
    // DEFAULT-DENY: any denial NOT reclassified here stays `POLICY_DENIED`, and
    // the gateway maps any unknown/unmapped code to a generic `403 policy_denied`
    // (fail-closed) — a new code never leaks or falls through to 500.
    //
    // NOTE: there is deliberately NO `venue_not_allowed` class. Venue-ACL denial
    // (`authorize_venue`) returns a uniform `BadRequest` on purpose — a distinct
    // venue class would be a venue-scope oracle (an attacker could enumerate
    // which venues a stolen token is granted). Kept opaque per that existing
    // anti-oracle control; revisit only with an explicit CTO call.
    /// Request action / HTTP method / path prefix is not permitted by policy.
    pub const ACTION_NOT_ALLOWED: &str = "action_not_allowed";
    /// Order quantity exceeds the policy's per-symbol `max_qty` cap.
    pub const SIZE_OVER_CAP: &str = "size_over_cap";
    /// Order notional (`qty × price`) exceeds the policy's `max_notional` cap.
    pub const NOTIONAL_OVER_CAP: &str = "notional_over_cap";
    /// The request targets a withdrawal / transfer primitive, which is never
    /// signable under the policy's withdrawal-deny (a useful, safe signal).
    pub const WITHDRAWAL_NOT_SIGNABLE: &str = "withdrawal_not_signable";
}
