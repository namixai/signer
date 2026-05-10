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
    pub error: Option<String>,
}

impl SignResponse {
    pub fn ok(signature_base64: String) -> Self {
        Self {
            signature_base64,
            headers: None,
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
            error: None,
        }
    }

    pub fn err(code: &str) -> Self {
        Self {
            signature_base64: String::new(),
            headers: None,
            error: Some(code.to_owned()),
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
}
