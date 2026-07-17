//! Vsock client used by the gateway to talk to the enclave.
//!
//! The wire shape is duplicated here from `enclave/src/proto.rs` (same
//! pattern as `parent/src/main.rs`). We deliberately don't share a third
//! "common" crate — the duplication is auditable and keeps the workspace
//! flat.
//!
//! Connection lifecycle: one connection per HTTP request. Vsock connect
//! cost is sub-millisecond inside an EC2 host, so pooling is a Phase 4+
//! optimization.
//!
//! Logging policy: we log only `latency_ms`, `success`, and `error_code`.
//! Bodies, signatures, headers, AWS credentials, and ciphertext are NEVER
//! emitted.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hard cap on a single framed message. Must match the enclave constant.
/// Linux-only because darwin/Windows can't run the actual `round_trip` and
/// `cargo` then flags the symbol as dead code.
#[cfg(target_os = "linux")]
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Vsock CID + port the gateway dials. Mirrors the enclave's listener
/// constants. CID is supplied at runtime (it's discoverable via
/// `nitro-cli describe-enclaves`). Default port matches the enclave's
/// default. Linux-only for the same reason as `MAX_MESSAGE_BYTES` above.
#[allow(dead_code)] // Reserved as default in case CLI doesn't pass --enclave-port.
#[cfg(target_os = "linux")]
pub const VSOCK_PORT: u32 = 5000;

/// Compile-time size of the length prefix.
#[cfg(target_os = "linux")]
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// AWS SigV4 credentials forwarded from the gateway's IMDS cache to the
/// enclave for the duration of one signing call.
///
/// Manually-redacted `Debug` so an accidental `tracing::debug!(?creds, ...)`
/// can't leak the secret.
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

/// Vsock-side request shape. Only the fields the gateway actually populates
/// are present — `key_blob_s3_key` and `key_id` are informational on the
/// enclave side and we omit them on the wire (they're optional, default to
/// None on the enclave).
///
/// C21 (ZLODEY 2026-05-18, Gemini round-1 PR #30): the struct now derives
/// Zeroize + ZeroizeOnDrop so the in-memory plaintext fields (body, query,
/// vault_address, ciphertext_blob_base64) are wiped from heap when the
/// struct drops. AwsCredentials was already ZeroizeOnDrop from earlier
/// hardening. hl_action carries serde_json::Value which has no Zeroize
/// impl in the ecosystem — we mark it `#[zeroize(skip)]` and accept the
/// brief lifecycle leak (documented in proto.rs SECURITY NOTE for the
/// enclave-side equivalent; same caveat applies here).
#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct VsockRequest {
    pub action: String,
    /// PR-B (D7): wire-protocol version. Always `1` from this gateway; the
    /// enclave rejects `< 1` (an old gateway) rather than signing without
    /// tenant isolation.
    pub proto_version: u8,
    /// PR-B (§3): the RAW bearer token, relayed UNCHANGED for the enclave to
    /// resolve identity itself. The gateway never builds the EncryptionContext.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub opaque_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_credentials: Option<AwsCredentials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_blob_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_blob_s3_key: Option<String>,
    /// Phase 1 Week 4: query string for Binance/Bybit signing (no leading `?`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// `/sign/binance-request` (keyless generic primitive): the allow-listed op
    /// name + the EXACT urlencoded payload the enclave HMACs. Mirror of the
    /// enclave `SignRequest.op` / `.payload`. Public (no key material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    // Phase 1 Stage 2 — EIP-712 (Hyperliquid family) action payload.
    // serde_json::Value does not implement Zeroize; we skip and document
    // (same caveat as the enclave-side ParsedBlob serde_json::Value note).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub hl_action: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_address: Option<String>,
    // x402 / EIP-3009 payment-authorization params (opaque pass-through to the
    // enclave, which deserializes into its typed `X402Request`). Public payment
    // fields only — no key material — so `zeroize` is skipped (same caveat as
    // `hl_action`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub x402: Option<serde_json::Value>,

    /// Structured order params (opaque pass-through; enclave deserializes into
    /// its typed `OrderRequest`). Public order shape — no key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub order: Option<serde_json::Value>,

    /// Structured cancel params (opaque pass-through; enclave → `CancelRequest`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub cancel: Option<serde_json::Value>,

    /// H5 (`action == "attestation"`): hex of the caller nonce bound into the
    /// NSM document, and optional hex user-data. Public (no key material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_user_data: Option<String>,

    /// Attested-signed-data (P2): the read-only payload to sign with the
    /// data-signing key (for `action == "sign_data"`), carried as RAW JSON TEXT
    /// (mirrors enclave `proto::SignRequest.data: Option<String>`, #210). The
    /// gateway forwards the bytes VERBATIM — it never parses/re-serializes them —
    /// so the enclave's dup-key rejection and the buyer's byte-exact canonical
    /// recompute both see the producer's original bytes. Public market data only.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub data: Option<String>,

    /// AF-2: the agent's Ed25519 signature (hex) over the canonical order intent,
    /// forwarded VERBATIM to the enclave (mirrors `SignRequest.intent_signature`).
    /// Public authenticator — no key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub intent_signature: Option<String>,

    /// AF-2: the per-intent replay nonce for cancels (UUID). Orders reuse their
    /// `client_order_id`; this is `None` for them.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub intent_nonce: Option<String>,
}

/// Vsock-side response shape.
///
/// C21 (ZLODEY 2026-05-18, Gemini round-1 PR #30): response carries signed
/// material (HMAC headers, EIP-712 r,s,v). Although KMS plaintext is not
/// here, signatures are sensitive in transit on a parent VM that may be
/// memory-dumped. Derive Zeroize + ZeroizeOnDrop so the struct's strings
/// are wiped when the response goes out of scope at the gateway.
///
/// Gemini PR #30 round-2 HIGH: removed the `Debug` derive. Default derive
/// would print signature_base64 / headers / signatures verbatim via
/// `tracing::debug!(?resp, ...)`. Manual Debug below redacts secrets.
///
/// Drop is now MANUAL (replaces `ZeroizeOnDrop` derive) so we can also
/// wipe the BTreeMap header VALUE strings — those are `#[zeroize(skip)]`
/// because BTreeMap itself has no Zeroize impl, but we walk it manually
/// in Drop. Gemini PR #30 round-2 MEDIUM L125.
/// Attested-signed-data response over the vsock — mirrors the enclave's
/// `proto::AttestedDataResponse`. signature + pubkey are PUBLIC (served to
/// buyers) but Zeroize with the rest of VsockResponse for uniform hygiene.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct AttestedDataVsock {
    pub signature: HlSignatureVsock,
    pub pubkey_compressed: String,
    pub pubkey_address: String,
}

#[derive(Clone, Deserialize, Zeroize)]
pub struct VsockResponse {
    pub signature_base64: String,
    #[serde(default)]
    #[zeroize(skip)]
    pub headers: Option<BTreeMap<String, String>>,
    /// Phase 1 Stage 2: EIP-712 signature `{r,s,v}` for Hyperliquid family.
    #[serde(default)]
    pub hl_signature: Option<HlSignatureVsock>,
    pub error: Option<String>,
    /// Path B-lite (Stage 4 pre-flight): hex SHA-256 of decrypted plaintext
    /// for the `verify_blob` action. `None` for sign actions. Plaintext
    /// never crosses the vsock — only the hash bytes.
    #[serde(default)]
    pub plaintext_sha256: Option<String>,
    /// Path B-lite: length in bytes of the verified plaintext. Lets the
    /// operator sanity-check obvious truncation (0 bytes ≠ valid secret).
    #[serde(default)]
    pub plaintext_len: Option<u64>,

    /// For `sign_<venue>_order` / `sign_<venue>_cancel`: the venue-canonical
    /// string the enclave signed (Binance form-urlencoded query without
    /// `&signature=`, OKX exact JSON body). Forwarded byte-for-byte by the
    /// gateway. None for header-only sign flows.
    #[serde(default)]
    pub canonical_body: Option<String>,

    /// Attested-signed-data (P2): the data signature + the attested data-signing
    /// pubkey (both wire forms). `Some` only for `action == "sign_data"`.
    #[serde(default)]
    pub attested: Option<AttestedDataVsock>,

    /// H5: base64 NSM-signed COSE attestation document. `Some` only for
    /// `action == "attestation"`. PUBLIC (PCRs + cert chain, no secret).
    #[serde(default)]
    #[zeroize(skip)]
    pub attestation_document_b64: Option<String>,
}

impl fmt::Debug for VsockResponse {
    /// Manually-redacted Debug — Gemini PR #30 round-2 HIGH.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockResponse")
            .field(
                "signature_base64",
                &format!("[REDACTED {} chars]", self.signature_base64.len()),
            )
            .field(
                "headers",
                &self
                    .headers
                    .as_ref()
                    .map(|m| format!("[REDACTED {} headers]", m.len())),
            )
            .field(
                "hl_signature",
                &self.hl_signature.as_ref().map(|_| "[REDACTED]"),
            )
            .field("error", &self.error)
            .finish()
    }
}

impl Drop for VsockResponse {
    /// Manual Drop replaces the `ZeroizeOnDrop` derive so we can also wipe
    /// the BTreeMap header value bytes (the derive can't reach inside a
    /// `#[zeroize(skip)]` field). Gemini PR #30 round-2.
    fn drop(&mut self) {
        // First wipe the BTreeMap value strings manually (HMAC headers
        // like KuCoin v2 KC-API-KEY / KC-API-PASSPHRASE / KC-API-SIGN).
        if let Some(map) = self.headers.as_mut() {
            for v in map.values_mut() {
                v.zeroize();
            }
        }
        // Then call the derive's zeroize() to wipe everything else.
        self.zeroize();
    }
}

/// `(r, s, v)` triple as it flows over the vsock channel from the enclave.
/// Kept structurally identical to `crate::proto::HlSignatureWire` so the
/// gateway can pass-through without re-shaping.
///
/// Zeroize + ZeroizeOnDrop so the r,s strings are wiped when HlSignatureVsock
/// drops as part of VsockResponse. Gemini round-1 PR #30.
/// Manually-redacted Debug — Gemini round-2 PR #30, same rationale as
/// VsockResponse above.
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct HlSignatureVsock {
    pub r: String,
    pub s: String,
    pub v: u8,
}

impl fmt::Debug for HlSignatureVsock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HlSignatureVsock")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .field("v", &self.v)
            .finish()
    }
}

/// Send `req` to the enclave over vsock and read back one response. This is
/// the only function in the module that actually touches the kernel socket;
/// every other helper is pure / synchronous data shaping.
///
/// On non-Linux hosts the function exists for `cargo check / clippy` but
/// returns an error immediately — vsock is a Linux kernel socket family.
#[cfg(target_os = "linux")]
pub async fn round_trip(cid: u32, port: u32, req: &VsockRequest) -> Result<VsockResponse> {
    use anyhow::{anyhow, Context};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};
    use tokio_vsock::{VsockAddr, VsockStream};

    let addr = VsockAddr::new(cid, port);
    // Bound the connect on a wall clock — the enclave can be down, busy,
    // or simply mis-numbered. 1s is well above realistic latency.
    let mut stream = timeout(Duration::from_secs(1), VsockStream::connect(addr))
        .await
        .map_err(|_| anyhow!("vsock connect timed out"))?
        .with_context(|| format!("vsock connect to (cid={cid}, port={port})"))?;

    // C21 (ZLODEY 2026-05-18) partial mitigation: wrap the serialized vsock
    // payload in Zeroizing so the plaintext (which contains AwsCredentials
    // and HL action JSON) does not linger in heap memory after the send.
    // This does NOT protect against an attacker reading the vsock socket
    // mid-flight — full mitigation is the attestation-handshake AEAD
    // proposed in DESIGN-C21-VSOCK-ENCRYPTION.md, deferred work. This is a
    // narrow defense-in-depth against post-send memory residue on the
    // parent VM (e.g., if a swap dump or core dump captures the heap).
    let body = zeroize::Zeroizing::new(
        serde_json::to_vec(req).context("serialize vsock request")?,
    );
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(anyhow!(
            "vsock request body exceeds {} bytes",
            MAX_MESSAGE_BYTES
        ));
    }
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body[..]).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > MAX_MESSAGE_BYTES {
        return Err(anyhow!("vsock response length {resp_len} out of bounds"));
    }
    // Same Zeroizing wrapper on the response buffer — although the response
    // does not contain credentials, it does contain signed material (HMAC,
    // EIP-712 signature) which is sensitive in transit. Cheap defense.
    let mut resp_buf = zeroize::Zeroizing::new(vec![0u8; resp_len]);
    stream.read_exact(&mut resp_buf[..]).await?;
    let resp: VsockResponse =
        serde_json::from_slice(&resp_buf).context("deserialize vsock response")?;
    Ok(resp)
}

#[cfg(not(target_os = "linux"))]
pub async fn round_trip(_cid: u32, _port: u32, _req: &VsockRequest) -> Result<VsockResponse> {
    anyhow::bail!("vsock is Linux-only; signer-gateway must run on EC2 with the enclave");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JSON shape sanity: a `VsockRequest` round-trips through serde with
    /// the exact field names the enclave's `SignRequest` deserializes.
    #[test]
    fn vsock_request_serializes_with_action_field() {
        let req = VsockRequest {
            action: "sign_kucoin".to_owned(),
            method: Some("GET".to_owned()),
            path: Some("/api/v1/accounts".to_owned()),
            body: Some(String::new()),
            timestamp_ms: Some(1714997000000),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIA".to_owned(),
                secret_access_key: "secret".to_owned(),
                session_token: "tok".to_owned(),
            }),
            ciphertext_blob_base64: Some("Zm9v".to_owned()),
            proto_version: 1,
            opaque_token: None,
            key_blob_s3_key: Some("secrets/kucoin.enc".to_owned()),
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
        };
        let s = serde_json::to_string(&req).expect("serialize");
        assert!(s.contains("\"action\":\"sign_kucoin\""));
        assert!(s.contains("\"method\":\"GET\""));
        assert!(s.contains("\"ciphertext_blob_base64\":\"Zm9v\""));
        assert!(s.contains("\"aws_credentials\""));
        // None query is omitted from JSON.
        assert!(!s.contains("\"query\""));
    }

    #[test]
    fn vsock_response_parses_header_form() {
        let json = r#"{
            "signature_base64": "",
            "headers": { "KC-API-KEY": "k", "KC-API-SIGN": "s" },
            "error": null
        }"#;
        let mut resp: VsockResponse = serde_json::from_str(json).expect("parse");
        assert!(resp.error.is_none());
        // C21: VsockResponse is ZeroizeOnDrop, can't partial-move. take().
        let h = resp.headers.take().expect("headers");
        assert_eq!(h.get("KC-API-KEY").map(String::as_str), Some("k"));
    }

    #[test]
    fn vsock_response_parses_error_form() {
        let json = r#"{"signature_base64":"","error":"kms_decrypt_denied"}"#;
        let resp: VsockResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.error.as_deref(), Some("kms_decrypt_denied"));
        assert!(resp.headers.is_none());
    }

    #[test]
    fn schema_drift_gateway_to_enclave_round_trip() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct EnclaveSignRequest {
            action: String,
            #[serde(default)]
            method: Option<String>,
            #[serde(default)]
            path: Option<String>,
            #[serde(default)]
            body: Option<String>,
            #[serde(default)]
            timestamp_ms: Option<u64>,
            #[serde(default)]
            key_blob_s3_key: Option<String>,
            #[serde(default)]
            key_id: Option<String>,
            #[serde(default)]
            aws_credentials: Option<serde_json::Value>,
            #[serde(default)]
            ciphertext_blob_base64: Option<String>,
            #[serde(default)]
            proto_version: u8,
            #[serde(default)]
            opaque_token: Option<String>,
            #[serde(default)]
            query: Option<String>,
            #[serde(default)]
            op: Option<String>,
            #[serde(default)]
            payload: Option<String>,
            #[serde(default)]
            hl_action: Option<serde_json::Value>,
            #[serde(default)]
            nonce: Option<u64>,
            #[serde(default)]
            vault_address: Option<String>,
        }

        let req = VsockRequest {
            action: "sign_binance".to_owned(),
            method: Some("POST".to_owned()),
            path: Some("/api/v3/order".to_owned()),
            body: Some("symbol=BTCUSDT".to_owned()),
            timestamp_ms: Some(1716000000000),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIA_TEST".to_owned(),
                secret_access_key: "test_secret".to_owned(),
                session_token: "test_token".to_owned(),
            }),
            ciphertext_blob_base64: Some("dGVzdA==".to_owned()),
            proto_version: 1,
            opaque_token: Some("tok".to_owned()),
            key_blob_s3_key: Some("secrets/binance.enc".to_owned()),
            query: Some("recvWindow=5000".to_owned()),
            op: Some("account".to_owned()),
            payload: Some("timestamp=1716000000000".to_owned()),
            hl_action: None,
            nonce: Some(42),
            vault_address: Some("0xdead".to_owned()),
            x402: None,
            order: None,
            cancel: None,
            data: None,
            intent_signature: None,
            intent_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
        };

        let json = serde_json::to_string(&req).expect("serialize VsockRequest");
        let enc: EnclaveSignRequest =
            serde_json::from_str(&json).expect("deserialize as EnclaveSignRequest");

        assert_eq!(enc.action, "sign_binance");
        assert_eq!(enc.method.as_deref(), Some("POST"));
        assert!(enc.aws_credentials.is_some());
        assert_eq!(enc.ciphertext_blob_base64.as_deref(), Some("dGVzdA=="));
        // PR-B: the gateway-supplied encryption_context is GONE; instead the
        // proto_version + opaque_token must survive the round-trip so the
        // enclave can gate the wire version and resolve identity itself.
        assert_eq!(enc.proto_version, 1);
        assert_eq!(enc.opaque_token.as_deref(), Some("tok"));
        assert_eq!(
            enc.key_blob_s3_key.as_deref(),
            Some("secrets/binance.enc"),
            "key_blob_s3_key must survive round-trip (ZN-207)"
        );
        // /sign/binance-request: op + payload must survive the round-trip so the
        // enclave allow-lists + HMACs the exact client payload.
        assert_eq!(enc.op.as_deref(), Some("account"));
        assert_eq!(enc.payload.as_deref(), Some("timestamp=1716000000000"));
    }

    /// Manual `Debug` impl on `AwsCredentials` keeps secret + token redacted.
    #[test]
    fn aws_credentials_debug_redacts_secret_and_token() {
        let creds = AwsCredentials {
            access_key_id: "AKIASOMETHING".to_owned(),
            secret_access_key: "supersecret".to_owned(),
            session_token: "verylongsessiontoken".to_owned(),
        };
        let dbg = format!("{:?}", creds);
        assert!(dbg.contains("AKIASOMETHING"));
        assert!(!dbg.contains("supersecret"));
        assert!(!dbg.contains("verylongsessiontoken"));
        assert!(dbg.contains("[REDACTED]"));
    }
}
