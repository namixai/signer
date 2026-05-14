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
use zeroize::Zeroize;

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
#[derive(Clone, Serialize)]
pub struct VsockRequest {
    pub action: String,
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
    /// Phase 1 Week 4: query string for Binance/Bybit signing (no leading `?`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    // Phase 1 Stage 2 — EIP-712 (Hyperliquid family) action payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hl_action: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_address: Option<String>,
}

/// Vsock-side response shape.
#[derive(Debug, Clone, Deserialize)]
pub struct VsockResponse {
    pub signature_base64: String,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
    /// Phase 1 Stage 2: EIP-712 signature `{r,s,v}` for Hyperliquid family.
    #[serde(default)]
    pub hl_signature: Option<HlSignatureVsock>,
    pub error: Option<String>,
}

/// `(r, s, v)` triple as it flows over the vsock channel from the enclave.
/// Kept structurally identical to `crate::proto::HlSignatureWire` so the
/// gateway can pass-through without re-shaping.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HlSignatureVsock {
    pub r: String,
    pub s: String,
    pub v: u8,
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

    let body = serde_json::to_vec(req).context("serialize vsock request")?;
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(anyhow!(
            "vsock request body exceeds {} bytes",
            MAX_MESSAGE_BYTES
        ));
    }
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > MAX_MESSAGE_BYTES {
        return Err(anyhow!("vsock response length {resp_len} out of bounds"));
    }
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;
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
            query: None,
            // Phase 1 Stage 2 — EIP-712 fields. HMAC-only test sets
            // them to None; serde omits via `skip_serializing_if`.
            hl_action: None,
            nonce: None,
            vault_address: None,
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
        let resp: VsockResponse = serde_json::from_str(json).expect("parse");
        assert!(resp.error.is_none());
        let h = resp.headers.expect("headers");
        assert_eq!(h.get("KC-API-KEY").map(String::as_str), Some("k"));
    }

    #[test]
    fn vsock_response_parses_error_form() {
        let json = r#"{"signature_base64":"","error":"kms_decrypt_denied"}"#;
        let resp: VsockResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.error.as_deref(), Some("kms_decrypt_denied"));
        assert!(resp.headers.is_none());
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
