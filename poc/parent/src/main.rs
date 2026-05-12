//! Parent-side vsock client / smoke-test driver.
//!
//! Two subcommands:
//!   - `ping`  : send `{"action":"ping"}`, expect `pong`.
//!   - `sign`  : send a full KuCoin SignRequest, print the base64 signature.
//!
//! Wire framing must mirror the enclave exactly: 4-byte big-endian length
//! prefix, then JSON. Hard cap 64 KiB per message.
//!
//! Types are duplicated (NOT shared via a third crate) — this is by design
//! to keep the workspace minimal. Keep the two definitions in lockstep.
//!
//! Platform note: vsock is Linux-only. The CLI parses on every platform but
//! the actual roundtrip refuses to run on non-Linux with a clear error,
//! so `cargo fmt / clippy / test` work on darwin while real usage is on EC2.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroize;

// Used only inside `roundtrip` (Linux-gated). Silence dead_code on darwin
// where the function body is replaced by an early bail.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const LENGTH_PREFIX_BYTES: usize = 4;

/// Parent-side STS credentials forwarded to the enclave. Zeroized on drop
/// so a `/proc/self/mem` reader on a compromised parent cannot recover them
/// after the request completes. `Debug` is manual + redacted, mirroring
/// the enclave-side proto.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
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

#[derive(Clone, Serialize, Deserialize)]
struct SignRequest {
    action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timestamp_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_blob_s3_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aws_credentials: Option<AwsCredentials>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext_blob_base64: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignResponse {
    signature_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
    error: Option<String>,
}

#[derive(Parser, Debug)]
#[command(version, about = "Usenami Signer parent-side vsock client")]
struct Cli {
    /// vsock CID of the running enclave (find via `nitro-cli describe-enclaves`).
    #[arg(long, default_value_t = 16)]
    cid: u32,

    /// vsock port the enclave is listening on.
    #[arg(long, default_value_t = 5000)]
    port: u32,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Send a ping; expect signature_base64 == "pong".
    Ping,
    /// Send a full KuCoin sign request. Phase 3 requires `--blob` (path to
    /// the KMS-ciphertext file fetched from S3) and `AWS_ACCESS_KEY_ID` /
    /// `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` in the environment
    /// (typically sourced from IMDS by the test driver script).
    Sign {
        #[arg(long, default_value = "POST")]
        method: String,
        #[arg(long, default_value = "/api/v1/orders")]
        path: String,
        #[arg(long, default_value = r#"{"clientOid":"test"}"#)]
        body: String,
        #[arg(long, default_value_t = 1714997000000)]
        timestamp_ms: u64,
        #[arg(long, default_value = "secrets/test-kucoin.enc")]
        key_blob_s3_key: String,
        #[arg(long, default_value = "alias/signer-poc")]
        key_id: String,
        /// Path to the KMS-ciphertext file (parent fetches from S3 first).
        #[arg(long)]
        blob: PathBuf,
    },
    /// Day 3: send a `sign_kucoin` action; expect a `headers` map with the
    /// full KuCoin v2 auth set. Same env / blob requirements as `Sign`. The
    /// blob plaintext must be a JSON object `{"key","secret","passphrase"}`.
    SignKucoin {
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long, default_value = "/api/v1/accounts")]
        path: String,
        #[arg(long, default_value = "")]
        body: String,
        #[arg(long, default_value_t = 1714997000000)]
        timestamp_ms: u64,
        #[arg(long, default_value = "secrets/test-kucoin.enc")]
        key_blob_s3_key: String,
        #[arg(long, default_value = "alias/signer-poc")]
        key_id: String,
        /// Path to the KMS-ciphertext file (parent fetches from S3 first).
        #[arg(long)]
        blob: PathBuf,
    },
}

fn build_request(cmd: Cmd) -> Result<SignRequest> {
    match cmd {
        Cmd::Ping => Ok(SignRequest {
            action: "ping".to_owned(),
            method: None,
            path: None,
            body: None,
            timestamp_ms: None,
            key_blob_s3_key: None,
            key_id: None,
            aws_credentials: None,
            ciphertext_blob_base64: None,
        }),
        Cmd::Sign {
            method,
            path,
            body,
            timestamp_ms,
            key_blob_s3_key,
            key_id,
            blob,
        } => build_kucoin_request(
            "sign",
            method,
            path,
            body,
            timestamp_ms,
            key_blob_s3_key,
            key_id,
            blob,
        ),
        Cmd::SignKucoin {
            method,
            path,
            body,
            timestamp_ms,
            key_blob_s3_key,
            key_id,
            blob,
        } => build_kucoin_request(
            "sign_kucoin",
            method,
            path,
            body,
            timestamp_ms,
            key_blob_s3_key,
            key_id,
            blob,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_kucoin_request(
    action: &str,
    method: String,
    path: String,
    body: String,
    timestamp_ms: u64,
    key_blob_s3_key: String,
    key_id: String,
    blob: PathBuf,
) -> Result<SignRequest> {
    let creds = load_credentials_from_env()
        .context("AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY/SESSION_TOKEN missing in env")?;
    let ciphertext =
        std::fs::read(&blob).with_context(|| format!("read ciphertext blob {}", blob.display()))?;
    let ciphertext_b64 = B64.encode(&ciphertext);

    Ok(SignRequest {
        action: action.to_owned(),
        method: Some(method),
        path: Some(path),
        body: Some(body),
        timestamp_ms: Some(timestamp_ms),
        key_blob_s3_key: Some(key_blob_s3_key),
        key_id: Some(key_id),
        aws_credentials: Some(creds),
        ciphertext_blob_base64: Some(ciphertext_b64),
    })
}

/// Pull STS credentials from the standard AWS env vars. The driver script
/// (`scripts/run-e2e-test.sh`) fetches them from IMDS and exports first.
fn load_credentials_from_env() -> Result<AwsCredentials> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").context("AWS_ACCESS_KEY_ID not set")?;
    let secret_access_key =
        std::env::var("AWS_SECRET_ACCESS_KEY").context("AWS_SECRET_ACCESS_KEY not set")?;
    // Session token is REQUIRED for instance-role STS creds. We refuse
    // long-lived IAM-user keys to avoid accidentally shipping them around.
    let session_token = std::env::var("AWS_SESSION_TOKEN")
        .context("AWS_SESSION_TOKEN not set (required — instance role only)")?;
    if access_key_id.is_empty() || secret_access_key.is_empty() || session_token.is_empty() {
        bail!("AWS credential env var is set but empty");
    }
    Ok(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let req = build_request(cli.cmd)?;

    let resp = roundtrip(cli.cid, cli.port, &req).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    if let Some(code) = resp.error.as_deref() {
        bail!("enclave returned error: {code}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn roundtrip(cid: u32, port: u32, req: &SignRequest) -> Result<SignResponse> {
    use anyhow::{anyhow, Context};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_vsock::{VsockAddr, VsockStream};

    let addr = VsockAddr::new(cid, port);
    let mut stream = VsockStream::connect(addr)
        .await
        .with_context(|| format!("vsock connect to (cid={cid}, port={port})"))?;

    let body = serde_json::to_vec(req)?;
    if body.len() > MAX_MESSAGE_BYTES {
        bail!("request body exceeds {} bytes", MAX_MESSAGE_BYTES);
    }
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > MAX_MESSAGE_BYTES {
        return Err(anyhow!("response length {resp_len} out of bounds"));
    }
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;
    let resp: SignResponse = serde_json::from_slice(&resp_buf)?;
    Ok(resp)
}

#[cfg(not(target_os = "linux"))]
async fn roundtrip(_cid: u32, _port: u32, _req: &SignRequest) -> Result<SignResponse> {
    bail!("vsock is Linux-only; run signer-client on the EC2 parent instance")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_ping_ok() {
        let req = build_request(Cmd::Ping).expect("ping always succeeds");
        assert_eq!(req.action, "ping");
        assert!(req.method.is_none());
        assert!(req.body.is_none());
        assert!(req.ciphertext_blob_base64.is_none());
    }

    #[test]
    fn sign_request_round_trip_json_with_blob() {
        // Construct directly (skipping env-driven build_request) so the
        // test doesn't depend on real AWS creds.
        let req = SignRequest {
            action: "sign".to_owned(),
            method: Some("POST".to_owned()),
            path: Some("/api/v1/orders".to_owned()),
            body: Some(r#"{"clientOid":"test"}"#.to_owned()),
            timestamp_ms: Some(1714997000000),
            key_blob_s3_key: Some("secrets/test-kucoin.enc".to_owned()),
            key_id: Some("alias/signer-poc".to_owned()),
            aws_credentials: Some(AwsCredentials {
                access_key_id: "AKIAFAKE".to_owned(),
                secret_access_key: "secret".to_owned(),
                session_token: "session".to_owned(),
            }),
            ciphertext_blob_base64: Some(B64.encode(b"fake-ciphertext")),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SignRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.action, "sign");
        assert_eq!(back.method.as_deref(), Some("POST"));
        assert_eq!(back.timestamp_ms, Some(1714997000000));
        assert!(back.ciphertext_blob_base64.is_some());
        assert!(back.aws_credentials.is_some());
    }

    #[test]
    fn sign_response_error_field() {
        let json = r#"{"signature_base64":"","error":"kms_decrypt_denied"}"#;
        let r: SignResponse = serde_json::from_str(json).expect("deserialize");
        assert!(r.signature_base64.is_empty());
        assert_eq!(r.error.as_deref(), Some("kms_decrypt_denied"));
        assert!(r.headers.is_none());
    }

    /// Day 3: a successful `sign_kucoin` response shape over the wire.
    #[test]
    fn sign_response_with_headers() {
        let json = r#"{
            "signature_base64": "",
            "headers": {
                "KC-API-KEY": "abc",
                "KC-API-SIGN": "sig",
                "KC-API-TIMESTAMP": "1714997000000",
                "KC-API-PASSPHRASE": "pass",
                "KC-API-KEY-VERSION": "2"
            },
            "error": null
        }"#;
        let r: SignResponse = serde_json::from_str(json).expect("deserialize");
        assert!(r.error.is_none());
        let h = r.headers.expect("headers present");
        assert_eq!(h.len(), 5);
        assert_eq!(h.get("KC-API-KEY").map(String::as_str), Some("abc"));
        assert_eq!(h.get("KC-API-KEY-VERSION").map(String::as_str), Some("2"));
    }
}
