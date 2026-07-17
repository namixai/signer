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

/// Registry-refresh parameters — mirrors `enclave::proto::RegistryRefreshParams`.
/// Produced off-box by `signer-policy-wrap registry sign` (refresh.json). That
/// file also carries a `content_hash_hex` field which is DELIBERATELY not parsed
/// here (no `deny_unknown_fields`): it is advisory-only, for the operator's
/// pre-encrypt `sha256sum` integrity check — the enclave recomputes the hash from
/// the decrypted plaintext, so it never travels on the wire (review F4).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryRefreshParams {
    nonce_hex: String,
    version: u64,
    signature_hex: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registry_refresh: Option<RegistryRefreshParams>,
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
            // nonce/version/signature are public refresh params, not secrets.
            .field("registry_refresh", &self.registry_refresh)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignResponse {
    signature_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
    /// Attested-data provisioning (Option-1): the sealed data-key envelope +
    /// pubkey. `Some` only for the `provision-data-key` action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provision: Option<ProvisionDataKeyResponse>,
    error: Option<String>,
}

/// Mirror of the enclave `proto::ProvisionDataKeyResponse`. `envelope_b64` is the
/// base64 of the sealed v2 envelope blob; the public key (both forms) is recorded
/// off-box as `SIGNER_DATA_PUBKEY` / `SIGNER_DATA_ADDRESS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvisionDataKeyResponse {
    envelope_b64: String,
    pubkey_compressed: String,
    pubkey_address: String,
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
    /// Phase 1.5 registry bootstrap, step 1: ask the enclave for a fresh
    /// challenge nonce. Print it, then sign off-box with
    /// `signer-policy-wrap registry sign --nonce <this>`. No AWS creds needed.
    RegistryChallenge,
    /// Phase 1.5 registry bootstrap, step 2: deliver the signed registry
    /// refresh. `--blob` is the base64 KMS-ciphertext of the SIGNED entries
    /// bytes (the `aws kms encrypt --output text --query CiphertextBlob` text),
    /// `--refresh` is the refresh.json from `registry sign`. AWS creds from env
    /// (the enclave KMS-decrypts the blob under the registry context).
    RegistryRefresh {
        /// File with the base64 KMS-ciphertext of the registry entries.
        #[arg(long)]
        blob: PathBuf,
        /// refresh.json from `signer-policy-wrap registry sign`.
        #[arg(long)]
        refresh: PathBuf,
    },
    /// Attested-data provisioning (Option-1), ONE-SHOT: ask the enclave to BIRTH
    /// the data-signing key, KMS-seal it, and return the sealed envelope + pubkey.
    /// Requires AWS creds in the env (IMDS) carrying the EPHEMERAL scoped role
    /// that grants `kms:GenerateDataKey` on the data key under the
    /// `{customer_id:"attested-data", venue_id:"data-signing"}` context. Writes the
    /// sealed envelope to `--out` and prints `SIGNER_DATA_PUBKEY` / `..._ADDRESS`.
    ProvisionDataKey {
        /// KMS key id/alias to GenerateDataKey under (the signer KMS key).
        #[arg(long, default_value = "alias/signer-poc")]
        key_id: String,
        /// Path to write the sealed envelope blob (the gateway loads this).
        #[arg(long, default_value = "secrets/attested-data/data-signing.enc")]
        out: PathBuf,
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
            registry_refresh: None,
        }),
        Cmd::RegistryChallenge => Ok(SignRequest {
            action: "registry_challenge".to_owned(),
            method: None,
            path: None,
            body: None,
            timestamp_ms: None,
            key_blob_s3_key: None,
            key_id: None,
            aws_credentials: None,
            ciphertext_blob_base64: None,
            registry_refresh: None,
        }),
        Cmd::RegistryRefresh { blob, refresh } => build_registry_refresh_request(blob, refresh),
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
        Cmd::ProvisionDataKey { key_id, .. } => build_provision_request(key_id),
    }
}

/// Build a `provision_data_key` request: action + the KMS key id + IMDS creds.
/// No blob — the key is BORN in the enclave. `main` writes the returned sealed
/// envelope to `--out` after the round-trip.
fn build_provision_request(key_id: String) -> Result<SignRequest> {
    let creds = load_credentials_from_env().context(
        "AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY/SESSION_TOKEN missing in env \
         (need the ephemeral scoped role granting kms:GenerateDataKey)",
    )?;
    Ok(SignRequest {
        action: "provision_data_key".to_owned(),
        method: None,
        path: None,
        body: None,
        timestamp_ms: None,
        key_blob_s3_key: None,
        key_id: Some(key_id),
        aws_credentials: Some(creds),
        ciphertext_blob_base64: None,
        registry_refresh: None,
    })
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
        registry_refresh: None,
    })
}

/// Build a `registry_refresh` request: the base64 KMS-ciphertext of the SIGNED
/// registry entries (passed THROUGH verbatim — the enclave KMS-decrypts it under
/// the registry context and hashes the plaintext to match the signature) plus
/// the refresh params from `registry sign`. AWS creds come from the box env.
fn build_registry_refresh_request(blob: PathBuf, refresh: PathBuf) -> Result<SignRequest> {
    let creds = load_credentials_from_env()
        .context("AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY/SESSION_TOKEN missing in env")?;

    // The blob file is the base64 ciphertext TEXT from `aws kms encrypt
    // --output text --query CiphertextBlob` — pass it through verbatim (trimmed),
    // do NOT re-encode. Validate it's well-formed base64 so a mangled paste
    // fails here, not as an opaque enclave bad_request.
    let ciphertext_b64 = std::fs::read_to_string(&blob)
        .with_context(|| format!("read registry ciphertext blob {}", blob.display()))?
        .trim()
        .to_owned();
    if ciphertext_b64.is_empty() {
        bail!("registry blob {} is empty", blob.display());
    }
    B64.decode(ciphertext_b64.as_bytes())
        .with_context(|| format!("registry blob {} is not valid base64", blob.display()))?;

    let refresh_bytes = std::fs::read(&refresh)
        .with_context(|| format!("read refresh params {}", refresh.display()))?;
    let params: RegistryRefreshParams = serde_json::from_slice(&refresh_bytes)
        .with_context(|| format!("parse {} as refresh params", refresh.display()))?;

    Ok(SignRequest {
        action: "registry_refresh".to_owned(),
        method: None,
        path: None,
        body: None,
        timestamp_ms: None,
        key_blob_s3_key: None,
        key_id: None,
        aws_credentials: Some(creds),
        ciphertext_blob_base64: Some(ciphertext_b64),
        registry_refresh: Some(params),
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

/// Write `bytes` to a NEW file with owner-only perms (0600 on unix). Fails if the
/// path already exists (atomic no-clobber via `create_new`) so a re-run never
/// silently overwrites a provisioned data-key blob and orphans its published
/// pubkey. Gemini security-medium (parent provisioning write).
fn write_new_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| {
        format!(
            "create new {} (already exists? refusing to clobber a provisioned key)",
            path.display()
        )
    })?;
    f.write_all(bytes)?;
    f.flush()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Capture the provision out-path before build_request consumes cli.cmd.
    let provision_out = match &cli.cmd {
        Cmd::ProvisionDataKey { out, .. } => Some(out.clone()),
        _ => None,
    };
    let req = build_request(cli.cmd)?;

    let resp = roundtrip(cli.cid, cli.port, &req).await?;
    if let Some(code) = resp.error.as_deref() {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        bail!("enclave returned error: {code}");
    }

    // Attested-data provisioning: persist the sealed envelope + surface the
    // pubkey for the operator to record (SIGNER_DATA_PUBKEY / _ADDRESS).
    //
    // FAIL-CLOSED (CodeRabbit Major): a provision command MUST receive a
    // `provision` payload — never exit 0 having written nothing. If `out` is set
    // (it WAS a provision call) but the enclave returned no `provision` field,
    // that's an error, not a silent success.
    if let Some(out) = provision_out {
        let prov = resp.provision.as_ref().context(
            "provision-data-key: enclave returned no `provision` payload — refusing \
             to exit 0 without a sealed key",
        )?;
        let blob = B64
            .decode(&prov.envelope_b64)
            .context("decode provision envelope_b64")?;
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        // Atomic no-clobber + owner-only perms (Gemini security-medium): refuse to
        // overwrite an already-provisioned blob (re-provision would orphan the
        // published pubkey) and never leave the key-bearing (sealed) blob
        // world-readable.
        write_new_private_file(&out, &blob)
            .with_context(|| format!("write sealed envelope to {}", out.display()))?;
        println!("attested-data key provisioned:");
        println!("  sealed envelope -> {}", out.display());
        println!("  SIGNER_DATA_PUBKEY={}", prov.pubkey_compressed);
        println!("  SIGNER_DATA_ADDRESS={}", prov.pubkey_address);
        return Ok(());
    }

    println!("{}", serde_json::to_string_pretty(&resp)?);
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
    fn build_request_registry_challenge_ok() {
        // Challenge needs no creds and no blob — just asks for a nonce.
        let req = build_request(Cmd::RegistryChallenge).expect("challenge always succeeds");
        assert_eq!(req.action, "registry_challenge");
        assert!(req.aws_credentials.is_none());
        assert!(req.ciphertext_blob_base64.is_none());
        assert!(req.registry_refresh.is_none());
        // Serializes to exactly {"action":"registry_challenge"} (skip_serializing_if).
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"action":"registry_challenge"}"#
        );
    }

    #[test]
    fn registry_refresh_params_roundtrip() {
        // The shape the parent forwards must match what `registry sign` emits.
        let json = r#"{"nonce_hex":"ab","version":7,"signature_hex":"cd"}"#;
        let p: RegistryRefreshParams = serde_json::from_str(json).unwrap();
        assert_eq!(p.version, 7);
        assert_eq!(p.nonce_hex, "ab");
        let req = SignRequest {
            action: "registry_refresh".to_owned(),
            method: None,
            path: None,
            body: None,
            timestamp_ms: None,
            key_blob_s3_key: None,
            key_id: None,
            aws_credentials: None,
            ciphertext_blob_base64: Some("Zg==".to_owned()),
            registry_refresh: Some(p),
        };
        // registry_refresh survives serialization (the enclave needs it).
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""registry_refresh":{"nonce_hex":"ab","version":7"#), "{s}");
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
            registry_refresh: None,
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
