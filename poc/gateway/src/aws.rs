//! AWS helpers used by the gateway.
//!
//! Currently the only AWS-flavoured surface here is IMDSv2 — the EC2
//! instance-metadata service that exposes the role's STS credentials. We
//! cache the credentials in `Arc<RwLock<>>` and refresh them shortly before
//! they expire.
//!
//! The KMS-encrypted ciphertext blob is intentionally NOT fetched from S3
//! in-process. The operator's systemd unit pre-stages the blob to a local
//! file (typically via `aws s3 cp` in `ExecStartPre`) and the gateway just
//! reads the path supplied in `SIGNER_BLOB_PATH`. That keeps SigV4 out of
//! the gateway's auditable binary; the only network surface here is IMDSv2.
//!
//! Logging policy: HTTP status codes and latencies are logged. AWS
//! credentials and ciphertext are NEVER logged.

use anyhow::{anyhow, bail, Context, Result};
use parking_lot::RwLock;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use zeroize::Zeroize;

use crate::vsock::AwsCredentials;

/// IMDSv2 endpoint (link-local). The `169.254.169.254` address is reserved
/// for instance-metadata service across every AZ.
const IMDS_BASE: &str = "http://169.254.169.254";

/// IMDSv2 PUT-token TTL. AWS caps this at 21600 (6 h); we use the upper
/// bound so a single token covers the whole gateway lifetime.
const IMDS_TOKEN_TTL_SECONDS: u32 = 21_600;

/// Refresh creds when their expiration is within this many seconds. STS
/// session creds typically last 6 h; refreshing 5 min early avoids the
/// edge where a request arrives just after expiry.
const CREDS_REFRESH_BEFORE_SECONDS: i64 = 300;

/// In-memory cache of role credentials. Held inside `Arc<RwLock<>>` so the
/// axum router can share it between worker tasks.
#[derive(Default)]
pub struct CredsCache {
    inner: RwLock<Option<CachedCreds>>,
}

struct CachedCreds {
    creds: AwsCredentials,
    /// Epoch seconds at which the creds expire (per IMDS metadata).
    expires_at_unix: i64,
}

impl CredsCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(None),
        })
    }

    /// Return a fresh copy of the role credentials. If the cached copy is
    /// missing or about to expire, this will block on a fresh IMDS fetch.
    /// The returned copy is the caller's responsibility to drop in a
    /// timely manner — `AwsCredentials` zeroizes itself on Drop.
    pub async fn get(self: &Arc<Self>) -> Result<AwsCredentials> {
        if let Some(c) = self.read_if_fresh() {
            return Ok(c);
        }
        // Slow path: fetch a fresh token + creds. We don't hold the
        // RwLock across the await (parking_lot RwLockGuard is !Send).
        let fresh = fetch_imds_credentials().await?;
        let mut guard = self.inner.write();
        *guard = Some(fresh.clone_cached());
        Ok(fresh.creds)
    }

    fn read_if_fresh(&self) -> Option<AwsCredentials> {
        let guard = self.inner.read();
        let cached = guard.as_ref()?;
        let now = unix_now();
        if cached.expires_at_unix - now > CREDS_REFRESH_BEFORE_SECONDS {
            Some(cached.creds.clone())
        } else {
            None
        }
    }
}

/// Result of a successful IMDS fetch — both the live `AwsCredentials` (for
/// returning to the caller) and the data needed to populate the cache.
struct FreshCreds {
    creds: AwsCredentials,
    expires_at_unix: i64,
}

impl FreshCreds {
    fn clone_cached(&self) -> CachedCreds {
        CachedCreds {
            creds: self.creds.clone(),
            expires_at_unix: self.expires_at_unix,
        }
    }
}

/// Raw IMDSv2 credentials JSON shape (subset). Trailing fields (`Type`,
/// `LastUpdated`, `Code`) that we don't use are ignored at parse time.
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ImdsCredsJson {
    AccessKeyId: String,
    SecretAccessKey: String,
    Token: String,
    /// RFC3339 timestamp, e.g. "2024-12-31T23:59:59Z".
    Expiration: String,
}

impl Drop for ImdsCredsJson {
    fn drop(&mut self) {
        // Wipe the heap allocations backing the secret + token. We don't
        // depend on Zeroize's derive here because the field names are
        // PascalCase (matching the JSON); explicit clear is auditable.
        self.SecretAccessKey.zeroize();
        self.Token.zeroize();
    }
}

/// Run the IMDSv2 token PUT and the credentials GET. Returns role creds
/// with their declared expiration. Fails if IMDS isn't reachable or the
/// instance has no role attached.
async fn fetch_imds_credentials() -> Result<FreshCreds> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        // IMDS is on a link-local address; explicit no-proxy avoids the
        // gateway picking up an HTTPS_PROXY env that would 404 the call.
        .no_proxy()
        .build()
        .context("build reqwest client")?;

    let token_resp = client
        .put(format!("{IMDS_BASE}/latest/api/token"))
        .header(
            "X-aws-ec2-metadata-token-ttl-seconds",
            IMDS_TOKEN_TTL_SECONDS.to_string(),
        )
        .send()
        .await
        .context("imds token PUT")?;
    if !token_resp.status().is_success() {
        bail!("imds token request failed: {}", token_resp.status());
    }
    let token = token_resp.text().await.context("imds token body")?;

    // Discover the role name attached to this instance.
    let role = client
        .get(format!(
            "{IMDS_BASE}/latest/meta-data/iam/security-credentials/"
        ))
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .context("imds role list")?
        .error_for_status()
        .context("imds role list status")?
        .text()
        .await
        .context("imds role list body")?;
    let role = role.trim();
    if role.is_empty() {
        bail!("instance has no IAM role attached");
    }

    let creds_url = format!("{IMDS_BASE}/latest/meta-data/iam/security-credentials/{role}");
    let creds_resp = client
        .get(&creds_url)
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .context("imds creds GET")?
        .error_for_status()
        .context("imds creds status")?;
    let creds_json: ImdsCredsJson = creds_resp.json().await.context("imds creds parse")?;

    let expires_at_unix =
        parse_rfc3339_to_unix(&creds_json.Expiration).context("parse imds Expiration field")?;

    let creds = AwsCredentials {
        access_key_id: creds_json.AccessKeyId.clone(),
        secret_access_key: creds_json.SecretAccessKey.clone(),
        session_token: creds_json.Token.clone(),
    };
    // creds_json drops here, zeroizing its private fields; only the
    // `creds` clone (also Zeroize-on-drop) survives.
    Ok(FreshCreds {
        creds,
        expires_at_unix,
    })
}

/// Minimal RFC3339 parser for the IMDS `Expiration` string. We only need
/// epoch seconds for the freshness comparison, so we can lean on the
/// fixed `YYYY-MM-DDThh:mm:ssZ` shape that IMDS always returns.
fn parse_rfc3339_to_unix(s: &str) -> Result<i64> {
    // Expected exact length: "1970-01-01T00:00:00Z" -> 20 chars.
    if s.len() < 20 || !s.ends_with('Z') {
        bail!("unexpected RFC3339 shape");
    }
    let bytes = s.as_bytes();
    // Verify the structural separators before slicing through them.
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        bail!("unexpected RFC3339 separators");
    }
    let year: i64 = s[0..4].parse().context("year")?;
    let month: i64 = s[5..7].parse().context("month")?;
    let day: i64 = s[8..10].parse().context("day")?;
    let hour: i64 = s[11..13].parse().context("hour")?;
    let minute: i64 = s[14..16].parse().context("minute")?;
    let second: i64 = s[17..19].parse().context("second")?;

    // Days from epoch using Howard Hinnant's "days_from_civil" algorithm.
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400).rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Load the KMS-encrypted ciphertext blob from a local file path. The
/// operator pre-stages the file via `aws s3 cp` in their systemd unit;
/// the gateway just reads it once at startup.
pub fn load_blob_from_path(path: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("read blob {path}"))?;
    if bytes.is_empty() {
        return Err(anyhow!("blob file is empty: {path}"));
    }
    if bytes.len() > 8 * 1024 {
        return Err(anyhow!(
            "blob exceeds 8 KiB enclave cap (got {} bytes)",
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rfc3339_round_trip() {
        // 1970-01-01T00:00:00Z -> 0
        assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:00Z").unwrap(), 0);
        // 2026-05-07T12:00:00Z -> reproducible value
        let v = parse_rfc3339_to_unix("2026-05-07T12:00:00Z").unwrap();
        // Sanity: must be after 2024-01-01 (1704067200) and before 2030.
        assert!(v > 1_704_067_200);
        assert!(v < 1_900_000_000);
    }

    #[test]
    fn parse_rfc3339_rejects_bad_shapes() {
        assert!(parse_rfc3339_to_unix("not-a-date").is_err());
        assert!(parse_rfc3339_to_unix("2026-05-07 12:00:00Z").is_err());
        assert!(parse_rfc3339_to_unix("").is_err());
    }

    #[test]
    fn creds_cache_starts_empty() {
        let cache = CredsCache::new();
        assert!(cache.read_if_fresh().is_none());
    }

    #[test]
    fn load_blob_rejects_missing_file() {
        let r = load_blob_from_path("/tmp/this-path-definitely-does-not-exist-9876543210");
        assert!(r.is_err());
    }

    #[test]
    fn load_blob_rejects_oversize() {
        let path = std::env::temp_dir().join("signer-gateway-oversize-fixture.bin");
        std::fs::write(&path, vec![0u8; 9_000]).expect("seed file");
        let r = load_blob_from_path(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        assert!(r.is_err());
    }
}
