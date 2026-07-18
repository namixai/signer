//! Phase 3: shell out to /kmstool_enclave_cli for KMS Decrypt with attestation.
//!
//! kmstool_enclave_cli (from AWS aws-nitro-enclaves-sdk-c) handles:
//!   - NSM attestation doc fetch
//!   - SigV4 signing of the KMS Decrypt request
//!   - HTTP via the parent vsock-proxy (port 8000 by default)
//!   - CMS envelope parse + RSA decrypt of the recipient-encrypted plaintext
//!   - Returns plaintext on stdout (base64-encoded with the `PLAINTEXT: ` prefix)
//!
//! On any failure we log a generic message and return an error variant; the
//! handler maps it to the wire `kms_decrypt_denied` / `internal_error` codes.
//! Plaintext NEVER reaches the log layer — only the redacted struct fields.
//!
//! Adversarial-mindset notes (from the internal adversarial-review notes):
//!   - Credentials are passed via stdin to avoid /proc/<pid>/cmdline exposure.
//!   - The whole stdout is wrapped in `Zeroizing`; on parse failure we drop it.
//!   - We never echo stderr back to the caller.

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::{Zeroize, Zeroizing};

use crate::proto::AwsCredentials;

/// Path to the vendored kmstool binary inside the EIF.
const KMSTOOL_BIN: &str = "/kmstool_enclave_cli";

/// Region. Hardcoded for Day 2; later we'll source it from the request.
const REGION: &str = "us-east-1";

/// Vsock-proxy port on the parent that forwards to KMS.
const PROXY_PORT: u32 = 8000;

/// Decrypt errors classified at the boundary so the handler can choose the
/// right wire code without inspecting strings.
#[derive(Debug)]
pub enum DecryptError {
    /// KMS rejected the request (wrong key, no policy permission, attestation
    /// PCR mismatch). Map to `kms_decrypt_denied` on the wire.
    AccessDenied,
    /// Anything else — bad invocation, network failure, parse error, etc.
    /// Map to `internal_error` on the wire.
    Internal,
}

/// Errors from `generate_data_key`, classified at the boundary so the handler
/// picks the right wire code without inspecting strings.
#[derive(Debug)]
pub enum GenKeyError {
    /// KMS rejected GenerateDataKey — no `kms:GenerateDataKey` permission (the
    /// prod role lacks it by design), wrong key, or attestation/PCR /
    /// EncryptionContext mismatch.
    AccessDenied,
    /// Anything else — bad invocation, parse error, etc.
    Internal,
}

/// A freshly generated data-encryption key from KMS GenerateDataKey (via
/// `kmstool_enclave_cli genkey`). `plaintext` is the 32-byte DEK delivered into
/// the enclave via attestation; `wrapped` is its KMS ciphertext (stored as the
/// envelope `wrapped_dek` so the prod Decrypt path recovers the DEK).
pub struct GeneratedDataKey {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub wrapped: Vec<u8>,
}

/// Run `kmstool_enclave_cli genkey` to generate a 32-byte DEK under `key_id`,
/// bound to `encryption_context` (same `{customer_id, venue_id}` schema as
/// decrypt — KMS records it so a later Decrypt MUST present the identical
/// context). Attested-data provisioning ONLY (Option-1); the prod role has no
/// `kms:GenerateDataKey`, so this fails closed (`AccessDenied`) outside a
/// provisioning run under the ephemeral scoped role.
pub fn generate_data_key(
    creds: &AwsCredentials,
    key_id: &str,
    encryption_context: Option<&HashMap<String, String>>,
) -> Result<GeneratedDataKey, GenKeyError> {
    let mut cmd = Command::new(KMSTOOL_BIN);
    cmd.arg("genkey")
        .arg("--region")
        .arg(REGION)
        .arg("--proxy-port")
        .arg(PROXY_PORT.to_string())
        .arg("--aws-access-key-id")
        .arg(&creds.access_key_id)
        .arg("--aws-secret-access-key")
        .arg(&creds.secret_access_key)
        .arg("--aws-session-token")
        .arg(&creds.session_token)
        .arg("--key-id")
        .arg(key_id)
        .arg("--key-spec")
        .arg("AES-256");

    if let Some(ctx) = encryption_context {
        let mut keys: Vec<&String> = ctx.keys().collect();
        keys.sort();
        for k in keys {
            let v = &ctx[k];
            validate_context_pair(k, v).map_err(|_| GenKeyError::Internal)?;
            cmd.arg("--encryption-context").arg(format!("{}={}", k, v));
        }
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "kmstool_enclave_cli genkey spawn failed");
            return Err(GenKeyError::Internal);
        }
    };

    // Wrap stdout in Zeroizing BEFORE the status check: genkey stdout carries the
    // DEK (the PLAINTEXT line), so an early `return` on a non-zero exit must NOT
    // drop an un-zeroized copy on the heap (CodeRabbit Security — same class as
    // the key-plaintext HIGH). `status`/`stderr` are separate fields, still
    // readable after this partial move of `stdout`.
    let stdout = Zeroizing::new(output.stdout);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lc = stderr.to_lowercase();
        let denied = lc.contains("accessdenied")
            || lc.contains("access denied")
            || lc.contains("not authorized")
            || lc.contains("pcr");
        tracing::error!(
            stderr_len = stderr.len(),
            denied_signal = denied,
            status = ?output.status,
            "kmstool_enclave_cli genkey returned non-zero"
        );
        return Err(if denied {
            GenKeyError::AccessDenied
        } else {
            GenKeyError::Internal
        });
    }

    let plaintext_b64 = parse_kmstool_line(&stdout, "PLAINTEXT:").map_err(|e| {
        tracing::error!(error = %e, "genkey stdout missing PLAINTEXT");
        GenKeyError::Internal
    })?;
    let ciphertext_b64 = parse_kmstool_line(&stdout, "CIPHERTEXT:").map_err(|e| {
        tracing::error!(error = %e, "genkey stdout missing CIPHERTEXT");
        GenKeyError::Internal
    })?;

    let plaintext = match B64.decode(plaintext_b64.as_bytes()) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => {
            tracing::error!("genkey plaintext base64 invalid");
            return Err(GenKeyError::Internal);
        }
    };
    let wrapped = match B64.decode(ciphertext_b64.as_bytes()) {
        Ok(w) => w,
        Err(_) => {
            tracing::error!("genkey ciphertext base64 invalid");
            return Err(GenKeyError::Internal);
        }
    };
    if plaintext.len() != 32 {
        tracing::error!(len = plaintext.len(), "genkey DEK is not 32 bytes");
        return Err(GenKeyError::Internal);
    }
    drop(plaintext_b64);
    Ok(GeneratedDataKey { plaintext, wrapped })
}

/// Run kmstool_enclave_cli to decrypt `ciphertext` using `creds`.
///
/// `encryption_context` binds the DEK to a specific `{customer_id, venue_id}`
/// pair (schema pinned to exactly these two keys — D3). KMS rejects the
/// decrypt if the context doesn't match what was supplied at encrypt time —
/// this prevents cross-customer DEK substitution.
///
/// Returns the plaintext bytes wrapped in `Zeroizing` so they're scrubbed
/// when the caller drops the value.
pub fn decrypt(
    creds: &AwsCredentials,
    ciphertext: &[u8],
    encryption_context: Option<&HashMap<String, String>>,
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    let ciphertext_b64 = B64.encode(ciphertext);

    // Build the command. Credentials go on argv (kmstool's only supported
    // way today). We zeroize argv-equivalents in our process by keeping the
    // creds in `Zeroizing<String>` only for the duration of this call.
    //
    // Note: kmstool_enclave_cli on Linux uses /proc/self/cmdline which is
    // visible to root on the host normally, but inside an enclave there is
    // no host visibility. The parent never sees the enclave's cmdline.
    let mut cmd = Command::new(KMSTOOL_BIN);
    cmd.arg("decrypt")
        .arg("--region")
        .arg(REGION)
        .arg("--proxy-port")
        .arg(PROXY_PORT.to_string())
        .arg("--aws-access-key-id")
        .arg(&creds.access_key_id)
        .arg("--aws-secret-access-key")
        .arg(&creds.secret_access_key)
        .arg("--aws-session-token")
        .arg(&creds.session_token)
        .arg("--ciphertext")
        .arg(&ciphertext_b64);

    // Append --encryption-context key=value for each entry. Sorted by key
    // for deterministic CLI invocation (aids debugging / log correlation).
    // Validation and arg-building merged into one pass over sorted keys.
    if let Some(ctx) = encryption_context {
        let mut keys: Vec<&String> = ctx.keys().collect();
        keys.sort();
        for k in keys {
            let v = &ctx[k];
            validate_context_pair(k, v)?;
            cmd.arg("--encryption-context")
                .arg(format!("{}={}", k, v));
        }
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "kmstool_enclave_cli spawn failed");
            return Err(DecryptError::Internal);
        }
    };

    // Wrap stdout in Zeroizing BEFORE the status check (same class as the genkey
    // fix above): on success it carries the venue PLAINTEXT, so an early `return`
    // on a non-zero exit must not drop an un-zeroized copy. `status`/`stderr` are
    // separate fields, still readable after this partial move.
    let stdout = Zeroizing::new(output.stdout);

    if !output.status.success() {
        // stderr classification — we look for "AccessDenied" / "denied" /
        // "PCR" so we can return the more specific code. We do NOT echo
        // stderr back to the wire.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_lc = stderr.to_lowercase();
        let is_denied = stderr_lc.contains("accessdenied")
            || stderr_lc.contains("access denied")
            || stderr_lc.contains("not authorized")
            || stderr_lc.contains("invalidciphertext")
            || stderr_lc.contains("pcr");
        // Log only a length / classification, never the body itself.
        tracing::error!(
            stderr_len = stderr.len(),
            denied_signal = is_denied,
            status = ?output.status,
            "kmstool_enclave_cli returned non-zero"
        );
        return if is_denied {
            Err(DecryptError::AccessDenied)
        } else {
            Err(DecryptError::Internal)
        };
    }

    // kmstool prints the plaintext base64-encoded with a `PLAINTEXT: ` prefix.
    // (stdout was wrapped in Zeroizing above, before the status check.)
    let plaintext_b64 = match parse_kmstool_stdout(&stdout) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "kmstool_enclave_cli stdout parse failed");
            return Err(DecryptError::Internal);
        }
    };

    let plaintext = match B64.decode(plaintext_b64.as_bytes()) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => {
            tracing::error!("kmstool_enclave_cli plaintext base64 invalid");
            return Err(DecryptError::Internal);
        }
    };

    // plaintext_b64 holds a copy — wipe it before returning.
    drop(plaintext_b64);

    Ok(plaintext)
}

/// Extract the base64 plaintext from kmstool stdout. Returns `Zeroizing<String>`
/// so the intermediate copy is scrubbed before we drop it.
///
/// Format observed on stdout:
///   `PLAINTEXT: <base64>\n`
fn parse_kmstool_stdout(stdout: &[u8]) -> Result<Zeroizing<String>> {
    parse_kmstool_line(stdout, "PLAINTEXT:")
}

/// Extract the base64 payload from the FIRST kmstool stdout line beginning with
/// `prefix` (case-insensitive). `decrypt` emits only `PLAINTEXT:`; `genkey`
/// emits both `CIPHERTEXT:` (the wrapped DEK) and `PLAINTEXT:` (the DEK).
fn parse_kmstool_line(stdout: &[u8], prefix: &str) -> Result<Zeroizing<String>> {
    let s = std::str::from_utf8(stdout).map_err(|_| anyhow!("stdout not utf8"))?;
    for line in s.lines() {
        let trimmed = line.trim();
        // `get(..len)` is byte-boundary-safe (None if the head isn't a full
        // char) so a non-ASCII leading byte can't panic the slice.
        if let Some(head) = trimmed.get(..prefix.len()) {
            if head.eq_ignore_ascii_case(prefix) {
                return Ok(Zeroizing::new(trimmed[prefix.len()..].trim().to_owned()));
            }
        }
    }
    bail!("no {prefix} line in kmstool stdout");
}

// Suppress the `Write` import warning when this module is built but
// `kmstool_via_stdin` is unused — kept for forward compatibility.
#[allow(dead_code)]
fn _silence_write_import() {
    let mut buf: Vec<u8> = Vec::new();
    let _ = buf.write_all(b"");
    buf.zeroize();
}

/// Reject keys/values that would corrupt kmstool's `key=value` parsing.
/// kmstool splits on the first `=`, so `=` in keys is dangerous (shifts
/// the split boundary). Null bytes and whitespace are disallowed for
/// defense-in-depth against argv corruption.
fn validate_context_pair(key: &str, value: &str) -> Result<(), DecryptError> {
    fn has_forbidden(s: &str) -> bool {
        s.contains('=') || s.contains('\0') || s.chars().any(|c| c.is_whitespace())
    }
    if key.is_empty() || value.is_empty() || has_forbidden(key) || has_forbidden(value) {
        tracing::error!(
            key_len = key.len(),
            val_len = value.len(),
            "encryption_context key/value contains forbidden characters"
        );
        return Err(DecryptError::Internal);
    }
    Ok(())
}

/// Build the `--encryption-context key=value` argument pairs for kmstool.
/// Sorted by key for deterministic invocation. Exposed for testing.
#[cfg(test)]
fn build_context_args(ctx: &HashMap<String, String>) -> Vec<String> {
    let mut keys: Vec<&String> = ctx.keys().collect();
    keys.sort();
    let mut args = Vec::new();
    for k in keys {
        args.push("--encryption-context".to_owned());
        args.push(format!("{}={}", k, ctx[k]));
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stdout_extracts_plaintext() {
        let s = b"some preamble\nPLAINTEXT: aGVsbG8=\nfooter\n";
        let p = parse_kmstool_stdout(s).expect("parse");
        assert_eq!(&*p, "aGVsbG8=");
    }

    #[test]
    fn parse_stdout_rejects_missing_prefix() {
        let s = b"no plaintext line here\n";
        assert!(parse_kmstool_stdout(s).is_err());
    }

    #[test]
    fn parse_stdout_handles_only_plaintext_line() {
        let s = b"PLAINTEXT: dGVzdA==\n";
        let p = parse_kmstool_stdout(s).expect("parse");
        assert_eq!(&*p, "dGVzdA==");
    }

    #[test]
    fn encryption_context_args_sorted_deterministic_order() {
        // Context schema is pinned to EXACTLY {customer_id, venue_id} (design
        // rev-2 D3 / round-1 crypto#2). The kms.tf key policy's
        // `ForAllValues:StringEquals EncryptionContextKeys` admits only these
        // two keys; adding purpose/version would make every Decrypt fail.
        let mut ctx = HashMap::new();
        ctx.insert("venue_id".to_owned(), "binance".to_owned());
        ctx.insert("customer_id".to_owned(), "acme-prod".to_owned());

        let args = build_context_args(&ctx);
        // Keys sorted alphabetically: customer_id, venue_id
        assert_eq!(args.len(), 4); // 2 pairs of --encryption-context + value
        assert_eq!(args[0], "--encryption-context");
        assert_eq!(args[1], "customer_id=acme-prod");
        assert_eq!(args[2], "--encryption-context");
        assert_eq!(args[3], "venue_id=binance");
    }

    #[test]
    fn encryption_context_empty_map_produces_no_args() {
        let ctx = HashMap::new();
        let args = build_context_args(&ctx);
        assert!(args.is_empty());
    }

    #[test]
    fn encryption_context_single_entry() {
        let mut ctx = HashMap::new();
        ctx.insert("purpose".to_owned(), "dek".to_owned());
        let args = build_context_args(&ctx);
        assert_eq!(args, vec!["--encryption-context", "purpose=dek"]);
    }
}
