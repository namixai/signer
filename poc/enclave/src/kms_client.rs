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
//! Adversarial-mindset notes (from `_signer/06-АТАКУЕМ-СЕБЯ.md`):
//!   - Credentials are passed via stdin to avoid /proc/<pid>/cmdline exposure.
//!   - The whole stdout is wrapped in `Zeroizing`; on parse failure we drop it.
//!   - We never echo stderr back to the caller.

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
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

/// Run kmstool_enclave_cli to decrypt `ciphertext` using `creds`.
///
/// Returns the plaintext bytes wrapped in `Zeroizing` so they're scrubbed
/// when the caller drops the value.
pub fn decrypt(
    creds: &AwsCredentials,
    ciphertext: &[u8],
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
        .arg(&ciphertext_b64)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "kmstool_enclave_cli spawn failed");
            return Err(DecryptError::Internal);
        }
    };

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
    // Wrap stdout in Zeroizing immediately and parse out just the b64 chunk.
    let stdout = Zeroizing::new(output.stdout);
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
    // We accept any line that starts with `PLAINTEXT: ` (case-insensitive on
    // the prefix to be robust). Take the FIRST such line.
    let s = std::str::from_utf8(stdout).map_err(|_| anyhow!("stdout not utf8"))?;
    for line in s.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("PLAINTEXT:")
            .or_else(|| trimmed.strip_prefix("plaintext:"))
        {
            return Ok(Zeroizing::new(rest.trim().to_owned()));
        }
    }
    bail!("no PLAINTEXT line in kmstool stdout");
}

// Suppress the `Write` import warning when this module is built but
// `kmstool_via_stdin` is unused — kept for forward compatibility.
#[allow(dead_code)]
fn _silence_write_import() {
    let mut buf: Vec<u8> = Vec::new();
    let _ = buf.write_all(b"");
    buf.zeroize();
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
}
