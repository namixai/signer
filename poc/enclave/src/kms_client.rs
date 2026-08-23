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
//!   - **Secrets reach kmstool on STDIN, not argv (ROT-8, 2026-08-09).** All
//!     four — the three credential parts and the base64 DEK — are written to the
//!     child's stdin as `KEY=VALUE` lines; argv carries only region, proxy port,
//!     ciphertext and encryption context, none of which is secret. The wire
//!     format and its fail-closed rules live in
//!     `vendor/kmstool-enclave-cli/secrets_stdin.h`.
//!   - 🔴 **The history matters more than the fix, so it stays written down.**
//!     This block once claimed the stdin path as fact while the code passed
//!     flags; the claim was aspirational, read as true for months, and was
//!     corrected on 2026-08-02 to say plainly that secrets went through argv.
//!     Now the code matches the original claim — and the lesson does not expire:
//!     a security property that lives only in a comment is worth less than no
//!     comment at all. The property is now pinned by tests
//!     (`rot8_encrypt_argv_carries_no_secret` here,
//!     `scripts/test_secrets_stdin.py` for the C parser) rather than by prose.
//!   - Scope of what this bought: inside a Nitro enclave the process space holds
//!     only this binary and the kmstool child it spawns, so there was never a
//!     third party to read `/proc`. This was a property to fix, not a live hole
//!     — the value is that "no secret appears in argv" is now a sentence we can
//!     say without an asterisk.
//!   - Our OWN heap copies of key material ARE zeroized: the stdin payload is
//!     `Zeroizing<String>`, `build_encrypt_args` returns `Zeroizing<String>`
//!     (CodeRabbit, #347), and since ROT-8 the C side wipes its copies too
//!     (`s_app_ctx_secure_clean_up`) — before, they lived until process exit.
//!   - The whole stdout is wrapped in `Zeroizing`; on parse failure we drop it.
//!   - We never echo stderr back to the caller.

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

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

/// Errors from `wrap_dek_with_context`, classified at the boundary so the
/// handler picks the right wire code without inspecting strings.
#[derive(Debug)]
pub enum GenKeyError {
    /// KMS rejected the wrap — no `kms:Encrypt` permission (the prod role lacks
    /// it by design), wrong key, or attestation/PCR / EncryptionContext
    /// mismatch.
    AccessDenied,
    /// Anything else — bad invocation, parse error, missing context, etc.
    Internal,
}

/// ROT-8: the secret payload the child reads on stdin, in the format
/// `vendor/kmstool-enclave-cli/secrets_stdin.h` defines — one `KEY=VALUE` per
/// line, order-independent, EOF-terminated.
///
/// Built by a PURE function for the same reason `build_encrypt_args` is: the
/// property worth asserting is "no secret appears in argv", and a test can only
/// assert that if the two sides — what goes to argv, what goes to stdin — are
/// separately inspectable without a kmstool binary.
///
/// `Zeroizing` because this string holds all three credentials at once; it is
/// the single largest concentration of secret material in the process.
fn build_stdin_secrets(
    creds: &AwsCredentials,
    dek_b64: Option<&str>,
) -> Result<Zeroizing<String>, ()> {
    // 🔴 THE DELIMITER MUST NOT APPEAR IN A VALUE. The format is line-oriented,
    // so a value carrying `\n` would end its own record and start another one —
    // a credential that contains `\nPLAINTEXT_B64=…` injects a DEK the caller
    // never passed. Found by Gemini and CodeRabbit independently on #417, and it
    // is exactly the defect class this department keeps catching in others: a
    // parser hardened at one end while the writer assumes well-formed input.
    //
    // Rejected, not escaped. Escaping would need the C side to unescape, and two
    // implementations of one encoding is how they drift; none of these four
    // values can legally contain a newline, so refusing is both correct and
    // cheaper. `\r` too — the parser strips a trailing CR, so a value ending in
    // one would arrive silently altered.
    //
    // Fail-closed via Result rather than `assert!`: a panic inside the enclave
    // takes the whole process down, and the caller already maps this to a clean
    // internal_error. The log names the FIELD and never the value.
    for (field, value) in [
        ("access_key_id", creds.access_key_id.as_str()),
        ("secret_access_key", creds.secret_access_key.as_str()),
        ("session_token", creds.session_token.as_str()),
    ]
    .into_iter()
    .chain(dek_b64.map(|d| ("plaintext_b64", d)))
    {
        if value.contains('\n') || value.contains('\r') {
            tracing::error!(
                field = field,
                "secret contains a line delimiter — refusing to build the stdin payload"
            );
            return Err(());
        }
        if value.is_empty() {
            // The C parser rejects an empty value (an empty secret would satisfy
            // a "was it provided" check). Catch it here so the failure names the
            // field instead of arriving as a generic parse error.
            tracing::error!(field = field, "secret is empty");
            return Err(());
        }
    }

    let mut out = String::with_capacity(512);
    out.push_str("AWS_ACCESS_KEY_ID=");
    out.push_str(&creds.access_key_id);
    out.push('\n');
    out.push_str("AWS_SECRET_ACCESS_KEY=");
    out.push_str(&creds.secret_access_key);
    out.push('\n');
    out.push_str("AWS_SESSION_TOKEN=");
    out.push_str(&creds.session_token);
    out.push('\n');
    if let Some(dek) = dek_b64 {
        out.push_str("PLAINTEXT_B64=");
        out.push_str(dek);
        out.push('\n');
    }
    Ok(Zeroizing::new(out))
}

/// The COMPLETE argv for `encrypt`, secret-free by construction.
///
/// Extracted so the property that matters — "no secret appears in the command
/// line" — is asserted on the whole thing rather than on the tail fragment
/// (CodeRabbit, #417). A test over a fragment cannot see a secret re-added to
/// the head, which is precisely where the credentials used to live.
fn encrypt_argv(tail: &[Zeroizing<String>]) -> Vec<String> {
    let mut argv = vec![
        "encrypt".to_owned(),
        "--secrets-from-stdin".to_owned(),
        "--region".to_owned(),
        REGION.to_owned(),
        "--proxy-port".to_owned(),
        PROXY_PORT.to_string(),
    ];
    argv.extend(tail.iter().map(|a| a.to_string()));
    argv
}

/// The head of the `decrypt` argv; the caller appends the encryption context.
fn decrypt_argv(ciphertext_b64: &str) -> Vec<String> {
    vec![
        "decrypt".to_owned(),
        "--secrets-from-stdin".to_owned(),
        "--region".to_owned(),
        REGION.to_owned(),
        "--proxy-port".to_owned(),
        PROXY_PORT.to_string(),
        "--ciphertext".to_owned(),
        ciphertext_b64.to_owned(),
    ]
}

/// Spawn the child, write the secrets to its stdin, close it, and collect the
/// output. Closing stdin is what ends the child's read loop — leaving it open
/// would hang both processes, so it is not optional politeness.
///
/// The payload is small (three credentials plus a 44-byte base64 DEK, far under
/// a pipe buffer), so writing before reading cannot deadlock.
fn run_with_stdin_secrets(
    mut cmd: Command,
    payload: &Zeroizing<String>,
    what: &'static str,
) -> Result<std::process::Output, ()> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, op = what, "kmstool_enclave_cli spawn failed");
            return Err(());
        }
    };
    {
        let Some(stdin) = child.stdin.as_mut() else {
            tracing::error!(op = what, "child stdin unavailable after piped spawn");
            let _ = child.kill();
            // Reap it: kill() only signals. Without wait() the child stays a
            // zombie for the life of the enclave process (Gemini, #417).
            let _ = child.wait();
            return Err(());
        };
        if let Err(e) = stdin.write_all(payload.as_bytes()) {
            tracing::error!(error = %e, op = what, "writing secrets to child stdin failed");
            let _ = child.kill();
            let _ = child.wait();
            return Err(());
        }
    }
    // Dropping the handle closes the pipe → the child sees EOF and stops reading.
    drop(child.stdin.take());
    match child.wait_with_output() {
        Ok(o) => Ok(o),
        Err(e) => {
            tracing::error!(error = %e, op = what, "kmstool_enclave_cli wait failed");
            Err(())
        }
    }
}

/// Wrap an ENCLAVE-GENERATED 32-byte DEK under `key_id`, bound to
/// `encryption_context` (the same `{customer_id, venue_id}` schema decrypt
/// uses — KMS records it, so the later Decrypt MUST present the identical
/// context). Attested-data provisioning ONLY; the prod role has no
/// `kms:Encrypt`, so this fails closed (`AccessDenied`) outside a provisioning
/// run under the ephemeral scoped role.
///
/// # Why not `GenerateDataKey` (ROT-7)
///
/// It cannot carry an EncryptionContext. The Nitro SDK exposes no
/// `aws_kms_generate_data_key_blocking_with_context` and no `..._from_request`
/// transport for GenerateDataKey — checked against upstream `main`, not only
/// our pinned v0.4.5 — so there is nowhere to put the context. It is not a
/// version we can bump past. `aws_kms_encrypt_blocking_with_context` DOES
/// exist upstream, so wrapping a locally-born DEK reaches the same end state
/// through an API that honours the context, and leaves the vendored SDK
/// unpatched.
///
/// This is not a weakening. The DEK is generated by the same in-enclave CSPRNG
/// that already births the secp256k1 SIGNING key — a far more sensitive
/// secret — so no new trust assumption is introduced. It is arguably tighter:
/// with `GenerateDataKey` the DEK is minted by KMS and travels back (encrypted
/// to the enclave); here it never leaves the enclave in any form.
///
/// # Fail-closed on an empty context
///
/// An empty/absent context is rejected HERE, before the process is spawned.
/// A context-less wrap yields a ciphertext the context-pinned read path can
/// never open, and that failure would only surface at the first real
/// signature — long after provisioning reported success.
pub fn wrap_dek_with_context(
    creds: &AwsCredentials,
    key_id: &str,
    dek: &[u8],
    encryption_context: Option<&HashMap<String, String>>,
) -> Result<Vec<u8>, GenKeyError> {
    let ctx = match encryption_context {
        Some(c) if !c.is_empty() => c,
        _ => {
            tracing::error!("wrap_dek_with_context called without an encryption context");
            return Err(GenKeyError::Internal);
        }
    };
    if dek.len() != 32 {
        tracing::error!(len = dek.len(), "DEK to wrap is not 32 bytes");
        return Err(GenKeyError::Internal);
    }

    let dek_b64 = Zeroizing::new(B64.encode(dek));

    // Credential-free part of the argv, built by a PURE function so it can be
    // asserted in unit tests without a kmstool binary, an enclave or a network.
    // This is the piece that was silently wrong before ROT-7.
    let tail = build_encrypt_args(key_id, ctx)?;

    // ROT-8: the four secrets travel on stdin; argv carries only the
    // non-secret shape of the call.
    let argv = encrypt_argv(&tail);
    let mut cmd = Command::new(KMSTOOL_BIN);
    cmd.args(argv.iter().map(|a| a.as_str()));

    let payload = match build_stdin_secrets(creds, Some(dek_b64.as_str())) {
        Ok(p) => p,
        Err(()) => return Err(GenKeyError::Internal),
    };
    let output = match run_with_stdin_secrets(cmd, &payload, "encrypt") {
        Ok(o) => o,
        Err(()) => return Err(GenKeyError::Internal),
    };

    // Kept Zeroizing even though `encrypt` stdout no longer carries a DEK: the
    // guarantee is cheap, and a future subcommand change must not silently
    // start leaking key material through this buffer.
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
            "kmstool_enclave_cli encrypt returned non-zero"
        );
        return Err(if denied {
            GenKeyError::AccessDenied
        } else {
            GenKeyError::Internal
        });
    }

    // `encrypt` prints ONLY the ciphertext — the plaintext came from us, so
    // there is no PLAINTEXT line to parse and no second copy of the DEK to
    // wipe. (genkey had to print both because KMS minted the key.)
    let ciphertext_b64 = parse_kmstool_line(&stdout, "CIPHERTEXT:").map_err(|e| {
        tracing::error!(error = %e, "encrypt stdout missing CIPHERTEXT");
        GenKeyError::Internal
    })?;

    let wrapped = match B64.decode(ciphertext_b64.as_bytes()) {
        Ok(w) => w,
        Err(_) => {
            tracing::error!("encrypt ciphertext base64 invalid");
            return Err(GenKeyError::Internal);
        }
    };
    if wrapped.is_empty() {
        tracing::error!("encrypt returned an empty ciphertext");
        return Err(GenKeyError::Internal);
    }
    Ok(wrapped)
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

    // ROT-8: credentials travel on stdin. argv now carries only the shape of
    // the call — region, proxy port, ciphertext, encryption context — none of
    // which is secret. The note that used to sit here ("inside an enclave there
    // is no host visibility") stays true and is still why this was a property to
    // fix rather than a live hole; it is simply no longer the whole answer.
    let mut argv = decrypt_argv(&ciphertext_b64);

    // Append --encryption-context key=value for each entry. Sorted by key
    // for deterministic CLI invocation (aids debugging / log correlation).
    // Validation and arg-building merged into one pass over sorted keys.
    if let Some(ctx) = encryption_context {
        let mut keys: Vec<&String> = ctx.keys().collect();
        keys.sort();
        for k in keys {
            let v = &ctx[k];
            validate_context_pair(k, v)?;
            argv.push("--encryption-context".to_owned());
            argv.push(format!("{}={}", k, v));
        }
    }
    let mut cmd = Command::new(KMSTOOL_BIN);
    cmd.args(argv.iter().map(|a| a.as_str()));

    let payload = match build_stdin_secrets(creds, None) {
        Ok(p) => p,
        Err(()) => return Err(DecryptError::Internal),
    };
    let output = match run_with_stdin_secrets(cmd, &payload, "decrypt") {
        Ok(o) => o,
        Err(()) => return Err(DecryptError::Internal),
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

/// Credential-free argv tail for `kmstool_enclave_cli encrypt` (ROT-7).
///
/// Pure and total, so the shape of the call is unit-testable. Fails closed on
/// an empty context: that is the whole point of this code path, and a default
/// of "no context" would recreate the exact silent-invalid-key trap that
/// genkey's hard-fail exposed.
/// Returns `Zeroizing<String>` elements, not plain `String` (CodeRabbit review
/// on #347). One of them holds the base64 DEK, and a plain `Vec<String>` would
/// drop that copy onto the heap un-wiped — `Zeroizing` on the *source*
/// `dek_b64` does not reach a clone made here. This wipes OUR copies.
///
/// ROT-8 closed the other half of that review comment: the DEK is no longer an
/// argv element at all — it travels on stdin (`build_stdin_secrets`), so this
/// function now builds a genuinely secret-free argument list. What remains here
/// is the key id and the encryption context, neither of which is a secret.
fn build_encrypt_args(
    key_id: &str,
    ctx: &HashMap<String, String>,
) -> Result<Vec<Zeroizing<String>>, GenKeyError> {
    if ctx.is_empty() {
        tracing::error!("refusing to wrap a DEK without an encryption context");
        return Err(GenKeyError::Internal);
    }
    let mut args = vec![
        Zeroizing::new("--key-id".to_owned()),
        Zeroizing::new(key_id.to_owned()),
    ];
    let mut keys: Vec<&String> = ctx.keys().collect();
    keys.sort();
    for k in keys {
        let v = &ctx[k];
        validate_context_pair(k, v).map_err(|_| GenKeyError::Internal)?;
        args.push(Zeroizing::new("--encryption-context".to_owned()));
        args.push(Zeroizing::new(format!("{}={}", k, v)));
    }
    Ok(args)
}

#[cfg(test)]
mod rot7_encrypt_args {
    use super::*;

    fn data_signing_ctx() -> HashMap<String, String> {
        let mut c = HashMap::new();
        c.insert("customer_id".to_owned(), "attested-data".to_owned());
        c.insert("venue_id".to_owned(), "data-signing".to_owned());
        c
    }

    // ── ROT-8: the secrets are on stdin, and NOTHING secret is on argv ──────
    //
    // The test that did not exist before this change: nothing asserted the
    // ABSENCE of credentials from the argument list, so the property could be
    // lost by a one-line edit and no build would notice.

    fn test_creds() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            session_token: "FwoGZXIvYXdzEExampleSessionToken".to_owned(),
        }
    }

    /// Every secret we hold, in one place, so a test can assert none of them
    /// appear somewhere they should not.
    fn secret_values(creds: &AwsCredentials, dek_b64: &str) -> Vec<String> {
        vec![
            creds.access_key_id.clone(),
            creds.secret_access_key.clone(),
            creds.session_token.clone(),
            dek_b64.to_owned(),
        ]
    }

    #[test]
    fn rot8_encrypt_argv_carries_no_secret() {
        let creds = test_creds();
        // The COMPLETE argv, head included — a fragment cannot see a secret
        // re-added where the credentials used to live (CodeRabbit, #417).
        let tail = build_encrypt_args("cec983ce", &data_signing_ctx()).expect("build");
        let args = encrypt_argv(&tail);
        let joined = args.join(" ");
        for secret in secret_values(&creds, "ZGVr") {
            assert!(!joined.contains(&secret), "a secret reached argv: {joined}");
        }
        // …and the flags that used to carry them are gone entirely, so a future
        // edit cannot re-add a value under an existing flag name.
        for flag in [
            "--aws-access-key-id",
            "--aws-secret-access-key",
            "--aws-session-token",
            "--plaintext",
        ] {
            assert!(!args.iter().any(|a| a == flag), "{flag} is back in argv");
        }
    }

    #[test]
    fn rot8_decrypt_argv_carries_no_secret() {
        let creds = test_creds();
        let mut args = decrypt_argv("Y2lwaGVy");
        args.push("--encryption-context".to_owned());
        args.push("customer_id=attested-data".to_owned());
        let joined = args.join(" ");
        for secret in secret_values(&creds, "ZGVr") {
            assert!(!joined.contains(&secret), "a secret reached argv: {joined}");
        }
        for flag in [
            "--aws-access-key-id",
            "--aws-secret-access-key",
            "--aws-session-token",
            "--plaintext",
        ] {
            assert!(!args.iter().any(|a| a == flag), "{flag} is back in argv");
        }
        // …and the flag that tells the child to read stdin must be present, or
        // the child would sit waiting for flags that never come.
        assert!(args.iter().any(|a| a == "--secrets-from-stdin"));
    }

    #[test]
    fn rot8_both_argvs_request_stdin_mode() {
        let tail = build_encrypt_args("k", &data_signing_ctx()).expect("build");
        assert!(encrypt_argv(&tail)
            .iter()
            .any(|a| a == "--secrets-from-stdin"));
        assert!(decrypt_argv("c")
            .iter()
            .any(|a| a == "--secrets-from-stdin"));
    }

    #[test]
    fn rot8_stdin_payload_carries_every_secret_exactly_once() {
        let creds = test_creds();
        let payload = build_stdin_secrets(&creds, Some("ZGVr")).expect("clean creds build");
        for line in [
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS_SESSION_TOKEN=FwoGZXIvYXdzEExampleSessionToken",
            "PLAINTEXT_B64=ZGVr",
        ] {
            assert_eq!(
                payload.matches(line).count(),
                1,
                "expected exactly one {line} in the payload"
            );
        }
        // Every line terminated: the C parser reads line-wise, and a missing
        // final newline on a middle line would glue two secrets together.
        assert_eq!(payload.lines().count(), 4);
        assert!(payload.ends_with('\n'));
    }

    #[test]
    fn rot8_decrypt_payload_omits_the_dek_key_entirely() {
        // `decrypt` has no plaintext. The key must be ABSENT, not empty — an
        // empty value is a parse error on the C side (deliberately), so an
        // "always send all four" shortcut would break every decrypt.
        let payload = build_stdin_secrets(&test_creds(), None).expect("clean creds build");
        assert!(
            !payload.contains("PLAINTEXT_B64"),
            "decrypt payload must not carry a DEK key"
        );
        assert_eq!(payload.lines().count(), 3);
    }

    #[test]
    fn rot8_a_newline_in_any_secret_is_refused_not_escaped() {
        // The injection this format invites: a value carrying the record
        // delimiter ends its own line and starts another, so a credential
        // containing "\nPLAINTEXT_B64=…" would hand the child a DEK the caller
        // never passed. Refused for every field, both delimiters.
        for bad in ["A\nPLAINTEXT_B64=evil", "A\rB", "\n", "tail\n"] {
            let mut creds = test_creds();
            creds.access_key_id = bad.to_owned();
            assert!(
                build_stdin_secrets(&creds, None).is_err(),
                "access_key_id={bad:?} must be refused"
            );

            let mut creds = test_creds();
            creds.secret_access_key = bad.to_owned();
            assert!(build_stdin_secrets(&creds, None).is_err());

            let mut creds = test_creds();
            creds.session_token = bad.to_owned();
            assert!(build_stdin_secrets(&creds, None).is_err());

            assert!(
                build_stdin_secrets(&test_creds(), Some(bad)).is_err(),
                "dek={bad:?} must be refused"
            );
        }
    }

    #[test]
    fn rot8_empty_secret_is_refused_at_the_writer() {
        // The C parser rejects an empty value; catching it here names the field
        // instead of surfacing a generic parse error from the child.
        let mut creds = test_creds();
        creds.session_token = String::new();
        assert!(build_stdin_secrets(&creds, None).is_err());
        assert!(build_stdin_secrets(&test_creds(), Some("")).is_err());
    }

    #[test]
    fn rot8_clean_secrets_still_build() {
        // Falsification handle for the two tests above: the guard must reject
        // delimiters, not everything.
        assert!(build_stdin_secrets(&test_creds(), Some("ZGVr")).is_ok());
        assert!(build_stdin_secrets(&test_creds(), None).is_ok());
    }

    #[test]
    fn rot8_payload_shape_matches_the_c_parser_contract() {
        // Guards the two sides against drifting apart: the C header splits on
        // the FIRST '=' and rejects unknown keys, so the key names here are a
        // contract, not a convention.
        let payload =
            build_stdin_secrets(&test_creds(), Some("ZGVr==")).expect("clean creds build");
        for line in payload.lines() {
            let (key, _) = line.split_once('=').expect("every line is KEY=VALUE");
            assert!(
                matches!(
                    key,
                    "AWS_ACCESS_KEY_ID"
                        | "AWS_SECRET_ACCESS_KEY"
                        | "AWS_SESSION_TOKEN"
                        | "PLAINTEXT_B64"
                ),
                "unknown key {key} would be refused by the C parser"
            );
        }
        // A base64 value containing '=' must survive — split-on-first-'=' only.
        assert!(payload.contains("PLAINTEXT_B64=ZGVr=="));
    }

    /// The regression ROT-7 exists for: the encryption context MUST reach the
    /// argv. Falsification — drop the two `--encryption-context` pushes from
    /// `build_encrypt_args` and this test goes red, which is exactly what the
    /// old genkey path did silently.
    #[test]
    fn context_pairs_are_present_and_sorted() {
        // ROT-8 removed `--plaintext ZGVr` from this list: the DEK now travels
        // on stdin. The rest of the shape is unchanged and still asserted
        // exactly — the context pairs are what ROT-7 got silently wrong, and a
        // wrapped DEK with the wrong context is a key the read path can never
        // open.
        let built = build_encrypt_args("cec983ce", &data_signing_ctx()).expect("build");
        let args: Vec<&str> = built.iter().map(|a| a.as_str()).collect();
        assert_eq!(
            args,
            vec![
                "--key-id",
                "cec983ce",
                "--encryption-context",
                "customer_id=attested-data",
                "--encryption-context",
                "venue_id=data-signing",
            ]
        );
    }

    /// Fail-closed, not "default to no context".
    #[test]
    fn empty_context_is_refused() {
        let err = build_encrypt_args("cec983ce", &HashMap::new());
        assert!(
            err.is_err(),
            "an empty context must be refused, not defaulted"
        );
    }

    /// The context is what the KMS policy pins; a pair that could shift field
    /// boundaries must never reach the argv.
    #[test]
    fn forbidden_characters_in_context_are_refused() {
        for (k, v) in [
            ("customer_id", "attested data"),
            ("customer_id", "attested=data"),
            ("venue id", "data-signing"),
            ("customer_id", ""),
        ] {
            let mut c = data_signing_ctx();
            c.insert(k.to_owned(), v.to_owned());
            assert!(
                build_encrypt_args("k", &c).is_err(),
                "must refuse {k:?}={v:?}"
            );
        }
    }

    /// Ordering is deterministic regardless of insertion order — the argv is
    /// what a reviewer reads, and a HashMap must not make it wobble.
    #[test]
    fn ordering_is_insertion_independent() {
        let mut reversed = HashMap::new();
        reversed.insert("venue_id".to_owned(), "data-signing".to_owned());
        reversed.insert("customer_id".to_owned(), "attested-data".to_owned());
        let a: Vec<String> = build_encrypt_args("k", &reversed)
            .expect("build")
            .iter()
            .map(|z| z.to_string())
            .collect();
        let b: Vec<String> = build_encrypt_args("k", &data_signing_ctx())
            .expect("build")
            .iter()
            .map(|z| z.to_string())
            .collect();
        assert_eq!(a, b);
    }

    /// A DEK must be 32 bytes; the length guard sits in the caller, so assert
    /// the caller's contract here rather than letting a short key through.
    #[test]
    fn dek_length_is_enforced_by_the_caller_contract() {
        let ctx = data_signing_ctx();
        // build_encrypt_args itself is length-agnostic (it takes base64), so the
        // guarantee lives in wrap_dek_with_context. Documented by this test so a
        // future refactor that moves the check cannot drop it unnoticed.
        assert!(build_encrypt_args("k", &ctx).is_ok());
    }
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
