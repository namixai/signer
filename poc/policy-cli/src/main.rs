//! `signer-policy-wrap` — operator/customer tool that produces a
//! UPL-wrapped plaintext blob ready for `aws kms encrypt`.
//!
//! Usage:
//!
//! ```text
//! signer-policy-wrap \
//!     --policy ./binance-prod-policy.json \
//!     --secret ./binance-prod-secret.json \
//!     --output ./blob.plain.json
//!
//! # Then encrypt under the enclave's KMS key:
//! aws kms encrypt \
//!     --key-id alias/signer-poc \
//!     --plaintext fileb://blob.plain.json \
//!     --output text \
//!     --query CiphertextBlob > blob.enc.b64
//!
//! # Stage blob.enc.b64 on the gateway/S3 path the customer configured.
//! ```
//!
//! Why a separate tool (and not part of the SDK):
//! - The enclave is the ONLY component that should ever decrypt this blob.
//!   The gateway pulls the ciphertext from S3 and forwards inline — it
//!   never knows the plaintext.
//! - The customer assembles policy + secret on their OWN laptop, with
//!   their OWN AWS credentials, against the enclave's published KMS key
//!   alias. No third-party trust in the wrapping step.
//! - Wrapping is deterministic and trivial — pure JSON. We deliberately
//!   keep AWS SDK dependencies OUT of this tool so the customer can audit
//!   the source in five minutes (~150 LoC) before placing real keys.
//!
//! The wrapped JSON layout matches `enclave::proto::PolicyWrappedSecret`:
//!
//! ```json
//! {
//!   "policy": { ... validated against Policy schema below ... },
//!   "secret": { ... opaque to this tool — exchange-specific shape ... }
//! }
//! ```
//!
//! Policy schema (must stay aligned with `_signer/poc/enclave/src/proto.rs`
//! `pub struct Policy`):
//!   - allowed_actions:        Option<Vec<String>>
//!   - allowed_methods:        Option<Vec<String>>
//!   - allowed_path_prefixes:  Option<Vec<String>>
//!   - denied_path_prefixes:   Option<Vec<String>>
//!   - max_requests_per_minute: Option<u32>
//!   - label:                  Option<String>  (max 128 chars)

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Local Policy schema. MUST stay in sync with the enclave's
/// `proto::Policy`. Equivalence is checked at runtime via the enclave's
/// own `serde_json::from_value` on decrypt — a drift here will surface
/// as `policy_denied` or `bad_request` on the first signing attempt.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_path_prefixes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    denied_path_prefixes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_requests_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

/// Wire shape that gets fed into `aws kms encrypt`. Field order is
/// preserved across runs (serde_json with `preserve_order`) so the
/// ciphertext is byte-stable when inputs are byte-stable.
#[derive(Debug, Serialize)]
struct PolicyWrappedSecret {
    policy: Policy,
    secret: serde_json::Value,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Wrap a UPL policy + exchange secret into a plaintext blob ready for `aws kms encrypt`."
)]
struct Cli {
    /// Path to the UPL policy JSON file.
    #[arg(long)]
    policy: PathBuf,
    /// Path to the exchange-specific secret JSON file.
    /// Shape depends on the exchange:
    ///   - KuCoin/OKX: {"key", "secret", "passphrase"}
    ///   - Binance/Bybit: {"key", "secret"}
    ///   - Hyperliquid: {"exchange", "private_key", "wallet_address", "vault_address"}
    ///   - Asterdex: {"exchange", "private_key", "signer_address"}
    #[arg(long)]
    secret: PathBuf,
    /// Path where the wrapped plaintext blob will be written.
    /// Feed this directly into `aws kms encrypt --plaintext fileb://...`.
    #[arg(long)]
    output: PathBuf,
    /// Skip the policy "looks reasonable" sanity check. Use with care —
    /// the enclave will reject malformed policies on the first signing
    /// attempt anyway, but client-side validation surfaces typos earlier.
    #[arg(long, default_value_t = false)]
    skip_sanity_check: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1. Load policy from disk + parse against the local schema. This
    //    catches typos (e.g. `allow_actions` instead of `allowed_actions`)
    //    before the customer wastes a KMS encrypt + upload + signing
    //    attempt to discover the policy was misspelled.
    let policy_bytes = std::fs::read(&cli.policy)
        .with_context(|| format!("reading policy file: {}", cli.policy.display()))?;
    let policy: Policy = serde_json::from_slice(&policy_bytes)
        .with_context(|| format!("parsing policy as Policy schema: {}", cli.policy.display()))?;

    // 2. Load secret as a free-form JSON Value. We deliberately don't
    //    enforce a specific exchange schema here — the customer might
    //    add a new exchange type that this CLI version doesn't know
    //    about, and we don't want stale-tooling errors to block them.
    //    The enclave is the authoritative validator of secret shape.
    let secret_bytes = std::fs::read(&cli.secret)
        .with_context(|| format!("reading secret file: {}", cli.secret.display()))?;
    let secret: serde_json::Value = serde_json::from_slice(&secret_bytes).with_context(|| {
        format!(
            "parsing secret file as JSON: {}",
            cli.secret.display()
        )
    })?;
    if !secret.is_object() {
        bail!(
            "secret file must be a JSON object (got {}): {}",
            secret_kind(&secret),
            cli.secret.display()
        );
    }

    // 3. Sanity-check the policy unless explicitly skipped. These checks
    //    mirror what the enclave's `enforce_policy` enforces, so a policy
    //    that passes these will not be rejected for "obvious" reasons.
    if !cli.skip_sanity_check {
        sanity_check_policy(&policy)?;
    }

    // 4. Assemble and serialize. We pretty-print with 2-space indent for
    //    operator readability — KMS encrypt is byte-exact, so the
    //    resulting ciphertext bytes are deterministic for given input.
    let wrapped = PolicyWrappedSecret { policy, secret };
    // Compact JSON (no pretty-printing): KMS ciphertext blobs have an
    // 8 KiB hard ceiling (`MAX_CIPHERTEXT_BYTES`). Pretty-printing wastes
    // ~30% on whitespace and pushes realistic Hyperliquid/Asterdex secrets
    // (multi-line ABI fragments) over the wire limit. Gemini OSS PR #9 catch.
    let plaintext = serde_json::to_vec(&wrapped).context("serializing wrapped blob")?;

    std::fs::write(&cli.output, &plaintext)
        .with_context(|| format!("writing output: {}", cli.output.display()))?;

    eprintln!(
        "Wrapped {} bytes of policy + secret → {} ({} bytes).",
        policy_bytes.len() + secret_bytes.len(),
        cli.output.display(),
        plaintext.len()
    );
    eprintln!("Next step: `aws kms encrypt --key-id <alias> --plaintext fileb://{} --output text --query CiphertextBlob`", cli.output.display());

    Ok(())
}

fn secret_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Local mirror of the enclave's `enforce_policy` static checks. Catches
/// obvious mistakes client-side. NOT a replacement for the enclave's
/// own validation — it's a fast-fail convenience.
fn sanity_check_policy(p: &Policy) -> Result<()> {
    // Label length: char count, max 128 (enclave-side limit). We mirror
    // the `chars().count()` semantic so a customer can stage UTF-8
    // labels (cyrillic, kanji, etc) up to 128 grapheme-ish units.
    if let Some(ref label) = p.label {
        let len = label.chars().count();
        if len > 128 {
            bail!(
                "policy.label must be ≤128 chars, got {} chars (UTF-8 byte len = {})",
                len,
                label.len()
            );
        }
    }

    // Known sign actions as of UPL v0. We warn (not error) on unknown
    // values because a customer might be working with a build that
    // includes an exchange the tool doesn't know about yet.
    const KNOWN_ACTIONS: &[&str] = &[
        "ping",
        "sign",
        "sign_kucoin",
        "sign_binance",
        "sign_bybit",
        "sign_okx",
        "sign_hyperliquid_main_order",
        "sign_hyperliquid_main_cancel",
        "sign_asterdex",
    ];
    if let Some(ref actions) = p.allowed_actions {
        for a in actions {
            if !KNOWN_ACTIONS.contains(&a.as_str()) {
                eprintln!(
                    "warning: policy.allowed_actions contains unrecognized action '{}' — \
                     will be rejected by the enclave unless this tool is out of date.",
                    a
                );
            }
        }
    }

    // Known HTTP methods. Same warning policy.
    const KNOWN_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE"];
    if let Some(ref methods) = p.allowed_methods {
        for m in methods {
            if !KNOWN_METHODS.contains(&m.as_str()) {
                eprintln!(
                    "warning: policy.allowed_methods contains unrecognized method '{}'.",
                    m
                );
            }
        }
    }

    // Path prefixes should start with `/` — if they don't, the
    // boundary-safe matcher in the enclave still works, but the customer
    // probably meant to write an absolute path.
    //
    // Empty string in allowed_path_prefixes is a HARD ERROR (not a warning):
    // an empty prefix would (or would, absent enclave-side hardening)
    // unconditionally match every path and silently disable the allowlist.
    // The enclave now rejects empty prefixes too, but we fail at wrap time
    // so the operator never ships a broken policy. Gemini round-4 catch.
    if let Some(ref prefixes) = p.allowed_path_prefixes {
        for prefix in prefixes {
            if prefix.is_empty() {
                anyhow::bail!(
                    "policy.allowed_path_prefixes contains an empty string. \
                     An empty prefix would bypass the allowlist (matches any \
                     path). Remove the empty entry or use `[]` for an \
                     allow-nothing list."
                );
            }
            if !prefix.starts_with('/') {
                eprintln!(
                    "warning: policy.allowed_path_prefixes entry '{}' does not start with '/'.",
                    prefix
                );
            }
        }
    }
    if let Some(ref prefixes) = p.denied_path_prefixes {
        for prefix in prefixes {
            if prefix.is_empty() {
                anyhow::bail!(
                    "policy.denied_path_prefixes contains an empty string. \
                     An empty denial prefix would deny every request. Remove \
                     the empty entry or use `[]` to opt out of denials."
                );
            }
            if !prefix.starts_with('/') {
                eprintln!(
                    "warning: policy.denied_path_prefixes entry '{}' does not start with '/'.",
                    prefix
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_policy() {
        let json = "{}";
        let p: Policy = serde_json::from_str(json).expect("parse");
        assert!(p.allowed_actions.is_none());
        assert!(p.label.is_none());
    }

    #[test]
    fn parses_full_policy() {
        let json = r#"{
            "allowed_actions": ["sign_binance", "sign_okx"],
            "allowed_methods": ["POST", "DELETE"],
            "allowed_path_prefixes": ["/api/v1/order"],
            "denied_path_prefixes": ["/sapi/v1/withdraw"],
            "max_requests_per_minute": 60,
            "label": "binance-prod-trading"
        }"#;
        let p: Policy = serde_json::from_str(json).expect("parse");
        assert_eq!(p.allowed_actions.as_ref().unwrap().len(), 2);
        assert_eq!(p.allowed_methods.as_ref().unwrap()[0], "POST");
        assert_eq!(p.max_requests_per_minute, Some(60));
        assert_eq!(p.label.as_deref(), Some("binance-prod-trading"));
    }

    #[test]
    fn round_trip_preserves_fields() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".into()]),
            allowed_methods: Some(vec!["POST".into()]),
            label: Some("test".into()),
            ..Policy::default()
        };
        let s = serde_json::to_string(&p).unwrap();
        let p2: Policy = serde_json::from_str(&s).unwrap();
        assert_eq!(p.allowed_actions, p2.allowed_actions);
        assert_eq!(p.allowed_methods, p2.allowed_methods);
        assert_eq!(p.label, p2.label);
    }

    #[test]
    fn sanity_check_rejects_long_label_chars() {
        let p = Policy {
            label: Some("a".repeat(129)),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p).is_err());
    }

    #[test]
    fn sanity_check_accepts_128_char_label() {
        let p = Policy {
            label: Some("a".repeat(128)),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p).is_ok());
    }

    #[test]
    fn sanity_check_accepts_128_cyrillic_chars() {
        // 128 cyrillic chars = 256 bytes, must pass char-count check.
        let label: String = "а".repeat(128);
        assert_eq!(label.chars().count(), 128);
        assert_eq!(label.len(), 256);
        let p = Policy {
            label: Some(label),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p).is_ok());
    }
}
