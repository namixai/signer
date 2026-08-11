//! Registry control-plane SIGNER — the off-box half of the enclave-resident
//! tenant registry (the receiver lives in `enclave/src/registry.rs`).
//!
//! The enclave accepts a registry refresh only if a control-plane Ed25519
//! signature verifies over the canonical message
//!
//!     nonce(32) ‖ version.to_le_bytes()(8) ‖ sha256(entries_json)(32)   // 72 bytes
//!
//! where `entries_json` are the EXACT bytes the enclave KMS-decrypts and then
//! deserializes into `RefreshEntry`s (the receiver hashes the decrypted bytes —
//! there is no separate entries argument it could desync from, see
//! `enclave/src/registry.rs::refresh` "F1"). So this tool MUST:
//!   1. serialize the entries to bytes ONCE,
//!   2. hash THOSE bytes,
//!   3. sign nonce‖version‖hash,
//!   4. hand the operator the SAME bytes to KMS-encrypt (under the registry
//!      context) — byte-for-byte, never a re-serialization.
//!
//! ⚠️ CROWN-JEWEL TRUST ROOT. The byte layout below is duplicated (not shared)
//! with the enclave verifier on purpose — keeping the merged, twice-reviewed
//! receiver untouched. Drift is caught by `GOLDEN_*` test vectors asserted
//! IDENTICALLY here and in `enclave/src/registry.rs` tests: a change to either
//! side's byte layout breaks its golden test. If you change the canonical
//! format, you MUST update both golden vectors in lockstep.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// KMS EncryptionContext the registry blob is wrapped under. MUST match
/// `enclave/src/handler.rs::registry_blob_context` exactly — the enclave
/// decrypts the blob under this context, so a mismatch fails KMS decrypt.
pub const REGISTRY_KMS_CONTEXT: &str = "customer_id=registry-system,venue_id=registry";

/// Env var selecting the deploy environment segment of the registry key alias —
/// mirrors Terraform `var.environment`. Defaults to "prod".
const REGISTRY_KMS_ENV_VAR: &str = "SIGNER_KMS_ENV";

/// Alias of the ATTESTATION-GATED registry trust-root key (`infra/kms.tf`
/// `aws_kms_alias.registry` = `alias/signer/<env>/registry/v1`). The registry blob
/// carries plaintext bearer tokens, so it MUST ride on this key — whose Decrypt is
/// gated on the enclave PCR0 attestation — and NEVER the legacy `alias/signer-poc`
/// (not PCR0-gated). The `<env>` segment is env-derived (`$SIGNER_KMS_ENV`, default
/// "prod") so a non-prod stack stages under its own key without a code edit (nit).
pub fn registry_kms_alias() -> String {
    let env = std::env::var(REGISTRY_KMS_ENV_VAR).unwrap_or_else(|_| "prod".to_owned());
    format!("alias/signer/{env}/registry/v1")
}

/// The reserved platform venue — only the reserved x402 system identity may
/// carry it (mirrors `enclave/src/registry.rs::RESERVED_X402_VENUE`). The
/// enclave's `refresh` rejects a non-reserved customer holding it; we reject it
/// here too so the operator gets immediate feedback, not a cryptic enclave deny.
const RESERVED_X402_VENUE: &str = "x402";
/// Mirrors `enclave/src/handler.rs::X402_CUSTOMER_ID`.
const X402_CUSTOMER_ID: &str = "x402-00000000-0000-0000-0000-0000000x402";

/// One registry entry. Field order/shape MUST match
/// `enclave/src/registry.rs::RefreshEntry` (token, customer_id, allowed_venues)
/// so the serialized bytes — and thus their sha256 — are identical on both
/// sides. The enclave applies `#[serde(deny_unknown_fields)]`; we emit exactly
/// these three keys and nothing else.
// No `Debug` derive: `token` is a plaintext bearer token, and a derived Debug
// would leak it through any `{:?}` / `dbg!` / error-context capture (review F2).
#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshEntry {
    /// PLAINTEXT bearer token. Confidential — the whole blob is KMS-sealed; the
    /// enclave HMAC-keys it on receipt and drops the plaintext.
    pub token: String,
    pub customer_id: String,
    pub allowed_venues: Vec<String>,
}

/// Charset guard mirroring `enclave/src/registry.rs::is_safe_id`: ASCII
/// alnum + `-`/`_`, 1..=64 bytes, NO `\n`/`=`/control chars (those would shift
/// the sealed-AAD / KMS-context field boundaries). Pre-validated here so a bad
/// id fails before the operator KMS-encrypts and ships a doomed blob.
fn is_safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validate the operator-supplied entries against every rule the enclave's
/// `refresh` enforces, so misconfiguration is caught at sign time (loudly)
/// rather than as an opaque enclave reject after a KMS round-trip.
fn validate_entries(entries: &[RefreshEntry]) -> Result<()> {
    if entries.is_empty() {
        bail!("registry refresh carried no entries (enclave rejects Empty)");
    }
    for (i, e) in entries.iter().enumerate() {
        if e.token.is_empty() {
            bail!("entry {i}: empty token");
        }
        if !is_safe_id(&e.customer_id) {
            bail!(
                "entry {i}: customer_id {:?} is not a safe id (ASCII alnum/-/_ , 1..=64)",
                e.customer_id
            );
        }
        if e.allowed_venues.is_empty() {
            bail!("entry {i}: customer {:?} has no allowed_venues", e.customer_id);
        }
        for v in &e.allowed_venues {
            if !is_safe_id(v) {
                bail!("entry {i}: venue {:?} is not a safe id", v);
            }
            // Reserved-venue blocklist — only the reserved x402 identity may
            // hold the x402 venue (case-insensitive, matching the enclave).
            if v.eq_ignore_ascii_case(RESERVED_X402_VENUE) && e.customer_id != X402_CUSTOMER_ID {
                bail!(
                    "entry {i}: customer {:?} may not be granted the reserved \"x402\" venue \
                     (only {X402_CUSTOMER_ID} may); the enclave rejects this as ReservedVenue",
                    e.customer_id
                );
            }
        }
    }
    // Duplicate-token guard: two entries with the same token would make the
    // enclave's constant-time scan resolve to whichever it finds — almost
    // always an operator mistake. Non-constant-time `==` is fine here: both
    // sides are operator-supplied from the same file; this is not an auth
    // comparison against a secret (review F3).
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            if entries[i].token == entries[j].token {
                bail!("entries {i} and {j} share the same token");
            }
        }
    }
    Ok(())
}

/// sha256 of the exact serialized entries bytes. MUST match
/// `enclave/src/registry.rs::hash_entries`.
fn hash_entries(entries_json: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(entries_json);
    h.finalize().into()
}

/// Canonical 72-byte message the control plane signs and the enclave
/// re-derives. MUST match `enclave/src/registry.rs::signed_message`:
/// `nonce(32) ‖ version_le(8) ‖ content_hash(32)`.
fn signed_message(nonce: &[u8; 32], version: u64, content_hash: &[u8; 32]) -> [u8; 72] {
    let mut m = [0u8; 72];
    m[0..32].copy_from_slice(nonce);
    m[32..40].copy_from_slice(&version.to_le_bytes());
    m[40..72].copy_from_slice(content_hash);
    m
}

/// Parse a 32-byte hex string (nonce or Ed25519 seed) into bytes.
fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).with_context(|| format!("{what} is not valid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be exactly 32 bytes (64 hex chars), got {} bytes", bytes.len()))
}

/// The product of a successful sign: the bytes to KMS-encrypt verbatim plus the
/// refresh parameters the enclave needs (`nonce_hex`, `version`, `signature_hex`).
pub struct SignedRefresh {
    /// EXACT bytes to KMS-encrypt (under [`REGISTRY_KMS_CONTEXT`]) and ship as
    /// `ciphertext_blob_base64`. NEVER re-serialize these.
    pub entries_json: Vec<u8>,
    pub content_hash_hex: String,
    pub nonce_hex: String,
    pub version: u64,
    pub signature_hex: String,
}

// Manual Debug: `entries_json` carries plaintext bearer tokens, so it is
// redacted to a byte count (review F2). The hashes/sig/version are public.
impl std::fmt::Debug for SignedRefresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedRefresh")
            .field("entries_json", &format_args!("[REDACTED {} bytes]", self.entries_json.len()))
            .field("content_hash_hex", &self.content_hash_hex)
            .field("nonce_hex", &self.nonce_hex)
            .field("version", &self.version)
            .field("signature_hex", &self.signature_hex)
            .finish()
    }
}

/// Sign a registry refresh. `seed` is the 32-byte Ed25519 control-plane private
/// seed (the baked pubkey is its verifying key). The signature is deterministic
/// (RFC 8032), so identical inputs always yield an identical signature.
pub fn sign_refresh(
    entries: &[RefreshEntry],
    nonce_hex: &str,
    version: u64,
    seed: &Zeroizing<[u8; 32]>,
) -> Result<SignedRefresh> {
    validate_entries(entries)?;
    // The enclave's cold-boot baseline is version 0 and it rejects
    // `version <= max_known`, so version 0 can never install. Fail here with a
    // clear message instead of a confusing enclave NonMonotonicVersion.
    if version == 0 {
        bail!("version must be >= 1 (the enclave refuses version <= its last-known, baseline 0)");
    }
    let nonce = parse_hex32(nonce_hex, "nonce")?;

    // Serialize ONCE — these exact bytes are both hashed and (by the operator)
    // KMS-encrypted. A compact, key-order-stable encoding (workspace serde_json
    // has `preserve_order`) keeps the bytes reproducible.
    let entries_json = serde_json::to_vec(entries).context("serialize registry entries")?;
    let content_hash = hash_entries(&entries_json);

    let signing_key = SigningKey::from_bytes(seed);
    let msg = signed_message(&nonce, version, &content_hash);
    let signature = signing_key.sign(&msg);

    Ok(SignedRefresh {
        entries_json,
        content_hash_hex: hex::encode(content_hash),
        nonce_hex: hex::encode(nonce),
        version,
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

/// Generate a fresh control-plane keypair. Returns (pubkey_hex, privkey_seed_hex).
/// The pubkey is baked into the enclave Dockerfile (`SIGNER_REGISTRY_PUBKEY`) —
/// PCR0-determining. The private seed goes OFF-BOX (vault/HSM), NEVER the repo.
pub fn keygen() -> (String, Zeroizing<String>) {
    use rand::RngCore;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let privkey_hex = Zeroizing::new(hex::encode(seed.as_ref()));
    (pubkey_hex, privkey_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── GOLDEN VECTOR ─────────────────────────────────────────────────────
    // Asserted IDENTICALLY in enclave/src/registry.rs tests
    // (`golden_vector_matches_control_plane`). If either side's byte layout
    // drifts, exactly one golden test breaks. DO NOT edit one without the other.
    //
    // Inputs: seed = 32×0x07, version = 1,
    //   nonce  = 32×0x01,
    //   entries = [{token:"tok-a", customer_id:"cust-a", allowed_venues:["binance","okx"]}]
    const GOLDEN_SEED: [u8; 32] = [7u8; 32];
    const GOLDEN_NONCE_HEX: &str =
        "0101010101010101010101010101010101010101010101010101010101010101";
    const GOLDEN_VERSION: u64 = 1;
    // Pinned outputs (deterministic Ed25519 over the fixed message):
    const GOLDEN_ENTRIES_JSON: &str =
        r#"[{"token":"tok-a","customer_id":"cust-a","allowed_venues":["binance","okx"]}]"#;
    const GOLDEN_CONTENT_HASH_HEX: &str =
        "4c3acd5004975c7d13e21b041831c70c04ae45440d14627bccc7d5dd6d46d454";
    const GOLDEN_SIGNATURE_HEX: &str =
        "3bd8bf339dfd0a188bbaad55c2d3fb7b4157ad8dbef027447f8bc726eb887ec5afc155801548086a9f6b5ce0adc2e35420a5867e6a618aeb669560b2e185b101";

    fn golden_entries() -> Vec<RefreshEntry> {
        vec![RefreshEntry {
            token: "tok-a".to_owned(),
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned(), "okx".to_owned()],
        }]
    }

    #[test]
    fn golden_entries_json_is_canonical() {
        let json = serde_json::to_vec(&golden_entries()).unwrap();
        assert_eq!(
            String::from_utf8(json).unwrap(),
            GOLDEN_ENTRIES_JSON,
            "serialized entries bytes drifted — the enclave hashes these exact bytes"
        );
    }

    #[test]
    fn golden_vector_signs_deterministically() {
        let seed = Zeroizing::new(GOLDEN_SEED);
        let out = sign_refresh(&golden_entries(), GOLDEN_NONCE_HEX, GOLDEN_VERSION, &seed).unwrap();
        assert_eq!(String::from_utf8(out.entries_json.clone()).unwrap(), GOLDEN_ENTRIES_JSON);
        assert_eq!(out.content_hash_hex, GOLDEN_CONTENT_HASH_HEX, "content hash drift");
        assert_eq!(out.signature_hex, GOLDEN_SIGNATURE_HEX, "signature drift");
        // Re-sign — Ed25519 is deterministic, so it must be byte-identical.
        let out2 = sign_refresh(&golden_entries(), GOLDEN_NONCE_HEX, GOLDEN_VERSION, &seed).unwrap();
        assert_eq!(out.signature_hex, out2.signature_hex);
    }

    // Second golden vector — TWO entries. Covers the array-element comma and
    // multi-entry field ordering that the single-entry vector can't. Asserted
    // identically in enclave/src/registry.rs (`golden_vector_two_entries`).
    const GOLDEN2_CONTENT_HASH_HEX: &str =
        "75bfd82d8021c4e228eb0c2de36559bb4ec8bcf362967dcbb63f597cef8baab9";
    const GOLDEN2_SIGNATURE_HEX: &str =
        "8cbfc61e0e1d189d4420b47bfee270f967e4b8328103e1c0bd35fe96d2b63e5e793108dfd17075f19a65983c59b2b8b3f115af8eb998acb9fc611f418a275f0e";

    #[test]
    fn golden_vector_two_entries() {
        let entries = vec![
            RefreshEntry {
                token: "tok-a".to_owned(),
                customer_id: "cust-a".to_owned(),
                allowed_venues: vec!["binance".to_owned(), "okx".to_owned()],
            },
            RefreshEntry {
                token: "tok-b".to_owned(),
                customer_id: "cust-b".to_owned(),
                allowed_venues: vec!["kucoin".to_owned()],
            },
        ];
        let seed = Zeroizing::new(GOLDEN_SEED);
        let out = sign_refresh(&entries, GOLDEN_NONCE_HEX, GOLDEN_VERSION, &seed).unwrap();
        assert_eq!(
            String::from_utf8(out.entries_json.clone()).unwrap(),
            r#"[{"token":"tok-a","customer_id":"cust-a","allowed_venues":["binance","okx"]},{"token":"tok-b","customer_id":"cust-b","allowed_venues":["kucoin"]}]"#
        );
        assert_eq!(out.content_hash_hex, GOLDEN2_CONTENT_HASH_HEX);
        assert_eq!(out.signature_hex, GOLDEN2_SIGNATURE_HEX);
    }

    #[test]
    fn keygen_pubkey_is_seed_verifying_key() {
        let (pubkey_hex, priv_hex) = keygen();
        let seed: [u8; 32] = hex::decode(priv_hex.as_str()).unwrap().try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(hex::encode(sk.verifying_key().to_bytes()), pubkey_hex);
        assert_eq!(pubkey_hex.len(), 64);
    }

    #[test]
    fn registry_kms_alias_env_derived() {
        // One test does both cases sequentially (no other test reads SIGNER_KMS_ENV,
        // so no cross-test env race). edition 2021 → set_var/remove_var are safe.
        std::env::remove_var(REGISTRY_KMS_ENV_VAR);
        assert_eq!(registry_kms_alias(), "alias/signer/prod/registry/v1");
        std::env::set_var(REGISTRY_KMS_ENV_VAR, "staging");
        assert_eq!(registry_kms_alias(), "alias/signer/staging/registry/v1");
        std::env::remove_var(REGISTRY_KMS_ENV_VAR);
    }

    #[test]
    fn rejects_empty_entries() {
        let seed = Zeroizing::new(GOLDEN_SEED);
        assert!(sign_refresh(&[], GOLDEN_NONCE_HEX, 1, &seed).is_err());
    }

    #[test]
    fn rejects_x402_for_non_reserved_customer() {
        let seed = Zeroizing::new(GOLDEN_SEED);
        let entries = vec![RefreshEntry {
            token: "evil".to_owned(),
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned(), "x402".to_owned()],
        }];
        let err = sign_refresh(&entries, GOLDEN_NONCE_HEX, 1, &seed).unwrap_err();
        assert!(err.to_string().contains("x402"), "got: {err}");
    }

    #[test]
    fn allows_x402_for_reserved_customer() {
        let seed = Zeroizing::new(GOLDEN_SEED);
        let entries = vec![RefreshEntry {
            token: "x402-platform".to_owned(),
            customer_id: X402_CUSTOMER_ID.to_owned(),
            allowed_venues: vec!["x402".to_owned()],
        }];
        assert!(sign_refresh(&entries, GOLDEN_NONCE_HEX, 1, &seed).is_ok());
    }

    #[test]
    fn rejects_unsafe_id_and_duplicate_token() {
        let seed = Zeroizing::new(GOLDEN_SEED);
        let bad_id = vec![RefreshEntry {
            token: "t".to_owned(),
            customer_id: "cust\na".to_owned(),
            allowed_venues: vec!["binance".to_owned()],
        }];
        assert!(sign_refresh(&bad_id, GOLDEN_NONCE_HEX, 1, &seed).is_err());

        let dup = vec![
            RefreshEntry { token: "dup".to_owned(), customer_id: "a".to_owned(), allowed_venues: vec!["binance".to_owned()] },
            RefreshEntry { token: "dup".to_owned(), customer_id: "b".to_owned(), allowed_venues: vec!["okx".to_owned()] },
        ];
        assert!(sign_refresh(&dup, GOLDEN_NONCE_HEX, 1, &seed).is_err());
    }
}
