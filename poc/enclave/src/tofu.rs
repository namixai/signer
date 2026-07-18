//! Ed25519 TOFU (Trust-On-First-Use) pubkey pinning for UPL policies.
//!
//! When a policy blob carries `signer_pubkey` + `policy_signature`, the
//! enclave:
//!   1. Verifies the Ed25519 signature over the canonical policy JSON.
//!   2. On first use for a given S3 key, PINS the pubkey. Subsequent
//!      requests with a different pubkey are rejected — preventing key
//!      substitution even if the attacker has KMS Encrypt access.
//!
//! The pin store is in-memory (HashMap behind a Mutex). It resets on
//! enclave restart, which is acceptable for Phase 0: an attacker who can
//! restart the enclave already controls the parent instance.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;

const MAX_PINS: usize = 256;

#[derive(Debug, Error)]
pub enum TofuError {
    #[error("pubkey hex must be 64 chars (32 bytes)")]
    BadPubkeyLength,
    #[error("signature hex must be 128 chars (64 bytes)")]
    BadSignatureLength,
    #[error("invalid pubkey hex: {0}")]
    PubkeyHex(hex::FromHexError),
    #[error("invalid signature hex: {0}")]
    SignatureHex(hex::FromHexError),
    #[error("invalid Ed25519 public key")]
    InvalidPubkey,
    #[error("Ed25519 signature verification failed")]
    SignatureInvalid,
    #[error("pubkey mismatch: pinned key differs from request")]
    PubkeyMismatch,
    #[error("pinned key requires signature but policy is unsigned")]
    PinnedKeyUnsigned,
    #[error("pin store full ({MAX_PINS} keys)")]
    PinStoreFull,
}

type PinStore = HashMap<String, [u8; 32]>;

fn pins() -> &'static Mutex<PinStore> {
    static STORE: OnceLock<Mutex<PinStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Check if an S3 key has a pinned pubkey. If so, an unsigned policy is
/// a bypass attempt and must be rejected.
pub fn require_if_pinned(s3_key: &str) -> Result<(), TofuError> {
    let store = pins().lock().unwrap_or_else(|e| e.into_inner());
    if store.contains_key(s3_key) {
        Err(TofuError::PinnedKeyUnsigned)
    } else {
        Ok(())
    }
}

pub fn verify_and_pin(
    s3_key: &str,
    policy_json: &[u8],
    signer_pubkey_hex: &str,
    policy_signature_hex: &str,
) -> Result<(), TofuError> {
    if signer_pubkey_hex.len() != 64 {
        return Err(TofuError::BadPubkeyLength);
    }
    if policy_signature_hex.len() != 128 {
        return Err(TofuError::BadSignatureLength);
    }

    let pk_bytes: [u8; 32] = hex::decode(signer_pubkey_hex)
        .map_err(TofuError::PubkeyHex)?
        .try_into()
        .map_err(|_| TofuError::BadPubkeyLength)?;

    let sig_bytes: [u8; 64] = hex::decode(policy_signature_hex)
        .map_err(TofuError::SignatureHex)?
        .try_into()
        .map_err(|_| TofuError::BadSignatureLength)?;

    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| TofuError::InvalidPubkey)?;
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(policy_json, &sig)
        .map_err(|_| TofuError::SignatureInvalid)?;

    let mut store = pins().lock().unwrap_or_else(|e| e.into_inner());
    match store.get(s3_key) {
        Some(pinned) if *pinned != pk_bytes => Err(TofuError::PubkeyMismatch),
        Some(_) => Ok(()),
        None => {
            if store.len() >= MAX_PINS {
                return Err(TofuError::PinStoreFull);
            }
            store.insert(s3_key.to_owned(), pk_bytes);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    fn random_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn sign_policy(sk: &SigningKey, policy: &[u8]) -> (String, String) {
        use ed25519_dalek::Signer;
        let sig = sk.sign(policy);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        (pk_hex, sig_hex)
    }

    #[test]
    fn verify_valid_signature() {
        let sk = random_signing_key();
        let policy = b"{\"allowed_actions\":[\"sign_binance\"]}";
        let (pk, sig) = sign_policy(&sk, policy);
        assert!(verify_and_pin("test-valid", policy, &pk, &sig).is_ok());
    }

    #[test]
    fn reject_wrong_signature() {
        let sk = random_signing_key();
        let policy = b"{\"allowed_actions\":[\"sign_binance\"]}";
        let (pk, _) = sign_policy(&sk, policy);
        let wrong_sig = hex::encode([0xFFu8; 64]);
        assert!(matches!(
            verify_and_pin("test-wrong-sig", policy, &pk, &wrong_sig),
            Err(TofuError::SignatureInvalid)
        ));
    }

    #[test]
    fn tofu_pin_established_and_reused() {
        let sk = random_signing_key();
        let policy = b"{\"label\":\"tofu-reuse-test\"}";
        let (pk, sig) = sign_policy(&sk, policy);
        assert!(verify_and_pin("test-pin-reuse", policy, &pk, &sig).is_ok());
        assert!(verify_and_pin("test-pin-reuse", policy, &pk, &sig).is_ok());
    }

    #[test]
    fn tofu_rejects_different_pubkey() {
        let sk1 = random_signing_key();
        let sk2 = random_signing_key();
        let policy = b"{\"label\":\"tofu-mismatch-test\"}";
        let (pk1, sig1) = sign_policy(&sk1, policy);
        let (pk2, sig2) = sign_policy(&sk2, policy);
        assert!(verify_and_pin("test-pin-mismatch", policy, &pk1, &sig1).is_ok());
        assert!(matches!(
            verify_and_pin("test-pin-mismatch", policy, &pk2, &sig2),
            Err(TofuError::PubkeyMismatch)
        ));
    }

    #[test]
    fn bad_hex_rejected() {
        let bad_pk = "zz".repeat(32); // 64 chars but invalid hex
        let fake_sig = "00".repeat(64);
        assert!(matches!(
            verify_and_pin("x", b"{}", &bad_pk, &fake_sig),
            Err(TofuError::PubkeyHex(_))
        ));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(matches!(
            verify_and_pin("x", b"{}", "aabb", "ccdd"),
            Err(TofuError::BadPubkeyLength)
        ));
    }
}
