//! Envelope encryption: AES-256-GCM decrypt of DEK-wrapped secrets.
//!
//! Blob format v2 ("envelope"):
//! ```json
//! {
//!   "version": 2,
//!   "wrapped_dek": "<base64 KMS ciphertext of 32-byte DEK>",
//!   "nonce": "<base64 12-byte GCM nonce>",
//!   "ciphertext": "<base64 AES-GCM ciphertext+tag>"
//! }
//! ```
//!
//! The enclave KMS-decrypts `wrapped_dek` (32 bytes) using attestation,
//! then AES-GCM-256-decrypts the `ciphertext` to recover the plaintext
//! secret JSON (same format as today: either legacy or policy-wrapped).

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const ENVELOPE_VERSION: u64 = 2;
const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u64,
    pub wrapped_dek: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u64),
    #[error("DEK must be {DEK_LEN} bytes, got {0}")]
    BadDekLength(usize),
    #[error("nonce must be {NONCE_LEN} bytes, got {0}")]
    BadNonceLength(usize),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("envelope JSON parse failed")]
    JsonParse,
    #[error("AES-GCM decrypt failed (wrong DEK or tampered ciphertext)")]
    AesGcmDecrypt,
    #[error("AES-GCM encrypt failed")]
    AesGcmEncrypt,
}

pub fn is_envelope(blob: &[u8]) -> bool {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(blob) {
        v.get("version")
            .and_then(|v| v.as_u64())
            .is_some_and(|v| v >= ENVELOPE_VERSION)
    } else {
        false
    }
}

pub fn parse_envelope(blob: &[u8]) -> Result<Envelope, EnvelopeError> {
    let env: Envelope = serde_json::from_slice(blob).map_err(|_| EnvelopeError::JsonParse)?;
    if env.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion(env.version));
    }
    Ok(env)
}

/// AES-256-GCM decrypt the envelope ciphertext, binding `aad` as the GCM
/// **Additional Authenticated Data** (design §5.4 Option A — real GCM AAD).
///
/// `aad` is the enclave's canonical sealed-identity bytes
/// (`customer_id=…\nvenue_id=…\nkey_version=…`, built in `registry::sealed_aad`
/// and matched by `rewrap-with-context.sh`). A blob wrapped for customer B
/// fails the GCM tag under customer A's resolved identity — a second,
/// tamper-evident identity check on top of the KMS EncryptionContext. Pass an
/// empty slice for the pre-AAD migration path (legacy blobs wrapped with no
/// AAD); the value MUST be byte-identical to what the blob was sealed with.
pub fn decrypt_with_dek(
    dek: &Zeroizing<Vec<u8>>,
    envelope: &Envelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if dek.len() != DEK_LEN {
        return Err(EnvelopeError::BadDekLength(dek.len()));
    }

    let nonce_bytes = B64.decode(&envelope.nonce)?;
    let nonce_array: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|v: Vec<u8>| EnvelopeError::BadNonceLength(v.len()))?;

    let ciphertext = B64.decode(&envelope.ciphertext)?;

    let cipher =
        Aes256Gcm::new_from_slice(dek.as_slice()).map_err(|_| EnvelopeError::AesGcmDecrypt)?;
    let nonce = Nonce::from(nonce_array);

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|_| EnvelopeError::AesGcmDecrypt)?;

    Ok(Zeroizing::new(plaintext))
}

/// AES-256-GCM **encrypt** `plaintext` under `dek`, binding `aad` as GCM AAD,
/// and assemble the v2 envelope around it — the inverse of [`decrypt_with_dek`].
/// `wrapped_dek` is the KMS ciphertext of `dek` (from KMS GenerateDataKey),
/// stored verbatim so the prod path KMS-decrypts it back. A fresh random 12-byte
/// nonce is drawn per call. Used by attested-data provisioning (Option-1); the
/// sealed blob is byte-compatible with `parse_envelope` + `decrypt_with_dek`.
/// `dek` is `&[u8]` rather than `&Zeroizing<Vec<u8>>` so the caller can hand us
/// a stack array — the provisioning path now generates the DEK as
/// `Zeroizing<[u8; 32]>` and must not be forced into a heap allocation just to
/// satisfy this signature (Gemini review on #347). The length check below is
/// unchanged and is what actually guards the invariant. Only the provisioning
/// path calls this; the read path uses `decrypt_with_dek`, untouched.
pub fn seal_with_dek(
    dek: &[u8],
    wrapped_dek: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Envelope, EnvelopeError> {
    if dek.len() != DEK_LEN {
        return Err(EnvelopeError::BadDekLength(dek.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|_| EnvelopeError::AesGcmEncrypt)?;
    let nonce = Aes256Gcm::generate_nonce(OsRng); // 12 bytes from the CSPRNG
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EnvelopeError::AesGcmEncrypt)?;
    Ok(Envelope {
        version: ENVELOPE_VERSION,
        wrapped_dek: B64.encode(wrapped_dek),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::OsRng;
    use aes_gcm::AeadCore;

    fn make_test_envelope(plaintext: &[u8]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let dek = Zeroizing::new(Aes256Gcm::generate_key(OsRng).to_vec());
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();

        let env = Envelope {
            version: ENVELOPE_VERSION,
            wrapped_dek: B64.encode(&*dek),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        };
        let blob = serde_json::to_vec(&env).unwrap();
        (dek, blob)
    }

    #[test]
    fn round_trip() {
        let secret = b"{\"key\":\"abc\",\"secret\":\"xyz\"}";
        let (dek, blob) = make_test_envelope(secret);
        let env = parse_envelope(&blob).unwrap();
        let plaintext = decrypt_with_dek(&dek, &env, &[]).unwrap();
        assert_eq!(&*plaintext, secret);
    }

    #[test]
    fn seal_with_dek_round_trips_through_decrypt() {
        // `seal_with_dek` (attested-data provisioning) is the inverse of
        // `decrypt_with_dek`: the blob it produces decrypts ONLY under the
        // identical DEK + AAD, and carries the wrapped_dek verbatim.
        let dek = Zeroizing::new(vec![9u8; 32]);
        let aad = b"customer_id=attested-data\nvenue_id=data-signing\nkey_version=1";
        let secret = br#"{"private_key":"0xdead"}"#;
        let env = seal_with_dek(&dek, b"wrapped", secret, aad).unwrap();
        assert_eq!(env.version, ENVELOPE_VERSION);
        assert_eq!(&B64.decode(&env.wrapped_dek).unwrap()[..], b"wrapped");
        assert_eq!(&*decrypt_with_dek(&dek, &env, aad).unwrap(), secret);
        assert!(decrypt_with_dek(&dek, &env, b"other-aad").is_err());
        let wrong = Zeroizing::new(vec![1u8; 32]);
        assert!(decrypt_with_dek(&wrong, &env, aad).is_err());
    }

    #[test]
    fn is_envelope_detects_v2() {
        let (_, blob) = make_test_envelope(b"test");
        assert!(is_envelope(&blob));
    }

    #[test]
    fn is_envelope_rejects_legacy() {
        let legacy = b"{\"key\":\"abc\",\"secret\":\"xyz\"}";
        assert!(!is_envelope(legacy));
    }

    #[test]
    fn is_envelope_rejects_binary() {
        assert!(!is_envelope(&[0xFF, 0xFE, 0x00]));
    }

    #[test]
    fn wrong_dek_fails() {
        let secret = b"secret data";
        let (_, blob) = make_test_envelope(secret);
        let env = parse_envelope(&blob).unwrap();
        let wrong_dek = Zeroizing::new(vec![0u8; 32]);
        assert!(decrypt_with_dek(&wrong_dek, &env, &[]).is_err());
    }

    #[test]
    fn bad_dek_length_fails() {
        let (_, blob) = make_test_envelope(b"test");
        let env = parse_envelope(&blob).unwrap();
        let short_dek = Zeroizing::new(vec![0u8; 16]);
        match decrypt_with_dek(&short_dek, &env, &[]) {
            Err(EnvelopeError::BadDekLength(16)) => {}
            other => panic!("expected BadDekLength(16), got {:?}", other),
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (dek, blob) = make_test_envelope(b"test");
        let mut env = parse_envelope(&blob).unwrap();
        let mut ct = B64.decode(&env.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        env.ciphertext = B64.encode(&ct);
        assert!(decrypt_with_dek(&dek, &env, &[]).is_err());
    }

    /// AAD round-trip: a blob sealed with sealed-identity AAD decrypts only
    /// under the IDENTICAL AAD; a mismatched AAD fails the GCM tag (design
    /// §5.4 Option A — the tamper-evident second identity check).
    #[test]
    fn aad_must_match_or_gcm_tag_fails() {
        let dek = Zeroizing::new(Aes256Gcm::generate_key(OsRng).to_vec());
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
        let aad_a = b"customer_id=cust-a\nvenue_id=binance\nkey_version=1";
        let aad_b = b"customer_id=cust-b\nvenue_id=binance\nkey_version=1";
        let secret = b"{\"key\":\"k\"}";
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: secret.as_ref(),
                    aad: aad_a,
                },
            )
            .unwrap();
        let env = Envelope {
            version: ENVELOPE_VERSION,
            wrapped_dek: B64.encode(&*dek),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(&ct),
        };
        // Correct AAD → decrypts.
        assert_eq!(&*decrypt_with_dek(&dek, &env, aad_a).unwrap(), secret);
        // Wrong customer's AAD → GCM tag fails (cross-tenant blob substitution).
        assert!(decrypt_with_dek(&dek, &env, aad_b).is_err());
        // Empty AAD against an AAD-sealed blob → also fails.
        assert!(decrypt_with_dek(&dek, &env, &[]).is_err());
    }

    #[test]
    fn unsupported_version_fails() {
        let blob = br#"{"version":99,"wrapped_dek":"AA==","nonce":"AA==","ciphertext":"AA=="}"#;
        match parse_envelope(blob) {
            Err(EnvelopeError::UnsupportedVersion(99)) => {}
            other => panic!("expected UnsupportedVersion(99), got {:?}", other),
        }
    }
}
