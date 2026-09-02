//! Decision receipts — `docs/DECISION-RECEIPTS-DESIGN.md` (accepted 2026-08-22).
//!
//! Every decision the enclave takes on a tenant request — allow and deny alike,
//! one counter — leaves a receipt signed by a key that lives only here and whose
//! public key is bound into the NSM attestation document. An outside verifier
//! does what it already does for the image: verify the COSE document against
//! the AWS root, take `public_key` from the SIGNED document, verify the receipt
//! signature with it. "Denied by policy" becomes a checkable fact, not a line in
//! the gateway's log — and a receipt the gateway cannot forge, because it holds
//! no key.
//!
//! ## Key (CTO ruling: variant 1, with domain separation)
//!
//! The attested-data secp256k1 key (already provisioned, KMS-sealed under
//! PCR0). It is NOT resident in the enclave by design: `sign_data` decrypts it
//! from an operator-staged blob under the data-signing SERVICE identity, which a
//! TENANT request cannot do. So this module keeps a RESIDENT copy in enclave
//! RAM once `sign_data` has decrypted it — the same trust boundary the DEK
//! cache already lives in (`dek_cache.rs`): KMS released the key to THIS
//! measurement; holding it for the process lifetime does not widen who can use
//! it. The gateway's live-signature probe calls `sign_data` at boot and every
//! ~300 s, so the key is resident seconds after start.
//!
//! Until it is resident — and permanently on a venue-only box with no data key
//! provisioned — NO receipts are issued and the attestation document carries NO
//! `public_key`. That absence is itself verifiable ("the receipt epoch has not
//! started on this enclave"); what must never happen is a receipt that cannot be
//! checked. Receipts never block signing.
//!
//! ## Domain separation (CTO condition)
//!
//! `attested-data` already signs `keccak(ATTESTED_DATA_DOMAIN_V1 ‖ canonical)`.
//! Receipts sign `keccak(DECISION_RECEIPT_DOMAIN_V1 ‖ canonical)` with the same
//! canonical-v1 (RFC 8785 JCS) function — a receipt can never be presented as
//! attested data nor the reverse, and a verifier that does not know the domain
//! cannot verify the signature, which is the point.
//!
//! ## Fields (all JSON strings — canonical-v1 forbids numbers; binary as hex)
//!
//! `v` "1" · `decision` allow|deny · `reason_code` wire code or "ok" ·
//! `customer_id` · `action` · `request_hash` (§`request_digest_v1`) ·
//! `intent_sig_hash` sha256 of the AF-2 agent signature or "" · `policy_hash`
//! (also on deny now) · `supplied_ts_ms` the request's own timestamp — "as
//! supplied", the enclave has no trusted clock · `boot_id` 16 random bytes per
//! enclave start, hex · `seq` per-boot, PER-CUSTOMER decision counter, GAP-FREE:
//! assigned atomically in the same step as the signature, after the decision is
//! final, so a missing number means the gateway dropped a receipt, never that
//! the enclave skipped one.
//!
//! No self-reported PCR0: the NSM document binds `public_key` to PCR0; the
//! receipt binds the decision to `public_key`. The chain is complete without the
//! enclave asserting its own measurement.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::proto::{HlSignature, SignRequest, SignResponse};

pub const DECISION_RECEIPT_DOMAIN_V1: &[u8] = b"usenami-decision-receipt-v1";

static KEY: OnceLock<Mutex<Option<Zeroizing<[u8; 32]>>>> = OnceLock::new();
/// The decision counter. A `Mutex`, not an `AtomicU64`, because the number is
/// INSIDE the signed payload: it must be chosen, signed over, and committed as
/// one step, and released WITHOUT advancing if the signature fails (CodeRabbit
/// — `fetch_add` then a failed sign burned a number and produced a gap the
/// verifier would blame on the gateway, inverting the whole property). Signing
/// is therefore serialized across enclave threads; that is the price of a
/// gap-free chain, and it costs **185 µs per decision** (release build,
/// `receipt_signing_cost_is_bounded`) — canonical-v1 + keccak + one ECDSA over
/// ~300 bytes — against a request that spends 200-300 ms end to end. The KEY
/// lock is NOT held across the signature (Gemini).
/// Decision counter, **per customer**. It was one global counter until
/// 2026-08-31, and that made the gap-free property true only on an enclave with
/// exactly one tenant: with two, tenant A's receipts read 828, 831, 835 — the
/// holes are B's decisions, and A cannot tell them from a receipt the gateway
/// dropped. The whole point of the counter is that a hole means exactly one
/// thing, so the counter has to be scoped to the party who reads it.
///
/// Keyed by `customer_id`, which comes from the SIGNED registry — the key space
/// is bounded by the registry, not by anything a caller supplies.
static SEQ: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
static BOOT_ID: OnceLock<[u8; 16]> = OnceLock::new();

fn key_slot() -> &'static Mutex<Option<Zeroizing<[u8; 32]>>> {
    KEY.get_or_init(|| Mutex::new(None))
}

/// Per-boot random id — partitions `seq` across enclave restarts.
pub fn boot_id() -> &'static [u8; 16] {
    BOOT_ID.get_or_init(|| {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b
    })
}

/// Make the data-signing key resident for receipt signing. Idempotent; a
/// different key (re-provisioned data key) replaces the old one. Called by
/// `sign_data` after a successful KMS decrypt — never from a tenant path.
pub fn install_key(pk: &[u8; 32]) {
    let mut slot = key_slot().lock().unwrap_or_else(|p| p.into_inner());
    let same = slot.as_ref().is_some_and(|k| k.as_ref() == pk);
    if same {
        return;
    }
    let pubkey = crate::signer::attested_data_pubkey(pk)
        .map(|(c, _)| c)
        .unwrap_or_else(|_| "<invalid>".to_owned());
    *slot = Some(Zeroizing::new(*pk));
    tracing::info!(event = "receipt_key_resident", pubkey_compressed = %pubkey, "decision receipts are now issued");
}

/// True once a key is resident.
pub fn key_resident() -> bool {
    key_slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_some()
}

/// Compressed secp256k1 public key (33 bytes) for the attestation document's
/// `public_key` field. `None` before the key is resident.
pub fn public_key_compressed() -> Option<Vec<u8>> {
    let slot = key_slot().lock().unwrap_or_else(|p| p.into_inner());
    let pk = slot.as_ref()?;
    let (hex_compressed, _) = crate::signer::attested_data_pubkey(pk).ok()?;
    hex::decode(hex_compressed.trim_start_matches("0x")).ok()
}

#[cfg(test)]
pub fn test_reset_seq() {
    SEQ.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

#[cfg(test)]
pub fn test_clear_key() {
    *key_slot().lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// The signed receipt. Field order is the JSON order on the wire; signing uses
/// canonical-v1 (sorted keys), so order here is cosmetic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub v: String,
    pub decision: String,
    pub reason_code: String,
    pub customer_id: String,
    pub action: String,
    pub request_hash: String,
    pub intent_sig_hash: String,
    pub policy_hash: String,
    pub supplied_ts_ms: String,
    pub boot_id: String,
    pub seq: String,
    pub signature: HlSignature,
}

fn push_field(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

/// `request_digest_v1` — SHA-256 over the length-prefixed request fields the
/// enclave evaluated, in this fixed order (absent = empty string):
/// action, method, path, query, body, op, payload, timestamp_ms (decimal),
/// hl_action (compact JSON), nonce (decimal), vault_address, order (compact
/// JSON), cancel (compact JSON), x402 (compact JSON), data (raw).
/// A client can recompute it from what it sent — the gateway forwards these
/// verbatim — and so tie a receipt to ONE request.
pub fn request_digest_v1(req: &SignRequest) -> [u8; 32] {
    let mut h = Sha256::new();
    // Straight into the hasher — no intermediate Vec of Strings per decision
    // (Gemini). JSON-valued fields are serialized with `serde_json`, NOT
    // canonical-v1: canonical-v1 deliberately rejects JSON numbers
    // (numerics-as-strings), and `hl_action` legitimately carries them
    // (`{"a":7,...}`) — routing it through canonical-v1 would fail and silently
    // hash an empty field, destroying the binding. Determinism holds without
    // it: `serde_json` is built with `preserve_order`, so a `Value` re-emits
    // the key order the enclave evaluated (the same order the venue's own
    // msgpack/HMAC commits to), and typed structs emit declaration order.
    fn push_str(h: &mut Sha256, v: Option<&str>) {
        push_field(h, v.unwrap_or("").as_bytes());
    }
    fn push_json<T: serde::Serialize>(h: &mut Sha256, v: &Option<T>) {
        match v.as_ref().map(serde_json::to_vec) {
            Some(Ok(bytes)) => push_field(h, &bytes),
            _ => push_field(h, b""),
        }
    }
    fn push_num(h: &mut Sha256, v: Option<u64>) {
        match v {
            Some(x) => push_field(h, x.to_string().as_bytes()),
            None => push_field(h, b""),
        }
    }
    push_field(&mut h, req.action.as_bytes());
    push_str(&mut h, req.method.as_deref());
    push_str(&mut h, req.path.as_deref());
    push_str(&mut h, req.query.as_deref());
    push_str(&mut h, req.body.as_deref());
    push_str(&mut h, req.op.as_deref());
    push_str(&mut h, req.payload.as_deref());
    push_num(&mut h, req.timestamp_ms);
    push_json(&mut h, &req.hl_action);
    push_num(&mut h, req.nonce);
    push_str(&mut h, req.vault_address.as_deref());
    push_json(&mut h, &req.order);
    push_json(&mut h, &req.cancel);
    push_json(&mut h, &req.x402);
    push_str(&mut h, req.data.as_deref());
    h.finalize().into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Tenant actions that are decisions. Service / operator / management actions
/// are not receipted: `sign_data` (service identity), `verify_blob` (no
/// signature is produced, an operator probe), and everything that bypasses the
/// identity gate.
pub fn is_receipted_action(action: &str) -> bool {
    action.starts_with("sign_") && action != "sign_data" && action != "sign"
}

/// What a receipt needs from the REQUEST, captured before the request moves
/// into its handler (no clone of the credential-bearing struct).
#[derive(Clone, Debug)]
pub struct Pre {
    pub customer_id: String,
    pub action: String,
    pub request_hash: String,
    pub intent_sig_hash: String,
    pub supplied_ts_ms: String,
}

impl Pre {
    pub fn capture(identity: &crate::registry::ResolvedIdentity, req: &SignRequest) -> Self {
        Self {
            customer_id: identity.customer_id.clone(),
            action: req.action.clone(),
            request_hash: hex::encode(request_digest_v1(req)),
            intent_sig_hash: req
                .intent_signature
                .as_deref()
                .map(|s| sha256_hex(s.as_bytes()))
                .unwrap_or_default(),
            supplied_ts_ms: req.timestamp_ms.map(|t| t.to_string()).unwrap_or_default(),
        }
    }
}

/// Build and sign the receipt for a finished decision. `None` when no key is
/// resident (epoch not started) or the action is not receipted. The `seq` is
/// taken atomically HERE, after the decision is final — never earlier.
pub fn issue(
    identity: &crate::registry::ResolvedIdentity,
    req: &SignRequest,
    resp: &SignResponse,
) -> Option<DecisionReceipt> {
    issue_pre(&Pre::capture(identity, req), resp)
}

pub fn issue_pre(pre: &Pre, resp: &SignResponse) -> Option<DecisionReceipt> {
    if !is_receipted_action(&pre.action) {
        return None;
    }
    // Copy the key out and release the key lock before signing.
    let pk: Zeroizing<[u8; 32]> = {
        let slot = key_slot().lock().unwrap_or_else(|p| p.into_inner());
        slot.as_ref()?.clone()
    };
    let (decision, reason_code) = match resp.error.as_deref() {
        None => ("allow", "ok".to_owned()),
        Some(code) => ("deny", code.to_owned()),
    };
    let mut receipt = DecisionReceipt {
        v: "1".to_owned(),
        decision: decision.to_owned(),
        reason_code,
        customer_id: pre.customer_id.clone(),
        action: pre.action.clone(),
        request_hash: pre.request_hash.clone(),
        intent_sig_hash: pre.intent_sig_hash.clone(),
        policy_hash: resp.policy_hash.clone().unwrap_or_default(),
        supplied_ts_ms: pre.supplied_ts_ms.clone(),
        boot_id: hex::encode(boot_id()),
        seq: String::new(),
        signature: HlSignature {
            r: String::new(),
            s: String::new(),
            v: 0,
        },
    };
    // Number, sign, THEN commit — all under the counter lock. A failed
    // signature returns without advancing, so the chain never shows a gap the
    // enclave itself created.
    let mut seq_guard = SEQ.lock().unwrap_or_else(|p| p.into_inner());
    // `get_mut` first so the steady state does not clone the key on every
    // decision; `entry` only pays for the allocation on a customer's FIRST
    // receipt (Gemini, #668).
    if !seq_guard.contains_key(&pre.customer_id) {
        seq_guard.insert(pre.customer_id.clone(), 0);
    }
    let counter = seq_guard
        .get_mut(&pre.customer_id)
        .expect("inserted directly above");
    let candidate = *counter;
    receipt.seq = candidate.to_string();
    let sig = sign_receipt(&pk, &receipt).ok()?;
    receipt.signature = sig;
    *counter = candidate + 1;
    Some(receipt)
}

/// Canonical bytes the signature covers: canonical-v1 of the receipt WITHOUT
/// its `signature` field.
pub fn signing_payload(receipt: &DecisionReceipt) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::json!({
        "v": receipt.v,
        "decision": receipt.decision,
        "reason_code": receipt.reason_code,
        "customer_id": receipt.customer_id,
        "action": receipt.action,
        "request_hash": receipt.request_hash,
        "intent_sig_hash": receipt.intent_sig_hash,
        "policy_hash": receipt.policy_hash,
        "supplied_ts_ms": receipt.supplied_ts_ms,
        "boot_id": receipt.boot_id,
        "seq": receipt.seq,
    });
    crate::signer::canonical_v1(&value)
}

/// `keccak256(DECISION_RECEIPT_DOMAIN_V1 ‖ canonical)` — the 32-byte digest.
pub fn receipt_digest_v1(canonical: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DECISION_RECEIPT_DOMAIN_V1.len() + canonical.len());
    buf.extend_from_slice(DECISION_RECEIPT_DOMAIN_V1);
    buf.extend_from_slice(canonical);
    crate::signer::keccak256(&buf)
}

fn sign_receipt(pk: &[u8; 32], receipt: &DecisionReceipt) -> anyhow::Result<HlSignature> {
    let canonical = signing_payload(receipt)?;
    let digest = receipt_digest_v1(&canonical);
    crate::signer::sign_eip712_digest(pk, &digest)
}

/// Attach a receipt to a finished tenant response (no-op when none is issued).
pub fn attach(pre: &Pre, mut resp: SignResponse) -> SignResponse {
    if let Some(r) = issue_pre(pre, &resp) {
        resp.receipt = Some(r);
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────
// Signed counter heartbeat
//
// The receipt chain answers "was this decision hidden?" only in arrears, and in
// one case never: if the gateway swallows a tenant's LAST decision and that
// tenant never calls again, no later receipt exists to show the hole. The
// heartbeat closes it — the tenant asks the enclave directly how many decisions
// it has issued for them, and compares with how many receipts they hold.
//
// 🔴 `client_nonce` is load-bearing, not decoration. The first design carried
// `supplied_ts_ms` instead, and it was replayable: the enclave has no trusted
// clock, that timestamp comes from the caller, and so a gateway could hold one
// old signed heartbeat and keep serving it — hiding exactly the `seq` growth
// the heartbeat exists to reveal. Signature genuine, verification passes,
// answer stale. The client's own nonce, signed INSIDE the document, makes an
// old heartbeat unusable for a new question. Same trick `/attestation` already
// uses; found by Gemini on #645 in MY proposal, not in shipped code.
//
// What it does NOT do, stated so nobody sells it: it cannot make a gateway
// answer. "Refusal to serve" stays visible only as unavailability — there is no
// cryptographic proof of silence. The heartbeat turns "hid a decision" from
// unobservable into observable; it does not turn "switched the service off"
// into anything but downtime.
// ─────────────────────────────────────────────────────────────────────────

/// Domain separator for the heartbeat. Distinct from `DECISION_RECEIPT_DOMAIN_V1`
/// on purpose: a heartbeat must never verify as a receipt, nor the reverse.
pub const RECEIPT_HEARTBEAT_DOMAIN_V1: &[u8] = b"usenami-receipt-heartbeat-v1";

/// Longest `client_nonce` the enclave will echo. The nonce only has to be
/// unguessable to the gateway; 128 chars is far past that and keeps the signed
/// payload bounded.
pub const MAX_CLIENT_NONCE_LEN: usize = 128;

/// The signed answer to "how many decisions have you made for me?".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptHeartbeat {
    pub v: String,
    pub boot_id: String,
    pub customer_id: String,
    /// The NEXT `seq` this customer will be issued — i.e. exactly how many
    /// receipts they have been issued since `boot_id`.
    ///
    /// Named `seq_next`, not `seq_latest` as the design draft had it: after k
    /// receipts the counter reads k, while the last number ISSUED was k-1. A
    /// field whose name is off by one from its value is a trap for the very
    /// verifier this exists to serve.
    pub seq_next: String,
    /// Echo of the caller's nonce — the freshness proof. A document that does
    /// not carry the nonce of THIS request is not an answer to it.
    pub client_nonce: String,
    /// Version of the registry the enclave is actually running, decimal.
    pub registry_version: String,
    /// SHA-256 of the caller's OWN resident registry entry
    /// (`ResolvedIdentity::entry_hash`) — the drift check that needs no
    /// read-back route and leaks nothing to a stolen token.
    pub entry_hash: String,
    pub signature: HlSignature,
}

/// Why no heartbeat was produced — and the distinction is not cosmetic.
///
/// 🔴 `receipts_unavailable` documents its own absence as **verifiable**: the
/// attestation document carries no `public_key` either, so a caller can check
/// the claim. That holds for exactly one of the three ways this can fail.
///
/// If the key IS resident and something else went wrong, answering
/// `receipts_unavailable` would publish a contradiction — the attestation shows
/// the key, the wire says there is none. That is a claim outliving its
/// mechanism, in a document whose entire job is to be checkable. Those paths
/// answer `internal_error` and log, which is honest: something broke, and it
/// was not the absence of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatUnavailable {
    /// No resident key — the receipt epoch has not started on this enclave.
    /// Cross-checkable against the attestation document.
    NoKey,
    /// Key present, something else failed. Never `receipts_unavailable`.
    Internal(&'static str),
}

/// How many receipts this customer has been issued since boot. `0` for a
/// customer with no decisions yet — indistinguishable, and correctly so, from a
/// customer the enclave has never seen.
pub fn seq_next_for(customer_id: &str) -> u64 {
    SEQ.lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(customer_id)
        .copied()
        .unwrap_or(0)
}

/// Canonical bytes the heartbeat signature covers — the document without its
/// `signature` field, canonical-v1 (JCS), same as receipts.
pub fn heartbeat_signing_payload(hb: &ReceiptHeartbeat) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::json!({
        "v": hb.v,
        "boot_id": hb.boot_id,
        "customer_id": hb.customer_id,
        "seq_next": hb.seq_next,
        "client_nonce": hb.client_nonce,
        "registry_version": hb.registry_version,
        "entry_hash": hb.entry_hash,
    });
    crate::signer::canonical_v1(&value)
}

/// `keccak256(RECEIPT_HEARTBEAT_DOMAIN_V1 ‖ canonical)` — the 32-byte digest.
pub fn heartbeat_digest_v1(canonical: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(RECEIPT_HEARTBEAT_DOMAIN_V1.len() + canonical.len());
    buf.extend_from_slice(RECEIPT_HEARTBEAT_DOMAIN_V1);
    buf.extend_from_slice(canonical);
    crate::signer::keccak256(&buf)
}

/// Build and sign a heartbeat for the calling tenant. `None` when no key is resident
/// — the same honest absence as receipts ("the receipt epoch has not started on
/// this enclave"), never an unverifiable document.
///
/// Reads the counter; never advances it. The heartbeat is not a decision, and
/// `is_receipted_action` keeps it out of the chain by construction (the action
/// does not start with `sign_`).
pub fn issue_heartbeat(
    identity: &crate::registry::ResolvedIdentity,
    client_nonce: &str,
) -> Result<ReceiptHeartbeat, HeartbeatUnavailable> {
    let customer_id = identity.customer_id.as_str();
    let pk: Zeroizing<[u8; 32]> = {
        let slot = key_slot().lock().unwrap_or_else(|p| p.into_inner());
        match slot.as_ref() {
            Some(k) => k.clone(),
            None => return Err(HeartbeatUnavailable::NoKey),
        }
    };
    // Two different absences reach the caller as one wire code, so the one that
    // does NOT cross-check against the attestation document has to say so in the
    // log. `receipts_unavailable` documents itself as "verifiable — the
    // attestation carries no public_key either"; that holds for the no-key
    // branch above and NOT for this one, where the key is resident and only the
    // entry failed to canonicalise (CodeRabbit, #668).
    let Some(entry_hash) = identity.entry_hash() else {
        tracing::error!(
            event = "heartbeat_entry_not_canonical",
            customer_id = %customer_id,
            "registry entry does not canonicalise — refusing to sign a blank where a digest belongs"
        );
        return Err(HeartbeatUnavailable::Internal("entry_not_canonical"));
    };
    let mut hb = ReceiptHeartbeat {
        v: "1".to_owned(),
        boot_id: hex::encode(boot_id()),
        customer_id: customer_id.to_owned(),
        seq_next: seq_next_for(customer_id).to_string(),
        client_nonce: client_nonce.to_owned(),
        registry_version: crate::registry::current_version().to_string(),
        entry_hash,
        signature: HlSignature {
            r: String::new(),
            s: String::new(),
            v: 0,
        },
    };
    let canonical = match heartbeat_signing_payload(&hb) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(event = "heartbeat_canonical_failed", error = %e);
            return Err(HeartbeatUnavailable::Internal("canonical_failed"));
        }
    };
    let digest = heartbeat_digest_v1(&canonical);
    hb.signature = match crate::signer::sign_eip712_digest(&pk, &digest) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!(event = "heartbeat_sign_failed", error = %e);
            return Err(HeartbeatUnavailable::Internal("sign_failed"));
        }
    };
    Ok(hb)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resident key and the seq counter are process-global; serialize the
    /// tests that touch them so the parallel runner cannot interleave
    /// install/clear.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = 7;
        k
    }

    fn req(action: &str) -> SignRequest {
        SignRequest {
            action: action.to_owned(),
            proto_version: 1,
            opaque_token: Some("t".to_owned()),
            method: Some("POST".to_owned()),
            path: Some("/api/v1/orders".to_owned()),
            body: Some("{\"a\":1}".to_owned()),
            timestamp_ms: Some(1_700_000_000_000),
            key_blob_s3_key: None,
            key_id: None,
            aws_credentials: None,
            ciphertext_blob_base64: None,
            registry_refresh: None,
            query: None,
            op: None,
            payload: None,
            hl_action: None,
            nonce: None,
            vault_address: None,
            x402: None,
            order: None,
            cancel: None,
            data: None,
            intent_signature: Some("0xabc".to_owned()),
            intent_nonce: None,
            client_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
            provision_venue: None,
            provision_customer_id: None,
            provision_policy: None,
        }
    }

    fn identity() -> crate::registry::ResolvedIdentity {
        crate::registry::ResolvedIdentity::for_provisioned_agent("cust-r", "binance")
    }

    #[test]
    fn no_key_no_receipt_and_no_public_key() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        test_clear_key();
        assert!(!key_resident());
        assert!(public_key_compressed().is_none());
        assert!(issue(
            &identity(),
            &req("sign_binance_order"),
            &SignResponse::err("policy_denied")
        )
        .is_none());
    }

    #[test]
    fn receipt_is_issued_for_allow_and_deny_with_gap_free_seq_and_verifies() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        let id = identity();
        let deny = SignResponse::err("size_over_cap");
        let allow = SignResponse::ok("x".to_owned());
        let r1 = issue(&id, &req("sign_binance_order"), &deny).unwrap();
        let r2 = issue(&id, &req("sign_okx_cancel"), &allow).unwrap();
        assert_eq!(r1.decision, "deny");
        assert_eq!(r1.reason_code, "size_over_cap");
        assert_eq!(r2.decision, "allow");
        assert_eq!(r2.reason_code, "ok");
        let s1: u64 = r1.seq.parse().unwrap();
        let s2: u64 = r2.seq.parse().unwrap();
        assert_eq!(s2, s1 + 1, "one counter, allow and deny alike");
        assert_eq!(r1.boot_id, r2.boot_id);
        assert_eq!(r1.boot_id.len(), 32);
        assert_eq!(r1.request_hash.len(), 64);
        assert_eq!(r1.intent_sig_hash, hex::encode(Sha256::digest(b"0xabc")));
        // Verify exactly as an outsider would: recover the signer from
        // keccak(domain ‖ canonical) and compare with the attestation pubkey.
        let canonical = signing_payload(&r1).unwrap();
        let digest = receipt_digest_v1(&canonical);
        let recovered = crate::signer::recover_eip712_signer(&digest, &r1.signature).unwrap();
        let (_, address) = crate::signer::attested_data_pubkey(&key()).unwrap();
        assert_eq!(format!("0x{}", hex::encode(recovered)), address);
        assert_eq!(public_key_compressed().unwrap().len(), 33);
    }

    /// The receipt copies `policy_hash` from the response verbatim, so whether
    /// a denial can be bound to the rule that produced it is decided ENTIRELY
    /// by whether the refusing response was stamped. That is why the stamping
    /// is enforced at the source in `handler.rs`
    /// (`every_post_policy_refusal_names_the_policy`) — there is no second
    /// chance to add it here.
    ///
    /// Regression 2026-08-31: Hyperliquid per-asset-cap and vault-list denials
    /// reached the client unstamped, so the receipt for a MONEY refusal could
    /// not name the policy it was refused under.
    #[test]
    fn deny_receipt_names_the_policy_the_response_was_stamped_with() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        let id = identity();
        let hash = "9f".repeat(32);
        let stamped = SignResponse::err("policy_denied").with_policy_hash(Some(hash.clone()));
        let r = issue(&id, &req("sign_hyperliquid_main_order"), &stamped).unwrap();
        assert_eq!(r.decision, "deny");
        assert_eq!(r.policy_hash, hash, "a denial must name its policy");

        // And the honest converse: no policy in force → empty, never invented.
        let bare = SignResponse::err("bad_request");
        let r2 = issue(&id, &req("sign_hyperliquid_main_order"), &bare).unwrap();
        assert!(
            r2.policy_hash.is_empty(),
            "an empty hash must keep meaning `refused before the policy was read`"
        );
    }

    /// 🔴 The counter is per CUSTOMER, and that is what makes a hole mean one
    /// thing. Until 2026-08-31 it was one global counter, so the gap-free
    /// property held only on an enclave with exactly one tenant: with two,
    /// tenant A reads 0, 2, 4 and cannot tell B's traffic from a receipt the
    /// gateway dropped. Found while designing the heartbeat, which would have
    /// inherited the same defect AND leaked B's volume to A.
    #[test]
    fn seq_is_per_customer_so_a_hole_means_exactly_one_thing() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        test_reset_seq();
        let a = crate::registry::ResolvedIdentity::for_provisioned_agent("cust-seq-a", "binance");
        let b = crate::registry::ResolvedIdentity::for_provisioned_agent("cust-seq-b", "binance");
        let ok = || SignResponse::ok("x".to_owned());

        // Interleaved on purpose — the global counter passed a sequential test.
        let a0 = issue(&a, &req("sign_binance_order"), &ok()).unwrap();
        let b0 = issue(&b, &req("sign_binance_order"), &ok()).unwrap();
        let a1 = issue(&a, &req("sign_binance_order"), &ok()).unwrap();
        let b1 = issue(&b, &req("sign_binance_order"), &ok()).unwrap();
        let a2 = issue(&a, &req("sign_binance_order"), &ok()).unwrap();

        assert_eq!(
            (a0.seq.as_str(), a1.seq.as_str(), a2.seq.as_str()),
            ("0", "1", "2"),
            "A's chain must be dense despite B trading between every call"
        );
        assert_eq!((b0.seq.as_str(), b1.seq.as_str()), ("0", "1"));
        test_clear_key();
    }

    /// The heartbeat answers the one question the chain cannot: it is read
    /// live, it counts only the caller, it echoes the caller's nonce, it
    /// verifies against the attested key, and reading it never advances the
    /// counter it reports.
    #[test]
    fn heartbeat_counts_only_the_caller_echoes_the_nonce_and_does_not_advance() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        test_reset_seq();
        let a = crate::registry::ResolvedIdentity::for_provisioned_agent("cust-hb-a", "binance");
        let b = crate::registry::ResolvedIdentity::for_provisioned_agent("cust-hb-b", "binance");
        for _ in 0..3 {
            issue(
                &a,
                &req("sign_binance_order"),
                &SignResponse::ok("x".to_owned()),
            )
            .unwrap();
        }
        issue(
            &b,
            &req("sign_okx_cancel"),
            &SignResponse::err("size_over_cap"),
        )
        .unwrap();

        let hb = issue_heartbeat(&a, "nonce-A1").unwrap();
        assert_eq!(hb.customer_id, "cust-hb-a");
        assert_eq!(hb.seq_next, "3", "three receipts issued, next number is 3");
        assert_eq!(
            hb.client_nonce, "nonce-A1",
            "freshness is the caller's, not ours"
        );
        assert_eq!(hb.boot_id.len(), 32);

        // Verify exactly as an outsider would: recover from
        // keccak(heartbeat-domain ‖ canonical) and compare with the pubkey the
        // attestation document publishes.
        let canonical = heartbeat_signing_payload(&hb).unwrap();
        let recovered =
            crate::signer::recover_eip712_signer(&heartbeat_digest_v1(&canonical), &hb.signature)
                .unwrap();
        let (_, address) = crate::signer::attested_data_pubkey(&key()).unwrap();
        assert_eq!(format!("0x{}", hex::encode(recovered)), address);

        // Reading is not a decision.
        let hb2 = issue_heartbeat(&a, "nonce-A2").unwrap();
        assert_eq!(hb2.seq_next, "3", "a read must not advance the counter");
        assert_eq!(hb2.client_nonce, "nonce-A2");

        // 🔴 No cross-tenant oracle: B's volume is B's.
        assert_eq!(issue_heartbeat(&b, "n1").unwrap().seq_next, "1");
        // A customer the enclave has never seen answers 0, not an error — the
        // honest count for "no decisions yet".
        let fresh = crate::registry::ResolvedIdentity::for_provisioned_agent("cust-never", "okx");
        assert_eq!(issue_heartbeat(&fresh, "n1").unwrap().seq_next, "0");

        // And the chain continues where the heartbeat said it would.
        let next = issue(
            &a,
            &req("sign_binance_order"),
            &SignResponse::ok("x".to_owned()),
        )
        .unwrap();
        assert_eq!(next.seq, "3");
        test_clear_key();
    }

    /// Domain separation, stated as a test rather than as a comment: the same
    /// signed bytes must not check out under the receipt domain. Otherwise a
    /// heartbeat could be presented as a decision receipt (or the reverse), and
    /// the two documents make very different claims.
    #[test]
    fn a_heartbeat_never_verifies_as_a_receipt() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        test_reset_seq();
        let dom = crate::registry::ResolvedIdentity::for_provisioned_agent("cust-dom", "binance");
        let hb = issue_heartbeat(&dom, "nonce-1").unwrap();
        let canonical = heartbeat_signing_payload(&hb).unwrap();
        let (_, address) = crate::signer::attested_data_pubkey(&key()).unwrap();

        let right =
            crate::signer::recover_eip712_signer(&heartbeat_digest_v1(&canonical), &hb.signature)
                .unwrap();
        assert_eq!(format!("0x{}", hex::encode(right)), address);

        // Same bytes, receipt domain: recovery still yields *an* address (ECDSA
        // recovery always does) — it must not be OURS.
        // Recovery under the wrong domain either fails outright or yields some
        // OTHER address; both are disjointness, neither may be ours.
        if let Ok(addr) =
            crate::signer::recover_eip712_signer(&receipt_digest_v1(&canonical), &hb.signature)
        {
            assert_ne!(
                format!("0x{}", hex::encode(addr)),
                address,
                "a heartbeat must not verify as a receipt"
            );
        }
        assert_ne!(RECEIPT_HEARTBEAT_DOMAIN_V1, DECISION_RECEIPT_DOMAIN_V1);
        test_clear_key();
    }

    /// End-to-end through the dispatcher: a HALTED tenant can still audit, the
    /// heartbeat is not itself entered into the chain it reports on, and a
    /// nonce the enclave would have to sign blindly is refused.
    #[test]
    fn heartbeat_survives_a_halt_and_is_not_a_decision() {
        // Two locks because this test touches two globals: the shared registry
        // (seeded below, and wiped by other modules' tests) and the receipt key
        // + counter. Broadest first; nothing else takes them in the other order
        // (receipt's TEST_LOCK is private to this module), so no cycle exists.
        let _r = crate::registry::GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        test_reset_seq();
        crate::registry::test_install_with_mode(&[(
            "tok-hb",
            "cust-halted",
            &["binance"],
            crate::registry::TenantMode::Halted,
        )]);

        let mut r = req("receipt_heartbeat");
        r.opaque_token = Some("tok-hb".to_owned());
        r.client_nonce = Some("abc-123_XYZ".to_owned());
        let resp = crate::handler::handle(r);

        assert!(
            resp.error.is_none(),
            "a stopped tenant is exactly the one who needs the evidence: {:?}",
            resp.error
        );
        let hb = resp.heartbeat.as_ref().expect("signed heartbeat");
        assert_eq!(hb.client_nonce, "abc-123_XYZ");
        assert_eq!(hb.customer_id, "cust-halted");
        assert!(
            resp.receipt.is_none(),
            "the heartbeat must not become a decision in the chain it reports"
        );
        // Naryad item 4: the same signed document carries the drift check, so
        // the registry needs no read-back route of its own. The tenant compares
        // `entry_hash` with the composition the operator signed; a thief learns
        // a digest of something they would have to already know.
        assert_eq!(
            hb.entry_hash,
            crate::registry::resolve("tok-hb")
                .unwrap()
                .entry_hash()
                .unwrap(),
            "the heartbeat must report THIS caller's resident entry"
        );
        assert_eq!(
            hb.registry_version,
            crate::registry::current_version().to_string()
        );
        assert_eq!(
            seq_next_for("cust-halted"),
            0,
            "no decision, so nothing to number"
        );

        // A nonce the enclave cannot bound is refused before it is signed.
        // `" abc "` is the one that matters beyond charset hygiene: the gateway
        // used to `trim()` it and forward `"abc"`, so the signed document would
        // have echoed a value the client never sent — and the echo IS the
        // freshness proof. Whitespace is rejected, never repaired.
        for bad in [
            "",
            " abc ",
            "has space",
            &"x".repeat(MAX_CLIENT_NONCE_LEN + 1),
        ] {
            let mut r = req("receipt_heartbeat");
            r.opaque_token = Some("tok-hb".to_owned());
            r.client_nonce = Some(bad.to_owned());
            assert_eq!(
                crate::handler::handle(r).error.as_deref(),
                Some("bad_request"),
                "nonce {bad:?} must not reach the signature"
            );
        }
        // And a missing nonce is not "sign whatever" — a heartbeat without the
        // caller's freshness value is the replayable shape we removed.
        let mut r = req("receipt_heartbeat");
        r.opaque_token = Some("tok-hb".to_owned());
        r.client_nonce = None;
        assert_eq!(
            crate::handler::handle(r).error.as_deref(),
            Some("bad_request")
        );
        test_clear_key();
    }

    /// CTO condition (2): a receipt NEVER blocks signing. With no key resident
    /// the response passes through `attach` byte-identical (no error, no
    /// receipt); with a key resident the ORIGINAL outcome is untouched — only
    /// `receipt` is added. Signing a receipt can fail only if the key is
    /// invalid, and then `issue` returns None rather than turning an allow
    /// into a deny.
    #[test]
    fn receipts_never_block_signing() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let pre = Pre::capture(&identity(), &req("sign_binance_order"));
        test_clear_key();
        let allow = SignResponse::ok("sig".to_owned());
        let out = attach(&pre, allow.clone());
        assert!(out.error.is_none() && out.receipt.is_none());
        assert_eq!(out.signature_base64, "sig");
        let deny = SignResponse::err("size_over_cap");
        let out = attach(&pre, deny);
        assert_eq!(out.error.as_deref(), Some("size_over_cap"));
        assert!(out.receipt.is_none());
        install_key(&key());
        let out = attach(&pre, allow);
        assert!(out.error.is_none(), "an allow stays an allow");
        assert_eq!(out.signature_base64, "sig");
        assert!(out.receipt.is_some());
        // An unusable key (all-zero scalar is invalid for secp256k1): issue()
        // yields None, the decision still goes out unchanged.
        install_key(&[0u8; 32]);
        let out = attach(&pre, SignResponse::ok("sig2".to_owned()));
        assert!(out.error.is_none() && out.receipt.is_none());
        assert_eq!(out.signature_base64, "sig2");
        test_clear_key();
    }

    /// CodeRabbit: the counter must NOT advance when the signature fails —
    /// otherwise the enclave itself creates the gap that the chain blames on
    /// the gateway. An all-zero scalar is invalid for secp256k1, so every
    /// `sign_receipt` under it fails.
    #[test]
    fn failed_signature_does_not_burn_a_seq() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        let id = identity();
        let before: u64 = issue(
            &id,
            &req("sign_okx_cancel"),
            &SignResponse::ok("x".to_owned()),
        )
        .unwrap()
        .seq
        .parse()
        .unwrap();
        install_key(&[0u8; 32]);
        for _ in 0..3 {
            assert!(issue(
                &id,
                &req("sign_okx_cancel"),
                &SignResponse::ok("x".to_owned())
            )
            .is_none());
        }
        install_key(&key());
        let after: u64 = issue(
            &id,
            &req("sign_okx_cancel"),
            &SignResponse::ok("x".to_owned()),
        )
        .unwrap()
        .seq
        .parse()
        .unwrap();
        assert_eq!(
            after,
            before + 1,
            "three failed signatures must not consume numbers"
        );
        test_clear_key();
    }

    /// The cost of the serialized step, so the trade-off is a number and not an
    /// opinion (Gemini asked to release the lock across signing — we cannot,
    /// the number is inside the signed payload). Dev-box figure only.
    #[test]
    fn receipt_signing_cost_is_bounded() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        let id = identity();
        let r = req("sign_okx_cancel");
        let t0 = std::time::Instant::now();
        const N: u32 = 50;
        for _ in 0..N {
            assert!(issue(&id, &r, &SignResponse::ok("x".to_owned())).is_some());
        }
        let per = t0.elapsed() / N;
        println!("receipt issue (canonical+keccak+ecdsa): {per:?} per decision");
        assert!(
            per < std::time::Duration::from_millis(20),
            "receipt cost {per:?} is out of budget"
        );
        test_clear_key();
    }

    #[test]
    fn domain_separation_from_attested_data() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        let r = issue(
            &identity(),
            &req("sign_okx_order"),
            &SignResponse::err("policy_denied"),
        )
        .unwrap();
        let canonical = signing_payload(&r).unwrap();
        // The same bytes under the attested-data domain give a DIFFERENT digest,
        // so a receipt can never be replayed as attested data (or the reverse).
        assert_ne!(
            receipt_digest_v1(&canonical),
            crate::signer::attested_data_digest_v1(&canonical)
        );
        assert_ne!(
            DECISION_RECEIPT_DOMAIN_V1,
            crate::signer::ATTESTED_DATA_DOMAIN_V1
        );
    }

    #[test]
    fn request_digest_ties_receipt_to_one_request() {
        let a = request_digest_v1(&req("sign_binance_order"));
        let mut other = req("sign_binance_order");
        other.body = Some("{\"a\":2}".to_owned());
        assert_ne!(a, request_digest_v1(&other));
        let mut moved = req("sign_binance_order");
        moved.path = Some("/api/v1/order".to_owned()); // field-shift must not collide
        moved.body = Some("s{\"a\":1}".to_owned());
        assert_ne!(a, request_digest_v1(&moved));
    }

    #[test]
    fn service_and_operator_actions_are_not_receipted() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_key(&key());
        for a in ["sign_data", "verify_blob", "ping", "attestation", "sign"] {
            assert!(
                issue(&identity(), &req(a), &SignResponse::ok("x".to_owned())).is_none(),
                "{a}"
            );
        }
        assert!(is_receipted_action("sign_x402_eip3009"));
        assert!(is_receipted_action("sign_kucoin"));
    }
}
