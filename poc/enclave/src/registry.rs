//! Enclave-resident tenant registry — the §3 invariant made concrete.
//!
//! Maps an opaque bearer token → `{customer_id, allowed_venues}`, resolved
//! ENTIRELY inside the enclave. The gateway forwards only the opaque token; it
//! can never assert which customer a request belongs to (design §5.1, §3). The
//! EncryptionContext the enclave hands to KMS, the TOFU/rate-limit namespaces,
//! and the in-blob sealed-identity AAD are all derived from THIS resolution —
//! never from a gateway field.
//!
//! Design decisions, traced to the round-2-PASS sign-off:
//! - **Vec, not HashMap (round-1 R6).** A `HashMap` absent-key lookup
//!   short-circuits and leaks a present/absent timing oracle. The registry is
//!   a `Vec<TenantEntry>` scanned in full every time, branch-free, so the only
//!   timing signal is "how many tenants are configured" — never identity.
//! - **Keyed token hash (round-1 C8).** Entries store
//!   `HMAC-SHA256(token, registry_key)`, not a bare hash, so a *partial* memory
//!   disclosure of the resident hash Vec (without the key) is not usable. The
//!   key is a per-boot random 32 bytes, `Zeroizing`, never serialized.
//! - **Signed, nonce-bound, monotonic refresh (design §5.2 Ruling 3, D5).** A
//!   refresh is accepted only if a control-plane Ed25519 signature (pubkey
//!   baked into the EIF → PCR0) verifies over `canonical(nonce ‖ version ‖
//!   content_hash)`, the nonce equals the one THIS enclave just issued, and the
//!   version is monotonic. Replay of an old signed blob is blocked by the fresh
//!   nonce; the control plane must, by contract, only sign the current HEAD.
//! - **Cold-boot (round-2 C4 note).** `max_known_version` lives in RAM and
//!   starts at 0; the FIRST validated refresh is accepted unconditionally. The
//!   nonce binding is the sole rollback protection at first boot — which is
//!   sound: a cold boot issues a fresh nonce, so the gateway cannot replay an
//!   old signed payload. There is deliberately NO stateless cold-boot version
//!   check (the enclave has no disk; the counter is RAM-only).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Control-plane Ed25519 public key (32 bytes, hex) baked into the EIF. A
/// rotation of this key is a PCR0-changing event (re-attestation), which is
/// the intended infrequency for the registry's trust root. Sourced from an
/// env the Dockerfile bakes (`SIGNER_REGISTRY_PUBKEY`); absent ⇒ refresh is
/// disabled (fail-closed: no tenant can be loaded, so nothing signs).
const REGISTRY_PUBKEY_ENV: &str = "SIGNER_REGISTRY_PUBKEY";

/// Resolved tenant identity — the SOLE source of the customer dimension for
/// everything downstream (KMS context, TOFU/rate key, sealed-identity AAD).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedIdentity {
    pub customer_id: String,
    allowed_venues: Vec<String>,
    /// PR-4 (kill switch, enclave floor): the tenant's operating mode as
    /// signed into the registry by the control plane. Enforced in `handle()`
    /// before any action runs — a mode the gateway cannot lift, because only
    /// a signed refresh changes it.
    pub mode: TenantMode,
}

/// Per-tenant operating mode, carried in the SIGNED registry entry (so the
/// gateway cannot change it). Mirrors the gateway's three states
/// (docs/TENANT-KILL-SWITCH-DESIGN.md §5, PR-4): `Active` — everything the
/// venue ACL + policy allow; `CancelOnly` — no new exposure (orders, x402,
/// opaque POST bodies refused), cancels and reads still signed; `Halted` —
/// nothing signed for this tenant. Absent in older registry blobs ⇒ `Active`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TenantMode {
    #[default]
    Active,
    CancelOnly,
    Halted,
}

impl TenantMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(TenantMode::Active),
            "cancel_only" => Some(TenantMode::CancelOnly),
            "halted" => Some(TenantMode::Halted),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            TenantMode::Active => "active",
            TenantMode::CancelOnly => "cancel_only",
            TenantMode::Halted => "halted",
        }
    }
}

impl ResolvedIdentity {
    /// SHA-256 over the canonical form of THIS tenant's resident registry entry:
    /// `{"allowed_venues":[…sorted…],"customer_id":"…","mode":"active|cancel_only|halted"}`
    /// under canonical-v1 (RFC 8785 JCS), hex.
    ///
    /// Why a HASH and not the entry. The live registry is RAM-only and there is
    /// no way to read it back — composition drift is therefore invisible until
    /// a request happens to fail on it, which is exactly how 2026-08-31 went.
    /// A read-back of the entry itself would fix that and simultaneously hand a
    /// STOLEN token its own scope in one call, which is the venue-scope oracle
    /// `authorize_venue` deliberately refuses to be (see the `err_code` note on
    /// the absent `venue_not_allowed` class). A hash gives the operator — who
    /// holds the composition they signed — a one-line drift check, and gives a
    /// thief nothing: a digest of something they would have to already know.
    ///
    /// `token_hmac` is deliberately NOT covered: its key is enclave-internal, so
    /// including it would make the hash unreproducible off-box, which defeats
    /// the entire purpose. The token→entry mapping is still covered in effect —
    /// the caller's own token is what resolved to this entry, so a re-pointed
    /// token shows up as a different `customer_id`.
    ///
    /// Venues are SORTED so the digest does not depend on the order the
    /// composition happened to list them in.
    pub fn entry_hash(&self) -> Option<String> {
        let mut venues = self.allowed_venues.clone();
        venues.sort();
        let value = serde_json::json!({
            "customer_id": self.customer_id,
            "allowed_venues": venues,
            "mode": self.mode.as_str(),
        });
        let canonical = crate::signer::canonical_v1(&value).ok()?;
        Some(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            &canonical,
        )))
    }

    /// True iff this tenant is permitted to act on `venue`. The venue ACL is
    /// checked BEFORE blob access (design §5.4), so an authenticated tenant
    /// can never even reach a venue blob outside their grant.
    pub fn venue_allowed(&self, venue: &str) -> bool {
        self.allowed_venues.iter().any(|v| v == venue)
    }

    /// Build the KMS EncryptionContext from the RESOLVED identity — pinned to
    /// exactly `{customer_id, venue_id}` (design D3). This is the only place
    /// the context is constructed; the gateway-supplied field is gone.
    pub fn encryption_context(&self, venue: &str) -> HashMap<String, String> {
        let mut ctx = HashMap::with_capacity(2);
        ctx.insert("customer_id".to_owned(), self.customer_id.clone());
        ctx.insert("venue_id".to_owned(), venue.to_owned());
        ctx
    }

    /// Canonical sealed-identity AAD bytes (design §5.4 Option A). Bound as
    /// real AES-GCM AAD in `envelope::decrypt_with_dek`, so a blob wrapped for
    /// customer B fails the GCM tag under customer A's resolved identity. The
    /// byte encoding is pinned here and MUST match `rewrap-with-context.sh`.
    pub fn sealed_aad(&self, venue: &str, key_version: u32) -> Vec<u8> {
        format!(
            "customer_id={}\nvenue_id={}\nkey_version={}",
            self.customer_id, venue, key_version
        )
        .into_bytes()
    }

    /// The attested-data data-signing SERVICE identity (Option-1 / §5). Its
    /// `encryption_context` + `sealed_aad` are EXACTLY what the data-key blob is
    /// sealed under at provisioning and decrypted under at sign time — the single
    /// source so both sides stay byte-identical. `customer_id` MUST equal the
    /// gateway `DATA_SIGNING_CUSTOMER` and the reserved-venue owner.
    pub fn for_data_signing() -> Self {
        ResolvedIdentity {
            customer_id: "attested-data".to_owned(),
            allowed_venues: vec!["data-signing".to_owned()],
            mode: TenantMode::Active,
        }
    }

    /// ROT-1: the identity a freshly-minted TENANT agent key is sealed under.
    ///
    /// `for_data_signing` above is a fixed SERVICE identity — one customer, one
    /// venue, both hardcoded, because there is exactly one data-signing key. An
    /// agent key belongs to a tenant, so both halves come from the provisioning
    /// request. The pair is what determines the KMS encryption context and the
    /// sealed AAD, and the sign path rebuilds it from the RESOLVED tenant plus
    /// the venue implied by the action — so a mismatch here does not produce a
    /// weaker key, it produces an unopenable one.
    ///
    /// `allowed_venues` is set to exactly the one venue on purpose: this value
    /// exists only to derive context/AAD at mint time and is never the thing
    /// that authorises a signature — that is the registry-resolved identity at
    /// request time.
    pub fn for_provisioned_agent(customer_id: &str, venue: &str) -> Self {
        ResolvedIdentity {
            customer_id: customer_id.to_owned(),
            allowed_venues: vec![venue.to_owned()],
            mode: TenantMode::Active,
        }
    }
}

/// One tenant: a keyed token hash + the customer id + venue ACL. The plaintext
/// token is NEVER stored (only its `HMAC(token, registry_key)`).
#[derive(Clone)]
struct TenantEntry {
    token_hmac: [u8; 32],
    customer_id: String,
    allowed_venues: Vec<String>,
    mode: TenantMode,
}

/// Immutable resolved registry. Swapped wholesale under the `RwLock` on each
/// refresh (rust#5: `RwLock<Arc<…>>`, zero new deps — `std` has no `Arc::swap`
/// and `arc-swap` is not a dependency). In-flight resolves hold a cloned `Arc`
/// and are never interrupted.
struct Registry {
    entries: Vec<TenantEntry>,
    version: u64,
}

impl Registry {
    fn empty() -> Self {
        Registry {
            entries: Vec::new(),
            version: 0,
        }
    }
}

/// Per-boot HMAC key for token hashing (C8). Random, `Zeroizing`, never
/// serialized. Stable for the enclave's lifetime so refresh-time and
/// resolve-time hashes agree.
fn registry_key() -> &'static Zeroizing<[u8; 32]> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();
    KEY.get_or_init(|| {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Zeroizing::new(k)
    })
}

fn token_hmac(token: &str) -> [u8; 32] {
    // SAFETY (cannot panic): `Hmac::new_from_slice` returns `Err(InvalidLength)`
    // only for block-cipher MACs with a key-length constraint; HMAC accepts a key
    // of ANY length, and `registry_key()` is always a fixed [u8; 32]. The expect
    // is therefore unreachable.
    let mut mac = HmacSha256::new_from_slice(registry_key().as_slice())
        .expect("HMAC accepts any key length (registry_key is [u8;32]) — unreachable");
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().into()
}

fn global() -> &'static RwLock<Arc<Registry>> {
    use std::sync::OnceLock;
    static REG: OnceLock<RwLock<Arc<Registry>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(Arc::new(Registry::empty())))
}

/// The fresh nonce THIS enclave last issued for a refresh challenge, if any.
/// One-shot: consumed on a successful `refresh`. Replaced on each `challenge`.
fn pending_nonce() -> &'static std::sync::Mutex<Option<[u8; 32]>> {
    use std::sync::OnceLock;
    static N: OnceLock<std::sync::Mutex<Option<[u8; 32]>>> = OnceLock::new();
    N.get_or_init(|| std::sync::Mutex::new(None))
}

/// Issue a fresh 32-byte nonce for a registry-refresh challenge. The control
/// plane must sign over THIS nonce; a refresh whose nonce ≠ the last issued is
/// rejected (anti-replay). Returns the nonce hex for the parent to relay.
pub fn challenge() -> String {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    // Use the poison-recovering guard (consistent with refresh) rather than a bare
    // `lock().unwrap_or_else(into_inner)` — a poisoned mutex is recovered + logged,
    // not silently served. We overwrite the slot here, so the guard's poison-clear
    // is harmless.
    *pending_nonce_guard() = Some(nonce);
    hex::encode(nonce)
}

#[derive(Debug)]
pub enum RegistryError {
    NoPubkey,
    BadPubkey,
    NoPendingNonce,
    NonceMismatch,
    BadNonceHex,
    BadSignature,
    SignatureInvalid,
    ContentHashMismatch,
    NonMonotonicVersion {
        got: u64,
        max_known: u64,
    },
    Empty,
    MalformedEntries,
    UnsafeId,
    ReservedVenue,
    /// PR-4: `mode` present but not one of active | cancel_only | halted.
    BadMode,
}

impl RegistryError {
    /// ROT-6 (narrow): map to the wire code the ceremony operator sees.
    ///
    /// The mapping lives HERE, on the enum, so adding a variant is a compile
    /// error until it is classified — the previous shape collapsed everything
    /// to `bad_request` at the call site, where a new variant would have
    /// silently joined the pile.
    ///
    /// Grouped by STEP, not one-per-variant, and never carrying a value: an
    /// operator's next action is the same for every member of a group ("your
    /// nonce is stale — re-issue the challenge", "you signed with the wrong
    /// key", "your entries file is malformed", "raise the version"), so finer
    /// codes would grow the surface without shortening a single diagnosis.
    /// `NonMonotonicVersion` deliberately does NOT export `max_known` — that
    /// number stays the one fact reconstructed from the operator's own signed
    /// artefacts, and putting it on the wire would make a rejected refresh a
    /// read primitive for the installed version.
    pub fn wire_code(&self) -> &'static str {
        use crate::proto::err_code;
        match self {
            RegistryError::NoPendingNonce
            | RegistryError::NonceMismatch
            | RegistryError::BadNonceHex => err_code::REGISTRY_NONCE_REJECTED,
            RegistryError::NoPubkey
            | RegistryError::BadPubkey
            | RegistryError::BadSignature
            | RegistryError::SignatureInvalid
            | RegistryError::ContentHashMismatch => err_code::REGISTRY_SIGNATURE_REJECTED,
            RegistryError::MalformedEntries
            | RegistryError::Empty
            | RegistryError::UnsafeId
            | RegistryError::ReservedVenue
            | RegistryError::BadMode => err_code::REGISTRY_ENTRIES_REJECTED,
            RegistryError::NonMonotonicVersion { .. } => err_code::REGISTRY_VERSION_REJECTED,
        }
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::NoPubkey => write!(f, "registry control-plane pubkey not configured"),
            RegistryError::BadPubkey => write!(f, "registry control-plane pubkey malformed"),
            RegistryError::NoPendingNonce => write!(f, "no pending nonce — challenge first"),
            RegistryError::NonceMismatch => write!(f, "refresh nonce != last issued challenge"),
            RegistryError::BadNonceHex => write!(f, "refresh nonce hex malformed"),
            RegistryError::BadSignature => write!(f, "refresh signature malformed"),
            RegistryError::SignatureInvalid => write!(f, "refresh signature does not verify"),
            RegistryError::ContentHashMismatch => write!(f, "signed content hash != entries hash"),
            RegistryError::NonMonotonicVersion { got, max_known } => {
                write!(
                    f,
                    "registry version {got} <= max_known {max_known} (rollback)"
                )
            }
            RegistryError::Empty => write!(f, "registry refresh carried no entries"),
            RegistryError::MalformedEntries => write!(f, "registry entries_json failed to parse"),
            RegistryError::UnsafeId => {
                write!(f, "registry entry customer_id/venue has unsafe characters")
            }
            RegistryError::ReservedVenue => {
                write!(
                    f,
                    "registry entry grants a reserved platform venue to a non-owner customer"
                )
            }
            RegistryError::BadMode => {
                write!(
                    f,
                    "registry entry mode must be active | cancel_only | halted"
                )
            }
        }
    }
}
impl std::error::Error for RegistryError {}

/// A single registry entry as it arrives in a (decrypted) refresh payload.
/// `token` is the PLAINTEXT token (the payload is KMS-confidential); the
/// enclave immediately HMAC-keys it and drops the plaintext. `deny_unknown_fields`
/// so a payload carrying extra fields (that serde would silently drop and a
/// future parser might interpret differently) is rejected, not absorbed.
// `Serialize` is derived (used only by the test signer below) so the golden
// vector exercises the EXACT same `serde` Serialize path the control-plane tool
// uses — not a `json!`-macro re-spelling that could silently diverge (crypto
// review M). Production only ever DEserializes this (refresh decodes it).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshEntry {
    pub token: String,
    pub customer_id: String,
    pub allowed_venues: Vec<String>,
    /// PR-4: `"active" | "cancel_only" | "halted"`. Optional so every registry
    /// blob signed before PR-4 still validates (⇒ `active`); an unknown value
    /// rejects the whole refresh (`RegistryError::BadMode`) — a typo must not
    /// silently become `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// An id (customer_id / venue) safe to embed in the newline-delimited sealed
/// AAD and the KMS EncryptionContext: ASCII alnum + `-`/`_`, 1..=64 bytes, and
/// crucially NO `\n`/`=`/control chars — closing the AAD field-shift injection
/// (review F4) at the trust boundary, not only in the bash wrap script.
///
/// `pub(crate)` since ROT-1: agent provisioning takes a customer id from the
/// request and puts it into exactly those two structured strings, so it has to
/// apply the same rule. Re-implementing it there would be a second definition
/// of "safe", and the two would drift.
pub(crate) fn is_safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Reserved platform venues — each may be carried ONLY by its designated system
/// identity. A refresh that grants one to any other customer is rejected at
/// INSTALL time: defense-in-depth so the isolation never rests on every other
/// tenant simply not listing the venue (the per-request venue ACL + KMS
/// EncryptionContext already keep tenants out at request time).
/// - `"x402"`         → only `crate::handler::X402_CUSTOMER_ID` (CTO x402 decision).
/// - `"data-signing"` → only `DATA_SIGNING_OWNER` (attested-signed-data §5,
///   #210/#211): the data key is sealed under `{customer_id:"attested-data", …}`.
const RESERVED_X402_VENUE: &str = "x402";
const RESERVED_DATA_SIGNING_VENUE: &str = "data-signing";
/// The only customer that may carry the reserved data-signing venue. MUST equal
/// the sealed data-key KMS-context customer_id + the gateway `DATA_SIGNING_CUSTOMER`.
const DATA_SIGNING_OWNER: &str = "attested-data";

/// The system identity that EXCLUSIVELY owns a reserved venue, or `None` if the
/// venue is not reserved. Case-insensitive (defense-in-depth: `is_safe_id`
/// permits uppercase, so a control plane could otherwise install `"X402"` /
/// `"Data-Signing"` — inert at request time since `venue_for_action` emits
/// lowercase, but rejected at install so no surprising entry ever resides).
fn reserved_venue_owner(venue: &str) -> Option<&'static str> {
    if venue.eq_ignore_ascii_case(RESERVED_X402_VENUE) {
        Some(crate::handler::X402_CUSTOMER_ID)
    } else if venue.eq_ignore_ascii_case(RESERVED_DATA_SIGNING_VENUE) {
        Some(DATA_SIGNING_OWNER)
    } else {
        None
    }
}

/// True if `e` would grant ANY reserved venue to a customer other than that
/// venue's designated owner.
fn grants_reserved_venue_to_non_reserved(customer_id: &str, allowed_venues: &[String]) -> bool {
    allowed_venues
        .iter()
        .any(|v| matches!(reserved_venue_owner(v), Some(owner) if owner != customer_id))
}

/// Load the baked control-plane verifying key, or `NoPubkey` if unset
/// (fail-closed: refresh impossible ⇒ registry stays empty ⇒ nothing signs).
fn control_plane_vk() -> Result<VerifyingKey, RegistryError> {
    let hex = std::env::var(REGISTRY_PUBKEY_ENV).map_err(|_| RegistryError::NoPubkey)?;
    let bytes = hex::decode(hex.trim()).map_err(|_| RegistryError::BadPubkey)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::BadPubkey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| RegistryError::BadPubkey)
}

/// Canonical bytes the control plane signs and the enclave re-derives:
/// `nonce(32) ‖ version_le(8) ‖ sha256(entries_json)`. Pins exactly what the
/// signature commits to so neither side can reinterpret the payload.
fn signed_message(nonce: &[u8; 32], version: u64, content_hash: &[u8; 32]) -> [u8; 72] {
    let mut m = [0u8; 72];
    m[0..32].copy_from_slice(nonce);
    m[32..40].copy_from_slice(&version.to_le_bytes());
    m[40..72].copy_from_slice(content_hash);
    m
}

fn hash_entries(entries_json: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(entries_json);
    h.finalize().into()
}

/// Recover a possibly-poisoned `pending_nonce` guard, treating poison as
/// "clear the nonce" rather than transparently serving a panicking thread's
/// stale state (review F6).
fn pending_nonce_guard() -> std::sync::MutexGuard<'static, Option<[u8; 32]>> {
    match pending_nonce().lock() {
        Ok(g) => g,
        Err(p) => {
            tracing::error!(event = "pending_nonce_poisoned", "clearing nonce state");
            let mut g = p.into_inner();
            *g = None;
            g
        }
    }
}

/// Validate + install a registry refresh (design §5.2 Ruling 3 / D5 / C4).
///
/// The signature commits to `entries_json` and the resident registry is built
/// by deserializing EXACTLY those bytes — there is no separate `entries`
/// argument a caller could desync from the signed bytes (review F1). The nonce
/// is PEEKED (not consumed) until every check passes, so a bad-signature replay
/// can't burn the pending nonce (review F3).
pub fn refresh(
    entries_json: &[u8],
    nonce_hex: &str,
    version: u64,
    signature_hex: &str,
) -> Result<u64, RegistryError> {
    let vk = control_plane_vk()?;

    // 1. Nonce must equal the one THIS enclave issued — PEEK (don't consume).
    let nonce_bytes = hex::decode(nonce_hex.trim()).map_err(|_| RegistryError::BadNonceHex)?;
    let nonce: [u8; 32] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::BadNonceHex)?;
    {
        let pend = pending_nonce_guard();
        match *pend {
            None => return Err(RegistryError::NoPendingNonce),
            // Constant-time compare — a refresh nonce is attacker-relayable.
            Some(issued) if issued.ct_eq(&nonce).unwrap_u8() != 1 => {
                return Err(RegistryError::NonceMismatch)
            }
            Some(_) => {}
        }
    }

    // 2. Signature over canonical(nonce ‖ version ‖ sha256(entries_json)).
    let content_hash = hash_entries(entries_json);
    let sig_bytes = hex::decode(signature_hex.trim()).map_err(|_| RegistryError::BadSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    let msg = signed_message(&nonce, version, &content_hash);
    vk.verify(&msg, &sig)
        .map_err(|_| RegistryError::SignatureInvalid)?;

    // 3. Derive the entries from the SIGNED bytes — never a caller-supplied Vec.
    let entries: Vec<RefreshEntry> =
        serde_json::from_slice(entries_json).map_err(|_| RegistryError::MalformedEntries)?;
    if entries.is_empty() {
        return Err(RegistryError::Empty);
    }
    // 4. Charset-guard ids so they can never shift AAD/context field boundaries,
    //    AND enforce the reserved-venue blocklist: only the reserved x402 system
    //    identity may carry the `"x402"` venue (defense-in-depth so a hostile or
    //    fat-fingered registry blob can't grant a tenant access to the platform's
    //    x402 payer key).
    for e in &entries {
        if !is_safe_id(&e.customer_id) || e.allowed_venues.iter().any(|v| !is_safe_id(v)) {
            return Err(RegistryError::UnsafeId);
        }
        if grants_reserved_venue_to_non_reserved(&e.customer_id, &e.allowed_venues) {
            return Err(RegistryError::ReservedVenue);
        }
        if let Some(m) = e.mode.as_deref() {
            if TenantMode::parse(m).is_none() {
                return Err(RegistryError::BadMode);
            }
        }
    }

    // 5-7 under ONE write guard (crypto review C7 — version TOCTOU). The old
    // shape read `max_known` under a READ lock, then installed under a SEPARATE
    // WRITE lock: two concurrent refreshes could BOTH pass the read-side check,
    // then the LOWER version win the install race and DOWNGRADE the registry —
    // re-admitting a tenant a higher version had removed. Holding the write lock
    // across the monotonic check + the keyed-hash build + the install + the
    // nonce-consume makes the whole admit atomic. refresh is rare + operator-only,
    // so the longer critical section is free.
    {
        let mut guard = global().write().unwrap_or_else(|p| p.into_inner());

        // 5. Monotonicity (C4): version must exceed the last validated version.
        // On cold boot guard.version == 0, so the first valid refresh (version ≥ 1)
        // is accepted unconditionally — the fresh nonce is the sole rollback
        // protection at first boot, which is sound (fresh nonce ⇒ no replay).
        if version <= guard.version {
            return Err(RegistryError::NonMonotonicVersion {
                got: version,
                max_known: guard.version,
            });
        }

        // 6. Build the resident registry: keyed-hash each token, drop the plaintext.
        let resident: Vec<TenantEntry> = entries
            .into_iter()
            .map(|e| TenantEntry {
                token_hmac: token_hmac(&e.token),
                customer_id: e.customer_id,
                allowed_venues: e.allowed_venues,
                mode: e
                    .mode
                    .as_deref()
                    .and_then(TenantMode::parse)
                    .unwrap_or_default(),
            })
            .collect();
        *guard = Arc::new(Registry {
            entries: resident,
            version,
        });

        // 7. ALL checks passed — consume the nonce (one-shot) WHILE still holding
        // the registry write lock, so install + nonce-consume are atomic. The
        // step-1 peek RELEASED the nonce mutex (so the Ed25519 verify could run
        // unlocked), so a concurrent challenge() may have replaced the pending
        // nonce since. COMPARE-AND-CLEAR (crypto review F3): clear ONLY if the
        // pending nonce is still the one we validated — never burn a fresh nonce a
        // concurrent challenge just issued for the next operator. Constant-time
        // compare (the nonce is attacker-relayable). A failure on any earlier step
        // left it pending so a legit retry can re-sign. (Lock order registry-write
        // → nonce-mutex; the step-1 peek released its guard, so no inverse
        // acquisition and no deadlock.)
        let mut pend = pending_nonce_guard();
        let still_ours = matches!(*pend, Some(p) if p.ct_eq(&nonce).unwrap_u8() == 1);
        if still_ours {
            *pend = None;
        } else {
            // A concurrent challenge() superseded our nonce between the step-1 peek
            // and here. We do NOT clear it (that's the next operator's fresh nonce);
            // surface it so an operator who sees a surprising NoPendingNonce on a
            // follow-up refresh knows a racing challenge consumed the slot (nit).
            tracing::warn!(
                event = "registry_refresh_nonce_superseded",
                "a concurrent challenge replaced the pending nonce during this refresh; \
                 install succeeded, fresh nonce left intact for the next refresh"
            );
        }
    }
    Ok(version)
}

/// Resolve an opaque token to a tenant identity, or `None` if unknown.
///
/// Constant-time over the entry SET: HMAC the token once, then scan ALL entries
/// with `ConstantTimeEq` and a branch-free index select (no early exit). The
/// only timing signal is the tenant count. Mirrors the gateway `auth.rs`
/// pattern (design §5.1).
pub fn resolve(token: &str) -> Option<ResolvedIdentity> {
    let incoming = token_hmac(token);
    let reg = global().read().unwrap_or_else(|p| p.into_inner()).clone();
    let mut matched: usize = usize::MAX;
    for (i, e) in reg.entries.iter().enumerate() {
        let eq = e.token_hmac.ct_eq(&incoming).unwrap_u8() as usize;
        let mask = eq.wrapping_neg();
        matched = (matched & !mask) | (i & mask);
    }
    // Residual (review F5): the final present/absent branch + the clone on the
    // hit path is a small timing asymmetry. It leaks only "did this opaque
    // 32-byte token resolve" — NOT which tenant and NOT anything enumerable
    // (token space is 2^256). Accepted: the Nitro model does not expose
    // co-tenant nanosecond timing, and the per-byte HMAC compare (the only
    // identity-bearing step) is constant-time via ct_eq.
    if matched == usize::MAX {
        None
    } else {
        // SAFETY (cannot panic): `matched` is either usize::MAX (the None arm
        // above) or an index assigned from `enumerate()` over `reg.entries`, so it
        // is always in-bounds here. `.get().expect` over a raw index makes the
        // invariant explicit and yields a named message if it were ever violated.
        let e = reg
            .entries
            .get(matched)
            .expect("matched index is in-bounds (set from enumerate; MAX handled above)");
        Some(ResolvedIdentity {
            customer_id: e.customer_id.clone(),
            allowed_venues: e.allowed_venues.clone(),
            mode: e.mode,
        })
    }
}

/// Current registry version (for logging/diagnostics; 0 = empty/cold).
pub fn current_version() -> u64 {
    global().read().unwrap_or_else(|p| p.into_inner()).version
}

/// Process-wide serialization lock for ANY test that touches the global registry
/// (this module's refresh/reset tests AND handler.rs tests that seed via
/// `test_install` then call `handle`). Cargo runs tests in parallel; without one
/// shared lock a `reset_registry()` here could wipe a handler test's seed between
/// its seed and its `handle()`, silently turning that test into a shadow of the
/// identity gate. Shared (pub(crate)) so both test modules acquire the SAME lock.
#[cfg(test)]
pub(crate) static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-only: install entries directly (bypassing the signed-refresh path) so
/// handler integration tests can seed the registry without a control-plane key.
///
/// ADDITIVE upsert (keyed by token): the whole read-modify-write runs under one
/// write guard, so concurrent seeders from cargo's parallel runner never clobber
/// each other — a test that seeds `tok-a` and another that seeds a broad tenant
/// can both run without one wiping the other's entry. Bypasses the reserved-venue
/// blocklist on purpose (tests construct identities the refresh path would reject).
#[cfg(test)]
pub fn test_install(entries: &[(&str, &str, &[&str])]) {
    let with_mode: Vec<(&str, &str, &[&str], TenantMode)> = entries
        .iter()
        .map(|(t, c, v)| (*t, *c, *v, TenantMode::Active))
        .collect();
    test_install_with_mode(&with_mode);
}

/// Like `test_install`, with an explicit per-tenant mode (PR-4 tests).
#[cfg(test)]
pub fn test_install_with_mode(entries: &[(&str, &str, &[&str], TenantMode)]) {
    let mut g = global().write().unwrap_or_else(|p| p.into_inner());
    let mut current: Vec<TenantEntry> = g.entries.clone();
    for (tok, cid, venues, mode) in entries {
        let token_hmac = token_hmac(tok);
        let entry = TenantEntry {
            token_hmac,
            customer_id: (*cid).to_owned(),
            allowed_venues: venues.iter().map(|v| (*v).to_owned()).collect(),
            mode: *mode,
        };
        match current.iter_mut().find(|e| e.token_hmac == token_hmac) {
            Some(slot) => *slot = entry,
            None => current.push(entry),
        }
    }
    let version = g.version.max(1);
    *g = Arc::new(Registry {
        entries: current,
        version,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 The drift check that costs no read-back route (naryad item 4).
    ///
    /// The resident registry cannot be read out — composition drift is
    /// invisible until a request happens to fail on it, which is exactly how
    /// 2026-08-31 went. `entry_hash` gives the operator a one-line comparison
    /// against the composition they signed, while giving a stolen token
    /// nothing: a digest of a value its holder would have to already know.
    ///
    /// The fixture is computed OUTSIDE this codebase (`json.dumps(..., sort_keys,
    /// separators=(',',':'))` + sha256). If canonical-v1 ever drifts from JCS
    /// this test says so — an operator check that only agrees with itself is
    /// not a check.
    #[test]
    fn entry_hash_is_reproducible_off_box_and_moves_when_the_grant_moves() {
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        test_install(&[(
            "tok-drift",
            "cust-drift",
            &["binance", "hyperliquid_main", "okx"],
        )]);
        let id = resolve("tok-drift").expect("seeded token resolves");
        let h = id.entry_hash().expect("entry canonicalises");
        assert_eq!(
            h, "a0a88958fc7cbde51adda37ec49028a65bd4a27e8580582f412a868585212d8e",
            "canonical form must stay \
             {{\"allowed_venues\":[…],\"customer_id\":…,\"mode\":…}} under JCS"
        );

        // Order of the composition must not matter — an operator who lists the
        // same venues differently has not drifted.
        test_install(&[(
            "tok-drift",
            "cust-drift",
            &["okx", "binance", "hyperliquid_main"],
        )]);
        assert_eq!(resolve("tok-drift").unwrap().entry_hash().unwrap(), h);

        // 🔴 The case this exists for: a venue silently missing from the live
        // entry. This is the shape the Hyperliquid refusal is suspected to be,
        // and today nothing surfaces it until a signature fails.
        test_install(&[("tok-drift", "cust-drift", &["binance", "okx"])]);
        assert_ne!(
            resolve("tok-drift").unwrap().entry_hash().unwrap(),
            h,
            "a dropped venue must change the digest"
        );

        // A silently changed MODE is drift too — a tenant halted by a bad
        // composition looks identical to one halted on purpose.
        test_install_with_mode(&[(
            "tok-drift",
            "cust-drift",
            &["binance", "hyperliquid_main", "okx"],
            TenantMode::CancelOnly,
        )]);
        assert_ne!(resolve("tok-drift").unwrap().entry_hash().unwrap(), h);
    }
    use ed25519_dalek::{Signer, SigningKey};

    /// Install the control-plane pubkey AND take the shared GLOBAL_TEST_LOCK for
    /// the test's duration — serializes env mutation AND global-registry mutation
    /// against every other registry/handler test (see GLOBAL_TEST_LOCK).
    fn install_pubkey(sk: &SigningKey) -> std::sync::MutexGuard<'static, ()> {
        let g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        // SAFETY: GLOBAL_TEST_LOCK serializes env access in this test module.
        unsafe { std::env::set_var(REGISTRY_PUBKEY_ENV, vk_hex) };
        g
    }

    fn sign_refresh(
        sk: &SigningKey,
        entries: &[RefreshEntry],
        nonce_hex: &str,
        version: u64,
    ) -> (Vec<u8>, String) {
        // Serialize via the struct's derived `Serialize` — byte-identical to the
        // control-plane `policy-cli` path (crypto review M: no `json!`-macro
        // re-spelling that could diverge from the production serializer).
        let json = serde_json::to_vec(entries).unwrap();
        let nonce: [u8; 32] = hex::decode(nonce_hex).unwrap().try_into().unwrap();
        let ch = hash_entries(&json);
        let msg = signed_message(&nonce, version, &ch);
        let sig = sk.sign(&msg);
        (json, hex::encode(sig.to_bytes()))
    }

    fn reset_registry() {
        *global().write().unwrap_or_else(|p| p.into_inner()) = Arc::new(Registry::empty());
    }

    /// CROWN-JEWEL anti-drift: this golden vector is asserted IDENTICALLY in the
    /// control-plane signer (`policy-cli/src/registry.rs` tests). It pins the
    /// canonical byte layout (`hash_entries` + `signed_message`, the exact fns
    /// `refresh` verifies against) so the off-box signer and this on-box verifier
    /// can never silently drift: a change to either side's byte layout breaks its
    /// golden test. If you change the format, update BOTH vectors in lockstep.
    ///
    /// Inputs: seed = 32×0x07, nonce = 32×0x01, version = 1,
    ///   entries = [{token:"tok-a", customer_id:"cust-a", allowed_venues:["binance","okx"]}]
    #[test]
    fn golden_vector_matches_control_plane() {
        const GOLDEN_ENTRIES_JSON: &str =
            r#"[{"token":"tok-a","customer_id":"cust-a","allowed_venues":["binance","okx"]}]"#;
        const GOLDEN_CONTENT_HASH_HEX: &str =
            "4c3acd5004975c7d13e21b041831c70c04ae45440d14627bccc7d5dd6d46d454";
        const GOLDEN_SIGNATURE_HEX: &str =
            "3bd8bf339dfd0a188bbaad55c2d3fb7b4157ad8dbef027447f8bc726eb887ec5afc155801548086a9f6b5ce0adc2e35420a5867e6a618aeb669560b2e185b101";

        let entries = vec![RefreshEntry {
            token: "tok-a".to_owned(),
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned(), "okx".to_owned()],
            mode: None,
        }];
        let nonce = [1u8; 32];
        let version = 1u64;
        let sk = SigningKey::from_bytes(&[7u8; 32]);

        // sign_refresh emits the same bytes the control plane KMS-encrypts.
        let (json, sig_hex) = sign_refresh(&sk, &entries, &hex::encode(nonce), version);
        assert_eq!(
            String::from_utf8(json.clone()).unwrap(),
            GOLDEN_ENTRIES_JSON,
            "entries_json byte layout drifted from the control-plane signer"
        );
        // hash_entries + signed_message are EXACTLY what `refresh` re-derives.
        let ch = hash_entries(&json);
        assert_eq!(
            hex::encode(ch),
            GOLDEN_CONTENT_HASH_HEX,
            "content hash drift"
        );
        assert_eq!(
            sig_hex, GOLDEN_SIGNATURE_HEX,
            "signature drift vs control plane"
        );
        // And the verifier path itself accepts the golden signature.
        let msg = signed_message(&nonce, version, &ch);
        assert!(sk
            .verifying_key()
            .verify(
                &msg,
                &Signature::from_bytes(
                    &hex::decode(GOLDEN_SIGNATURE_HEX)
                        .unwrap()
                        .try_into()
                        .unwrap()
                )
            )
            .is_ok());
    }

    /// Second golden vector — TWO entries (array comma + multi-entry ordering).
    /// Asserted identically in `policy-cli/src/registry.rs::golden_vector_two_entries`.
    #[test]
    fn golden_vector_two_entries() {
        const GOLDEN2_CONTENT_HASH_HEX: &str =
            "75bfd82d8021c4e228eb0c2de36559bb4ec8bcf362967dcbb63f597cef8baab9";
        const GOLDEN2_SIGNATURE_HEX: &str =
            "8cbfc61e0e1d189d4420b47bfee270f967e4b8328103e1c0bd35fe96d2b63e5e793108dfd17075f19a65983c59b2b8b3f115af8eb998acb9fc611f418a275f0e";

        let entries = vec![
            RefreshEntry {
                token: "tok-a".to_owned(),
                customer_id: "cust-a".to_owned(),
                allowed_venues: vec!["binance".to_owned(), "okx".to_owned()],
                mode: None,
            },
            RefreshEntry {
                token: "tok-b".to_owned(),
                customer_id: "cust-b".to_owned(),
                allowed_venues: vec!["kucoin".to_owned()],
                mode: None,
            },
        ];
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let (json, sig_hex) = sign_refresh(&sk, &entries, &hex::encode([1u8; 32]), 1);
        assert_eq!(hex::encode(hash_entries(&json)), GOLDEN2_CONTENT_HASH_HEX);
        assert_eq!(sig_hex, GOLDEN2_SIGNATURE_HEX);
    }

    #[test]
    fn challenge_refresh_resolve_roundtrip() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[7u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let entries = vec![RefreshEntry {
            token: "nxai_alpha".to_owned(),
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned(), "okx".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&sk, &entries, &nonce, 1);
        assert_eq!(refresh(&json, &nonce, 1, &sig).unwrap(), 1);

        let id = resolve("nxai_alpha").expect("resolves");
        assert_eq!(id.customer_id, "cust-a");
        assert!(id.venue_allowed("binance") && id.venue_allowed("okx"));
        assert!(!id.venue_allowed("kucoin"));
        assert!(resolve("unknown-token").is_none());
        assert_eq!(
            id.encryption_context("binance").get("customer_id"),
            Some(&"cust-a".to_owned())
        );
    }

    #[test]
    fn refresh_rejects_replayed_nonce() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[9u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let entries = vec![RefreshEntry {
            token: "t".to_owned(),
            customer_id: "c".to_owned(),
            allowed_venues: vec!["binance".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&sk, &entries, &nonce, 1);
        refresh(&json, &nonce, 1, &sig).unwrap();
        // Same nonce again (consumed) → NoPendingNonce.
        let err = refresh(&json, &nonce, 2, &sig).unwrap_err();
        assert!(matches!(err, RegistryError::NoPendingNonce), "{err:?}");
    }

    /// F3: a bad-signature refresh must NOT consume the pending nonce — a
    /// legitimate retry over the same nonce still works.
    #[test]
    fn bad_signature_does_not_burn_pending_nonce() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[11u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let attacker = SigningKey::from_bytes(&[12u8; 32]);
        let entries = vec![RefreshEntry {
            token: "t".to_owned(),
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, bad_sig) = sign_refresh(&attacker, &entries, &nonce, 1);
        assert!(matches!(
            refresh(&json, &nonce, 1, &bad_sig).unwrap_err(),
            RegistryError::SignatureInvalid
        ));
        // Nonce survived → a correctly-signed retry over the SAME nonce works.
        let (json2, good_sig) = sign_refresh(&sk, &entries, &nonce, 1);
        assert_eq!(refresh(&json2, &nonce, 1, &good_sig).unwrap(), 1);
        assert!(resolve("t").is_some());
    }

    /// F4: an entry whose customer_id/venue contains a newline (which would
    /// shift the sealed-AAD field boundaries) is rejected at install time.
    #[test]
    fn refresh_rejects_unsafe_id_chars() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[13u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[13u8; 32]);
        let entries = vec![RefreshEntry {
            token: "t".to_owned(),
            customer_id: "cust-a\nvenue_id=binance".to_owned(), // injection
            allowed_venues: vec!["binance".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&sk, &entries, &nonce, 1);
        assert!(matches!(
            refresh(&json, &nonce, 1, &sig).unwrap_err(),
            RegistryError::UnsafeId
        ));
    }

    /// Round-1 SHOULD-FIX: the reserved `"x402"` venue may be granted ONLY to the
    /// reserved x402 system identity. A refresh granting it to any other customer
    /// is rejected at install time; the reserved customer itself is accepted.
    #[test]
    fn refresh_blocks_reserved_x402_venue_for_non_reserved_customer() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[21u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[21u8; 32]);

        // (a) A normal tenant claiming the reserved venue → rejected.
        let tenant = vec![RefreshEntry {
            token: "evil".to_owned(),
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned(), "x402".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&sk, &tenant, &nonce, 1);
        assert!(matches!(
            refresh(&json, &nonce, 1, &sig).unwrap_err(),
            RegistryError::ReservedVenue
        ));
        // Rejected → registry stays empty, the would-be x402 grant never resolves.
        assert!(resolve("evil").is_none());

        // (b) The reserved x402 system identity may hold the x402 venue.
        let reserved = vec![RefreshEntry {
            token: "x402-platform".to_owned(),
            customer_id: crate::handler::X402_CUSTOMER_ID.to_owned(),
            allowed_venues: vec!["x402".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&sk, &reserved, &nonce, 1);
        assert_eq!(refresh(&json, &nonce, 1, &sig).unwrap(), 1);
        assert!(resolve("x402-platform")
            .expect("reserved resolves")
            .venue_allowed("x402"));
    }

    /// LOW#1 (crypto-panel #211 fast-follow): the reserved `"data-signing"` venue
    /// (attested-signed-data §5) may be granted ONLY to the attested-data identity
    /// — same install-time defense-in-depth as `"x402"`. A tenant claiming it is
    /// rejected; the attested-data identity itself is accepted.
    #[test]
    fn refresh_blocks_reserved_data_signing_venue_for_non_owner() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[22u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[22u8; 32]);

        // (a) A tenant claiming the reserved data-signing venue → rejected.
        let tenant = vec![RefreshEntry {
            token: "evil-ds".to_owned(),
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned(), "data-signing".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&sk, &tenant, &nonce, 1);
        assert!(matches!(
            refresh(&json, &nonce, 1, &sig).unwrap_err(),
            RegistryError::ReservedVenue
        ));
        assert!(resolve("evil-ds").is_none());

        // (b) The attested-data identity may hold the data-signing venue.
        let owner = vec![RefreshEntry {
            token: "data-signing-svc".to_owned(),
            customer_id: DATA_SIGNING_OWNER.to_owned(),
            allowed_venues: vec!["data-signing".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&sk, &owner, &nonce, 1);
        assert_eq!(refresh(&json, &nonce, 1, &sig).unwrap(), 1);
        assert!(resolve("data-signing-svc")
            .expect("owner resolves")
            .venue_allowed("data-signing"));
    }

    #[test]
    fn refresh_rejects_rollback_version() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[3u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let mk = |tok: &str| {
            vec![RefreshEntry {
                token: tok.to_owned(),
                customer_id: "c".to_owned(),
                allowed_venues: vec!["binance".to_owned()],
                mode: None,
            }]
        };
        let n1 = challenge();
        let e1 = mk("a");
        let (j1, s1) = sign_refresh(&sk, &e1, &n1, 5);
        refresh(&j1, &n1, 5, &s1).unwrap();
        // version 4 < max_known 5 → rollback rejected.
        let n2 = challenge();
        let e2 = mk("b");
        let (j2, s2) = sign_refresh(&sk, &e2, &n2, 4);
        let err = refresh(&j2, &n2, 4, &s2).unwrap_err();
        assert!(
            matches!(err, RegistryError::NonMonotonicVersion { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn refresh_rejects_forged_signature() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[1u8; 32]));
        reset_registry();
        let attacker = SigningKey::from_bytes(&[2u8; 32]); // not the baked key
        let entries = vec![RefreshEntry {
            token: "t".to_owned(),
            customer_id: "c".to_owned(),
            allowed_venues: vec!["binance".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (json, sig) = sign_refresh(&attacker, &entries, &nonce, 1);
        let err = refresh(&json, &nonce, 1, &sig).unwrap_err();
        assert!(matches!(err, RegistryError::SignatureInvalid), "{err:?}");
    }

    #[test]
    fn refresh_rejects_tampered_content() {
        let _g = install_pubkey(&SigningKey::from_bytes(&[4u8; 32]));
        reset_registry();
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let entries = vec![RefreshEntry {
            token: "t".to_owned(),
            customer_id: "c".to_owned(),
            allowed_venues: vec!["binance".to_owned()],
            mode: None,
        }];
        let nonce = challenge();
        let (_json, sig) = sign_refresh(&sk, &entries, &nonce, 1);
        // Different entries_json than what was signed → content-hash mismatch
        // surfaces as an invalid signature (the hash is inside the signed msg).
        let tampered = br#"[{"token":"t","customer_id":"EVIL","allowed_venues":["binance"]}]"#;
        let err = refresh(tampered, &nonce, 1, &sig).unwrap_err();
        assert!(matches!(err, RegistryError::SignatureInvalid), "{err:?}");
    }

    /// PR-4: `mode` is optional (old blobs ⇒ active), parsed when present, and
    /// an unknown value rejects the refresh — a typo must not become `active`.
    #[test]
    fn refresh_entry_mode_is_optional_parsed_and_validated() {
        let absent: RefreshEntry =
            serde_json::from_str(r#"{"token":"t","customer_id":"c","allowed_venues":["binance"]}"#)
                .unwrap();
        assert!(absent.mode.is_none());
        let co: RefreshEntry = serde_json::from_str(
            r#"{"token":"t","customer_id":"c","allowed_venues":["binance"],"mode":"cancel_only"}"#,
        )
        .unwrap();
        assert_eq!(
            TenantMode::parse(co.mode.as_deref().unwrap()),
            Some(TenantMode::CancelOnly)
        );
        assert_eq!(TenantMode::parse("halted"), Some(TenantMode::Halted));
        assert_eq!(TenantMode::parse("active"), Some(TenantMode::Active));
        assert_eq!(TenantMode::parse("HALTED"), None, "exact spelling only");
        assert_eq!(TenantMode::parse("paused"), None);
        // Serialization omits an absent mode — byte-identical blobs for old tooling.
        assert!(!serde_json::to_string(&absent).unwrap().contains("mode"));
    }

    #[test]
    fn sealed_aad_is_canonical_and_identity_bound() {
        let id = ResolvedIdentity {
            customer_id: "cust-a".to_owned(),
            allowed_venues: vec!["binance".to_owned()],
            mode: TenantMode::Active,
        };
        assert_eq!(
            id.sealed_aad("binance", 1),
            b"customer_id=cust-a\nvenue_id=binance\nkey_version=1".to_vec()
        );
        // Different customer → different AAD → GCM tag would fail.
        let other = ResolvedIdentity {
            customer_id: "cust-b".to_owned(),
            allowed_venues: vec!["binance".to_owned()],
            mode: TenantMode::Active,
        };
        assert_ne!(id.sealed_aad("binance", 1), other.sealed_aad("binance", 1));
    }
}
