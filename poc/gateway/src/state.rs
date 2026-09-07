//! Shared application state held in `axum::Router::with_state`.
//!
//! Three things live here:
//!   - The IMDSv2 credentials cache (`Arc<CredsCache>`).
//!   - Pre-loaded ciphertext blobs keyed by exchange name. Each exchange has
//!     its own KMS-encrypted secret (KuCoin: 3-field, Binance/Bybit: 2-field).
//!     Immutable for the life of the process — operator restarts to rotate.
//!   - The vsock target (cid + port) for the running enclave.
//!
//! `Clone` is required by axum's `State` extractor; all fields are `Arc`s
//! so cloning is cheap and ref-counted.

use crate::aws::CredsCache;
use crate::backoff::BackoffManager;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// E3 — live-signature health. The gateway runs a periodic attested-data
/// self-sign probe (the same round-trip as the boot self-test) and records the
/// outcome here; `/healthz` publishes it so an external monitor can alert when
/// signing is silently broken (KMS/key/enclave decrypt failure) even though the
/// enclave still answers vsock `ping`s. Atomics (not a Mutex) — writes are a
/// handful of scalar stores from one probe task; reads are lock-free on the hot
/// `/healthz` path.
#[derive(Debug, Default)]
pub struct SignHealth {
    /// The periodic probe is ACTIVE (attested-data key provisioned). When false,
    /// a monitor MUST ignore the other fields — a venue-only box has no
    /// gateway-initiated sign path (the gateway holds only the data-signing token).
    pub enabled: AtomicBool,
    /// Unix seconds of the last SUCCESSFUL probe (0 = never succeeded yet).
    pub last_ok_epoch: AtomicU64,
    /// Unix seconds of the last probe ATTEMPT (0 = never attempted yet).
    pub last_attempt_epoch: AtomicU64,
    /// Whether the most recent completed probe passed.
    pub last_ok: AtomicBool,
    /// Consecutive failed probes (reset to 0 on success).
    pub consecutive_failures: AtomicU32,
}

impl SignHealth {
    /// Mark the probe path active (data key provisioned) — called once at boot.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn record_success(&self, now_epoch: u64) {
        self.last_attempt_epoch.store(now_epoch, Ordering::Relaxed);
        self.last_ok_epoch.store(now_epoch, Ordering::Relaxed);
        self.last_ok.store(true, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self, now_epoch: u64) {
        self.last_attempt_epoch.store(now_epoch, Ordering::Relaxed);
        self.last_ok.store(false, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn last_ok(&self) -> bool {
        self.last_ok.load(Ordering::Relaxed)
    }

    /// Seconds since the last SUCCESSFUL probe; `None` if it never succeeded.
    pub fn age_since_ok(&self, now_epoch: u64) -> Option<u64> {
        let ok = self.last_ok_epoch.load(Ordering::Relaxed);
        (ok != 0).then(|| now_epoch.saturating_sub(ok))
    }
}

/// Legacy single-tenant customer id. Used as the composite-key namespace for
/// flat `{venue}.enc` blobs (the pre-multi-tenant on-disk layout) and as the
/// resolved customer when auth is not enforcing (no-auth dev mode). Matches
/// the `customer_id` baked into the single-tenant `.ctx.json` sidecars
/// (`rewrap-with-context.sh` default). Multi-tenant deployments override the
/// resolved customer per-token via `SIGNER_API_TOKENS`.
pub const DEFAULT_CUSTOMER_ID: &str = "00000000-0000-0000-0000-000000000001";

/// Attested-signed-data (P2): the service-owned data-signing key is staged under
/// this fixed `(customer, stem)` namespace — `secrets/attested-data/data-signing.enc`
/// on disk → `blob_key("attested-data", "data-signing")`. The customer id MUST
/// equal the enclave-side sealed KMS EncryptionContext `customer_id` (design §5),
/// which the enclave reconstructs from the data-signing service identity that the
/// forwarded `SIGNER_DATA_SIGNING_TOKEN` resolves to.
pub const DATA_SIGNING_CUSTOMER: &str = "attested-data";
pub const DATA_SIGNING_STEM: &str = "data-signing";

/// Build the composite blob-map key from a resolved customer id and a venue /
/// key stem. This is the SINGLE place the `(customer, venue)` → key mapping is
/// defined; every handler lookup site and the loader funnel through it so a
/// customer can only ever reach a blob stored under their own namespace.
///
/// PR-A (PCR0-neutral) makes the gateway route by (auth-resolved customer,
/// venue). The cryptographic isolation (enclave-authoritative identity, KMS
/// EncryptionContext, in-blob sealed identity) lands in PR-B — this composite
/// key is the routing half, not yet the trust boundary (design §6 note).
pub fn blob_key(customer_id: &str, stem: &str) -> String {
    format!("{customer_id}/{stem}")
}

/// Vsock target (CID + port) where the enclave is listening.
#[derive(Clone, Copy, Debug)]
pub struct EnclaveTarget {
    pub cid: u32,
    pub port: u32,
}

#[derive(Clone, Debug)]
pub struct BlobBundle {
    pub ciphertext: Vec<u8>,
    /// Loaded from the `{venue}.ctx.json` sidecar. PR-B: the gateway no longer
    /// FORWARDS this to the enclave — the enclave builds the EncryptionContext
    /// from its own resolved identity (§3). Kept loaded (vestigial) so the
    /// on-disk layout + loader stay unchanged; remove in a follow-up cleanup.
    #[allow(dead_code)]
    pub encryption_context: Option<HashMap<String, String>>,
}

#[derive(Clone)]
pub struct AppState {
    pub creds: Arc<CredsCache>,
    /// Ciphertext blobs keyed by the composite `{customer_id}/{stem}` key
    /// (see [`blob_key`]). The loader maps legacy flat `{venue}.enc` files
    /// under [`DEFAULT_CUSTOMER_ID`]; per-customer blobs use their own id.
    pub blobs: Arc<HashMap<String, BlobBundle>>,
    pub enclave: EnclaveTarget,
    /// Phase 0: per-exchange adaptive backoff circuit breaker.
    pub backoff: Arc<BackoffManager>,
    /// Attested-signed-data (P2): the enclave `opaque_token` forwarded for
    /// `sign_data` — the DATA-SIGNING service token (from `SIGNER_DATA_SIGNING_TOKEN`)
    /// that the enclave registry resolves to `{customer_id:"attested-data",
    /// allowed_venues:["data-signing"]}`. This is NOT a gateway auth credential
    /// (the operator router gates WHO may call `/sign-data`); it selects WHICH
    /// key the enclave decrypts. `None` until the data key is provisioned →
    /// `/sign-data` fails closed.
    pub data_signing_token: Option<Arc<str>>,
    /// B3 (mainnet gate): per-token daily order counter (fail-closed) +
    /// per-token per-minute rate limit. `Limits::disabled()` by default;
    /// `main()` installs the env-configured instance via `with_limits`.
    pub limits: Arc<crate::limits::Limits>,
    /// E3: live-signature health, written by the periodic self-sign probe and
    /// read by `/healthz`. Shared (`Arc`) so the spawned probe task and the
    /// request handlers see the same cell.
    pub sign_health: Arc<SignHealth>,
    /// Per-tenant kill switch (ACTIVE / CANCEL_ONLY / HALTED), switched at
    /// runtime without a restart and persisted so a halt survives one. In-memory
    /// by default; `main()` installs the file-backed store via `with_tenants`.
    pub tenants: Arc<crate::tenant_state::TenantStateStore>,
}

impl AppState {
    pub fn new(blobs: HashMap<String, BlobBundle>, enclave: EnclaveTarget) -> Self {
        Self {
            creds: CredsCache::new(),
            blobs: Arc::new(blobs),
            enclave,
            backoff: Arc::new(BackoffManager::new()),
            data_signing_token: None,
            limits: Arc::new(crate::limits::Limits::disabled()),
            sign_health: Arc::new(SignHealth::default()),
            tenants: Arc::new(crate::tenant_state::TenantStateStore::in_memory()),
        }
    }

    /// Install the file-backed tenant-state store (see `tenant_state::TenantStateStore::load`).
    pub fn with_tenants(mut self, tenants: crate::tenant_state::TenantStateStore) -> Self {
        self.tenants = Arc::new(tenants);
        self
    }

    /// Set the data-signing service token (from `SIGNER_DATA_SIGNING_TOKEN`).
    /// Empty/whitespace → `None` (treated as "not provisioned").
    pub fn with_data_signing_token(mut self, token: Option<String>) -> Self {
        self.data_signing_token = token
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .map(|t| Arc::from(t.as_str()));
        self
    }

    /// Install the env-configured B3 limits (see `limits::Limits::from_env`).
    pub fn with_limits(mut self, limits: crate::limits::Limits) -> Self {
        self.limits = Arc::new(limits);
        self
    }
}

// NOTE: blob lookups go through `blob_key(customer, stem)` at each handler
// site (paired with the identically-keyed circuit-breaker), so there is
// deliberately NO `resolve_blob` convenience method that could be called with
// an unscoped key by mistake. The composite key is the ONLY way in.

#[cfg(test)]
mod sign_health_tests {
    use super::SignHealth;

    #[test]
    fn default_is_disabled_never_ok() {
        let sh = SignHealth::default();
        assert!(!sh.is_enabled());
        assert!(!sh.last_ok());
        assert_eq!(sh.age_since_ok(1_000), None, "never succeeded → no age");
    }

    #[test]
    fn success_sets_ok_and_age_and_clears_failures() {
        let sh = SignHealth::default();
        sh.set_enabled(true);
        sh.record_failure(90); // one prior failure
        sh.record_failure(95);
        sh.record_success(100);
        assert!(sh.is_enabled());
        assert!(sh.last_ok());
        assert_eq!(
            sh.consecutive_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "success resets the consecutive-failure counter"
        );
        assert_eq!(sh.age_since_ok(160), Some(60));
    }

    #[test]
    fn failure_does_not_move_last_ok_epoch_so_age_grows() {
        // The monitor alerts on STALENESS (age since last success), which must keep
        // growing across failures — a single blip after a good check must not reset it.
        let sh = SignHealth::default();
        sh.set_enabled(true);
        sh.record_success(100);
        sh.record_failure(130);
        sh.record_failure(160);
        assert!(!sh.last_ok(), "most recent probe failed");
        assert_eq!(
            sh.age_since_ok(200),
            Some(100),
            "age measured from last SUCCESS"
        );
        assert_eq!(
            sh.consecutive_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn age_saturates_on_backwards_clock() {
        let sh = SignHealth::default();
        sh.record_success(1_000);
        // now < last_ok (clock stepped back) → saturating_sub → 0, not underflow.
        assert_eq!(sh.age_since_ok(900), Some(0));
    }
}
