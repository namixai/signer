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
use std::sync::Arc;

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
        }
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
