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
use std::collections::HashMap;
use std::sync::Arc;

/// Vsock target (CID + port) where the enclave is listening.
#[derive(Clone, Copy, Debug)]
pub struct EnclaveTarget {
    pub cid: u32,
    pub port: u32,
}

#[derive(Clone)]
pub struct AppState {
    pub creds: Arc<CredsCache>,
    /// Per-exchange ciphertext blobs. Lookup by lowercase exchange name
    /// (e.g. "kucoin", "binance", "binance_futures", "bybit").
    pub blobs: Arc<HashMap<String, Vec<u8>>>,
    pub enclave: EnclaveTarget,
}

impl AppState {
    pub fn new(blobs: HashMap<String, Vec<u8>>, enclave: EnclaveTarget) -> Self {
        Self {
            creds: CredsCache::new(),
            blobs: Arc::new(blobs),
            enclave,
        }
    }
}
