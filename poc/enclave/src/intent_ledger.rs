//! AF-2 in-enclave replay ledger for agent order intents.
//!
//! Records the per-intent nonce (for orders: the `client_order_id`; for
//! cancels: a client UUID) keyed by `customer/venue/nonce`. A second sign
//! request carrying a nonce already in the ledger is a replay → refused. This
//! is DEFENCE-IN-DEPTH, not the sole replay bound:
//!
//!  - The PRIMARY freshness bound is the venue itself — the enclave binds the
//!    request `timestamp_ms` into the signed intent AND signs a small,
//!    enclave-fixed `recvWindow` (5000ms) into the venue HMAC, so the exchange
//!    rejects any order older than the window using ITS reliable clock. A
//!    replayed intent carries a stale timestamp the venue drops; a fresh
//!    timestamp can't be substituted because it is inside the agent signature.
//!  - For orders, the `client_order_id` doubles as the exchange idempotency
//!    key, so the venue dedups a same-coid replay even after this RAM ledger is
//!    wiped by an enclave restart (the ledger, like the rate limiter, holds no
//!    state across restarts by design).
//!
//! This ledger closes the remaining intra-window, same-timestamp replay gap.
//! It is a bounded FIFO set (no unbounded growth, O(1) amortised): capped at
//! `MAX_TRACKED_NONCES`; the oldest entry is evicted when full. Eviction can
//! only re-open a replay window for a nonce older than the last
//! `MAX_TRACKED_NONCES` intents — far beyond the venue's seconds-scale
//! `recvWindow`, so the venue-timestamp bound already covers it.
//!
//! Thread-safety mirrors `rate_limiter`: a `Mutex` behind a `OnceLock` static.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

const MAX_TRACKED_NONCES: usize = 100_000;

pub struct IntentLedger {
    state: Mutex<LedgerState>,
}

struct LedgerState {
    seen: HashSet<String>,
    /// FIFO insertion order for O(1) eviction. Front = oldest.
    order: VecDeque<String>,
}

impl IntentLedger {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(LedgerState {
                seen: HashSet::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// Record `key` if unseen. Returns `true` if it was NEW (allow the sign),
    /// `false` if it was already present (replay → refuse). Bounded FIFO: when
    /// full, evict the oldest key before inserting.
    pub fn record_if_new(&self, key: &str) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.seen.contains(key) {
            return false;
        }
        if state.seen.len() >= MAX_TRACKED_NONCES {
            if let Some(oldest) = state.order.pop_front() {
                state.seen.remove(&oldest);
            }
        }
        // One allocation, then clone the owned String into the FIFO queue
        // (Gemini #233 — avoids a second `to_owned` of the same bytes).
        let owned = key.to_owned();
        state.seen.insert(owned.clone());
        state.order.push_back(owned);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).seen.len()
    }
}

impl Default for IntentLedger {
    fn default() -> Self {
        Self::new()
    }
}

static LEDGER: std::sync::OnceLock<IntentLedger> = std::sync::OnceLock::new();

/// Global replay check: `true` if `key` is new (sign allowed), `false` if a
/// replay (refuse). `key` is `customer/venue/nonce`.
pub fn record_if_new(key: &str) -> bool {
    LEDGER.get_or_init(IntentLedger::new).record_if_new(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_nonce_allowed_replay_refused() {
        let l = IntentLedger::new();
        assert!(l.record_if_new("cust1/binance/coid-1"), "first use allowed");
        assert!(!l.record_if_new("cust1/binance/coid-1"), "replay refused");
        // A different nonce is independent.
        assert!(l.record_if_new("cust1/binance/coid-2"));
        // Tenant/venue namespacing: same nonce under a different tenant is new.
        assert!(l.record_if_new("cust2/binance/coid-1"));
        assert!(l.record_if_new("cust1/okx/coid-1"));
    }

    #[test]
    fn bounded_fifo_eviction() {
        let l = IntentLedger::new();
        for i in 0..MAX_TRACKED_NONCES {
            assert!(l.record_if_new(&format!("k{i}")));
        }
        assert_eq!(l.len(), MAX_TRACKED_NONCES);
        // Overflow evicts the oldest (k0) and inserts the new one.
        assert!(l.record_if_new("overflow"));
        assert_eq!(l.len(), MAX_TRACKED_NONCES);
        // k0 was evicted → it is "new" again (acceptable: far past the venue's
        // seconds-scale recvWindow, which is the primary bound).
        assert!(l.record_if_new("k0"));
    }
}
