//! Per-exchange adaptive backoff (circuit breaker).
//!
//! When the enclave returns `rate_limited`, the gateway opens a per-exchange
//! circuit that rejects subsequent requests without calling the enclave.
//! The backoff doubles on each consecutive rejection (50ms → 100ms → ... →
//! 10s cap). After the backoff window expires, the circuit half-opens: one
//! request is allowed through. If it succeeds, the circuit closes; if it
//! fails, the backoff doubles again.
//!
//! This protects the enclave from burst retries (clients that retry
//! immediately on rate_limited) and gives the token bucket time to refill.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// Upper bound on tracked circuits. Multi-tenant keys the map by the composite
/// `{customer}/{venue}` (PR-A), so the population is ~tenants × venues. 4096 is
/// far above alpha scale (e.g. ~580 customers × 7 venues) but caps memory if a
/// large flood of distinct keys ever opens circuits. On overflow we prune
/// expired entries first; if still full, the new key simply isn't tracked
/// (degrades to "no backoff for this key", never unbounded growth).
const MAX_CIRCUITS: usize = 4096;

pub struct BackoffManager {
    // NOTE: `lock().unwrap_or_else(|e| e.into_inner())` recovers a poisoned
    // mutex (a panic while holding the lock). The map is plain bookkeeping —
    // serving from a possibly-stale circuit only loosens/tightens backoff, never
    // touches key material — so recovery is safe here (unlike the enclave DEK
    // path). `release` runs `panic = "abort"`, so poisoning cannot occur in
    // prod anyway. Pre-existing; flagged in PR-A review #7, intentionally kept.
    circuits: Mutex<HashMap<String, CircuitState>>,
}

#[derive(Clone)]
struct CircuitState {
    backoff: Duration,
    opened_at: Instant,
    half_open: bool,
}

impl BackoffManager {
    pub fn new() -> Self {
        Self {
            circuits: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request for `exchange` should be allowed through.
    /// Returns `true` if allowed, `false` if the circuit is open (backoff active).
    pub fn allow(&self, exchange: &str) -> bool {
        let mut circuits = self.circuits.lock().unwrap_or_else(|e| e.into_inner());

        let Some(state) = circuits.get_mut(exchange) else {
            return true; // no circuit → allow
        };

        let elapsed = state.opened_at.elapsed();
        if elapsed >= state.backoff {
            // Backoff expired → half-open: allow one probe request
            state.half_open = true;
            true
        } else {
            false
        }
    }

    /// Report a successful response — close the circuit for this exchange.
    pub fn report_success(&self, exchange: &str) {
        let mut circuits = self.circuits.lock().unwrap_or_else(|e| e.into_inner());
        circuits.remove(exchange);
    }

    /// Report a rate_limited response — open or extend the circuit.
    pub fn report_rate_limited(&self, exchange: &str) {
        let mut circuits = self.circuits.lock().unwrap_or_else(|e| e.into_inner());

        // Bound the map: if we're at cap and this is a NEW key, prune circuits
        // whose backoff window has already elapsed (they'd half-open on the next
        // `allow` anyway). If still full, skip tracking this key rather than
        // grow without limit.
        if circuits.len() >= MAX_CIRCUITS && !circuits.contains_key(exchange) {
            circuits.retain(|_, s| s.opened_at.elapsed() < s.backoff);
            if circuits.len() >= MAX_CIRCUITS {
                tracing::warn!(
                    event = "backoff_circuits_at_cap",
                    cap = MAX_CIRCUITS,
                    "circuit map at cap — not tracking a new key this cycle"
                );
                return;
            }
        }

        let state = circuits.entry(exchange.to_owned()).or_insert(CircuitState {
            backoff: INITIAL_BACKOFF,
            opened_at: Instant::now(),
            half_open: false,
        });

        if state.half_open {
            // Half-open probe failed → double the backoff
            state.backoff = (state.backoff * 2).min(MAX_BACKOFF);
        }

        state.opened_at = Instant::now();
        state.half_open = false;
    }

    /// Number of open circuits (for metrics/testing).
    #[cfg(test)]
    fn open_circuits(&self) -> usize {
        self.circuits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_when_no_circuit() {
        let bm = BackoffManager::new();
        assert!(bm.allow("binance"));
        assert_eq!(bm.open_circuits(), 0);
    }

    #[test]
    fn blocks_after_rate_limit() {
        let bm = BackoffManager::new();
        bm.report_rate_limited("binance");
        // Immediately after → should block (backoff not expired)
        assert!(!bm.allow("binance"));
    }

    #[test]
    fn clears_on_success() {
        let bm = BackoffManager::new();
        bm.report_rate_limited("okx");
        assert!(!bm.allow("okx"));
        bm.report_success("okx");
        assert!(bm.allow("okx"));
        assert_eq!(bm.open_circuits(), 0);
    }

    #[test]
    fn independent_exchanges() {
        let bm = BackoffManager::new();
        bm.report_rate_limited("binance");
        assert!(!bm.allow("binance"));
        assert!(bm.allow("okx")); // okx unaffected
    }

    #[test]
    fn half_open_after_backoff_expires() {
        let bm = BackoffManager::new();

        // Manually set a very short backoff that has expired
        {
            let mut circuits = bm.circuits.lock().unwrap();
            circuits.insert(
                "test".to_owned(),
                CircuitState {
                    backoff: Duration::from_millis(1),
                    opened_at: Instant::now() - Duration::from_millis(10),
                    half_open: false,
                },
            );
        }

        // Backoff expired → should allow (half-open probe)
        assert!(bm.allow("test"));

        // Check half_open is set
        let circuits = bm.circuits.lock().unwrap();
        assert!(circuits.get("test").unwrap().half_open);
    }

    #[test]
    fn backoff_doubles_on_repeated_failure() {
        let bm = BackoffManager::new();
        bm.report_rate_limited("burst");

        // Simulate half-open probe failure
        {
            let mut circuits = bm.circuits.lock().unwrap();
            let state = circuits.get_mut("burst").unwrap();
            state.half_open = true;
        }

        bm.report_rate_limited("burst");

        // Backoff should be doubled from 50ms to 100ms
        let circuits = bm.circuits.lock().unwrap();
        let state = circuits.get("burst").unwrap();
        assert_eq!(state.backoff, Duration::from_millis(100));
    }

    #[test]
    fn backoff_caps_at_max() {
        let bm = BackoffManager::new();

        // Set backoff near max
        {
            let mut circuits = bm.circuits.lock().unwrap();
            circuits.insert(
                "capped".to_owned(),
                CircuitState {
                    backoff: Duration::from_secs(8),
                    opened_at: Instant::now(),
                    half_open: true,
                },
            );
        }

        bm.report_rate_limited("capped");

        let circuits = bm.circuits.lock().unwrap();
        let state = circuits.get("capped").unwrap();
        assert_eq!(state.backoff, MAX_BACKOFF); // capped at 10s, not 16s
    }
}
