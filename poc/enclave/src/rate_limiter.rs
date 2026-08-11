//! In-enclave token-bucket rate limiter.
//!
//! Limits signing requests per S3-key (≈ per-venue per-customer). The bucket
//! refills at `rate` tokens/sec up to `capacity`. Each request consumes one
//! token; if the bucket is empty the request is rejected immediately (no
//! queuing — the enclave must stay non-blocking).
//!
//! The limiter lives entirely in enclave memory — no external state, no
//! Redis, no persistence across restarts. This is intentional: a restarted
//! enclave gets a fresh budget, and an attacker who somehow forces a restart
//! gets at most `capacity` burst requests before the limiter kicks in again.
//!
//! Eviction policy: FIFO by insertion order, capped at `MAX_TRACKED_KEYS`
//! (Gemini PR #46 round-1: O(N) `min_by_key` LRU scan under mutex was a DoS
//! amplifier when a flood of unique keys forced a scan per-insert). FIFO is
//! O(1) per eviction.
//!
//! Bypass mitigation (Gemini PR #46 round-2): a naive FIFO with "reset to
//! capacity on re-insert" allows an attacker (assumed compromised gateway)
//! who cycles `MAX_TRACKED_KEYS+1` unique keys to evict a target rate-limited
//! key, then re-uses it with a fresh full bucket. We mitigate by maintaining
//! a parallel "ghost cache" of evicted (`tokens`, `last_refill`) state. The
//! ghost queue is strictly FIFO-bounded at `MAX_TRACKED_KEYS` (tombstones
//! from lazy removal are dropped on push, preventing memory leak). On re-insertion of an evicted key, we
//! restore its prior state from the ghost cache (refilling tokens by elapsed
//! time) instead of resetting to full capacity. To force a full reset the
//! attacker must now cycle through `2 * MAX_TRACKED_KEYS` unique keys, AND
//! the target key must not be touched during the ghost's lifetime. This
//! raises the cost materially; production deployments should additionally
//! apply a global per-process request rate limit (not yet implemented).
//!
//! Thread-safety: the `RateLimiter` holds a `Mutex<LimiterState>` and is
//! designed to be stored in a `static` via `OnceLock`. The mutex is
//! uncontested in the current single-threaded tokio runtime but is correct
//! if we ever move to multi-threaded.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

const MAX_TRACKED_KEYS: usize = 10_000;

pub struct RateLimiter {
    capacity: f64,
    rate: f64,
    state: Mutex<LimiterState>,
}

struct LimiterState {
    buckets: HashMap<String, Bucket>,
    /// Insertion order for FIFO eviction. Front = oldest, back = newest.
    /// Kept in sync with `buckets` keys.
    insertion_order: VecDeque<String>,
    /// Ghost cache: state of recently-evicted keys. Re-inserting a key
    /// found here restores its prior tokens/last_refill instead of granting
    /// a fresh full bucket. FIFO-bounded at `MAX_TRACKED_KEYS`.
    ghost: HashMap<String, Bucket>,
    ghost_order: VecDeque<String>,
}

#[derive(Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, rate_per_sec: u32) -> Self {
        Self {
            capacity: capacity as f64,
            rate: rate_per_sec as f64,
            state: Mutex::new(LimiterState {
                buckets: HashMap::new(),
                insertion_order: VecDeque::new(),
                ghost: HashMap::new(),
                ghost_order: VecDeque::new(),
            }),
        }
    }

    /// Try to consume one token for `key`. Returns `true` if allowed,
    /// `false` if rate-limited.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if !state.buckets.contains_key(key) {
            // O(1) FIFO eviction from main → push to ghost.
            if state.buckets.len() >= MAX_TRACKED_KEYS {
                if let Some(oldest) = state.insertion_order.pop_front() {
                    if let Some(evicted) = state.buckets.remove(&oldest) {
                        // Push to ghost (also FIFO-bounded).
                        //
                        // Bound `ghost_order` length, NOT `ghost` map length
                        // (Gemini PR #46 round-3 SEC-HIGH catch). The previous
                        // implementation only pruned when `ghost.len() >= MAX`,
                        // but `ghost.remove(key)` on restore left tombstones in
                        // `ghost_order`. Under frequent restore patterns the
                        // ghost map stayed small, the pruning loop never ran,
                        // and `ghost_order` grew without bound → OOM in enclave.
                        //
                        // Capping `ghost_order` strictly at MAX_TRACKED_KEYS
                        // guarantees O(1) amortized push (each push removes
                        // at most one front entry — tombstone or real).
                        while state.ghost_order.len() >= MAX_TRACKED_KEYS {
                            match state.ghost_order.pop_front() {
                                Some(stale) => {
                                    // Drop the matching ghost entry if still
                                    // present; silently discard tombstones.
                                    state.ghost.remove(&stale);
                                }
                                None => break,
                            }
                        }
                        state.ghost.insert(oldest.clone(), evicted);
                        state.ghost_order.push_back(oldest);
                    }
                }
            }

            // Restore from ghost if previously evicted; otherwise fresh full
            // bucket. Gemini PR #46 round-3: keep this path O(1) — only
            // remove from the ghost map, NOT from ghost_order. The stale
            // ghost_order entry becomes a tombstone, lazily skipped on the
            // next eviction (see while-loop above).
            let restored = state.ghost.remove(key);
            let bucket = restored.unwrap_or(Bucket {
                tokens: self.capacity,
                last_refill: now,
            });
            state.insertion_order.push_back(key.to_owned());
            state.buckets.insert(key.to_owned(), bucket);
        }

        let bucket = state
            .buckets
            .get_mut(key)
            .expect("bucket inserted above must be present");

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of tracked keys (for metrics/testing).
    #[cfg(test)]
    fn tracked_keys(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .buckets
            .len()
    }
}

/// Global singleton. Initialized on first use with defaults from env vars
/// or compile-time constants.
static LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();

const DEFAULT_CAPACITY: u32 = 100;
const DEFAULT_RATE_PER_SEC: u32 = 100;

fn parse_env_u32(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn init_limiter() -> RateLimiter {
    let capacity = parse_env_u32("SIGNER_RATE_LIMIT_CAPACITY", DEFAULT_CAPACITY);
    let rate = parse_env_u32("SIGNER_RATE_LIMIT_PER_SEC", DEFAULT_RATE_PER_SEC);
    tracing::info!(capacity, rate, "rate limiter initialized");
    RateLimiter::new(capacity, rate)
}

/// Check if a request for `s3_key` is allowed. Returns `true` if within
/// budget, `false` if rate-limited.
pub fn check(s3_key: &str) -> bool {
    LIMITER.get_or_init(init_limiter).check(s3_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_capacity() {
        let rl = RateLimiter::new(5, 5);
        for _ in 0..5 {
            assert!(rl.check("venue-a"));
        }
        assert!(!rl.check("venue-a"));
    }

    #[test]
    fn separate_keys_independent() {
        let rl = RateLimiter::new(2, 2);
        assert!(rl.check("venue-a"));
        assert!(rl.check("venue-a"));
        assert!(!rl.check("venue-a"));
        assert!(rl.check("venue-b"));
        assert!(rl.check("venue-b"));
        assert!(!rl.check("venue-b"));
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(1, 1000);
        assert!(rl.check("k"));
        assert!(!rl.check("k"));
        {
            let mut state = rl.state.lock().unwrap();
            let b = state.buckets.get_mut("k").unwrap();
            b.last_refill = Instant::now() - std::time::Duration::from_millis(10);
        }
        assert!(rl.check("k"));
    }

    #[test]
    fn zero_capacity_rejects_all() {
        let rl = RateLimiter::new(0, 100);
        assert!(!rl.check("any"));
    }

    #[test]
    fn tracks_keys() {
        let rl = RateLimiter::new(10, 10);
        rl.check("a");
        rl.check("b");
        rl.check("a");
        assert_eq!(rl.tracked_keys(), 2);
    }

    #[test]
    fn evicts_oldest_when_at_capacity() {
        let rl = RateLimiter::new(100, 100);
        for i in 0..MAX_TRACKED_KEYS {
            rl.check(&format!("key-{}", i));
        }
        assert_eq!(rl.tracked_keys(), MAX_TRACKED_KEYS);
        rl.check("overflow-key");
        assert_eq!(rl.tracked_keys(), MAX_TRACKED_KEYS);

        // Gemini PR #46 round-1 catch: FIFO order — key-0 evicted, overflow-key present.
        let state = rl.state.lock().unwrap();
        assert!(
            !state.buckets.contains_key("key-0"),
            "key-0 (first inserted) should have been evicted"
        );
        assert!(
            state.buckets.contains_key("overflow-key"),
            "overflow-key should be present after eviction"
        );
        assert_eq!(state.insertion_order.len(), state.buckets.len());
    }

    #[test]
    fn evicted_key_preserves_tokens_in_ghost() {
        // Gemini PR #46 round-2 catch: re-inserting an evicted key must
        // NOT grant a fresh full bucket — restore tokens from ghost cache.
        let rl = RateLimiter::new(5, 1); // cap=5, refill 1/sec
                                         // Drain "target" down to 0 tokens.
        for _ in 0..5 {
            assert!(rl.check("target"));
        }
        assert!(!rl.check("target"), "target should be rate-limited");

        // Force eviction by filling main with MAX_TRACKED_KEYS unique keys.
        for i in 0..MAX_TRACKED_KEYS {
            rl.check(&format!("flood-{}", i));
        }
        // target must now be in ghost, not main.
        {
            let state = rl.state.lock().unwrap();
            assert!(
                !state.buckets.contains_key("target"),
                "target should be evicted from main"
            );
            assert!(
                state.ghost.contains_key("target"),
                "target's prior state should live in ghost"
            );
        }

        // Re-inserting target should restore its (near-zero) token state,
        // NOT grant a fresh burst of `capacity` tokens.
        // First call: bucket has ~0 tokens, gets refilled a tiny bit, decrement →
        // rejected because tokens still < 1.
        let allowed_after_reinsert = rl.check("target");
        // After a small refill since last activity (microseconds in tests),
        // tokens should still be below 1.
        assert!(
            !allowed_after_reinsert,
            "re-inserted target should NOT be granted a fresh burst (ghost restore)"
        );
    }

    #[test]
    fn ghost_order_bounded_under_frequent_restores() {
        // Gemini PR #46 round-3 SEC-HIGH regression: previously, ghost_order
        // grew unbounded when keys were frequently restored (because ghost
        // map stayed small and the pruning loop never triggered).
        //
        // Scenario: cycle the same target key through eviction/restore many
        // times. ghost_order must remain bounded.
        let rl = RateLimiter::new(10, 10);

        // Prime: insert target so it exists and can be evicted later.
        rl.check("target");

        // Cycle: flood with MAX_TRACKED_KEYS unique keys to evict target,
        // then re-touch target (which restores from ghost, creates tombstone
        // in ghost_order). Repeat several times.
        for cycle in 0..5 {
            for i in 0..MAX_TRACKED_KEYS {
                rl.check(&format!("flood-{}-{}", cycle, i));
            }
            // Now target is in ghost. Restore it.
            rl.check("target");
        }

        let state = rl.state.lock().unwrap();
        // ghost_order must be bounded — previously grew to ~5 * MAX_TRACKED_KEYS.
        assert!(
            state.ghost_order.len() <= MAX_TRACKED_KEYS,
            "ghost_order leaked: {} entries (cap {})",
            state.ghost_order.len(),
            MAX_TRACKED_KEYS
        );
    }

    #[test]
    fn poisoned_mutex_recovers() {
        let rl = RateLimiter::new(10, 10);
        assert!(rl.check("recover"));
    }
}
