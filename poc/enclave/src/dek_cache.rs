//! In-enclave DEK (data-encryption-key) cache.
//!
//! ## What this removes
//! Today every sign on an envelope-v2 blob shells out to `kmstool_enclave_cli`
//! to KMS-Decrypt the wrapped DEK (≈140 ms box-internal, and it serializes
//! concurrency — see the internal latency-benchmark notes).
//! This cache holds the **decrypted DEK** in enclave RAM for a short TTL so the
//! 2nd…Nth sign on the same blob skips kmstool and unwraps the envelope
//! locally (AES-256-GCM, microseconds).
//!
//! ## What is cached — and what is NOT
//! - Cached: the **DEK** (the 32-byte AES key that unwraps the envelope).
//! - NOT cached: the final venue secret (HMAC key / private key). It is still
//!   derived per-sign from the freshly-unwrapped plaintext and zeroized
//!   immediately, exactly as before.
//! - NOT cached: legacy (non-envelope) blobs. Those have no separate DEK — KMS
//!   decrypts the secret directly, and caching that would mean caching the
//!   venue secret, which this module deliberately never does. Legacy blobs keep
//!   the per-sign KMS round-trip.
//!
//! ## Invariant preserved
//! The DEK never leaves the enclave. The only delta vs the per-sign model is
//! *residency*: the DEK lives in enclave RAM for up to TTL across many signs
//! instead of for the duration of one sign. An adversary who can read enclave
//! RAM has already defeated the Nitro isolation (which also breaks the per-sign
//! model). Mitigations keep the marginal residency risk small: short TTL,
//! DEK-only, bounded cache, Zeroize-on-evict + on Drop.
//!
//! ## Cache key = SHA-256(len(wrapped_dek) ‖ wrapped_dek ‖ sorted(encryption_context))
//! - The wrapped DEK is KMS *ciphertext* (not secret), but we hash it to get a
//!   fixed-size, non-reversible key and to avoid holding identifiable blob
//!   material as a map key. It is length-prefixed so its bytes can never be
//!   confused with the separator / context region (collision defense-in-depth).
//! - The encryption_context is folded in so a cache hit can only occur for the
//!   exact (wrapped_dek, context) pair KMS itself binds. This means the cache
//!   never bypasses KMS's cross-customer-substitution protection: a different
//!   context → different key → miss → real KMS decrypt (which enforces/denies).
//! - A policy change re-encrypts the whole blob → new `wrapped_dek` → new key →
//!   automatic miss (fresh KMS decrypt). PCR0 rotation replaces the enclave
//!   image → new process → empty cache. So there is deliberately **no separate
//!   attestation/rotation/policy-flush hook** beyond TTL + this key derivation
//!   — flush-on-rotation/policy falls out of the key + process model.
//!
//! ## Poisoned-lock safety (rust-auditor BLOCKER)
//! `get`/`put` return `Result<_, CacheError>`. If the internal mutex is poisoned
//! (a thread panicked mid-mutation, so the map↔order invariant may be broken),
//! they return `Err(CacheError::Poisoned)` rather than `into_inner()`-ing and
//! serving from corrupted state. The call site treats that exactly like a miss
//! → safe KMS fallthrough; the cache self-disables until the process restarts.
//! In release the enclave runs `panic = "abort"`, so a panic tears the process
//! down before poisoning can happen — this path is reachable only in debug/test,
//! but the graceful degradation is correct either way.
//!
//! ## Disable switch
//! `SIGNER_DEK_CACHE_TTL_SECS=0` disables caching entirely (every sign hits KMS
//! — identical to pre-cache behavior). This is the dark-launch / kill switch.
//!
//! ## Emergency stop (operator note — enclave-cryptographer review, M-1)
//! A cached DEK survives KMS-side access changes until its TTL expires: this
//! cache deliberately does NOT call KMS on a hit, so `kms:DisableKey`,
//! `kms:RevokeGrant`, or a key-policy / PCR0-condition change that does NOT
//! re-encrypt the blob will NOT stop signing on already-cached blobs for up to
//! TTL seconds. *Planned* rotation is unaffected — it re-encrypts blobs (new
//! `wrapped_dek` → cache miss), and a PCR0 image rotation restarts the process
//! (empty cache). **To stop signing immediately during an incident, terminate
//! the enclave (`nitro-cli terminate-enclave`) — do not rely on KMS revocation
//! alone.** A startup WARN log states this when the cache is enabled, and the
//! operator runbook documents it.
//! `flush()` is the in-process lever; a host-triggered `flush_dek_cache` vsock
//! command is a documented future option (kept out of v1 to avoid widening the
//! host→enclave command surface without its own review). The default TTL is the
//! spec floor (60 s) to bound this window.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Default residency window: the conservative floor of the spec's 60–300 s
/// band (lowered 120 → 60 per enclave-cryptographer M-1). Operator-tunable.
const DEFAULT_TTL_SECS: u64 = 60;

/// Default bound on distinct cached DEKs. The number of live (customer, venue)
/// blobs is small; this caps RAM residency and bounds the LRU scan.
const DEFAULT_MAX_ENTRIES: usize = 256;

/// Hard ceiling on the env-configurable bound. Caps worst-case RAM residency
/// even if an operator sets `SIGNER_DEK_CACHE_MAX` absurdly high (review MED).
const MAX_ENTRIES_CEILING: usize = 1024;

/// Cache operation outcome error. The only failure mode is a poisoned mutex —
/// surfaced (not silently recovered) so the call site falls through to KMS
/// instead of serving from a possibly-corrupted map↔order. See module docs.
#[derive(Debug)]
pub enum CacheError {
    Poisoned,
}

/// One cached DEK plus its insertion time. The DEK is `Zeroizing`, so removing
/// or dropping an `Entry` (evict / expire / flush / process exit) wipes the key
/// material — there is no separate manual zeroize path to forget.
struct Entry {
    dek: Zeroizing<Vec<u8>>,
    inserted: Instant,
}

struct Inner {
    map: HashMap<[u8; 32], Entry>,
    /// Access order for LRU. Front = least-recently-used, back = most-recent.
    /// Kept in sync with `map`.
    order: VecDeque<[u8; 32]>,
}

pub struct DekCache {
    ttl: Duration,
    max: usize,
    inner: Mutex<Inner>,
}

impl DekCache {
    /// Construct a cache with an explicit TTL + bound. `ttl == 0` means the
    /// cache is disabled: `get` always misses and `put` is a no-op. `max` is
    /// clamped to `[1, MAX_ENTRIES_CEILING]`. Tests use this directly;
    /// production uses [`global`].
    pub fn new(ttl: Duration, max: usize) -> Self {
        Self {
            ttl,
            max: max.clamp(1, MAX_ENTRIES_CEILING),
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    /// Look up a DEK by key.
    ///
    /// - `Ok(Some(dek))` — fresh hit (returns an independent `Zeroizing` clone;
    ///   the key is promoted to most-recently-used).
    /// - `Ok(None)` — miss, expired (the stale entry is removed → zeroized), or
    ///   the cache is disabled.
    /// - `Err(Poisoned)` — the lock was poisoned; caller must treat as a miss.
    ///
    /// Single map lookup: hit/expired/absent are decided in one borrow.
    pub fn get(&self, key: &[u8; 32]) -> Result<Option<Zeroizing<Vec<u8>>>, CacheError> {
        if !self.enabled() {
            return Ok(None);
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().map_err(|_| CacheError::Poisoned)?;

        enum Outcome {
            Absent,
            Expired,
            Fresh(Zeroizing<Vec<u8>>),
        }
        let outcome = match inner.map.get(key) {
            None => Outcome::Absent,
            Some(entry) if now.duration_since(entry.inserted) >= self.ttl => Outcome::Expired,
            Some(entry) => Outcome::Fresh(entry.dek.clone()),
        };

        match outcome {
            Outcome::Absent => Ok(None),
            Outcome::Expired => {
                // Drop the Entry → zeroizes the DEK.
                inner.map.remove(key);
                remove_from_order(&mut inner.order, key);
                Ok(None)
            }
            Outcome::Fresh(dek) => {
                remove_from_order(&mut inner.order, key);
                inner.order.push_back(*key);
                Ok(Some(dek))
            }
        }
    }

    /// Insert (or refresh) a DEK. `Ok(())` on success or when disabled (no-op);
    /// `Err(Poisoned)` if the lock was poisoned (caller ignores — caching is
    /// best-effort). Evicts the least-recently-used entry when the bound is
    /// exceeded (the evicted `Entry` is dropped → zeroized).
    pub fn put(&self, key: [u8; 32], dek: Zeroizing<Vec<u8>>) -> Result<(), CacheError> {
        if !self.enabled() {
            return Ok(());
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().map_err(|_| CacheError::Poisoned)?;

        if inner.map.contains_key(&key) {
            remove_from_order(&mut inner.order, &key);
        }
        inner.map.insert(key, Entry { dek, inserted: now });
        inner.order.push_back(key);

        // Evict LRU until within bound. Dropping each evicted Entry zeroizes it.
        while inner.map.len() > self.max {
            match inner.order.pop_front() {
                Some(oldest) => {
                    inner.map.remove(&oldest);
                }
                None => break,
            }
        }
        Ok(())
    }

    /// Drop every cached DEK immediately (each Entry's Drop zeroizes it).
    /// Best-effort emergency lever: on a poisoned lock we still recover and
    /// clear — clearing discards the (possibly desynced) map+order entirely,
    /// which is the goal, so reading corrupted state is not a concern here
    /// (unlike `get`/`put`).
    ///
    /// Not wired to a caller in v1 — a host-triggered `flush_dek_cache` vsock
    /// command is the planned follow-up (M-1 option B), deferred to avoid
    /// widening the host→enclave command surface without its own review.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn flush(&self) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.map.clear();
        inner.order.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        // Test helper: degrade to 0 on poison rather than panic.
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }
}

/// Remove a key from the LRU order deque. O(n) over `order`, but `n ≤ max`
/// (≤ 1024) and KMS gates every insert, so this can't be flooded.
fn remove_from_order(order: &mut VecDeque<[u8; 32]>, key: &[u8; 32]) {
    if let Some(pos) = order.iter().position(|k| k == key) {
        order.remove(pos);
    }
}

/// Derive the cache key from the wrapped DEK and the encryption context.
///
/// `SHA-256(len_le(wrapped_dek) ‖ wrapped_dek ‖ 0x1F ‖ for each sorted (k,v):
/// k ‖ 0x1E ‖ v ‖ 0x1D)`. The wrapped_dek is length-prefixed (collision
/// defense-in-depth); sorting makes the context order-independent (it's a
/// `HashMap`); the separators are domain separation so distinct (k,v) splits
/// can't collide. `None` context and an empty map hash the same — fine, because
/// the wrapped_dek bytes differ across customers regardless.
pub fn derive_key(wrapped_dek: &[u8], enc_ctx: Option<&HashMap<String, String>>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((wrapped_dek.len() as u64).to_le_bytes());
    hasher.update(wrapped_dek);
    hasher.update([0x1F]);
    if let Some(ctx) = enc_ctx {
        let mut kv: Vec<(&String, &String)> = ctx.iter().collect();
        kv.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in kv {
            hasher.update(k.as_bytes());
            hasher.update([0x1E]);
            hasher.update(v.as_bytes());
            hasher.update([0x1D]);
        }
    }
    hasher.finalize().into()
}

/// Process-wide singleton, configured from the environment at first use.
///
/// `SIGNER_DEK_CACHE_TTL_SECS` (default 60; `0` disables the cache).
/// `SIGNER_DEK_CACHE_MAX`      (default 256; clamped to `[1, 1024]`).
///
/// Read once via `OnceLock`: flipping the value means restarting the enclave,
/// which is the deploy unit anyway (a config change coincides with a fresh
/// PCR0 baseline). Same idiom as `handler::policy_required`. Touch this at boot
/// (see `init_at_startup`) so the enabled/disabled state is logged at startup.
pub fn global() -> &'static DekCache {
    static CACHE: OnceLock<DekCache> = OnceLock::new();
    CACHE.get_or_init(|| {
        let ttl = env_ttl();
        let max = env_max();
        if ttl.is_zero() {
            tracing::info!(
                event = "dek_cache_disabled",
                "DEK cache disabled (SIGNER_DEK_CACHE_TTL_SECS=0) — every sign hits KMS"
            );
        } else {
            tracing::warn!(
                event = "dek_cache_enabled",
                ttl_secs = ttl.as_secs(),
                max_entries = max,
                "DEK cache ACTIVE — a cached DEK survives KMS revocation for up to \
                 ttl_secs; to stop signing immediately, terminate the enclave \
                 (nitro-cli terminate-enclave), not KMS revoke alone"
            );
        }
        DekCache::new(ttl, max)
    })
}

/// Initialize + log the cache configuration at enclave startup (so the
/// enabled/disabled WARN fires at boot, not lazily on the first sign).
pub fn init_at_startup() {
    let _ = global();
}

fn env_ttl() -> Duration {
    let secs = std::env::var("SIGNER_DEK_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_SECS);
    Duration::from_secs(secs)
}

fn env_max() -> usize {
    std::env::var("SIGNER_DEK_CACHE_MAX")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_ENTRIES)
        .min(MAX_ENTRIES_CEILING)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek(byte: u8) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![byte; 32])
    }

    #[test]
    fn hit_returns_cached_dek() {
        let c = DekCache::new(Duration::from_secs(60), 8);
        let k = derive_key(b"wrapped-1", None);
        assert!(c.get(&k).unwrap().is_none(), "cold miss");
        c.put(k, dek(0xAB)).unwrap();
        let got = c.get(&k).unwrap().expect("warm hit");
        assert_eq!(&*got, &vec![0xAB; 32]);
    }

    #[test]
    fn miss_on_different_key() {
        let c = DekCache::new(Duration::from_secs(60), 8);
        c.put(derive_key(b"wrapped-1", None), dek(1)).unwrap();
        assert!(c.get(&derive_key(b"wrapped-2", None)).unwrap().is_none());
    }

    #[test]
    fn context_changes_key() {
        let mut ctx_a = HashMap::new();
        ctx_a.insert("customer_id".to_string(), "A".to_string());
        let mut ctx_b = HashMap::new();
        ctx_b.insert("customer_id".to_string(), "B".to_string());
        let ka = derive_key(b"same-wrapped", Some(&ctx_a));
        let kb = derive_key(b"same-wrapped", Some(&ctx_b));
        assert_ne!(ka, kb, "different context must not collide");
    }

    #[test]
    fn context_order_independent() {
        let mut ctx1 = HashMap::new();
        ctx1.insert("a".to_string(), "1".to_string());
        ctx1.insert("b".to_string(), "2".to_string());
        let mut ctx2 = HashMap::new();
        ctx2.insert("b".to_string(), "2".to_string());
        ctx2.insert("a".to_string(), "1".to_string());
        assert_eq!(
            derive_key(b"w", Some(&ctx1)),
            derive_key(b"w", Some(&ctx2)),
            "HashMap order must not change the key"
        );
    }

    #[test]
    fn length_prefix_disambiguates_wrapped_dek() {
        // Without a length prefix, ("AB", ctx "") could collide with ("A","B"…).
        // The length prefix makes the boundary explicit.
        let k1 = derive_key(b"AB", None);
        let k2 = derive_key(b"A", None);
        assert_ne!(k1, k2);
    }

    #[test]
    fn expiry_evicts_and_misses() {
        let c = DekCache::new(Duration::from_millis(20), 8);
        let k = derive_key(b"w", None);
        c.put(k, dek(7)).unwrap();
        assert!(c.get(&k).unwrap().is_some(), "fresh hit");
        std::thread::sleep(Duration::from_millis(40));
        assert!(c.get(&k).unwrap().is_none(), "expired miss");
        assert_eq!(c.len(), 0, "expired entry removed from map");
    }

    #[test]
    fn disabled_when_ttl_zero() {
        let c = DekCache::new(Duration::from_secs(0), 8);
        let k = derive_key(b"w", None);
        c.put(k, dek(9)).unwrap();
        assert!(c.get(&k).unwrap().is_none(), "disabled cache never hits");
        assert_eq!(c.len(), 0, "disabled cache stores nothing");
    }

    #[test]
    fn lru_evicts_oldest_over_bound() {
        let c = DekCache::new(Duration::from_secs(60), 2);
        let k1 = derive_key(b"w1", None);
        let k2 = derive_key(b"w2", None);
        let k3 = derive_key(b"w3", None);
        c.put(k1, dek(1)).unwrap();
        c.put(k2, dek(2)).unwrap();
        // Touch k1 so k2 is now LRU.
        assert!(c.get(&k1).unwrap().is_some());
        c.put(k3, dek(3)).unwrap(); // exceeds bound → evict LRU (k2)
        assert!(c.get(&k1).unwrap().is_some(), "k1 retained (recently used)");
        assert!(c.get(&k3).unwrap().is_some(), "k3 retained (just inserted)");
        assert!(c.get(&k2).unwrap().is_none(), "k2 evicted as LRU");
        assert_eq!(c.len(), 2, "bound held");
    }

    #[test]
    fn flush_clears_all() {
        let c = DekCache::new(Duration::from_secs(60), 8);
        c.put(derive_key(b"w1", None), dek(1)).unwrap();
        c.put(derive_key(b"w2", None), dek(2)).unwrap();
        assert_eq!(c.len(), 2);
        c.flush();
        assert_eq!(c.len(), 0, "flush drops every entry");
    }

    #[test]
    fn put_refreshes_existing_key() {
        let c = DekCache::new(Duration::from_secs(60), 8);
        let k = derive_key(b"w", None);
        c.put(k, dek(1)).unwrap();
        c.put(k, dek(2)).unwrap();
        assert_eq!(c.len(), 1, "same key updates in place, no duplicate");
        assert_eq!(&*c.get(&k).unwrap().unwrap(), &vec![2u8; 32]);
    }

    #[test]
    fn max_clamped_to_ceiling() {
        let c = DekCache::new(Duration::from_secs(60), 1_000_000);
        assert_eq!(c.max, MAX_ENTRIES_CEILING, "max clamped to hard ceiling");
    }

    #[test]
    fn poisoned_lock_degrades_to_error_not_corruption() {
        use std::sync::Arc;
        let c = Arc::new(DekCache::new(Duration::from_secs(60), 8));
        let k = derive_key(b"w", None);
        c.put(k, dek(1)).unwrap();

        // Poison the mutex: panic while holding the lock (test profile unwinds;
        // release runs panic=abort so this can't happen in production).
        let c2 = Arc::clone(&c);
        let res = std::thread::spawn(move || {
            let _guard = c2.inner.lock().unwrap();
            panic!("intentional poison");
        })
        .join();
        assert!(res.is_err(), "spawned thread panicked as intended");

        // get/put now surface the poison instead of serving corrupted state.
        assert!(matches!(c.get(&k), Err(CacheError::Poisoned)));
        assert!(matches!(c.put(k, dek(2)), Err(CacheError::Poisoned)));
    }
}
