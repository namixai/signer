//! B3 (mainnet-gate checklist §B): gateway-side compensating controls.
//!
//! Two per-token limits, both TEMPORARY compensating controls until stateful
//! UPL (roadmap — deliberately NOT built into the enclave under deadline
//! pressure, CTO decision on §B.B3):
//!
//!  (б) **Daily order counter, fail-closed.** Bounds the CUMULATIVE number of
//!      order-placing signatures a single bearer token can obtain per UTC day.
//!      B2's `max_notional` bounds a single signature; this bounds the burst.
//!      Fail-closed means exactly what the checklist says: counter store
//!      unavailable (I/O error, corrupt state file) OR limit exhausted → DENY.
//!      The counter is persisted to disk so a gateway restart does not reset
//!      the day's spend (systemd restarts must not multiply the cap).
//!
//!      **What one increment buys, stated exactly (ROT-1 round-3).** This doc
//!      used to read "worst-case exposure = per-order cap × daily cap", which
//!      was true only where a request carries exactly one order. A Hyperliquid
//!      `order` action carries a BATCH — `orders[]` — and the counter charges
//!      the batch as ONE increment (see the `sign_hyperliquid_*_order` gate in
//!      `handlers.rs`), so the old arithmetic understated the burst by the
//!      batch length. The enclave now bounds a batch from the inside: sizes and
//!      notionals are summed PER ASSET against the same cap — EVERY entry
//!      counts, reduce-only included, because such an order still executes a
//!      trade at a requester-chosen price — and an action may carry at most
//!      `HL_MAX_ENTRIES_PER_ACTION` entries. So on the Hyperliquid routes one
//!      increment buys at most the sum of the per-asset caps the policy grants,
//!      not that figure multiplied by however many orders fit in a vsock frame.
//!
//!      Two things this does NOT say. `/hedge` still buys TWO legs per
//!      increment — its legs are bounded individually by the enclave per-order
//!      caps, exactly as the `/hedge` note above states, and nothing here
//!      changes that; size the cap accordingly. And cancels remain uncounted
//!      and carry no size, so the entry ceiling is their only bound.
//!
//!  (в) **Per-token rate limit** (requests/minute, fixed window). In-memory
//!      only: a restart forgives at most one 60-second window, operationally
//!      irrelevant (unlike the daily counter, which must survive restarts).
//!      Two modes:
//!        - BLANKET (`SIGNER_RATE_LIMIT_PER_MIN`): one bucket across the whole
//!          tenant sign tier, enforced by the `rate_limit_mw` middleware.
//!        - SPLIT (B3.1, `SIGNER_ORDERS_PER_MIN` + `SIGNER_CANCELS_PER_MIN`):
//!          separate order-placing and cancel buckets, enforced at the handler
//!          gates (`order_gate` / `cancel_gate`) using the SAME op
//!          classification as the daily counter (a class-blind middleware
//!          cannot tell an order from a cancel from a read). Reads are
//!          unthrottled in split mode (they create no exposure). Setting either
//!          split var switches to split mode; the blanket value is then
//!          rejected at boot (contradictory). Backward-compat: both split vars
//!          unset ⇒ blanket mode, so an existing blanket deploy is unaffected.
//!
//! Threat model framing (checklist §B rationale): the gateway env is a zero
//! barrier against an ON-BOX attacker — they can lift the caps by editing the
//! unit file. These limits are compensating controls against a REMOTE
//! attacker holding a leaked/stolen bearer token or driving a compromised
//! agent framework: the enclave's per-order caps bound each signature, these
//! bound count × rate, and the KMS/registry kill-switch bounds duration.
//!
//! What counts as an "order" for the daily counter (handler-level, body-aware
//! — a route-level middleware cannot see the HL `kind` or the
//! binance-request `op`):
//!   - `/sign/binance-order`, `/sign/okx-order` (structured order routes)
//!   - `/hedge` (ONE increment per request; its two legs are individually
//!     bounded by the enclave per-order caps — size the cap accordingly)
//!   - `POST /sign` with an order-`kind` (Hyperliquid order actions)
//!   - `/sign/binance-request` with `op == "order"`
//!
//! Deliberately NOT counted by the DAILY ORDER counter: cancels / cancel-all /
//! reads (exposure-REDUCING or read-only — exhausting the day's quota must
//! never lock an operator out of cleaning up open orders), `/sign-x402` (it has
//! its OWN cumulative spend cap — see H2 below — plus the mandatory enclave
//! per-signature cap), and opaque generic-`/sign` HMAC bodies
//! (bybit/kucoin/asterdex legacy flows; on the mainnet profile money-venue keys
//! are policy-capped, and CR051 already denies capped keys order-shaped generic
//! signing — the uncounted paths cannot place orders there).
//!
//! **H2 (CR096) — cumulative x402 spend cap.** A THIRD control, same shape as
//! the daily order counter but accumulating VALUE, not count: `/sign-x402`
//! charges each EIP-3009 transfer's `value` against a per-payer-key per-UTC-day
//! running sum (`SIGNER_X402_PERIOD_CAP` / `SIGNER_X402_SPEND_PATH`): fail-closed,
//! atomic-persisted, and attempt-counted before the signature. The enclave
//! already enforces a PER-SIGNATURE ceiling (`X402Policy.max_value`, CR050);
//! this bounds the SUM across many signatures — the aggregate the stateless
//! enclave cannot track — turning "mainnet x402 = fully denied" into a bounded
//! allow. Dormant rail (0 payers today) → shipped dark (`SIGNER_LIMITS_DRY_RUN`)
//! as pure hardening, NOT a live requirement; unset ⇒ off (default deny holds).
//!
//! **Residual (gateway-side, by design).** Like the daily counter, this is a
//! GATEWAY compensating control: an ON-BOX attacker can reset/fudge the
//! accumulator file (zero barrier — same threat framing as above). It bounds a
//! REMOTE attacker / compromised agent draining a payer key via many
//! sub-per-sig-cap transfers. The real fix — an enclave-STATEFUL spend ledger
//! (UPL) that survives a hostile gateway — stays roadmap; the interim exposure
//! is bounded by the in-enclave per-signature `max_value` (CR050) × the small
//! dormant-rail balance, and by the KMS/registry kill-switch on duration.
//! Scope OUT (CR096 WONTFIX): an x402 `to` allow-list — the recipient is
//! inherently dynamic. v1 applies ONE cap per payer key; per-token/chain-
//! granular caps are a follow-up if a live rail needs them.
//!
//! The counter increments BEFORE the signature is produced (attempt-counted,
//! fail-closed): a request that later fails in the enclave still burns quota.
//! Counting successes instead would let N parallel in-flight requests
//! overshoot the cap.
//!
//! Rollout (two-phase, dark → soak → enable): `SIGNER_LIMITS_DRY_RUN=1`
//! evaluates and LOGS every would-deny decision but allows the request —
//! deploy on the demo box first, watch `limits_dry_run_would_deny` events
//! for a soak window, then drop the flag. The strict/mainnet profile
//! (`SIGNER_REQUIRE_AUTH=1`) refuses to boot in dry-run mode or with either
//! limit unconfigured — a mainnet box cannot silently run without B3.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Env: daily order-placing signature cap per token (u64 > 0). Unset = daily
/// counter disabled (dev/demo default; the strict profile requires it).
pub const DAILY_CAP_ENV: &str = "SIGNER_DAILY_ORDER_CAP";
/// Env: state-file path for the daily counter. REQUIRED when the cap is set —
/// the operator states explicitly where counter state lives; we never guess a
/// writable directory for a security control.
pub const COUNTER_PATH_ENV: &str = "SIGNER_DAILY_COUNTER_PATH";
/// Env: per-token requests/minute across the tenant sign tier (u32 > 0).
/// Unset = rate limit disabled (dev/demo default; strict profile requires it).
/// This is the BLANKET bucket — used only when the B3.1 split buckets below are
/// BOTH unset (backward-compat). If either split bucket is set, the gateway
/// switches to SPLIT mode and this blanket value is ignored.
pub const RATE_LIMIT_ENV: &str = "SIGNER_RATE_LIMIT_PER_MIN";
/// B3.1 (GTM: separate order vs cancel throttles). Env: per-token
/// order-placing requests/minute (u32 > 0). Setting this (or CANCELS) switches
/// the gateway to SPLIT mode: the blanket middleware check is disabled and
/// order-placing handlers enforce THIS bucket (same op-classification as the
/// daily order counter). Unset AND `SIGNER_CANCELS_PER_MIN` unset = blanket
/// mode (fallback to `RATE_LIMIT_PER_MIN`), so an existing blanket deploy is
/// unaffected until both split vars are configured.
pub const ORDERS_PER_MIN_ENV: &str = "SIGNER_ORDERS_PER_MIN";
/// B3.1: per-token cancel-path requests/minute (u32 > 0). Split-mode cancel
/// bucket (cancels never create exposure, so operators often want a looser
/// cancel budget than orders — that separation is the whole point). See
/// `ORDERS_PER_MIN_ENV`.
pub const CANCELS_PER_MIN_ENV: &str = "SIGNER_CANCELS_PER_MIN";
/// H2 (CR096): per-payer-key per-UTC-day CUMULATIVE x402/EIP-3009 `value` cap
/// (u128 > 0, raw token units). The enclave enforces a PER-SIGNATURE ceiling
/// (`X402Policy.max_value`, CR050); this bounds the SUM across many signatures
/// a single payer key can obtain per day — the aggregate the stateless enclave
/// cannot track. Unset = disabled (the x402 rail is dormant; this is a default-
/// deny-backed hardening control, not a live requirement). Same fail-closed +
/// dry-run + atomic-persist + attempt-counted discipline as the daily counter.
pub const X402_PERIOD_CAP_ENV: &str = "SIGNER_X402_PERIOD_CAP";
/// Env: state-file path for the x402 spend accumulator. REQUIRED when the cap
/// is set — same rule as the daily counter (never guess a writable directory
/// for a security control).
pub const X402_SPEND_PATH_ENV: &str = "SIGNER_X402_SPEND_PATH";
/// Env: dark-phase observation mode — evaluate + log, never deny.
pub const DRY_RUN_ENV: &str = "SIGNER_LIMITS_DRY_RUN";
/// Env: the CR097 strict/mainnet profile flag (owned by auth.rs; read here to
/// couple "mainnet profile ⇒ B3 configured & enforcing" at boot).
const REQUIRE_AUTH_ENV: &str = "SIGNER_REQUIRE_AUTH";

const SECS_PER_DAY: u64 = 86_400;
const SECS_PER_MINUTE: u64 = 60;

/// Boot-time configuration error. Fail-loud at startup — a misconfigured
/// limit must never degrade to "no limit".
#[derive(Debug)]
pub enum LimitsConfigError {
    /// Env var set but not a positive integer.
    BadValue(&'static str, String),
    /// `SIGNER_DAILY_ORDER_CAP` set without `SIGNER_DAILY_COUNTER_PATH`.
    CounterPathRequired,
    /// `SIGNER_REQUIRE_AUTH=1` but a B3 limit is unset or dry-run is on —
    /// the strict/mainnet profile must run with B3 fully enforcing.
    StrictProfileRequiresLimits(String),
    /// B3.1: both the blanket `RATE_LIMIT_PER_MIN` AND a split bucket
    /// (`ORDERS_PER_MIN`/`CANCELS_PER_MIN`) are set. Split replaces blanket, so
    /// the two together are contradictory — fail loud rather than silently
    /// ignore the blanket value.
    BlanketAndSplitBothSet,
    /// H2: `SIGNER_X402_PERIOD_CAP` set without `SIGNER_X402_SPEND_PATH`.
    X402SpendPathRequired,
}

impl std::fmt::Display for LimitsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitsConfigError::BadValue(var, got) => {
                write!(f, "{var} must be a positive integer, got {got:?}")
            }
            LimitsConfigError::CounterPathRequired => write!(
                f,
                "{DAILY_CAP_ENV} is set but {COUNTER_PATH_ENV} is not — the daily \
                 counter is fail-closed and needs an explicit state-file path \
                 (e.g. /var/lib/signer-gateway/daily-counters.json)"
            ),
            LimitsConfigError::StrictProfileRequiresLimits(what) => write!(
                f,
                "{REQUIRE_AUTH_ENV}=1 (strict/mainnet profile) requires B3 limits \
                 fully enforcing: {what}"
            ),
            LimitsConfigError::BlanketAndSplitBothSet => write!(
                f,
                "both {RATE_LIMIT_ENV} and a split bucket ({ORDERS_PER_MIN_ENV}/\
                 {CANCELS_PER_MIN_ENV}) are set — split mode replaces the blanket \
                 rate limit; set one OR the other, not both"
            ),
            LimitsConfigError::X402SpendPathRequired => write!(
                f,
                "{X402_PERIOD_CAP_ENV} is set but {X402_SPEND_PATH_ENV} is not — the \
                 x402 spend accumulator is fail-closed and needs an explicit \
                 state-file path (e.g. /var/lib/signer-gateway/x402-spend.json)"
            ),
        }
    }
}

impl std::error::Error for LimitsConfigError {}

/// Outcome of a limit check. `Allow` includes dry-run "would deny" cases
/// (already logged inside). The deny variants carry everything the HTTP
/// layer needs to shape the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    Allow,
    /// Per-minute window exhausted → 429, retry next window.
    RateLimited {
        retry_after_secs: u64,
    },
    /// Daily order cap exhausted → 429, retry at next UTC midnight.
    DailyCapExhausted {
        retry_after_secs: u64,
    },
    /// H2: per-key cumulative x402 spend cap exhausted for the day → 429, retry
    /// at next UTC midnight. Same wire shape as `DailyCapExhausted` (reuses the
    /// `rate_limited` code + `Retry-After`, no new CR037 allow-list entry).
    X402CapExhausted {
        retry_after_secs: u64,
    },
    /// Counter store unreadable/unwritable → 500 (fail-closed deny; this is
    /// a server-side failure, not client throttling).
    CounterUnavailable,
}

/// Per-token fixed-window rate state: (window id, count in window).
type RateWindows = HashMap<[u8; 32], (u64, u32)>;

/// On-disk shape of the daily counter state. `day` = unix days since epoch
/// (UTC by construction); `counts` keyed by SHA-256(token) hex — the raw
/// bearer token never touches disk (same hashing discipline as
/// `auth::AuthState`).
#[derive(serde::Serialize, serde::Deserialize)]
struct DailyState {
    day: u64,
    counts: HashMap<String, u64>,
}

/// H2: on-disk shape of the x402 spend accumulator. `day` = unix days since
/// epoch (UTC, same forward-only rollover rule as `DailyState`); `spend` keyed
/// by SHA-256(scope) hex where scope = `customer_id/key_id` (the payer key) —
/// hashed on disk for uniformity with the token discipline. Value = cumulative
/// signed `value` for the day in raw token units (u128: comfortably holds any
/// USDC 6-decimal amount; oversized inputs are rejected before they reach here).
#[derive(serde::Serialize, serde::Deserialize)]
struct X402SpendState {
    day: u64,
    spend: HashMap<String, u128>,
}

pub struct Limits {
    daily_cap: Option<u64>,
    counter_path: Option<PathBuf>,
    rate_per_min: Option<u32>,
    /// B3.1 split buckets. When either is `Some`, the gateway is in SPLIT mode:
    /// the blanket `rate` bucket (via the middleware) is bypassed and these are
    /// enforced per class at the handler gates instead. Backward-compat: both
    /// `None` ⇒ blanket mode (`rate_per_min`).
    orders_per_min: Option<u32>,
    cancels_per_min: Option<u32>,
    dry_run: bool,
    /// Fixed-window rate state. Entries are one per configured token (the
    /// middleware runs AFTER bearer auth, so only valid tokens reach here) —
    /// bounded, no eviction needed. `rate` = blanket bucket; `orders_rate` /
    /// `cancels_rate` = the B3.1 split buckets (separate windows so an order
    /// burst can't consume the cancel budget and vice-versa).
    rate: Mutex<RateWindows>,
    orders_rate: Mutex<RateWindows>,
    cancels_rate: Mutex<RateWindows>,
    /// In-memory daily-counter state, written THROUGH to the counter file on
    /// every increment (Gemini #223 HIGH: no disk read + JSON parse per
    /// order). Within a process lifetime this cache is authoritative; the
    /// file exists to survive restarts. Consequence: a mid-day on-disk edit
    /// is not re-read until restart — acceptable, on-box tampering is outside
    /// this control's threat model anyway (gateway env = zero barrier).
    ///
    /// The mutex is DELIBERATELY held across the write-through fsync
    /// (Gemini #223 round-3): an increment must be ordered with its
    /// persistence or two racing orders could both persist "count = N+1".
    /// Yes, this serializes ALL order-placing requests behind one fsync
    /// (~1-5 ms) — bounded and intended: the sustainable ~200+/s is orders
    /// of magnitude above any sane `SIGNER_DAILY_ORDER_CAP`, the per-minute
    /// rate limit throttles earlier anyway, and the whole call already runs
    /// on the blocking pool (`order_gate`), so the async executor
    /// never blocks on it. Reads/cancels never touch this lock.
    daily_state: Mutex<Option<DailyState>>,
    /// H2: per-key per-day x402 spend cap (raw token units) + its state file.
    /// Both `None` ⇒ the x402 aggregate cap is off (dormant-rail default).
    x402_period_cap: Option<u128>,
    x402_spend_path: Option<PathBuf>,
    /// H2: in-memory x402 spend accumulator, write-through to disk on every
    /// charge (same discipline + lock semantics as `daily_state`: the mutex is
    /// held across the persist so two racing charges can't both under-persist).
    x402_spend_state: Mutex<Option<X402SpendState>>,
}

impl Limits {
    /// Both limits off — dev/test default (`AppState::new`).
    pub fn disabled() -> Self {
        Self {
            daily_cap: None,
            counter_path: None,
            rate_per_min: None,
            orders_per_min: None,
            cancels_per_min: None,
            dry_run: false,
            rate: Mutex::new(HashMap::new()),
            orders_rate: Mutex::new(HashMap::new()),
            cancels_rate: Mutex::new(HashMap::new()),
            daily_state: Mutex::new(None),
            x402_period_cap: None,
            x402_spend_path: None,
            x402_spend_state: Mutex::new(None),
        }
    }

    /// Rate limit only, no daily counter — for the middleware integration
    /// test in `main.rs` (fields are private to this module by design).
    #[cfg(test)]
    pub fn rate_only_for_tests(per_min: u32) -> Self {
        Self {
            rate_per_min: Some(per_min),
            ..Self::disabled()
        }
    }

    /// Parse configuration from the environment. Fail-loud on any
    /// inconsistency (see `LimitsConfigError`).
    pub fn from_env() -> Result<Self, LimitsConfigError> {
        let daily_cap = parse_positive_u64(DAILY_CAP_ENV)?;
        let rate_per_min = parse_positive_u32(RATE_LIMIT_ENV)?;
        let orders_per_min = parse_positive_u32(ORDERS_PER_MIN_ENV)?;
        let cancels_per_min = parse_positive_u32(CANCELS_PER_MIN_ENV)?;
        let counter_path = std::env::var(COUNTER_PATH_ENV)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let x402_period_cap = parse_positive_u128(X402_PERIOD_CAP_ENV)?;
        let x402_spend_path = std::env::var(X402_SPEND_PATH_ENV)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let dry_run = env_flag_enabled(DRY_RUN_ENV);

        if daily_cap.is_some() && counter_path.is_none() {
            return Err(LimitsConfigError::CounterPathRequired);
        }
        // H2: same fail-closed rule as the daily counter — a cap without an
        // explicit state-file path is a misconfig, not "no path = memory only".
        if x402_period_cap.is_some() && x402_spend_path.is_none() {
            return Err(LimitsConfigError::X402SpendPathRequired);
        }
        // B3.1: SPLIT mode iff either split bucket is set. In split mode the
        // blanket `rate_per_min` is ignored (the split buckets replace it) — a
        // stale blanket value left alongside the split vars is a likely
        // misconfig, so fail loud rather than silently ignore it.
        let split_mode = orders_per_min.is_some() || cancels_per_min.is_some();
        if split_mode && rate_per_min.is_some() {
            return Err(LimitsConfigError::BlanketAndSplitBothSet);
        }
        // A "rate control" is present iff blanket OR a full split (both buckets)
        // is configured. A PARTIAL split (only orders, or only cancels) leaves
        // the other class unlimited — allowed for dev, but not a complete rate
        // control for the strict profile check below.
        let full_rate_control =
            rate_per_min.is_some() || (orders_per_min.is_some() && cancels_per_min.is_some());
        // CR097 strict/mainnet profile ⇒ B3 present and ENFORCING. A mainnet
        // box must not boot with the compensating controls missing or in
        // observation mode.
        if env_flag_enabled(REQUIRE_AUTH_ENV) {
            let mut missing: Vec<&str> = Vec::new();
            if daily_cap.is_none() {
                missing.push(DAILY_CAP_ENV);
            }
            if !full_rate_control {
                missing.push("a rate control (SIGNER_RATE_LIMIT_PER_MIN, or BOTH SIGNER_ORDERS_PER_MIN + SIGNER_CANCELS_PER_MIN)");
            }
            if dry_run {
                missing.push("SIGNER_LIMITS_DRY_RUN must be unset");
            }
            if !missing.is_empty() {
                return Err(LimitsConfigError::StrictProfileRequiresLimits(
                    missing.join(", "),
                ));
            }
        }

        tracing::info!(
            event = "limits_config",
            daily_order_cap = ?daily_cap,
            rate_limit_per_min = ?rate_per_min,
            orders_per_min = ?orders_per_min,
            cancels_per_min = ?cancels_per_min,
            rate_mode = if split_mode { "split" } else { "blanket" },
            dry_run = dry_run,
            counter_path = ?counter_path,
            x402_period_cap = ?x402_period_cap,
            x402_spend_path = ?x402_spend_path,
            "B3 gateway limits loaded"
        );
        Ok(Self {
            daily_cap,
            counter_path,
            rate_per_min,
            orders_per_min,
            cancels_per_min,
            dry_run,
            rate: Mutex::new(HashMap::new()),
            orders_rate: Mutex::new(HashMap::new()),
            cancels_rate: Mutex::new(HashMap::new()),
            daily_state: Mutex::new(None),
            x402_period_cap,
            x402_spend_path,
            x402_spend_state: Mutex::new(None),
        })
    }

    /// True iff the daily counter is configured — handlers use it to skip the
    /// `spawn_blocking` hop entirely when the limit is off.
    pub fn daily_enabled(&self) -> bool {
        self.daily_cap.is_some()
    }

    /// Boot-time probe: when the daily cap is enabled, load-or-init the
    /// counter file, write it back once (an unwritable path fails the BOOT
    /// loudly instead of denying every order at runtime) and prime the
    /// in-memory cache so even the first request skips the disk read.
    pub fn boot_probe(&self) -> std::io::Result<()> {
        if let (Some(_), Some(path)) = (self.daily_cap, self.counter_path.as_deref()) {
            let mut guard = self.daily_state.lock().expect("daily_state mutex poisoned");
            let state = load_daily_state(path, today(now_unix_secs()))?;
            store_daily_state(path, &state)?;
            *guard = Some(state);
        }
        // H2: same load-or-init-and-write-back so an unwritable x402 spend path
        // fails the BOOT loudly instead of denying every x402 sign at runtime.
        if let (Some(_), Some(path)) = (self.x402_period_cap, self.x402_spend_path.as_deref()) {
            let mut guard = self
                .x402_spend_state
                .lock()
                .expect("x402_spend_state mutex poisoned");
            let state = load_x402_spend_state(path, today(now_unix_secs()))?;
            store_x402_spend_state(path, &state)?;
            *guard = Some(state);
        }
        Ok(())
    }

    /// True iff the x402 spend cap is configured — the handler uses it to skip
    /// the `spawn_blocking` hop entirely when the cap is off.
    pub fn x402_spend_enabled(&self) -> bool {
        self.x402_period_cap.is_some()
    }

    /// B3.1: SPLIT mode iff either split bucket is configured. In split mode the
    /// blanket middleware check is bypassed and order/cancel handlers enforce
    /// `orders_per_min` / `cancels_per_min` per class instead.
    pub fn split_mode(&self) -> bool {
        self.orders_per_min.is_some() || self.cancels_per_min.is_some()
    }

    /// True iff the blanket middleware rate check should run: a blanket cap is
    /// configured AND we're NOT in split mode. (`from_env` rejects both being
    /// set, so this is just `rate_per_min.is_some()` in practice, but the
    /// explicit `!split_mode()` documents the intent.)
    pub fn blanket_rate_active(&self) -> bool {
        self.rate_per_min.is_some() && !self.split_mode()
    }

    /// Shared fixed-window per-token bucket check. `cap` None ⇒ Allow (bucket
    /// disabled). Increments on allow. `limit_label` names the bucket in the
    /// throttle log so operators see WHICH budget was hit.
    fn check_bucket(
        &self,
        cap: Option<u32>,
        map: &Mutex<RateWindows>,
        token: &str,
        now_secs: u64,
        limit_label: &'static str,
    ) -> LimitDecision {
        let Some(cap) = cap else {
            return LimitDecision::Allow;
        };
        // A zero clock (SystemTime before UNIX_EPOCH — broken RTC) would put
        // every request in window 0; deny rather than guess (fail-closed, and
        // a box with a broken clock must not sign timestamped requests anyway).
        if now_secs == 0 {
            tracing::error!(
                event = "limits_clock_invalid",
                "system clock reads 0 — deny"
            );
            return if self.dry_run {
                LimitDecision::Allow
            } else {
                LimitDecision::CounterUnavailable
            };
        }
        let window = now_secs / SECS_PER_MINUTE;
        let retry_after_secs = SECS_PER_MINUTE - (now_secs % SECS_PER_MINUTE);
        let key = token_key(token);
        let mut guard = map.lock().expect("rate mutex poisoned");
        let entry = guard.entry(key).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= cap {
            drop(guard);
            // Log the token's SHA-256 (Gemini #223: per-token observability —
            // WHICH token is throttled, without exposing the raw secret; the
            // same hash the counter file and SIGNER_API_TOKENS ops use) + WHICH
            // bucket (B3.1: rate_per_min / orders_per_min / cancels_per_min).
            let token_sha256 = hex::encode(key);
            if self.dry_run {
                tracing::warn!(
                    event = "limits_dry_run_would_deny",
                    limit = limit_label,
                    cap = cap,
                    token_sha256 = %token_sha256,
                    "dry-run: request WOULD be rate-limited"
                );
                return LimitDecision::Allow;
            }
            tracing::warn!(
                event = "rate_limited",
                limit = limit_label,
                cap = cap,
                token_sha256 = %token_sha256,
                "per-token rate limit hit"
            );
            return LimitDecision::RateLimited { retry_after_secs };
        }
        entry.1 += 1;
        LimitDecision::Allow
    }

    /// (в) BLANKET per-token per-minute rate limit. Called by the middleware on
    /// EVERY tenant sign-tier request when `blanket_rate_active()` — i.e. the
    /// backward-compat path. In split mode the middleware skips this and the
    /// order/cancel handlers call `check_orders_rate` / `check_cancels_rate`.
    pub fn check_rate(&self, token: &str, now_secs: u64) -> LimitDecision {
        self.check_bucket(
            self.rate_per_min,
            &self.rate,
            token,
            now_secs,
            "rate_per_min",
        )
    }

    /// B3.1: order-placing per-token per-minute bucket. Called by order handlers
    /// (same op-classification as the daily order counter). No-op when
    /// `orders_per_min` is unset (blanket mode, or split with only cancels set).
    pub fn check_orders_rate(&self, token: &str, now_secs: u64) -> LimitDecision {
        self.check_bucket(
            self.orders_per_min,
            &self.orders_rate,
            token,
            now_secs,
            "orders_per_min",
        )
    }

    /// B3.1: cancel-path per-token per-minute bucket. Called by cancel handlers.
    /// No-op when `cancels_per_min` is unset.
    pub fn check_cancels_rate(&self, token: &str, now_secs: u64) -> LimitDecision {
        self.check_bucket(
            self.cancels_per_min,
            &self.cancels_rate,
            token,
            now_secs,
            "cancels_per_min",
        )
    }

    /// (б) Daily order counter: check + increment, fail-closed. Called by the
    /// order-placing handlers BEFORE the signing round-trip. One increment =
    /// one order-placing request (a `/hedge` request increments once; its two
    /// legs are each bounded by the enclave per-order caps).
    pub fn check_and_count_order(&self, token: &str, now_secs: u64) -> LimitDecision {
        let (Some(cap), Some(path)) = (self.daily_cap, self.counter_path.as_deref()) else {
            return LimitDecision::Allow;
        };
        // Broken clock (see check_rate): day 0 would mismatch the stored day
        // and RESET the counts on every call — a fail-OPEN path. Deny instead.
        if now_secs == 0 {
            tracing::error!(
                event = "limits_clock_invalid",
                "system clock reads 0 — deny"
            );
            return if self.dry_run {
                LimitDecision::Allow
            } else {
                LimitDecision::CounterUnavailable
            };
        }
        let day = today(now_secs);
        let retry_after_secs = SECS_PER_DAY - (now_secs % SECS_PER_DAY);
        let key_hex = hex::encode(token_key(token));

        let mut guard = self.daily_state.lock().expect("daily_state mutex poisoned");
        // Resolve today's state: the in-process cache when it matches, a UTC
        // rollover resets in place, and a cache from a FUTURE day means the
        // clock went backwards mid-process — deny, never re-zero (Gemini #223
        // CRITICAL: a backwards clock must not refill quota). Cache miss
        // (first call after boot without probe) loads from disk, where
        // `load_daily_state` applies the same forward-only day rule.
        let mut state = match guard.take() {
            Some(s) if s.day == day => s,
            Some(s) if s.day < day => DailyState {
                day,
                counts: HashMap::new(),
            },
            Some(s) => {
                // s.day > day — clock rollback.
                tracing::error!(
                    event = "limits_clock_invalid",
                    cached_day = s.day,
                    now_day = day,
                    "system clock moved backwards across a day boundary — deny"
                );
                *guard = Some(s);
                return if self.dry_run {
                    LimitDecision::Allow
                } else {
                    LimitDecision::CounterUnavailable
                };
            }
            None => match load_daily_state(path, day) {
                Ok(s) => s,
                Err(e) => return self.counter_error("load", path, &e),
            },
        };
        let count = state.counts.entry(key_hex.clone()).or_insert(0);
        if *count >= cap {
            // token_sha256 = the same hash the counter file stores (Gemini
            // #223: operators see WHICH token exhausted the cap, no secrets).
            if self.dry_run {
                tracing::warn!(
                    event = "limits_dry_run_would_deny",
                    limit = "daily_order_cap",
                    cap = cap,
                    count = *count,
                    token_sha256 = %key_hex,
                    "dry-run: order WOULD be denied (daily cap exhausted)"
                );
                // Keep counting in dry-run so the soak shows the real curve.
            } else {
                tracing::warn!(
                    event = "daily_cap_exhausted",
                    cap = cap,
                    count = *count,
                    token_sha256 = %key_hex,
                    "daily order cap exhausted for token"
                );
                *guard = Some(state);
                return LimitDecision::DailyCapExhausted { retry_after_secs };
            }
        }
        *count += 1;
        // Write-through BEFORE releasing the deny/allow decision. On store
        // failure the incremented state STAYS cached (conservative: the
        // attempt burned quota) and the request is denied fail-closed.
        let store_result = store_daily_state(path, &state);
        *guard = Some(state);
        if let Err(e) = store_result {
            return self.counter_error("store", path, &e);
        }
        LimitDecision::Allow
    }

    /// H2: charge `value` against `key`'s x402 spend for the current UTC day and
    /// decide. Mirrors `check_and_count_order` but ACCUMULATES a value sum (not
    /// a +1 count). Attempt-counted: the charge is persisted BEFORE the enclave
    /// signs, so a concurrent/retried request cannot push the day's sum past the
    /// cap. `key` is the SHA-256(scope) hex identifying the payer key.
    pub fn check_and_count_x402_spend(
        &self,
        scope: &str,
        value: u128,
        now_secs: u64,
    ) -> LimitDecision {
        let (Some(cap), Some(path)) = (self.x402_period_cap, self.x402_spend_path.as_deref())
        else {
            return LimitDecision::Allow;
        };
        // Hash the payer-key scope (customer_id/key_id) the same way tokens are
        // hashed — the on-disk accumulator + logs never carry the raw scope.
        let key_hex = hex::encode(token_key(scope));
        // Broken clock (day 0) would reset the day on every call — fail-OPEN. Deny.
        if now_secs == 0 {
            tracing::error!(
                event = "limits_clock_invalid",
                "system clock reads 0 — deny"
            );
            return if self.dry_run {
                LimitDecision::Allow
            } else {
                LimitDecision::CounterUnavailable
            };
        }
        let day = today(now_secs);
        let retry_after_secs = SECS_PER_DAY - (now_secs % SECS_PER_DAY);

        let mut guard = self
            .x402_spend_state
            .lock()
            .expect("x402_spend_state mutex poisoned");
        // Same forward-only day resolution as the daily counter: cache hit /
        // UTC rollover reset / FUTURE-day clock-rollback deny / disk load.
        let mut state = match guard.take() {
            Some(s) if s.day == day => s,
            Some(s) if s.day < day => X402SpendState {
                day,
                spend: HashMap::new(),
            },
            Some(s) => {
                tracing::error!(
                    event = "limits_clock_invalid",
                    cached_day = s.day,
                    now_day = day,
                    "system clock moved backwards across a day boundary — deny"
                );
                *guard = Some(s);
                return if self.dry_run {
                    LimitDecision::Allow
                } else {
                    LimitDecision::CounterUnavailable
                };
            }
            None => match load_x402_spend_state(path, day) {
                Ok(s) => s,
                Err(e) => return self.x402_spend_error("x402_load", path, &e),
            },
        };
        let current = *state.spend.get(&key_hex).unwrap_or(&0);
        // Overflow guard: never wrap. A value that would overflow the u128 sum
        // is adversarial (real token units never approach u128::MAX) → fail-closed.
        let Some(new_total) = current.checked_add(value) else {
            tracing::error!(
                event = "x402_spend_overflow",
                key_sha256 = %key_hex,
                "x402 spend sum would overflow u128 — deny"
            );
            *guard = Some(state);
            return if self.dry_run {
                LimitDecision::Allow
            } else {
                LimitDecision::CounterUnavailable
            };
        };
        if new_total > cap {
            if self.dry_run {
                tracing::warn!(
                    event = "limits_dry_run_would_deny",
                    limit = "x402_period_cap",
                    cap = %cap,
                    current = %current,
                    value = %value,
                    would_total = %new_total,
                    key_sha256 = %key_hex,
                    "dry-run: x402 sign WOULD be denied (period spend cap exceeded)"
                );
                // Fall through and STILL charge, so the soak shows the real curve.
            } else {
                tracing::warn!(
                    event = "x402_period_cap_exhausted",
                    cap = %cap,
                    current = %current,
                    value = %value,
                    key_sha256 = %key_hex,
                    "x402 period spend cap exhausted for payer key"
                );
                // Deny WITHOUT charging — the transfer is rejected, no spend.
                *guard = Some(state);
                return LimitDecision::X402CapExhausted { retry_after_secs };
            }
        }
        // Charge the spend and write-through BEFORE releasing the decision. On
        // store failure the charged state STAYS cached (conservative: the
        // attempt burned quota) and the request is denied fail-closed.
        state.spend.insert(key_hex, new_total);
        let store_result = store_x402_spend_state(path, &state);
        *guard = Some(state);
        if let Err(e) = store_result {
            return self.x402_spend_error("x402_store", path, &e);
        }
        LimitDecision::Allow
    }

    /// Counter-store failure → fail-closed deny (enforce) / loud pass (dry-run).
    fn counter_error(&self, op: &str, path: &Path, e: &std::io::Error) -> LimitDecision {
        tracing::error!(
            event = "daily_counter_error",
            op = op,
            path = %path.display(),
            error = %e,
            "daily counter store failed — fail-closed (orders denied until fixed)"
        );
        if self.dry_run {
            LimitDecision::Allow
        } else {
            LimitDecision::CounterUnavailable
        }
    }

    /// H2: x402 spend-state load/store failure → fail-closed deny (enforce) /
    /// loud pass (dry-run). Same shape as `counter_error` but with x402-specific
    /// logging (it is transfers, not orders, that get denied — Gemini).
    fn x402_spend_error(&self, op: &str, path: &Path, e: &std::io::Error) -> LimitDecision {
        tracing::error!(
            event = "x402_spend_error",
            op = op,
            path = %path.display(),
            error = %e,
            "x402 spend state persistence failed — fail-closed (transfers denied until fixed)"
        );
        if self.dry_run {
            LimitDecision::Allow
        } else {
            LimitDecision::CounterUnavailable
        }
    }
}

/// Wire code for a deny decision (for `finish_log` outcome accounting).
/// Both throttle variants report `rate_limited`; a counter-store failure is
/// `internal_error`. `Allow` has no code — callers only ask after a deny.
pub fn deny_code(decision: LimitDecision) -> &'static str {
    match decision {
        LimitDecision::Allow => unreachable!("deny_code called on Allow"),
        LimitDecision::RateLimited { .. }
        | LimitDecision::DailyCapExhausted { .. }
        | LimitDecision::X402CapExhausted { .. } => crate::proto::err_code::RATE_LIMITED,
        LimitDecision::CounterUnavailable => crate::proto::err_code::INTERNAL_ERROR,
    }
}

/// Shape a deny decision into the wire response. Both throttle variants ride
/// the existing allow-listed `rate_limited` code (429) — the `Retry-After`
/// header distinguishes "next minute" from "next UTC day" for well-behaved
/// clients without adding a new wire code (CR037 allow-list stays untouched).
/// A counter-store failure is `internal_error` (500): server-side fail-closed,
/// not client throttling. Returns `None` for `Allow`.
pub fn deny_response(decision: LimitDecision) -> Option<axum::response::Response> {
    use axum::response::IntoResponse;
    let (code, retry_after) = match decision {
        LimitDecision::Allow => return None,
        LimitDecision::RateLimited { retry_after_secs }
        | LimitDecision::DailyCapExhausted { retry_after_secs }
        | LimitDecision::X402CapExhausted { retry_after_secs } => {
            (crate::proto::err_code::RATE_LIMITED, Some(retry_after_secs))
        }
        LimitDecision::CounterUnavailable => (crate::proto::err_code::INTERNAL_ERROR, None),
    };
    let status = axum::http::StatusCode::from_u16(crate::proto::http_status_for(code))
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::Json(crate::proto::ErrorResponse::new(code));
    let mut resp = (status, body).into_response();
    if let Some(secs) = retry_after {
        if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
    }
    Some(resp)
}

/// Axum middleware for (в): per-token rate limit over the whole tenant sign
/// tier. Layered INSIDE `require_bearer` (registered earlier in the builder
/// chain → inner), so `RawToken` is always present and only authenticated
/// requests spend limiter state. In no-auth dev mode the token is empty —
/// all traffic shares one bucket, which is fine for a dev box.
pub async fn rate_limit_mw(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // B3.1: the blanket bucket runs here ONLY in blanket mode. In split mode the
    // per-class buckets are enforced at the order/cancel handler gates (this
    // middleware is class-blind — it cannot tell an order from a cancel from a
    // read), so it passes through and reads stay unthrottled by design (reads
    // create no exposure; orders/cancels carry the split budgets).
    if !state.limits.blanket_rate_active() {
        return next.run(req).await;
    }
    let token = req
        .extensions()
        .get::<crate::auth::RawToken>()
        .map(|t| t.0.clone())
        .unwrap_or_default();
    let decision = state.limits.check_rate(&token, now_unix_secs());
    if let Some(resp) = deny_response(decision) {
        return resp;
    }
    next.run(req).await
}

/// SHA-256 of the bearer token — the only form a token takes in limiter
/// memory or on disk (mirrors `auth::AuthState` hashing).
fn token_key(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

/// Unix days since epoch — a UTC day boundary by construction (no tz math).
fn today(now_secs: u64) -> u64 {
    now_secs / SECS_PER_DAY
}

pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load the counter state. Day handling is FORWARD-ONLY (Gemini + CodeRabbit
/// #223): counts reset only when the stored day is OLDER than today (a normal
/// UTC rollover); a stored day in the FUTURE means the system clock moved
/// backwards after the file was written — surfacing it as `InvalidData` makes
/// `check_and_count_order` deny fail-closed instead of refilling the quota.
/// A missing file initializes empty (first boot); ANY read/parse error is
/// surfaced to the caller — a corrupt state file is an operator-intervention
/// signal, never a silent reset (silently resetting would let "corrupt the
/// file" become "refill the quota").
fn load_daily_state(path: &Path, day: u64) -> std::io::Result<DailyState> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DailyState {
                day,
                counts: HashMap::new(),
            })
        }
        Err(e) => return Err(e),
    };
    let mut state: DailyState = serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    match state.day.cmp(&day) {
        std::cmp::Ordering::Less => {
            state = DailyState {
                day,
                counts: HashMap::new(),
            };
        }
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Greater => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "counter file day {} is in the future (today {}) — clock rollback?",
                    state.day, day
                ),
            ));
        }
    }
    Ok(state)
}

/// Atomic write: temp file in the same directory + fsync + rename + parent-
/// directory fsync, so a crash mid-write never leaves a truncated JSON and
/// the rename itself is durable (file fsync alone persists contents, not the
/// directory entry — CodeRabbit #223). The temp name APPENDS `.tmp` to the
/// full filename instead of `Path::with_extension` (which would REPLACE an
/// existing extension: a configured `daily-counters.tmp` would make tmp ==
/// target and truncate it in place, breaking the atomicity — Gemini #223).
fn store_daily_state(path: &Path, state: &DailyState) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    atomic_write_bytes(path, &bytes)
}

/// Shared atomic write for the fail-closed state files: temp file in the same
/// directory + fsync + rename + parent-directory fsync, so a crash mid-write
/// never leaves a truncated JSON and the rename itself is durable (file fsync
/// alone persists contents, not the directory entry — CodeRabbit #223). The
/// temp name APPENDS `.tmp` to the full filename instead of
/// `Path::with_extension` (which would REPLACE an existing extension: a
/// configured `x.tmp` would make tmp == target and truncate it in place,
/// breaking the atomicity — Gemini #223). Used by BOTH the daily counter and
/// the H2 x402 spend accumulator.
fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    let write_then_rename = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = write_then_rename {
        // Best-effort cleanup of the temp file (Gemini #223 round-3). The
        // FIXED temp name already bounds any residue to a single stale file
        // (the next successful store truncates it) — this just avoids leaving
        // even that one behind on a failed write/sync/rename.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Parent-dir fsync is BEST-EFFORT (Gemini #223 round-2): it only makes
    // the rename itself crash-durable. Some environments (certain Docker
    // storage drivers / network filesystems) cannot open-or-sync a
    // directory — propagating that failure would hard-deny every request for
    // zero security gain: the tmp-file fsync above already guards the
    // fail-closed case (corrupt/truncated state), and a rename lost to a
    // host crash only means the post-crash restart resumes from the
    // previous write (a bounded under-count that a remote attacker cannot
    // trigger). Log loudly and continue. Unix-only (Gemini #223): opening a
    // directory ALWAYS fails on Windows — a per-request warning there would be
    // pure log pollution for a sync that platform cannot express anyway.
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
            tracing::warn!(
                event = "limits_state_dirsync_failed",
                path = %path.display(),
                error = %e,
                "parent-dir fsync failed — continuing (rename durability is best-effort)"
            );
        }
    }
    Ok(())
}

/// H2: load the x402 spend accumulator. Same FORWARD-ONLY day handling as
/// `load_daily_state` (older day = normal UTC rollover → reset; a FUTURE day =
/// clock rolled backwards after the file was written → `InvalidData` so the
/// caller denies fail-closed; missing file = empty; any parse error surfaces).
fn load_x402_spend_state(path: &Path, day: u64) -> std::io::Result<X402SpendState> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(X402SpendState {
                day,
                spend: HashMap::new(),
            })
        }
        Err(e) => return Err(e),
    };
    let mut state: X402SpendState = serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    match state.day.cmp(&day) {
        std::cmp::Ordering::Less => {
            state = X402SpendState {
                day,
                spend: HashMap::new(),
            };
        }
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Greater => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "x402 spend file day {} is in the future (today {}) — clock rollback?",
                    state.day, day
                ),
            ));
        }
    }
    Ok(state)
}

/// H2: atomic write for the x402 spend accumulator (mirrors `store_daily_state`).
fn store_x402_spend_state(path: &Path, state: &X402SpendState) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    atomic_write_bytes(path, &bytes)
}

/// True iff `var` is set to an explicit truthy value (`1`/`true`/`yes`,
/// case-insensitive). Mirrors `auth::env_flag_enabled` (private there).
fn env_flag_enabled(var: &str) -> bool {
    std::env::var(var)
        .map(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("1")
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

/// Parse an env var as a positive integer; unset/empty = None; zero or
/// garbage = config error (a zero cap means "deny everything" — if an
/// operator wants that, the kill-switch inventory is the right tool, not a
/// degenerate limit that reads like a typo).
fn parse_positive_u64(var: &'static str) -> Result<Option<u64>, LimitsConfigError> {
    let Ok(raw) = std::env::var(var) else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    match raw.parse::<u64>() {
        Ok(v) if v > 0 => Ok(Some(v)),
        _ => Err(LimitsConfigError::BadValue(var, raw.to_owned())),
    }
}

/// H2: parse an env var as a positive `u128` (the x402 spend cap — raw token
/// units, which can exceed `u64`). Same rules as `parse_positive_u64`.
fn parse_positive_u128(var: &'static str) -> Result<Option<u128>, LimitsConfigError> {
    let Ok(raw) = std::env::var(var) else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    match raw.parse::<u128>() {
        Ok(v) if v > 0 => Ok(Some(v)),
        _ => Err(LimitsConfigError::BadValue(var, raw.to_owned())),
    }
}

/// Parse an env var as a positive `u32` (rate buckets). Same rules as
/// `parse_positive_u64`; a value over `u32::MAX` is a `BadValue`, not a silent
/// wrap.
fn parse_positive_u32(var: &'static str) -> Result<Option<u32>, LimitsConfigError> {
    match parse_positive_u64(var)? {
        Some(v) if v > u32::MAX as u64 => Err(LimitsConfigError::BadValue(var, v.to_string())),
        Some(v) => Ok(Some(v as u32)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(daily: Option<u64>, path: Option<&Path>, rate: Option<u32>, dry: bool) -> Limits {
        Limits {
            daily_cap: daily,
            counter_path: path.map(|p| p.to_path_buf()),
            rate_per_min: rate,
            dry_run: dry,
            ..Limits::disabled()
        }
    }

    /// B3.1 split-mode test builder (orders/cancels buckets).
    fn split_limits(orders: Option<u32>, cancels: Option<u32>, dry: bool) -> Limits {
        Limits {
            orders_per_min: orders,
            cancels_per_min: cancels,
            dry_run: dry,
            ..Limits::disabled()
        }
    }

    /// H2 x402 spend-cap test builder.
    fn x402_limits(cap: Option<u128>, path: Option<&Path>, dry: bool) -> Limits {
        Limits {
            x402_period_cap: cap,
            x402_spend_path: path.map(|p| p.to_path_buf()),
            dry_run: dry,
            ..Limits::disabled()
        }
    }

    fn tmpfile(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("b3-limits-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    // ── (в) rate limit ──────────────────────────────────────────────────

    #[test]
    fn b3_rate_disabled_allows_everything() {
        let l = limits(None, None, None, false);
        for _ in 0..1000 {
            assert_eq!(l.check_rate("tok", 1_000_000), LimitDecision::Allow);
        }
    }

    #[test]
    fn b3_rate_caps_within_window_and_resets_on_next() {
        let l = limits(None, None, Some(3), false);
        let t0 = 1_200; // window 20, second 0
        for _ in 0..3 {
            assert_eq!(l.check_rate("tok", t0), LimitDecision::Allow);
        }
        assert_eq!(
            l.check_rate("tok", t0 + 30),
            LimitDecision::RateLimited {
                retry_after_secs: 30
            }
        );
        // Next fixed window → counter resets.
        assert_eq!(l.check_rate("tok", t0 + 60), LimitDecision::Allow);
    }

    #[test]
    fn b3_rate_windows_are_per_token() {
        let l = limits(None, None, Some(1), false);
        assert_eq!(l.check_rate("tok-a", 60), LimitDecision::Allow);
        assert!(matches!(
            l.check_rate("tok-a", 60),
            LimitDecision::RateLimited { .. }
        ));
        // A different token has its own window.
        assert_eq!(l.check_rate("tok-b", 60), LimitDecision::Allow);
    }

    #[test]
    fn b3_rate_dry_run_logs_but_allows() {
        let l = limits(None, None, Some(1), true);
        assert_eq!(l.check_rate("tok", 60), LimitDecision::Allow);
        assert_eq!(l.check_rate("tok", 60), LimitDecision::Allow); // would-deny → allow
    }

    // ── B3.1: orders/min + cancels/min split buckets ────────────────────

    #[test]
    fn b3_1_split_mode_and_blanket_active() {
        // Blanket only → blanket active, not split.
        let bl = limits(None, None, Some(5), false);
        assert!(!bl.split_mode());
        assert!(bl.blanket_rate_active());
        // Any split bucket set → split mode; blanket NOT active (bypassed).
        let sp = split_limits(Some(5), None, false);
        assert!(sp.split_mode());
        assert!(!sp.blanket_rate_active());
        // Nothing set → neither.
        let off = limits(None, None, None, false);
        assert!(!off.split_mode() && !off.blanket_rate_active());
    }

    #[test]
    fn b3_1_orders_bucket_caps_orders() {
        let l = split_limits(Some(2), Some(10), false);
        let t = 1_800; // window 30, sec 0
        assert_eq!(l.check_orders_rate("tok", t), LimitDecision::Allow);
        assert_eq!(l.check_orders_rate("tok", t), LimitDecision::Allow);
        assert_eq!(
            l.check_orders_rate("tok", t + 30),
            LimitDecision::RateLimited {
                retry_after_secs: 30
            }
        );
        // next window resets.
        assert_eq!(l.check_orders_rate("tok", t + 60), LimitDecision::Allow);
    }

    #[test]
    fn b3_1_order_burst_does_not_consume_cancel_budget() {
        // Separate windows: exhausting orders (cap 1) leaves cancels (cap 1) full.
        let l = split_limits(Some(1), Some(1), false);
        assert_eq!(l.check_orders_rate("tok", 60), LimitDecision::Allow);
        assert!(matches!(
            l.check_orders_rate("tok", 60),
            LimitDecision::RateLimited { .. }
        ));
        // cancels bucket for the SAME token is untouched.
        assert_eq!(l.check_cancels_rate("tok", 60), LimitDecision::Allow);
        assert!(matches!(
            l.check_cancels_rate("tok", 60),
            LimitDecision::RateLimited { .. }
        ));
    }

    #[test]
    fn b3_1_unset_bucket_is_noop() {
        // orders set, cancels unset → cancels unlimited, orders capped.
        let l = split_limits(Some(1), None, false);
        assert_eq!(l.check_orders_rate("tok", 60), LimitDecision::Allow);
        assert!(matches!(
            l.check_orders_rate("tok", 60),
            LimitDecision::RateLimited { .. }
        ));
        for _ in 0..100 {
            assert_eq!(l.check_cancels_rate("tok", 60), LimitDecision::Allow);
        }
    }

    #[test]
    fn b3_1_buckets_are_per_token() {
        let l = split_limits(Some(1), None, false);
        assert_eq!(l.check_orders_rate("a", 60), LimitDecision::Allow);
        assert!(matches!(
            l.check_orders_rate("a", 60),
            LimitDecision::RateLimited { .. }
        ));
        assert_eq!(l.check_orders_rate("b", 60), LimitDecision::Allow);
    }

    #[test]
    fn b3_1_split_dry_run_counts_not_denies() {
        let l = split_limits(Some(1), Some(1), true);
        assert_eq!(l.check_orders_rate("tok", 60), LimitDecision::Allow);
        assert_eq!(l.check_orders_rate("tok", 60), LimitDecision::Allow); // would-deny → allow
        assert_eq!(l.check_cancels_rate("tok", 60), LimitDecision::Allow);
        assert_eq!(l.check_cancels_rate("tok", 60), LimitDecision::Allow);
    }

    #[test]
    fn b3_1_blanket_check_rate_untouched_by_split_buckets() {
        // check_rate (blanket) uses the `rate` bucket only; orders/cancels
        // buckets are independent state. A split_limits instance has
        // rate_per_min=None → check_rate is a no-op (Allow).
        let l = split_limits(Some(1), Some(1), false);
        for _ in 0..50 {
            assert_eq!(l.check_rate("tok", 60), LimitDecision::Allow);
        }
    }

    // ── (б) daily counter ───────────────────────────────────────────────

    #[test]
    fn b3_daily_counts_persist_and_deny_at_cap() {
        let path = tmpfile("persist.json");
        let _ = std::fs::remove_file(&path);
        let now = 20_000 * SECS_PER_DAY + 100;
        {
            let l = limits(Some(2), Some(&path), None, false);
            assert_eq!(l.check_and_count_order("tok", now), LimitDecision::Allow);
            assert_eq!(l.check_and_count_order("tok", now), LimitDecision::Allow);
            assert_eq!(
                l.check_and_count_order("tok", now),
                LimitDecision::DailyCapExhausted {
                    retry_after_secs: SECS_PER_DAY - 100
                }
            );
        }
        // A NEW Limits (≈ gateway restart) reads the same file — the day's
        // spend survives, the cap stays exhausted.
        let l2 = limits(Some(2), Some(&path), None, false);
        assert!(matches!(
            l2.check_and_count_order("tok", now + 1),
            LimitDecision::DailyCapExhausted { .. }
        ));
    }

    #[test]
    fn b3_daily_resets_on_utc_day_rollover() {
        let path = tmpfile("rollover.json");
        let _ = std::fs::remove_file(&path);
        let day_n = 20_001 * SECS_PER_DAY;
        let l = limits(Some(1), Some(&path), None, false);
        assert_eq!(l.check_and_count_order("tok", day_n), LimitDecision::Allow);
        assert!(matches!(
            l.check_and_count_order("tok", day_n + 1),
            LimitDecision::DailyCapExhausted { .. }
        ));
        // Next UTC day → fresh quota.
        assert_eq!(
            l.check_and_count_order("tok", day_n + SECS_PER_DAY),
            LimitDecision::Allow
        );
    }

    #[test]
    fn b3_daily_counts_are_per_token_and_hashed_on_disk() {
        let path = tmpfile("hashed.json");
        let _ = std::fs::remove_file(&path);
        let now = 20_002 * SECS_PER_DAY;
        let l = limits(Some(1), Some(&path), None, false);
        assert_eq!(
            l.check_and_count_order("secret-token-a", now),
            LimitDecision::Allow
        );
        assert_eq!(
            l.check_and_count_order("secret-token-b", now),
            LimitDecision::Allow
        );
        assert!(matches!(
            l.check_and_count_order("secret-token-a", now),
            LimitDecision::DailyCapExhausted { .. }
        ));
        // The raw token never touches disk — only its SHA-256 hex.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("secret-token-a"),
            "raw token leaked to disk: {raw}"
        );
        assert!(raw.contains(&hex::encode(token_key("secret-token-a"))));
    }

    #[test]
    fn b3_daily_corrupt_state_file_is_fail_closed_deny() {
        let path = tmpfile("corrupt.json");
        std::fs::write(&path, b"{not json").unwrap();
        let l = limits(Some(5), Some(&path), None, false);
        // Corrupt file → deny (operator signal), NEVER silent-reset (that
        // would turn "corrupt the file" into "refill the quota").
        assert_eq!(
            l.check_and_count_order("tok", 20_003 * SECS_PER_DAY),
            LimitDecision::CounterUnavailable
        );
        // …and dry-run downgrades the same failure to allow + loud log.
        let l_dry = limits(Some(5), Some(&path), None, true);
        assert_eq!(
            l_dry.check_and_count_order("tok", 20_003 * SECS_PER_DAY),
            LimitDecision::Allow
        );
    }

    #[test]
    fn b3_daily_unwritable_path_is_fail_closed_deny() {
        // A directory that does not exist → store fails → deny.
        let path = PathBuf::from("/nonexistent-b3-dir/counters.json");
        let l = limits(Some(5), Some(&path), None, false);
        assert_eq!(
            l.check_and_count_order("tok", 20_004 * SECS_PER_DAY),
            LimitDecision::CounterUnavailable
        );
    }

    #[test]
    fn b3_daily_dry_run_would_deny_still_counts() {
        let path = tmpfile("dryrun.json");
        let _ = std::fs::remove_file(&path);
        let now = 20_005 * SECS_PER_DAY;
        let l = limits(Some(1), Some(&path), None, true);
        assert_eq!(l.check_and_count_order("tok", now), LimitDecision::Allow);
        // Over cap in dry-run: allowed, but the count keeps growing so the
        // soak logs show the true demand curve.
        assert_eq!(l.check_and_count_order("tok", now), LimitDecision::Allow);
        let raw = std::fs::read_to_string(&path).unwrap();
        let state: DailyState = serde_json::from_str(&raw).unwrap();
        assert_eq!(state.counts[&hex::encode(token_key("tok"))], 2);
    }

    #[test]
    fn b3_daily_future_dated_file_is_fail_closed() {
        // Gemini/CodeRabbit #223 CRITICAL: a counter file stamped with a
        // FUTURE day (clock rolled back after it was written) must DENY, not
        // silently reset — a backwards clock must never refill quota.
        let path = tmpfile("futureday.json");
        let day = 20_010u64;
        std::fs::write(
            &path,
            serde_json::to_vec(&DailyState {
                day: day + 1,
                counts: HashMap::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let l = limits(Some(5), Some(&path), None, false);
        assert_eq!(
            l.check_and_count_order("tok", day * SECS_PER_DAY + 10),
            LimitDecision::CounterUnavailable
        );
        // Same rule for the IN-PROCESS cache: count on day N+1, then roll the
        // clock back to day N — deny, and the cached counts survive.
        let path2 = tmpfile("futureday-cache.json");
        let _ = std::fs::remove_file(&path2);
        let l2 = limits(Some(5), Some(&path2), None, false);
        assert_eq!(
            l2.check_and_count_order("tok", (day + 1) * SECS_PER_DAY),
            LimitDecision::Allow
        );
        assert_eq!(
            l2.check_and_count_order("tok", day * SECS_PER_DAY),
            LimitDecision::CounterUnavailable
        );
        // Clock recovers → the cached day matches again, quota intact (1 of 5).
        assert_eq!(
            l2.check_and_count_order("tok", (day + 1) * SECS_PER_DAY + 5),
            LimitDecision::Allow
        );
    }

    #[test]
    fn b3_daily_tmp_suffixed_path_stays_atomic() {
        // Gemini #223: `with_extension("tmp")` on a path already ending in
        // `.tmp` made temp == target (in-place truncate). The temp name now
        // APPENDS `.tmp`, so a `daily-counters.tmp` target still round-trips.
        let path = tmpfile("counters.tmp");
        let _ = std::fs::remove_file(&path);
        let now = 20_011 * SECS_PER_DAY;
        let l = limits(Some(1), Some(&path), None, false);
        assert_eq!(l.check_and_count_order("tok", now), LimitDecision::Allow);
        // Restart-equivalent read proves the file persisted correctly.
        let l2 = limits(Some(1), Some(&path), None, false);
        assert!(matches!(
            l2.check_and_count_order("tok", now + 1),
            LimitDecision::DailyCapExhausted { .. }
        ));
    }

    #[test]
    fn b3_daily_cache_is_authoritative_within_process() {
        // Write-through cache (Gemini #223 perf): after the first call the
        // state lives in memory; corrupting the file mid-day does NOT affect
        // this process (no per-request re-read), but a RESTART reads the
        // corrupt file and fails closed.
        let path = tmpfile("cacheauth.json");
        let _ = std::fs::remove_file(&path);
        let now = 20_012 * SECS_PER_DAY;
        let l = limits(Some(2), Some(&path), None, false);
        assert_eq!(l.check_and_count_order("tok", now), LimitDecision::Allow);
        std::fs::write(&path, b"{corrupt").unwrap();
        // Cache hit → still served; the write-through repairs the file.
        assert_eq!(
            l.check_and_count_order("tok", now + 1),
            LimitDecision::Allow
        );
        assert!(matches!(
            l.check_and_count_order("tok", now + 2),
            LimitDecision::DailyCapExhausted { .. }
        ));
        // The write-through persisted the true count — a restart sees 2.
        let l2 = limits(Some(2), Some(&path), None, false);
        assert!(matches!(
            l2.check_and_count_order("tok", now + 3),
            LimitDecision::DailyCapExhausted { .. }
        ));
    }

    #[test]
    fn b3_zero_clock_is_fail_closed_not_counter_reset() {
        // SystemTime before UNIX_EPOCH → now_secs 0. Day 0 would mismatch the
        // stored day and silently RESET the counts every call (fail-open);
        // both limiters must deny instead.
        let path = tmpfile("zeroclock.json");
        let _ = std::fs::remove_file(&path);
        let l = limits(Some(1), Some(&path), Some(1), false);
        assert_eq!(
            l.check_and_count_order("tok", 0),
            LimitDecision::CounterUnavailable
        );
        assert_eq!(l.check_rate("tok", 0), LimitDecision::CounterUnavailable);
    }

    #[test]
    fn b3_boot_probe_fails_on_unwritable_path() {
        let l = limits(
            Some(5),
            Some(Path::new("/nonexistent-b3-dir/counters.json")),
            None,
            false,
        );
        assert!(l.boot_probe().is_err());
        // Disabled limits: probe is a no-op regardless of path.
        let l2 = limits(None, None, None, false);
        assert!(l2.boot_probe().is_ok());
    }

    // ── config parsing / strict-profile coupling ────────────────────────
    // Env-var tests mutate process env → serialize them under one lock
    // (mirrors the EnvVarGuard discipline in auth.rs).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard(Vec<(&'static str, Option<String>)>);
    impl EnvGuard {
        fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
            let saved = pairs
                .iter()
                .map(|(k, v)| {
                    let old = std::env::var(k).ok();
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                    (*k, old)
                })
                .collect();
            EnvGuard(saved)
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, old) in self.0.drain(..) {
                match old {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn b3_from_env_variants() {
        let _lock = ENV_LOCK.lock().unwrap();

        // All unset → both limits disabled.
        {
            let _g = EnvGuard::set(&[
                (DAILY_CAP_ENV, None),
                (COUNTER_PATH_ENV, None),
                (RATE_LIMIT_ENV, None),
                (DRY_RUN_ENV, None),
                (REQUIRE_AUTH_ENV, None),
            ]);
            let l = Limits::from_env().unwrap();
            assert!(l.daily_cap.is_none() && l.rate_per_min.is_none());
        }
        // Cap without a counter path → hard config error.
        {
            let _g = EnvGuard::set(&[
                (DAILY_CAP_ENV, Some("100")),
                (COUNTER_PATH_ENV, None),
                (RATE_LIMIT_ENV, None),
                (DRY_RUN_ENV, None),
                (REQUIRE_AUTH_ENV, None),
            ]);
            assert!(matches!(
                Limits::from_env(),
                Err(LimitsConfigError::CounterPathRequired)
            ));
        }
        // Zero / garbage values → hard config error, never "no limit".
        for bad in ["0", "-5", "lots", "1e3"] {
            let _g = EnvGuard::set(&[
                (DAILY_CAP_ENV, Some(bad)),
                (COUNTER_PATH_ENV, Some("/tmp/x.json")),
                (RATE_LIMIT_ENV, None),
                (DRY_RUN_ENV, None),
                (REQUIRE_AUTH_ENV, None),
            ]);
            assert!(
                matches!(Limits::from_env(), Err(LimitsConfigError::BadValue(..))),
                "value {bad:?} must be rejected"
            );
        }
        // Strict profile refuses: missing limits…
        {
            let _g = EnvGuard::set(&[
                (DAILY_CAP_ENV, None),
                (COUNTER_PATH_ENV, None),
                (RATE_LIMIT_ENV, None),
                (DRY_RUN_ENV, None),
                (REQUIRE_AUTH_ENV, Some("1")),
            ]);
            assert!(matches!(
                Limits::from_env(),
                Err(LimitsConfigError::StrictProfileRequiresLimits(_))
            ));
        }
        // …and dry-run under the strict profile.
        {
            let _g = EnvGuard::set(&[
                (DAILY_CAP_ENV, Some("100")),
                (COUNTER_PATH_ENV, Some("/tmp/x.json")),
                (RATE_LIMIT_ENV, Some("60")),
                (DRY_RUN_ENV, Some("1")),
                (REQUIRE_AUTH_ENV, Some("1")),
            ]);
            assert!(matches!(
                Limits::from_env(),
                Err(LimitsConfigError::StrictProfileRequiresLimits(_))
            ));
        }
        // Strict profile with everything configured → boots.
        {
            let _g = EnvGuard::set(&[
                (DAILY_CAP_ENV, Some("100")),
                (COUNTER_PATH_ENV, Some("/tmp/x.json")),
                (RATE_LIMIT_ENV, Some("60")),
                (DRY_RUN_ENV, None),
                (REQUIRE_AUTH_ENV, Some("1")),
            ]);
            let l = Limits::from_env().unwrap();
            assert_eq!(l.daily_cap, Some(100));
            assert_eq!(l.rate_per_min, Some(60));
            assert!(!l.dry_run);
        }
    }

    #[test]
    fn b3_1_from_env_split() {
        let _lock = ENV_LOCK.lock().unwrap();
        let base = |orders, cancels, blanket, req_auth| {
            EnvGuard::set(&[
                (DAILY_CAP_ENV, Some("100")),
                (COUNTER_PATH_ENV, Some("/tmp/x.json")),
                (RATE_LIMIT_ENV, blanket),
                (ORDERS_PER_MIN_ENV, orders),
                (CANCELS_PER_MIN_ENV, cancels),
                (DRY_RUN_ENV, None),
                (REQUIRE_AUTH_ENV, req_auth),
            ])
        };
        // Both split buckets → split mode, blanket bypassed.
        {
            let _g = base(Some("30"), Some("60"), None, None);
            let l = Limits::from_env().unwrap();
            assert!(l.split_mode() && !l.blanket_rate_active());
            assert_eq!(l.orders_per_min, Some(30));
            assert_eq!(l.cancels_per_min, Some(60));
        }
        // Blanket AND a split bucket both set → hard error.
        {
            let _g = base(Some("30"), None, Some("60"), None);
            assert!(matches!(
                Limits::from_env(),
                Err(LimitsConfigError::BlanketAndSplitBothSet)
            ));
        }
        // Strict profile + FULL split (both buckets) → boots (rate control present).
        {
            let _g = base(Some("30"), Some("60"), None, Some("1"));
            assert!(Limits::from_env().is_ok());
        }
        // Strict profile + PARTIAL split (only orders) → refuses (cancels unlimited
        // = not a full rate control).
        {
            let _g = base(Some("30"), None, None, Some("1"));
            assert!(matches!(
                Limits::from_env(),
                Err(LimitsConfigError::StrictProfileRequiresLimits(_))
            ));
        }
        // Bad split value → BadValue.
        {
            let _g = base(Some("0"), Some("60"), None, None);
            assert!(matches!(
                Limits::from_env(),
                Err(LimitsConfigError::BadValue(..))
            ));
        }
    }

    // ── H2: x402 cumulative per-key spend cap ───────────────────────────────
    const X402_DAY0: u64 = 20_000 * SECS_PER_DAY + 100;

    #[test]
    fn h2_x402_disabled_allows_any_spend() {
        let l = x402_limits(None, None, false);
        assert_eq!(
            l.check_and_count_x402_spend("cust/key", 10_u128.pow(30), X402_DAY0),
            LimitDecision::Allow
        );
    }

    #[test]
    fn h2_x402_accumulates_denies_over_cap_and_persists() {
        let path = tmpfile("x402-persist.json");
        let _ = std::fs::remove_file(&path);
        {
            let l = x402_limits(Some(100), Some(&path), false);
            // 40 + 40 = 80 ≤ 100 → allowed.
            assert_eq!(
                l.check_and_count_x402_spend("A", 40, X402_DAY0),
                LimitDecision::Allow
            );
            assert_eq!(
                l.check_and_count_x402_spend("A", 40, X402_DAY0),
                LimitDecision::Allow
            );
            // +40 would make 120 > 100 → denied (and NOT charged).
            assert!(matches!(
                l.check_and_count_x402_spend("A", 40, X402_DAY0),
                LimitDecision::X402CapExhausted { .. }
            ));
            // A charge that still fits (80 + 20 = 100) → allowed; now exactly at cap.
            assert_eq!(
                l.check_and_count_x402_spend("A", 20, X402_DAY0),
                LimitDecision::Allow
            );
            assert!(matches!(
                l.check_and_count_x402_spend("A", 1, X402_DAY0),
                LimitDecision::X402CapExhausted { .. }
            ));
        }
        // Restart-equivalent: a fresh Limits reads the file — the day's spend
        // (100) survives, the cap stays exhausted (systemd restart must not refill).
        let l2 = x402_limits(Some(100), Some(&path), false);
        assert!(matches!(
            l2.check_and_count_x402_spend("A", 1, X402_DAY0 + 1),
            LimitDecision::X402CapExhausted { .. }
        ));
    }

    #[test]
    fn h2_x402_per_key_isolation() {
        let path = tmpfile("x402-iso.json");
        let _ = std::fs::remove_file(&path);
        let l = x402_limits(Some(50), Some(&path), false);
        assert_eq!(
            l.check_and_count_x402_spend("A", 50, X402_DAY0),
            LimitDecision::Allow
        );
        assert!(matches!(
            l.check_and_count_x402_spend("A", 1, X402_DAY0),
            LimitDecision::X402CapExhausted { .. }
        ));
        // Key B has its own accumulator — A's exhaustion doesn't touch it.
        assert_eq!(
            l.check_and_count_x402_spend("B", 50, X402_DAY0),
            LimitDecision::Allow
        );
    }

    #[test]
    fn h2_x402_dry_run_allows_but_keeps_accumulating() {
        let path = tmpfile("x402-dry.json");
        let _ = std::fs::remove_file(&path);
        let l = x402_limits(Some(100), Some(&path), true); // dry-run
        assert_eq!(
            l.check_and_count_x402_spend("A", 80, X402_DAY0),
            LimitDecision::Allow
        );
        // 80 + 80 = 160 > 100, but dry-run ALLOWS (would-deny logged) and STILL charges.
        assert_eq!(
            l.check_and_count_x402_spend("A", 80, X402_DAY0),
            LimitDecision::Allow
        );
        // The soak accumulator reflects the real 160: a fresh ENFORCING Limits
        // reading the same file sees the key already over cap.
        let l2 = x402_limits(Some(100), Some(&path), false);
        assert!(matches!(
            l2.check_and_count_x402_spend("A", 1, X402_DAY0),
            LimitDecision::X402CapExhausted { .. }
        ));
    }

    #[test]
    fn h2_x402_utc_rollover_resets_spend() {
        let path = tmpfile("x402-rollover.json");
        let _ = std::fs::remove_file(&path);
        let l = x402_limits(Some(100), Some(&path), false);
        assert_eq!(
            l.check_and_count_x402_spend("A", 100, X402_DAY0),
            LimitDecision::Allow
        );
        assert!(matches!(
            l.check_and_count_x402_spend("A", 1, X402_DAY0),
            LimitDecision::X402CapExhausted { .. }
        ));
        // Next UTC day → fresh budget.
        assert_eq!(
            l.check_and_count_x402_spend("A", 100, X402_DAY0 + SECS_PER_DAY),
            LimitDecision::Allow
        );
    }

    #[test]
    fn h2_x402_clock_rollback_fails_closed() {
        let path = tmpfile("x402-rollback.json");
        let _ = std::fs::remove_file(&path);
        // A state file dated in the FUTURE = the clock moved backwards → deny,
        // never re-zero (a backwards clock must not refill quota).
        let future = X402SpendState {
            day: today(X402_DAY0) + 5,
            spend: HashMap::new(),
        };
        store_x402_spend_state(&path, &future).unwrap();
        let l = x402_limits(Some(100), Some(&path), false);
        assert_eq!(
            l.check_and_count_x402_spend("A", 1, X402_DAY0),
            LimitDecision::CounterUnavailable
        );
    }

    #[test]
    fn h2_x402_corrupt_state_denies_enforce_passes_dry_run() {
        let path = tmpfile("x402-corrupt.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        // Enforce: corrupt state → fail-closed deny (never a silent reset).
        let l = x402_limits(Some(100), Some(&path), false);
        assert_eq!(
            l.check_and_count_x402_spend("A", 1, X402_DAY0),
            LimitDecision::CounterUnavailable
        );
        // Dry-run: same corrupt state → loud pass, never blocks the soak.
        let ld = x402_limits(Some(100), Some(&path), true);
        assert_eq!(
            ld.check_and_count_x402_spend("A", 1, X402_DAY0),
            LimitDecision::Allow
        );
    }

    #[test]
    fn h2_x402_sum_overflow_fails_closed() {
        let path = tmpfile("x402-overflow.json");
        let _ = std::fs::remove_file(&path);
        // Cap = u128::MAX so the cap itself never denies — only the overflow guard.
        let l = x402_limits(Some(u128::MAX), Some(&path), false);
        assert_eq!(
            l.check_and_count_x402_spend("A", u128::MAX - 10, X402_DAY0),
            LimitDecision::Allow
        );
        // (MAX-10) + 20 overflows u128 → fail-closed deny, never wrap.
        assert_eq!(
            l.check_and_count_x402_spend("A", 20, X402_DAY0),
            LimitDecision::CounterUnavailable
        );
    }

    #[test]
    fn h2_x402_u128_value_roundtrips_through_persist() {
        let path = tmpfile("x402-u128.json");
        let _ = std::fs::remove_file(&path);
        // A value well beyond u64::MAX (~1.8e19) to prove the accumulator + JSON
        // persistence are truly u128 — a silent u64 truncation would corrupt this.
        let big: u128 = 1_000_000_000_000_000_000_000_000_000_000; // 1e30
        let cap: u128 = big + 5;
        {
            let l = x402_limits(Some(cap), Some(&path), false);
            assert_eq!(
                l.check_and_count_x402_spend("A", big, X402_DAY0),
                LimitDecision::Allow
            );
        }
        // Reload: current == big (survived the round-trip). +10 exceeds cap
        // (big+5) via the CAP path (no overflow); +5 exactly fills it.
        let l2 = x402_limits(Some(cap), Some(&path), false);
        assert!(matches!(
            l2.check_and_count_x402_spend("A", 10, X402_DAY0 + 1),
            LimitDecision::X402CapExhausted { .. }
        ));
        let l3 = x402_limits(Some(cap), Some(&path), false);
        assert_eq!(
            l3.check_and_count_x402_spend("A", 5, X402_DAY0 + 1),
            LimitDecision::Allow
        );
    }
}
