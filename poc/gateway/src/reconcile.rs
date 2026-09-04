//! Per-tenant automatic unwind — PR-2 of `docs/TENANT-KILL-SWITCH-DESIGN.md`.
//!
//! When a tenant enters CANCEL_ONLY or HALTED, this job walks every venue the
//! tenant has a staged blob for, lists the resting orders, cancels them,
//! re-lists, and writes a forensic bundle. It is the product-level port of
//! `reconcile()` from `scripts/box/auto-cycle.py`, which unwound real money on
//! 2026-08-19, and it keeps that script's three bought-dearly lessons:
//!
//! 1. **An unreadable book is an error, never an empty book.** "Could not look"
//!    must stay distinguishable from "clean" — `resting: None` vs `Some(0)`.
//! 2. **Cancel survives a rate limit.** A cancel that gives up on 429 leaves a
//!    REAL resting order; back off and retry instead (`cancel_one`, 4 attempts).
//! 3. **Raw venue responses are always recorded** — into the bundle, bounded.
//!
//! Who signs. The enclave resolves identity from the opaque tenant token
//! (registry.rs); there is no operator-signs-for-tenant identity by design. So
//! the job signs AS the tenant, with the tenant's own token read back from the
//! gateway's environment (`auth::raw_token_for_customer`) — the same box-level
//! secret the gateway authenticates with. The enclave sees ordinary tenant
//! cancels; cancels carry no daily-counter charge and no new exposure.
//!
//! Who executes. The venue is called BY THE GATEWAY (`hedge::venue_client`),
//! not by the client: during an unwind the client may be the compromised party.
//! This is the second place after `/hedge` where the gateway itself calls a
//! venue — deliberately.
//!
//! Rate limits. The job bypasses the HTTP-layer per-token bucket (it never goes
//! through the router) and is bounded by venue limits + the enclave's own
//! limiter; it runs one venue at a time, one cancel at a time, with backoff.
//! Throughput is therefore venue RTT, not our 20/min bucket (design §7).
//!
//! Termination. Between steps the job re-reads the tenant state: an operator
//! release to ACTIVE stops it (`Terminated`) — already-sent cancels stay sent,
//! nothing is "un-cancelled". Restart safety: the status is persisted in the
//! tenant record; `resume_all` at boot restarts any non-final job.
//!
//! Venues this version unwinds: `okx` (per-order cancel, server-side POST) and
//! `binance` (USD-M futures, cancel-all per symbol). Other stems are reported
//! `unsupported` and left to the operator — stated, never silently skipped.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::state::AppState;
use crate::tenant_state::{ReconcilePhase, TenantState, VenueReconcile};

pub const DEFAULT_INCIDENTS_DIR: &str = "/var/lib/signer/incidents";
pub const INCIDENTS_DIR_ENV: &str = "SIGNER_INCIDENTS_DIR";

/// Rounds of (list → cancel → re-list) before giving up as `Failed`.
const MAX_ROUNDS: u32 = 5;
/// Backoff between rounds: 5s, 10s, 20s, 40s (capped).
const ROUND_BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Per-cancel retry on a rate limit (auto-cycle lesson: 4 attempts, 20s × n).
const CANCEL_ATTEMPTS: u32 = 4;
const CANCEL_BACKOFF_BASE: Duration = Duration::from_secs(20);
/// Raw venue responses kept in the bundle are truncated to this many bytes.
const RAW_CAP: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenOrder {
    pub venue: String,
    pub symbol: String,
    pub order_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelOutcome {
    /// Venue acknowledged the cancel.
    Cancelled,
    /// Venue says the order is no longer there (already cancelled / filled) — not resting.
    Gone,
    /// Venue rejected or the call failed; the order may still rest.
    Failed(String),
}

/// One venue call as recorded in the bundle: what we asked, what came back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawExchange {
    pub venue: String,
    pub op: String,
    pub http_status: Option<u16>,
    /// Body, UTF-8 lossy, truncated to `RAW_CAP`.
    pub body: String,
}

/// How the orchestrator talks to venues. The production implementation signs
/// through the enclave and calls the venue; tests use an in-memory book.
/// `Result::Err` = the VENUE COULD NOT BE READ/ACTED ON (kept distinct from a
/// clean book — lesson 1).
pub trait VenueOps: Send + Sync {
    /// Stems (blob key_ids) this tenant has staged, e.g. `["binance", "okx"]`.
    fn venues(&self) -> Vec<String>;
    /// `None` if the venue is not unwindable by this version.
    fn supported(&self, venue: &str) -> bool;
    fn list_open(
        &self,
        venue: &str,
        raw: &mut Vec<RawExchange>,
    ) -> impl std::future::Future<Output = Result<Vec<OpenOrder>, String>> + Send;
    /// Cancel the given orders on one venue; one outcome per input order, same order.
    fn cancel(
        &self,
        venue: &str,
        orders: &[OpenOrder],
        raw: &mut Vec<RawExchange>,
    ) -> impl std::future::Future<Output = Vec<CancelOutcome>> + Send;
}

/// Sleep hook so tests don't wait real seconds.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
    fn sleep(&self, d: Duration) -> impl std::future::Future<Output = ()> + Send;
}

pub struct RealClock;
impl Clock for RealClock {
    fn now_unix(&self) -> u64 {
        crate::limits::now_unix_secs()
    }
    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await
    }
}

/// Forensic bundle written at the end of every job (design §6).
#[derive(Serialize, Deserialize)]
pub struct IncidentBundle {
    pub v: u32,
    pub customer: String,
    pub tenant_state: String,
    pub started_unix: u64,
    pub finished_unix: u64,
    pub phase: ReconcilePhase,
    pub rounds: u32,
    pub venues: BTreeMap<String, VenueReconcile>,
    /// First listing per venue — what was resting when the stop was pressed.
    pub before: BTreeMap<String, Vec<OpenOrder>>,
    /// Last listing per venue (absent = could not be read).
    pub after: BTreeMap<String, Vec<OpenOrder>>,
    pub raw: Vec<RawExchange>,
}

fn incidents_dir() -> PathBuf {
    std::env::var(INCIDENTS_DIR_ENV)
        .ok()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INCIDENTS_DIR))
}

fn create_private_dir(d: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(d)
    {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // `mode` applies only at creation: a directory that pre-dates this code
    // (or an upgrade) may sit at 0755. Tighten unconditionally — tenant order
    // data must never be world-readable (CodeRabbit).
    let meta = std::fs::metadata(d)?;
    if meta.permissions().mode() & 0o777 != 0o750 {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

fn write_bundle(dir: &std::path::Path, bundle: &IncidentBundle) -> std::io::Result<PathBuf> {
    let safe: String = bundle
        .customer
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let d = dir.join(safe);
    // Tenant order books + raw venue bodies: owner/group only (0750), never
    // world-readable. Retention is the unit's job (runbook: systemd-tmpfiles
    // age on the incidents dir), not the writer's (CodeRabbit).
    create_private_dir(&d)?;
    let path = d.join(format!("{}-reconcile.json", bundle.started_unix));
    let bytes = serde_json::to_vec_pretty(bundle)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    crate::limits::atomic_write_bytes(&path, &bytes)?;
    Ok(path)
}

/// Run one reconcile job to completion. Returns the final phase.
pub async fn run<O: VenueOps, C: Clock>(
    state: &AppState,
    customer: &str,
    ops: &O,
    clock: &C,
    incidents: &std::path::Path,
) -> ReconcilePhase {
    let started = clock.now_unix();
    let venues = ops.venues();
    let mut progress: BTreeMap<String, VenueReconcile> = BTreeMap::new();
    let mut before: BTreeMap<String, Vec<OpenOrder>> = BTreeMap::new();
    let mut after: BTreeMap<String, Vec<OpenOrder>> = BTreeMap::new();
    let mut raw: Vec<RawExchange> = Vec::new();
    let mut rounds = 0u32;

    for v in &venues {
        let mut pv = VenueReconcile::default();
        if !ops.supported(v) {
            pv.unsupported = true;
            pv.error = Some("venue not unwindable by this version — unwind by hand".to_owned());
        }
        progress.insert(v.clone(), pv);
    }
    state.tenants.update_reconcile(customer, |s| {
        s.phase = ReconcilePhase::Running;
        s.started_unix = started;
        s.venues = progress.clone();
    });
    info!(event = "tenant_reconcile_started", customer = %customer, venues = ?venues);

    let supported: Vec<String> = venues
        .iter()
        .filter(|v| ops.supported(v))
        .cloned()
        .collect();
    let mut phase = ReconcilePhase::Failed;

    'rounds: while rounds < MAX_ROUNDS {
        rounds += 1;
        // Operator release → stop here, keep what was already cancelled.
        if state.tenants.state_of(customer) == TenantState::Active {
            phase = ReconcilePhase::Terminated;
            break 'rounds;
        }
        let mut all_clean = true;
        for v in &supported {
            let listed = ops.list_open(v, &mut raw).await;
            let pv = progress.entry(v.clone()).or_default();
            match listed {
                Err(e) => {
                    pv.resting = None; // unknown ≠ clean
                    pv.error = Some(truncate(&e, 300));
                    all_clean = false;
                    warn!(event = "tenant_reconcile_list_failed", customer = %customer, venue = %v, error = %e);
                    continue;
                }
                Ok(orders) => {
                    if rounds == 1 {
                        pv.found = orders.len() as u32;
                        before.insert(v.clone(), orders.clone());
                    }
                    pv.resting = Some(orders.len() as u32);
                    pv.error = None;
                    after.insert(v.clone(), orders.clone());
                    if orders.is_empty() {
                        continue;
                    }
                    all_clean = false;
                    if state.tenants.state_of(customer) == TenantState::Active {
                        phase = ReconcilePhase::Terminated;
                        break 'rounds;
                    }
                    let outcomes = ops.cancel(v, &orders, &mut raw).await;
                    for (o, out) in orders.iter().zip(outcomes.iter()) {
                        match out {
                            CancelOutcome::Cancelled | CancelOutcome::Gone => pv.cancelled += 1,
                            CancelOutcome::Failed(e) => {
                                pv.error = Some(truncate(e, 300));
                                warn!(event = "tenant_reconcile_cancel_failed", customer = %customer, venue = %v, order_id = %o.order_id, error = %e);
                            }
                        }
                    }
                }
            }
        }
        state.tenants.update_reconcile(customer, |s| {
            s.rounds = rounds;
            s.venues = progress.clone();
        });
        if all_clean && rounds > 1 {
            // A round with nothing to cancel anywhere AFTER cancels were sent —
            // the re-list confirms the book is clean.
            phase = ReconcilePhase::Done;
            break 'rounds;
        }
        if all_clean && rounds == 1 && supported.iter().all(|v| progress[v].found == 0) {
            phase = ReconcilePhase::Done; // nothing was resting to begin with
            break 'rounds;
        }
        if rounds < MAX_ROUNDS {
            let backoff = ROUND_BACKOFF_BASE * 2u32.pow((rounds - 1).min(3));
            clock.sleep(backoff).await;
        }
    }

    // Final verdict: Done only if every supported venue was last seen EMPTY.
    if phase == ReconcilePhase::Done && !supported.iter().all(|v| progress[v].resting == Some(0)) {
        phase = ReconcilePhase::Failed;
    }
    // CR115: an unwindable venue is not a clean one. This version lists and
    // cancels on `okx` and `binance` only; every other stem is left untouched,
    // so its book state is UNKNOWN — and unknown is never `Done` (the same rule
    // that makes an unreadable book `resting: None` rather than zero). The
    // earlier guard caught only the ALL-unsupported tenant; a MIXED tenant
    // (binance + okx + asterdex) cleared the two it could reach and reported
    // `tenant_reconcile_done` while the asterdex orders kept resting, with no
    // page to the operator. Any unsupported venue now fails the job and names
    // itself in the error the healthcheck pages with.
    let mut job_error: Option<String> = None;
    let unsupported: Vec<&str> = venues
        .iter()
        .filter(|v| !ops.supported(v))
        .map(String::as_str)
        .collect();
    if !unsupported.is_empty() && phase != ReconcilePhase::Terminated {
        phase = ReconcilePhase::Failed;
        job_error = Some(format!(
            "{} venue(s) this version cannot unwind ({}): their books were NOT listed and orders may still be resting — cancel by hand via the venue UI",
            unsupported.len(),
            unsupported.join(", ")
        ));
    }
    let finished = clock.now_unix();
    let bundle = IncidentBundle {
        v: 1,
        customer: customer.to_owned(),
        tenant_state: state.tenants.state_of(customer).as_str().to_owned(),
        started_unix: started,
        finished_unix: finished,
        phase,
        rounds,
        venues: progress.clone(),
        before,
        after,
        raw,
    };
    let incident_path = match write_bundle(incidents, &bundle) {
        Ok(p) => Some(p.display().to_string()),
        Err(e) => {
            error!(event = "tenant_reconcile_bundle_failed", customer = %customer, error = %e);
            None
        }
    };
    state.tenants.update_reconcile(customer, |s| {
        s.phase = phase;
        s.finished_unix = Some(finished);
        s.rounds = rounds;
        s.venues = progress.clone();
        s.incident_path = incident_path.clone();
        if job_error.is_some() {
            s.error = job_error.clone();
        }
    });
    let resting_total: u32 = progress.values().filter_map(|p| p.resting).sum();
    let unknown: Vec<&String> = progress
        .iter()
        .filter(|(_, p)| p.resting.is_none() && !p.unsupported)
        .map(|(v, _)| v)
        .collect();
    match phase {
        ReconcilePhase::Done => {
            info!(event = "tenant_reconcile_done", customer = %customer, rounds, incident = ?incident_path)
        }
        ReconcilePhase::Terminated => {
            warn!(event = "tenant_reconcile_terminated", customer = %customer, rounds, resting = resting_total, "operator released the tenant mid-reconcile")
        }
        _ => {
            error!(event = "tenant_reconcile_failed", customer = %customer, rounds, resting = resting_total, unreadable = ?unknown, incident = ?incident_path, "orders may still be resting — unwind by hand")
        }
    }
    phase
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_owned()
    } else {
        let mut end = n;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

// ── Production ops: sign through the enclave as the tenant, call the venue ──

pub struct GatewayOps {
    state: AppState,
    customer: String,
    token: zeroize::Zeroizing<String>,
}

impl GatewayOps {
    pub fn new(state: AppState, customer: &str) -> Option<Self> {
        let token = crate::auth::raw_token_for_customer(customer)?;
        Some(Self {
            state,
            customer: customer.to_owned(),
            token,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        venue: &str,
        op: &str,
        method: reqwest::Method,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<String>,
        raw: &mut Vec<RawExchange>,
    ) -> Result<(u16, serde_json::Value), String> {
        let mut req = crate::hedge::venue_client().request(method, url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        if let Some(b) = body {
            req = req.body(b);
        }
        let mut resp = req
            .send()
            .await
            .map_err(|e| crate::hedge::transport_error_detail("venue call failed", e))?;
        let status = resp.status().as_u16();
        let bytes = crate::hedge::read_capped_body(&mut resp).await?;
        let text = String::from_utf8_lossy(&bytes).to_string();
        raw.push(RawExchange {
            venue: venue.to_owned(),
            op: op.to_owned(),
            http_status: Some(status),
            body: truncate(&text, RAW_CAP),
        });
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("venue returned non-JSON (HTTP {status}): {e}"))?;
        Ok((status, json))
    }

    /// Enclave-signed read with rate-limit backoff (sign path may 429).
    async fn signed_read(
        &self,
        venue: &str,
        method: &str,
        path: &str,
        query: &str,
    ) -> Result<BTreeMap<String, String>, String> {
        let mut last = String::new();
        for attempt in 1..=CANCEL_ATTEMPTS {
            match crate::handlers::sign_generic_venue_request(
                &self.state,
                &self.customer,
                &self.token,
                venue,
                method,
                path,
                "",
                query,
            )
            .await
            {
                Ok(h) => return Ok(h),
                Err(resp) => {
                    let status = resp.status().as_u16();
                    last = format!("sign {method} {path} refused: HTTP {status}");
                    if status == 429 && attempt < CANCEL_ATTEMPTS {
                        tokio::time::sleep(CANCEL_BACKOFF_BASE * attempt).await;
                        continue;
                    }
                    return Err(last);
                }
            }
        }
        Err(last)
    }
}

/// Stems that are TRADING venues. A customer directory may also hold blobs
/// that carry no orders (x402 payer keys, data keys); those must not be
/// reported as unwind work (CodeRabbit).
const VENUE_STEMS: &[&str] = &[
    "okx",
    "binance",
    "binance_spot",
    "binance_futures",
    "bybit",
    "kucoin",
    "asterdex",
    "hyperliquid_main",
    "hyperliquid_testnet",
];

impl VenueOps for GatewayOps {
    fn venues(&self) -> Vec<String> {
        let prefix = format!("{}/", self.customer);
        let mut v: Vec<String> = self
            .state
            .blobs
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(str::to_owned))
            .filter(|stem| VENUE_STEMS.contains(&stem.as_str()))
            .collect();
        v.sort();
        v
    }

    fn supported(&self, venue: &str) -> bool {
        matches!(venue, "okx" | "binance")
    }

    async fn list_open(
        &self,
        venue: &str,
        raw: &mut Vec<RawExchange>,
    ) -> Result<Vec<OpenOrder>, String> {
        match venue {
            "okx" => {
                let mut headers = self
                    .signed_read("okx", "GET", "/api/v5/trade/orders-pending", "")
                    .await?;
                if crate::handlers::okx_is_demo() {
                    headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
                }
                let url = format!(
                    "{}/api/v5/trade/orders-pending",
                    crate::handlers::okx_base_url()
                );
                let (status, json) = self
                    .send(
                        venue,
                        "list",
                        reqwest::Method::GET,
                        &url,
                        &headers,
                        None,
                        raw,
                    )
                    .await?;
                parse_okx_open_orders(status, &json)
            }
            "binance" => {
                let mut headers = self
                    .signed_read("binance", "GET", "/fapi/v1/openOrders", "")
                    .await?;
                let url =
                    crate::handlers::binance_signed_url("/fapi/v1/openOrders", "", &mut headers)
                        .map_err(|e| format!("binance url assembly: {e}"))?;
                let (status, json) = self
                    .send(
                        venue,
                        "list",
                        reqwest::Method::GET,
                        &url,
                        &headers,
                        None,
                        raw,
                    )
                    .await?;
                parse_binance_open_orders(status, &json)
            }
            other => Err(format!("venue {other} not supported")),
        }
    }

    async fn cancel(
        &self,
        venue: &str,
        orders: &[OpenOrder],
        raw: &mut Vec<RawExchange>,
    ) -> Vec<CancelOutcome> {
        match venue {
            "okx" => {
                let mut out = Vec::with_capacity(orders.len());
                for o in orders {
                    out.push(self.cancel_okx_one(o, raw).await);
                }
                out
            }
            "binance" => {
                // One cancel-all per symbol; every order of that symbol shares the outcome.
                let mut by_symbol: BTreeMap<&str, CancelOutcome> = BTreeMap::new();
                for o in orders {
                    if by_symbol.contains_key(o.symbol.as_str()) {
                        continue;
                    }
                    let outcome = self.cancel_binance_symbol(&o.symbol, raw).await;
                    by_symbol.insert(o.symbol.as_str(), outcome);
                }
                orders
                    .iter()
                    .map(|o| by_symbol[o.symbol.as_str()].clone())
                    .collect()
            }
            other => orders
                .iter()
                .map(|_| CancelOutcome::Failed(format!("venue {other} not supported")))
                .collect(),
        }
    }
}

impl GatewayOps {
    async fn cancel_okx_one(&self, o: &OpenOrder, raw: &mut Vec<RawExchange>) -> CancelOutcome {
        let payload =
            serde_json::json!({ "cancel": { "symbol": o.symbol, "order_id": o.order_id } });
        let mut last = String::new();
        for attempt in 1..=CANCEL_ATTEMPTS {
            // Latency of the unwind path matters: the latency runbook picks cancels
            // as its measurement vehicle precisely because they burn no caps, and
            // unwind is where a cold DEK cache would hurt most. One stopwatch PER
            // ATTEMPT — a 429 retry is a second signing attempt and earns its row.
            //
            // 🔴 PORT NOTE (2026-09-04). The private tree used `handlers::Stages`,
            // which `sign_structured_request` fills with the gate/creds/vsock split.
            // That helper takes two more parameters there (`charge_order`, `stages`)
            // and is called from six hot paths in this repository, so the port does
            // NOT widen it: a signature change on the signing path is not worth a
            // telemetry field. Measured instead is the WHOLE attempt, honestly
            // labelled — no `sign_stages` row claiming a breakdown it does not have.
            // Zeros in a metric are worse than an absent metric.
            let attempt_started = std::time::Instant::now();
            let signed = crate::handlers::sign_structured_request(
                &self.state,
                &self.customer,
                &self.token,
                "okx",
                "sign_okx_cancel",
                "POST",
                "/api/v5/trade/cancel-order",
                payload.clone(),
                crate::handlers::AgentIntentForward::default(),
            )
            .await;
            // The third element is the client-facing receipt; the unwind job has
            // no client. It is already ARCHIVED inside `sign_structured_request`
            // (take_receipt) — the enclave's record of every cancel this job
            // signed lands in /var/lib/signer/receipts like any other decision.
            let (canonical, mut headers, _receipt) = match signed {
                Ok(p) => p,
                Err(resp) => {
                    let status = resp.status().as_u16();
                    tracing::info!(
                        event = "reconcile_cancel_attempt",
                        outcome = "denied",
                        attempt_ms = attempt_started.elapsed().as_millis() as u64,
                    );
                    last = format!("sign okx cancel refused: HTTP {status}");
                    if status == 429 && attempt < CANCEL_ATTEMPTS {
                        tokio::time::sleep(CANCEL_BACKOFF_BASE * attempt).await;
                        continue;
                    }
                    return CancelOutcome::Failed(last);
                }
            };
            if crate::handlers::okx_is_demo() {
                headers.insert("x-simulated-trading".to_owned(), "1".to_owned());
            }
            headers.insert("Content-Type".to_owned(), "application/json".to_owned());
            let url = format!(
                "{}/api/v5/trade/cancel-order",
                crate::handlers::okx_base_url()
            );
            // Measured HERE, after the venue-native assembly and before the
            // outbound HTTP call, so the number covers sign + assemble. The venue
            // round-trip that follows is this module's own concern.
            tracing::info!(
                event = "reconcile_cancel_attempt",
                outcome = "ok",
                attempt_ms = attempt_started.elapsed().as_millis() as u64,
            );
            // THE LANDMINE (same as /sign/okx-order): `canonical` is the exact
            // byte-string the HMAC committed to — forwarded verbatim.
            match self
                .send(
                    "okx",
                    "cancel",
                    reqwest::Method::POST,
                    &url,
                    &headers,
                    Some(canonical),
                    raw,
                )
                .await
            {
                Ok((status, json)) => return parse_okx_cancel(status, &json),
                Err(e) => {
                    last = e;
                    if attempt < CANCEL_ATTEMPTS {
                        tokio::time::sleep(CANCEL_BACKOFF_BASE * attempt).await;
                        continue;
                    }
                }
            }
        }
        CancelOutcome::Failed(last)
    }

    /// Same bounded 429 retry as the OKX path (the module's lesson 2 applies
    /// to every venue, not only the one the box script was written for).
    async fn cancel_binance_symbol(
        &self,
        symbol: &str,
        raw: &mut Vec<RawExchange>,
    ) -> CancelOutcome {
        let query = format!("symbol={symbol}");
        let mut last = String::new();
        for attempt in 1..=CANCEL_ATTEMPTS {
            // Re-sign each attempt: the Binance signature carries a timestamp.
            let mut headers = match self
                .signed_read("binance", "DELETE", "/fapi/v1/allOpenOrders", &query)
                .await
            {
                Ok(h) => h,
                Err(e) => return CancelOutcome::Failed(e),
            };
            let url = match crate::handlers::binance_signed_url(
                "/fapi/v1/allOpenOrders",
                &query,
                &mut headers,
            ) {
                Ok(u) => u,
                Err(e) => return CancelOutcome::Failed(format!("binance url assembly: {e}")),
            };
            match self
                .send(
                    "binance",
                    "cancel_all",
                    reqwest::Method::DELETE,
                    &url,
                    &headers,
                    None,
                    raw,
                )
                .await
            {
                Ok((429, json)) => {
                    last = format!("binance HTTP 429 {}", truncate(&json.to_string(), 120));
                }
                Ok((status, json)) => return parse_binance_cancel_all(status, &json),
                Err(e) => last = e,
            }
            if attempt < CANCEL_ATTEMPTS {
                tokio::time::sleep(CANCEL_BACKOFF_BASE * attempt).await;
            }
        }
        CancelOutcome::Failed(last)
    }
}

// ── Venue response parsing (pure, unit-tested) ─────────────────────────────

/// OKX `GET /api/v5/trade/orders-pending`: `{"code":"0","data":[{instId, ordId, …}]}`.
/// Anything that is not a well-formed list is an ERROR (lesson 1).
pub fn parse_okx_open_orders(
    status: u16,
    json: &serde_json::Value,
) -> Result<Vec<OpenOrder>, String> {
    if status != 200 {
        return Err(format!(
            "okx HTTP {status}: {}",
            truncate(&json.to_string(), 200)
        ));
    }
    if json.get("code").and_then(|c| c.as_str()) != Some("0") {
        return Err(format!(
            "okx code {:?} msg {:?}",
            json.get("code"),
            json.get("msg")
        ));
    }
    let data = json
        .get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| "okx response without a data list — book NOT read".to_owned())?;
    let mut out = Vec::new();
    for row in data {
        let inst = row.get("instId").and_then(|v| v.as_str());
        let oid = row.get("ordId").and_then(|v| v.as_str());
        match (inst, oid) {
            (Some(i), Some(o)) if !i.is_empty() && !o.is_empty() => out.push(OpenOrder {
                venue: "okx".to_owned(),
                symbol: i.to_owned(),
                order_id: o.to_owned(),
            }),
            _ => return Err("okx order row without instId/ordId — book NOT read".to_owned()),
        }
    }
    Ok(out)
}

/// OKX `POST /api/v5/trade/cancel-order`: `{"code":"0","data":[{"sCode":"0",…}]}`.
/// sCode 51400/51401/51402/51410 = order no longer exists — not resting.
pub fn parse_okx_cancel(status: u16, json: &serde_json::Value) -> CancelOutcome {
    let row = json
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|a| a.first());
    let scode = row
        .and_then(|r| r.get("sCode"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Top-level failures (bad sign, bad key, rate limit) carry `msg` and no
    // `data` row — fall back to it so the operator reads a reason, not blanks.
    let top_msg = json.get("msg").and_then(|v| v.as_str()).unwrap_or("");
    let smsg = row
        .and_then(|r| r.get("sMsg"))
        .and_then(|v| v.as_str())
        .filter(|m| !m.is_empty())
        .unwrap_or(top_msg);
    let code = json.get("code").and_then(|c| c.as_str()).unwrap_or("");
    if status == 200 && code == "0" && scode == "0" {
        return CancelOutcome::Cancelled;
    }
    if matches!(scode, "51400" | "51401" | "51402" | "51410") {
        return CancelOutcome::Gone;
    }
    CancelOutcome::Failed(format!(
        "okx HTTP {status} code {code} sCode {scode} {smsg}"
    ))
}

/// Binance USD-M `GET /fapi/v1/openOrders`: a JSON ARRAY of `{symbol, orderId}`.
pub fn parse_binance_open_orders(
    status: u16,
    json: &serde_json::Value,
) -> Result<Vec<OpenOrder>, String> {
    if status != 200 {
        return Err(format!(
            "binance HTTP {status}: {}",
            truncate(&json.to_string(), 200)
        ));
    }
    let arr = json.as_array().ok_or_else(|| {
        format!(
            "binance openOrders is not a list — book NOT read: {}",
            truncate(&json.to_string(), 200)
        )
    })?;
    let mut out = Vec::new();
    for row in arr {
        let sym = row.get("symbol").and_then(|v| v.as_str());
        let oid = row.get("orderId").map(|v| match v {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            _ => String::new(),
        });
        match (sym, oid) {
            (Some(s), Some(o)) if !s.is_empty() && !o.is_empty() => out.push(OpenOrder {
                venue: "binance".to_owned(),
                symbol: s.to_owned(),
                order_id: o,
            }),
            _ => return Err("binance order row without symbol/orderId — book NOT read".to_owned()),
        }
    }
    Ok(out)
}

/// Binance `DELETE /fapi/v1/allOpenOrders`: `{"code":200,"msg":"…"}` on success;
/// -2011 "Unknown order sent" means nothing was resting for that symbol.
pub fn parse_binance_cancel_all(status: u16, json: &serde_json::Value) -> CancelOutcome {
    let code = json.get("code").and_then(|c| c.as_i64());
    match (status, code) {
        (200, Some(200)) | (200, None) => CancelOutcome::Cancelled,
        (_, Some(-2011)) => CancelOutcome::Gone,
        _ => CancelOutcome::Failed(format!(
            "binance HTTP {status} {}",
            truncate(&json.to_string(), 200)
        )),
    }
}

// ── Spawning: one job per tenant at a time, resumed at boot ────────────────

static RUNNING: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

fn try_claim(customer: &str) -> bool {
    let mut g = RUNNING.lock().unwrap_or_else(|p| p.into_inner());
    g.get_or_insert_with(Default::default)
        .insert(customer.to_owned())
}
fn release_claim(customer: &str) {
    let mut g = RUNNING.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(set) = g.as_mut() {
        set.remove(customer);
    }
}

/// Start the reconcile job for `customer` if its record says one is due and
/// none is running. Idempotent; safe to call on every transition.
pub fn kick(state: AppState, customer: &str) {
    let due = state
        .tenants
        .reconcile_candidates()
        .iter()
        .any(|c| c == customer);
    if !due {
        return;
    }
    if !try_claim(customer) {
        return; // already running in this process
    }
    let customer = customer.to_owned();
    tokio::spawn(async move {
        let Some(ops) = GatewayOps::new(state.clone(), &customer) else {
            error!(event = "tenant_reconcile_no_token", customer = %customer, "no SIGNER_API_TOKENS entry for this customer — cannot sign cancels; unwind by hand");
            state.tenants.update_reconcile(&customer, |s| {
                s.phase = ReconcilePhase::Failed;
                s.finished_unix = Some(crate::limits::now_unix_secs());
                // Job-level: the venue map is still empty at this point.
                s.error = Some(
                    "no SIGNER_API_TOKENS entry for this customer in the gateway environment — cannot sign cancels; unwind by hand"
                        .to_owned(),
                );
            });
            release_claim(&customer);
            return;
        };
        let _ = run(&state, &customer, &ops, &RealClock, &incidents_dir()).await;
        release_claim(&customer);
    });
}

/// At boot: restart every non-final job (a restart mid-unwind is not a loss).
pub fn resume_all(state: AppState) {
    // A release followed by a restart before the job noticed it leaves an
    // ACTIVE tenant with a non-final job on disk — nothing would ever finalize
    // it and the status would read `running` forever (Gemini). Close it.
    for (customer, rec) in state.tenants.all() {
        if rec.state == TenantState::Active {
            if let Some(r) = rec.reconcile.as_ref().filter(|r| !r.is_final()) {
                warn!(event = "tenant_reconcile_orphan_terminated", customer = %customer, phase = ?r.phase);
                state.tenants.update_reconcile(&customer, |s| {
                    s.phase = ReconcilePhase::Terminated;
                    s.finished_unix = Some(crate::limits::now_unix_secs());
                    s.error =
                        Some("released before the job finished; restart closed it".to_owned());
                });
            }
        }
    }
    for c in state.tenants.reconcile_candidates() {
        warn!(event = "tenant_reconcile_resume", customer = %c, "resuming reconcile after restart");
        kick(state.clone(), &c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EnclaveTarget;
    use crate::tenant_state::{Actor, TenantStateStore};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestClock {
        slept: AtomicU32,
    }
    impl Clock for TestClock {
        fn now_unix(&self) -> u64 {
            1_700_000_000
        }
        async fn sleep(&self, _d: Duration) {
            self.slept.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// In-memory venues: a book per venue, optional "unreadable" flag, a
    /// per-venue list of order ids whose cancel must fail, and a hook to
    /// release the tenant after N cancels (to test Terminated).
    struct MockOps {
        books: Mutex<HashMap<String, Vec<OpenOrder>>>,
        unreadable: Vec<String>,
        sticky: Vec<String>,
        unsupported: Vec<String>,
        release_after_cancels: Option<(u32, AppState, String)>,
        cancels: AtomicU32,
    }
    impl MockOps {
        fn new(books: &[(&str, &[(&str, &str)])]) -> Self {
            let mut m = HashMap::new();
            for (v, orders) in books {
                m.insert(
                    v.to_string(),
                    orders
                        .iter()
                        .map(|(s, o)| OpenOrder {
                            venue: v.to_string(),
                            symbol: s.to_string(),
                            order_id: o.to_string(),
                        })
                        .collect(),
                );
            }
            Self {
                books: Mutex::new(m),
                unreadable: vec![],
                sticky: vec![],
                unsupported: vec![],
                release_after_cancels: None,
                cancels: AtomicU32::new(0),
            }
        }
    }
    impl VenueOps for MockOps {
        fn venues(&self) -> Vec<String> {
            let mut v: Vec<String> = self.books.lock().unwrap().keys().cloned().collect();
            v.extend(self.unsupported.iter().cloned());
            v.sort();
            v
        }
        fn supported(&self, venue: &str) -> bool {
            !self.unsupported.iter().any(|u| u == venue)
        }
        async fn list_open(
            &self,
            venue: &str,
            raw: &mut Vec<RawExchange>,
        ) -> Result<Vec<OpenOrder>, String> {
            raw.push(RawExchange {
                venue: venue.into(),
                op: "list".into(),
                http_status: Some(200),
                body: "{}".into(),
            });
            if self.unreadable.iter().any(|u| u == venue) {
                return Err("simulated: venue unreadable".into());
            }
            Ok(self
                .books
                .lock()
                .unwrap()
                .get(venue)
                .cloned()
                .unwrap_or_default())
        }
        async fn cancel(
            &self,
            venue: &str,
            orders: &[OpenOrder],
            raw: &mut Vec<RawExchange>,
        ) -> Vec<CancelOutcome> {
            let mut out = Vec::new();
            for o in orders {
                raw.push(RawExchange {
                    venue: venue.into(),
                    op: "cancel".into(),
                    http_status: Some(200),
                    body: "{}".into(),
                });
                let n = self.cancels.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some((after, state, customer)) = &self.release_after_cancels {
                    if n == *after {
                        state
                            .tenants
                            .transition(
                                customer,
                                TenantState::Active,
                                Actor::Operator,
                                "release mid-job",
                                5,
                            )
                            .unwrap();
                    }
                }
                if self.sticky.iter().any(|s| s == &o.order_id) {
                    out.push(CancelOutcome::Failed("simulated: venue refused".into()));
                } else {
                    self.books
                        .lock()
                        .unwrap()
                        .get_mut(venue)
                        .unwrap()
                        .retain(|x| x.order_id != o.order_id);
                    out.push(CancelOutcome::Cancelled);
                }
            }
            out
        }
    }

    fn state_with(tmp: &std::path::Path, customer: &str, to: TenantState) -> AppState {
        let store = TenantStateStore::load(tmp.join("tenant-state.json")).unwrap();
        store
            .transition(customer, to, Actor::Client, "", 1)
            .unwrap();
        AppState::new(HashMap::new(), EnclaveTarget { cid: 0, port: 0 }).with_tenants(store)
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("reconcile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn clean_unwind_two_venues_is_done_with_bundle() {
        let d = tmpdir("clean");
        let state = state_with(&d, "t", TenantState::CancelOnly);
        let ops = MockOps::new(&[
            ("okx", &[("BTC-USDT-SWAP", "1"), ("BTC-USDT-SWAP", "2")]),
            ("binance", &[("BTCUSDT", "7")]),
        ]);
        let clock = TestClock {
            slept: AtomicU32::new(0),
        };
        let phase = run(&state, "t", &ops, &clock, &d.join("incidents")).await;
        assert_eq!(phase, ReconcilePhase::Done);
        let rec = state.tenants.record("t").unwrap().reconcile.unwrap();
        assert_eq!(rec.phase, ReconcilePhase::Done);
        assert_eq!(
            rec.rounds, 2,
            "round 1 cancels, round 2 confirms the empty book"
        );
        assert_eq!(rec.venues["okx"].found, 2);
        assert_eq!(rec.venues["okx"].cancelled, 2);
        assert_eq!(rec.venues["okx"].resting, Some(0));
        assert_eq!(rec.venues["binance"].resting, Some(0));
        let path = rec.incident_path.expect("bundle written");
        let bundle: IncidentBundle =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(bundle.before["okx"].len(), 2);
        assert_eq!(bundle.after["okx"].len(), 0);
        assert!(
            bundle.raw.iter().any(|r| r.op == "cancel"),
            "raw venue responses always recorded"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn nothing_resting_is_done_in_one_round() {
        let d = tmpdir("empty");
        let state = state_with(&d, "t", TenantState::Halted);
        let ops = MockOps::new(&[("okx", &[])]);
        let phase = run(
            &state,
            "t",
            &ops,
            &TestClock {
                slept: AtomicU32::new(0),
            },
            &d.join("inc"),
        )
        .await;
        assert_eq!(phase, ReconcilePhase::Done);
        assert_eq!(
            state.tenants.record("t").unwrap().reconcile.unwrap().rounds,
            1
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn unreadable_venue_is_failed_not_clean() {
        let d = tmpdir("unreadable");
        let state = state_with(&d, "t", TenantState::CancelOnly);
        let mut ops = MockOps::new(&[("okx", &[]), ("binance", &[])]);
        ops.unreadable = vec!["binance".into()];
        let clock = TestClock {
            slept: AtomicU32::new(0),
        };
        let phase = run(&state, "t", &ops, &clock, &d.join("inc")).await;
        assert_eq!(phase, ReconcilePhase::Failed, "could not look ≠ clean");
        let rec = state.tenants.record("t").unwrap().reconcile.unwrap();
        assert_eq!(rec.venues["binance"].resting, None);
        assert!(rec.venues["binance"].error.is_some());
        assert_eq!(rec.rounds, MAX_ROUNDS);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn sticky_order_exhausts_rounds_and_fails_with_resting_count() {
        let d = tmpdir("sticky");
        let state = state_with(&d, "t", TenantState::CancelOnly);
        let mut ops = MockOps::new(&[("okx", &[("BTC-USDT-SWAP", "1"), ("BTC-USDT-SWAP", "2")])]);
        ops.sticky = vec!["2".into()];
        let clock = TestClock {
            slept: AtomicU32::new(0),
        };
        let phase = run(&state, "t", &ops, &clock, &d.join("inc")).await;
        assert_eq!(phase, ReconcilePhase::Failed);
        let rec = state.tenants.record("t").unwrap().reconcile.unwrap();
        assert_eq!(
            rec.venues["okx"].resting,
            Some(1),
            "the sticky order is reported resting"
        );
        assert_eq!(rec.venues["okx"].cancelled, 1);
        assert!(
            clock.slept.load(Ordering::Relaxed) >= MAX_ROUNDS - 1,
            "backed off between rounds"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn operator_release_terminates_the_job() {
        let d = tmpdir("terminate");
        let state = state_with(&d, "t", TenantState::CancelOnly);
        let mut ops = MockOps::new(&[(
            "okx",
            &[
                ("BTC-USDT-SWAP", "1"),
                ("BTC-USDT-SWAP", "2"),
                ("BTC-USDT-SWAP", "3"),
            ],
        )]);
        ops.sticky = vec!["3".into()]; // keep the job alive into round 2
        ops.release_after_cancels = Some((2, state.clone(), "t".into()));
        let phase = run(
            &state,
            "t",
            &ops,
            &TestClock {
                slept: AtomicU32::new(0),
            },
            &d.join("inc"),
        )
        .await;
        assert_eq!(phase, ReconcilePhase::Terminated);
        let rec = state.tenants.record("t").unwrap();
        assert_eq!(rec.state, TenantState::Active);
        assert_eq!(rec.reconcile.unwrap().phase, ReconcilePhase::Terminated);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn unsupported_venue_is_reported_not_skipped() {
        let d = tmpdir("unsupported");
        let state = state_with(&d, "t", TenantState::CancelOnly);
        let mut ops = MockOps::new(&[("okx", &[])]);
        ops.unsupported = vec!["bybit".into()];
        let phase = run(
            &state,
            "t",
            &ops,
            &TestClock {
                slept: AtomicU32::new(0),
            },
            &d.join("inc"),
        )
        .await;
        // CR115: the supported venue being clean is NOT enough — bybit was
        // never listed, so its state is unknown and the job must fail loudly.
        assert_eq!(phase, ReconcilePhase::Failed);
        let rec = state.tenants.record("t").unwrap().reconcile.unwrap();
        assert!(rec.venues["bybit"].unsupported);
        assert!(rec.venues["bybit"]
            .error
            .as_deref()
            .unwrap()
            .contains("by hand"));
        assert!(
            rec.error.as_deref().unwrap().contains("bybit"),
            "the job-level error names the venue the operator must unwind"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// CR115 (AUD-017), the exact reported scenario: binance + okx unwound
    /// clean, asterdex never listed. `Done` here would tell the operator the
    /// tenant is flat while real orders keep resting.
    #[tokio::test]
    async fn mixed_supported_and_unsupported_is_failed_not_done() {
        let d = tmpdir("mixed");
        let state = state_with(&d, "t", TenantState::Halted);
        let mut ops = MockOps::new(&[
            ("binance", &[("BTCUSDT", "11")]),
            ("okx", &[("BTC-USDT-SWAP", "22")]),
        ]);
        ops.unsupported = vec!["asterdex".into()];
        let phase = run(
            &state,
            "t",
            &ops,
            &TestClock {
                slept: AtomicU32::new(0),
            },
            &d.join("inc"),
        )
        .await;
        assert_eq!(phase, ReconcilePhase::Failed, "asterdex was never listed");
        let rec = state.tenants.record("t").unwrap().reconcile.unwrap();
        // The two it COULD unwind are still reported as unwound.
        assert_eq!(rec.venues["binance"].cancelled, 1);
        assert_eq!(rec.venues["okx"].resting, Some(0));
        // …and the one it could not is named at the job level, which is what
        // the healthcheck pages on (`phase == failed`).
        assert!(rec.error.as_deref().unwrap().contains("asterdex"));
        assert!(rec.venues["asterdex"].unsupported);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// CodeRabbit (confirmed by CTO): a tenant whose venues are all unsupported
    /// used to finish `Done` with nothing listed and no page. Must be `Failed`
    /// with a job-level error naming the venues.
    #[tokio::test]
    async fn only_unsupported_venues_is_failed_not_done() {
        let d = tmpdir("allunsupported");
        let state = state_with(&d, "t", TenantState::CancelOnly);
        let mut ops = MockOps::new(&[]);
        ops.unsupported = vec!["bybit".into(), "kucoin".into()];
        let phase = run(
            &state,
            "t",
            &ops,
            &TestClock {
                slept: AtomicU32::new(0),
            },
            &d.join("inc"),
        )
        .await;
        assert_eq!(phase, ReconcilePhase::Failed);
        let rec = state.tenants.record("t").unwrap().reconcile.unwrap();
        assert!(rec.error.as_deref().unwrap().contains("bybit"));
        assert!(rec.venues["kucoin"].unsupported);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// No venues at all (no blobs staged) — nothing could ever rest: Done.
    #[tokio::test]
    async fn no_venues_at_all_is_done() {
        let d = tmpdir("novenues");
        let state = state_with(&d, "t", TenantState::CancelOnly);
        let ops = MockOps::new(&[]);
        let phase = run(
            &state,
            "t",
            &ops,
            &TestClock {
                slept: AtomicU32::new(0),
            },
            &d.join("inc"),
        )
        .await;
        assert_eq!(phase, ReconcilePhase::Done);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Gemini: release → restart before the job finalized left `running` on disk forever.
    #[test]
    fn resume_closes_orphaned_job_of_an_active_tenant() {
        let d = tmpdir("orphan");
        let store = TenantStateStore::load(d.join("s.json")).unwrap();
        store
            .transition("a", TenantState::CancelOnly, Actor::Client, "", 1)
            .unwrap();
        store.update_reconcile("a", |s| s.phase = ReconcilePhase::Running);
        store
            .transition("a", TenantState::Active, Actor::Operator, "released", 2)
            .unwrap();
        let state =
            AppState::new(HashMap::new(), EnclaveTarget { cid: 0, port: 0 }).with_tenants(store);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async { resume_all(state.clone()) });
        let r = state.tenants.record("a").unwrap().reconcile.unwrap();
        assert_eq!(r.phase, ReconcilePhase::Terminated);
        assert!(r.error.as_deref().unwrap().contains("restart"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn existing_incident_dir_is_tightened_to_0750() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("perm");
        let cust = d.join("wide");
        std::fs::create_dir_all(&cust).unwrap();
        std::fs::set_permissions(&cust, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&cust).unwrap();
        assert_eq!(
            std::fs::metadata(&cust).unwrap().permissions().mode() & 0o777,
            0o750
        );
        let fresh = d.join("fresh");
        create_private_dir(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o750
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn venue_stems_exclude_non_trading_blobs() {
        assert!(VENUE_STEMS.contains(&"okx"));
        assert!(!VENUE_STEMS.contains(&"x402"));
        assert!(!VENUE_STEMS.contains(&"data-signing"));
    }

    #[test]
    fn resume_candidates_follow_phase_and_state() {
        let d = tmpdir("candidates");
        let store = TenantStateStore::load(d.join("s.json")).unwrap();
        store
            .transition("a", TenantState::CancelOnly, Actor::Client, "", 1)
            .unwrap();
        store
            .transition("b", TenantState::Halted, Actor::Client, "", 1)
            .unwrap();
        store.update_reconcile("b", |s| s.phase = ReconcilePhase::Done);
        store
            .transition("c", TenantState::CancelOnly, Actor::Client, "", 1)
            .unwrap();
        store
            .transition("c", TenantState::Active, Actor::Operator, "released", 2)
            .unwrap();
        let mut c = store.reconcile_candidates();
        c.sort();
        assert_eq!(c, vec!["a".to_string()], "a pending; b done; c active");
        // escalation keeps the running job; a new stop after Done arms a fresh one
        store.update_reconcile("a", |s| s.phase = ReconcilePhase::Running);
        store
            .transition("a", TenantState::Halted, Actor::Client, "", 3)
            .unwrap();
        assert_eq!(
            store.record("a").unwrap().reconcile.unwrap().phase,
            ReconcilePhase::Running
        );
        store
            .transition("b", TenantState::Active, Actor::Operator, "r", 4)
            .unwrap();
        store
            .transition("b", TenantState::CancelOnly, Actor::Client, "", 5)
            .unwrap();
        assert_eq!(
            store.record("b").unwrap().reconcile.unwrap().phase,
            ReconcilePhase::Pending
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── venue response parsing fixtures ──
    #[test]
    fn okx_parsing() {
        let ok = serde_json::json!({"code":"0","msg":"","data":[{"instId":"BNB-USDT-SWAP","ordId":"3846845189025943552","sz":"3","px":"610.9","state":"live"}]});
        let got = parse_okx_open_orders(200, &ok).unwrap();
        assert_eq!(
            got,
            vec![OpenOrder {
                venue: "okx".into(),
                symbol: "BNB-USDT-SWAP".into(),
                order_id: "3846845189025943552".into()
            }]
        );
        assert!(parse_okx_open_orders(
            200,
            &serde_json::json!({"code":"50113","msg":"Invalid Sign"})
        )
        .is_err());
        assert!(
            parse_okx_open_orders(200, &serde_json::json!({"code":"0","data":"oops"})).is_err(),
            "data not a list = NOT read"
        );
        assert!(
            parse_okx_open_orders(200, &serde_json::json!({"code":"0"})).is_err(),
            "no data = NOT read"
        );
        assert!(parse_okx_open_orders(502, &serde_json::json!({})).is_err());
        assert_eq!(
            parse_okx_cancel(
                200,
                &serde_json::json!({"code":"0","data":[{"sCode":"0","sMsg":"","ordId":"1"}]})
            ),
            CancelOutcome::Cancelled
        );
        assert_eq!(
            parse_okx_cancel(
                200,
                &serde_json::json!({"code":"1","data":[{"sCode":"51400","sMsg":"Cancellation failed as the order does not exist"}]})
            ),
            CancelOutcome::Gone
        );
        assert!(matches!(
            parse_okx_cancel(
                200,
                &serde_json::json!({"code":"1","data":[{"sCode":"50113","sMsg":"Invalid Sign"}]})
            ),
            CancelOutcome::Failed(_)
        ));
        // top-level failure without a data row keeps the venue's reason
        match parse_okx_cancel(
            200,
            &serde_json::json!({"code":"50113","msg":"Invalid Sign"}),
        ) {
            CancelOutcome::Failed(e) => assert!(e.contains("Invalid Sign"), "{e}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(matches!(
            parse_okx_cancel(429, &serde_json::json!({})),
            CancelOutcome::Failed(_)
        ));
    }

    #[test]
    fn binance_parsing() {
        let ok = serde_json::json!([{"symbol":"BTCUSDT","orderId":283194212,"status":"NEW"},{"symbol":"ETHUSDT","orderId":"9"}]);
        let got = parse_binance_open_orders(200, &ok).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].order_id, "283194212");
        assert!(
            parse_binance_open_orders(
                200,
                &serde_json::json!({"code":-2015,"msg":"Invalid API-key"})
            )
            .is_err(),
            "error object is NOT a list"
        );
        assert!(
            parse_binance_open_orders(200, &serde_json::json!([{"symbol":"BTCUSDT"}])).is_err()
        );
        assert_eq!(
            parse_binance_cancel_all(
                200,
                &serde_json::json!({"code":200,"msg":"The operation of cancel all open order is done."})
            ),
            CancelOutcome::Cancelled
        );
        assert_eq!(
            parse_binance_cancel_all(
                400,
                &serde_json::json!({"code":-2011,"msg":"Unknown order sent."})
            ),
            CancelOutcome::Gone
        );
        assert!(matches!(
            parse_binance_cancel_all(401, &serde_json::json!({"code":-2015})),
            CancelOutcome::Failed(_)
        ));
    }
}
