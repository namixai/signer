//! Per-tenant kill switch — PR-1 of `docs/TENANT-KILL-SWITCH-DESIGN.md`.
//!
//! Three states per tenant, switched WITHOUT a gateway restart:
//!
//!   ACTIVE ──▶ CANCEL_ONLY ──▶ HALTED
//!
//! - **CANCEL_ONLY** is the load-bearing middle: no new exposure (order-placing
//!   and money-moving paths denied), existing exposure can be unwound (cancels
//!   and reads allowed).
//! - **HALTED** denies every tenant-facing path except the escalate-only
//!   `/tenant/halt` itself. Reads are closed too — `/account` hands back the
//!   venue's own auth headers (OKX passphrase included), and a halted tenant is
//!   a potentially compromised party (CTO ruling 2026-08-20 §1).
//!
//! **Monotonic for the tenant's own bearer.** A client token can only ESCALATE
//! (and re-request the same level idempotently); automation can only reach
//! CANCEL_ONLY; only the OPERATOR (Unix-socket admin, §4) can release. That
//! asymmetry is the product property: a halt the customer pressed cannot be
//! lifted by the customer's own compromised bot, because the refusal lives here
//! and not in the bot's code.
//!
//! **Durability, fail-safe direction.** A halt MUST survive `systemctl restart
//! signer-gateway` — otherwise a restart would be an un-halt, a hole worse than
//! not having the feature. The store is write-through to a JSON file with the
//! same atomic-write discipline as the daily counter and is loaded at boot. If
//! the disk write fails the transition is STILL applied in memory (stopping
//! must never wait on a disk), the store marks itself non-durable, and the
//! failure is logged at ERROR for the alert rail; `/healthz`-adjacent tooling
//! surfaces `durable:false`.
//!
//! **Where enforcement happens.** `tenant_state_mw` runs right after auth
//! (needs `ResolvedCustomer`) and before the rate limiter, so a halted bot's
//! retries don't drain the bucket a legitimate cancel would need. Routes whose
//! class depends on the BODY (`/sign` kind, `/sign/binance-request` op) pass the
//! middleware in CANCEL_ONLY and call `body_route_gate` once the action is
//! known; in HALTED the middleware denies them outright. An unclassified path
//! on the tenant router is treated as exposure-creating (denied in both
//! non-active states) — fail-closed for routes added later without thought.
//!
//! What this module deliberately does NOT do (later PRs): run the reconcile
//! (PR-2), decide automation thresholds (PR-3, triggers ship disabled and
//! log-only), or touch the enclave registry (PR-4 / runbook).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};

use axum::{
    extract::{Path as AxumPath, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::Instrument;
use tracing::{error, info, warn};

use crate::auth::ResolvedCustomer;
use crate::proto::err_code;
use crate::state::AppState;

/// Default on-disk location (the same `/var/lib/signer` the design reserves for
/// state that must outlive a restart; `StateDirectory=signer` in the unit).
pub const DEFAULT_STATE_PATH: &str = "/var/lib/signer/tenant-state.json";
pub const STATE_PATH_ENV: &str = "SIGNER_TENANT_STATE_PATH";
/// Default operator control socket. Unix socket, not a loopback HTTP route:
/// a TLS front that proxies to 127.0.0.1 makes every peer address 127.0.0.1,
/// so an address check proves nothing; a socket is unreachable through any
/// proxy by construction and its file mode IS the permission to press.
pub const DEFAULT_ADMIN_SOCKET: &str = "/run/signer/admin.sock";
pub const ADMIN_SOCKET_ENV: &str = "SIGNER_ADMIN_SOCKET";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    Active,
    CancelOnly,
    Halted,
}

impl TenantState {
    pub fn as_str(self) -> &'static str {
        match self {
            TenantState::Active => "active",
            TenantState::CancelOnly => "cancel_only",
            TenantState::Halted => "halted",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "active" => Some(TenantState::Active),
            "cancel_only" | "cancel-only" => Some(TenantState::CancelOnly),
            "halted" | "halt" => Some(TenantState::Halted),
            _ => None,
        }
    }
}

/// Who pressed. Drives the transition rules, recorded in the state file and in
/// every `tenant_state_changed` event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Operator,
    Client,
    Automation,
}

impl Actor {
    pub fn as_str(self) -> &'static str {
        match self {
            Actor::Operator => "operator",
            Actor::Client => "client",
            Actor::Automation => "automation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub state: TenantState,
    pub since_unix: u64,
    pub by: Actor,
    pub reason: String,
    /// PR-2: the automatic unwind that accompanies a transition into
    /// CANCEL_ONLY / HALTED. `None` on records written before PR-2 and for
    /// ACTIVE tenants that never stopped. Persisted so a job interrupted by a
    /// restart is resumed (`reconcile::resume_all`).
    #[serde(default)]
    pub reconcile: Option<ReconcileStatus>,
}

/// Lifecycle of one reconcile job (design §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcilePhase {
    /// Transition recorded, job not started yet (or lost to a restart — resumed at boot).
    Pending,
    Running,
    /// Every supported venue re-listed EMPTY after cancels.
    Done,
    /// Rounds exhausted with orders still resting, or a venue could not be read. Operator action needed.
    Failed,
    /// Operator released the tenant to ACTIVE while the job ran — stopped, not finished.
    Terminated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueReconcile {
    /// Orders found resting on the first listing.
    pub found: u32,
    /// Cancel calls the venue acknowledged (or reported already-gone).
    pub cancelled: u32,
    /// Orders still resting on the LAST successful listing; `None` = the venue
    /// could not be listed (unknown ≠ clean — the 08-19 lesson).
    pub resting: Option<u32>,
    /// Last error text (bounded), if any.
    pub error: Option<String>,
    /// `true` for venues this version cannot unwind automatically (stems other
    /// than okx / binance futures) — the operator unwinds by hand.
    #[serde(default)]
    pub unsupported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileStatus {
    pub phase: ReconcilePhase,
    pub started_unix: u64,
    pub finished_unix: Option<u64>,
    pub rounds: u32,
    /// venue stem → progress.
    pub venues: std::collections::BTreeMap<String, VenueReconcile>,
    /// Forensic bundle written for this job (`/var/lib/signer/incidents/...`).
    pub incident_path: Option<String>,
    /// Job-level error that is not about one venue (e.g. no tenant token in the
    /// gateway environment) — the operator's first line to read on `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ReconcileStatus {
    pub fn pending(now_unix: u64) -> Self {
        Self {
            phase: ReconcilePhase::Pending,
            started_unix: now_unix,
            finished_unix: None,
            rounds: 0,
            venues: std::collections::BTreeMap::new(),
            incident_path: None,
            error: None,
        }
    }
    /// A job in this phase has nothing left to do.
    pub fn is_final(&self) -> bool {
        matches!(
            self.phase,
            ReconcilePhase::Done | ReconcilePhase::Failed | ReconcilePhase::Terminated
        )
    }
}

/// Outcome of a transition request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    /// State changed `from → to`.
    Changed { from: TenantState, to: TenantState },
    /// Already in the requested state — idempotent no-op.
    Unchanged(TenantState),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// Client/automation asked for a LOWER state than the current one.
    NotEscalation {
        current: TenantState,
        requested: TenantState,
    },
    /// Automation may only reach CANCEL_ONLY (never HALTED, never release).
    AutomationScope,
    /// Empty reason on an operator action — every press leaves a why.
    ReasonRequired,
}

impl TransitionError {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransitionError::NotEscalation { .. } => "not_an_escalation",
            TransitionError::AutomationScope => "automation_scope",
            TransitionError::ReasonRequired => "reason_required",
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    tenants: HashMap<String, TenantRecord>,
}

pub struct TenantStateStore {
    inner: RwLock<HashMap<String, TenantRecord>>,
    path: Option<PathBuf>,
    durable: AtomicBool,
}

impl TenantStateStore {
    /// In-memory only — dev/test default (`AppState::new`). Halts do NOT
    /// survive a restart; `main()` installs a file-backed store.
    pub fn in_memory() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            path: None,
            durable: AtomicBool::new(false),
        }
    }

    /// File-backed store. A missing file is an empty store (first boot); a
    /// present-but-unparseable file is a boot ERROR — a halt we cannot read is
    /// a halt we might silently lift, so refuse to guess.
    pub fn load(path: PathBuf) -> std::io::Result<Self> {
        let tenants = match std::fs::read(&path) {
            Ok(bytes) => {
                let parsed: StateFile = serde_json::from_slice(&bytes).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "tenant-state file {} is not valid JSON: {e}",
                            path.display()
                        ),
                    )
                })?;
                parsed.tenants
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        let non_active = tenants
            .iter()
            .filter(|(_, r)| r.state != TenantState::Active)
            .count();
        info!(
            event = "tenant_state_loaded",
            path = %path.display(),
            tenants = tenants.len(),
            non_active,
        );
        Ok(Self {
            inner: RwLock::new(tenants),
            path: Some(path),
            durable: AtomicBool::new(true),
        })
    }

    /// Fail the boot if the state path cannot be written — same discipline as
    /// `limits::Limits::boot_probe`: a halt that cannot be persisted must be
    /// discovered at boot, not at the first press (CodeRabbit). Writes the
    /// current (possibly empty) state through the same atomic path.
    pub fn boot_probe(&self) -> std::io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let guard = self.inner.read().unwrap_or_else(|p| p.into_inner());
        let bytes = serde_json::to_vec_pretty(&StateFile {
            version: 1,
            tenants: guard.clone(),
        })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::limits::atomic_write_bytes(path, &bytes)?;
        self.durable.store(true, AtomicOrdering::Relaxed);
        Ok(())
    }

    /// True while the last write-through succeeded (or nothing was ever
    /// written). False = in-memory state is ahead of the disk; a restart in
    /// this window loses it. Surfaced on `/tenants` for the healthcheck.
    pub fn durable(&self) -> bool {
        self.durable.load(AtomicOrdering::Relaxed)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn state_of(&self, customer: &str) -> TenantState {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(customer)
            .map(|r| r.state)
            .unwrap_or(TenantState::Active)
    }

    pub fn record(&self, customer: &str) -> Option<TenantRecord> {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(customer)
            .cloned()
    }

    pub fn all(&self) -> Vec<(String, TenantRecord)> {
        let mut v: Vec<_> = self
            .inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(k, r)| (k.clone(), r.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Apply a transition under the rules:
    /// - `Operator`: any target, reason required.
    /// - `Client`: escalate only (`to > current`); `to == current` is an
    ///   idempotent no-op; `to < current` is refused.
    /// - `Automation`: only `CancelOnly`, and only as an escalation.
    ///
    /// Persists write-through while holding the write lock (two racing presses
    /// cannot under-persist each other). A persist failure does NOT fail the
    /// transition: memory is updated first, `durable` flips to false, ERROR is
    /// logged. Stopping never waits on a disk.
    pub fn transition(
        &self,
        customer: &str,
        to: TenantState,
        by: Actor,
        reason: &str,
        now_unix: u64,
    ) -> Result<Transition, TransitionError> {
        let reason = reason.trim();
        if by == Actor::Operator && reason.is_empty() {
            return Err(TransitionError::ReasonRequired);
        }
        if by == Actor::Automation && to != TenantState::CancelOnly {
            return Err(TransitionError::AutomationScope);
        }
        let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
        let current = guard
            .get(customer)
            .map(|r| r.state)
            .unwrap_or(TenantState::Active);
        if to == current {
            return Ok(Transition::Unchanged(current));
        }
        if by != Actor::Operator && to < current {
            return Err(TransitionError::NotEscalation {
                current,
                requested: to,
            });
        }
        // Reconcile bookkeeping: entering a stopped state from ACTIVE arms a
        // fresh job (Pending); escalating CANCEL_ONLY → HALTED keeps the job
        // that is already running (it covers both); a release to ACTIVE leaves
        // the status alone — the running job notices the state and finalizes
        // itself as Terminated (design §2).
        let prev_reconcile = guard.get(customer).and_then(|r| r.reconcile.clone());
        let keep = to == TenantState::Active || matches!(&prev_reconcile, Some(r) if !r.is_final());
        let reconcile = if keep {
            prev_reconcile
        } else {
            Some(ReconcileStatus::pending(now_unix))
        };
        guard.insert(
            customer.to_owned(),
            TenantRecord {
                state: to,
                since_unix: now_unix,
                by,
                reason: reason.to_owned(),
                reconcile,
            },
        );
        warn!(
            event = "tenant_state_changed",
            customer = %customer,
            from = current.as_str(),
            to = to.as_str(),
            by = by.as_str(),
            reason = %reason,
        );
        // The write-through fsyncs while the lock is held. On the production
        // multi-thread runtime, step off the async worker for it; a
        // current-thread runtime (`#[tokio::test]`) has no other worker and
        // `block_in_place` would panic there, so run inline (CodeRabbit).
        let multi = tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        if multi {
            tokio::task::block_in_place(|| self.persist_locked(&guard));
        } else {
            self.persist_locked(&guard);
        }
        Ok(Transition::Changed { from: current, to })
    }

    /// Mutate the reconcile status of `customer` under the write lock and
    /// persist. No-op (returns false) if the tenant has no record.
    pub fn update_reconcile(&self, customer: &str, f: impl FnOnce(&mut ReconcileStatus)) -> bool {
        let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
        let Some(rec) = guard.get_mut(customer) else {
            return false;
        };
        let status = rec
            .reconcile
            .get_or_insert_with(|| ReconcileStatus::pending(crate::limits::now_unix_secs()));
        f(status);
        // Same discipline as `transition`: the write-through fsyncs while the
        // lock is held; step off the async worker on the multi-thread runtime
        // (the reconcile job calls this several times per run — CodeRabbit).
        let multi = tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        if multi {
            tokio::task::block_in_place(|| self.persist_locked(&guard));
        } else {
            self.persist_locked(&guard);
        }
        true
    }

    /// Tenants whose reconcile job should be (re)started: stopped state and a
    /// non-final (or absent) job. Used at boot and by `reconcile::kick`.
    pub fn reconcile_candidates(&self) -> Vec<String> {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, r)| r.state != TenantState::Active)
            .filter(|(_, r)| r.reconcile.as_ref().is_none_or(|s| !s.is_final()))
            .map(|(c, _)| c.clone())
            .collect()
    }

    fn persist_locked(&self, tenants: &HashMap<String, TenantRecord>) {
        let Some(path) = self.path.as_deref() else {
            return; // in-memory store — nothing to persist, durable stays false
        };
        let file = StateFile {
            version: 1,
            tenants: tenants.clone(),
        };
        let bytes = match serde_json::to_vec_pretty(&file) {
            Ok(b) => b,
            Err(e) => {
                self.durable.store(false, AtomicOrdering::Relaxed);
                error!(event = "tenant_state_persist_failed", stage = "serialize", error = %e);
                return;
            }
        };
        match crate::limits::atomic_write_bytes(path, &bytes) {
            Ok(()) => self.durable.store(true, AtomicOrdering::Relaxed),
            Err(e) => {
                self.durable.store(false, AtomicOrdering::Relaxed);
                error!(
                    event = "tenant_state_persist_failed",
                    stage = "write",
                    path = %path.display(),
                    error = %e,
                    "tenant state applied IN MEMORY ONLY — a gateway restart will lose it; page the operator"
                );
            }
        }
    }
}

// ── Route classification ────────────────────────────────────────────────────

/// What a tenant-router path does to exposure. Decided from method+path only;
/// `BodyDecides` routes finish the decision in their handler via
/// `body_route_gate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    /// Places orders: `/sign/*-order`, `/hedge`.
    Order,
    /// Reduces exposure: `/sign/*-cancel`, `/cancel-all/*`.
    Cancel,
    /// Signed venue reads (return venue auth headers): `/account`, `/open-orders`, `/user-trades`.
    Read,
    /// Moves funds on another rail: `/sign-x402` (EIP-3009 transfer).
    MoneyMoving,
    /// `/sign` (HL kind / opaque HMAC body) and `/sign/binance-request` (op).
    BodyDecides,
    /// Always allowed: `/tenant/halt` (escalate-only by construction).
    Exempt,
    /// Not classified — treated as exposure-creating (fail-closed).
    Unknown,
}

pub fn classify(method: &Method, path: &str) -> RouteClass {
    let p = path.trim_end_matches('/');
    match (method, p) {
        (&Method::POST, "/tenant/halt") => RouteClass::Exempt,
        // Exempt like `/tenant/halt`, and for the mirror-image reason: halt is
        // the one call that must work when everything is stopped, and the
        // heartbeat is the one call that must still ANSWER when everything is
        // stopped. A kill switch that also destroys the audit trail turns an
        // incident into an unexaminable one. It signs nothing a venue accepts
        // and cannot create exposure.
        (&Method::POST, "/receipts/heartbeat") => RouteClass::Exempt,
        (&Method::POST, "/sign") | (&Method::POST, "/sign/binance-request") => {
            RouteClass::BodyDecides
        }
        (&Method::POST, "/sign-x402") => RouteClass::MoneyMoving,
        (&Method::POST, "/hedge") => RouteClass::Order,
        (&Method::POST, x) if x.starts_with("/sign/") && x.ends_with("-order") => RouteClass::Order,
        (&Method::POST, x) if x.starts_with("/sign/") && x.ends_with("-cancel") => {
            RouteClass::Cancel
        }
        (&Method::POST, x) if x.starts_with("/cancel-all/") => RouteClass::Cancel,
        (&Method::GET, x)
            if x.starts_with("/account/")
                || x.starts_with("/open-orders/")
                || x.starts_with("/user-trades/") =>
        {
            RouteClass::Read
        }
        _ => RouteClass::Unknown,
    }
}

/// The decision matrix. `Ok(())` = proceed; `Err(code)` = deny with that wire
/// code. `BodyDecides` in CANCEL_ONLY proceeds here and is settled by the
/// handler.
pub fn decide(state: TenantState, class: RouteClass) -> Result<(), &'static str> {
    match state {
        TenantState::Active => Ok(()),
        TenantState::CancelOnly => match class {
            RouteClass::Cancel
            | RouteClass::Read
            | RouteClass::Exempt
            | RouteClass::BodyDecides => Ok(()),
            RouteClass::Order | RouteClass::MoneyMoving | RouteClass::Unknown => {
                Err(err_code::TENANT_CANCEL_ONLY)
            }
        },
        TenantState::Halted => match class {
            RouteClass::Exempt => Ok(()),
            _ => Err(err_code::TENANT_HALTED),
        },
    }
}

fn deny(code: &'static str, customer: &str, class: RouteClass, state: TenantState) -> Response {
    warn!(
        event = "tenant_state_denied",
        customer = %customer,
        class = ?class,
        state = state.as_str(),
        code,
    );
    crate::handlers::error_response(code)
}

/// Middleware: enforce the tenant state for path-classified routes. Runs
/// after `require_bearer` (needs `ResolvedCustomer`) and before the rate
/// limiter. No customer (no-auth dev mode) ⇒ nothing to key on ⇒ pass.
pub async fn tenant_state_mw(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(ResolvedCustomer(customer)) = req.extensions().get::<ResolvedCustomer>().cloned()
    else {
        return next.run(req).await;
    };
    let tstate = state.tenants.state_of(&customer);
    if tstate == TenantState::Active {
        return next.run(req).await;
    }
    let class = classify(req.method(), req.uri().path());
    match decide(tstate, class) {
        Ok(()) => next.run(req).await,
        Err(code) => deny(code, &customer, class, tstate),
    }
}

/// Handler-level gate for `BodyDecides` routes, called once the action/op is
/// known. `class` is what the body turned out to be (`Order`, `Cancel`,
/// `Read`, or `Unknown` for an opaque HMAC body the gateway cannot classify —
/// which is denied in CANCEL_ONLY because it could place an order).
pub fn body_route_gate(
    state: &AppState,
    customer: &str,
    class: RouteClass,
) -> Option<(Response, &'static str)> {
    let tstate = state.tenants.state_of(customer);
    match decide(tstate, class) {
        Ok(()) => None,
        // The code travels with the response: a tenant can move to HALTED
        // between the middleware check and this gate, and the log line must
        // name what the body says (CodeRabbit).
        Err(code) => Some((deny(code, customer, class, tstate), code)),
    }
}

/// Per-request tracing span carrying the tenant dimension. Before this, no
/// lifecycle event named the customer (`request_finished` had latency /
/// success / code only), so "what did tenant X do in the last hour" could not
/// be answered from the gateway log at all. Installed right inside auth so
/// every event below — gates, handler `*_received`, `request_finished`,
/// tenant denials — inherits `customer`, `method`, `path`.
pub async fn request_span_mw(req: Request, next: Next) -> Response {
    let customer = req
        .extensions()
        .get::<ResolvedCustomer>()
        .map(|c| c.0.clone())
        .unwrap_or_else(|| "-".to_owned());
    let span = tracing::info_span!(
        "req",
        customer = %customer,
        method = %req.method(),
        path = %req.uri().path(),
    );
    next.run(req).instrument(span).await
}

// ── Client self-halt (tenant router) ────────────────────────────────────────

#[derive(Deserialize)]
pub struct ClientHaltRequest {
    /// `cancel_only` | `halted`. `active` is refused — a bearer never releases.
    pub level: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize)]
pub struct TenantStateView {
    pub customer: String,
    pub state: &'static str,
    pub since_unix: Option<u64>,
    pub by: Option<&'static str>,
    pub reason: Option<String>,
    pub changed: bool,
    pub durable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconcile: Option<ReconcileStatus>,
}

fn view(state: &AppState, customer: &str, changed: bool) -> TenantStateView {
    let rec = state.tenants.record(customer);
    TenantStateView {
        customer: customer.to_owned(),
        state: rec.as_ref().map(|r| r.state.as_str()).unwrap_or("active"),
        since_unix: rec.as_ref().map(|r| r.since_unix),
        by: rec.as_ref().map(|r| r.by.as_str()),
        reconcile: rec.as_ref().and_then(|r| r.reconcile.clone()),
        reason: rec.map(|r| r.reason),
        changed,
        durable: state.tenants.durable(),
    }
}

fn hint(status: StatusCode, code: &str, hint: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": code, "hint": hint })),
    )
        .into_response()
}

/// `POST /tenant/halt` — the customer stops THEMSELVES. Escalate-only,
/// idempotent. Release is not reachable with a bearer by construction.
pub async fn post_tenant_halt(
    State(state): State<AppState>,
    Extension(ResolvedCustomer(customer)): Extension<ResolvedCustomer>,
    Json(req): Json<ClientHaltRequest>,
) -> Response {
    let Some(level) = TenantState::parse(&req.level) else {
        return hint(
            StatusCode::BAD_REQUEST,
            err_code::BAD_REQUEST,
            "level must be cancel_only or halted",
        );
    };
    if level == TenantState::Active {
        return hint(
            StatusCode::FORBIDDEN,
            err_code::POLICY_DENIED,
            "a bearer token can only escalate; release is an operator action",
        );
    }
    let reason = if req.reason.trim().is_empty() {
        "client self-halt".to_owned()
    } else {
        req.reason.trim().chars().take(200).collect()
    };
    match state.tenants.transition(
        &customer,
        level,
        Actor::Client,
        &reason,
        crate::limits::now_unix_secs(),
    ) {
        Ok(Transition::Changed { .. }) => {
            crate::reconcile::kick(state.clone(), &customer);
            Json(view(&state, &customer, true)).into_response()
        }
        Ok(Transition::Unchanged(_)) => Json(view(&state, &customer, false)).into_response(),
        Err(e) => hint(StatusCode::CONFLICT, err_code::BAD_REQUEST, e.as_str()),
    }
}

// ── Operator admin (Unix socket) ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AdminSetRequest {
    pub state: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize)]
struct TenantsView {
    durable: bool,
    path: Option<String>,
    tenants: Vec<TenantEntryView>,
}

#[derive(Serialize)]
struct TenantEntryView {
    customer: String,
    state: &'static str,
    since_unix: u64,
    by: &'static str,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reconcile: Option<ReconcileStatus>,
}

async fn admin_list(State(state): State<AppState>) -> Response {
    let tenants = state
        .tenants
        .all()
        .into_iter()
        .map(|(customer, r)| TenantEntryView {
            customer,
            state: r.state.as_str(),
            since_unix: r.since_unix,
            by: r.by.as_str(),
            reason: r.reason,
            reconcile: r.reconcile,
        })
        .collect();
    Json(TenantsView {
        durable: state.tenants.durable(),
        path: state.tenants.path().map(|p| p.display().to_string()),
        tenants,
    })
    .into_response()
}

async fn admin_get(
    State(state): State<AppState>,
    AxumPath(customer): AxumPath<String>,
) -> Response {
    Json(view(&state, &customer, false)).into_response()
}

async fn admin_set(
    State(state): State<AppState>,
    AxumPath(customer): AxumPath<String>,
    Json(req): Json<AdminSetRequest>,
) -> Response {
    let Some(to) = TenantState::parse(&req.state) else {
        return hint(
            StatusCode::BAD_REQUEST,
            err_code::BAD_REQUEST,
            "state must be active | cancel_only | halted",
        );
    };
    if customer.trim().is_empty() || customer.len() > 128 {
        return hint(
            StatusCode::BAD_REQUEST,
            err_code::BAD_REQUEST,
            "bad customer label",
        );
    }
    warn!(event = "tenant_admin_request", customer = %customer, to = to.as_str(), reason = %req.reason.trim());
    match state.tenants.transition(
        &customer,
        to,
        Actor::Operator,
        &req.reason,
        crate::limits::now_unix_secs(),
    ) {
        Ok(Transition::Changed { .. }) => {
            crate::reconcile::kick(state.clone(), &customer);
            Json(view(&state, &customer, true)).into_response()
        }
        Ok(Transition::Unchanged(_)) => Json(view(&state, &customer, false)).into_response(),
        Err(e) => hint(StatusCode::CONFLICT, err_code::BAD_REQUEST, e.as_str()),
    }
}

/// The operator router. NO bearer: reachability of the socket file is the
/// credential (mode 0660, owner = gateway user, group = the operators).
pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/tenants", get(admin_list))
        .route("/tenant/{customer}", get(admin_get))
        .route("/tenant/{customer}/state", post(admin_set))
        .with_state(state)
}

/// Bind the operator socket at BOOT — a failure here fails the boot. A gateway
/// that serves signing traffic with no operator control path is exactly the
/// state the kill switch exists to prevent (CodeRabbit). Removes a stale
/// socket file (only if it IS a socket — never an arbitrary file).
///
/// Permissions are made independent of the process umask: the socket is bound
/// under an unguessable temporary name, chmod'ed to 0660, then renamed into
/// place — so the final path never exists with a wider mode, whatever the
/// umask (CodeRabbit). A 0750 parent directory is the documented second layer.
pub fn bind_admin_socket(path: &Path) -> anyhow::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            anyhow::bail!(
                "{} exists and is not a socket — refusing to replace it",
                path.display()
            );
        }
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("admin socket path has no file name"))?;
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = std::os::unix::net::UnixListener::bind(&tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o660))?;
    std::fs::rename(&tmp, path)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    info!(event = "tenant_admin_socket_bound", path = %path.display());
    Ok(listener)
}

/// Accept loop for the operator socket, same hyper http1 settings as the TCP
/// front (no keep-alive). Takes a listener from `bind_admin_socket`.
pub async fn serve_admin_socket(
    listener: tokio::net::UnixListener,
    app: Router,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::Service;

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.timer(TokioTimer::new()).keep_alive(false);
    let builder = Arc::new(builder);
    let make_service = app.into_make_service();
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                warn!(error = %err, "admin socket accept failed; continuing");
                continue;
            }
        };
        let mut make_service = make_service.clone();
        let builder = builder.clone();
        tokio::spawn(async move {
            let svc: Router = match make_service.call(()).await {
                Ok(svc) => svc,
                Err(_unreachable) => return,
            };
            let hyper_svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut svc = svc.clone();
                    async move { svc.call(req).await }
                });
            if let Err(err) = builder
                .serve_connection(TokioIo::new(stream), hyper_svc)
                .await
            {
                tracing::debug!(error = %err, "admin connection finished with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("tenant-state-{tag}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn client_can_escalate_but_never_release() {
        let s = TenantStateStore::in_memory();
        assert_eq!(s.state_of("a"), TenantState::Active);
        assert_eq!(
            s.transition("a", TenantState::CancelOnly, Actor::Client, "", 10),
            Ok(Transition::Changed {
                from: TenantState::Active,
                to: TenantState::CancelOnly
            })
        );
        // idempotent
        assert_eq!(
            s.transition("a", TenantState::CancelOnly, Actor::Client, "", 11),
            Ok(Transition::Unchanged(TenantState::CancelOnly))
        );
        assert_eq!(
            s.transition("a", TenantState::Halted, Actor::Client, "", 12),
            Ok(Transition::Changed {
                from: TenantState::CancelOnly,
                to: TenantState::Halted
            })
        );
        // release by client: refused
        assert_eq!(
            s.transition("a", TenantState::Active, Actor::Client, "", 13),
            Err(TransitionError::NotEscalation {
                current: TenantState::Halted,
                requested: TenantState::Active
            })
        );
        assert_eq!(
            s.transition("a", TenantState::CancelOnly, Actor::Client, "", 14),
            Err(TransitionError::NotEscalation {
                current: TenantState::Halted,
                requested: TenantState::CancelOnly
            })
        );
        assert_eq!(s.state_of("a"), TenantState::Halted);
        // other tenants untouched
        assert_eq!(s.state_of("b"), TenantState::Active);
    }

    #[test]
    fn automation_only_reaches_cancel_only() {
        let s = TenantStateStore::in_memory();
        assert_eq!(
            s.transition("a", TenantState::Halted, Actor::Automation, "", 1),
            Err(TransitionError::AutomationScope)
        );
        assert_eq!(
            s.transition("a", TenantState::Active, Actor::Automation, "", 1),
            Err(TransitionError::AutomationScope)
        );
        assert!(matches!(
            s.transition(
                "a",
                TenantState::CancelOnly,
                Actor::Automation,
                "breaker open",
                1
            ),
            Ok(Transition::Changed { .. })
        ));
    }

    #[test]
    fn operator_releases_with_reason_only() {
        let s = TenantStateStore::in_memory();
        s.transition("a", TenantState::Halted, Actor::Client, "", 1)
            .unwrap();
        assert_eq!(
            s.transition("a", TenantState::Active, Actor::Operator, "   ", 2),
            Err(TransitionError::ReasonRequired)
        );
        assert_eq!(
            s.transition(
                "a",
                TenantState::Active,
                Actor::Operator,
                "incident closed",
                2
            ),
            Ok(Transition::Changed {
                from: TenantState::Halted,
                to: TenantState::Active
            })
        );
        assert_eq!(s.state_of("a"), TenantState::Active);
        let rec = s.record("a").unwrap();
        assert_eq!(rec.by, Actor::Operator);
        assert_eq!(rec.reason, "incident closed");
    }

    #[test]
    fn halt_survives_reload() {
        let p = tmp("reload");
        {
            let s = TenantStateStore::load(p.clone()).unwrap();
            s.transition("dogfood", TenantState::CancelOnly, Actor::Client, "", 100)
                .unwrap();
            s.transition("other", TenantState::Halted, Actor::Operator, "drill", 101)
                .unwrap();
            assert!(s.durable());
        }
        let s2 = TenantStateStore::load(p.clone()).unwrap();
        assert_eq!(s2.state_of("dogfood"), TenantState::CancelOnly);
        assert_eq!(s2.state_of("other"), TenantState::Halted);
        assert_eq!(s2.state_of("unknown"), TenantState::Active);
        assert_eq!(s2.record("other").unwrap().reason, "drill");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unparseable_file_refuses_to_boot() {
        let p = tmp("garbage");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(TenantStateStore::load(p.clone()).is_err());
        let _ = std::fs::remove_file(&p);
    }

    /// A path whose parent is a REGULAR FILE: `create_dir_all` fails with
    /// ENOTDIR for every user, root included — unlike a nonexistent absolute
    /// directory, which root could simply create (CodeRabbit).
    fn unwritable_path(tag: &str) -> PathBuf {
        let parent = tmp(&format!("{tag}-parent-file"));
        std::fs::write(&parent, b"i am a file, not a directory").unwrap();
        parent.join("state.json")
    }

    #[test]
    fn disk_failure_still_applies_in_memory() {
        let p = unwritable_path("diskfail");
        let s = TenantStateStore {
            inner: RwLock::new(HashMap::new()),
            path: Some(p),
            durable: AtomicBool::new(true),
        };
        assert!(matches!(
            s.transition("a", TenantState::Halted, Actor::Client, "", 1),
            Ok(Transition::Changed { .. })
        ));
        assert_eq!(
            s.state_of("a"),
            TenantState::Halted,
            "halt applied despite the disk"
        );
        assert!(!s.durable(), "store must flag itself non-durable");
    }

    #[test]
    fn boot_probe_refuses_unwritable_path_and_accepts_writable() {
        let bad = TenantStateStore {
            inner: RwLock::new(HashMap::new()),
            path: Some(unwritable_path("probe-bad")),
            durable: AtomicBool::new(true),
        };
        assert!(
            bad.boot_probe().is_err(),
            "unwritable path must fail the boot probe"
        );
        let p = tmp("probe");
        let good = TenantStateStore::load(p.clone()).unwrap();
        good.boot_probe().unwrap();
        assert!(
            p.exists(),
            "probe writes the (empty) state file through the atomic path"
        );
        assert!(good.durable());
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn admin_socket_bind_mode_and_stale_handling() {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("tenant-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("admin.sock");
        // Fresh bind: socket exists with mode 0660 regardless of umask.
        let l1 = bind_admin_socket(&path).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o660);
        drop(l1);
        // Stale socket file from a previous run is replaced.
        let l2 = bind_admin_socket(&path).unwrap();
        drop(l2);
        // A regular file at the path is NEVER replaced.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"not a socket").unwrap();
        assert!(
            bind_admin_socket(&path).is_err(),
            "must refuse to replace a non-socket"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classification_table() {
        use RouteClass::*;
        let c = |m: Method, p: &str| classify(&m, p);
        assert_eq!(c(Method::POST, "/sign/binance-order"), Order);
        assert_eq!(c(Method::POST, "/sign/binance-spot-order"), Order);
        assert_eq!(c(Method::POST, "/sign/okx-order"), Order);
        assert_eq!(c(Method::POST, "/hedge"), Order);
        assert_eq!(c(Method::POST, "/sign/binance-cancel"), Cancel);
        assert_eq!(c(Method::POST, "/sign/okx-cancel"), Cancel);
        assert_eq!(c(Method::POST, "/cancel-all/binance"), Cancel);
        assert_eq!(c(Method::GET, "/account/okx"), Read);
        assert_eq!(c(Method::GET, "/open-orders/binance"), Read);
        assert_eq!(c(Method::GET, "/user-trades/binance"), Read);
        assert_eq!(c(Method::POST, "/sign-x402"), MoneyMoving);
        assert_eq!(c(Method::POST, "/sign"), BodyDecides);
        assert_eq!(c(Method::POST, "/sign/binance-request"), BodyDecides);
        assert_eq!(c(Method::POST, "/tenant/halt"), Exempt);
        // The audit read survives a stop, by the same rule that lets the stop
        // itself through. A kill switch that also silences the evidence turns
        // an incident into one nobody can examine afterwards.
        assert_eq!(c(Method::POST, "/receipts/heartbeat"), Exempt);
        assert!(
            decide(TenantState::Halted, Exempt).is_ok(),
            "a HALTED tenant must still be able to ask what was decided"
        );
        // fail-closed for anything unclassified
        assert_eq!(c(Method::POST, "/sign/newvenue-transfer"), Unknown);
        assert_eq!(c(Method::GET, "/something"), Unknown);
    }

    #[test]
    fn decision_matrix() {
        use RouteClass::*;
        use TenantState::*;
        for class in [
            Order,
            Cancel,
            Read,
            MoneyMoving,
            BodyDecides,
            Exempt,
            Unknown,
        ] {
            assert_eq!(decide(Active, class), Ok(()));
        }
        assert_eq!(decide(CancelOnly, Cancel), Ok(()));
        assert_eq!(decide(CancelOnly, Read), Ok(()));
        assert_eq!(decide(CancelOnly, Exempt), Ok(()));
        assert_eq!(decide(CancelOnly, BodyDecides), Ok(()));
        assert_eq!(decide(CancelOnly, Order), Err(err_code::TENANT_CANCEL_ONLY));
        assert_eq!(
            decide(CancelOnly, MoneyMoving),
            Err(err_code::TENANT_CANCEL_ONLY)
        );
        assert_eq!(
            decide(CancelOnly, Unknown),
            Err(err_code::TENANT_CANCEL_ONLY)
        );
        for class in [Order, Cancel, Read, MoneyMoving, BodyDecides, Unknown] {
            assert_eq!(decide(Halted, class), Err(err_code::TENANT_HALTED));
        }
        assert_eq!(decide(Halted, Exempt), Ok(()));
    }

    // ── End-to-end over a real listener: two tenants, one router ───────────

    /// Fake auth: the test names the tenant in a header. Stands in for
    /// `require_bearer`, which is what inserts `ResolvedCustomer` in prod.
    async fn fake_auth(mut req: Request, next: Next) -> Response {
        if let Some(c) = req
            .headers()
            .get("x-test-customer")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        {
            req.extensions_mut().insert(ResolvedCustomer(c));
        }
        next.run(req).await
    }

    async fn ok() -> &'static str {
        "ok"
    }

    async fn spawn(state: AppState) -> String {
        let app = Router::new()
            .route("/sign/binance-order", post(ok))
            .route("/sign/okx-cancel", post(ok))
            .route("/cancel-all/{venue}", post(ok))
            .route("/account/{venue}", get(ok))
            .route("/sign-x402", post(ok))
            .route("/hedge", post(ok))
            .route("/sign/new-thing", post(ok)) // unclassified on purpose
            .route("/tenant/halt", post(post_tenant_halt))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                tenant_state_mw,
            ))
            .route_layer(axum::middleware::from_fn(request_span_mw))
            .route_layer(axum::middleware::from_fn(fake_auth))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        format!("http://{addr}")
    }

    async fn call(
        base: &str,
        customer: &str,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let client = reqwest::Client::new();
        let mut rb = client
            .request(method, format!("{base}{path}"))
            .header("x-test-customer", customer);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (status, json)
    }

    #[tokio::test]
    async fn end_to_end_three_states_two_tenants() {
        use crate::state::EnclaveTarget;
        let state = AppState::new(HashMap::new(), EnclaveTarget { cid: 0, port: 0 });
        let base = spawn(state.clone()).await;
        let (a, b) = ("tenant-a", "tenant-b");

        // ACTIVE: everything passes.
        assert_eq!(
            call(&base, a, Method::POST, "/sign/binance-order", None)
                .await
                .0,
            200
        );
        assert_eq!(
            call(&base, a, Method::POST, "/sign/new-thing", None)
                .await
                .0,
            200
        );

        // A halts itself to CANCEL_ONLY with its bearer.
        let (st, body) = call(
            &base,
            a,
            Method::POST,
            "/tenant/halt",
            Some(serde_json::json!({"level": "cancel_only"})),
        )
        .await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body["state"], "cancel_only");
        assert_eq!(body["changed"], true);
        assert_eq!(body["by"], "client");

        // CANCEL_ONLY: orders / x402 / hedge / unclassified denied with the
        // explainable class; cancels and reads pass.
        for path in [
            "/sign/binance-order",
            "/sign-x402",
            "/hedge",
            "/sign/new-thing",
        ] {
            let (st, body) = call(&base, a, Method::POST, path, None).await;
            assert_eq!(st, 403, "{path}: {body}");
            assert_eq!(body["error"], "tenant_cancel_only", "{path}");
            assert_eq!(body["rule_class"], "tenant_state", "{path}");
            assert_eq!(body["denied"], true, "{path}");
        }
        assert_eq!(
            call(&base, a, Method::POST, "/sign/okx-cancel", None)
                .await
                .0,
            200
        );
        assert_eq!(
            call(&base, a, Method::POST, "/cancel-all/binance", None)
                .await
                .0,
            200
        );
        assert_eq!(
            call(&base, a, Method::GET, "/account/okx", None).await.0,
            200
        );

        // Isolation: B is untouched.
        assert_eq!(
            call(&base, b, Method::POST, "/sign/binance-order", None)
                .await
                .0,
            200
        );

        // Idempotent re-press.
        let (st, body) = call(
            &base,
            a,
            Method::POST,
            "/tenant/halt",
            Some(serde_json::json!({"level": "cancel_only"})),
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(body["changed"], false);

        // Escalate to HALTED: even cancels and reads are refused now; the
        // halt endpoint itself stays reachable (idempotent, escalate-only).
        let (st, _) = call(
            &base,
            a,
            Method::POST,
            "/tenant/halt",
            Some(serde_json::json!({"level": "halted", "reason": "bot compromised"})),
        )
        .await;
        assert_eq!(st, 200);
        for (m, path) in [
            (Method::POST, "/sign/okx-cancel"),
            (Method::POST, "/cancel-all/binance"),
            (Method::GET, "/account/okx"),
            (Method::POST, "/sign/binance-order"),
        ] {
            let (st, body) = call(&base, a, m, path, None).await;
            assert_eq!(st, 403, "{path}: {body}");
            assert_eq!(body["error"], "tenant_halted", "{path}");
        }
        let (st, body) = call(
            &base,
            a,
            Method::POST,
            "/tenant/halt",
            Some(serde_json::json!({"level": "halted"})),
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(body["changed"], false);

        // The bearer cannot release — neither to active nor back to cancel_only.
        let (st, _) = call(
            &base,
            a,
            Method::POST,
            "/tenant/halt",
            Some(serde_json::json!({"level": "active"})),
        )
        .await;
        assert_eq!(st, 403);
        let (st, body) = call(
            &base,
            a,
            Method::POST,
            "/tenant/halt",
            Some(serde_json::json!({"level": "cancel_only"})),
        )
        .await;
        assert_eq!(st, 409, "{body}");
        assert_eq!(body["hint"], "not_an_escalation");
        assert_eq!(state.tenants.state_of(a), TenantState::Halted);

        // Operator release (what the admin socket does) restores service.
        state
            .tenants
            .transition(a, TenantState::Active, Actor::Operator, "drill over", 1)
            .unwrap();
        assert_eq!(
            call(&base, a, Method::POST, "/sign/binance-order", None)
                .await
                .0,
            200
        );
        // B never noticed any of it.
        assert_eq!(
            call(&base, b, Method::POST, "/sign/binance-order", None)
                .await
                .0,
            200
        );
    }
}
