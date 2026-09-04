//! Usenami Signer HTTP gateway.
//!
//! axum-based HTTP server that fronts the Nitro-Enclave signer. Listens on
//! `0.0.0.0:<--port>` (default 8443). The plan is for the VPS to reach this
//! via SSH tunnel — there is no TLS terminator here on Day 3 (PoC).
//!
//! Configuration (CLI flags + env):
//!   - `--bind 0.0.0.0:8443`       — address to listen on.
//!   - `--enclave-cid 16`          — vsock CID where the enclave runs.
//!   - `--enclave-port 5000`       — vsock port the enclave listens on.
//!   - `--blob-path /var/lib/...`  — path to the KMS-encrypted ciphertext
//!     blob (operator pre-stages with `aws s3 cp`).
//!
//! Request body limits: enforced by `tower-http::limit::RequestBodyLimitLayer`
//! at 32 KiB. Anything larger gets a `413 payload_too_large` before the body
//! is even read.

mod auth;
mod aws;
mod backoff;
mod handlers;
mod hedge;
mod limits;
mod proto;
mod receipts;
mod reconcile;
mod state;
mod tenant_state;
mod vsock;

use anyhow::{Context, Result};
use axum::error_handling::HandleErrorLayer;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::BoxError;
use axum::Router;
use clap::Parser;
use hyper::body::Incoming;
use hyper::server::conn::http1 as hyper_http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tower::{Service, ServiceBuilder};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::state::{
    blob_key, AppState, BlobBundle, EnclaveTarget, DATA_SIGNING_CUSTOMER, DATA_SIGNING_STEM,
    DEFAULT_CUSTOMER_ID,
};

/// Exchanges this gateway can serve. Each gets one blob file in
/// `--blobs-dir` named `{exchange}.enc`. Blobs not present at startup are
/// skipped — operator can stage them later and restart.
const SUPPORTED_EXCHANGES: &[&str] = &[
    "asterdex",
    "kucoin",
    "binance",
    "binance_futures",
    "bybit",
    "okx",
    "hyperliquid_main",
    // HL TESTNET demo agent-wallet blob (`hyperliquid_testnet.enc`).
    "hyperliquid_testnet",
];

/// Maximum HTTP request body the gateway accepts. Realistic KuCoin order
/// bodies are well under 1 KiB; 32 KiB is a generous cap.
const MAX_REQUEST_BYTES: usize = 32 * 1024;

/// C30 (ZLODEY 2026-05-18): total per-request timeout at the HTTP layer
/// (after hyper has parsed headers and dispatched into the tower stack).
/// Body-phase slow-loris and slow-handler DoS are bounded by this.
///
/// TCP-level slow-loris (trickled headers before hyper parses the request)
/// is bounded SEPARATELY by `HEADER_READ_TIMEOUT_SECS` via the manual
/// hyper-util Builder in the accept loop below (C30.next).
///
/// Capacity math: with 30s timeout and 256 slots, sustained ~8.5 req/s
/// of slow attacker connections fills the pool. Tighten if pilot load
/// proves /sign p99 well under 1s.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// C30.next (ZLODEY 2026-05-18): TCP-level slow-loris hardening.
///
/// `header_read_timeout` bounds how long hyper will wait for the
/// request headers to fully arrive after the TCP connection is
/// established. An attacker who opens a socket and writes 1 byte every
/// N seconds keeps the connection alive but never finishes the headers
/// — without this bound, the connection sits in hyper's pre-dispatch
/// state indefinitely, consuming a file descriptor per slow client.
/// The tower-http TimeoutLayer ONLY fires after hyper has dispatched
/// into the tower stack, which never happens for never-finished
/// headers.
///
/// 2 seconds is well under any plausible legitimate browser/SDK
/// header-send time (typically <100ms) while still allowing Cloudflare's
/// origin-fetch worst case (sub-second on a healthy edge) to complete.
/// Tightened from 10s → 2s after pilot traffic confirmed no
/// false-positive timeouts (Gemini PR #46 round-3 MED: docs now
/// reflect the hardened value).
const HEADER_READ_TIMEOUT_SECS: u64 = 2;

/// C30: cap on concurrent in-flight requests. Combined with the load
/// shedder below, the gateway responds 503 to the (N+1)th request
/// instead of queueing it (queueing would itself amplify DoS impact).
/// Default 256 is comfortably above quant-pilot peak (~10 concurrent
/// /sign in flight at peak in dogfood).
const MAX_CONCURRENT_REQUESTS: usize = 256;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Usenami Signer HTTP gateway (axum + vsock client to enclave)"
)]
struct Cli {
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    /// vsock CID where the enclave is running.
    #[arg(long, default_value_t = 16)]
    enclave_cid: u32,

    /// vsock port the enclave listens on.
    #[arg(long, default_value_t = 5000)]
    enclave_port: u32,

    /// Path to the KMS-encrypted KuCoin blob (legacy single-exchange flag).
    /// Use `--blobs-dir` for multi-exchange. If both are set, blobs-dir wins.
    #[arg(long, env = "SIGNER_BLOB_PATH")]
    blob_path: Option<String>,

    /// Directory containing per-exchange blob files: `kucoin.enc`,
    /// `binance.enc`, `binance_futures.enc`, `bybit.enc`. Missing files are
    /// skipped (the gateway will return `bad_request` if an unconfigured
    /// exchange is requested).
    #[arg(long, env = "SIGNER_BLOBS_DIR")]
    blobs_dir: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    info!(
        bind = %cli.bind,
        enclave_cid = cli.enclave_cid,
        enclave_port = cli.enclave_port,
        blob_path = ?cli.blob_path,
        blobs_dir = ?cli.blobs_dir,
        "signer-gateway starting"
    );

    let blobs = load_all_blobs(&cli)?;
    if blobs.is_empty() {
        anyhow::bail!("no exchange blobs loaded — set --blobs-dir or --blob-path");
    }
    let exchange_list: Vec<&str> = blobs.keys().map(String::as_str).collect();
    info!(exchanges = ?exchange_list, "ciphertext blobs loaded");

    // B3 (mainnet gate): per-token daily order counter (fail-closed) +
    // per-token rate limit. Fail-loud on misconfig; when the daily cap is
    // enabled, probe the counter file NOW so an unwritable path fails the
    // boot instead of denying every order at runtime.
    let b3_limits = limits::Limits::from_env().context("load B3 limits config")?;
    b3_limits
        .boot_probe()
        .context("B3 daily-counter state file probe (SIGNER_DAILY_COUNTER_PATH)")?;

    let state = AppState::new(
        blobs,
        EnclaveTarget {
            cid: cli.enclave_cid,
            port: cli.enclave_port,
        },
    )
    // Attested-signed-data (P2): the enclave opaque_token forwarded for sign_data
    // (resolves to the data-signing service identity). None until provisioned.
    .with_data_signing_token(std::env::var("SIGNER_DATA_SIGNING_TOKEN").ok())
    .with_limits(b3_limits)
    .with_tenants({
        let path = std::env::var(tenant_state::STATE_PATH_ENV)
            .ok()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| tenant_state::DEFAULT_STATE_PATH.to_owned());
        let store = tenant_state::TenantStateStore::load(std::path::PathBuf::from(&path))
            .with_context(|| format!("load tenant-state file {path}"))?;
        // Prove the path is WRITABLE at boot (same discipline as the daily
        // counter): an unwritable /var/lib/signer must fail here, not at the
        // first halt.
        store.boot_probe().with_context(|| {
            format!(
                "tenant-state file {path} is not writable ({})",
                tenant_state::STATE_PATH_ENV
            )
        })?;
        store
    });

    // C22 (ZLODEY 2026-05-18): load bearer-token config and apply to /sign.
    // Healthz stays unauthenticated for Cloudflare/AWS liveness probes.
    // When SIGNER_API_TOKENS is unset, AuthState::from_env logs a loud
    // warning and the middleware passes through (backward compat).
    // Gemini PR #29 round-4: from_env now returns Result; propagate via `?`
    // so anyhow attaches a proper context chain when main() reports the
    // boot failure (instead of a bare panic).
    let auth_state = auth::AuthState::from_env().context("load SIGNER_API_TOKENS")?;

    let sign_router = Router::new()
        .route("/sign", post(handlers::post_sign))
        // x402 / EIP-3009 signing endpoint (PR #74 primitive). Same auth +
        // dos-hardening as /sign — it produces a payment authorization.
        .route("/sign-x402", post(handlers::post_sign_x402))
        // NOTE: `/attestation` is intentionally NOT here — it is a PUBLIC,
        // no-bearer route (see `public_router` below). It used to live on this
        // bearer-gated router, which made the signer-mcp proof tool return 401.
        // signer-mcp signed-read tool: per-venue signed account-read
        // (Option A — gateway never calls the venue; MCP submits + parses).
        .route("/account/{venue}", get(handlers::get_account))
        // Signed enumerate (reconcile orders an agent lost the id for) + signed
        // mass-cancel. Reuse the GENERIC sign_binance/sign_okx action via
        // sign_account_read — no enclave change / no PCR0 cutover. Tenant-authed.
        .route("/open-orders/{venue}", get(handlers::get_open_orders))
        // gate-2: signed read of own filled-trade history (audit without a raw
        // key). Binance only in v0; OKX fills-history fast-follows.
        .route("/user-trades/{venue}", get(handlers::get_user_trades))
        .route("/cancel-all/{venue}", post(handlers::post_cancel_all))
        // Binance USD-M Futures trade signing — structured order/cancel in,
        // venue-canonical signed bytes out (enclave builds canonical inside).
        .route(
            "/sign/binance-order",
            post(handlers::post_sign_binance_order),
        )
        .route(
            "/sign/binance-request",
            post(handlers::post_sign_binance_request),
        )
        .route(
            "/sign/binance-cancel",
            post(handlers::post_sign_binance_cancel),
        )
        // Binance SPOT trade signing (`/api/v3/order` on api.binance.com).
        // Reuses the futures ACTIONS on purpose — the enclave takes the path
        // from us and builds the canonical itself, so spot is a path + policy
        // change, not new enclave code (no PCR0 rotation). See the doctrine
        // note above these handlers, incl. why spot wants its OWN blob stem.
        .route(
            "/sign/binance-spot-order",
            post(handlers::post_sign_binance_spot_order),
        )
        .route(
            "/sign/binance-spot-cancel",
            post(handlers::post_sign_binance_spot_cancel),
        )
        // OKX v5 perp trade signing — byte-exact JSON body signed inside the
        // enclave and forwarded verbatim (re-serialization would invalidate
        // the OK-ACCESS-SIGN HMAC). Cancel is POST not DELETE.
        .route("/sign/okx-order", post(handlers::post_sign_okx_order))
        .route("/sign/okx-cancel", post(handlers::post_sign_okx_cancel))
        // Atomic 2-leg hedge: sign both legs (all-or-nothing), then the
        // gateway executes both venue calls in parallel from the box. The
        // ONLY endpoint where the gateway itself calls venues (deliberate
        // Option-A exception — see hedge.rs doctrine note). Same auth +
        // dos-hardening stack as /sign.
        .route("/hedge", post(hedge::post_hedge))
        // Signed counter heartbeat: ask the ENCLAVE how many decisions it has
        // made for this tenant. The one call whose purpose is to catch this
        // very gateway hiding a decision, so it sits on the tenant router (the
        // tenant's own bearer resolves the identity inside the enclave) and
        // carries nothing the gateway chooses.
        .route(
            "/receipts/heartbeat",
            post(handlers::post_receipt_heartbeat),
        )
        // B3 (в): per-token rate limit across the WHOLE tenant sign tier.
        // Registered BEFORE require_bearer in the builder chain → INNER layer
        // (axum: later layers wrap earlier ones), so it runs AFTER auth and
        // reads the RawToken extension — only authenticated requests spend
        // limiter state. The daily ORDER counter (б) is NOT a layer here: it
        // is body-aware (HL `kind`, binance-request `op`) and lives in the
        // order-placing handlers via `Limits::check_and_count_order`.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            limits::rate_limit_mw,
        ))
        // Per-tenant kill switch: OUTSIDE the rate limiter (a halted bot's
        // retries must not drain the bucket a legitimate cancel needs) and
        // INSIDE auth (needs ResolvedCustomer). Path-classified routes are
        // settled here; `/sign` and `/sign/binance-request` finish in-handler.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            tenant_state::tenant_state_mw,
        ))
        // Tenant dimension on every lifecycle event (customer/method/path span):
        // without it "what did tenant X do in the last hour" cannot be answered
        // from the gateway log. Directly inside auth so the span wraps
        // everything below, denials included.
        .route_layer(axum::middleware::from_fn(tenant_state::request_span_mw))
        .route_layer(axum::middleware::from_fn_with_state(
            // Cloned so the original survives the operator/tenant overlap check
            // below (LOW#2) before it is dropped.
            auth_state.clone(),
            auth::require_bearer,
        ));

    // PR-B (decision H-severity): /verify-blob lives in its OWN router behind a
    // SEPARATE operator credential (`SIGNER_OPERATOR_TOKENS`), NOT the tenant
    // tokens. On the shared sign_router a tenant token could call /verify-blob
    // and probe whether another tenant's blob exists (a cross-tenant oracle).
    // The operator router reuses the same require_bearer + dos-hardening stack.
    let operator_auth_state =
        auth::AuthState::operator_from_env().context("load SIGNER_OPERATOR_TOKENS")?;
    // crypto-panel #211 LOW#2: refuse to boot if a bearer token is configured in
    // BOTH tiers — that collapses the tenant/operator isolation the panel
    // verified (the token could reach the /sign venues AND /sign-data +
    // /verify-blob). Disjoint token sets are required.
    if operator_auth_state.shares_token_with(&auth_state) {
        anyhow::bail!(
            "a bearer token is configured in BOTH SIGNER_API_TOKENS and \
             SIGNER_OPERATOR_TOKENS — this collapses the tenant/operator isolation; \
             use disjoint token sets"
        );
    }
    // `/sign-data` (attested-signed-data P2) ALSO lives here: operator-gated, so a
    // tenant token gets 401 (it can only reach the tenant /sign venues) and an
    // operator token gets 401 on those venues — the two credential tiers never
    // cross. This is layer-1 of the data-key isolation; the enclave KMS
    // EncryptionContext (§5) is layer-2. (CTO re-reviews this ACL on the PR.)
    let operator_router = Router::new()
        .route("/verify-blob", post(handlers::post_verify_blob))
        .route("/sign-data", post(handlers::post_sign_data))
        .route_layer(axum::middleware::from_fn_with_state(
            operator_auth_state,
            auth::require_bearer,
        ));

    // PUBLIC (no-bearer) routes. `/attestation` is the signer-mcp proof tool:
    // live PCR0 + on-chain registration — secret-free, and intentionally
    // UNAUTHENTICATED so any agent can verify the trust anchor before it holds a
    // token (PCR0 is exactly what is published to the on-chain registry). The
    // payload exposes no EnclaveID / instance-id by design.
    //
    // It is merged into `app` (NOT `api_router`) so it is EXEMPT from the shared
    // `/sign` concurrency pool — same tier as `/healthz`. Rationale (Gemini PR#194
    // HIGH): the `Cache-Control: public, max-age=60` header alone does not stop a
    // *cache-busting* flood (`/attestation?x=rand` → CF cache-miss → origin); if
    // /attestation shared the bounded pool, such a flood would drain slots and
    // 503 `/sign` for real clients. The handler is cheap (a cached `OnceLock`
    // read + JSON, no enclave round-trip, no I/O) so it needs no per-request
    // concurrency cap of its own, and the connection-level cap (manual accept
    // loop) still bounds it. The cache header is retained to serve repeat reads
    // from the CF edge and cut origin work for legit traffic.
    // Body-limit the public tier too (Gemini PR#194): /attestation is a GET, but
    // an unauthenticated client could still attach an oversized body that hyper
    // must drain to reuse the keep-alive connection — 413 it early instead. This
    // is the ONLY hardening layer the public tier shares with api_router; it does
    // NOT join the concurrency pool (that's the whole point of the exemption).
    let public_router = Router::new()
        .route("/attestation", get(handlers::get_attestation))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES));

    // C30 (ZLODEY 2026-05-18): slow-loris + connection-exhaustion hardening.
    //
    // Stack on /sign (outermost → innermost; axum applies last .layer() first):
    //   1. RequestBodyLimitLayer — 413 for oversized bodies BEFORE acquiring
    //      a concurrency slot (otherwise an oversized body wastes a slot).
    //   2. HandleErrorLayer — convert tower::BoxError → HTTP response.
    //   3. LoadShedLayer — when ConcurrencyLimit is at capacity, shed the
    //      request immediately (503) instead of queueing.
    //   4. ConcurrencyLimitLayer — cap in-flight requests.
    //   5. TimeoutLayer (408) — kill any single slow request after
    //      REQUEST_TIMEOUT_SECS, freeing the slot for legit traffic.
    //   6. TraceLayer — observability (innermost so spans capture outcomes).
    //
    // /healthz is EXEMPT from dos_hardening. Without this exemption, a
    // sustained slow-loris attack on /sign would fill the concurrency pool
    // and start 503-ing /healthz too — Cloudflare would mark the origin
    // dead and stop routing ALL traffic, turning the DoS defense into a
    // DoS amplifier. Health checks must always reach the handler.
    let dos_hardening = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_middleware_error))
        .load_shed()
        .concurrency_limit(MAX_CONCURRENT_REQUESTS)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
        ));

    // 🔴 The kill switch gets its OWN router, WITHOUT the per-token rate limiter.
    //
    // Why: the press that matters happens under load. A bot that has run away is,
    // by definition, the one that saturated its own minute bucket — and on the
    // shared sign_router its next request, the halt, would be refused 429 by the
    // limiter its own traffic filled. The stop would be unreachable exactly when
    // it is needed, which is worse than not advertising one (CodeRabbit on #82;
    // the private tree has the same layering and inherits the fix).
    //
    // Safe to exempt because the route can only TIGHTEN: `post_tenant_halt`
    // escalates ACTIVE → CANCEL_ONLY → HALTED and cannot release — release is an
    // operator action over the admin socket. So an attacker holding the token
    // gains nothing by calling it repeatedly except stopping themselves. It keeps
    // auth (a bearer is still required) and the tenant span, and it is exempt from
    // the tenant-state middleware by construction.
    let halt_router = Router::new()
        .route("/tenant/halt", post(tenant_state::post_tenant_halt))
        .route_layer(axum::middleware::from_fn(tenant_state::request_span_mw))
        .route_layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            auth::require_bearer,
        ));

    let api_router = sign_router
        .merge(halt_router)
        .merge(operator_router)
        .layer(TraceLayer::new_for_http())
        .layer(dos_hardening)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES));

    // Q2a (attested-data): fail-loud at boot if the provisioned data-signing key
    // drifts from the published pubkey. Runs BEFORE `state` is moved into the
    // router; skipped (logged) when the data key isn't provisioned.
    data_signing_self_test(&state)
        .await
        .context("attested-data boot self-test")?;

    // E3: arm the periodic live-signature health probe (no-op if the data key
    // isn't provisioned or the interval is 0). Clone BEFORE `state` is moved into
    // the router below; the probe task and the handlers share the same
    // `Arc<SignHealth>` cell.
    spawn_sign_health_probe(state.clone());

    // `/attestation` (public_router) and `/healthz` ride the `app` tier — OUTSIDE
    // the dos_hardening pool that gates `/sign` — so neither can starve `/sign`.
    let app = Router::new()
        .merge(api_router)
        .merge(public_router)
        .route("/healthz", get(handlers::get_healthz))
        // Cloned: `reconcile::resume_all` and the admin-socket task below both
        // need the state after the router takes ownership. AppState is Arc-backed.
        .with_state(state.clone());

    // PR-2: restart any reconcile job a previous process left non-final — a
    // restart mid-unwind must not leave orders resting unnoticed.
    reconcile::resume_all(state.clone());

    // Cloned for the admin-socket task, which outlives this scope.
    let admin_state = state.clone();

    // Operator control socket for the per-tenant kill switch. Unix socket, no
    // bearer: the file mode (0660) is the permission to press, and no TLS
    // front can ever proxy to it. `SIGNER_ADMIN_SOCKET=off` disables it (dev).
    {
        let sock = std::env::var(tenant_state::ADMIN_SOCKET_ENV)
            .ok()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| tenant_state::DEFAULT_ADMIN_SOCKET.to_owned());
        if sock == "off" {
            warn!(
                event = "tenant_admin_socket_disabled",
                "SIGNER_ADMIN_SOCKET=off — operator per-tenant stop is NOT reachable on this box"
            );
        } else {
            // Bind is a BOOT-time concern: if the operator control path cannot
            // exist, the gateway must not serve signing traffic without it
            // (CodeRabbit). Only the accept loop is spawned.
            let sock_path = std::path::PathBuf::from(&sock);
            let listener = tenant_state::bind_admin_socket(&sock_path).with_context(|| {
                format!(
                    "bind operator admin socket {sock} ({})",
                    tenant_state::ADMIN_SOCKET_ENV
                )
            })?;
            let admin_app = tenant_state::admin_router(admin_state.clone());
            tokio::spawn(async move {
                if let Err(e) = tenant_state::serve_admin_socket(listener, admin_app).await {
                    error!(event = "tenant_admin_socket_failed", error = %e, "operator per-tenant stop NOT reachable");
                }
            });
        }
    }

    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("bind {}", cli.bind))?;
    info!(local_addr = %listener.local_addr()?, "listener ready");

    // C30.next (ZLODEY 2026-05-18): manual accept loop with a custom
    // hyper-util Builder configured with `http1.header_read_timeout`.
    // `axum::serve` uses hyper-util defaults which leave the header-
    // read phase unbounded — a slow-loris attacker who opens a TCP
    // connection and writes 1 byte every N seconds without ever
    // finishing the headers keeps the connection (and an FD) alive
    // forever. The tower-http TimeoutLayer ONLY fires post-dispatch,
    // so it never triggers for never-finished requests.
    //
    // The accept loop pattern below is the documented axum 0.7 + hyper
    // 1 idiom: spawn one task per connection, share an Arc'd Builder.
    serve_with_hyper_util(
        listener,
        app,
        Duration::from_secs(HEADER_READ_TIMEOUT_SECS),
        MAX_CONCURRENT_CONNECTIONS,
    )
    .await
}

/// Q2a boot self-test for attested-signed-data. If the data-signing key is
/// provisioned (token + published address + staged blob), sign a fixed probe
/// payload via the enclave and assert the returned key address equals the
/// published `SIGNER_DATA_ADDRESS`. A mismatch — or an enclave that cannot
/// decrypt the data key — means `/attestation` would publish a `data_pubkey`
/// that buyers pin and then fail to verify against, so we FAIL LOUD (abort boot)
/// rather than serve a drifted/garbage trust anchor. Independent ecrecover of the
/// returned signature is covered by the enclave's
/// `sign_attested_data_ecrecover_roundtrip` unit test; here we assert the
/// enclave-derived address (the drift + key-availability check) without
/// duplicating canonical-v1 / keccak / secp256k1 in the gateway.
///
/// Skipped (logged) when the data key is not provisioned — venue-only
/// deployments are unaffected.
/// Outcome of one attested-data self-sign probe (shared by the boot self-test
/// and the E3 periodic health probe).
enum ProbeOutcome {
    /// Signature round-trip succeeded and the enclave key address matched.
    Passed,
    /// Nothing to probe — the attested-data key is not provisioned on this box.
    Skipped(&'static str),
    /// The probe ran but signing is broken (enclave error, key undecryptable,
    /// address drift, or the enclave was unreachable across all attempts).
    Failed(String),
}

const SIGN_PROBE_PAYLOAD: &str = r#"{"usenami_self_test":"boot"}"#;
/// Boot uses many attempts (waits out enclave cold-start); the periodic probe
/// uses few (the enclave is already up — a sustained outage should surface via
/// staleness, and one transient blip must not spam).
const BOOT_PROBE_ATTEMPTS: u32 = 20;
const PERIODIC_PROBE_ATTEMPTS: u32 = 3;
/// Default cadence of the E3 periodic self-sign probe (0 disables it).
const DEFAULT_SIGN_PROBE_INTERVAL_SEC: u64 = 300;

fn now_epoch_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run ONE attested-data self-sign probe: sign a fixed harmless payload via the
/// enclave (`sign_data`) and assert the returned key address equals the published
/// `SIGNER_DATA_ADDRESS`. This exercises the FULL sign path (IMDS creds → vsock →
/// enclave KMS-decrypt-under-attestation → secp256k1 sign → attested response),
/// so it detects a silently-broken signer that still answers vsock `ping`. It
/// never touches a venue or places an order — the payload is a constant.
async fn run_data_signing_probe(state: &AppState, max_attempts: u32) -> ProbeOutcome {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    let Some(token) = state.data_signing_token.as_deref() else {
        return ProbeOutcome::Skipped("SIGNER_DATA_SIGNING_TOKEN unset");
    };
    let expected_addr = match std::env::var("SIGNER_DATA_ADDRESS")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
    {
        Some(a) => a,
        None => {
            return ProbeOutcome::Failed(
                "SIGNER_DATA_SIGNING_TOKEN is set but SIGNER_DATA_ADDRESS is not — \
                 cannot self-test the data key"
                    .to_owned(),
            )
        }
    };
    let scope = blob_key(DATA_SIGNING_CUSTOMER, DATA_SIGNING_STEM);
    let Some(blob) = state.blobs.get(&scope) else {
        return ProbeOutcome::Failed(format!(
            "data-signing provisioned but blob '{scope}' not loaded"
        ));
    };

    let mut last_err = String::new();
    for attempt in 1..=max_attempts {
        // LOW#3 (crypto-panel #211): jittered, growing backoff (cap 5s) so a
        // fleet restarting together doesn't bail in lockstep at a fixed cliff
        // when the enclave is briefly slow. Jitter from clock nanos — no rand dep.
        let backoff = {
            let grow = 500u64.saturating_mul(u64::from(attempt)).min(5_000);
            let jitter = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::from(d.subsec_nanos()) % 250)
                .unwrap_or(0);
            Duration::from_millis(grow + jitter)
        };
        // IMDS creds are independent of the enclave; only the vsock round-trip
        // below waits on enclave readiness.
        let creds = match state.creds.get().await {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("creds: {e}");
                tokio::time::sleep(backoff).await;
                continue;
            }
        };
        let req = crate::vsock::VsockRequest {
            action: "sign_data".to_owned(),
            method: None,
            path: None,
            body: None,
            timestamp_ms: None,
            aws_credentials: Some(crate::vsock::AwsCredentials {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
            }),
            ciphertext_blob_base64: Some(b64.encode(blob.ciphertext.as_slice())),
            proto_version: 1,
            opaque_token: Some(token.to_owned()),
            key_blob_s3_key: Some(format!(
                "secrets/{DATA_SIGNING_CUSTOMER}/{DATA_SIGNING_STEM}.enc"
            )),
            query: None,
            op: None,
            payload: None,
            hl_action: None,
            nonce: None,
            vault_address: None,
            x402: None,
            order: None,
            cancel: None,
            data: Some(SIGN_PROBE_PAYLOAD.to_owned()),
            intent_signature: None,
            intent_nonce: None,
            client_nonce: None,
            attestation_nonce: None,
            attestation_user_data: None,
        };
        match crate::vsock::round_trip(state.enclave.cid, state.enclave.port, &req).await {
            Ok(mut resp) => {
                if let Some(code) = resp.error.as_deref() {
                    return ProbeOutcome::Failed(format!(
                        "enclave returned '{code}' — the data key is not decryptable / misconfigured"
                    ));
                }
                let Some(attested) = resp.attested.take() else {
                    return ProbeOutcome::Failed("enclave ok but no attested payload".to_owned());
                };
                let got = attested.pubkey_address.trim().to_ascii_lowercase();
                if got != expected_addr {
                    return ProbeOutcome::Failed(format!(
                        "enclave key address {got} != published SIGNER_DATA_ADDRESS \
                         {expected_addr} (config drift)"
                    ));
                }
                return ProbeOutcome::Passed;
            }
            Err(e) => {
                last_err = format!("vsock: {e}");
                warn!(event = "data_signing_probe_retry", attempt, detail = %last_err);
                tokio::time::sleep(backoff).await;
            }
        }
    }
    ProbeOutcome::Failed(format!(
        "enclave unreachable after {max_attempts} attempts ({last_err})"
    ))
}

/// Q2a boot self-test for attested-signed-data. If the data-signing key is
/// provisioned (token + published address + staged blob), sign a fixed probe
/// payload via the enclave and assert the returned key address equals the
/// published `SIGNER_DATA_ADDRESS`. A mismatch — or an enclave that cannot
/// decrypt the data key — means `/attestation` would publish a `data_pubkey`
/// that buyers pin and then fail to verify against, so we FAIL LOUD (abort boot)
/// rather than serve a drifted/garbage trust anchor.
///
/// Also seeds the E3 `sign_health` cell: on pass, the periodic probe is armed
/// (`enabled`) and the first success is recorded; when the data key isn't
/// provisioned the probe stays disabled and `/healthz` reports `sign_checked:false`.
///
/// Skipped (logged) when the data key is not provisioned — venue-only
/// deployments are unaffected.
async fn data_signing_self_test(state: &AppState) -> Result<()> {
    match run_data_signing_probe(state, BOOT_PROBE_ATTEMPTS).await {
        ProbeOutcome::Passed => {
            state.sign_health.set_enabled(true);
            state.sign_health.record_success(now_epoch_s());
            info!(event = "data_signing_self_test_passed");
            Ok(())
        }
        ProbeOutcome::Skipped(reason) => {
            state.sign_health.set_enabled(false);
            info!(event = "data_signing_self_test_skipped", reason);
            Ok(())
        }
        ProbeOutcome::Failed(detail) => {
            anyhow::bail!("data-signing boot self-test failed ({detail}); refusing to start")
        }
    }
}

/// E3: spawn the periodic self-sign health probe. No-op unless the attested-data
/// key is provisioned (boot self-test set `sign_health.enabled`) AND the interval
/// is > 0. On each tick it re-runs the probe and records the outcome in
/// `sign_health`; `/healthz` publishes it and the on-box healthcheck alerts on
/// staleness. It NEVER restarts anything — a signing outage pages an operator; it
/// does not make the gateway flap. `SIGNER_HEALTH_SIGN_INTERVAL_SEC` overrides the
/// cadence (0 disables).
fn spawn_sign_health_probe(state: AppState) {
    let interval_s = std::env::var("SIGNER_HEALTH_SIGN_INTERVAL_SEC")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SIGN_PROBE_INTERVAL_SEC);
    if interval_s == 0 {
        // Disable the /healthz sign-liveness view too: boot set enabled=true, but
        // with no periodic re-probe `sign_age_s` would grow forever and the monitor
        // would false-alert on staleness (CodeRabbit). interval=0 ⇒ not monitored.
        state.sign_health.set_enabled(false);
        info!(event = "sign_health_probe_disabled", reason = "interval=0");
        return;
    }
    if !state.sign_health.is_enabled() {
        info!(
            event = "sign_health_probe_skipped",
            reason = "attested-data key not provisioned"
        );
        return;
    }
    info!(event = "sign_health_probe_started", interval_s);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_s));
        // Skip (don't burst) missed ticks: after a host suspend/stall the default
        // Burst would fire back-to-back probes to "catch up" — pointless for a
        // liveness probe and a needless enclave-sign storm (Gemini).
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The boot self-test already recorded one success; skip the immediate
        // first tick so the first re-probe happens one interval later.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match run_data_signing_probe(&state, PERIODIC_PROBE_ATTEMPTS).await {
                ProbeOutcome::Passed => {
                    state.sign_health.record_success(now_epoch_s());
                    tracing::debug!(event = "sign_health_probe_ok");
                }
                ProbeOutcome::Skipped(reason) => {
                    // Shouldn't happen once enabled (token can't unset at runtime),
                    // but treat as non-fatal and keep the last-known state.
                    warn!(event = "sign_health_probe_skipped_runtime", reason);
                }
                ProbeOutcome::Failed(detail) => {
                    state.sign_health.record_failure(now_epoch_s());
                    let consecutive = state
                        .sign_health
                        .consecutive_failures
                        .load(std::sync::atomic::Ordering::Relaxed);
                    error!(
                        event = "sign_health_probe_failed",
                        consecutive,
                        detail = %detail
                    );
                }
            }
        }
    });
}

/// C30.next: hard cap on concurrent TCP connections in the accept loop.
///
/// Self-review HIGH catch: without this, `header_read_timeout` only
/// shortens the lifetime of each slow-loris connection but does NOT
/// bound how many can exist simultaneously. An attacker opening
/// connections faster than `1/header_read_timeout` × MAX_CONNECTIONS
/// can still exhaust file descriptors and spawn-task memory.
///
/// Gemini round-1 HIGH-1 sharpening: this cap applies to ALL incoming
/// connections including /healthz. If an attacker fills the cap via
/// slow-loris on /sign, Cloudflare's origin probe to /healthz also
/// gets refused → origin marked dead → DoS amplification.
///
/// Mitigation in this PR: cap is raised to 4096, which is 16× the
/// in-flight request limit. Realistic attack sustained rate to fill
/// it is ~410 conn/s — well above what a single attacker can keep
/// open simultaneously (each connection costs THEM a FD + state). At
/// 4096 attack connections, Cloudflare's small fleet of probe
/// connections (typically 1-3 at any moment) almost always slip
/// through. Operational requirement: `ulimit -n` ≥ 8192 on the host.
///
/// Proper architectural fix (deferred): bind a SECOND TcpListener on
/// a separate port for /healthz only, with a tiny cap (e.g., 16),
/// and point Cloudflare's health check at that port. Then /sign and
/// /healthz can never DoS each other. Tracked as follow-up.
///
/// Gemini round-3 MED-A: expressed as a function of MAX_CONCURRENT_
/// REQUESTS so the relationship stays explicit if either constant is
/// tuned. 16× because connection-level work (TCP accept, header
/// parsing, Tower dispatch) is dominated by the per-request handler
/// cost; at any moment we expect roughly 16 idle/setup connections
/// per actively-processing request.
const MAX_CONCURRENT_CONNECTIONS: usize = MAX_CONCURRENT_REQUESTS * 16;

/// C30.next: accept loop that wires axum's Router to hyper's HTTP/1
/// Builder with `header_read_timeout` set. One spawned task per
/// inbound connection; a Semaphore bounds total live connections.
///
/// `header_read_timeout` and `max_connections` are parameterized so
/// integration tests can use tight values without waiting on the 10s /
/// 4096-slot production caps.
///
/// HTTP/2 IS NOT SUPPORTED. We deliberately use the HTTP/1-only Builder
/// instead of `hyper_util::server::conn::auto::Builder` because the
/// auto Builder accepts HTTP/2 prior-knowledge connections, and
/// `header_read_timeout` only applies to the http1() branch — an
/// attacker who sends the HTTP/2 connection preface then dribbles
/// SETTINGS frames would bypass the timeout entirely. The gateway is
/// a signing API; clients (SDK, Cloudflare origin fetch) use HTTP/1.1
/// without exception. If we ever need HTTP/2, also wire an http2
/// keep-alive/idle timeout.
async fn serve_with_hyper_util(
    listener: tokio::net::TcpListener,
    app: Router,
    header_read_timeout: Duration,
    max_connections: usize,
) -> Result<()> {
    let mut builder = hyper_http1::Builder::new();
    // hyper 1.x requires an explicit Timer when any timeout is set —
    // without this, the read returns a panic on first use.
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        // Gemini round-1 HIGH-2: disable keep-alive. Without it, an
        // authenticated client could send one request then hold the
        // connection idle indefinitely, eating a slot from the
        // MAX_CONCURRENT_CONNECTIONS pool. hyper http1::Builder has
        // no idle-timeout setter, so closing-after-each-response is
        // the only way to bound idle connections.
        //
        // Cloudflare and quant SDKs both pool at the APPLICATION
        // layer (they reopen connections on demand) — no perf hit.
        // For a signing API the cost of one extra TCP handshake per
        // sign is negligible compared to the KMS round-trip.
        .keep_alive(false);
    let builder = Arc::new(builder);

    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));

    let make_service = app.into_make_service();

    loop {
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // Accept errors usually mean fd exhaustion or transient
                // network issues — log and keep looping. Never break:
                // killing the loop kills the server.
                warn!(error = %err, "accept failed; continuing");
                continue;
            }
        };

        // Self-review HIGH: bound concurrent connections. try_acquire
        // returns immediately — if we're at capacity, drop the socket
        // (the kernel will send RST on the client's next packet).
        // Better to refuse fast than let an attacker queue.
        //
        // Gemini round-3 MED-B correction: try_acquire_owned consumes
        // the Arc (`self: Arc<Self>`), so the `.clone()` IS needed —
        // without it, connection_semaphore would be moved on the first
        // iteration and unusable on the next. The .clone() is cheap
        // (just a refcount bump).
        let permit = match connection_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    peer = %peer_addr,
                    "connection refused: MAX_CONCURRENT_CONNECTIONS reached"
                );
                drop(tcp);
                continue;
            }
        };

        let mut make_service = make_service.clone();
        let builder = builder.clone();
        tokio::spawn(async move {
            // Hold the permit for the entire connection lifetime;
            // dropping releases the slot back to the semaphore.
            let _permit = permit;

            // axum's IntoMakeService is a tower::Service<()> that
            // returns a per-connection Router. Call() it once per
            // accepted socket.
            let svc: Router = match make_service.call(()).await {
                Ok(svc) => svc,
                Err(_unreachable) => return, // axum guarantees Infallible
            };

            // Gemini round-1 MED-3: re-insert axum's ConnectInfo<SocketAddr>
            // extension so handlers/middleware that use `ConnectInfo` keep
            // working. `axum::serve` does this automatically; the manual
            // accept loop must do it explicitly. Today no handler uses it,
            // but defensive future-proofing — audit-log middleware is a
            // natural near-term addition.
            let hyper_svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer_addr));
                let mut svc = svc.clone();
                async move { svc.call(req).await }
            });

            let io = TokioIo::new(tcp);
            // serve_connection (NOT serve_connection_with_upgrades) —
            // we don't support upgrades (no WebSocket, no HTTP/2).
            if let Err(err) = builder.serve_connection(io, hyper_svc).await {
                // Most "errors" here are clients disconnecting mid-
                // request (broken pipe, connection reset). The
                // header_read_timeout case lands here too — that's the
                // intended C30.next behavior, so log at debug.
                tracing::debug!(
                    peer = %peer_addr,
                    error = %err,
                    "connection finished with error"
                );
            }
        });
    }
}

/// C30: convert errors raised by load_shed into proper HTTP responses.
/// Without this, axum rejects the layer because its Router requires the
/// inner service to be `Infallible`.
///
/// - `tower::load_shed::error::Overloaded` → 503 Service Unavailable
/// - anything else (defense in depth) → 500 Internal Server Error
///
/// Note: tower-http's `TimeoutLayer` does NOT propagate errors; it returns
/// the configured status code (408) directly, so timeout never reaches here.
async fn handle_middleware_error(err: BoxError) -> (StatusCode, &'static str) {
    if err.is::<tower::load_shed::error::Overloaded>() {
        tracing::warn!(event = "load_shed", "request shed: server overloaded");
        return (StatusCode::SERVICE_UNAVAILABLE, "overloaded");
    }
    tracing::error!(event = "middleware_error", error = %err);
    (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
}

/// Resolve all per-exchange blobs for startup. Precedence:
/// 1. `--blobs-dir` (preferred, multi-exchange) — read every
///    `{exchange}.enc` file that exists.
/// 2. `--blob-path` (legacy, single-exchange KuCoin) — load that single
///    file as the kucoin blob.
///
/// Both flags may be set together; blobs-dir wins for any exchange that
/// has a file, and `--blob-path` falls through only for kucoin if the
/// directory has no `kucoin.enc`.
/// Load one `<stem>.enc` blob + its optional `<stem>.ctx.json` from `dir_path`.
/// Shared by the trading-venue pass and the extra-key scan below.
fn load_blob_with_ctx(dir_path: &Path, stem: &str) -> Result<BlobBundle> {
    let candidate = dir_path.join(format!("{}.enc", stem));
    // Gemini PR #46 catch: don't mask non-UTF-8 paths as empty string —
    // propagate with the actual PathBuf so the operator sees the real cause.
    let candidate_str = candidate
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("blob path is not valid UTF-8: {:?}", candidate))?;
    let bytes = aws::load_blob_from_path(candidate_str)
        .with_context(|| format!("load {} blob from {:?}", stem, candidate))?;
    let ctx_path = dir_path.join(format!("{}.ctx.json", stem));
    let encryption_context = if ctx_path.exists() {
        let ctx_bytes =
            std::fs::read(&ctx_path).with_context(|| format!("read {}", ctx_path.display()))?;
        let ctx: HashMap<String, String> = serde_json::from_slice(&ctx_bytes)
            .with_context(|| format!("parse {}", ctx_path.display()))?;
        if ctx.is_empty() {
            anyhow::bail!(
                "{} exists but is empty — must have at least venue_id",
                ctx_path.display()
            );
        }
        info!(stem = %stem, keys = ?ctx.keys().collect::<Vec<_>>(), "encryption context loaded");
        Some(ctx)
    } else {
        warn!(stem = %stem, ctx_path = %ctx_path.display(), "no .ctx.json — encryption_context will be None");
        None
    };
    info!(stem = %stem, path = %candidate.display(), bytes = bytes.len(), has_context = encryption_context.is_some(), "blob loaded");
    Ok(BlobBundle {
        ciphertext: bytes,
        encryption_context,
    })
}

fn load_all_blobs(cli: &Cli) -> Result<HashMap<String, BlobBundle>> {
    let mut blobs: HashMap<String, BlobBundle> = HashMap::new();

    if let Some(dir) = &cli.blobs_dir {
        let dir_path = Path::new(dir);
        // Pass 1 — trading venues by name; warn if a configured venue is absent.
        // Flat `{venue}.enc` files are the legacy single-tenant layout — keyed
        // under DEFAULT_CUSTOMER_ID so only the default-customer token resolves
        // them. Per-customer blobs live in subdirectories (Pass 3).
        for exchange in SUPPORTED_EXCHANGES {
            let candidate = dir_path.join(format!("{}.enc", exchange));
            if candidate.exists() {
                blobs.insert(
                    blob_key(DEFAULT_CUSTOMER_ID, exchange),
                    load_blob_with_ctx(dir_path, exchange)?,
                );
            } else {
                warn!(
                    exchange = %exchange,
                    path = %candidate.display(),
                    "blob not present — exchange unavailable"
                );
            }
        }
        // Pass 2 (Gemini #75 CRITICAL) — load any OTHER `*.enc` (e.g. x402
        // payer keys) so /sign-x402 can resolve them by key_id. Without this
        // the x402 path always 400s (key never in state.blobs). The blobs dir
        // is operator-owned (root, /var/lib/signer/blobs) and per-endpoint
        // validation still gates use. Only files whose FINAL extension is
        // `.enc` match — `.enc.bak`/`.RESTORE-*`/`.v1` rollback copies are
        // skipped (their last component isn't `enc`).
        match std::fs::read_dir(dir_path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                        continue;
                    }
                    let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned)
                    else {
                        continue;
                    };
                    let key = blob_key(DEFAULT_CUSTOMER_ID, &stem);
                    if blobs.contains_key(&key) {
                        continue; // already loaded in pass 1
                    }
                    match load_blob_with_ctx(dir_path, &stem) {
                        Ok(bundle) => {
                            info!(key_id = %stem, "extra (non-venue) key blob loaded (default customer)");
                            blobs.insert(key, bundle);
                        }
                        Err(e) => {
                            // A bad extra blob must not take down the gateway —
                            // skip it; the venue blobs already loaded are intact.
                            warn!(key_id = %stem, error = %e, "failed to load extra key blob — skipped");
                        }
                    }
                }
            }
            Err(e) => {
                warn!(dir = %dir_path.display(), error = %e, "could not scan blobs dir for extra keys");
            }
        }

        // Pass 3 (multi-tenant) — each SUBDIRECTORY of `blobs_dir` is a
        // per-customer namespace. `{blobs_dir}/{customer_id}/{stem}.enc` loads
        // under the composite key `{customer_id}/{stem}`. This is the on-disk
        // layout `rewrap-with-context.sh` produces per customer; the gateway
        // never builds a path from a REQUEST field (the customer comes from the
        // authenticated token, the venue from a validated allow-list).
        match std::fs::read_dir(dir_path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let sub = entry.path();
                    if !sub.is_dir() {
                        continue;
                    }
                    let Some(customer) =
                        sub.file_name().and_then(|s| s.to_str()).map(str::to_owned)
                    else {
                        continue;
                    };
                    // Guard: a subdir literally named DEFAULT_CUSTOMER_ID would
                    // produce the SAME composite keys as the flat Pass-1/2 blobs
                    // and silently clobber them (operator misconfig / migration
                    // footgun — flagged by both sign-off reviewers). Skip it.
                    if customer == DEFAULT_CUSTOMER_ID {
                        warn!(
                            customer = %customer,
                            "per-customer subdir uses the DEFAULT customer id — would shadow the \
                             flat single-tenant blobs; skipped (move it to a real customer id)"
                        );
                        continue;
                    }
                    // Guard: the subdir name becomes a blob-key prefix — hold it
                    // to the same stem alphabet as a request key_id (no `/`, `..`,
                    // control chars, over-long).
                    if !crate::handlers::is_safe_key_id(&customer) {
                        warn!(customer = %customer, "per-customer subdir name is not a safe id — skipped");
                        continue;
                    }
                    let Ok(files) = std::fs::read_dir(&sub) else {
                        warn!(customer = %customer, "could not scan per-customer blob dir — skipped");
                        continue;
                    };
                    for f in files.flatten() {
                        let p = f.path();
                        if p.extension().and_then(|e| e.to_str()) != Some("enc") {
                            continue;
                        }
                        let Some(stem) = p.file_stem().and_then(|s| s.to_str()).map(str::to_owned)
                        else {
                            continue;
                        };
                        let key = blob_key(&customer, &stem);
                        // Dedup guard (parity with Pass 2): never silently
                        // overwrite an already-loaded composite key.
                        if blobs.contains_key(&key) {
                            warn!(customer = %customer, stem = %stem, "per-customer blob key already loaded — skipped");
                            continue;
                        }
                        match load_blob_with_ctx(&sub, &stem) {
                            Ok(bundle) => {
                                info!(customer = %customer, stem = %stem, "per-customer blob loaded");
                                blobs.insert(key, bundle);
                            }
                            Err(e) => {
                                warn!(customer = %customer, stem = %stem, error = %e, "failed to load per-customer blob — skipped");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(dir = %dir_path.display(), error = %e, "could not scan blobs dir for per-customer subdirs");
            }
        }
    }

    if let Some(legacy_path) = &cli.blob_path {
        let kucoin_key = blob_key(DEFAULT_CUSTOMER_ID, "kucoin");
        // `map_entry` doesn't fit: the value init is fallible (`?`) and emits a
        // log, neither of which compose with `entry().or_insert_with`.
        #[allow(clippy::map_entry)]
        if !blobs.contains_key(&kucoin_key) {
            let bytes = aws::load_blob_from_path(legacy_path)
                .context("load legacy --blob-path as kucoin blob")?;
            info!(
                exchange = "kucoin",
                path = %legacy_path,
                bytes = bytes.len(),
                "legacy KuCoin blob loaded (default customer)"
            );
            blobs.insert(
                kucoin_key,
                BlobBundle {
                    ciphertext: bytes,
                    encryption_context: None,
                },
            );
        }
    }

    Ok(blobs)
}

#[cfg(test)]
mod tests {

    /// Every route path in this file must be constructible by the axum version
    /// we actually link against.
    ///
    /// 🔴 This exists because the four `/:venue` routes below survived CI, a
    /// green clippy, a tag and a production deploy, and then panicked on the
    /// first real startup: axum 0.8 changed capture syntax from `/:param` to
    /// `/{param}` and rejects the old form when the Router is BUILT. Nothing in
    /// this crate built a Router — the routers are assembled inline in `main()`
    /// — so no test could go red. The bump arrived on its own; the breakage
    /// waited for a human to restart the gateway on the box.
    ///
    /// Paths are read from this file's own source rather than listed here, so a
    /// route added tomorrow is covered without anyone remembering to add it.
    /// 🔴 The route table is a CONTRACT, and losing a route is as much a defect
    /// as adding a broken one.
    ///
    /// Measured 2026-09-04: the production gateway had been rebuilt on 09-03 from
    /// this repository, which at the time carried no `tenant_state.rs` — so
    /// `POST /tenant/halt` went from `401` (2026-08-31) to `404`, and the
    /// per-tenant kill switch was gone from production for a day before anyone
    /// noticed. Nothing went red, because every check asked "did the new thing
    /// appear?" and none asked "did the old thing survive?".
    ///
    /// This list is that second question. Removing or renaming a route must be a
    /// deliberate edit here, in the same commit, with the reason in the message.
    #[test]
    fn the_route_table_has_not_silently_lost_anything() {
        let mut found: Vec<&str> = route_paths(include_str!("main.rs"));
        found.sort_unstable();
        found.dedup();
        // Every tenant- and operator-facing route this file registers, listed in
        // full rather than sampled: the five binance signing routes were missing
        // from the first version of this guard (both review bots caught it), and a
        // guard that covers part of the table teaches people it covers all of it.
        // Test-only routes (/probe, /slow, /fast, /block) are deliberately absent.
        for expected in [
            "/account/{venue}",
            "/attestation",
            "/cancel-all/{venue}",
            "/healthz",
            "/hedge",
            "/open-orders/{venue}",
            "/receipts/heartbeat",
            "/sign",
            "/sign-data",
            "/sign-x402",
            "/sign/binance-cancel",
            "/sign/binance-order",
            "/sign/binance-request",
            "/sign/binance-spot-cancel",
            "/sign/binance-spot-order",
            "/sign/okx-cancel",
            "/sign/okx-order",
            "/tenant/halt",
            "/user-trades/{venue}",
            "/verify-blob",
        ] {
            assert!(
                found.contains(&expected),
                "route {expected} is gone from main.rs. If that is intentional, delete it \
                 from this list in the SAME commit and say why in the message — otherwise \
                 you are repeating 2026-09-03, when /tenant/halt vanished from production \
                 for a day and no test noticed. Routes currently registered: {found:?}"
            );
        }
    }

    #[test]
    fn every_route_path_is_valid_for_the_linked_axum() {
        for path in route_paths(include_str!("main.rs")) {
            let p = path.to_owned();
            let built = std::panic::catch_unwind(move || {
                // Bound rather than dropped: `Router` is `#[must_use]`, and the
                // point here is that CONSTRUCTION is what panics.
                let _r = Router::<()>::new().route(&p, get(|| async {}));
            });
            assert!(
                built.is_ok(),
                "axum refuses this path: {path:?}. Since 0.8 a capture is \
                 written {{name}}, not :name — and the Router only rejects it \
                 when it is BUILT, which no other test here does."
            );
        }
    }

    /// Every route path registered in a Rust source, read from the source.
    ///
    /// Split out of the test so the extraction itself can be exercised — it has
    /// its own failure modes, and two of them already bit:
    ///
    ///   - a same-line-only reader silently skipped the MULTI-LINE
    ///     registrations, including `/receipts/heartbeat`, and reported success
    ///     on half the table;
    ///   - the marker matched prose: first a path inside this test's own doc
    ///     comment, then the `.rfind` in the neighbouring heartbeat guard. A
    ///     captured path must start with `/` — the real rule, and the cheapest
    ///     way to ignore commentary.
    ///
    /// 🔴 Advancing by `c.len_utf8()` and not by 1: a multi-byte whitespace
    /// (NBSP, U+2028) would leave `k` inside a UTF-8 sequence and the next slice
    /// would PANIC — a source-reading guard brought down by the source it reads
    /// (Gemini, #79). Our sources are ASCII today; that is a property of today.
    fn route_paths(src: &str) -> Vec<&str> {
        let marker = concat!(".", "route(");
        let mut paths = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(marker) {
            let mut k = from + rel + marker.len();
            from = k;
            while let Some(c) = src[k..].chars().next() {
                if !c.is_whitespace() {
                    break;
                }
                k += c.len_utf8();
            }
            if !src[k..].starts_with('"') {
                continue;
            }
            let start = k + 1;
            let Some(end_rel) = src[start..].find('"') else {
                continue;
            };
            let path = &src[start..start + end_rel];
            if path.starts_with('/') {
                paths.push(path);
            }
        }
        paths
    }

    /// The extractor must survive the source it is pointed at, and must read the
    /// whole table rather than the half it can see on one line.
    #[test]
    fn route_paths_reads_the_whole_table_and_survives_non_ascii() {
        // U+00A0 NBSP between `.route(` and the literal: byte-wise `k += 1`
        // lands mid-sequence and the next slice panics.
        let synthetic = concat!(
            "        .route(\"/same-line\", get(h))\n",
            "        .route(\u{00a0}\n            \"/multi-line\",\n            post(h),\n        )\n",
            "        // prose mentioning .route( in a comment\n",
            "        .rfind(\".route(\")\n",
        );
        let got = route_paths(synthetic);
        assert_eq!(
            got,
            vec!["/same-line", "/multi-line"],
            "expected both registrations and neither piece of prose"
        );

        // And on the real file: the count is a floor, and the route this
        // rotation adds is written multi-line, so it proves the reader is not
        // quietly seeing half.
        let real = route_paths(include_str!("main.rs"));
        assert!(
            real.len() >= 15,
            "expected the route table, found {} — the extractor is reading \
             nothing and would pass on anything",
            real.len()
        );
        // The exact path, not a prefix: `contains("/receipts/")` would be
        // satisfied by any other route under that namespace, and the point is
        // that THIS one — written multi-line — is being read (CodeRabbit, #79).
        assert!(
            real.contains(&"/receipts/heartbeat"),
            "the multi-line registrations are not being read: /receipts/heartbeat \
             is written that way and is missing from what the extractor returned"
        );
    }
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use std::sync::Arc;
    use tokio::sync::Notify;

    /// Gemini #75 CRITICAL regression: an x402 payer-key blob (NOT a trading
    /// venue) must be loaded so /sign-x402 can resolve it by key_id. Pass 1
    /// loads named venues; pass 2 scans for any other `*.enc`. Rollback copies
    /// with a different final extension (`.enc.bak`) must be skipped.
    #[test]
    fn load_all_blobs_resolves_non_venue_x402_key() {
        let dir = std::env::temp_dir().join(format!("signer-blobtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("binance.enc"), b"fake-ciphertext-binance").unwrap();
        std::fs::write(dir.join("x402.enc"), b"fake-ciphertext-x402").unwrap();
        std::fs::write(dir.join("x402.enc.bak"), b"old-rollback-copy").unwrap();

        let cli = Cli {
            bind: "0.0.0.0:8443".parse().unwrap(),
            enclave_cid: 16,
            enclave_port: 5000,
            blob_path: None,
            blobs_dir: Some(dir.to_str().unwrap().to_owned()),
        };
        let blobs = load_all_blobs(&cli).unwrap();

        // Flat `{venue}.enc` files load under the default-customer namespace
        // (composite key), not a bare venue key (multi-tenant routing).
        assert!(
            blobs.contains_key(&blob_key(DEFAULT_CUSTOMER_ID, "binance")),
            "trading venue must load under default customer (pass 1)"
        );
        assert!(
            blobs.contains_key(&blob_key(DEFAULT_CUSTOMER_ID, "x402")),
            "x402 key must resolve (Gemini #75: was never loaded before this fix)"
        );
        assert!(
            !blobs.contains_key("binance"),
            "no bare (unscoped) venue key — lookups must go through blob_key"
        );
        assert!(
            !blobs.contains_key(&blob_key(DEFAULT_CUSTOMER_ID, "x402.enc")),
            "`.enc.bak` rollback copy must be ignored (final ext != enc)"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Pass 3: a per-customer subdirectory `{blobs_dir}/{customer}/{venue}.enc`
    /// loads under the composite key `{customer}/{venue}`, isolated from the
    /// default-customer flat blobs.
    #[test]
    fn load_all_blobs_loads_per_customer_subdir() {
        let dir = std::env::temp_dir().join(format!("signer-mt-blobtest-{}", std::process::id()));
        let cust = "11111111-1111-1111-1111-111111111111";
        std::fs::create_dir_all(dir.join(cust)).unwrap();
        std::fs::write(dir.join("binance.enc"), b"default-binance").unwrap();
        std::fs::write(dir.join(cust).join("binance.enc"), b"custA-binance").unwrap();

        let cli = Cli {
            bind: "0.0.0.0:8443".parse().unwrap(),
            enclave_cid: 16,
            enclave_port: 5000,
            blob_path: None,
            blobs_dir: Some(dir.to_str().unwrap().to_owned()),
        };
        let blobs = load_all_blobs(&cli).unwrap();

        let default_b = blobs
            .get(&blob_key(DEFAULT_CUSTOMER_ID, "binance"))
            .unwrap();
        let cust_b = blobs.get(&blob_key(cust, "binance")).unwrap();
        assert_eq!(default_b.ciphertext, b"default-binance");
        assert_eq!(cust_b.ciphertext, b"custA-binance");
        // Distinct namespaces — customer A's blob is NOT the default's.
        assert_ne!(default_b.ciphertext, cust_b.ciphertext);

        std::fs::remove_dir_all(&dir).ok();
    }
    use tower::ServiceExt;

    /// B3 (в): the rate-limit middleware reads the `RawToken` extension the
    /// auth layer inserts (production layering: `rate_limit_mw` is INNER of
    /// `require_bearer` — registered earlier in the builder chain), denies
    /// with 429 + `Retry-After` once the per-token window is exhausted, and
    /// keys windows PER TOKEN. The auth layer itself is stood in for by a
    /// minimal extension-inserting middleware (require_bearer has its own
    /// tests in auth.rs; env-driven AuthState would race other env tests).
    #[tokio::test]
    async fn b3_rate_limit_mw_denies_per_token_after_auth() {
        use crate::auth::RawToken;

        async fn ok() -> &'static str {
            "signed"
        }
        /// Stand-in for require_bearer: token = Authorization header verbatim.
        async fn fake_auth(
            mut req: Request<Body>,
            next: axum::middleware::Next,
        ) -> axum::response::Response {
            let tok = req
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            req.extensions_mut().insert(RawToken(tok));
            next.run(req).await
        }

        let state = AppState::new(
            std::collections::HashMap::new(),
            EnclaveTarget { cid: 0, port: 0 },
        )
        .with_limits(limits::Limits::rate_only_for_tests(1));

        // Same layer ORDER as the production sign_router: rate_limit_mw
        // registered first (inner), auth layer second (outer, runs first).
        let app = Router::new()
            .route("/probe", get(ok))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                limits::rate_limit_mw,
            ))
            .route_layer(axum::middleware::from_fn(fake_auth))
            .with_state(state);

        let req = |tok: &str| {
            Request::builder()
                .uri("/probe")
                .header(axum::http::header::AUTHORIZATION, tok)
                .body(Body::empty())
                .unwrap()
        };

        // First request for token A passes; second hits the cap → 429 with
        // a Retry-After header and the allow-listed `rate_limited` code.
        let r1 = app.clone().oneshot(req("tok-a")).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app.clone().oneshot(req("tok-a")).await.unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            r2.headers().contains_key(axum::http::header::RETRY_AFTER),
            "429 must carry Retry-After"
        );
        // A different token has its own window (per-token isolation).
        let r3 = app.clone().oneshot(req("tok-b")).await.unwrap();
        assert_eq!(r3.status(), StatusCode::OK);
    }

    /// C30: a request that exceeds the timeout returns 408, not 500.
    /// Verifies tower-http's TimeoutLayer is wired correctly and uses the
    /// explicit REQUEST_TIMEOUT status code.
    #[tokio::test]
    async fn c30_timeout_returns_408_on_slow_handler() {
        async fn slow() -> &'static str {
            tokio::time::sleep(Duration::from_millis(500)).await;
            "done"
        }

        let app = Router::new()
            .route("/slow", get(slow))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_millis(50),
            ));

        let resp = app
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    /// C30: a request that completes within the timeout returns the
    /// handler's response unchanged. Regression guard: the timeout layer
    /// must NOT add latency or modify successful responses.
    #[tokio::test]
    async fn c30_timeout_layer_passes_fast_requests() {
        async fn fast() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/fast", get(fast))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(30),
            ));

        let resp = app
            .oneshot(Request::builder().uri("/fast").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// C30: when the concurrency limit is at capacity, load_shed returns
    /// 503 immediately instead of queueing. Verifies the
    /// HandleErrorLayer + load_shed + concurrency_limit stack converts
    /// `Overloaded` errors into the expected wire response.
    #[tokio::test]
    async fn c30_load_shed_returns_503_when_overloaded() {
        /// Combined state: a `slot_acquired` signal the handler emits as
        /// soon as it starts (proving it has the semaphore permit), and a
        /// `release` signal the test sends to let the handler return.
        /// Using two Notify-s instead of a sleep-based yield eliminates a
        /// timing race on loaded CI runners.
        struct HandlerSync {
            slot_acquired: Notify,
            release: Notify,
        }

        async fn block(
            axum::extract::State(s): axum::extract::State<Arc<HandlerSync>>,
        ) -> &'static str {
            s.slot_acquired.notify_one();
            s.release.notified().await;
            "done"
        }

        let sync = Arc::new(HandlerSync {
            slot_acquired: Notify::new(),
            release: Notify::new(),
        });

        let app = Router::new()
            .route("/block", get(block))
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_middleware_error))
                    .load_shed()
                    .concurrency_limit(1),
            )
            .with_state(sync.clone());

        // Spawn the first request — it will block inside the handler.
        let app_clone = app.clone();
        let first = tokio::spawn(async move {
            app_clone
                .oneshot(
                    Request::builder()
                        .uri("/block")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });

        // Deterministic handshake: wait until the handler has actually
        // taken the concurrency slot before firing the second request.
        sync.slot_acquired.notified().await;

        // Second request: should be shed (503).
        let resp_shed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/block")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_shed.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Unblock the first request so the test exits cleanly.
        sync.release.notify_one();
        let resp_first = first.await.unwrap();
        assert_eq!(resp_first.status(), StatusCode::OK);
    }

    /// C30: /healthz MUST be exempt from the dos_hardening stack. If
    /// /healthz were inside the concurrency gate, a sustained attack
    /// filling the pool would 503 health probes too — Cloudflare would
    /// mark the origin dead and stop routing legit traffic, turning the
    /// DoS defense into a DoS amplifier. This test mirrors the production
    /// router layout: dos_hardening on /api routes only, /healthz outside.
    #[tokio::test]
    async fn c30_healthz_stays_reachable_under_load_shed() {
        struct HandlerSync {
            slot_acquired: Notify,
            release: Notify,
        }

        async fn block(
            axum::extract::State(s): axum::extract::State<Arc<HandlerSync>>,
        ) -> &'static str {
            s.slot_acquired.notify_one();
            s.release.notified().await;
            "done"
        }

        async fn health() -> &'static str {
            "ok"
        }

        let sync = Arc::new(HandlerSync {
            slot_acquired: Notify::new(),
            release: Notify::new(),
        });

        // Production-equivalent layout: dos_hardening wraps the api router
        // only; healthz is merged AFTER and stays outside the limit.
        let api_router = Router::new().route("/block", get(block)).layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_middleware_error))
                .load_shed()
                .concurrency_limit(1),
        );

        let app = Router::new()
            .merge(api_router)
            .route("/healthz", get(health))
            .with_state(sync.clone());

        // Fill the concurrency slot.
        let app_clone = app.clone();
        let first = tokio::spawn(async move {
            app_clone
                .oneshot(
                    Request::builder()
                        .uri("/block")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        sync.slot_acquired.notified().await;

        // /healthz must still return 200 even with the api pool exhausted.
        let resp_health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_health.status(), StatusCode::OK);

        sync.release.notify_one();
        let _ = first.await.unwrap();
    }

    // ─── C30.next: TCP-level slow-loris (header_read_timeout) ──────────
    //
    // These tests bind a real TCP socket and exercise the hyper-util
    // accept loop, not the in-process tower stack. They prove that the
    // header_read_timeout is wired correctly and fires even when no
    // tower layer has had a chance to see the request.

    /// The heartbeat exists to let a TENANT catch this gateway hiding a
    /// decision. On the operator router it is answerable only by us — the one
    /// party it is meant to check — and a tenant's own bearer gets 401, so the
    /// mechanism ships dead while every other test stays green.
    ///
    /// This is a source guard rather than a request test because the routers
    /// are assembled inline in `main()` and cannot be built from a test. It is
    /// falsifiable: move the route back under `operator_router` and it fails.
    #[test]
    fn heartbeat_answers_the_tenant_not_only_the_operator() {
        let src = include_str!("main.rs");
        // Every needle is assembled at compile time rather than written as one
        // literal: `include_str!` pulls in THIS test too, so a whole-string
        // needle would also match itself and the counts below would be off by
        // one. `concat!` leaves no single matching literal in the source.
        let sign = src
            .find(concat!("let sign_router = ", "Router::new()"))
            .expect("sign_router is built in main()");
        let operator = src
            .find(concat!("let operator_router = ", "Router::new()"))
            .expect("operator_router is built in main()");
        // The HANDLER reference, not the path string: a path string also
        // occurs in prose, so a guard anchored on it would keep passing after
        // the `.route(...)` itself moved or went away (CodeRabbit, #78).
        let needle = concat!("post(handlers::", "post_receipt_heartbeat)");
        assert_eq!(
            src.matches(needle).count(),
            1,
            "the heartbeat handler must be wired exactly once, or `find` below \
             would report an arbitrary one of several registrations"
        );
        let route = src.find(needle).expect("the heartbeat route is registered");
        let decl = src[..route]
            .rfind(".route(")
            .expect("the handler is reached through a .route(...) registration");
        assert!(
            src[decl..route].contains(concat!("\"/receipts", "/heartbeat\"")),
            "the handler must be registered under its own path"
        );
        assert!(
            sign < decl && decl < operator,
            "the heartbeat must sit on the tenant router: a tenant bearer is \
             the only credential that makes it evidence rather than \
             self-testimony (sign={sign}, decl={decl}, operator={operator})"
        );
    }

    /// Build a minimal Router that returns 200 on /healthz, suitable
    /// for spinning up behind serve_with_hyper_util in tests.
    fn slow_loris_test_app() -> Router {
        Router::new().route("/healthz", get(|| async { "ok" }))
    }

    /// Bind a TcpListener on a random port and spawn the gateway
    /// serve loop with a short `header_read_timeout` and a generous
    /// connection cap (so existing tests aren't affected). Returns the
    /// bound address so the test can connect to it.
    async fn spawn_test_server(header_timeout: Duration) -> SocketAddr {
        spawn_test_server_with_cap(header_timeout, 256).await
    }

    /// Like `spawn_test_server` but lets the caller pin a low connection
    /// cap. Used by the C30.next refuse-excess-connections test.
    async fn spawn_test_server_with_cap(
        header_timeout: Duration,
        max_connections: usize,
    ) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        let app = slow_loris_test_app();
        tokio::spawn(async move {
            let _ = serve_with_hyper_util(listener, app, header_timeout, max_connections).await;
        });
        // Tiny yield so the spawned task gets to the accept loop before
        // the test connects. Without this, connect() can race the
        // listener and silently succeed against a "pending" socket.
        tokio::time::sleep(Duration::from_millis(20)).await;
        addr
    }

    /// C30.next: a client that opens a connection and dribbles partial
    /// headers (no final \r\n\r\n) gets the connection closed by the
    /// server after `header_read_timeout`. Without this, the FD would
    /// be held forever.
    #[tokio::test]
    async fn c30_next_header_read_timeout_closes_slow_loris_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 200ms header timeout — tight enough that the test runs fast,
        // loose enough that local CI loopback can't false-positive.
        let header_timeout = Duration::from_millis(200);
        let addr = spawn_test_server(header_timeout).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

        // Send a partial request line + one header but NO terminating
        // \r\n\r\n. Hyper is now waiting for more bytes that we will
        // never send.
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .expect("partial write");
        stream.flush().await.expect("flush");

        // Wait longer than header_timeout. Server should drop us.
        // Use a generous slack to avoid flake on busy CI.
        let mut buf = [0u8; 1024];
        let read_result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

        match read_result {
            // EOF (0 bytes) = clean close by server. This is the
            // expected outcome on header_read_timeout: hyper drops the
            // connection without sending a response.
            Ok(Ok(0)) => { /* pass */ }
            // Server responded then closed. Hyper sometimes emits a
            // 408 Request Timeout before tearing down. Self-review
            // MEDIUM-1: if ANY response came back, it MUST NOT be 200 —
            // a 200 here would mean the server somehow processed the
            // partial request, which is the bug we're testing against.
            Ok(Ok(n)) => {
                let response = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    !response.starts_with("HTTP/1.1 200"),
                    "header_read_timeout regression: server returned 200 \
                     to a partial request (got: {})",
                    &response[..response.len().min(120)]
                );
                // 408 or 400 is the expected response if hyper writes
                // anything at all. Either is fine for the C30.next
                // semantics — the partial request was rejected.
            }
            // Read error (connection reset) is also a pass — server
            // tore down the connection.
            Ok(Err(_)) => { /* pass */ }
            // The outer tokio::time::timeout fired = server kept the
            // connection alive past header_read_timeout + slack. FAIL.
            Err(_) => panic!(
                "header_read_timeout did not fire: connection stayed \
                 alive past {:?} (timeout was {:?})",
                Duration::from_secs(2),
                header_timeout
            ),
        }
    }

    /// C30.next HIGH-1 (Gemini round-2): the connection semaphore
    /// actually refuses new TCP connections once max_connections is
    /// reached. Spin up a server with cap = 2, open 2 slow-loris
    /// connections that hold their slots, then open a 3rd connection
    /// and assert the server closes it WITHOUT processing a request.
    ///
    /// Without this test, the cap could regress silently (e.g.,
    /// permit holding broken, semaphore size bug) and we'd only catch
    /// it under real production load.
    #[tokio::test]
    async fn c30_next_connection_cap_refuses_excess_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const CAP: usize = 2;
        // Long enough that both holders stay alive through the test,
        // short enough that the test exits quickly.
        let header_timeout = Duration::from_secs(2);
        let addr = spawn_test_server_with_cap(header_timeout, CAP).await;

        // Open and hold CAP slow-loris connections. Each writes a
        // partial header to confirm the server has accepted the
        // socket into hyper, then keeps the stream alive — the
        // semaphore permit is held until the connection task ends.
        async fn hold_slot(addr: SocketAddr) -> tokio::net::TcpStream {
            let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
            s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
                .await
                .expect("partial write");
            s.flush().await.expect("flush");
            s
        }

        let _hold1 = hold_slot(addr).await;
        let _hold2 = hold_slot(addr).await;

        // Give the accept loop a moment to process both holders and
        // mark both semaphore permits as taken. This is the same
        // race-guard pattern as spawn_test_server — accept is async.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3rd connection. TCP-level connect() will succeed (the
        // listener's listen backlog still accepts the SYN), but the
        // server's accept loop will drop the socket immediately
        // because semaphore.try_acquire_owned() returns Err.
        let mut excess = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect on excess succeeds — TCP-level");

        // Write a complete request. The server SHOULDN'T process it
        // because it refused the slot. With keep_alive(false) and
        // the dropped TCP, the read should return EOF (0 bytes) or
        // an error promptly.
        let _ = excess
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        let _ = excess.flush().await;

        let mut buf = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(1), excess.read_to_end(&mut buf)).await;

        match read_result {
            // EOF on a refused connection — expected. The server
            // dropped the TCP without writing anything.
            Ok(Ok(0)) => { /* pass */ }
            // Read error (connection reset) — also pass.
            Ok(Err(_)) => { /* pass */ }
            // ANY data on the wire means the server processed the
            // request despite being at cap. FAIL.
            Ok(Ok(n)) => {
                let response = String::from_utf8_lossy(&buf[..n]);
                panic!(
                    "connection cap regression: server responded to excess \
                     connection (got {} bytes: {})",
                    n,
                    &response[..response.len().min(120)]
                );
            }
            // Outer timeout — server kept the connection alive
            // somehow. Could mean the semaphore released permits
            // unexpectedly mid-test. Treat as fail (excess should
            // close within sub-second on a healthy cap).
            Err(_) => panic!(
                "connection cap regression: excess connection stayed alive \
                 past 1s (cap was {CAP}; 2 holders should have filled it)"
            ),
        }
    }

    /// Sanity: a well-formed request to the same test server returns
    /// 200, proving that the header timeout doesn't kill legitimate
    /// traffic.
    #[tokio::test]
    async fn c30_next_header_read_timeout_does_not_break_normal_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let header_timeout = Duration::from_millis(500);
        let addr = spawn_test_server(header_timeout).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

        // Complete the request immediately — server should respond
        // with 200 well before header_timeout.
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        stream.flush().await.expect("flush");

        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
            .await
            .expect("read completes within timeout")
            .expect("read ok");

        let response = String::from_utf8_lossy(&buf);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200 OK, got: {}",
            &response[..response.len().min(120)]
        );
    }
}
