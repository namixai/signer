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

mod aws;
mod handlers;
mod proto;
mod state;
mod vsock;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::state::{AppState, EnclaveTarget};

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
];

/// Maximum HTTP request body the gateway accepts. Realistic KuCoin order
/// bodies are well under 1 KiB; 32 KiB is a generous cap.
const MAX_REQUEST_BYTES: usize = 32 * 1024;

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
        anyhow::bail!(
            "no exchange blobs loaded — set --blobs-dir or --blob-path"
        );
    }
    let exchange_list: Vec<&str> = blobs.keys().map(String::as_str).collect();
    info!(exchanges = ?exchange_list, "ciphertext blobs loaded");

    let state = AppState::new(
        blobs,
        EnclaveTarget {
            cid: cli.enclave_cid,
            port: cli.enclave_port,
        },
    );

    let app = Router::new()
        .route("/sign", post(handlers::post_sign))
        .route("/healthz", get(handlers::get_healthz))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("bind {}", cli.bind))?;
    info!(local_addr = %listener.local_addr()?, "listener ready");

    axum::serve(listener, app)
        .await
        .context("axum::serve exited")?;
    Ok(())
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
fn load_all_blobs(cli: &Cli) -> Result<HashMap<String, Vec<u8>>> {
    let mut blobs: HashMap<String, Vec<u8>> = HashMap::new();

    if let Some(dir) = &cli.blobs_dir {
        let dir_path = Path::new(dir);
        for exchange in SUPPORTED_EXCHANGES {
            let candidate = dir_path.join(format!("{}.enc", exchange));
            if candidate.exists() {
                let bytes = aws::load_blob_from_path(candidate.to_str().unwrap_or(""))
                    .with_context(|| format!("load {} blob from {:?}", exchange, candidate))?;
                info!(
                    exchange = %exchange,
                    path = %candidate.display(),
                    bytes = bytes.len(),
                    "blob loaded"
                );
                blobs.insert((*exchange).to_owned(), bytes);
            } else {
                warn!(
                    exchange = %exchange,
                    path = %candidate.display(),
                    "blob not present — exchange unavailable"
                );
            }
        }
    }

    if let Some(legacy_path) = &cli.blob_path {
        if !blobs.contains_key("kucoin") {
            let bytes = aws::load_blob_from_path(legacy_path)
                .context("load legacy --blob-path as kucoin blob")?;
            info!(
                exchange = "kucoin",
                path = %legacy_path,
                bytes = bytes.len(),
                "legacy KuCoin blob loaded"
            );
            blobs.insert("kucoin".to_owned(), bytes);
        }
    }

    Ok(blobs)
}
