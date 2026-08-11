//! Usenami Signer enclave entry point.
//!
//! Listens on vsock port 5000 (CID = ANY) and handles `ping` / `sign`
//! requests. Phase 2 stub uses a hardcoded test secret; Phase 3 will
//! add NSM attestation, KMS Decrypt, and S3 GetObject.
//!
//! Platform note: `vsock_server` is Linux-only (vsock is a Linux kernel
//! socket family). On non-Linux hosts the binary still compiles so that
//! `cargo fmt / clippy / test` can run cross-platform, but `main` exits
//! with an error explaining the binary must run on Linux (in practice:
//! inside the Nitro Enclave).

// All four modules are linked unconditionally so unit tests run on every
// host. Only `vsock_server` is Linux-only because it pulls in the vsock
// kernel socket family. On non-Linux hosts, the items in the other modules
// would otherwise look "unused" (because nothing in the binary path calls
// them outside of `vsock_server`), so we silence dead_code there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod attestation;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod dek_cache;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod envelope;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod handler;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod intent_ledger;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod kms_client;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod proto;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod rate_limiter;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod registry;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod signer;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod tofu;
#[cfg(target_os = "linux")]
mod vsock_server;

use anyhow::{bail, Result};
use tracing_subscriber::EnvFilter;

/// vsock port the enclave listens on. Parent connects to `(ENCLAVE_CID, 5000)`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const VSOCK_PORT: u32 = 5000;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    run().await
}

#[cfg(target_os = "linux")]
async fn run() -> Result<()> {
    tracing::info!(port = VSOCK_PORT, "signer-enclave starting");
    vsock_server::serve(VSOCK_PORT).await
}

#[cfg(not(target_os = "linux"))]
async fn run() -> Result<()> {
    tracing::error!("vsock is Linux-only; this binary must run inside the enclave");
    bail!("vsock is Linux-only; build & run inside the Nitro Enclave EIF");
}
