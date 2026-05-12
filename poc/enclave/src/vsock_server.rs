//! vsock listener and per-connection request loop.
//!
//! Wire framing: 4-byte big-endian `u32` length, then exactly that many bytes
//! of UTF-8 JSON. Length must be in `1..=MAX_MESSAGE_BYTES`. Anything outside
//! that range causes the connection to be dropped after sending a single
//! `payload_too_large` / `bad_request` response.
//!
//! Concurrency: each accepted connection runs in its own task. Per-connection
//! errors are logged via `tracing::warn!` and never bubble up to the accept
//! loop; the server stays alive even if one client misbehaves.
//!
//! Logging policy: we log only `action`, `latency_ms`, `success` bool, and
//! `error_code` (when set). Request bodies, signatures, and secrets are
//! never logged.

use crate::handler;
use crate::proto::{err_code, SignRequest, SignResponse, LENGTH_PREFIX_BYTES, MAX_MESSAGE_BYTES};
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{info, warn};

/// Hard cap on concurrent connections being processed. The enclave has
/// fixed memory (1024 MiB on Day 2) and OOM kills the whole process with
/// no recovery. A misbehaving or compromised parent could otherwise burst
/// us into oblivion.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Bind on `(VMADDR_CID_ANY, port)` and accept connections forever.
pub async fn serve(port: u32) -> Result<()> {
    let addr = VsockAddr::new(VMADDR_CID_ANY, port);
    let mut listener =
        VsockListener::bind(addr).with_context(|| format!("vsock bind on port {port}"))?;
    info!(port, cid = "ANY", "vsock listener ready");

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        // Block accepting new connections until a permit is available.
        // This is the back-pressure: kernel queues at vsock layer, no
        // unbounded task spawning regardless of attacker burst size.
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                // Semaphore closed — should never happen in our flow.
                return Err(anyhow!("connection semaphore closed unexpectedly"));
            }
        };

        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(async move {
                    let _permit = permit; // released on task drop
                    if let Err(e) = handle_connection(stream).await {
                        warn!(peer_cid = peer.cid(), peer_port = peer.port(), error = %e, "connection ended with error");
                    }
                });
            }
            Err(e) => {
                // Non-fatal: e.g. transient OOM, fd exhaustion. Keep serving.
                drop(permit);
                warn!(error = %e, "accept failed");
            }
        }
    }
}

/// Handle a single connection: one request -> one response, then close.
///
/// We do NOT keep the connection open for multiple requests in this PoC.
/// Multi-request multiplexing is a Phase 4+ optimization.
async fn handle_connection(mut stream: VsockStream) -> Result<()> {
    let started = Instant::now();
    let action_label;
    let success;
    let error_code: Option<&'static str>;

    match read_frame(&mut stream).await {
        Err(FrameError::TooLarge) => {
            action_label = "?";
            success = false;
            error_code = Some(err_code::PAYLOAD_TOO_LARGE);
            write_response(&mut stream, &SignResponse::err(err_code::PAYLOAD_TOO_LARGE)).await?;
        }
        Err(FrameError::Io(e)) => {
            // Peer hung up mid-frame, etc.
            return Err(anyhow!(e));
        }
        Ok(bytes) => {
            match serde_json::from_slice::<SignRequest>(&bytes) {
                Err(_) => {
                    action_label = "?";
                    success = false;
                    error_code = Some(err_code::BAD_REQUEST);
                    write_response(&mut stream, &SignResponse::err(err_code::BAD_REQUEST)).await?;
                }
                Ok(req) => {
                    // Capture action label BEFORE moving req into handler.
                    action_label = match req.action.as_str() {
                        "ping" => "ping",
                        "sign" => "sign",
                        _ => "unknown",
                    };
                    let resp = handler::handle(req);
                    success = resp.error.is_none();
                    error_code = match resp.error.as_deref() {
                        Some(err_code::BAD_REQUEST) => Some(err_code::BAD_REQUEST),
                        Some(err_code::PAYLOAD_TOO_LARGE) => Some(err_code::PAYLOAD_TOO_LARGE),
                        Some(err_code::KMS_DECRYPT_DENIED) => Some(err_code::KMS_DECRYPT_DENIED),
                        Some(err_code::INTERNAL_ERROR) => Some(err_code::INTERNAL_ERROR),
                        Some(_) => Some(err_code::INTERNAL_ERROR),
                        None => None,
                    };
                    write_response(&mut stream, &resp).await?;
                }
            }
        }
    }

    let latency_ms = started.elapsed().as_millis() as u64;
    info!(
        action = action_label,
        latency_ms,
        success,
        error = error_code.unwrap_or(""),
        "request handled"
    );
    Ok(())
}

#[derive(thiserror::Error, Debug)]
enum FrameError {
    #[error("payload exceeds {MAX_MESSAGE_BYTES} byte cap")]
    TooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Read one length-prefixed frame from the stream.
///
/// On `TooLarge`, the four prefix bytes have already been consumed. The
/// caller is responsible for sending the error response and dropping the
/// connection — we do NOT try to skip past the oversized body.
async fn read_frame(stream: &mut VsockStream) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Serialize and write one length-prefixed JSON response.
async fn write_response(stream: &mut VsockStream, resp: &SignResponse) -> Result<()> {
    let json = serde_json::to_vec(resp)?;
    if json.len() > MAX_MESSAGE_BYTES {
        // Should never happen for our tiny responses; fail safely.
        return Err(anyhow!("response exceeds {} byte cap", MAX_MESSAGE_BYTES));
    }
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&json).await?;
    stream.flush().await?;
    Ok(())
}
