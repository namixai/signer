//! H5: fetch an NSM-signed COSE attestation document from `/dev/nsm`.
//!
//! The enclave already reaches NSM *indirectly* — `kmstool_enclave_cli` builds
//! an attestation doc for every KMS Decrypt (`kms_client`) — but that document
//! never surfaces to a caller. This module asks the NSM driver DIRECTLY for a
//! `Request::Attestation`, so the gateway can publish the live, COSE-signed
//! proof at `/attestation` (AWS Nitro Attestation PKI). The returned bytes are
//! PUBLIC (PCRs + certificate chain, no secret material).
//!
//! Linux-only: the driver ioctls `/dev/nsm`, which exists ONLY inside a running
//! Nitro enclave. A non-linux stub lets the crate build + unit-test on darwin
//! (mirrors the `tokio-vsock` gate).

/// Why an attestation fetch failed. The handler maps EVERY variant to the
/// generic `internal_error` wire code — a caller never learns which NSM step
/// failed (no oracle), only that no signed document was produced.
#[derive(Debug)]
pub enum AttestationError {
    /// `/dev/nsm` could not be opened (`nsm_init` returned < 0). Does not
    /// happen on a healthy enclave; signals the NSM device is missing.
    NsmInit,
    /// The NSM driver returned a non-`Attestation` / error response.
    NsmRequest,
    /// Built off-enclave (no NSM device). Only reachable in non-linux
    /// test/dev builds — production always runs the linux path in-enclave.
    Unavailable,
}

/// Ask the NSM driver for a COSE-signed attestation document binding the
/// caller `nonce` (and optional `user_data`). Returns the raw `COSE_Sign1`
/// bytes. `public_key` is intentionally omitted — `/attestation` proves the
/// enclave IMAGE (PCR0), not a per-request keypair.
#[cfg(target_os = "linux")]
pub fn nsm_attestation(
    nonce: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
) -> Result<Vec<u8>, AttestationError> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use serde_bytes::ByteBuf;

    let fd = nsm_init();
    if fd < 0 {
        return Err(AttestationError::NsmInit);
    }
    let request = Request::Attestation {
        user_data: user_data.map(ByteBuf::from),
        nonce: nonce.map(ByteBuf::from),
        public_key: None,
    };
    let response = nsm_process_request(fd, request);
    // Always release the NSM fd, success or failure.
    nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        _ => Err(AttestationError::NsmRequest),
    }
}

/// Non-linux stub: NSM only exists inside a Nitro enclave. Off-enclave builds
/// (darwin dev / cross-platform unit tests) have no device, so this fails
/// closed. Production is always the linux path above.
#[cfg(not(target_os = "linux"))]
pub fn nsm_attestation(
    _nonce: Option<Vec<u8>>,
    _user_data: Option<Vec<u8>>,
) -> Result<Vec<u8>, AttestationError> {
    Err(AttestationError::Unavailable)
}
