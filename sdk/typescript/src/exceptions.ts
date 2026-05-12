/**
 * Custom error classes for @usenami/signer.
 *
 * Throw a specific subclass so callers can switch() on error.constructor.name
 * or use `instanceof` checks for control flow.
 */

export class SignerError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "SignerError";
  }
}

/**
 * The signer gateway rejected the sign request based on UPL policy.
 * Inspect `errorCode` for the specific UPL rule that fired (e.g.,
 * "size_exceeds_max", "destination_not_whitelisted").
 */
export class PolicyDeniedError extends SignerError {
  constructor(
    public readonly errorCode: string,
    public readonly policyId: string,
    message?: string,
  ) {
    super(message ?? `UPL policy denied: ${errorCode}`);
    this.name = "PolicyDeniedError";
  }
}

/**
 * The signed request reached the exchange but the exchange itself returned
 * an error (HTTP 4xx/5xx). Examine `.exchangeStatus` and `.exchangeBody`.
 */
export class ExchangeRejectedError extends SignerError {
  constructor(
    public readonly exchangeStatus: number,
    public readonly exchangeBody: unknown,
    message?: string,
  ) {
    super(message ?? `Exchange returned HTTP ${exchangeStatus}`);
    this.name = "ExchangeRejectedError";
  }
}

/**
 * Gateway / network / configuration issue (timeout, DNS, 502, etc.).
 * Not policy-related, not exchange-related.
 */
export class TransportError extends SignerError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "TransportError";
  }
}

/**
 * Verifiable Policy Proof verification failed for some reason.
 * Inspect `.reason` for what specifically went wrong:
 *  - "invalid_signature" — Nitro attestation signature didn't match AWS root
 *  - "pcr0_not_registered" — On-chain registry returned false / wrong owner
 *  - "timestamp_drift" — Proof timestamp outside acceptable window
 *  - "request_hash_mismatch" — Computed hash doesn't match proof claim
 *  - "tampered_proof" — Generic tampering detected
 */
export class VerificationError extends SignerError {
  constructor(
    public readonly reason: string,
    message?: string,
  ) {
    super(message ?? `VPP verification failed: ${reason}`);
    this.name = "VerificationError";
  }
}
