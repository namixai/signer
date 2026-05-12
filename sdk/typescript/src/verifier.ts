/**
 * VPP verifier — independent client-side verification of Verifiable Policy Proofs.
 *
 * Per VPP Spec v0.1 §5 Verification Algorithm.
 *
 * Usage:
 *   import { verifyVPP } from "@usenami/signer/verifier";
 *
 *   const result = await verifyVPP(proof, {
 *     expectedOwner: "0x742d35Cc...",
 *     expectedPCR0Hex: "10c5c26d...599f4",  // Level 1
 *     registryRpcUrl: "https://mainnet.base.org",  // Level 2 (optional)
 *   });
 *
 *   if (!result.valid) {
 *     console.error("Invalid VPP:", result.reason);
 *   } else {
 *     console.log("Trust level:", result.trustLevel);  // "local" or "registry-anchored"
 *   }
 */

import type { VerifiablePolicyProof } from "./types.js";
import { VerificationError } from "./exceptions.js";

export interface VerifyOptions {
  /** Expected owner address (the Usenami deployer you trust). */
  expectedOwner?: string;
  /** Expected enclave PCR0 hex. If provided, attestation must match. */
  expectedPCR0Hex?: string;
  /** Base mainnet RPC for on-chain registry check (Level 2). */
  registryRpcUrl?: string;
  /** Registry contract address (defaults to Usenami production registry). */
  registryAddress?: string;
  /** Replay window in seconds. Default 600 (10 min). */
  replayWindowSec?: number;
}

export interface VerifyResult {
  valid: boolean;
  trustLevel: "local" | "registry-anchored" | "invalid";
  attestedPCR0?: string;
  owner?: string;
  reason?: string;
}

/**
 * Verify a Verifiable Policy Proof per VPP Spec §5.
 *
 * Level 1 (local): verifies AWS Nitro signature + matches expected PCR0.
 * Level 2 (registry-anchored): additionally queries Base registry contract.
 *
 * Throws VerificationError on tampering; returns invalid result on policy
 * mismatches.
 */
export async function verifyVPP(
  proof: VerifiablePolicyProof,
  opts: VerifyOptions = {},
): Promise<VerifyResult> {
  // Step 1: version check
  if (proof.version !== "0.1") {
    throw new VerificationError("unsupported_proof_version");
  }

  // Step 2: parse + verify Nitro attestation document
  const attested = await parseNitroAttestation(proof.enclave_attestation);
  if (!attested.signatureValid) {
    throw new VerificationError("invalid_signature", "Nitro attestation signature failed AWS root verification");
  }

  // Step 2c: check expected PCR0 if provided
  if (opts.expectedPCR0Hex) {
    const expected = opts.expectedPCR0Hex.replace(/^0x/, "").toLowerCase();
    if (attested.pcr0Hex !== expected) {
      return {
        valid: false,
        trustLevel: "invalid",
        attestedPCR0: attested.pcr0Hex,
        reason: `PCR0 mismatch: expected ${expected}, got ${attested.pcr0Hex}`,
      };
    }
  }

  // Step 3: registry anchor (Level 2)
  let trustLevel: VerifyResult["trustLevel"] = "local";
  let owner: string | undefined;
  if (proof.registry_anchor && opts.registryRpcUrl) {
    const onChain = await checkRegistry(
      attested.pcr0Hex,
      opts.registryRpcUrl,
      opts.registryAddress ?? proof.registry_anchor.registry_address,
    );
    if (!onChain.active) {
      return {
        valid: false,
        trustLevel: "invalid",
        attestedPCR0: attested.pcr0Hex,
        reason: "pcr0_not_registered",
      };
    }
    if (opts.expectedOwner && onChain.owner.toLowerCase() !== opts.expectedOwner.toLowerCase()) {
      return {
        valid: false,
        trustLevel: "invalid",
        attestedPCR0: attested.pcr0Hex,
        reason: `registry_owner_mismatch: expected ${opts.expectedOwner}, got ${onChain.owner}`,
      };
    }
    owner = onChain.owner;
    trustLevel = "registry-anchored";
  }

  // Step 4: timestamp drift
  const proofTime = new Date(proof.metadata.timestamp).getTime();
  const now = Date.now();
  const drift = Math.abs(now - proofTime) / 1000;
  const replayWindow = opts.replayWindowSec ?? 600;
  if (drift > replayWindow) {
    return {
      valid: false,
      trustLevel: "invalid",
      attestedPCR0: attested.pcr0Hex,
      reason: `timestamp_drift: ${drift}s > ${replayWindow}s window`,
    };
  }

  // Step 5/6: decision-specific checks
  if (proof.decision === "APPROVE" && !proof.signature) {
    return {
      valid: false,
      trustLevel: "invalid",
      reason: "approve_without_signature",
    };
  }
  if (proof.decision === "REJECT" && proof.signature) {
    return {
      valid: false,
      trustLevel: "invalid",
      reason: "reject_with_signature",
    };
  }

  return {
    valid: true,
    trustLevel,
    attestedPCR0: attested.pcr0Hex,
    owner,
  };
}

// --- Internal: stubs to be replaced with real implementations in W4 ---

async function parseNitroAttestation(_b64: string): Promise<{ signatureValid: boolean; pcr0Hex: string; timestamp: number }> {
  // TODO W4 — actual COSE_Sign1 parsing + AWS root cert verification + PCR0 extraction.
  // For scaffold: stub assumes attestation is valid and PCR0 is whatever the gateway claimed.
  // Production verifier MUST cryptographically verify the COSE signature against
  // pinned AWS Nitro root CA before trusting any field from the document.
  throw new Error("parseNitroAttestation not implemented yet — W4 deliverable");
}

async function checkRegistry(
  _pcr0Hex: string,
  _rpcUrl: string,
  _registryAddress: string,
): Promise<{ active: boolean; owner: string }> {
  // TODO W4 — viem-based eth_call to UsenamiAttestationRegistry.isPCR0Active(bytes48)
  // Returns (bool active, address owner) — decode and return.
  throw new Error("checkRegistry not implemented yet — W4 deliverable");
}
