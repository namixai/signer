/**
 * Core type definitions for @usenami/signer.
 */

/**
 * Supported exchange identifiers. Per-venue namespacing — keep alphabetical.
 */
export type Exchange =
  | "asterdex"        // EIP-712, BNB chain
  | "binance"         // HMAC-SHA256
  | "bybit"           // HMAC-SHA256
  | "hyperliquid_main"  // EIP-712, Hyperliquid L1
  // | "hyperliquid_xyz" // future
  // | "hyperliquid_km"  // future
  // | "hyperliquid_cash"// future
  | "kucoin_futures"  // HMAC-SHA256
  | "okx";            // HMAC-SHA256 + passphrase

/**
 * Action types per UPL Spec v0.1 §4.1.
 */
export type ActionType =
  | "order"
  | "cancel"
  | "transfer"
  | "withdrawal"
  | "approve"
  | "attest";

/**
 * UPL policy rules (subset for v0.1).
 */
export interface UPLRules {
  allowed_actions?: ActionType[];
  allowed_exchanges?: Exchange[];
  allowed_assets?: string[];
  max_position_size_usd?: number;
  destination_whitelist?: DestinationEntry[];
  min_interval_seconds?: number;
  allowed_chains?: string[];
}

export interface DestinationEntry {
  venue: string;
  chain: string;
  address: string;
}

/**
 * UPL policy document (per UPL Spec v0.1 §3).
 */
export interface UPLPolicy {
  version: "0.1";
  policy_id: string;
  owner: string;
  issued_at?: string;
  valid_until?: string;
  rules: UPLRules;
  attestation_id?: string;
  state_anchor_block?: number | null;
  description?: string;
}

/**
 * Verifiable Policy Proof (per VPP Spec v0.1 §3).
 */
export interface VerifiablePolicyProof {
  version: "0.1";
  request_hash: string;          // hex SHA-256
  policy_canonical_hash: string; // hex SHA-256
  policy_id: string;
  decision: "APPROVE" | "REJECT";
  error_code: string | null;
  signature: {
    scheme: "hmac-sha256" | "eip712" | "stark" | "ed25519";
    value: string; // base64 or hex per scheme
    exchange: Exchange;
  } | null;
  enclave_attestation: string;   // base64 AWS Nitro doc
  registry_anchor?: {
    chain: string;
    registry_address: string;
    block_number: number;
    tx_hash: string | null;
  };
  metadata: {
    timestamp: string;
    request_size_bytes?: number;
    policy_version: "0.1";
  };
}

/**
 * Result returned from .sign() — includes signature + VPP for audit.
 */
export interface SignResult {
  signature: VerifiablePolicyProof["signature"];
  verifiable_proof: VerifiablePolicyProof;
}

/**
 * Result returned from a high-level convenience call like .getBalance().
 */
export interface ExchangeResponse<T = unknown> {
  status: number;
  data: T;
  verifiable_proof: VerifiablePolicyProof;
}

/**
 * Client configuration.
 */
export interface SignerConfig {
  /**
   * Base URL of the signer gateway, e.g. "http://signer-demo.usenami.io:8443"
   * or your own self-hosted enclave's gateway.
   */
  baseUrl: string;

  /**
   * API key (customer identifier the gateway recognizes for routing/auth).
   * For Phase 1 pilots this is provisioned by Usenami operations.
   */
  apiKey: string;

  /**
   * Optional Base RPC URL for VPP Level-2 verification (on-chain registry).
   * If omitted, verification only checks AWS Nitro attestation (Level 1).
   */
  baseRpcUrl?: string;

  /**
   * Optional on-chain registry contract address.
   * Default: production registry on Base mainnet (TBD W2).
   */
  registryAddress?: string;

  /**
   * Request timeout in milliseconds. Default 30000.
   */
  timeoutMs?: number;
}
