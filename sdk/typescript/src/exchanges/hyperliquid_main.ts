/**
 * Hyperliquid mainnet exchange namespace.
 *
 * Auth: EIP-712 typed data signing (chainId=1337, "Exchange" domain, primaryType="Agent").
 * Signed structure:
 *   1. action JSON → msgpack
 *   2. actionHash = keccak256(msgpack(action) || nonce_u64_le || vaultAddress_20)
 *   3. EIP-712 message: {source: "a", connectionId: actionHash}
 *   4. typedDataHash = keccak256("\x19\x01" || domainSeparator || hashStruct(message))
 *   5. secp256k1 sign → (r, s, v)
 *
 * Reference: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing
 * Reference impl: TBD enclave worker brief PHASE-1-EIP712-HYPERLIQUID-BRIEF.md
 */

import { BaseExchange } from "./base.js";
import type { SignResult, ExchangeResponse } from "../types.js";

const HYPERLIQUID_API_BASE = "https://api.hyperliquid.xyz";

export class HyperliquidMainExchange extends BaseExchange {
  /**
   * POST /info — read-only queries (no signing required server-side, but we
   * still emit a VPP for audit consistency).
   */
  async getClearingHouseState(user: string): Promise<ExchangeResponse> {
    const url = `${HYPERLIQUID_API_BASE}/info`;
    const body = { type: "clearinghouseState", user };
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    // No VPP for pure-info calls; return synthetic placeholder
    return {
      status: resp.status,
      data,
      verifiable_proof: this.#syntheticVPP("info_call"),
    };
  }

  /**
   * Place a Hyperliquid order via the /exchange endpoint.
   *
   * @example
   *   signer.hyperliquid_main.order({
   *     asset: 0,                // BTC = 0 on mainnet
   *     isBuy: true,
   *     price: "50000",
   *     size: "0.001",
   *     reduceOnly: false,
   *     orderType: { limit: { tif: "Gtc" } },
   *   });
   */
  async order(opts: HyperliquidOrderOpts): Promise<ExchangeResponse> {
    const nonce = Date.now();
    const action = {
      type: "order",
      orders: [{
        a: opts.asset,
        b: opts.isBuy,
        p: opts.price,
        s: opts.size,
        r: opts.reduceOnly,
        t: opts.orderType,
      }],
      grouping: "na",
    };

    // Sign via enclave
    const { signature, verifiable_proof } = await this.sign({
      action: "order",
      actionData: { action, nonce, vaultAddress: opts.vaultAddress ?? null },
    });

    if (!signature || signature.scheme !== "eip712") {
      throw new Error("Hyperliquid requires eip712 signature scheme");
    }

    // Parse signature components from gateway (expected: hex-encoded r||s||v)
    const sigObj = JSON.parse(signature.value) as { r: string; s: string; v: number };

    // Submit to Hyperliquid /exchange
    const url = `${HYPERLIQUID_API_BASE}/exchange`;
    const body = {
      action,
      nonce,
      signature: sigObj,
      vaultAddress: opts.vaultAddress ?? null,
    };
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    return { status: resp.status, data, verifiable_proof };
  }

  /**
   * Cancel an existing order by oid.
   */
  async cancel(opts: { asset: number; oid: number }): Promise<ExchangeResponse> {
    const nonce = Date.now();
    const action = {
      type: "cancel",
      cancels: [{ a: opts.asset, o: opts.oid }],
    };

    const { signature, verifiable_proof } = await this.sign({
      action: "cancel",
      actionData: { action, nonce, vaultAddress: null },
    });

    if (!signature || signature.scheme !== "eip712") {
      throw new Error("Hyperliquid requires eip712 signature scheme");
    }
    const sigObj = JSON.parse(signature.value) as { r: string; s: string; v: number };

    const url = `${HYPERLIQUID_API_BASE}/exchange`;
    const body = { action, nonce, signature: sigObj, vaultAddress: null };
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    return { status: resp.status, data, verifiable_proof };
  }

  /**
   * EIP-712 schemes do not use HTTP headers for signing (signature is in body).
   * Stub for trait completeness.
   */
  protected headersFromSignatureImpl(): Record<string, string> {
    return {};
  }

  #syntheticVPP(reason: string) {
    return {
      version: "0.1" as const,
      request_hash: "0x" + "0".repeat(64),
      policy_canonical_hash: "0x" + "0".repeat(64),
      policy_id: "info-call-no-policy",
      decision: "APPROVE" as const,
      error_code: null,
      signature: null,
      enclave_attestation: "",
      metadata: {
        timestamp: new Date().toISOString(),
        policy_version: "0.1" as const,
      },
    };
  }
}

export interface HyperliquidOrderOpts {
  asset: number;
  isBuy: boolean;
  price: string;       // strings to preserve precision
  size: string;
  reduceOnly: boolean;
  orderType: { limit: { tif: "Gtc" | "Ioc" | "Alo" } } | { trigger: unknown };
  vaultAddress?: string | null;
}
