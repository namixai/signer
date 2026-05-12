/**
 * KuCoin Futures exchange namespace.
 *
 * Auth: HMAC-SHA256 v2 headers.
 * Signed string: timestamp + method + endpoint + body
 *
 * Reference Python impl: sdk/python/src/usenami_signer/exchanges/kucoin.py
 */

import { BaseExchange } from "./base.js";
import type { SignResult, ExchangeResponse } from "../types.js";

const KUCOIN_FUTURES_BASE_URL = "https://api-futures.kucoin.com";

export class KucoinExchange extends BaseExchange {
  /**
   * GET /api/v1/account-overview — account balances.
   */
  async getAccounts(currency: string = "USDT"): Promise<ExchangeResponse> {
    return this.signAndExecute({
      action: "attest", // KuCoin /accounts is read-only; treat as attestation
      method: "GET",
      path: "/api/v1/account-overview",
      params: { currency },
      exchangeBaseUrl: KUCOIN_FUTURES_BASE_URL,
    });
  }

  /**
   * POST /api/v1/orders — place an order.
   *
   * @example
   *   signer.kucoin.placeOrder({
   *     clientOid: "uuid-here",
   *     symbol: "BTCUSDTM",
   *     side: "buy",
   *     leverage: "5",
   *     size: 1,
   *     type: "limit",
   *     price: "60000",
   *   });
   */
  async placeOrder(body: KucoinOrderBody): Promise<ExchangeResponse> {
    return this.signAndExecute({
      action: "order",
      method: "POST",
      path: "/api/v1/orders",
      body,
      exchangeBaseUrl: KUCOIN_FUTURES_BASE_URL,
    });
  }

  /**
   * DELETE /api/v1/orders/{orderId} — cancel an order.
   */
  async cancelOrder(orderId: string): Promise<ExchangeResponse> {
    return this.signAndExecute({
      action: "cancel",
      method: "DELETE",
      path: `/api/v1/orders/${orderId}`,
      exchangeBaseUrl: KUCOIN_FUTURES_BASE_URL,
    });
  }

  /**
   * KuCoin signature → HTTP headers.
   * KC-API-* family per KuCoin Futures v2 docs.
   */
  protected headersFromSignatureImpl(signature: SignResult["signature"]): Record<string, string> {
    if (!signature || signature.scheme !== "hmac-sha256") {
      throw new Error("KuCoin requires hmac-sha256 signature scheme");
    }
    // Gateway returns signature.value as JSON-encoded header dict
    return JSON.parse(signature.value) as Record<string, string>;
  }
}

export interface KucoinOrderBody {
  clientOid: string;
  symbol: string;
  side: "buy" | "sell";
  leverage: string;
  size: number;
  type: "limit" | "market";
  price?: string;
  stopPrice?: string;
  reduceOnly?: boolean;
}
