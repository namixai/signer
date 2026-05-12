/**
 * Base class for per-exchange namespaces.
 *
 * Each exchange (kucoin, binance, bybit, okx, hyperliquid_main, asterdex)
 * extends this and adds high-level convenience methods on top of .sign().
 */

import type {
  ActionType,
  Exchange,
  SignResult,
  ExchangeResponse,
  SignerConfig,
} from "../types.js";
import { TransportError, PolicyDeniedError, ExchangeRejectedError } from "../exceptions.js";

export abstract class BaseExchange {
  protected readonly config: SignerConfig;
  protected readonly exchange: Exchange;

  constructor(config: SignerConfig, exchange: Exchange) {
    this.config = config;
    this.exchange = exchange;
  }

  /**
   * Low-level sign: send a sign request to the gateway, receive signature + VPP.
   * Does NOT execute the signed request against the exchange — that's the
   * caller's responsibility (per Programmable HSM doctrine: we sign, you submit).
   */
  async sign(opts: {
    action: ActionType;
    method?: string;       // HTTP method for CEX adapters
    path?: string;         // HTTP path for CEX adapters
    body?: unknown;        // request body (will be canonicalized server-side)
    params?: Record<string, string | number>; // query params for CEX
    actionData?: unknown;  // for EIP-712 / wallet-style adapters
  }): Promise<SignResult> {
    const url = `${this.config.baseUrl}/sign`;
    const payload = {
      exchange: this.exchange,
      action: opts.action,
      method: opts.method,
      path: opts.path,
      body: opts.body,
      params: opts.params,
      action_data: opts.actionData,
    };

    const resp = await this.#fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify(payload),
    });

    const data = await resp.json() as {
      signature: SignResult["signature"];
      verifiable_proof: SignResult["verifiable_proof"];
      error?: { code: string; message: string; policy_id?: string };
    };

    if (!resp.ok) {
      if (data.error?.code && data.verifiable_proof?.decision === "REJECT") {
        throw new PolicyDeniedError(
          data.error.code,
          data.verifiable_proof.policy_id,
          data.error.message,
        );
      }
      throw new TransportError(
        `Gateway returned HTTP ${resp.status}: ${data.error?.message ?? "unknown"}`,
      );
    }

    return {
      signature: data.signature,
      verifiable_proof: data.verifiable_proof,
    };
  }

  /**
   * Sign + execute against the exchange. Returns exchange response + VPP.
   *
   * For most use cases. Use .sign() directly only if you need to inspect
   * or modify the signed request before submission.
   */
  protected async signAndExecute<T = unknown>(opts: {
    action: ActionType;
    method: string;
    path: string;
    exchangeBaseUrl: string;
    body?: unknown;
    params?: Record<string, string | number>;
  }): Promise<ExchangeResponse<T>> {
    const { signature, verifiable_proof } = await this.sign({
      action: opts.action,
      method: opts.method,
      path: opts.path,
      body: opts.body,
      params: opts.params,
    });

    // Build exchange URL + headers from signature scheme
    const exchangeUrl = this.#buildExchangeUrl(opts.exchangeBaseUrl, opts.path, opts.params);
    const headers = this.#headersFromSignature(signature);
    const exchangeResp = await this.#fetch(exchangeUrl, {
      method: opts.method,
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });

    const data = await exchangeResp.json() as T;

    if (!exchangeResp.ok) {
      throw new ExchangeRejectedError(exchangeResp.status, data);
    }

    return { status: exchangeResp.status, data, verifiable_proof };
  }

  // --- Internal helpers (implementation TBD per exchange) ---

  /**
   * Build the per-exchange request URL (handles query param encoding).
   * Subclasses override if the exchange has unusual URL conventions.
   */
  #buildExchangeUrl(base: string, path: string | undefined, params?: Record<string, string | number>): string {
    const url = new URL(path ?? "/", base);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, String(v));
      }
    }
    return url.toString();
  }

  /**
   * Convert the VPP signature object into HTTP headers per exchange convention.
   * HMAC exchanges (KuCoin, Binance, Bybit, OKX) override this with their
   * specific header set. EIP-712 exchanges may not need headers (body holds sig).
   *
   * MUST be implemented by subclass.
   */
  protected abstract headersFromSignatureImpl(signature: SignResult["signature"]): Record<string, string>;

  #headersFromSignature(signature: SignResult["signature"]): Record<string, string> {
    if (!signature) {
      return {};
    }
    return this.headersFromSignatureImpl(signature);
  }

  async #fetch(url: string, init: RequestInit): Promise<Response> {
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), this.config.timeoutMs ?? 30000);
    try {
      return await fetch(url, { ...init, signal: ctrl.signal });
    } catch (e) {
      if (e instanceof Error && e.name === "AbortError") {
        throw new TransportError(`Request timed out after ${this.config.timeoutMs ?? 30000}ms`, e);
      }
      throw new TransportError(String(e), e);
    } finally {
      clearTimeout(timeout);
    }
  }
}
