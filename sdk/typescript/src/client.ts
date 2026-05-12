/**
 * Main Signer client. Per-exchange namespaces exposed as properties.
 *
 * @example
 *   import { Signer } from "@usenami/signer";
 *
 *   const signer = new Signer({
 *     baseUrl: "https://signer-demo.usenami.io:8443",
 *     apiKey: "sk_live_xxxxxxxxxxxx",
 *   });
 *
 *   const { data } = await signer.kucoin.getAccounts();
 *   const { data, verifiable_proof } = await signer.hyperliquid_main.order({
 *     asset: 0, isBuy: true, price: "50000", size: "0.001",
 *     reduceOnly: false, orderType: { limit: { tif: "Gtc" } },
 *   });
 *
 *   // Audit: every call returns a verifiable_proof
 *   console.log("Signed under policy:", verifiable_proof.policy_id);
 */

import type { SignerConfig } from "./types.js";
import { KucoinExchange } from "./exchanges/kucoin.js";
import { HyperliquidMainExchange } from "./exchanges/hyperliquid_main.js";
// Stubs — actual impls follow same KucoinExchange pattern:
// import { BinanceExchange } from "./exchanges/binance.js";
// import { BybitExchange } from "./exchanges/bybit.js";
// import { OkxExchange } from "./exchanges/okx.js";
// import { AsterdexExchange } from "./exchanges/asterdex.js";

export class Signer {
  readonly kucoin: KucoinExchange;
  readonly hyperliquid_main: HyperliquidMainExchange;
  // TODO when scaffolding fills out:
  // readonly binance: BinanceExchange;
  // readonly bybit: BybitExchange;
  // readonly okx: OkxExchange;
  // readonly asterdex: AsterdexExchange;

  constructor(config: SignerConfig) {
    this.#validate(config);
    this.kucoin = new KucoinExchange(config, "kucoin_futures");
    this.hyperliquid_main = new HyperliquidMainExchange(config, "hyperliquid_main");
    // this.binance = new BinanceExchange(config, "binance");
    // this.bybit = new BybitExchange(config, "bybit");
    // this.okx = new OkxExchange(config, "okx");
    // this.asterdex = new AsterdexExchange(config, "asterdex");
  }

  #validate(config: SignerConfig): void {
    if (!config.baseUrl) throw new Error("SignerConfig.baseUrl required");
    if (!config.apiKey) throw new Error("SignerConfig.apiKey required");
    if (!config.baseUrl.startsWith("http://") && !config.baseUrl.startsWith("https://")) {
      throw new Error("SignerConfig.baseUrl must be http(s)://");
    }
  }
}
