/**
 * @usenami/signer — TypeScript SDK for Usenami Signer.
 *
 * Hardware-isolated signing for crypto exchanges via AWS Nitro Enclave + KMS.
 * Per-exchange namespaces, Verifiable Policy Proof on every call.
 *
 * @see https://github.com/namixai/signer
 */

export { Signer } from "./client.js";

export type {
  Exchange,
  ActionType,
  UPLRules,
  UPLPolicy,
  DestinationEntry,
  VerifiablePolicyProof,
  SignResult,
  ExchangeResponse,
  SignerConfig,
} from "./types.js";

export {
  SignerError,
  PolicyDeniedError,
  ExchangeRejectedError,
  TransportError,
  VerificationError,
} from "./exceptions.js";

// Per-exchange classes exported for advanced users / typing helpers.
export { KucoinExchange } from "./exchanges/kucoin.js";
export { HyperliquidMainExchange } from "./exchanges/hyperliquid_main.js";
