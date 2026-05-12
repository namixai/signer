# @usenami/signer (TypeScript)

**Hardware-isolated signing for crypto exchanges. TypeScript SDK.**

Mirror of [`sdk/python/usenami-signer`](../python). Same Signer object, same per-exchange namespaces, same Verifiable Policy Proof return values.

---

## Install

```bash
npm install @usenami/signer
# optional: viem peer dep for Level-2 verification
npm install viem
```

---

## Quick start

```typescript
import { Signer } from "@usenami/signer";

const signer = new Signer({
  baseUrl: "https://signer-demo.usenami.io:8443",
  apiKey: process.env.USENAMI_API_KEY!,
  baseRpcUrl: "https://mainnet.base.org", // optional: enables on-chain VPP verification
});

// Sign and submit in one call
const { data, verifiable_proof } = await signer.kucoin.getAccounts();
console.log("KuCoin accounts:", data);
console.log("Policy:", verifiable_proof.policy_id, "decision:", verifiable_proof.decision);

// EIP-712 example: Hyperliquid
const order = await signer.hyperliquid_main.order({
  asset: 0,            // BTC
  isBuy: true,
  price: "50000",
  size: "0.001",
  reduceOnly: false,
  orderType: { limit: { tif: "Gtc" } },
});
console.log("Order response:", order.data);
console.log("Audit:", order.verifiable_proof);
```

---

## Verifiable Policy Proof verification

```typescript
import { verifyVPP } from "@usenami/signer/verifier";

const result = await verifyVPP(order.verifiable_proof, {
  expectedOwner: "0x...usenami-deployer-address",
  expectedPCR0Hex: "10c5c26d...599f4",
  registryRpcUrl: "https://mainnet.base.org",
});

if (result.valid && result.trustLevel === "registry-anchored") {
  console.log("Action verified on-chain. Attested PCR0:", result.attestedPCR0);
}
```

---

## API surface

### `new Signer(config)`

Config:
- `baseUrl` — gateway URL (string, required)
- `apiKey` — your API key (string, required)
- `baseRpcUrl` — Base RPC (optional, for Level-2 VPP verification)
- `registryAddress` — registry contract address (optional, defaults to Usenami production registry)
- `timeoutMs` — request timeout (default 30000)

### Per-exchange namespaces

Each namespace has high-level helpers and a low-level `.sign()`. Current scaffold:

| Exchange | High-level methods | Scheme |
|---|---|---|
| `signer.kucoin` | `.getAccounts()`, `.placeOrder()`, `.cancelOrder()` | HMAC-SHA256 |
| `signer.hyperliquid_main` | `.order()`, `.cancel()`, `.getClearingHouseState()` | EIP-712 |
| `signer.binance` | (TBD W2) | HMAC-SHA256 |
| `signer.bybit` | (TBD W2) | HMAC-SHA256 |
| `signer.okx` | (TBD W2) | HMAC-SHA256 |
| `signer.asterdex` | (TBD W3) | EIP-712 |

Every method returns `{ data, verifiable_proof }`.

---

## Errors

```typescript
import {
  PolicyDeniedError,
  ExchangeRejectedError,
  TransportError,
  VerificationError,
} from "@usenami/signer";

try {
  await signer.kucoin.placeOrder({ ... });
} catch (e) {
  if (e instanceof PolicyDeniedError) {
    console.log("UPL blocked it:", e.errorCode);
  } else if (e instanceof ExchangeRejectedError) {
    console.log("Exchange said no:", e.exchangeStatus);
  }
}
```

---

## Status

**Phase 1 Scaffold (W1, 2026-05-11).** Production-ready code shipping W3-W4. Current state:

- ✅ Type definitions for UPL, VPP, SignerConfig
- ✅ Base exchange class + KuCoin namespace (full impl)
- ✅ Hyperliquid_main namespace (scaffold, signing flow defined, awaits enclave EIP-712 W2)
- 🔜 Binance/Bybit/OKX namespaces (W2)
- 🔜 Verifier with real Nitro attestation parsing (W4)
- 🔜 Test vectors against gateway mock + production endpoint

---

## License

Apache-2.0
