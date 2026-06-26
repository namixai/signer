# Usenami Signer

**Hardware-isolated signing-as-a-service for crypto exchanges.**

Your exchange API secrets never leave a measured AWS Nitro Enclave. Even root on the host VM can't read them. AWS KMS releases secrets only to a specific, attested binary — change one byte, KMS denies.

🔗 **Live demo:** [signer-demo.usenami.io:8443/healthz](http://signer-demo.usenami.io:8443/healthz) (allowlisted pilots only) &middot; full walkthrough in [`DEMO.md`](DEMO.md)
📜 **License:** Apache-2.0

---

## What it does

You upload an encrypted secret once. Your bot calls our SDK to sign requests. The plaintext key exists only inside the enclave's RAM for the duration of a single signing operation, then is zeroed.

```
Your bot  →  Usenami SDK  →  Gateway :8443  →  [vsock]  →  Nitro Enclave
                                                            ├ KMS Decrypt (attestation-gated)
                                                            ├ UPL policy validation (live)
                                                            └ HMAC-SHA256 or EIP-712 sign
                                                                  ↓
Your bot  ←  signed headers / signature  ←  Gateway
```

Three guarantees, cryptographically enforced:

1. **No operator access** — even root on the host VM can't read enclave memory (Nitro hypervisor isolation)
2. **Code integrity** — KMS releases secrets only to a specific, measured binary (PCR0 attestation)
3. **Zero plaintext exposure** — secret decrypted in enclave RAM only, Zeroize-on-drop, no disk/swap/network egress

Adversarial-tested: direct KMS decrypt without attestation → AccessDenied. Wrong-PCR0 enclave (1 byte changed) → KMS denies. Correct-PCR0 → live exchange HTTP 200.

---

## Documentation

For engineers, security reviewers, and recruiters who want to dig deeper:

- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** — visual data flow, trust boundaries, and component-by-component responsibilities. Mermaid diagrams render natively on GitHub.
- **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)** — formal enumeration of attacker classes (host root, supply chain, compromised IAM, network MITM, insider, etc), what each can attempt, and what stops them.
- **[`docs/CASE_STUDY_PCR0_ROTATION.md`](docs/CASE_STUDY_PCR0_ROTATION.md)** — walk-through of a real production migration: rotating the enclave hash across 6 live trading venues with zero plaintext exposure and zero downtime.

---

## Supported exchanges

| Exchange | Scheme | Status |
|---|---|---|
| KuCoin Futures | HMAC-SHA256 v2 headers | Live |
| Binance | HMAC-SHA256 query param | Live |
| Bybit V5 | HMAC-SHA256 headers | Live |
| OKX V5 | HMAC-SHA256 + passphrase | Live |
| **Hyperliquid mainnet** | **EIP-712 typed-data (secp256k1)** | **Live** (first non-HMAC adapter) |
| Asterdex (BNB chain) | EIP-712 typed-data | Live |
| Hyperliquid HIP-3 family (xyz/km/cash/flx) | EIP-712 (same as main, different chainId) | Coming next |
| dYdX v4 | Cosmos signing | Phase 2 |
| Paradex | StarkEx | Phase 2 |

Adding a new exchange with same crypto scheme ≈ ~50 lines per venue.

---

## Repository layout

```
poc/
  enclave/    # Rust binary running inside Nitro Enclave (signing logic)
  gateway/    # Rust binary on host EC2 (port 8443, routes to enclave via vsock)
  parent/     # Helper scripts for vsock-proxy, S3 fetch, systemd integration
  policies/   # KMS key policies (PCR0-locked) + build pins
  scripts/    # build-eif.sh, deploy.sh, check-drift.sh, reproducibility-check.sh
  vendor/     # Vendored Rust crates for offline `cargo build --locked`
  contracts/  # Foundry workspace: UsenamiAttestationRegistry.sol (on-chain trust anchor, live on Base)

sdk/
  typescript/ # @usenami/signer — TypeScript SDK (npm: `npm i @usenami/signer`)
  python/     # Python SDK (source only — not yet published to PyPI)
```

---

## On-chain trust anchor

You don't have to trust `usenami.io` to publish a truthful enclave measurement. The current production PCR0 is registered in an immutable on-chain registry on Base mainnet:

- **Contract**: [`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240) (source verified)
- **Owner address**: `0x21538eBF6598e5866BA496A954dE8E39097bFB59`
- **Active PCR0**: `7c9e8b26a8f6af6e6109faeff1ed4313f332735f6b7aacce7795461de656c84a70f3761d806738121accaf171f329375`

### How to verify (the correct way — read this carefully)

The PCR0 alone is **not** enough. Three checks must all pass; any one of them is bypassable on its own.

**1. PCR0 registered, owned by us, currently active:**

```bash
cast call 0x38b42eED740b0fDeb211bBDf773F2238cAEec240 \
  "isPCR0Active(bytes)(bool,address)" \
  0x7c9e8b26a8f6af6e6109faeff1ed4313f332735f6b7aacce7795461de656c84a70f3761d806738121accaf171f329375 \
  --rpc-url https://mainnet.base.org
# → (true, 0x21538eBF6598e5866BA496A954dE8E39097bFB59)
```

⚠️ **Critical: strict-compare the owner address.** If your code just checks `if (active) accept` and ignores the owner, an attacker can register the same 48 bytes after we deprecate and you will accept their fake attestation. The canonical Usenami owner is:

```
0x21538eBF6598e5866BA496A954dE8E39097bFB59
```

(Published here in the OSS source and on Basescan as the contract deployer. If these two sources disagree, do not trust this registry — open an issue.)

Reference snippet for SDKs:

```rust
let (active, owner) = registry.is_pcr0_active(pcr0).await?;
const USENAMI_OWNER: Address = address!("0x21538eBF6598e5866BA496A954dE8E39097bFB59");
if !active || owner != USENAMI_OWNER {
    return Err(AttestationError::UnauthorizedEnclave);
}
```

**2. Running enclave measurement matches the registered PCR0:**

```bash
# On the host running the enclave you intend to trust:
nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0'
# Must equal the PCR0 you queried in step 1.
```

**3. KMS key policy is bound to that specific PCR0 (not "any enclave"):**

```bash
aws kms get-key-policy --key-id <our-kms-key-id> --policy-name default \
  | jq -r '.Policy | fromjson | .Statement[]
           | select(.Sid == "EnclaveAttestedDecryptOnly")
           | .Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:ImageSha384"]'
# Must equal the PCR0 from steps 1 and 2.
```

All three sources (registry, running enclave, KMS policy) must hold the same PCR0. If any diverge, you've caught either a misconfiguration or an active attack — refuse to use the service until resolved.

### Contract design notes

- **Append-only** — `deprecatePCR0` marks expired but never deletes history.
- **Owner-scoped** — each address controls its own PCR0 chain. The registry answers "which owner registered this PCR0 and is it still active?" — answering "yes" to the second half does NOT imply the answer to "is this Usenami's enclave?"; that's why step 1 above includes the strict owner check.
- **`description` field is self-reported by the registrant.** Any UI/SDK displaying it MUST prefix with `[self-reported by <owner>]` — it is not validated, signed, or attested. Treat as you would treat ENS profile data.
- **No proxy.** If the schema evolves, we deploy v2 and republish the canonical address. Clients choose which contract address to trust based on the published owner.

### Known limitation (will be fixed in v2)

**Squatter risk after deprecation** — when we deprecate a PCR0, the `activePCR0OwnerByHash` mapping clears to zero. The current v1 contract allows anyone to register the same 48 bytes afterward and become the new "owner" of that PCR0 hash. Customers MUST rely on the strict-owner check in step 1 above; v2 will additionally maintain a `retired` mapping that permanently blocks re-registration of previously-seen PCR0s. Tracked in [issue #4](https://github.com/namixai/signer/issues/4).

Source + tests + deploy script live in [`poc/contracts/`](./poc/contracts). 13/13 forge tests pass (10 functional + 1 fuzz @ 256 runs + 1 gas snapshot + production PCR0 sanity). See [`poc/contracts/test/`](./poc/contracts/test) for the squatter regression test which pins v1 behavior and documents the v2 contract.

---

## Quickstart

Connect from any MCP-aware agent (Claude, Gemini, Cursor…):

```bash
claude mcp add signer npx @usenami/signer-mcp@0.3.0 \
  -e SIGNER_GATEWAY_URL=https://signer-demo.usenami.io:8443 \
  -e SIGNER_API_TOKEN=<your-token>
```

Then ask your agent: *"place a 0.001 BTC limit order on Binance testnet."* Your API key never leaves the AWS Nitro enclave.

For direct programmatic use, the TypeScript SDK is on npm — `npm i @usenami/signer` (see [`sdk/typescript`](./sdk/typescript)).

Every signed call returns a **Verifiable Policy Proof** — a Nitro attestation receipt proving the enclave signed your specific request under your declared UPL policy.

---

## Reproducible build

The enclave EIF (Enclave Image File) is **deterministically buildable**:

```bash
cd poc
./scripts/build-eif.sh   # builds inside Docker with locked deps + timestamps
```

Current locked PCR0: see `poc/policies/build-pins.txt`.

KMS key policy refuses to release encrypted secrets unless the requesting enclave's PCR0 measurement matches the value pinned in `poc/policies/kms-policy-day3-attestation.json`. **Change one byte of the source code → new PCR0 → KMS denies → all existing customer secrets become unusable until the new measurement is added to the policy.** This is the security boundary.

### Cross-vector regression tests

For Hyperliquid EIP-712 signing, see `poc/enclave/src/signer.rs::tests::action_hash_matches_hyperliquid_sdk_reference` — asserts byte-for-byte match against the official `hyperliquid-python-sdk`. Catches msgpack encoding bugs (e.g., key ordering), EIP-712 domain/struct mistakes, signature serialization issues.

---

## Security

- **Bug bounty:** $1,000 pool — see `SECURITY.md` (W3-W4 ship)
- **Threat model:** internal red-team scenarios run before each phase; public version coming with audit publication
- **Zero unsafe Rust:** see `cargo-geiger` output in CI (coming)
- **Audit:** scheduled — Sentinel (Usenami in-house auditor) + optional external

---

## Project status (2026-06-24)

**Live in production.** 6 exchanges — 4 CEX (KuCoin, Binance, Bybit, OKX) plus two EIP-712 DEXes (Hyperliquid, Asterdex). PCR0 rotation collapsed to single-allow on 2026-06-24; EIP-712 DEX signing verified byte-for-byte against the official Hyperliquid SDK.

Production PCR0: `7c9e8b26a8f6af6e6109faeff1ed4313f332735f6b7aacce7795461de656c84a70f3761d806738121accaf171f329375`

Shipped:
- **UPL** (Usenami Policy Layer) — JSON policy validated in-enclave on every sign request, including order-size and transfer-recipient enforcement (live)
- **Verifiable Policy Proof** — Nitro attestation receipt per signed request (live)
- **On-chain attestation registry** on Base — removes the trust-Usenami-website assumption (live)
- **MCP server** (`@usenami/signer-mcp`) + **Eliza plugin** — sign from any MCP-aware AI agent (shipped)

---

## Building from source

Requires:
- Linux x86_64 (cross-compile for AL2023 if developing on macOS)
- Docker
- AWS Nitro CLI (`nitro-cli`) for `.eif` builds
- Rust 1.95+ (see `poc/rust-toolchain.toml`)

```bash
cd poc
./scripts/build-eif.sh
```

For development without an actual Nitro Enclave (local-only signing), see `poc/enclave/README.md`.

---

## License

[Apache-2.0](./LICENSE).

If you build something with this and ship it, drop a note at [@usenami_io](https://twitter.com/usenami_io).
