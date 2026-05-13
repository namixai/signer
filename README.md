# Usenami Signer

**Hardware-isolated signing-as-a-service for crypto exchanges.**

Your exchange API secrets never leave a measured AWS Nitro Enclave. Even root on the host VM can't read them. AWS KMS releases secrets only to a specific, attested binary — change one byte, KMS denies.

🔗 **Live demo:** [signer-demo.usenami.io:8443/healthz](http://signer-demo.usenami.io:8443/healthz) (allowlisted pilots only) &middot; full walkthrough in [`DEMO.md`](DEMO.md)
📜 **License:** Apache-2.0

---

## What it does

You upload an encrypted secret once. Your bot calls our SDK to sign requests. The plaintext key exists only inside the enclave's RAM for `<10ms` per request, then is zeroed.

```
Your bot  →  Usenami SDK  →  Gateway :8443  →  [vsock]  →  Nitro Enclave
                                                            ├ KMS Decrypt (attestation-gated)
                                                            ├ UPL policy validation (Phase 1.5)
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

## Supported exchanges

| Exchange | Scheme | Status |
|---|---|---|
| KuCoin Futures | HMAC-SHA256 v2 headers | Live |
| Binance | HMAC-SHA256 query param | Live |
| Bybit V5 | HMAC-SHA256 headers | Live |
| OKX V5 | HMAC-SHA256 + passphrase | Live |
| **Hyperliquid mainnet** | **EIP-712 typed-data (secp256k1)** | **Live** (first non-HMAC adapter) |
| Asterdex (BNB chain) | EIP-712 typed-data | Coming next (W3) |
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
  contracts/  # Foundry workspace: UsenamiAttestationRegistry.sol (Phase 1.5 on-chain trust anchor)

sdk/
  python/     # usenami-signer Python SDK — `pip install usenami-signer`
              # Per-exchange namespaces: signer.kucoin, signer.binance,
              # signer.bybit, signer.okx, signer.hyperliquid_main
```

---

## On-chain trust anchor (Phase 1.5)

You don't have to trust `usenami.io` to publish a truthful enclave measurement. The current production PCR0 is registered in an immutable on-chain registry on Base mainnet:

- **Contract**: [`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240) (source verified)
- **Owner address**: `0x21538eBF6598e5866BA496A954dE8E39097bFB59`
- **Active PCR0**: `9f6f512f81c3b533333fb53098e9df45aaa0fb31d4536a4b39ab690e056839814ab6a2595859885cc6327c544cf059ab`

### How to verify (the correct way — read this carefully)

The PCR0 alone is **not** enough. Three checks must all pass; any one of them is bypassable on its own.

**1. PCR0 registered, owned by us, currently active:**

```bash
cast call 0x38b42eED740b0fDeb211bBDf773F2238cAEec240 \
  "isPCR0Active(bytes)(bool,address)" \
  0x9f6f512f81c3b533333fb53098e9df45aaa0fb31d4536a4b39ab690e056839814ab6a2595859885cc6327c544cf059ab \
  --rpc-url https://mainnet.base.org
# → (true, 0x21538eBF6598e5866BA496A954dE8E39097bFB59)
```

⚠️ **Critical: strict-compare the owner address.** If your code just checks `if (active) accept` and ignores the owner, an attacker can register the same 48 bytes after we deprecate and you will accept their fake attestation. The canonical Usenami owner is:

```
0x21538eBF6598e5866BA496A954dE8E39097bFB59
```

(Published here in the OSS source, on Basescan as the contract deployer, and in our [`STATUS.md`](https://github.com/namixai/usenami-platform/blob/main/_signer/STATUS.md). If any of these three sources disagree, do not trust this registry — open an issue.)

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

All four sources (registry, running enclave, KMS policy, [`STATUS.md`](https://github.com/namixai/usenami-platform/blob/main/_signer/STATUS.md)) must hold the same PCR0. If any diverge, you've caught either a misconfiguration or an active attack — refuse to use the service until resolved.

### Contract design notes

- **Append-only** — `deprecatePCR0` marks expired but never deletes history.
- **Owner-scoped** — each address controls its own PCR0 chain. The registry answers "which owner registered this PCR0 and is it still active?" — answering "yes" to the second half does NOT imply the answer to "is this Usenami's enclave?"; that's why step 1 above includes the strict owner check.
- **`description` field is self-reported by the registrant.** Any UI/SDK displaying it MUST prefix with `[self-reported by <owner>]` — it is not validated, signed, or attested. Treat as you would treat ENS profile data.
- **No proxy.** If the schema evolves, we deploy v2 and republish the canonical address. Clients choose which contract address to trust based on the published owner.

### Known limitation (will be fixed in v2)

**Squatter risk after deprecation** — when we deprecate a PCR0, the `activePCR0OwnerByHash` mapping clears to zero. The current v1 contract allows anyone to register the same 48 bytes afterward and become the new "owner" of that PCR0 hash. Customers MUST rely on the strict-owner check in step 1 above; v2 will additionally maintain a `retired` mapping that permanently blocks re-registration of previously-seen PCR0s. Tracked in [issue #4](https://github.com/namixai/signer/issues/4).

Source + tests + deploy script live in [`poc/contracts/`](./poc/contracts). 13/13 forge tests pass (10 functional + 1 fuzz @ 256 runs + 1 gas snapshot + production PCR0 sanity). See [`poc/contracts/test/`](./poc/contracts/test) for the squatter regression test which pins v1 behavior and documents the v2 contract.

---

## Quickstart (developer)

```python
from usenami_signer import Signer

signer = Signer(base_url="http://signer-demo.usenami.io:8443")

# CEX HMAC signing
accounts = signer.kucoin.get_accounts()
balance  = signer.okx.get_account_config()

# DEX EIP-712 signing (Hyperliquid)
order = signer.hyperliquid_main.order(
    asset=0,                  # BTC = 0 on mainnet
    is_buy=True,
    price="50000",
    size="0.001",
    reduce_only=False,
    order_type={"limit": {"tif": "Gtc"}},
)
```

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

## Project status (2026-05-12)

**Phase 1 Stage 2 LIVE in production.** 5 exchanges, first EIP-712 DEX adapter shipped + verified byte-for-byte against official Hyperliquid SDK.

Production PCR0: `9f6f512f81c3b533333fb53098e9df45aaa0fb31d4536a4b39ab690e056839814ab6a2595859885cc6327c544cf059ab`

Phase 1.5 (W3-W5, late May / early June):
- **UPL** (Usenami Policy Language) — JSON policy validated in-enclave on every sign request
- **Verifiable Policy Proof** — Nitro attestation receipt per signed request
- **On-chain attestation registry** on Base — eliminates trust-Usenami-website assumption
- **Eliza plugin** — first AI-agent platform integration

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
