# Usenami Signer

**Hardware-isolated signing-as-a-service for crypto exchanges.**

Your exchange API secrets never leave a measured AWS Nitro Enclave. Even root on the host VM can't read them. AWS KMS releases secrets only to a specific, attested binary — change one byte, KMS denies.

🔗 **Live demo:** [signer-demo.usenami.io:8443/healthz](http://signer-demo.usenami.io:8443/healthz)
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

sdk/
  python/     # usenami-signer Python SDK — `pip install usenami-signer`
              # Per-exchange namespaces: signer.kucoin, signer.binance,
              # signer.bybit, signer.okx, signer.hyperliquid_main
```

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
