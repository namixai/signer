# Usenami Signer

**Hardware-isolated signing-as-a-service for crypto exchanges.**

Your exchange API secrets never leave a measured AWS Nitro Enclave.
Even root on the host VM can't read them. AWS KMS releases secrets only to a specific, attested binary — change one byte, KMS denies.

🔗 **Live demo:** [signer-demo.usenami.io:8443/healthz](http://signer-demo.usenami.io:8443/healthz)
📜 **License:** Apache-2.0

---

## What it does

You upload an encrypted secret once. Your bot calls our SDK to sign requests. The plaintext key exists only inside the enclave's RAM for `<10ms` per request, then is zeroed.

```
Your bot  →  Usenami SDK  →  Gateway :8443  →  [vsock]  →  Nitro Enclave
                                                            ├ KMS Decrypt (attestation-gated)
                                                            └ HMAC-SHA256 sign
                                                                  ↓
Your bot  ←  signed headers  ←  Gateway
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
| Hyperliquid (HIP-3 family) | EIP-712 typed data | Coming next |
| Asterdex | EIP-712 typed data | Coming next |
| dYdX v4 | Cosmos signing | Phase 2 |
| Paradex | StarkEx | Phase 2 |

Adding a new exchange ≈ ~50 lines of Rust if it shares an existing crypto scheme.

---

## Repository layout

```
poc/
  enclave/    # Rust binary running inside Nitro Enclave (signer logic)
  gateway/    # Rust binary running on host EC2 (port 8443, routes to enclave via vsock)
  parent/     # Helper scripts for vsock-proxy, S3 fetch, systemd integration
  policies/   # KMS key policies (PCR0-locked) + build pins
  scripts/    # build-eif.sh, deterministic-build.sh
  vendor/     # Vendored Rust crates for offline `cargo build --locked`

sdk/
  python/     # usenami-signer Python package — `pip install usenami-signer`
              # exposes signer.kucoin, signer.binance, signer.bybit, signer.okx
              # ETA: signer.hyperliquid_main, signer.asterdex (next release)
```

---

## Quickstart (developer)

```python
from usenami_signer import Signer

signer = Signer(base_url="https://signer-demo.usenami.io:8443")

# Sign and execute in one call
accounts = signer.kucoin.get_accounts()
balances = signer.binance.get_balances()
config = signer.okx.get_account_config()

# Or get signed headers for a custom request
headers = signer.bybit.sign(method="GET", path="/v5/account/wallet-balance", params={"accountType": "UNIFIED"})
```

To onboard your own exchange API key:
1. Encrypt your secret blob locally with `usenami-signer encrypt --exchange okx --kms-key <ARN>`
2. Upload the encrypted blob to the configured S3 bucket
3. Restart the gateway; it loads the new blob on startup
4. Use the SDK as above — your plaintext key never touches our control plane

Full onboarding doc: see `docs/ONBOARDING.md` (coming with Phase 1 W3 ship).

---

## Reproducible build

The enclave EIF (Enclave Image File) is **deterministically buildable**.

```bash
cd poc
./scripts/build-eif.sh    # builds twice, compares PCR0 hashes — fails if they differ
```

Current locked PCR0: see `poc/policies/build-pins.txt`.

KMS key policy refuses to release encrypted secrets unless the requesting enclave's PCR0 measurement matches the value pinned in `poc/policies/kms-policy-day3-attestation.json`. **Change one byte of the source code → new PCR0 → KMS denies → all existing customer secrets become unusable until the new measurement is added to the policy.** This is the security boundary.

---

## Security

- **Bug bounty:** $1,000 pool — see `SECURITY.md` (coming Phase 1 W3)
- **Threat model:** internal red-team scenarios run before each phase; public version coming with audit publication
- **Zero unsafe Rust:** see `cargo-geiger` output in CI (coming)
- **Audit:** scheduled (Sentinel — Usenami in-house auditor + optional external review by Cantina)

---

## Project status

This is **Phase 1** (multi-exchange + SDK). Phase 0 PoC ($2.36, 4 days) proved the architecture; Phase 1 ships production-grade SDK + 6+ exchange adapters + first 3 pilot customers. Public roadmap will be updated as items ship.

---

## Building from source

Requires:
- Linux x86_64 (cross-compile for AL2023 if developing on macOS)
- Docker
- AWS Nitro CLI (`nitro-cli`) for `.eif` builds
- Rust 1.84+ (see `poc/rust-toolchain.toml`)

```bash
cd poc
./scripts/build-eif.sh
```

For development without an actual Nitro Enclave (local-only signing), see `poc/enclave/README.md`.

---

## License

[Apache-2.0](./LICENSE).

If you build something with this and ship it, drop a note at [@usenami_io](https://twitter.com/usenami_io).
