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
| Asterdex (BNB chain) | EIP-712 typed-data (secp256k1) | Live (first non-HMAC adapter) |
| Hyperliquid **testnet** | EIP-712 typed-data (secp256k1) | Live |
| Hyperliquid **mainnet** | EIP-712 typed-data (secp256k1) | **No key provisioned** — see below |
| Hyperliquid HIP-3 family (xyz/km/cash/flx) | EIP-712 (same as main, different chainId) | Coming next |
| dYdX v4 | Cosmos signing | Phase 2 |
| Paradex | StarkEx | Phase 2 |

> **On Hyperliquid mainnet — the guarantee CHANGED on 2026-08-10, read this.**
> Until then the enclave refused `sign_hyperliquid_main_order` and
> `sign_hyperliquid_main_cancel` before touching any key material: denied inside the
> enclave, not merely unconfigured. **That in-enclave deny was removed** in the
> rotation deployed on 2026-08-10, so the code path no longer refuses by construction.
>
> What stops a mainnet signature today is weaker and worth stating plainly: **no
> Hyperliquid mainnet key exists** — none is provisioned, so there is nothing to
> decrypt and nothing to sign with. That is an operational fact, not an enclave-enforced
> property, and it can change the day a key is created. Do not rely on this row as a
> safety guarantee; rely on the policy you attest.
>
> Hyperliquid **testnet** signs through the same EIP-712 code path; the only difference
> is the phantom-agent source byte.
>
> This row read `Live` from 2026-06-26 until 2026-08-05, which was wrong for the whole
> of that period. Corrected rather than quietly edited — and corrected again here, in
> the other direction, rather than leaving a stale claim that flattered us.


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

> ## ⚠️ THE ON-CHAIN ANCHOR IS STALE — READ THIS BEFORE USING IT
>
> Measured against Base on 2026-08-11, after the rotation:
>
> | PCR0 | `isPCR0Active` |
> |---|---|
> | `7c9e8b26…` (registered, no longer running) | **true** |
> | `32d25d8c…` (**currently running**) | **false** |
> | `ff53e1fe…` (retired 2026-08-10) | **false** |
>
> The registry marks an old measurement active and does not know the one actually
> serving. The dangerous failure mode is not the obvious one: a careful verifier
> compares the LIVE attestation against the chain, gets `false`, and correctly refuses.
> A careless one compares this README's number against the chain, sees them agree, and
> concludes it verified something — **two stale sources agreeing looks exactly like
> verification.**
>
> Until a fresh registration lands, treat the on-chain check as **not satisfiable** and
> rely on `/attestation` verified against the AWS Nitro root. Published rather than
> quietly re-pointed, because the point of this section is that you should not have to
> take our word for it.

An immutable registry on Base exists for exactly this purpose, subject to the staleness
above:

- **Contract**: [`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240) (source verified)
- **Owner address**: `0x21538eBF6598e5866BA496A954dE8E39097bFB59`
- **Registered PCR0 (STALE — not the running enclave)**: `7c9e8b26a8f6af6e6109faeff1ed4313f332735f6b7aacce7795461de656c84a70f3761d806738121accaf171f329375`

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

The enclave EIF (Enclave Image File) is **deterministically buildable** — a clean
clone of this repository rebuilds the measurement the production endpoint attests to.

```bash
cd poc
SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh
# → PCR0 32d25d8c2f0bde55610e6a25b9ae51678a50b3a3929c70cdb5a497ec0a5f8c1f34520c5fb67b20912677ecc47d377103
```

> ### The flag is part of the measurement, not a runtime switch
>
> `SIGNER_REQUIRE_POLICY` is **baked into the image**, so it changes PCR0. Omitting
> it is not "the same build without a setting" — it is a different enclave:
>
> | build | PCR0 |
> |---|---|
> | `SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh` | `32d25d8c…` — **this is production** |
> | `SIGNER_ROTATION_GATE=0 ./scripts/build-eif.sh` (permissive) | `9f80b8d4…` — not deployed anywhere |
>
> Both values are measured on this tree, not asserted. Note the permissive build
> now needs an explicit `SIGNER_ROTATION_GATE=0`: on a rotation tree the plain
> flagless command **refuses to build** rather than silently emit a permissive
> image (see the note below). If your build lands on `9f80b8d4…` you have
> reproduced the permissive image correctly and simply used the non-production
> command; if it lands on neither, that is the interesting case and we would like
> to hear about it.
>
> The permissive PCR0 is a property of the source tree — an earlier tree measured
> `18b6ece4…` here; on the current tree it is `9f80b8d4…`. The strict value is what
> the production endpoint attests, and it is the one to trust.
>
> ### The permissive build is gated on a rotation tree
>
> Running `./scripts/build-eif.sh` without the flag on this tree stops with:
> `rotation gate — this image is PERMISSIVE (SIGNER_REQUIRE_POLICY=0). A mainnet
> rotation image must bake exactly 1.` That is deliberate: the build itself refuses
> to hand you a permissive image where a rotation expects the strict one. To
> measure the permissive PCR0 anyway, ask for it explicitly with
> `SIGNER_ROTATION_GATE=0`.
>
> This README previously showed the flagless command next to a production PCR0, so
> anyone following it byte-for-byte got a mismatch and had every reason to conclude
> the claim was false. Corrected rather than quietly amended.

**The authority is `/attestation`, not this file.** It returns an NSM-signed COSE
document carrying the measurement the running enclave actually reports, verifiable
against the AWS Nitro root. A value printed in a README goes stale silently; compare
your build against the live document, and use the number here only to know what to
expect.

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

## Project status (2026-08-11)

**Live in production.** 5 venues signing on mainnet — 4 CEX (KuCoin, Binance, Bybit, OKX) plus the Asterdex EIP-712 DEX. Hyperliquid **mainnet has no key provisioned** — the in-enclave deny was removed on 2026-08-10 (below); Hyperliquid **testnet** signs. EIP-712 signing is verified byte-for-byte against the official Hyperliquid SDK.

Production PCR0: `32d25d8c2f0bde55610e6a25b9ae51678a50b3a3929c70cdb5a497ec0a5f8c1f34520c5fb67b20912677ecc47d377103`

Check it yourself rather than taking this file's word for it — `/attestation` returns an
NSM-signed COSE document carrying the running measurement, and it is the authority here.
A value printed in a README goes stale silently; the one this repository published did.

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
SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh   # strict = the production measurement
```

The flag is baked into the image and therefore part of PCR0 — see
[Reproducible build](#reproducible-build) for both measured values and why the
flagless form is a different enclave rather than the same one unconfigured.

For development without an actual Nitro Enclave (local-only signing), see `poc/enclave/README.md`.

---

## License

[Apache-2.0](./LICENSE).

If you build something with this and ship it, drop a note at [@usenami_io](https://twitter.com/usenami_io).
