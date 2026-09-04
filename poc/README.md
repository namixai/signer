# Usenami Signer

Keyless signing for crypto exchange (CEX) and DEX order/transfer requests inside an **AWS Nitro Enclave**. The exchange API secret (or DEX private key) never leaves the attested enclave — not to the parent EC2 instance, the operator, the OS, or any other process. A client sends an order; the enclave returns only the signed request (auth headers / signature), never the key.

**Status:** production build, **multi-tenant**; mainnet venue keys exist for the operator's own funds only (no third-party money in production, no external audit). The current production enclave measures to PCR0 `103ccd79…` (since rotation #4 on 2026-08-24) — **reproducible from this repository at commit `96cd4e46`** (check that commit out first; HEAD carries later dependency bumps and builds to a different, undeployed PCR0 — see [Reproducible build](../README.md#reproducible-build) and [`docs/VERIFY-SIGNER-YOURSELF.md`](../docs/VERIFY-SIGNER-YOURSELF.md)). The attestation registry contract is live on Base mainnet and the current production PCR0 is registered there (since 2026-08-24, owner `0x21538eBF…`). The public **demo** box rotates on its own schedule: it attested `32d25d8c…` from 2026-08-24, which that rotation auto-deprecated, and was moved onto the production measurement on 2026-08-27. Read what the demo attests from its own `/attestation` rather than from this line, because the two boxes can be on different measurements in any rotation window. `/attestation` no longer carries a `registered_onchain` field: it was a boolean this gateway computed about a fact with a public oracle, so believing it bought you nothing over believing us. Ask the chain instead — `isPCR0Active` on the registry — and compare the **owner**, because `registerPCR0` is permissionless. Note that the registry keeps ONE active measurement per owner: registering the production measurement deprecates the demo's in the same transaction, so the two boxes cannot both answer `true` while they run different images.

## What it does
- **CEX request signing** — HMAC-SHA256 auth headers (KuCoin/Binance/OKX/Bybit style) and per-venue structured order/cancel signing for Binance + OKX.
- **DEX / x402 signing** — EIP-712 / ECDSA, and `/sign-x402` for EIP-3009 `TransferWithAuthorization` (agent micropayments).
- **Multi-tenant** — many customers' keys on one signer, cryptographically isolated per customer (see Registry control-plane).
- **Verifiable trust** — the key blob only decrypts inside the enclave whose attested measurement (PCR0) the KMS key policy allows, and that PCR0 is reproducible from this source at the pinned commit so anyone can verify it; it is also published on-chain (Base registry, see Trust model).

> **Policy-enforcement scope (be precise — hardening in progress):** per-asset **size caps** (`order_caps`) are enforced inside the enclave on the **structured Binance/OKX `order`/`cancel` path only**. The generic `/sign`, the `/sign-x402` recipient, and the EIP-712 venues (Hyperliquid, Asterdex) are **action/venue-gated but NOT yet size-capped**. Do not claim or rely on a size cap outside the structured Binance/OKX path until CR050–053 land.

## Architecture
```
client ──HTTP(bearer)──▶ Parent EC2 ──vsock──▶ Nitro Enclave
                         (gateway)            (signer)
```
- **Parent EC2 (`gateway/`)** — HTTP API + bearer-token auth + vsock proxy. Holds NO secrets; forwards sign requests over vsock and relays AWS creds for the enclave's KMS/exchange calls. Routes are split into three tiers:
  - `sign_router` (gated by `SIGNER_API_TOKENS`, tenant tokens) — all `/sign*`, `/hedge`, `/account/:venue`.
  - `operator_router` (gated by `SIGNER_OPERATOR_TOKENS`, operator tokens) — `/verify-blob` only. A tenant token cannot reach operator routes and vice-versa (route_layer applied before merge — hard separation).
  - **public (no bearer)** — `/attestation` (trust-anchor proof) + `/healthz`. Kept OFF the shared `/sign` concurrency pool so an unauthenticated flood can't starve signing; `/attestation` is served with `Cache-Control: no-store` — every call does a vsock round-trip to the enclave for a fresh NSM document, so a client-supplied `?nonce=` is bound into it (the nonce must be hex with an even number of digits, at most 2048 characters; anything else is `bad_request`).
- **Nitro Enclave (`enclave/`)** — the signer: resolves the caller's identity via the in-memory registry, KMS-decrypts that customer's venue key blob under attestation, signs, returns only the signature. The key plaintext lives only transiently in enclave RAM.
- **`parent/`** — `signer-client` CLI (vsock test driver, registry-challenge/refresh).
- **`policy-cli/`** — off-box tool to author + Ed25519-sign registry refresh envelopes and venue policies.

## Multi-tenant registry (control-plane)
The enclave keeps an **in-memory (RAM-only) registry** mapping each bearer token → `{customer_id, allowed_venues}`. It is installed via a **signed, KMS-encrypted refresh**:
- `policy-cli registry sign` builds a 72-byte envelope `nonce(32) ‖ version_le(8) ‖ sha256(entries_json)(32)`, Ed25519-signed by a control-plane key whose **public key is baked into the EIF** (so the enclave only accepts registries signed by that key — fail-closed: bad sig → empty registry → no access).
- `aws kms encrypt` under context `customer_id=registry-system,venue_id=registry` → `signer-client registry-challenge` (one-shot nonce) → `registry-refresh`.
- Per-customer key blobs are KMS-encrypted under context `{customer_id, venue}`, so customer A's identity can never decrypt customer B's blob (KMS-enforced isolation), and the per-venue ACL gates which venues each customer may sign for.
- **RAM-only**: an enclave restart wipes the registry → re-refresh required. (A `--collapse-to` KMS-policy change does NOT restart the enclave, so it does not wipe the registry.)
- **blob ↔ owner mapping:** the registry maps `token → {customer_id, allowed_venues}` and the vault records `token + customer_id` — but **NEITHER records which real exchange account** a customer's blob holds (the venue API key inside the blob is opaque to the control plane; only the operator who wrapped it knows the real account). Keep the `token → tenant → real-exchange-account` map in the operator's private vault, never in the registry or this repo.

## Trust model
1. Key blobs are KMS-encrypted; the KMS key policy allows `Decrypt` **only** under a `kms:RecipientAttestation:ImageSha384` condition matching the enclave's PCR0 → only the exact attested code can decrypt.
2. The attestation registry contract is live on Base mainnet (`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`) and holds the current production PCR0 `103ccd79…` as a public record (registered 2026-08-24; the demo box's measurement was deprecated by that same rotation). Read it with `isPCR0Active(bytes)` and compare the returned owner to `0x21538eBF6598e5866BA496A954dE8E39097bFB59`: registration is permissionless, so `active=true` alone proves nothing.
3. The operator and host are untrusted for key material; they manage the vsock channel and relay creds but cannot extract the key (Nitro isolation + attestation-gated KMS).

## Venues (6)
`binance`, `okx`, `bybit`, `kucoin`, `asterdex`, `hyperliquid_main`. Binance + OKX have dedicated structured order/cancel endpoints; all six are reachable via the generic signing path and per-customer `allowed_venues`.

## HTTP endpoints (gateway)
| Route | Auth | Purpose |
|---|---|---|
| `POST /sign` | tenant | generic CEX auth-header signing |
| `POST /sign/{binance,okx}-order` / `-cancel` | tenant | per-venue structured trade signing |
| `POST /sign-x402` | tenant | EIP-3009 TransferWithAuthorization (x402) |
| `POST /hedge` | tenant | place_hedge |
| `GET /account/:venue` | tenant | signed read (balances) |
| `POST /verify-blob` | operator | anti-oracle pre-flight: confirm a blob decrypts under the current PCR0 (returns attestation, never the key) |
| `GET /attestation` | — (public) | PCR0 + on-chain registration proof; `Cache-Control: no-store` (never edge-cached, so a nonce round-trip is honest), exempt from the `/sign` pool |
| `GET /healthz` | — (public) | liveness |

## PCR0 lifecycle (enclave rotation / cutover)
EIF build → capture PCR0 → **KMS dual-allow** `[old, new]` on the venue + registry keys → `registerPCR0(new)` on the Base registry contract → re-verify (`verify-all-blobs`, tenant signs) → 24h soak → **collapse** to single-allow (drops the old PCR0). Pass `REGISTRY_KMS_KEY_ID` as the KMS **key-id**, never an alias. See the operator cutover/rotation runbook.

## Build & test
```bash
cd poc
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --all
```
The reproducible enclave image (EIF → PCR0) is built on an EC2 build host (Docker + `nitro-cli`) in a pinned musl container; local native builds only confirm the source compiles + tests pass. Build the enclave image with **`SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh`** — the strict/money-path build the **mainnet/production** enclave runs; **on commit `96cd4e46`** its PCR0 reproduces `103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3` (measured 2026-08-23, nitro-cli 1.4.4). HEAD of `main` carries dependency bumps merged after that measurement and builds to a different, undeployed PCR0 — see the repository README's "Reproducible build" table and `scripts/enclave-closure-check.py`. The **public demo** endpoint is a separate box on its own rotation schedule; it measured `32d25d8c…` between 2026-08-24 and 2026-08-27. One published number stopped covering both lanes on 2026-08-24 and can stop again. See [`docs/VERIFY-SIGNER-YOURSELF.md`](../docs/VERIFY-SIGNER-YOURSELF.md) to verify the live enclave against it.

## MCP / clients
- **`@usenami/signer-mcp`** (npm) — drive the signer from Claude Code or any MCP-compatible client (5 tools: list_venues, get_account, place_order, cancel_order, get_attestation).
- **Model-agnostic** — any agent (Gemini/Grok/custom) or script can call the gateway HTTP API directly with a bearer token.

## Reference docs
- [`docs/VERIFY-SIGNER-YOURSELF.md`](../docs/VERIFY-SIGNER-YOURSELF.md) — verify the live enclave PCR0 against a reproducible rebuild, trusting no Usenami code.
- `enclave/src/handler.rs`, `enclave/src/registry.rs`, `gateway/src/main.rs` — the authoritative source.
