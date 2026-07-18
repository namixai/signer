# Usenami Signer

Keyless signing for crypto exchange (CEX) and DEX order/transfer requests inside an **AWS Nitro Enclave**. The exchange API secret (or DEX private key) never leaves the attested enclave — not to the parent EC2 instance, the operator, the OS, or any other process. A client sends an order; the enclave returns only the signed request (auth headers / signature), never the key.

**Status:** production build, **multi-tenant** (testnet venue keys). The current production enclave measures to PCR0 `ff53e1fe…`, **reproducible from this source** (see [`docs/VERIFY-SIGNER-YOURSELF.md`](../docs/VERIFY-SIGNER-YOURSELF.md)). The attestation registry contract is live on Base mainnet; on-chain registration of the current PCR0 is the next step, and the public demo attests `registered_onchain: false`.

## What it does
- **CEX request signing** — HMAC-SHA256 auth headers (KuCoin/Binance/OKX/Bybit style) and per-venue structured order/cancel signing for Binance + OKX.
- **DEX / x402 signing** — EIP-712 / ECDSA, and `/sign-x402` for EIP-3009 `TransferWithAuthorization` (agent micropayments).
- **Multi-tenant** — many customers' keys on one signer, cryptographically isolated per customer (see Registry control-plane).
- **Verifiable trust** — the key blob only decrypts inside the enclave whose attested measurement (PCR0) the KMS key policy allows, and that PCR0 is reproducible from this source so anyone can verify it (on-chain publication of the PCR0 is the next step).

> **Policy-enforcement scope (be precise — hardening in progress):** per-asset **size caps** (`order_caps`) are enforced inside the enclave on the **structured Binance/OKX `order`/`cancel` path only**. The generic `/sign`, the `/sign-x402` recipient, and the EIP-712 venues (Hyperliquid, Asterdex) are **action/venue-gated but NOT yet size-capped**. Do not claim or rely on a size cap outside the structured Binance/OKX path until CR050–053 land.

## Architecture
```
client ──HTTP(bearer)──▶ Parent EC2 ──vsock──▶ Nitro Enclave
                         (gateway)            (signer)
```
- **Parent EC2 (`gateway/`)** — HTTP API + bearer-token auth + vsock proxy. Holds NO secrets; forwards sign requests over vsock and relays AWS creds for the enclave's KMS/exchange calls. Routes are split into three tiers:
  - `sign_router` (gated by `SIGNER_API_TOKENS`, tenant tokens) — all `/sign*`, `/hedge`, `/account/:venue`.
  - `operator_router` (gated by `SIGNER_OPERATOR_TOKENS`, operator tokens) — `/verify-blob` only. A tenant token cannot reach operator routes and vice-versa (route_layer applied before merge — hard separation).
  - **public (no bearer)** — `/attestation` (trust-anchor proof) + `/healthz`. Kept OFF the shared `/sign` concurrency pool so an unauthenticated flood can't starve signing; `/attestation` is edge-cached (`Cache-Control: public, max-age=60`).
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
2. The attestation registry contract is live on Base mainnet (`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`) to hold the authorized PCR0 on-chain as a public, verifiable record; registering the current PCR0 (`registerPCR0`) is the next step.
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
| `GET /attestation` | — (public) | PCR0 + on-chain registration proof; edge-cached, exempt from the `/sign` pool |
| `GET /healthz` | — (public) | liveness |

## PCR0 lifecycle (enclave rotation / cutover)
EIF build → capture PCR0 → **KMS dual-allow** `[old, new]` on the venue + registry keys → `registerPCR0(new)` on the Base registry contract → re-verify (`verify-all-blobs`, tenant signs) → 24h soak → **collapse** to single-allow (drops the old PCR0). Pass `REGISTRY_KMS_KEY_ID` as the KMS **key-id**, never an alias. See the operator cutover/rotation runbook.

## Build & test
```bash
cd poc
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --all
```
The reproducible enclave image (EIF → PCR0) is built on an EC2 build host (Docker + `nitro-cli`) in a pinned musl container; local native builds only confirm the source compiles + tests pass. Build the enclave image with **`SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh`** — the strict/money-path build the public demo runs; its PCR0 reproduces `ff53e1fe23498737e647a3baf0706133c4b157af024a519bf9d983a1f538d356e01f05792e15837728a7829c2908f6c6`. See [`docs/VERIFY-SIGNER-YOURSELF.md`](../docs/VERIFY-SIGNER-YOURSELF.md) to verify the live enclave against it.

## MCP / clients
- **`@usenami/signer-mcp`** (npm) — drive the signer from Claude Code or any MCP-compatible client (5 tools: list_venues, get_account, place_order, cancel_order, get_attestation).
- **Model-agnostic** — any agent (Gemini/Grok/custom) or script can call the gateway HTTP API directly with a bearer token.

## Reference docs
- [`docs/VERIFY-SIGNER-YOURSELF.md`](../docs/VERIFY-SIGNER-YOURSELF.md) — verify the live enclave PCR0 against a reproducible rebuild, trusting no Usenami code.
- `enclave/src/handler.rs`, `enclave/src/registry.rs`, `gateway/src/main.rs` — the authoritative source.
