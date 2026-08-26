# Usenami Signer

**Hardware-isolated signing-as-a-service for crypto exchanges.**

Your exchange API secrets never leave a measured AWS Nitro Enclave. Even root on the host VM can't read them. AWS KMS releases secrets only to a specific, attested binary — change one byte, KMS denies.

🔗 **Live demo:** [signer-demo.usenami.io:8443/healthz](http://signer-demo.usenami.io:8443/healthz) (open — it answers 200 to anyone; earlier revisions of this line said "allowlisted pilots only", which was never true of `/healthz`) &middot; full walkthrough in [`DEMO.md`](DEMO.md)
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
| KuCoin Futures | HMAC-SHA256 v2 headers | Adapter; no mainnet key, generic path fail-closed under caps |
| Binance USD-M futures | HMAC-SHA256 query param | **Mainnet, own funds** — completed round trip 2026-07-27 |
| Bybit V5 | HMAC-SHA256 headers | Adapter; no mainnet key, generic path fail-closed under caps |
| OKX V5 | HMAC-SHA256 + passphrase | **Mainnet, own funds** — signed, accepted into the book, cancelled (2026-08-18); never filled |
| Asterdex (BNB chain) | EIP-712 typed-data (secp256k1) | Adapter (first non-HMAC); not armed on mainnet |
| Hyperliquid **testnet** | EIP-712 typed-data (secp256k1) | Live |
| Hyperliquid **mainnet** | EIP-712 typed-data (secp256k1) | **Mainnet, own funds** — agent key born inside the enclave 2026-08-16, completed round trip 2026-08-19 |
| Hyperliquid HIP-3 family (xyz/km/cash/flx) | EIP-712 (same as main, different chainId) | Coming next |
| dYdX v4 | Cosmos signing | Phase 2 |
| Paradex | StarkEx | Phase 2 |

> **On Hyperliquid mainnet — what holds the line, stated plainly.**
> Until 2026-08-10 the enclave refused `sign_hyperliquid_main_order` /
> `sign_hyperliquid_main_cancel` before touching any key material. That in-enclave deny
> was removed in the 2026-08-10 rotation. On 2026-08-16 a mainnet agent key was minted
> **inside the enclave** (ROT-1 in-enclave mint, `poc/enclave/src/handler.rs` "MINT an agent key in-enclave"; the operator-side ceremony script is not yet synced to this repo; the key never existed outside;
> the account owner approved the agent address from their own wallet), and on 2026-08-19
> that key signed a completed round trip (entry filled, position closed — verifiable
> against Hyperliquid's public `userFills`).
>
> So today nothing is "unprovisioned". What limits a mainnet signature is the **attested
> policy** (`hl_order_caps`: per-asset size and notional caps, checked before signing) plus
> Hyperliquid's own rule that agent wallets cannot withdraw — the latter is the venue's
> property, not ours. Rely on the policy you attest, not on this row.
>
> Hyperliquid **testnet** signs through the same EIP-712 code path; the only difference
> is the phantom-agent source byte.
>
> History of this row, kept on purpose: it read `Live` from 2026-06-26 to 2026-08-05 while
> the enclave still refused mainnet (wrong); then `No key provisioned` from 2026-08-11 to
> 2026-08-22 while a key already existed since 2026-08-16 (stale). Corrected in the open both
> times rather than quietly edited.

Adding a new exchange with same crypto scheme ≈ ~50 lines per venue.

---

## Repository layout

```
poc/
  enclave/    # Rust binary running inside Nitro Enclave (signing logic)
  gateway/    # Rust binary on host EC2 (port 8443, routes to enclave via vsock)
  parent/     # Helper scripts for vsock-proxy, S3 fetch, systemd integration
  policies/   # KMS key policies (PCR0-locked) + build pins
  scripts/    # build-eif.sh, reproducibility-check.sh, enclave-closure-check.py,
              # run-enclave-prod.sh, upl-smoke.sh (deploy.sh and check-drift.sh
              # were listed here but do not exist in this repo)
  vendor/     # Vendored Rust crates for offline `cargo build --locked`
  contracts/  # Foundry workspace: UsenamiAttestationRegistry.sol (on-chain trust anchor, live on Base)

sdk/
  typescript/ # @usenami/signer — TypeScript SDK (npm: `npm i @usenami/signer`)
  python/     # Python SDK (source only — not yet published to PyPI)
```

---

## On-chain trust anchor

> ## What the registry says today, and why the demo box answers `false`
>
> Every row re-measured against Base on **2026-08-26**, with the `cast` call below:
>
> | PCR0 | what it is | `isPCR0Active` → `(active, owner)` |
> |---|---|---|
> | `103ccd79…` | **production**, since rotation #4 on 2026-08-24 | **`(true, 0x21538eBF…)`** |
> | `32d25d8c…` | what the **demo box still runs**; was production 2026-08-10 → 08-24 | `(false, 0x0000…0000)` |
> | `7c9e8b26…` | registered 2026-06-23, auto-deprecated | `(false, 0x0000…0000)` |
> | `ff53e1fe…` | retired 2026-08-10 | `(false, 0x0000…0000)` |
>
> 🔴 **Read row two before you test us with the demo endpoint.** The demo box has not
> been rotated onto the production image yet, so asking the registry about the
> measurement the demo attests returns `false`. That is our rotation lag, printed here
> rather than left for you to trip over. Production passes the same check today.
>
> **Why this notice stays.** Between the 2026-08-10 rotation and the re-registration,
> this section told you the opposite — that `7c9e8b26…` was the active value — and it
> published `7c9e8b26…` as the number to paste. Copy-pasting it today returns `false`.
> The failure mode was the quiet one: a careless verifier compares *this page's* number
> against the chain, sees two stale sources agree, and concludes it verified something.
> **Two sources agreeing looks exactly like verification.** The fix is not to trust this
> table either — it is to take the measurement from the live `/attestation` document and
> put *that* into the call.
>
> The correction is published rather than quietly swapped, because the point of this
> section is that you should not have to take our word for it.

A public registry on Base records which measurement an address claims. Read what it
actually guarantees before leaning on it:

- **Contract**: [`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240) (source verified)
- **Canonical owner address**: `0x21538eBF6598e5866BA496A954dE8E39097bFB59`
- **Active on-chain, production lane**: `103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3` — registered 2026-08-24 by the owner
  above. That is what the registry says. What a box is *running* is a separate fact from
  a separate source: that box's `/attestation`. This file used to print one number for
  both, and that is how it went stale.
- **What the demo box runs**: `32d25d8c2f0bde55610e6a25b9ae51678a50b3a3929c70cdb5a497ec0a5f8c1f34520c5fb67b20912677ecc47d377103` — deprecated by that
  same rotation, so it answers `false` on-chain. See the table above before you check it.

> 🔴 **`isPCR0Active` reads mutable state, and `registerPCR0` is permissionless.** Any
> address may register an unclaimed measurement and become its owner; an owner's next
> registration auto-deprecates their previous one. So `active = true` means "somebody
> has this measurement registered right now" — **not** "Usenami vouches for this
> enclave". What no one can rewrite after the fact is the **event log**
> (`PCR0Registered` / `PCR0Deprecated`) and the blocks carrying it. Two things make a
> `true` meaningful: the `owner` equals the canonical address above, and the
> registration event is where and when it claims to be.

### How to verify (the correct way — read this carefully)

The PCR0 alone is **not** enough. Three checks must all pass; any one of them is bypassable on its own.

**1. PCR0 registered, owned by us, currently active:**

```bash
# Take the measurement from the /attestation of the endpoint you intend to use, then
# ask the registry about THAT value. Do not paste a number out of this file: files lag,
# attestation documents do not.
# 🔴 `pcr0_sha384` is the CONVENIENCE MIRROR, not the signed document. A gateway
# that wanted to fool you would put a registered measurement in this field while
# the COSE document carries a different one — and the registry would answer
# `true` about a measurement nothing is running. This shortcut is only worth
# anything AFTER verify.py has validated the signed document; treat a `true`
# here without that step as unproven, not as proof.
# Fail closed on the fetch too: an error page or a missing field would otherwise
# walk an empty value straight into the calldata.
SIGNER_URL=https://signer-demo.usenami.io:8443   # or your production endpoint
PCR0=$(curl -sf "$SIGNER_URL/attestation" | jq -r '.pcr0_sha384 // empty')
# POSIX, and case-normalised first: an uppercase hash is the same hash, and
# `[[ =~ ]]` is a bashism that dies in dash — which is /bin/sh on Debian.
# `shopt -s nocasematch` also quietly makes both `[[ =~ ]]` and a bare `case`
# accept uppercase, so normalise rather than rely on the match being strict.
# LC_ALL=C: `tr` ranges and `case` bracket expressions collate per locale, so a
# range like a-f is not guaranteed to mean the six letters everywhere. Not
# reproduced on this machine — every locale available here behaved correctly —
# but the guard costs one line and removes the whole class.
PCR0=$(printf '%s' "$PCR0" | LC_ALL=C tr 'A-F' 'a-f')
case "$PCR0" in
  *[!0123456789abcdef]*) echo "no usable pcr0_sha384 from $SIGNER_URL" >&2; exit 1 ;;
esac
[ ${#PCR0} -eq 96 ] || { echo "no usable pcr0_sha384 from $SIGNER_URL" >&2; exit 1; }

cast call 0x38b42eED740b0fDeb211bBDf773F2238cAEec240 \
  "isPCR0Active(bytes)(bool,address)" \
  "0x$PCR0" \
  --rpc-url https://mainnet.base.org
# → true
#   0x21538eBF6598e5866BA496A954dE8E39097bFB59
# BOTH lines must match: `false` or a different owner = stop, do not use the service.
# For the production lane today that is 0x103ccd79de6c… — see the demo caveat above
# before you run this against the demo box.
```

The argument is the raw **48 bytes** — `cast` encodes the `0x…` literal for you. Passing
the 96-character hex *text* is 96 bytes and reverts `InvalidPCR0Length()`, which reads
like a broken contract and is really an encoding mistake.

Best practice is to feed this call the PCR0 you read out of the **verified live
attestation document**, not the constant printed above — that is what turns the two into
a cross-check instead of two copies of the same claim. See
[`docs/VERIFY-SIGNER-YOURSELF.md`](./docs/VERIFY-SIGNER-YOURSELF.md) §1.3, which also
shows how to read the immutable registration **event** rather than the mutable getter.

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
claude mcp add signer npx @usenami/signer-mcp@0.6.0 \
  -e SIGNER_GATEWAY_URL=https://signer-demo.usenami.io:8443 \
  -e SIGNER_API_TOKEN=<your-token>
```

Then ask your agent to place a small limit order. **Point the venue at testnet yourself if that is what you want** — the hosted gateway signs against Binance USD-M **mainnet**, so a request that does not say otherwise moves real funds. This line used to read "on Binance testnet", which described a deployment we no longer run. Your API key never leaves the AWS Nitro enclave.

For direct programmatic use, the TypeScript SDK is on npm — `npm i @usenami/signer` (see [`sdk/typescript`](./sdk/typescript)).

Every signed call returns a **Verifiable Policy Proof** — a Nitro attestation receipt proving the enclave signed your specific request under your declared UPL policy.

---

## Reproducible build

The enclave EIF (Enclave Image File) is **deterministically buildable** — a clean
clone of this repository **at the measured commit** rebuilds the measurement the
production endpoint attests to. A measurement belongs to a commit, not to a
branch: dependency bumps on `main` change the enclave binary and therefore PCR0.

```bash
git clone https://github.com/namixai/signer.git && cd signer
git checkout 96cd4e46                   # the commit the production PCR0 was measured on
cd poc
SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh
# → PCR0 103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3
# Compare that against the production /attestation, not against this line. The table
# below records which commit produced which measurement, and when each was deployed.
```

> **Measured, not asserted — and here is the measurement record.**
> Last re-run: **2026-08-23** (103ccd79 measurement; prior re-run 2026-08-20), clean anonymous clone into an empty
> directory, `env -i`, x86_64 EC2 build host `i-0d332f8f`, **`nitro-cli 1.4.4`**.
> PCR0 also depends on the `nitro-cli` release (it bundles the enclave kernel and
> init), so use the same version or expect a different number for that reason alone.
> A build needs ~30 GB of free disk for the Docker layers; `build-eif.sh` prunes
> its own cache after the build (set `SIGNER_BUILD_KEEP_CACHE=1` to keep it).
>
> | tree | build | PCR0 |
> |---|---|---|
> | commit `db68182` (2026-08-11) | `SIGNER_REQUIRE_POLICY=1` | `32d25d8c…` — previous production (2026-08-10 → 2026-08-24) |
> | commit `db68182` | `SIGNER_REQUIRE_POLICY=0 SIGNER_ROTATION_GATE=0` | `9f80b8d4…` — permissive, not deployed anywhere |
> | commit `96cd4e46` (2026-08-23, merge of #55: tenant mode + decision receipts + ROT-8) | `SIGNER_REQUIRE_POLICY=1` | `103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3` — **production since 2026-08-24** (registry v108, decision receipts + enclave-level tenant stop live); the live value is always `/attestation` |
> | commit `1207d37` (2026-08-19, current `main` lineage) | `SIGNER_REQUIRE_POLICY=1` | `b502601bcd11517d7bb0ddcd4b21b5374097248936be79b832d3bd53cb02d2141c88bffb29c975a9c431ac73207a1cf9` — **not deployed**; differs because `anyhow` and `thiserror` were bumped after the measurement |
>
> Between 2026-08-17 and 2026-08-20 this section pointed a `main` checkout at the
> production number. Anyone who followed it got `b502601b…` and had every reason to
> call the claim false. The mechanism was intact; the instruction was stale. Since then
> CI runs `scripts/enclave-closure-check.py`: the enclave's dependency closure is
> snapshotted in `poc/enclave/DEPENDENCY-CLOSURE.lock` next to the PCR0 it was measured
> as, and a lockfile change that touches the enclave fails CI until someone re-measures
> and updates both in the same PR.

> ### The flag is part of the measurement, not a runtime switch
>
> `SIGNER_REQUIRE_POLICY` is **baked into the image**, so it changes PCR0. Omitting
> it is not "the same build without a setting" — it is a different enclave:
>
> | build | PCR0 |
> |---|---|
> | `SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh` | `103ccd79…` — **this is production** |
> | `SIGNER_REQUIRE_POLICY=0 SIGNER_ROTATION_GATE=0 ./scripts/build-eif.sh` | `9f80b8d4…` — not deployed anywhere |
>
> The strict value is measured on commit `96cd4e46` (production since 2026-08-24), the
> permissive one on `db68182`. Measured, not asserted, and each measurement belongs to
> the commit it was taken on. Set **both** variables
> explicitly for the permissive build: the script honours whatever
> `SIGNER_REQUIRE_POLICY` it inherits from your shell before falling back to its
> permissive default, so if you exported `=1` for the strict build above, passing
> only `SIGNER_ROTATION_GATE=0` would rebuild the *strict* image. If your build
> lands on `9f80b8d4…` you reproduced the permissive image correctly; if it lands
> on neither, that is the interesting case and we would like to hear about it.
>
> The permissive PCR0 is a property of the source tree — an earlier tree measured
> `18b6ece4…` here; on `db68182` it is `9f80b8d4…`. The strict value is what the
> production endpoint attests, and it is the one to trust.
>
> ### The permissive build is gated on a rotation tree
>
> With `SIGNER_REQUIRE_POLICY` unset (its default is permissive), the flagless
> `./scripts/build-eif.sh` on this tree stops with:
>
> ```text
> FATAL: rotation gate — this image is PERMISSIVE (SIGNER_REQUIRE_POLICY=0).
>        A mainnet rotation image must bake exactly 1.
> ```
>
> That is deliberate: the build refuses to hand you a permissive image where a
> rotation expects the strict one. To measure the permissive PCR0 anyway, ask for
> it explicitly with `SIGNER_REQUIRE_POLICY=0 SIGNER_ROTATION_GATE=0`.
>
> This README previously showed the flagless command next to a production PCR0, so
> anyone following it byte-for-byte got a mismatch and had every reason to conclude
> the claim was false. Corrected rather than quietly amended.

**The authority is `/attestation`, not this file.** It returns an NSM-signed COSE
document carrying the measurement the running enclave actually reports, verifiable
against the AWS Nitro root. A value printed in a README goes stale silently; compare
your build against the live document, and use the number here only to know what to
expect.

KMS key policy refuses to release encrypted secrets unless the requesting enclave's PCR0 measurement matches the value pinned in the KMS key policy (`kms:RecipientAttestation:ImageSha384`; the Terraform that pins it lives in the private infra tree; a snapshot of the LIVE policy belongs in `poc/policies/` for clients to read, and until it is committed there this link rests on our word — see `poc/policies/README.md`). **Change one byte of the source code → new PCR0 → KMS denies → all existing customer secrets become unusable until the new measurement is added to the policy.** This is the security boundary.

### Cross-vector regression tests

For Hyperliquid EIP-712 signing, see `poc/enclave/src/signer.rs::tests::action_hash_matches_hyperliquid_sdk_reference` — asserts byte-for-byte match against the official `hyperliquid-python-sdk`. Catches msgpack encoding bugs (e.g., key ordering), EIP-712 domain/struct mistakes, signature serialization issues.

---

## Security

- **Bug bounty:** $1,000 pool — see `SECURITY.md` (W3-W4 ship)
- **Threat model:** internal red-team scenarios run before each phase; public version coming with audit publication
- **Zero unsafe Rust:** see `cargo-geiger` output in CI (coming)
- **Audit:** none yet. No external audit has been commissioned or started; internal adversarial review only.

---

## Project status (2026-08-22)

**Mainnet, operator's own funds only (dogfood).** Three venues have signed on mainnet: Binance USD-M (completed round trip 2026-07-27), Hyperliquid (enclave-born agent key 2026-08-16, completed round trip 2026-08-19), OKX (signed, accepted into the book and cancelled 2026-08-18 — never filled; an hourly place→verify→cancel timer has run clean since). KuCoin, Bybit and Asterdex have adapters but no mainnet key; under a capped policy their generic path is fail-closed. Zero paying customers, zero third-party money in production, no external audit. EIP-712 signing is verified byte-for-byte against the official Hyperliquid SDK.

Production PCR0: `103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3` (since 2026-08-24; tag `pcr0-103ccd79`)

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

For development without an actual Nitro Enclave (local-only signing), read `poc/enclave/Dockerfile` and `poc/scripts/run-enclave-debug.sh`. (This pointed at `poc/enclave/README.md`, which does not exist in this repo.)

---

## License

[Apache-2.0](./LICENSE).

If you build something with this and ship it, drop a note at [@usenami_io](https://twitter.com/usenami_io).
