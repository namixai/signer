# Threat Model

This document enumerates the realistic attackers against the Usenami Signer, what each can attempt, and what stops them. It is the document I'd want to read before trusting any system with my exchange API keys.

If you find a class of attack we don't address here, please open an issue.

---

## Asset being protected

**The plaintext exchange API secret** (HMAC key or ECDSA private key). Compromise means an attacker can:

- Submit unauthorized trade requests
- Withdraw funds (on exchanges where the key has withdrawal permission)
- Impersonate the legitimate signer indefinitely

Everything else in the system is replaceable. The plaintext key is the only thing whose compromise is unrecoverable until rotation.

---

## Attacker classes

### A1 — Host operator with root

**Capability:** SSH access or compromised SSM session on the host EC2 instance. Can read process memory, dump disk, inspect network traffic on the host network namespace.

**What they try:**
- `ptrace` the gateway process → read whatever it holds
- Dump full RAM via `/proc/kcore` or `kdump` → search for key material
- Inspect KMS API traffic on the host → intercept plaintext key

**What stops them:**
- Plaintext key never exists in the gateway process or host RAM. It exists only in **enclave memory**, which is isolated by the Nitro hypervisor — the host kernel cannot map enclave pages.
- KMS traffic uses the Nitro attestation channel via `vsock-proxy`. The plaintext key never traverses the host network stack — it goes directly from KMS endpoint → enclave over the proxied vsock.

**Residual risk:** Operator with root can DoS the service (kill the enclave, block vsock, etc) but cannot extract the key.

---

### A2 — Compromised supply chain (gateway binary)

**Capability:** Attacker injects malicious code into the gateway build (compromised dependency, CI exfil, malicious PR).

**What they try:**
- Modify gateway to log signing requests and responses (exfil signing oracle)
- Add a covert side channel that triggers key signing on attacker-controlled requests

**What stops them:**
- Gateway has no plaintext key — at worst it becomes a malicious signing oracle, but it still has to ask the enclave to sign things, and the enclave is bound to a customer's keys.
- **UPL (Usenami Policy Layer) is live and enforced enclave-side** (shipped 2026-05-14 — this is the current build, not a future phase). Each customer key is co-encrypted with a JSON policy inside a single KMS ciphertext; the enclave decrypts both atomically and validates every request against the policy *after* decryption but *before* any signing work, returning `policy_denied` on a violation. A malicious gateway cannot forge, weaken, or swap a policy without re-encrypting through KMS — which it can't do without enclave attestation. So a malicious gateway is bounded to the venues, actions, HTTP methods, and path prefixes the customer pre-declared (deny-by-default on empty lists, fail-closed on malformed wrappers), plus a per-minute request cap.
- Signing-request volume is observable. Anomalous spikes show up in metrics.

**Residual risk:** UPL bounds *which* actions / venues / paths a malicious gateway can reach on every path, plus a per-minute rate cap. On the **structured order paths (Hyperliquid, Asterdex)** it additionally enforces per-policy **order-size caps** enclave-side, returning `policy_denied` on an over-cap request. On the **generic HMAC sign path** (`/sign/binance-request`, used by the keyless demo) the enclave enforces a per-operation parameter allow-list that **denies withdraw/transfer outright** — that refusal is enclave-side. On the **structured `/sign` path** the refusal happens one layer earlier, in the gateway, before the enclave is called at all (see *Where the withdraw refusal happens* below). Order *size* on the generic path is **not** yet capped — size caps on that path are a documented, pending hook, not a current guarantee. So a malicious gateway is confined to the declared action / venue / path envelope and the rate cap everywhere, and to per-policy size caps on the structured paths; **treat the generic sign path as deny-withdraw-bound, not cap-bound.** Defense in depth (disable exchange-side withdrawals, sandbox the bot) stays recommended.

---

### A3 — Compromised supply chain (enclave binary)

**Capability:** Attacker gets their backdoored enclave binary built and published.

**What they try:**
- Replace the legitimate enclave image with one that logs plaintext keys

**What stops them:**
- The enclave's PCR0 hash is **bound into the KMS key policy** at provisioning time. A backdoored enclave has a different PCR0 → KMS denies decryption → the backdoored binary cannot retrieve the plaintext key.
- Anyone can rebuild the published source and verify the resulting PCR0 matches the one in the KMS policy. **Reproducible builds + public PCR0 = supply chain verification.**

**Residual risk:** If the attacker can *also* compromise the KMS policy to add their backdoored PCR0 → see A4.

---

### A4 — Compromised AWS account / IAM

**Capability:** Attacker gains permissions to edit KMS key policies in the AWS account hosting the signer.

**What they try:**
- Add their backdoored enclave's PCR0 to the key policy
- Add a non-attestation-gated principal that can `kms:Decrypt` directly

**What stops them (defense in depth):**
- **Least-privilege IAM:** only one tightly-scoped IAM role can edit the signing KMS key policy. Day-to-day operators don't have `kms:PutKeyPolicy`.
- **CloudTrail alarms** on `PutKeyPolicy` events for this key. Any modification triggers a page.
- **Tamper-evident builds:** the dependency pins that make the enclave build DETERMINISTIC live in `poc/policies/build-pins.txt` (they are what makes two clean builds agree; the PCR0 is the OUTPUT of that build, and that file is not a record of the current measurement — the live `/attestation` document is), and the KMS key policy is what binds the PCR0 / `ImageSha384` the enclave is allowed to attest with (the `poc/policies/kms-policy-day{1,2,3}-*.json` snapshots this sentence used to cite were DELETED in the AUD-006 pass — they had diverged from the Terraform and one of them granted the builder `kms:PutKeyPolicy`; the replacement is a dated snapshot of the LIVE policy at `poc/policies/venue-key-policy-<venue>.json`, and `poc/policies/README.md` states whether it is published yet). A live KMS policy attesting a PCR0 that you cannot derive from this tree is **unverified from the public source**, which is not the same as unauthorized: a deliberate rotation can legitimately authorize a new measurement before this repository is synced, and has done so. Treat it as "not independently verifiable until the source revision and the rotation record are published" — and hold us to publishing them. (The Terraform that provisions the production KMS policy is not included in this public tree — request it for a full attestation-integrity review.)
- **Rotation discipline:** if a policy modification is detected, the signing keys can be rotated through a fresh KMS key under a new policy that lists only the reviewed PCR0.

**Residual risk:** A determined attacker with AWS root and the ability to suppress CloudTrail can theoretically substitute the policy. This is the hardest residual risk and is why AWS account hardening (hardware MFA, root account locked away, separate audit account) is part of the deployment runbook.

---

### A5 — Network attacker between SDK and gateway

**Capability:** MITM on the connection between customer's bot and the gateway.

**What they try:**
- Capture signing requests and replay them
- Modify request payloads in transit

**What stops them:**
- **TLS is terminated at Cloudflare**, which fronts the public hostname; the customer's bot speaks HTTPS to the Cloudflare edge. The gateway process itself currently serves **plain HTTP on `:8443`** behind that edge (`http://signer-demo.usenami.io:8443`). Gateway-native TLS is **Phase 2 and not yet built** — so the SDK↔Cloudflare hop is encrypted, while the Cloudflare↔gateway hop relies on the deployment's network controls rather than gateway TLS.
- **Authentication is a bearer token, not mTLS.** Every `/sign` request must carry `Authorization: Bearer <token>` (configured via `SIGNER_API_TOKENS`). mTLS was explicitly considered and **rejected** for Phase 1 — it would require Cloudflare's paid mTLS tier plus a client certificate provisioned on every customer bot, which was deemed too much setup friction for the pilot. **There is no client-certificate scheme today.**
- Replay protection: signed payloads contain nonces / timestamps that the exchange rejects on replay. (This is enforced by the exchange, not the signer — true defense in depth would add a signer-side replay window too, on the roadmap.)

**Residual risk:** A leaked bearer token lets an attacker submit signing requests directly (bounded by UPL's action/venue/path envelope — see A6). Bearer-token hygiene on the customer side is therefore load-bearing. Gateway-native TLS (Phase 2) and a future mTLS or signed-envelope upgrade would tighten this; neither is shipped yet.

---

### A6 — Compromised customer bot (or prompt-injected agent)

**Capability:** Attacker controls the customer's bot software — or, in the agentic use case, prompt-injects an AI agent that holds the signing token. Either way the attacker can issue arbitrary requests to the gateway with valid credentials.

**What they try:**
- Submit malicious signing requests — for example an oversized order or an unauthorized transfer

**What stops them (UPL, live and enforced enclave-side):**
- **UPL is live and enforced inside the enclave.** A compromised bot is bounded to the actions, venues, HTTP methods, and path prefixes in the customer's policy (deny-by-default, fail-closed), plus a per-minute rate cap. If the policy doesn't permit a given venue's order action, an injected agent can't get the enclave to sign one.

- **Order-size caps are enforced enclave-side on the structured order paths; on the generic sign path withdraw/transfer is denied enclave-side, while on the structured `/sign` path the same class is refused earlier by the gateway. Order size is not yet capped on the generic path.** On the **Hyperliquid / Asterdex structured order paths**, the enclave validates per-policy size caps *after* decryption but *before* signing, returning `policy_denied` on an over-cap request. On the **generic HMAC sign path** (the one the keyless demo uses), the per-operation parameter allow-list **denies withdraw/transfer entirely**, enclave-side. Order *size* is **not** capped there yet — that is a documented pending hook, not a shipped guarantee. Treat the generic path as **deny-withdraw-bound, not cap-bound**: an over-size order on that path will be signed.

**Residual risk:** Order-size limits do not yet cover the generic sign path (pending hook), and one narrow policy-enforcement edge on the structured paths remains under active hardening. As defense in depth — independent of UPL — customers should still disable withdrawals on the exchange-side API key wherever the venue allows it, sandbox the bot, and guard the bearer token. A compromised bot is bounded to the customer's declared action / venue / path envelope and the per-minute rate cap on every path (plus size caps on the structured paths) — withdrawal- and transfer-class requests are refused everywhere, though by **different layers depending on the path** (see *Where the withdraw refusal happens*). Do not rely on size caps on the generic path.

---

### A7 — Insider with multi-role access

**Capability:** Someone inside the operating organization (Usenami staff) with combined access to KMS policy + enclave deployment.

**What they try:**
- Substitute the enclave binary AND update KMS policy in one coordinated action

**What stops them:**
- **Separation of duties.** KMS policy edits and enclave deploy permissions are split across different IAM roles, granted to different people. The deploy script will refuse to ship an enclave whose PCR0 isn't already in the policy — and the policy editor can't deploy.
- **Public commitments.** Published PCR0 hashes in the repository commit the operator publicly. A mismatch between the published PCR0 and the in-use PCR0 is detectable by anyone running the verification script.

**Residual risk:** Two colluding insiders with both roles could theoretically bypass this. Mitigation is multi-party review on any KMS policy or enclave image change.

---

## Summary table

| Attacker | Can extract plaintext key? | Mitigation |
|---|---|---|
| A1 — Host root | No | Nitro hypervisor isolation |
| A2 — Backdoored gateway | No (can be a signing oracle, scoped by UPL) | UPL enforces action/venue/path enclave-side (live); withdraw/transfer refused on every path — **enclave-side on the generic path, and one layer earlier by the gateway on the structured `/sign` path** (see note below the table); order-size caps on structured order paths only — generic sign path is deny-withdraw-bound, not cap-bound |
| A3 — Backdoored enclave | No | PCR0 attestation binding |
| A4 — Compromised AWS IAM | Hard | Least-privilege, CloudTrail alarms, separation of duties |
| A5 — Network MITM | No | Bearer-token auth + Cloudflare-edge TLS (gateway-native TLS = Phase 2); exchange-side nonce. **No mTLS.** |
| A6 — Compromised bot / injected agent | No — key never leaves the enclave; can use it as a signing oracle, scoped by UPL | UPL (live) bounds action/venue/path enclave-side; withdraw/transfer refused everywhere — **enclave-side on the generic path, gateway-side on the structured `/sign` path** (see note below the table); order-size caps on structured paths only (generic sign path not cap-bound — pending hook); one narrow edge under hardening |
| A7 — Multi-role insider | Hard | Separation of duties + public PCR0 commitments |

### Where the withdraw refusal happens

Withdrawal- and transfer-class requests are refused on every path, but **not by the same layer**,
and the difference matters if you are reasoning about who has to be trusted.

**On the structured `/sign` path — the gateway, before the enclave is called.** It matches the
venue-native action name against a fixed list: `withdraw`, `withdraw3`, `withdrawal`, `usdSend`,
`spotSend`, `cWithdraw`, and the internal transfers `usdClassTransfer`, `vaultTransfer`,
`subAccountTransfer`, `hip3LiquidatorTransfer`. The request never reaches the enclave.

**On the generic HMAC sign path (`/sign/binance-request`) — the enclave.** The gateway performs no
withdrawal check there; the request is forwarded, and the enclave's per-operation parameter
allow-list refuses it, with path matching deliberately cautious enough that denying `/withdraw`
also denies `/withdrawal/...` and `/withdraw-anything`.

Two consequences follow:

- The gateway-side refusal does not depend on attestation or on enclave policy state — it holds
  even while the enclave restarts with an empty registry. But it carries the **gateway's** trust
  level: against a fully compromised gateway it is the enclave-side controls that hold, and on the
  generic path the withdraw refusal is one of them.
- Neither layer is a substitute for disabling withdrawals on the exchange-side API key. That
  remains the recommended defence in depth, as the rows above say.

On the wire both refusals currently look alike (`policy_denied`). Do not read that code as evidence
of which layer decided — check the path you called.

---

## What we'd love red-teamers to try

If you're reading this and you have ideas for attacks not listed, please open an issue. Particularly interested in:

- Side-channel attacks on Nitro Enclave memory isolation (cache timing, speculative execution)
- Attacks on the vsock-proxy KMS attestation channel
- AWS-specific privilege-escalation paths to `kms:PutKeyPolicy`
- Customer-bot social-engineering vectors that don't require code compromise

---

## See also

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — trust boundaries and component responsibilities
- [`CASE_STUDY_PCR0_ROTATION.md`](CASE_STUDY_PCR0_ROTATION.md) — how rotation works without breaking the security model
