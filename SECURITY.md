# Security Policy

We take the security of **Usenami Signer** — this repository: the AWS Nitro Enclave
signing core, the gateway in front of it, the attestation path, and the KMS
integration that together hold customer exchange credentials — seriously. Thank you
for helping keep it safe. This document is how to report a vulnerability, what is in
scope, and what you can expect from us.

If you believe you have found a security issue, **please report it privately** using
the process below rather than opening a public issue or PR.

---

## How to report

- **Email:** [business@usenami.io](mailto:business@usenami.io) (monitored; put "SECURITY" in the subject so it is
  triaged promptly)
- If you want to encrypt your report, ask in an initial email (no vulnerability details)
  and we will provide a PGP key.

Please include, as far as you can:

- a clear description of the issue and its **impact** (what an attacker can achieve);
- **reproduction steps** or a proof-of-concept (commands, requests, code);
- the affected component / endpoint / commit SHA;
- any suggested remediation.

You do **not** need to prove impact against live customer funds. A clear PoC against
the demo endpoint, testnet, or a local build is enough — please do not test against
real customer data or funds.

We aim to **acknowledge** a report within **3 business days** and to give a first
substantive assessment within **10 business days**. If you do not hear back, please
follow up — a missed email is far more likely than a dismissed report.

---

## Scope

This policy covers the Signer core in this repository: **enclave, gateway,
attestation, and the KMS integration**.

### In scope

- **The enclave signing core** (`poc/enclave/`): KMS-gated key decryption,
  in-enclave policy validation (deny-by-default whitelists), HMAC / EIP-712
  signing, and plaintext zeroization.
- **The KMS envelope + attestation gate:** any way to obtain plaintext key material
  without a valid attestation of the measured enclave image.
- **The gateway** (`poc/gateway/`) and the **gateway↔enclave vsock boundary**:
  authentication, request handling, and anything smuggled across that boundary.
- **The attestation-verification path** (including the `/attestation` endpoint):
  forging, replaying, or spoofing an attestation document, or otherwise defeating
  PCR0 verification.
- **Reproducible-build / attestation-integrity issues** — e.g. a way to make a
  running image measure to a PCR0 that does not match its published source.
- Anything that lets a party **read plaintext keys off-enclave**, **sign a request
  the client did not authorize**, or **bypass the in-enclave policy validation**.

Issues elsewhere in this repository (e.g. `sdk/`, helper scripts) are welcome at the
same address and will be triaged, but the components above are the priority.

### Out of scope

- Vulnerabilities in **AWS** itself (Nitro Enclaves, the Nitro attestation PKI, KMS
  as a service).
- **Pure upstream third-party dependency** issues with **no exploitable path in our
  system** — report those to the vendor (we are happy to coordinate). **However, if
  our integration, configuration, or version pin makes an upstream vulnerability
  *exploitable through Signer*, that IS in scope** — please report it; we want to
  know even while the underlying fix belongs upstream.
- **Denial-of-service / volumetric** attacks, rate-limit tuning, and load testing.
- **Social engineering**, physical attacks, or phishing of our staff/operators.
- Findings that require a **compromised trust base** we already document as trusted
  (see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)) — e.g. "if AWS root is
  malicious." Novel breaks of that base are, of course, very much in scope.
- **Other Usenami services and repositories** (the usenami.io website, the data
  marketplace, demo repositories). Reports are welcome at the same email, but this
  document's scope and safe harbor are about the Signer core in this repository.
- Missing security headers / best-practice nits with no demonstrated impact
  (still welcome as a low-severity note, but triaged accordingly).
- Automated-scanner output without a demonstrated, exploitable issue.

Some limitations are known and disclosed rather than hidden: the control plane is
currently **single-operator** (no external multi-party control yet), the system has
**not yet had a third-party audit**, and the deployed service is **mainnet-live
on three venues with our own funds** — Binance USD-M since 2026-07-27,
Hyperliquid since 2026-08-16, OKX since 2026-08-18. It is not client traffic,
but it is not testnet either; this paragraph said "testnet / pilot stage" until
2026-08-23, which understated what a bug here can reach. Pointing at these is appreciated but they are known; a
*new* angle on them is in scope.

---

## Supported versions

This is a pre-1.0, actively developed codebase. Security fixes land on `main`;
there are no maintained release branches.

---

## Safe harbor (good-faith research)

If you make a good-faith effort to comply with this policy, we will consider your
research **authorized**, will not pursue or support legal action against you for it,
and will work with you to understand and resolve the issue. "Good faith" means:

- report privately and give us reasonable time to remediate before public disclosure;
- do not access, modify, or exfiltrate data that is not yours; use test/demo/testnet
  targets and your own accounts;
- do not degrade service (no DoS), destroy data, or pivot beyond what is needed to
  demonstrate the issue;
- do not exploit the issue beyond the minimum proof required.

If you are unsure whether something is in bounds, ask us first.

---

## Coordinated disclosure

We practice coordinated disclosure. Default timeline (negotiable with the reporter):

- We triage and confirm, agree a severity, and share a remediation plan.
- We aim to remediate **critical/high** issues within **90 days**; sooner for actively
  exploitable ones. Complex fixes may take longer — we will keep you informed.
- We coordinate a **public disclosure date** with you once a fix is deployed (or a
  mitigation is in place). Please do not disclose publicly before then, except
  as permitted by the stall commitments below.

**If coordination stalls — our commitment to you.** You should never be stuck holding
a finding indefinitely because we went quiet:

- If you get **no acknowledgment within 14 calendar days** of your report, or **no substantive
  update for 30 calendar days** on an accepted report, you are free to disclose publicly, and
  we will not treat that as a breach of good faith.
- Regardless of fix status, we support disclosure **90 calendar days** after your initial
  report (the standard grace period), extendable only by **mutual** agreement — never
  unilaterally by us to bury an issue.
- If the normal channel is unresponsive, escalate with subject `SECURITY
  ESCALATION` to the same address, and — if email itself seems to be the problem —
  ping us via DM to [@usenami_io](https://x.com/usenami_io) (do not include
  vulnerability details there; just ask us to check the security inbox). We would
  rather you reach us than sit on a live risk.

---

## Recognition

- We are glad to **publicly credit** reporters who want it (name / handle / link) in
  the advisory and a security acknowledgments list. Tell us how you would like to be
  credited, or ask to remain anonymous.
- We do **not** run a paid bug-bounty program at this time, and we will not imply
  otherwise. A formal bounty may come with the external-audit milestone; until then
  recognition is our thanks. We would rather be honest about that than dangle a
  reward we have not set up.

---

*A note on our posture: Usenami Signer is built so that you can **verify the core
trust property yourself** without trusting us — see the verification walkthrough in
[`docs/VERIFY-SIGNER-YOURSELF.md`](docs/VERIFY-SIGNER-YOURSELF.md) and the trust boundaries in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). We would much rather hear about a
gap from you than have it stay hidden.*
