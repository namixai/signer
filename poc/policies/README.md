# KMS key policy — authoritative source

**For operators, the source of truth for the signer CMK key policy is `infra/kms.tf`** (`aws_kms_key.venue`, `policy = jsonencode({...})`) — that Terraform lives in the private infrastructure tree and is **not shipped in this public repository**. The link that used to sit here pointed at `../infra/kms.tf`, a path this repo does not contain.

The live key policy is then mutated **in place** by the deploy path (PCR0 rotation via boto3 `put_key_policy`), which is why `kms.tf` declares `lifecycle { ignore_changes = [policy] }`. An operator reads the live policy with `aws kms get-key-policy --key-id <id> --policy-name default` and diffs against `kms.tf`.

**For clients, the source of truth is the snapshot in this directory** — see the next section. A client has no IAM in our account, so "read the Terraform" is not an answer to them.

## Removed: static `kms-policy-day{1,2,3}-*.json` snapshots (AUD-006)

The previous `kms-policy-day1-permissive.json` / `day2-attestation.json` / `day3-attestation.json` static snapshots were **deleted** in the AUD-006 hardening pass. They had **no consumers** (nothing in `scripts/`, `infra/`, or the crates referenced them) and had **diverged** from `kms.tf`:

- **CR043** — the day2/day3 snapshots granted the builder `kms:PutKeyPolicy` (a `BuilderManagementOnly` Sid). `kms.tf` uses the correct, least-privilege **`BuilderEncryptOnly`** (only `kms:Encrypt` + `kms:DescribeKey`, scoped to the EncryptionContext). Keeping the stale JSON around risked someone re-applying the privilege-escalating version.
- **CR044** — the snapshots' attestation-deny had a `ViaService=s3` carve-out that warrants review against `kms.tf`'s `DenyDecryptWithoutAttestation`.

Removing the snapshots prevents accidental re-application and makes `kms.tf` the unambiguous source. (The live CMK's own divergence — it currently carries the `BuilderManagementOnly` + PutKeyPolicy grant — is being corrected in the **post-soak KMS policy edit**, bundled with the removal of the rotated-out PCR0. Not changed mid-soak.)

`build-pins.txt` is unrelated to KMS policy (reproducible-build pins) and is retained.

## What a CLIENT sees — one statement, not four

Four documents used to say four different things about where the key policy lives
(`DEMO.md` promised it "under `poc/policies/`", the top-level `README.md` said "private
infra tree", `docs/THREAT_MODEL.md` pointed at the day-JSONs deleted above, and this file
pointed at an `infra/kms.tf` that this repository does not ship). For an outside reader
that reads as a promise nobody kept.

The rule, from now on, is one line:

> **Operators** read `infra/kms.tf` (private tree, source of truth).
> **Clients** read `venue-key-policy-<venue>.json` in this directory — a snapshot of the
> LIVE policy, exported and committed by an operator, dated in its header.

### One file per live venue key

🔴 The export recipe named `alias/signer/prod/binance/v1` until 2026-08-23. **That alias
exists in no account of ours** — established from the live account twice (an operator
snapshot on 2026-07-26 and a re-check on 2026-08-23). It was also, until the same day,
the alias printed by `signer-policy-wrap` and written in `docs/CLIENT-ONBOARDING.md`: a
client following the published recipe hit `NotFoundException` on command one. The live
venue keys are lane-named:

| file | live alias |
|---|---|
| `venue-key-policy-binance.json` | `alias/signer-mainnet-binance` |
| `venue-key-policy-okx.json` | `alias/signer-mainnet-okx` |
| `venue-key-policy-hyperliquid.json` | `alias/signer-mainnet-hyperliquid` |

### The snapshot is not published yet

Exporting it needs AWS credentials that no one working on this repository holds day to
day, so it is an operator step — `aws kms get-key-policy` per venue, then a mechanical
redaction that rewrites IAM principal ARNs to the role each plays (`<account root>`,
`<account admin>`, `<builder>`, `<provisioner>`, `<enclave role>`) and leaves the account
id, every `Sid`, every `Action` and **every `Condition`** byte-for-byte — in particular
`Null: kms:RecipientAttestation:ImageSha384 = true` on `DenyDecryptWithoutAttestation`
and the `StringEquals` PCR0 on `EnclaveAttestedDecryptOnly`. Those two statements are the
claim; a snapshot that redacted them would prove nothing.

Until those files exist, `docs/CLIENT-ONBOARDING.md` says plainly that this link rests on
our word — do not add a sentence anywhere claiming otherwise.

### And what the snapshot will NOT prove

`kms:PutKeyPolicy` is deliberately not denied on these keys (PCR0 rotation needs it), so
an account admin can delete `DenyDecryptWithoutAttestation` and decrypt off-box. The
snapshot buys a **diffable baseline** backed by a CloudTrail record — an audit trail, not
an impossibility. `docs/CLIENT-ONBOARDING.md` states this in those words, and nothing here
or in `DEMO.md` may imply otherwise.
