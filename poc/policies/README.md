# KMS key policy — authoritative source

**The single source of truth for the signer CMK key policy is [`../infra/kms.tf`](../infra/kms.tf)** (`aws_kms_key.venue`, `policy = jsonencode({...})`).

The live key policy is then mutated **in place** by `../scripts/deploy.sh` (PCR0 rotation via boto3 `put_key_policy`), which is why `kms.tf` declares `lifecycle { ignore_changes = [policy] }`. To read the live policy, use `aws kms get-key-policy --key-id <id> --policy-name default` and diff against `kms.tf`.

## Removed: static `kms-policy-day{1,2,3}-*.json` snapshots (AUD-006)

The previous `kms-policy-day1-permissive.json` / `day2-attestation.json` / `day3-attestation.json` static snapshots were **deleted** in the AUD-006 hardening pass. They had **no consumers** (nothing in `scripts/`, `infra/`, or the crates referenced them) and had **diverged** from `kms.tf`:

- **CR043** — the day2/day3 snapshots granted the builder `kms:PutKeyPolicy` (a `BuilderManagementOnly` Sid). `kms.tf` uses the correct, least-privilege **`BuilderEncryptOnly`** (only `kms:Encrypt` + `kms:DescribeKey`, scoped to the EncryptionContext). Keeping the stale JSON around risked someone re-applying the privilege-escalating version.
- **CR044** — the snapshots' attestation-deny had a `ViaService=s3` carve-out that warrants review against `kms.tf`'s `DenyDecryptWithoutAttestation`.

Removing the snapshots prevents accidental re-application and makes `kms.tf` the unambiguous source. (The live CMK's own divergence — it currently carries the `BuilderManagementOnly` + PutKeyPolicy grant — is being corrected in the **post-soak KMS policy edit**, bundled with the removal of the rotated-out PCR0. Not changed mid-soak.)

`build-pins.txt` is unrelated to KMS policy (reproducible-build pins) and is retained.
