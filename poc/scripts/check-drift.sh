#!/usr/bin/env bash
# Drift check: compare PCR0 documented in _signer/STATUS.md against:
#   1. The EIF actually running in the production enclave
#   2. The PCR0 locked into the live KMS policy
#
# Exit codes:
#   0 — all three match (no drift)
#   1 — KMS policy disagrees with running EIF (deploy was incomplete)
#   2 — STATUS.md disagrees with running EIF (drift, deploy happened but docs weren't updated)
#   3 — internal error (ssh/aws/parsing)
#
# Intended for nightly cron + manual `make drift-check`. Output is plain
# text + a final SUMMARY line that's easy to grep from a Slack alert.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATUS_MD="$(cd "$SCRIPT_DIR/../../.." && pwd)/_signer/STATUS.md"
SSH_KEY="$HOME/.ssh/signer-poc-key.pem"
EC2="ec2-user@54.224.183.120"
KMS_KEY_ID="d587cf69-c70a-4bba-be6e-a5270bc4c6db"

# 1. Expected PCR0 from the **Deterministic PCR0:** field in STATUS.md.
#    Historical PCR0 values appear elsewhere in the file; we deliberately
#    pin to this single named field so updates flow through one place.
EXPECTED=$(grep -E '^\*\*Deterministic PCR0:\*\*' "$STATUS_MD" | grep -oE '[0-9a-f]{96}' | head -1)
[[ -z "$EXPECTED" ]] && { echo "ERROR: **Deterministic PCR0:** field not found in $STATUS_MD" >&2; exit 3; }

# 2. PCR0 of the EIF currently running in the enclave.
RUNNING=$(ssh -i "$SSH_KEY" -o ConnectTimeout=10 "$EC2" \
  'sudo nitro-cli describe-enclaves | jq -r ".[0].Measurements.PCR0"' 2>/dev/null)
[[ -z "$RUNNING" || "$RUNNING" == "null" ]] && { echo "ERROR: no enclave running" >&2; exit 3; }

# 3. PCR0 in the live KMS policy.
KMS_PCR0=$(python3.13 - <<EOF
import boto3, json
s = boto3.Session(profile_name='signer-poc', region_name='us-east-1')
p = json.loads(s.client('kms').get_key_policy(KeyId='$KMS_KEY_ID', PolicyName='default')['Policy'])
for stmt in p['Statement']:
    if stmt.get('Sid') == 'EnclaveAttestedDecryptOnly':
        print(stmt['Condition']['StringEqualsIgnoreCase']['kms:RecipientAttestation:ImageSha384'])
        break
EOF
)

printf 'STATUS.md says:   %s\n' "$EXPECTED"
printf 'Enclave running: %s\n' "$RUNNING"
printf 'KMS policy:      %s\n' "$KMS_PCR0"

if [[ "$RUNNING" != "$KMS_PCR0" ]]; then
  echo "SUMMARY: DRIFT — enclave PCR0 != KMS PCR0 (KMS Decrypt will fail in production)"
  exit 1
fi
if [[ "$EXPECTED" != "$RUNNING" ]]; then
  echo "SUMMARY: DOC_DRIFT — STATUS.md is stale (prod is on $RUNNING, docs say $EXPECTED)"
  exit 2
fi
echo "SUMMARY: OK — all three PCR0 values match"
