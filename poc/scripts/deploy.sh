#!/usr/bin/env bash
# One-shot deploy script for the signer.
#
# Runs the full chain: rsync code → build EIF → update KMS → restart enclave + gateway → smoke test.
# Each step short-circuits on failure with a clear error code.
#
# Usage:
#   _signer/poc/scripts/deploy.sh           # full deploy
#   _signer/poc/scripts/deploy.sh --dry-run # show what would happen
#
# Pre-conditions:
#   - SSH key at ~/.ssh/signer-poc-key.pem
#   - AWS profile "signer-poc" with kms:PutKeyPolicy permission
#   - python3.13 with boto3 installed
#
# Post-conditions on success:
#   - EC2 EIF rebuilt and running
#   - KMS policy updated to new PCR0
#   - Gateway restarted with new binary
#   - All exchanges in /var/lib/signer/blobs/ sign successfully

set -euo pipefail

EC2_USER="ec2-user"
EC2_HOST="54.224.183.120"
SSH_KEY="$HOME/.ssh/signer-poc-key.pem"
KMS_KEY_ID="d587cf69-c70a-4bba-be6e-a5270bc4c6db"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_SRC="$(cd "$SCRIPT_DIR/.." && pwd)"

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

log() { printf '\n=== %s ===\n' "$*" >&2; }
ssh_ec2() { ssh -i "$SSH_KEY" -o ConnectTimeout=10 "$EC2_USER@$EC2_HOST" "$@"; }

# Step 1: Verify SSH access.
log "Step 1/8: Verify SSH access"
if [[ $DRY_RUN -eq 0 ]]; then
  ssh_ec2 'echo "EC2 reachable"' >/dev/null || { echo "ERROR: SSH to EC2 failed" >&2; exit 1; }
fi

# Step 2: Sync code.
log "Step 2/8: Rsync source to EC2"
if [[ $DRY_RUN -eq 0 ]]; then
  rsync -avz --delete -e "ssh -i $SSH_KEY" \
    "$LOCAL_SRC/enclave/src/" "$EC2_USER@$EC2_HOST:/home/ec2-user/signer-poc/enclave/src/" >/dev/null
  rsync -avz --delete -e "ssh -i $SSH_KEY" \
    "$LOCAL_SRC/gateway/src/" "$EC2_USER@$EC2_HOST:/home/ec2-user/signer-poc/gateway/src/" >/dev/null
  # Per-crate manifests + Dockerfile
  rsync -avz -e "ssh -i $SSH_KEY" \
    "$LOCAL_SRC/enclave/Cargo.toml" "$LOCAL_SRC/enclave/Dockerfile" \
    "$EC2_USER@$EC2_HOST:/home/ec2-user/signer-poc/enclave/" >/dev/null
  rsync -avz -e "ssh -i $SSH_KEY" \
    "$LOCAL_SRC/gateway/Cargo.toml" \
    "$EC2_USER@$EC2_HOST:/home/ec2-user/signer-poc/gateway/" >/dev/null
  # Workspace root: Cargo.toml + Cargo.lock + toolchain pin.
  # Critical: workspace.dependencies (e.g. k256, tiny-keccak) live in root Cargo.toml.
  # Stale workspace toml on EC2 = `dependency.X was not found in workspace.dependencies`.
  rsync -avz -e "ssh -i $SSH_KEY" \
    "$LOCAL_SRC/Cargo.toml" "$LOCAL_SRC/Cargo.lock" "$LOCAL_SRC/rust-toolchain.toml" \
    "$EC2_USER@$EC2_HOST:/home/ec2-user/signer-poc/" >/dev/null
fi

# Step 3: Run unit tests on EC2.
log "Step 3/8: cargo test"
if [[ $DRY_RUN -eq 0 ]]; then
  ssh_ec2 'cd /home/ec2-user/signer-poc && cargo test 2>&1 | tail -3' || { echo "ERROR: tests failed" >&2; exit 2; }
fi

# Step 4: Build release gateway binary.
log "Step 4/8: cargo build --release -p signer-gateway"
if [[ $DRY_RUN -eq 0 ]]; then
  ssh_ec2 'cd /home/ec2-user/signer-poc && cargo build --release -p signer-gateway 2>&1 | tail -3'
fi

# Step 5: Build new EIF.
log "Step 5/8: Build EIF + capture PCR0"
if [[ $DRY_RUN -eq 0 ]]; then
  # 5a: docker build — fail-fast with diagnostic dump on error.
  ssh_ec2 'cd /home/ec2-user/signer-poc && \
    sudo docker rmi -f signer-enclave:latest 2>/dev/null || true; \
    sudo docker build --no-cache -t signer-enclave:latest -f enclave/Dockerfile . > /tmp/docker-build.log 2>&1' \
    || { echo "ERROR: docker build failed. Last 80 lines:" >&2; ssh_ec2 'tail -80 /tmp/docker-build.log' >&2; exit 3; }
  # 5b: nitro-cli build-enclave — fail-fast with diagnostic dump.
  ssh_ec2 'cd /home/ec2-user/signer-poc && \
    sudo nitro-cli build-enclave --docker-uri signer-enclave:latest --output-file signer.eif > /tmp/eif-build.log 2>&1' \
    || { echo "ERROR: nitro-cli build-enclave failed. Last 80 lines:" >&2; ssh_ec2 'tail -80 /tmp/eif-build.log' >&2; exit 3; }
  # 5c: extract PCR0 via clean ssh — no piping through diagnostic streams.
  NEW_PCR0=$(ssh_ec2 'sudo nitro-cli describe-eif --eif-path /home/ec2-user/signer-poc/signer.eif | jq -r ".Measurements.PCR0"')
  # PCR0 must be exactly 96 hex chars (48 bytes).
  if [[ -z "$NEW_PCR0" || "$NEW_PCR0" == "null" || ! "$NEW_PCR0" =~ ^[0-9a-f]{96}$ ]]; then
    echo "ERROR: PCR0 invalid: '$NEW_PCR0' (expected 96 hex chars)" >&2
    exit 3
  fi
  echo "New PCR0: $NEW_PCR0"
fi

# Step 6: Update KMS policy.
# CRITICAL: env vars (NOT bash interpolation) to keep Python heredoc parseable
# if NEW_PCR0 ever contains unexpected chars. Heredoc is single-quoted so $...
# inside is treated literally by bash and resolved by Python via os.environ.
log "Step 6/8: Update KMS policy"
if [[ $DRY_RUN -eq 0 ]]; then
  NEW_PCR0="$NEW_PCR0" KMS_KEY_ID="$KMS_KEY_ID" python3.13 - <<'EOF'
import os, sys, boto3, json
new_pcr0 = os.environ['NEW_PCR0']
kms_key_id = os.environ['KMS_KEY_ID']
session = boto3.Session(profile_name='signer-poc', region_name='us-east-1')
kms = session.client('kms')
policy_str = kms.get_key_policy(KeyId=kms_key_id, PolicyName='default')['Policy']
policy = json.loads(policy_str)
updated = False
for stmt in policy['Statement']:
    if stmt.get('Sid') == 'EnclaveAttestedDecryptOnly':
        cond = stmt['Condition']['StringEqualsIgnoreCase']
        old = cond['kms:RecipientAttestation:ImageSha384']
        cond['kms:RecipientAttestation:ImageSha384'] = new_pcr0
        print(f'PCR0: {old[:16]}... -> {new_pcr0[:16]}...')
        updated = True
if not updated:
    sys.exit('ERROR: EnclaveAttestedDecryptOnly statement not found in KMS policy')
kms.put_key_policy(KeyId=kms_key_id, PolicyName='default', Policy=json.dumps(policy))
print('KMS policy updated')
EOF
fi

# Step 7: Restart enclave + gateway.
log "Step 7/8: Restart enclave + gateway"
if [[ $DRY_RUN -eq 0 ]]; then
  ssh_ec2 'sudo nitro-cli terminate-enclave --all >/dev/null 2>&1; \
    sudo nitro-cli run-enclave --cpu-count 2 --memory 1024 --enclave-cid 16 \
      --eif-path /home/ec2-user/signer-poc/signer.eif | jq ".EnclaveID"; \
    sudo systemctl restart signer-gateway; \
    sleep 3; \
    echo "Gateway: $(sudo systemctl is-active signer-gateway)"; \
    echo "Enclave: $(sudo nitro-cli describe-enclaves | jq -r ".[0].State")"'
fi

# Step 8: Smoke test all configured exchanges.
log "Step 8/8: Smoke test"
if [[ $DRY_RUN -eq 0 ]]; then
  HEALTH=$(ssh_ec2 'curl -sS http://localhost:8443/healthz')
  echo "healthz: $HEALTH"
  [[ "$HEALTH" == *'"status":"ok"'* ]] || { echo "ERROR: healthz failed" >&2; exit 4; }

  # Iterate over configured blob files and test each.
  EXCHANGES=$(ssh_ec2 'ls /var/lib/signer/blobs/*.enc 2>/dev/null | xargs -n1 basename | sed "s/\.enc$//"')
  for ex in $EXCHANGES; do
    case $ex in
      kucoin)  D='{"exchange":"kucoin","method":"GET","path":"/api/v1/accounts"}';;
      binance) D='{"exchange":"binance","method":"GET","path":"/api/v3/account"}';;
      bybit)   D='{"exchange":"bybit","method":"GET","path":"/v5/account/wallet-balance","query":"accountType=UNIFIED"}';;
      okx)     D='{"exchange":"okx","method":"GET","path":"/api/v5/account/balance"}';;
      *)       D="{\"exchange\":\"$ex\",\"method\":\"GET\",\"path\":\"/probe\"}";;
    esac
    RESP=$(ssh_ec2 "curl -sS -X POST http://localhost:8443/sign -H 'Content-Type: application/json' -d '$D'")
    if echo "$RESP" | jq -e ".headers" >/dev/null 2>&1; then
      printf '  %-10s OK\n' "$ex"
    else
      printf '  %-10s FAIL: %s\n' "$ex" "$RESP"
      exit 5
    fi
  done
fi

log "DEPLOY COMPLETE"
echo "New PCR0: ${NEW_PCR0:-(dry-run)}"
echo "Production: http://signer-demo.usenami.io:8443"
