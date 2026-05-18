#!/usr/bin/env bash
# upl-smoke.sh — end-to-end smoke test for UPL v0 on the production EC2 enclave.
#
# Verifies four scenarios with the SAME exchange secret bound to four DIFFERENT
# policies:
#
#   1. Legacy blob (no policy)              → sign succeeds (backward compat)
#   2. Policy permits sign_binance          → sign succeeds
#   3. Policy denies sign_binance           → policy_denied
#   4. Policy blocks /sapi/v1/capital path  → policy_denied
#
# Prerequisites:
#   - AWS CLI configured with credentials authorised for kms:Encrypt under
#     the enclave's KMS key alias.
#   - `signer-policy-wrap` built (poc/target/release/signer-policy-wrap).
#   - `aws` and `jq` and `curl` on PATH.
#   - SSH access to the production EC2 host (env: SIGNER_EC2_HOST).
#   - A valid (or harmless throwaway) Binance API key pair for the fixture
#     secret. Smoke does NOT actually sign against a real Binance request;
#     it only exercises the enclave's policy check path.
#
# Environment:
#   SIGNER_EC2_HOST       — ec2-user@host or IP for ssh ProxyJump
#   SIGNER_GATEWAY_URL    — https://signer-demo.usenami.io:8443 (default)
#   KMS_KEY_ALIAS         — alias/signer-poc (default)
#   S3_BUCKET             — bucket where the enclave reads blobs from
#   S3_KEY_PREFIX         — secrets/upl-smoke (default)
#   POC_DIR               — path to _signer/poc (default: this script's dir/..)
#
# Exit codes:
#   0  — all four scenarios passed
#   1  — at least one scenario failed (smoke regression)
#   2  — environment / prerequisite error
#
set -euo pipefail

# ─── 1. Prereqs ──────────────────────────────────────────────────────────

err() { echo "smoke: $*" >&2; }

for tool in aws jq curl ssh; do
  command -v "$tool" >/dev/null 2>&1 || { err "missing prerequisite: $tool"; exit 2; }
done

POC_DIR="${POC_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
WRAP_BIN="${POC_DIR}/target/release/signer-policy-wrap"

if [[ ! -x "${WRAP_BIN}" ]]; then
  err "signer-policy-wrap binary not found at ${WRAP_BIN} — run 'cargo build --release -p signer-policy-cli' first"
  exit 2
fi

: "${SIGNER_EC2_HOST:?must export SIGNER_EC2_HOST (ec2-user@host or host alias)}"
: "${S3_BUCKET:?must export S3_BUCKET (the bucket the gateway reads blobs from)}"
SIGNER_GATEWAY_URL="${SIGNER_GATEWAY_URL:-https://signer-demo.usenami.io:8443}"
KMS_KEY_ALIAS="${KMS_KEY_ALIAS:-alias/signer-poc}"
S3_KEY_PREFIX="${S3_KEY_PREFIX:-secrets/upl-smoke}"

WORK_DIR="$(mktemp -d -t upl-smoke.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "smoke: working dir ${WORK_DIR}"
echo "smoke: gateway ${SIGNER_GATEWAY_URL}"
echo "smoke: kms key ${KMS_KEY_ALIAS}"
echo

# ─── 2. Fixture secret (Binance HMAC) — throwaway test creds ────────────

cat > "${WORK_DIR}/secret.json" <<'EOF'
{
  "key": "upl-smoke-binance-key-throwaway",
  "secret": "upl-smoke-binance-hmac-secret-throwaway"
}
EOF

# ─── 3. Four scenarios ──────────────────────────────────────────────────

# Scenario 1: LEGACY (no policy wrapper) — sign should succeed.
cat > "${WORK_DIR}/scenario1.plain.json" < "${WORK_DIR}/secret.json"

# Scenario 2: policy permits sign_binance.
cat > "${WORK_DIR}/scenario2.policy.json" <<'EOF'
{
  "allowed_actions": ["sign_binance"],
  "allowed_methods": ["GET", "POST", "DELETE"],
  "label": "upl-smoke-permissive"
}
EOF
"${WRAP_BIN}" \
  --policy "${WORK_DIR}/scenario2.policy.json" \
  --secret "${WORK_DIR}/secret.json" \
  --output "${WORK_DIR}/scenario2.plain.json"

# Scenario 3: policy DENIES sign_binance (allows only sign_okx).
cat > "${WORK_DIR}/scenario3.policy.json" <<'EOF'
{
  "allowed_actions": ["sign_okx"],
  "label": "upl-smoke-binance-blocked"
}
EOF
"${WRAP_BIN}" \
  --policy "${WORK_DIR}/scenario3.policy.json" \
  --secret "${WORK_DIR}/secret.json" \
  --output "${WORK_DIR}/scenario3.plain.json"

# Scenario 4: policy denies /sapi/v1/capital/* (withdraw path).
cat > "${WORK_DIR}/scenario4.policy.json" <<'EOF'
{
  "allowed_actions": ["sign_binance"],
  "denied_path_prefixes": ["/sapi/v1/capital"],
  "label": "upl-smoke-no-withdrawals"
}
EOF
"${WRAP_BIN}" \
  --policy "${WORK_DIR}/scenario4.policy.json" \
  --secret "${WORK_DIR}/secret.json" \
  --output "${WORK_DIR}/scenario4.plain.json"

# ─── 4. KMS encrypt each scenario → upload to S3 ────────────────────────

encrypt_and_stage() {
  local scenario="$1"
  local plain="${WORK_DIR}/${scenario}.plain.json"
  local ciphertext_b64="${WORK_DIR}/${scenario}.enc.b64"
  local s3_key="${S3_KEY_PREFIX}/${scenario}.enc"

  aws kms encrypt \
    --key-id "${KMS_KEY_ALIAS}" \
    --plaintext "fileb://${plain}" \
    --output text \
    --query CiphertextBlob > "${ciphertext_b64}"

  # KMS returns base64. The enclave wants the raw bytes uploaded to S3
  # (it base64s on its own side). Decode once before upload.
  base64 -D < "${ciphertext_b64}" > "${WORK_DIR}/${scenario}.enc.bin" 2>/dev/null \
    || base64 -d < "${ciphertext_b64}" > "${WORK_DIR}/${scenario}.enc.bin"

  aws s3 cp "${WORK_DIR}/${scenario}.enc.bin" "s3://${S3_BUCKET}/${s3_key}" >/dev/null
  echo "${s3_key}"
}

S1_KEY=$(encrypt_and_stage scenario1)
S2_KEY=$(encrypt_and_stage scenario2)
S3_KEY=$(encrypt_and_stage scenario3)
S4_KEY=$(encrypt_and_stage scenario4)

echo "smoke: staged 4 blobs under s3://${S3_BUCKET}/${S3_KEY_PREFIX}/"
echo

# ─── 5. For each scenario, fetch ciphertext from S3 + base64-encode ─────
#     (mirrors what the production gateway does at request time:
#      gateway reads the raw S3 blob, base64-encodes it, embeds in the
#      ciphertext_blob_base64 field of the /sign request body. Smoke
#      pulls the same blob via `aws s3 cp - -` for fidelity.)

fetch_b64() {
  local s3_key="$1"
  aws s3 cp "s3://${S3_BUCKET}/${s3_key}" - 2>/dev/null | base64 | tr -d '\n'
}

S1_B64=$(fetch_b64 "${S1_KEY}")
S2_B64=$(fetch_b64 "${S2_KEY}")
S3_B64=$(fetch_b64 "${S3_KEY}")
S4_B64=$(fetch_b64 "${S4_KEY}")

# ─── 6. Request templates ───────────────────────────────────────────────

# Common HMAC request shape — Binance order endpoint.
ORDER_REQ_TPL='{
  "action": "sign_binance",
  "method": "POST",
  "path": "/fapi/v1/order",
  "body": "",
  "timestamp_ms": 1714997000000,
  "query": "symbol=BTCUSDT&side=BUY&type=LIMIT&quantity=0.001&price=50000",
  "ciphertext_blob_base64": "BLOB_PLACEHOLDER"
}'

WITHDRAW_REQ_TPL='{
  "action": "sign_binance",
  "method": "POST",
  "path": "/sapi/v1/capital/withdraw/apply",
  "body": "",
  "timestamp_ms": 1714997000000,
  "query": "coin=USDT&amount=100&address=0xattacker",
  "ciphertext_blob_base64": "BLOB_PLACEHOLDER"
}'

post_sign() {
  local body="$1"
  curl -sS \
    --max-time 10 \
    -H "Content-Type: application/json" \
    -X POST \
    -d "${body}" \
    "${SIGNER_GATEWAY_URL}/sign"
}

run_scenario() {
  local name="$1"
  local req_tpl="$2"
  local b64="$3"
  local expected="$4"  # "success" or "policy_denied" or "bad_request"

  local body
  body=$(echo "${req_tpl}" | jq --arg b "${b64}" '.ciphertext_blob_base64 = $b')
  local resp
  resp=$(post_sign "${body}")
  local err
  err=$(echo "${resp}" | jq -r '.error // "null"')

  case "${expected}" in
    success)
      if [[ "${err}" == "null" ]]; then
        echo "smoke: [PASS] ${name} — success (no error)"
        return 0
      fi
      ;;
    *)
      if [[ "${err}" == "${expected}" ]]; then
        echo "smoke: [PASS] ${name} — expected ${expected}"
        return 0
      fi
      ;;
  esac

  echo "smoke: [FAIL] ${name} — expected ${expected}, got error='${err}'" >&2
  echo "       full response: ${resp}" >&2
  return 1
}

# ─── 7. Run scenarios ──────────────────────────────────────────────────

# We expect:
#   1. Legacy → success (Binance order request, key+secret unused real-side)
#   2. Permissive policy → success
#   3. Action-denial policy → policy_denied (request says sign_binance, policy
#      whitelists only sign_okx)
#   4. Path-denial policy → policy_denied for /sapi/v1/capital/withdraw

fail_count=0

run_scenario "1 legacy (no policy)"          "${ORDER_REQ_TPL}"    "${S1_B64}" success      || ((fail_count++))
run_scenario "2 permissive policy"           "${ORDER_REQ_TPL}"    "${S2_B64}" success      || ((fail_count++))
run_scenario "3 action-denial policy"        "${ORDER_REQ_TPL}"    "${S3_B64}" policy_denied || ((fail_count++))
run_scenario "4 withdraw-path denial policy" "${WITHDRAW_REQ_TPL}" "${S4_B64}" policy_denied || ((fail_count++))

# Scenario 5: same withdraw-path policy but request goes to /fapi/v1/order.
# Path is NOT in deny list → action allowed → success (regression guard
# that scenario 4 failure was about the path, not the policy generically).
run_scenario "5 withdraw policy + order path (regression)" "${ORDER_REQ_TPL}" "${S4_B64}" success || ((fail_count++))

echo
if (( fail_count == 0 )); then
  echo "smoke: ALL 5 SCENARIOS PASS — UPL v0 enforcement is live ✓"
  exit 0
else
  echo "smoke: ${fail_count} scenario(s) FAILED — UPL regression"
  exit 1
fi
