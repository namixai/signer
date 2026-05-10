#!/usr/bin/env bash
# End-to-end smoke test for Phase 3 (KMS attestation working).
#
# 1. Pulls instance-role STS creds from IMDSv2.
# 2. Fetches the test ciphertext from S3.
# 3. Invokes signer-client which forwards to the enclave via vsock.
# 4. Enclave shells out to /kmstool_enclave_cli, decrypts via KMS,
#    HMAC-signs the canonical KuCoin string, returns base64 signature.
#
# Expected on success:
#   "signature_base64": "RRsbFVIZBYt8HOJflZNJYRRp67awKuFxZOuQy7CpahM="
#
# That signature == Phase 2 reference (same plaintext, same canonical
# string), proving the KMS path produced the SAME bytes that the
# hardcoded Phase 2 stub did.

set -euo pipefail
cd "$(dirname "$0")/.."

ROLE="${ROLE:-signer-poc-enclave-role}"
BUCKET="${BUCKET:-usenami-signer-poc-194173164271}"
S3_KEY="${S3_KEY:-secrets/test-kucoin.enc}"
LOCAL_BLOB="/tmp/test-kucoin.enc"
CID="${CID:-16}"
PORT="${PORT:-5000}"
EXPECTED="RRsbFVIZBYt8HOJflZNJYRRp67awKuFxZOuQy7CpahM="

# 1. IMDSv2 token + creds.
TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}")
export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_SESSION_TOKEN
AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .AccessKeyId)
AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .SecretAccessKey)
AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .Token)
echo "Got STS creds for role=$ROLE Code=$(echo "$CREDS" | jq -r .Code)"

# 2. Fetch ciphertext.
aws s3 cp "s3://${BUCKET}/${S3_KEY}" "$LOCAL_BLOB"
echo "Ciphertext size: $(wc -c < "$LOCAL_BLOB") bytes"

# 3. Run parent client.
echo ""
echo "=== Invoking enclave ==="
RESP_FILE=$(mktemp)
trap 'rm -f "$RESP_FILE"' EXIT

set +e
./target/release/signer-client --cid "$CID" --port "$PORT" sign \
    --blob "$LOCAL_BLOB" \
    --method POST --path /api/v1/orders \
    --body '{"clientOid":"test"}' --timestamp-ms 1714997000000 \
    --key-blob-s3-key "$S3_KEY" --key-id alias/signer-poc \
    > "$RESP_FILE" 2>&1
RC=$?
set -e

cat "$RESP_FILE"

# 4. Wipe creds from env immediately.
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

if [ $RC -ne 0 ]; then
    echo ""
    echo "FAIL: signer-client exited with rc=$RC"
    exit $RC
fi

# 5. Verify signature matches Phase 2 reference.
GOT=$(jq -r .signature_base64 < "$RESP_FILE")
if [ "$GOT" = "$EXPECTED" ]; then
    echo ""
    echo "PASS: signature matches Phase 2 reference ($EXPECTED)"
else
    echo ""
    echo "FAIL: got=$GOT expected=$EXPECTED"
    exit 1
fi
