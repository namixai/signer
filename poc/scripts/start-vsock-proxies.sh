#!/usr/bin/env bash
# Start vsock-proxy bridges on the parent so the enclave can reach
# KMS (8001) and S3 (8002). Phase 3 will use both; Phase 2 keeps them
# running so the enclave can be smoke-tested in the same shape.
#
# vsock-proxy ships with the aws-nitro-enclaves-cli package and reads
# /etc/nitro_enclaves/vsock-proxy.yaml as an allowlist of upstream
# (host, port) pairs. KMS is allowlisted by default; S3 is not, so
# we patch it in once and back up the original.

set -euo pipefail

REGION="${REGION:-us-east-1}"

# vsock-proxy 8001 -> KMS (in default allowlist)
nohup vsock-proxy 8001 "kms.${REGION}.amazonaws.com" 443 \
    > /tmp/vsock-proxy-kms.log 2>&1 &
echo "vsock-proxy KMS pid=$!"

# vsock-proxy 8002 -> S3. Add to allowlist once.
ALLOWLIST=/etc/nitro_enclaves/vsock-proxy.yaml
if ! grep -q "s3.${REGION}.amazonaws.com" "$ALLOWLIST"; then
    sudo cp "$ALLOWLIST" "${ALLOWLIST}.bak.$(date +%Y%m%dT%H%M%S)"
    sudo bash -c "echo '- {address: s3.${REGION}.amazonaws.com, port: 443}' >> '$ALLOWLIST'"
fi

nohup vsock-proxy 8002 "s3.${REGION}.amazonaws.com" 443 \
    > /tmp/vsock-proxy-s3.log 2>&1 &
echo "vsock-proxy S3  pid=$!"

sleep 1
echo ""
echo "Active vsock-proxy processes:"
pgrep -af vsock-proxy
