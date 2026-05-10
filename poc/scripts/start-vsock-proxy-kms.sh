#!/usr/bin/env bash
# Start the vsock-proxy bridge on the parent so the enclave can reach KMS.
#
# kmstool_enclave_cli defaults to --proxy-port 8000, so we use 8000 (NOT
# 8001 like the Phase 2 test script). KMS is in the default vsock-proxy
# allowlist (/etc/nitro_enclaves/vsock-proxy.yaml).

set -euo pipefail

REGION="${REGION:-us-east-1}"

# Kill any prior instance to avoid duplicates on reruns.
pkill -f "vsock-proxy 8000" 2>/dev/null || true
sleep 0.3

nohup vsock-proxy 8000 "kms.${REGION}.amazonaws.com" 443 \
    > /tmp/vsock-proxy-kms.log 2>&1 &
echo "vsock-proxy KMS pid=$!"

sleep 0.5
echo ""
echo "Active vsock-proxy processes:"
pgrep -af vsock-proxy
