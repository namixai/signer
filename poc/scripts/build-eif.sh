#!/usr/bin/env bash
# Build the signer-enclave EIF (Enclave Image File) and print its PCR0.
#
# Reproducibility env:
#   SOURCE_DATE_EPOCH=1714900000  pins file mtimes inside the image.
#   LC_ALL=C                       removes locale-dependent sort orders.
#   umask 022                      avoids per-user permission drift.
#
# Run on the EC2 build host with nitro-cli + Docker installed.

set -euo pipefail
cd "$(dirname "$0")/.."

export SOURCE_DATE_EPOCH=1714900000
export LC_ALL=C
umask 022

# Build the deterministic builder image and copy the static binary out.
docker build --no-cache -t signer-enclave:latest -f enclave/Dockerfile .

# Wrap into an EIF.
nitro-cli build-enclave \
  --docker-uri signer-enclave:latest \
  --output-file signer.eif

# Print PCR0 — this is what the KMS key policy is bound to.
echo ""
echo "=== PCR0 ==="
nitro-cli describe-eif --eif-path signer.eif | jq -r '.Measurements.PCR0'
