#!/usr/bin/env bash
# Run the signer enclave in PRODUCTION mode (no debug, no console).
#
# Real PCR0 measurements are produced — KMS will accept Decrypt calls
# bound to that PCR0 in the key policy. The enclave runs detached;
# `nitro-cli describe-enclaves` shows the assigned EnclaveID for later
# `nitro-cli terminate-enclave --enclave-id <id>`.

set -euo pipefail
cd "$(dirname "$0")/.."

nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 1024 \
  --enclave-cid 16 \
  --eif-path signer.eif

echo ""
echo "Running enclaves:"
nitro-cli describe-enclaves
