#!/usr/bin/env bash
# Run the signer enclave in DEBUG mode with the console attached.
#
# In debug mode PCR0 is all zeros — KMS Decrypt will be denied, which is
# the correct behavior. Use this script for smoke-testing vsock plumbing
# (ping/sign with the hardcoded test secret), NOT for production.

set -euo pipefail
cd "$(dirname "$0")/.."

nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 1024 \
  --enclave-cid 16 \
  --eif-path signer.eif \
  --debug-mode \
  --attach-console
