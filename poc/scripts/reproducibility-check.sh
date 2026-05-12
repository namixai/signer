#!/usr/bin/env bash
# Run two clean builds in throwaway directories and compare PCR0.
#
# Goal: verify our build is byte-for-byte reproducible — same inputs,
# same PCR0 — which is what makes "KMS will only Decrypt for an enclave
# whose PCR0 matches policy" a meaningful guarantee.

set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -r . "$WORK/build-a"
cp -r . "$WORK/build-b"

(cd "$WORK/build-a" && rm -rf target/ signer.eif && ./scripts/build-eif.sh) \
    > /tmp/repro-a.log 2>&1
(cd "$WORK/build-b" && rm -rf target/ signer.eif && ./scripts/build-eif.sh) \
    > /tmp/repro-b.log 2>&1

PCR_A="$(nitro-cli describe-eif --eif-path "$WORK/build-a/signer.eif" \
    | jq -r '.Measurements.PCR0')"
PCR_B="$(nitro-cli describe-eif --eif-path "$WORK/build-b/signer.eif" \
    | jq -r '.Measurements.PCR0')"

echo "Build A PCR0: $PCR_A"
echo "Build B PCR0: $PCR_B"
if [ "$PCR_A" = "$PCR_B" ]; then
    echo "REPRODUCIBLE"
    exit 0
else
    echo "DIVERGED"
    exit 1
fi
