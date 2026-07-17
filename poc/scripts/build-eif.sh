#!/usr/bin/env bash
# Build the signer-enclave EIF (Enclave Image File) and print its PCR0.
#
# Reproducibility env:
#   SOURCE_DATE_EPOCH=1714900000  pins file mtimes inside the image.
#   LC_ALL=C                       removes locale-dependent sort orders.
#   umask 022                      avoids per-user permission drift.
#
# Run on the EC2 build host with nitro-cli + Docker installed.
#
# Strict-regime (B1) build:
#   SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh
# bakes SIGNER_REQUIRE_POLICY=1 into the EIF config (enclave-side flag; see
# enclave/Dockerfile). That yields a DISTINCT, PCR0-determining measurement vs
# the default permissive build (0) — attestation then proves policy enforcement.
# Default is 0 (permissive demo EIF). This script accepts ONLY an exact `0` or
# `1` and fails loudly otherwise — a build-time belt against the enclave parser
# being fail-permissive (it silently treats any non-truthy value, including
# whitespace-padded typos like `"1 "` or `"ture"`, as permissive). Better a loud
# build failure than a "strict" deploy that silently does not enforce.

set -euo pipefail
cd "$(dirname "$0")/.."

export SOURCE_DATE_EPOCH=1714900000
export LC_ALL=C
umask 022

# Enforcement posture baked into the EIF. Use `-` (unset-only default), NOT `:-`:
# only a genuinely-unset var falls back to permissive 0. An explicitly EMPTY
# value (e.g. CI expands a mis-configured var to "") must NOT coerce to 0 — it
# falls through to the 0|1 guard below and fails loudly (fail-closed).
SIGNER_REQUIRE_POLICY="${SIGNER_REQUIRE_POLICY-0}"

# Belt against the fail-permissive enclave parser: reject anything but an exact
# 0/1. A typo or stray space would otherwise bake a permissive EIF while the
# operator believes it is strict — a silent mainnet-floor failure.
case "${SIGNER_REQUIRE_POLICY}" in
  0|1) ;;
  *)
    echo "FATAL: SIGNER_REQUIRE_POLICY must be exactly '0' or '1' (got: '${SIGNER_REQUIRE_POLICY}')." >&2
    echo "       Strict/B1 EIF: SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh" >&2
    exit 1
    ;;
esac

# Build the deterministic builder image and copy the static binary out.
# --build-arg is the ONLY way to set the enclave-side flag: a Nitro Enclave takes
# its env solely from the baked image, never from the host at run time.
docker build --no-cache \
  --build-arg "SIGNER_REQUIRE_POLICY=${SIGNER_REQUIRE_POLICY}" \
  -t signer-enclave:latest -f enclave/Dockerfile .

# Defense-in-depth: prove the value actually baked into the image config (ENV),
# not merely that we passed an ARG — guards against Dockerfile drift decoupling
# the ARG from its ENV. (CTO-recommended baked-ENV assert.)
baked="$(docker inspect signer-enclave:latest \
  --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep '^SIGNER_REQUIRE_POLICY=' || true)"
if [ "${baked}" != "SIGNER_REQUIRE_POLICY=${SIGNER_REQUIRE_POLICY}" ]; then
  echo "FATAL: baked ENV mismatch — expected 'SIGNER_REQUIRE_POLICY=${SIGNER_REQUIRE_POLICY}', got '${baked}'." >&2
  exit 1
fi
echo "verified baked SIGNER_REQUIRE_POLICY=${SIGNER_REQUIRE_POLICY}"

# Wrap into an EIF.
nitro-cli build-enclave \
  --docker-uri signer-enclave:latest \
  --output-file signer.eif

# Print PCR0 — this is what the KMS key policy is bound to.
echo ""
echo "=== PCR0 ==="
nitro-cli describe-eif --eif-path signer.eif | jq -r '.Measurements.PCR0'
