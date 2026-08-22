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
# Strict-regime (B1) build — THE mainnet rotation command:
#   SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh
# bakes SIGNER_REQUIRE_POLICY=1 into the EIF config (enclave-side flag; see
# enclave/Dockerfile). That yields a DISTINCT, PCR0-determining measurement vs
# the permissive build (0) — attestation then proves policy enforcement.
#
# The flag still DEFAULTS to 0, but since 2026-08-08 a permissive build no longer
# passes the rotation gate below: it exits non-zero unless the operator disables
# the gate on purpose (`SIGNER_ROTATION_GATE=0`). The default is left permissive
# rather than flipped because flipping it would silently change what every
# existing demo/hackathon invocation produces; the gate makes the mistake loud
# without moving anyone's floor.
#
# This script accepts ONLY an exact `0` or
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

# ── ROTATION GATE (gate-0) ───────────────────────────────────────────────────
# The baked-ENV assert further down proves the baked value equals the REQUESTED
# one. That is a drift check between ARG and ENV, worth having — but it is NOT a
# strictness check, and it was being read as one. Built with the default, it
# prints "verified baked SIGNER_REQUIRE_POLICY=0" and exits 0: a green gate on a
# permissive image. A check that passes on the thing it exists to catch is not a
# check (2026-08-08, found while writing the rotation runbook).
#
# So this gate compares against ONE, not against what we asked for. It is ON by
# default because this script's product is the mainnet measurement; a deliberate
# permissive build (demo/hackathon lane) must say so out loud:
#
#   SIGNER_ROTATION_GATE=0 ./scripts/build-eif.sh
#
# WHAT THE BAKED FLAG ACTUALLY GOVERNS, since the earlier wording contradicted
# itself (CodeRabbit, #411): `SIGNER_REQUIRE_POLICY` is the strict-regime switch
# for EVERY money venue — binance, okx, bybit, kucoin, asterdex, hyperliquid
# testnet. The one exception runs the other way: `hyperliquid_main` carries an
# UNCONDITIONAL floor since ROT-1, so it stays strict even in a permissive image.
# Everything else on that list goes permissive with the flag, which is precisely
# why a permissive image must not be able to pass gate-0 quietly.
#
# The gate runs BEFORE `docker build` (CodeRabbit): it reads two env vars and
# nothing from the image, so a mistaken permissive invocation should not pay for
# a full uncached build before it is told. The baked-ENV assert stays after the
# build — it has to inspect the image.
SIGNER_ROTATION_GATE="${SIGNER_ROTATION_GATE-1}"
case "${SIGNER_ROTATION_GATE}" in
  0|1) ;;
  *)
    echo "FATAL: SIGNER_ROTATION_GATE must be exactly '0' or '1' (got: '${SIGNER_ROTATION_GATE}')." >&2
    exit 1
    ;;
esac
if [ "${SIGNER_ROTATION_GATE}" = "1" ]; then
  if [ "${SIGNER_REQUIRE_POLICY}" != "1" ]; then
    echo "FATAL: rotation gate — this image is PERMISSIVE (SIGNER_REQUIRE_POLICY=${SIGNER_REQUIRE_POLICY})." >&2
    echo "       A mainnet rotation image must bake exactly 1. Build it as:" >&2
    echo "         SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh" >&2
    echo "       For a deliberate permissive build, disable the gate explicitly:" >&2
    echo "         SIGNER_ROTATION_GATE=0 ./scripts/build-eif.sh" >&2
    exit 1
  fi
  # Print the VALUE, not the word "verified" — the gate's output is quoted into
  # rotation reports, and "verified" alone is what made a permissive build look
  # like a passed gate.
  echo "rotation gate PASSED: baked SIGNER_REQUIRE_POLICY=1 (strict)"
else
  # Report the MODE THAT WILL BE BAKED, not an assumption about it.
  # SIGNER_ROTATION_GATE=0 disables the pre-build assertion only; it does NOT
  # force SIGNER_REQUIRE_POLICY=0. Saying "permissive build" unconditionally
  # mislabels `SIGNER_ROTATION_GATE=0 SIGNER_REQUIRE_POLICY=1`, which bakes a
  # STRICT image — and this line gets quoted into rotation reports, so the
  # mislabel would outlive the shell that printed it.
  if [ "${SIGNER_REQUIRE_POLICY:-0}" = "1" ]; then
    echo "rotation gate DISABLED (SIGNER_ROTATION_GATE=0) — building with SIGNER_REQUIRE_POLICY=1 (strict), gate assertion SKIPPED" >&2
  else
    echo "rotation gate DISABLED (SIGNER_ROTATION_GATE=0) — building with SIGNER_REQUIRE_POLICY=${SIGNER_REQUIRE_POLICY:-0} (permissive), NOT for mainnet rotation" >&2
  fi
fi

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

# Reclaim the Docker build cache. Each --no-cache build leaves its layers behind
# (~30 GB on the build host); on 2026-08-20 the SECOND of two consecutive clean
# builds died with "No space left on device". If we ask outsiders to rebuild on
# demand, we must be able to rebuild on demand ourselves. Runs AFTER the PCR0 is
# printed, so it can never influence the measurement; opt out with
# SIGNER_BUILD_KEEP_CACHE=1 (e.g. to inspect intermediate layers).
if [ "${SIGNER_BUILD_KEEP_CACHE:-0}" != "1" ]; then
  echo "pruning docker build cache + dangling images (SIGNER_BUILD_KEEP_CACHE=1 to keep)" >&2
  docker builder prune -f >/dev/null 2>&1 || true
  docker image prune -f >/dev/null 2>&1 || true
fi
