#!/usr/bin/env bash
# Rebuild the EIF from a CLEAN CLONE OF THE PUBLIC REPOSITORY and compare PCR0.
#
# Why this exists, and why `reproducibility-check.sh` is not it
# -------------------------------------------------------------
# `reproducibility-check.sh` copies THIS tree twice and builds both. That proves
# the build is DETERMINISTIC. It does not prove the thing we say in public.
#
# What we say — in CLIENT-ONBOARDING.md, in the landing copy, in every "verify
# the code, not the company" sentence — is that a stranger can clone
# `namixai/signer`, build, and land on the measurement we registered on-chain.
# Two builds of the PRIVATE tree agreeing says nothing about that: the private
# tree can drift from the public one by a whole subsystem and both local builds
# still agree perfectly with each other.
#
# This script closes that gap: clone the PUBLIC repo at a tag, build, compare to
# the measurement we are about to register (or already did).
#
# STRICTNESS IS PART OF THE MEASUREMENT. `SIGNER_REQUIRE_POLICY=1` yields a
# DIFFERENT PCR0 than the permissive build. Comparing a permissive rebuild
# against a strict registered measurement diverges for a reason that has nothing
# to do with reproducibility, and an operator reads that as a reproducibility
# failure. So this script sets it explicitly and prints what it set.
#
# Where it runs: the EC2 build host (nitro-cli + Docker). Not on a laptop.
#
# Usage:
#   ./reproducibility-from-public-clone.sh --tag <tag> --expect <96hex>
#   ./reproducibility-from-public-clone.sh --selftest
#
# Exit codes:
#   0 — the public clone reproduces the expected measurement
#   1 — DIVERGED (the interesting failure; a file-level diff is printed)
#   2 — setup error: missing tool, clone failed, tag absent, bad arguments

set -euo pipefail

# Same discipline as build-eif.sh: `tr`, `sort` and `diff` all have
# locale-dependent behaviour, and a gate whose answer depends on the operator's
# environment is not a gate.
export LC_ALL=C

REPO_URL="https://github.com/namixai/signer.git"
TAG="" EXPECT="" KEEP=0 SELFTEST=0

is_hex96() { [[ "$1" =~ ^[0-9a-f]{96}$ ]]; }
# `printf '%s'`, not `echo`: `echo` eats a leading `-n`/`-e` as a flag. A
# measurement will not start with a hyphen, but a helper that mangles some
# inputs silently is a bad helper regardless of today's callers.
norm()     { printf '%s' "$1" | tr -d '[:space:]' | tr 'A-Z' 'a-z'; }

# -- selftest: the script's own logic, no network, no build, no box ----------
selftest() {
  local fails=0 r
  chk() { if [ "$1" != "$2" ]; then echo "  BAD $3: got '$1', want '$2'"; fails=$((fails+1)); fi; }

  if is_hex96 "$(printf 'a%.0s' {1..96})"; then r=yes; else r=no; fi
  chk "$r" "yes" "96 hex accepted"
  if is_hex96 ""; then r=yes; else r=no; fi
  chk "$r" "no" "empty rejected - else two empties would compare equal"
  if is_hex96 "$(printf 'a%.0s' {1..95})"; then r=yes; else r=no; fi
  chk "$r" "no" "95 chars rejected"
  if is_hex96 "$(printf 'A%.0s' {1..96})"; then r=yes; else r=no; fi
  chk "$r" "no" "uppercase rejected before normalisation"
  if is_hex96 "$(printf 'z%.0s' {1..96})"; then r=yes; else r=no; fi
  chk "$r" "no" "non-hex rejected"

  chk "$(norm '  ABC  ')" "abc" "input normalised (whitespace and case)"
  chk "$(norm "$(printf 'A%.0s' {1..96})")" "$(printf 'a%.0s' {1..96})" "normalised uppercase is valid"

  if [ "$fails" -eq 0 ]; then
    echo "  OK selftest passed - measurement shape and normalisation behave as documented"
    return 0
  fi
  echo "SELFTEST FAILED, $fails checks"
  return 1
}

# `${2:?...}` is deliberately NOT used for the value-taking flags. It exits 1 on
# an empty value, and 1 is this script's code for DIVERGED — so `--expect ""`
# would have reported a reproducibility failure that never happened, which is
# the worst wrong answer a gate can give. Values are taken as-is and validated
# below, where every refusal exits 2.
need_value() {
  if [ "$#" -lt 2 ]; then
    echo "ERROR: $1 requires a value." >&2
    exit 2
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)      need_value "$@"; TAG="$2"; shift 2 ;;
    --expect)   need_value "$@"; EXPECT="$2"; shift 2 ;;
    --repo)     need_value "$@"; REPO_URL="$2"; shift 2 ;;
    --keep)     KEEP=1; shift ;;
    --selftest) SELFTEST=1; shift ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$SELFTEST" = 1 ]; then selftest; exit $?; fi

# A half-empty parameter set must refuse rather than run a mixture of lanes.
if [ -z "$TAG" ] || [ -z "$EXPECT" ] || [ -z "$REPO_URL" ]; then
  echo "ERROR: --tag and --expect are both required (or --selftest)." >&2
  echo "  Without --expect the script would print a measurement and exit 0," >&2
  echo "  so 'I compared nothing' would look exactly like 'it matched'." >&2
  exit 2
fi

EXPECT="$(norm "$EXPECT")"
if ! is_hex96 "$EXPECT"; then
  echo "ERROR: --expect must be exactly 96 hex characters (got ${#EXPECT})." >&2
  exit 2
fi

for tool in git jq nitro-cli docker; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: '$tool' not found. This gate runs on the build host, not a laptop." >&2
    exit 2
  fi
done

PRIVATE_POC="$(cd "$(dirname "$0")/.." && pwd -P)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/repro-public.XXXXXXXX")"
cleanup() {
  if [ "$KEEP" != 1 ]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

echo "-- clone of the PUBLIC repository ------------------------"
echo "  repo: $REPO_URL"
echo "  tag:  $TAG"
# 🔴 A TAG, not any ref. `git clone --branch` happily takes a branch name, and
# a branch head MOVES: "commit X at ref R reproduces measurement Y" would stop
# being true the next time someone pushes to R, while this script had already
# printed it as evidence. The artefact the gate pins has to be immutable
# (CodeRabbit, #731).
if ! git ls-remote --exit-code --tags "$REPO_URL" "refs/tags/$TAG" >/dev/null 2>&1; then
  echo "ERROR: '$TAG' is not a TAG in $REPO_URL." >&2
  echo "  A branch head moves, so it cannot be what the measurement is pinned to." >&2
  exit 2
fi
# The peeled commit, resolved BEFORE the clone. Compared with the clone's HEAD
# below: two independent reads of the same tag, so a mid-run retag cannot slip
# a different tree past the check that just passed.
WANT_SHA="$(git ls-remote "$REPO_URL" "refs/tags/$TAG^{}" | cut -f1)"
if [ -z "$WANT_SHA" ]; then
  WANT_SHA="$(git ls-remote "$REPO_URL" "refs/tags/$TAG" | cut -f1)"   # lightweight tag
fi

if ! git clone --quiet --depth 1 --branch "$TAG" "$REPO_URL" "$WORK/public"; then
  echo "ERROR: clone at tag '$TAG' failed. Is the tag pushed?" >&2
  exit 2
fi
SHA="$(git -C "$WORK/public" rev-parse HEAD)"
if [ "$SHA" != "$WANT_SHA" ]; then
  echo "ERROR: the clone is not at the tag: tag names $WANT_SHA, clone is at $SHA." >&2
  echo "  Refusing to build - the evidence would name a commit we did not build." >&2
  exit 2
fi
echo "  commit: $SHA"
echo "  This commit IS the claim: what gets built is what an outsider sees."

echo
echo "-- build -------------------------------------------------"
# Set explicitly rather than inherited: strictness is part of the measurement,
# and "forgot to export" would produce a divergence that has nothing to do with
# reproducibility while looking exactly like one.
export SIGNER_REQUIRE_POLICY=1
echo "  SIGNER_REQUIRE_POLICY=1 (strict/B1 - a DIFFERENT measurement than 0)"
if ! ( cd "$WORK/public/poc" && ./scripts/build-eif.sh ) > "$WORK/build.log" 2>&1; then
  echo "ERROR: build failed. Log: $WORK/build.log" >&2
  tail -20 "$WORK/build.log" >&2
  KEEP=1
  exit 2
fi

# 🔴 NOT `GOT="$(norm "$(nitro-cli … | jq …)")"`. Measured, not assumed: in a
# NESTED command substitution the inner failure is swallowed — `norm` runs on an
# empty argument, succeeds, and `set -e` never fires. This is true on bash 5 as
# well as old ones; it is nesting, not a version quirk. The consequence here is
# the worst possible one for a gate: a failed `nitro-cli` would leave GOT empty,
# the comparison would fail, and the script would report DIVERGED (exit 1) with
# a file diff — an emphatic wrong answer about reproducibility when the truth is
# "the tool did not run" (Gemini, #731).
if ! GOT_RAW="$(nitro-cli describe-eif --eif-path "$WORK/public/poc/signer.eif" | jq -r '.Measurements.PCR0')"; then
  echo "ERROR: nitro-cli/jq failed - could not read PCR0 from the built EIF." >&2
  KEEP=1
  exit 2
fi
GOT="$(norm "$GOT_RAW")"
if ! is_hex96 "$GOT"; then
  echo "ERROR: the built EIF did not yield a 96-hex measurement (got '${GOT}')." >&2
  KEEP=1
  exit 2
fi

echo
echo "-- comparison --------------------------------------------"
echo "  expected: $EXPECT"
echo "  built:    $GOT"

if [ "$GOT" = "$EXPECT" ]; then
  echo
  echo "REPRODUCIBLE. The public clone at tag $TAG yields the registered measurement."
  echo "  commit: $SHA"
  exit 0
fi

echo
echo "DIVERGED. Below is WHY, not just WHAT:"
echo
echo "-- how the public clone differs from the private tree -----"
# The one cause we can show locally. Build outputs and git metadata are excluded:
# they are not inputs to the measurement.
diff -qr \
  --exclude=target --exclude=.git --exclude=signer.eif --exclude=node_modules \
  "$WORK/public/poc" "$PRIVATE_POC" 2>&1 | head -40 || true
echo
echo "  If that list is empty the trees agree and the divergence is NOT in our"
echo "  sources: look at the build pins (policies/build-pins.txt), the nitro-cli"
echo "  version and the base image. Dependabot bumps move the measurement without"
echo "  touching a line of our code."
KEEP=1
echo
echo "  Work directory kept: $WORK"
exit 1
