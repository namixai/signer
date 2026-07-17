#!/usr/bin/env bash
# 4-source PCR0 drift check + KMS-policy structural audit.
#
# PCR0 drift compares the PCR0 documented in _signer/STATUS.md against three
# independent live sources, with NO SSH dependency (the gateway is now fronted
# by Cloudflare and direct EC2 :22 is closed from outside):
#
#   1. STATUS.md  — the **Deterministic PCR0:** field (doc source of truth)
#   2. KMS policy — the EnclaveAttestedDecryptOnly ImageSha384 condition (live)
#   3. Enclave    — proven via the gateway POST /verify-blob decrypt-proof:
#                   KMS grants kms:Decrypt ONLY when the *running* enclave's
#                   measured PCR0 matches the policy condition, so a successful
#                   attested decrypt is live cryptographic proof that
#                   running-enclave-PCR0 == KMS-PCR0 — stronger than reading
#                   `nitro-cli describe-enclaves` over SSH (which we can no
#                   longer reach).
#   4. On-chain   — UsenamiAttestationRegistry.isPCR0Active(EXPECTED) on Base
#                   (best-effort: skipped with a warning if `cast` is absent).
#
# Structural audit (CR043 follow-up) — verifies the live KMS policy never drifts
# back to the privilege-escalating shapes the AUD-006 hardening pass closed:
#
#   5. BuilderEncryptOnly Sid must grant ONLY ["kms:Encrypt","kms:DescribeKey"].
#      Any extra action (notably kms:PutKeyPolicy, kms:GenerateDataKey beyond
#      what kms.tf declares) means the live key drifted out of the
#      least-privilege shape kms.tf locks in.
#   6. AdminUserFullAccess (alex-admin) granting kms:PutKeyPolicy WITHOUT a
#      MultiFactorAuthPresent condition. Once CTO lands the post-collapse MFA
#      gate, this check goes quiet; until then it surfaces the residual gap
#      as a warning so a soak-watch cron can see when the gate finally lands.
#
# Exit codes:
#   0 — all checked sources agree (no drift)
#   1 — enclave cannot decrypt under the current policy (runtime drift / KMS
#       PCR0 mismatch / enclave down) — production signing is broken
#   2 — STATUS.md disagrees with the KMS policy (doc drift)
#   3 — setup/internal error (missing tool, AWS auth, parse failure)
#   4 — on-chain registry says the documented PCR0 is NOT active (registry drift)
#   5 — BuilderEncryptOnly Sid grants more than [Encrypt, DescribeKey] (CR043 regression)
#   6 — AdminUserFullAccess grants PutKeyPolicy without MFA condition (CR043 gap; warn-mode by default)
#
# Structural checks (5,6) run AFTER the PCR0 checks (0-4) but BEFORE the final
# OK summary, so a PCR0-clean run still surfaces structural drift cleanly. Set
# CHECK_DRIFT_STRUCTURAL_FATAL=0 to demote 5+6 to warnings (default 1, fail).
# Set CHECK_DRIFT_ADMIN_MFA_FATAL=1 to also fail on 6 (default 0: warn until CTO
# lands the post-collapse MFA gate).
# Set SKIP_ONCHAIN_CHECK=1 (also accepts true/yes, any case) for a box that is
# deliberately NOT registered on-chain (SIGNER_PCR0_ONCHAIN=0, e.g. the strict
# demo box): source #4 is skipped and the run verifies on the first three
# (STATUS == KMS == enclave-decrypt), so a not-on-chain PCR0 does NOT trip a
# false REGISTRY_DRIFT (exit 4). Any other value (including typos) runs the
# full 4-source check — fail-closed toward MORE checking.
#
# Intended for nightly cron + manual `make drift-check`. Output is plain text
# + a final SUMMARY line that's easy to grep from a Slack/Telegram alert.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATUS_MD="$(cd "$SCRIPT_DIR/../../.." && pwd)/_signer/STATUS.md"

# --- Config (env-overridable for testing) ---
KMS_KEY_ID="${KMS_KEY_ID:-d587cf69-c70a-4bba-be6e-a5270bc4c6db}"
AWS_PROFILE_DRIFT="${AWS_PROFILE_DRIFT:-signer-poc}"
AWS_REGION_DRIFT="${AWS_REGION_DRIFT:-us-east-1}"
GATEWAY_URL="${GATEWAY_URL:-https://signer-demo.usenami.io:8443}"
SIGNER_API_TOKEN="${SIGNER_API_TOKEN:-test-token-signer-poc-2026}"
PROBE_VENUE="${PROBE_VENUE:-kucoin}"
REGISTRY_ADDR="${REGISTRY_ADDR:-0x38b42eED740b0fDeb211bBDf773F2238cAEec240}"
BASE_RPC_URL="${BASE_RPC_URL:-https://mainnet.base.org}"
CHECK_DRIFT_STRUCTURAL_FATAL="${CHECK_DRIFT_STRUCTURAL_FATAL:-1}"
CHECK_DRIFT_ADMIN_MFA_FATAL="${CHECK_DRIFT_ADMIN_MFA_FATAL:-0}"

# --- Pre-flight: required tools ---
for cmd in curl python3 aws; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: required command not found: $cmd" >&2; exit 3; }
done

# --- 1. Expected PCR0 from the **Deterministic PCR0:** field in STATUS.md. ---
# Historical PCR0 values appear elsewhere in the file; pin to this single named
# field so updates flow through one place.
# `|| true` so a missing field yields empty (handled by the guard below) rather
# than tripping `set -o pipefail` + `set -e` and aborting before the guard runs.
EXPECTED=$(grep -E '^\*\*Deterministic PCR0:\*\*' "$STATUS_MD" | grep -oE '[0-9a-f]{96}' | head -1 || true)
[[ -z "$EXPECTED" ]] && { echo "ERROR: **Deterministic PCR0:** field not found in $STATUS_MD" >&2; exit 3; }

# --- 2. PCR0 locked into the live KMS policy (EnclaveAttestedDecryptOnly). ---
KMS_POLICY=$(aws kms get-key-policy \
  --key-id "$KMS_KEY_ID" --policy-name default \
  --region "$AWS_REGION_DRIFT" --profile "$AWS_PROFILE_DRIFT" \
  --query Policy --output text 2>/dev/null) \
  || { echo "ERROR: aws kms get-key-policy failed (profile $AWS_PROFILE_DRIFT)" >&2; exit 3; }

KMS_PCR0=$(printf '%s' "$KMS_POLICY" | python3 -c '
import json, sys
try:
    p = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for stmt in p.get("Statement", []):
    if stmt.get("Sid") == "EnclaveAttestedDecryptOnly":
        cond = stmt.get("Condition", {}).get("StringEqualsIgnoreCase", {})
        v = cond.get("kms:RecipientAttestation:ImageSha384", "")
        # Single-PCR0 = string; dual-allow during a soak = list. Print all.
        print(" ".join(v) if isinstance(v, list) else v)
        break
')
[[ -z "$KMS_PCR0" ]] && { echo "ERROR: EnclaveAttestedDecryptOnly ImageSha384 not found in KMS policy" >&2; exit 3; }

# --- 3. Enclave decrypt-proof via gateway POST /verify-blob. ---
PROBE_BODY=$(curl -sS -X POST "$GATEWAY_URL/verify-blob" \
  -H "Authorization: Bearer $SIGNER_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"venue_id":"%s"}' "$PROBE_VENUE")" \
  --max-time 20 2>/dev/null) || PROBE_BODY=""
PROBE_SHA=$(printf '%s' "$PROBE_BODY" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    if d.get("ok") and len(d.get("plaintext_sha256", "")) == 64:
        print(d["plaintext_sha256"])
except Exception:
    pass
')

# --- 4. On-chain registry (best-effort). ---
# SKIP_ONCHAIN_CHECK=1/true/yes: the box is deliberately NOT on-chain
# (SIGNER_PCR0_ONCHAIN=0, e.g. the strict demo box). isPCR0Active(EXPECTED)
# would return `false`, and the registry-drift verdict (c) below would flag a
# FALSE REGISTRY_DRIFT (exit 4). Skip source #4 and verify on the remaining
# three (STATUS.md == KMS == enclave-decrypt). ONCHAIN stays a "skipped" string
# so neither the `false` nor the `error` arm fires. Unrecognized values fall
# through to the full check (fail-closed). (Gemini #226 follow-up.)
case "$(printf '%s' "${SKIP_ONCHAIN_CHECK:-0}" | tr '[:upper:]' '[:lower:]')" in
  1|true|yes)
    ONCHAIN="skipped (SKIP_ONCHAIN_CHECK=${SKIP_ONCHAIN_CHECK} - box not on-chain; 3-source check)"
    ;;
  *)
    ONCHAIN="skipped (cast not installed)"
    if command -v cast >/dev/null 2>&1; then
      ONCHAIN=$(cast call "$REGISTRY_ADDR" "isPCR0Active(bytes)(bool)" "0x${EXPECTED}" \
        --rpc-url "$BASE_RPC_URL" 2>/dev/null) || ONCHAIN="error"
    fi
    ;;
esac

printf 'STATUS.md says:    %s\n' "$EXPECTED"
printf 'KMS policy:        %s\n' "$KMS_PCR0"
printf 'Enclave decrypt:   %s\n' "${PROBE_SHA:+OK (sha256=$PROBE_SHA, proves running PCR0 == KMS PCR0)}"
printf 'On-chain active:   %s\n' "$ONCHAIN"

# --- Verdict ---
# (a) Doc drift: STATUS.md must be among the PCR0(s) the KMS policy allows.
case " $KMS_PCR0 " in
  *" $EXPECTED "*) : ;;
  *) echo "SUMMARY: DOC_DRIFT — STATUS.md PCR0 ($EXPECTED) not in KMS policy ($KMS_PCR0)"; exit 2 ;;
esac

# (b) Runtime drift: the enclave must actually decrypt under the live policy.
if [[ -z "$PROBE_SHA" ]]; then
  echo "SUMMARY: DRIFT — enclave did NOT decrypt via /verify-blob (PCR0 mismatch, enclave down, or gateway unreachable). Production signing is broken."
  exit 1
fi

# (c) Registry drift: on-chain must mark the documented PCR0 active (if checked).
if [[ "$ONCHAIN" == "false" ]]; then
  echo "SUMMARY: REGISTRY_DRIFT — on-chain isPCR0Active($EXPECTED) = false"
  exit 4
fi
# `cast` present but the RPC call failed — the 4th source is UNVERIFIED. Do NOT
# fall through to an OK summary (that would be a false green); surface it as a
# setup/internal error so a transient Base RPC hiccup is re-run, not trusted.
if [[ "$ONCHAIN" == "error" ]]; then
  echo "SUMMARY: ERROR — on-chain check failed (cast/RPC error); first 3 sources clean but the registry source is unverified. Re-run; if persistent, fix BASE_RPC_URL." >&2
  exit 3
fi

# --- 5. BuilderEncryptOnly Sid: must grant ONLY [Encrypt, DescribeKey]. ---
# Parse via python (already imported $KMS_POLICY string). Print a JSON-like line
# the verdict block below greps on. We emit BOTH the actions set and any
# unexpected action explicitly, so the SUMMARY line can name what drifted.
BUILDER_VERDICT=$(printf '%s' "$KMS_POLICY" | python3 -c '
import json, sys
ALLOWED = {"kms:Encrypt", "kms:DescribeKey"}
try:
    p = json.load(sys.stdin)
except Exception:
    print("PARSE_ERROR"); sys.exit(0)
for stmt in p.get("Statement", []):
    if stmt.get("Sid") == "BuilderEncryptOnly":
        actions = stmt.get("Action", [])
        if isinstance(actions, str): actions = [actions]
        extra = sorted(set(actions) - ALLOWED)
        if extra:
            print("OVERREACH " + ",".join(extra))
        else:
            print("OK")
        break
else:
    print("MISSING")
')

# --- 6. AdminUserFullAccess: PutKeyPolicy without MultiFactorAuthPresent. ---
# Today (pre-collapse): alex-admin has kms:* with no MFA condition. The dispatch
# wants this surfaced. After CTO lands the MFA gate, the python below stops
# emitting NO_MFA and this whole check goes quiet.
ADMIN_VERDICT=$(printf '%s' "$KMS_POLICY" | python3 -c '
import json, sys
SENSITIVE = {"kms:*", "kms:PutKeyPolicy"}
def has_mfa(cond):
    if not isinstance(cond, dict): return False
    for op_block in cond.values():
        if not isinstance(op_block, dict): continue
        for k, v in op_block.items():
            if k.lower() == "aws:multifactorauthpresent":
                if str(v).lower() in ("true", "[true]"): return True
                if isinstance(v, list) and any(str(x).lower() == "true" for x in v): return True
    return False
try:
    p = json.load(sys.stdin)
except Exception:
    print("PARSE_ERROR"); sys.exit(0)
for stmt in p.get("Statement", []):
    if stmt.get("Sid") == "AdminUserFullAccess":
        actions = stmt.get("Action", [])
        if isinstance(actions, str): actions = [actions]
        sensitive_present = any(a in SENSITIVE for a in actions)
        if sensitive_present and not has_mfa(stmt.get("Condition")):
            print("NO_MFA " + ",".join(a for a in actions if a in SENSITIVE))
        else:
            print("OK")
        break
else:
    print("MISSING")
')

printf 'Builder Sid:       %s\n' "$BUILDER_VERDICT"
printf 'Admin Sid:         %s\n' "$ADMIN_VERDICT"

# (d) Builder overreach — exit 5 unless explicitly demoted.
case "$BUILDER_VERDICT" in
  "OK")        : ;;
  "MISSING")
    echo "SUMMARY: STRUCT_DRIFT — BuilderEncryptOnly Sid is missing from live KMS policy (kms.tf declares it; live diverged)" >&2
    [[ "$CHECK_DRIFT_STRUCTURAL_FATAL" == "1" ]] && exit 5
    ;;
  "OVERREACH "*)
    EXTRA="${BUILDER_VERDICT#OVERREACH }"
    echo "SUMMARY: STRUCT_DRIFT — BuilderEncryptOnly grants disallowed action(s): $EXTRA (CR043 regression risk)" >&2
    [[ "$CHECK_DRIFT_STRUCTURAL_FATAL" == "1" ]] && exit 5
    ;;
  "PARSE_ERROR")
    echo "ERROR: KMS policy unparseable for Builder Sid audit" >&2
    exit 3
    ;;
esac

# (e) Admin MFA gap — exit 6 only if explicitly opted in (default warn).
case "$ADMIN_VERDICT" in
  "OK")        : ;;
  "MISSING")
    echo "SUMMARY: STRUCT_DRIFT — AdminUserFullAccess Sid missing from live KMS policy" >&2
    [[ "$CHECK_DRIFT_STRUCTURAL_FATAL" == "1" ]] && exit 6
    ;;
  "NO_MFA "*)
    SENSITIVE="${ADMIN_VERDICT#NO_MFA }"
    echo "WARN: AdminUserFullAccess grants $SENSITIVE without aws:MultiFactorAuthPresent condition (CR043 gap, post-collapse CTO action)" >&2
    [[ "$CHECK_DRIFT_ADMIN_MFA_FATAL" == "1" ]] && exit 6
    ;;
  "PARSE_ERROR")
    echo "ERROR: KMS policy unparseable for Admin Sid audit" >&2
    exit 3
    ;;
esac

if [[ "$ONCHAIN" == "true" ]]; then
  echo "SUMMARY: OK — 4-source clean (STATUS == KMS == enclave-decrypt == on-chain); structural (Builder/Admin) clean"
else
  # Reachable when the on-chain source is skipped: `cast` not installed, or
  # SKIP_ONCHAIN_CHECK=1/true/yes for a deliberately-not-on-chain box
  # (SIGNER_PCR0_ONCHAIN=0).
  echo "SUMMARY: OK — 3-source clean (STATUS == KMS == enclave-decrypt); structural (Builder/Admin) clean; on-chain $ONCHAIN"
fi
