#!/usr/bin/env bash
# ZN-200 migration: re-wrap each production blob with KMS EncryptionContext.
#
# PR-B PROVISIONING CONTRACT (sealed-identity GCM AAD, design §5.4 Option A):
# the enclave binds an in-blob sealed identity as REAL AES-GCM AAD when it
# decrypts an envelope blob (`registry::ResolvedIdentity::sealed_aad`). For a
# blob to decrypt under the resolved tenant, the ENVELOPE wrap MUST seal the
# inner AES-GCM ciphertext with the byte-identical AAD:
#     customer_id=<uuid>\nvenue_id=<venue>\nkey_version=1
# (no trailing newline; \n = 0x0A; key_version pinned to 1 = enclave KEY_VERSION).
# This script currently produces KMS-encrypt (legacy) blobs; the
# envelope-wrap-with-AAD tooling is the Phase-2 provisioning step that must use
# this exact AAD. KMS EncryptionContext {customer_id, venue_id} is the first
# identity check; the AAD is the second (tamper-evident) one.
#
# Background: blobs currently in /var/lib/signer/blobs/*.enc were encrypted
# under the live us-east-1 KMS key WITHOUT an EncryptionContext. ZN-200
# closure requires re-encrypting each blob with context = {customer_id,
# venue_id}, then activating SIGNER_REQUIRE_CONTEXT=1 so the enclave
# hard-rejects context-less requests.
#
# Operating modes (PR #48 Stage 3 dispatch convention):
#
#   SIGNER_REWRAP_DRY_RUN=1 ./rewrap-with-context.sh [venues...]
#     - Default mode (safe).
#     - For each venue: pull the live ciphertext from EC2, kms:Decrypt with
#       NO context (works against pre-ZN-200 blobs), write plaintext to
#       /tmp/signer-rewrap/<venue>.json on the OPERATOR workstation only,
#       then kms:Encrypt with EncryptionContext={customer_id, venue_id} to
#       verify the re-wrap actually succeeds end-to-end. Ciphertext is
#       discarded — NOTHING is written to /var/lib/signer/blobs/ on EC2.
#     - Both KMS calls are real AWS API calls; this is verification, not
#       simulation. The point is to catch IAM / context-condition mistakes
#       BEFORE the destructive apply path.
#
#   ./rewrap-with-context.sh --apply [venues...]
#     - Destructive. Same as dry-run PLUS:
#       - new ciphertext written to /var/lib/signer/blobs/<venue>.enc
#       - matching .ctx.json written for the gateway
#       - pre-migration original preserved as .enc.v1 (rollback)
#       - gateway restarted
#     - Operator MUST have already staged plaintexts at
#       /tmp/signer-rewrap/<venue>.json during a prior dry-run run.
#
# If [venues...] is empty, defaults to the full Phase 0 set:
#   asterdex binance bybit hyperliquid_main kucoin okx
#
# Pre-conditions:
#   - Pilot customer UUID (single tenant in Phase 0; multi-customer later)
#   - AWS creds with kms:Decrypt + kms:Encrypt on the live signer key
#   - SSH key + EC2 reachable
#
# Rollback (after --apply): rename <venue>.enc.v1 → <venue>.enc and
# `sudo systemctl restart signer-gateway` on EC2.

set -euo pipefail

# ── Mode: dry-run vs apply ────────────────────────────────────────────
# Env var takes precedence over the legacy --apply flag, per the PR #48
# Stage 3 dispatch convention. SIGNER_REWRAP_DRY_RUN=0 + --apply both
# enable destructive mode; anything else stays dry-run.
APPLY=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --*)     echo "ERROR: unknown flag $arg" >&2; exit 1 ;;
    *)       ARGS+=("$arg") ;;
  esac
done
if [[ "${SIGNER_REWRAP_DRY_RUN:-1}" == "0" ]]; then
  APPLY=1
fi
if [[ "${SIGNER_REWRAP_DRY_RUN:-}" == "1" ]]; then
  APPLY=0
fi
DRY_RUN=$((1 - APPLY))

# ── Venue selection ───────────────────────────────────────────────────
DEFAULT_VENUES=(asterdex binance bybit hyperliquid_main kucoin okx)
if [[ ${#ARGS[@]} -gt 0 ]]; then
  VENUES=("${ARGS[@]}")
else
  VENUES=("${DEFAULT_VENUES[@]}")
fi

EC2_USER="${EC2_USER:-ec2-user}"
EC2_HOST="${EC2_HOST:-54.224.183.120}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/signer-poc-key.pem}"
PROFILE="${AWS_PROFILE:-signer-poc}"
REGION="${AWS_REGION:-us-east-1}"
KMS_KEY_ID="${KMS_KEY_ID:-d587cf69-c70a-4bba-be6e-a5270bc4c6db}"
DEFAULT_CUSTOMER_ID="00000000-0000-0000-0000-000000000001"  # legacy single-tenant namespace
# Multi-tenant (PR-A): wrap one or more customers. `CUSTOMER_IDS` is a
# space/comma-separated list; `CUSTOMER_ID` (singular) is the back-compat
# default for one pilot. The DEFAULT_CUSTOMER_ID writes flat
# `/var/lib/signer/blobs/{venue}.enc` (live single-tenant layout, unchanged);
# every OTHER customer writes the per-customer subdir
# `/var/lib/signer/blobs/{customer}/{venue}.enc` that the gateway's Pass-3
# loader reads (state.rs `blob_key`).
CUSTOMER_IDS="${CUSTOMER_IDS:-${CUSTOMER_ID:-$DEFAULT_CUSTOMER_ID}}"
CUSTOMER_IDS="${CUSTOMER_IDS//,/ }"  # accept comma OR space separators
# Validate each id BEFORE it is used as a remote path component / KMS context
# value (review #6). A customer id is a UUID v4 (or the all-zero default);
# reject anything with path separators, `..`, or out-of-charset bytes so a
# crafted id can never escape `/var/lib/signer/blobs/{id}/` or the staging dir.
for _cid in $CUSTOMER_IDS; do
  if ! [[ "$_cid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    echo "ERROR: customer id '$_cid' is not a UUID — refusing to use it as a path/context component" >&2
    exit 1
  fi
done
# Plaintext SOURCE for non-default customers (each brings their OWN keys):
# operator stages `$SOURCE_PLAINTEXT_DIR/{customer}/{venue}.json` before --apply.
# The default customer needs no source — its plaintext is migrated by
# decrypting the existing live flat blob (Step 3).
SOURCE_PLAINTEXT_DIR="${SOURCE_PLAINTEXT_DIR:-}"
PLAINTEXT_DIR="${PLAINTEXT_DIR:-/tmp/signer-rewrap}"

log() { printf '\n=== %s ===\n' "$*" >&2; }

# CR052: SSH/scp host-key handling. The old `StrictHostKeyChecking=no` accepts ANY
# host key silently → a MITM during the rewrap can intercept the plaintext
# API keys this script handles. `accept-new` is TOFU: it pins the host key on
# first contact and HARD-FAILS on any later mismatch, defeating a persistent
# MITM. Operators who have already connected to the EC2 host (its key is in
# ~/.ssh/known_hosts) get full strict verification. Override with
# SIGNER_SSH_STRICT=yes for environments that pre-provision known_hosts.
SSH_HK="${SIGNER_SSH_STRICT:+yes}"; SSH_HK="${SSH_HK:-accept-new}"

# CR051: securely shred plaintext key material. `shred` (GNU/Linux) overwrites
# then unlinks; macOS has no `shred`, so fall back to `rm -P` (BSD overwrite)
# and finally plain removal. Best-effort on copy-on-write FS, but guarantees
# the file does not linger after the run.
secure_shred() {
  local f
  for f in "$@"; do
    [[ -e "$f" ]] || continue
    if command -v shred >/dev/null 2>&1; then
      shred -u "$f" 2>/dev/null && continue
    fi
    rm -P "$f" 2>/dev/null || rm -f "$f" 2>/dev/null || true
  done
}

# CR051: on ANY exit (success, error, or interrupt) shred staged plaintext
# and drop the temp dir, so decrypted API keys never linger on disk. The
# decrypt step re-derives plaintext on every run, so nothing downstream
# depends on it persisting between invocations.
TMPDIRS=()   # one mktemp dir per customer iteration; shredded on exit
cleanup() {
  if [[ -n "${PLAINTEXT_DIR:-}" && -d "$PLAINTEXT_DIR" ]]; then
    # Shred every staged plaintext under the (now per-customer) tree.
    while IFS= read -r -d '' f; do secure_shred "$f"; done \
      < <(find "$PLAINTEXT_DIR" -type f -name '*.json' -print0 2>/dev/null)
    rm -rf "$PLAINTEXT_DIR" 2>/dev/null || true
  fi
  for d in "${TMPDIRS[@]:-}"; do
    [[ -n "$d" && -d "$d" ]] && rm -rf "$d" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

if [[ $DRY_RUN -eq 1 ]]; then
  log "DRY-RUN MODE — real KMS decrypt/encrypt verification, NO blob mutation"
  echo "Venues:    ${VENUES[*]}"
  echo "Customers: ${CUSTOMER_IDS}"
  echo "Plaintext staging dir (operator-local): $PLAINTEXT_DIR"
else
  log "APPLY MODE — destructive: blobs will be re-wrapped + gateway restarted"
  echo "Venues:    ${VENUES[*]}"
  echo "Customers: ${CUSTOMER_IDS}"
fi

# ── Step 1: prerequisite checks ───────────────────────────────────────
log "Step 1/5: Verify pre-conditions"
mkdir -p "$PLAINTEXT_DIR"
chmod 700 "$PLAINTEXT_DIR"
ssh -i "$SSH_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=$SSH_HK \
  "$EC2_USER@$EC2_HOST" 'true' >/dev/null \
  || { echo "ERROR: SSH to $EC2_HOST failed" >&2; exit 2; }
echo "operator plaintext dir ready: $PLAINTEXT_DIR (mode 700)"
echo "EC2 reachable: $EC2_USER@$EC2_HOST"

# ── Steps 2-5 per customer ────────────────────────────────────────────
# Looped over CUSTOMER_IDS. The DEFAULT_CUSTOMER_ID migrates the EXISTING
# live flat blobs (decrypt-no-context → re-wrap-with-context, flat output,
# unchanged from the single-tenant script). Every OTHER customer brings their
# OWN keys, pre-staged by the operator at
# `$SOURCE_PLAINTEXT_DIR/{customer}/{venue}.json`, and is written to the
# per-customer subdir `/var/lib/signer/blobs/{customer}/{venue}.enc`.
rewrap_customer() {
  local CID="$1"
  local is_default=0
  [[ "$CID" == "$DEFAULT_CUSTOMER_ID" ]] && is_default=1
  local remote_sub=""
  [[ $is_default -eq 0 ]] && remote_sub="$CID"
  local pt_dir="$PLAINTEXT_DIR/$CID"
  mkdir -p "$pt_dir"; chmod 700 "$pt_dir"
  local TMPDIR; TMPDIR=$(mktemp -d -t signer-rewrap-XXXXXX); chmod 700 "$TMPDIR"
  TMPDIRS+=("$TMPDIR")  # cleanup() shreds plaintext + drops every TMPDIR on exit

  log "Customer $CID (layout: $([[ $is_default -eq 1 ]] && echo flat || echo "subdir $CID/"))"

  # Step 2/3 — obtain per-venue plaintext into $pt_dir.
  for v in "${VENUES[@]}"; do
    if [[ $is_default -eq 1 ]]; then
      # Migrate: pull the live flat blob and decrypt (pre-context = no ctx).
      scp -i "$SSH_KEY" -o StrictHostKeyChecking=$SSH_HK -q \
        "$EC2_USER@$EC2_HOST:/var/lib/signer/blobs/${v}.enc" "$TMPDIR/${v}.enc"
      local SIZE; SIZE=$(wc -c < "$TMPDIR/${v}.enc")
      [[ $SIZE -lt 100 ]] && { echo "ERROR: $v.enc only $SIZE bytes — missing/empty" >&2; exit 2; }
      local PLAINTEXT_B64
      if ! PLAINTEXT_B64=$(aws kms decrypt --ciphertext-blob "fileb://$TMPDIR/${v}.enc" \
            --profile "$PROFILE" --region "$REGION" --output text --query Plaintext \
            2>"$TMPDIR/${v}.decrypt.err"); then
        echo "ERROR: kms:Decrypt failed for $v:" >&2; cat "$TMPDIR/${v}.decrypt.err" >&2; exit 3
      fi
      echo "$PLAINTEXT_B64" | base64 -d > "$pt_dir/${v}.json"; chmod 600 "$pt_dir/${v}.json"
    else
      # New customer: their own keys, pre-staged by the operator.
      [[ -n "$SOURCE_PLAINTEXT_DIR" ]] || { echo "ERROR: customer $CID needs SOURCE_PLAINTEXT_DIR/{$CID}/{venue}.json (operator-staged keys)" >&2; exit 3; }
      local src="$SOURCE_PLAINTEXT_DIR/$CID/${v}.json"
      [[ -f "$src" ]] || { echo "ERROR: missing staged plaintext for $CID/$v at $src" >&2; exit 3; }
      cp "$src" "$pt_dir/${v}.json"; chmod 600 "$pt_dir/${v}.json"
    fi
    local PT_SIZE; PT_SIZE=$(wc -c < "$pt_dir/${v}.json")
    [[ $PT_SIZE -lt 10 ]] && { echo "ERROR: $CID/$v plaintext suspiciously small ($PT_SIZE bytes)" >&2; exit 3; }
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$pt_dir/${v}.json" 2>/dev/null \
      || echo "WARN: $CID/$v plaintext is not valid JSON ($PT_SIZE bytes) — check before --apply" >&2
    echo "  $CID/$v: plaintext $PT_SIZE bytes staged"
  done

  # Step 4 — re-encrypt each plaintext under context {customer_id=CID, venue_id=v}
  # and round-trip-verify the binding holds.
  for v in "${VENUES[@]}"; do
    local CTX="customer_id=${CID},venue_id=${v}"
    local CT_B64
    if ! CT_B64=$(aws kms encrypt --key-id "$KMS_KEY_ID" \
          --plaintext "fileb://$pt_dir/${v}.json" --encryption-context "$CTX" \
          --profile "$PROFILE" --region "$REGION" --output text --query CiphertextBlob \
          2>"$TMPDIR/${v}.encrypt.err"); then
      echo "ERROR: kms:Encrypt failed for $CID/$v (context=$CTX):" >&2; cat "$TMPDIR/${v}.encrypt.err" >&2; exit 4
    fi
    echo "$CT_B64" | base64 -d > "$TMPDIR/${v}.enc.v2"
    local CT_SIZE; CT_SIZE=$(wc -c < "$TMPDIR/${v}.enc.v2")
    [[ $CT_SIZE -lt 100 ]] && { echo "ERROR: $CID/$v re-encrypt ciphertext only $CT_SIZE bytes" >&2; exit 4; }
    if ! aws kms decrypt --ciphertext-blob "fileb://$TMPDIR/${v}.enc.v2" --encryption-context "$CTX" \
          --profile "$PROFILE" --region "$REGION" --output text --query Plaintext \
          >/dev/null 2>"$TMPDIR/${v}.rtrip.err"; then
      echo "ERROR: round-trip decrypt failed for $CID/$v:" >&2; cat "$TMPDIR/${v}.rtrip.err" >&2; exit 4
    fi
    echo "  $CID/$v: re-encrypt OK ($CT_SIZE bytes) + round-trip with context=$CTX OK"
    cat > "$TMPDIR/${v}.ctx.json" <<JSON
{
  "customer_id": "${CID}",
  "venue_id": "${v}"
}
JSON
  done

  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  dry-run OK for customer $CID (${#VENUES[@]} venues)"
    return 0
  fi

  # Step 5 — apply: stage to EC2, atomic same-FS swap into the (flat | subdir)
  # destination, preserve pre-migration originals as .enc.v1. Gateway restart
  # is deferred to AFTER all customers (one restart for the whole batch).
  local stage="/tmp/signer-rewrap-staging-${CID}"
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=$SSH_HK "$EC2_USER@$EC2_HOST" \
    "mkdir -p ${stage@Q} && chmod 700 ${stage@Q}"
  for v in "${VENUES[@]}"; do
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=$SSH_HK -q \
      "$TMPDIR/${v}.enc.v2" "$TMPDIR/${v}.ctx.json" \
      "$EC2_USER@$EC2_HOST:${stage}/"
  done
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=$SSH_HK "$EC2_USER@$EC2_HOST" \
    "bash -s -- ${remote_sub@Q} ${stage@Q} ${VENUES[*]@Q}" <<'EOSSH'
set -euo pipefail
SUB="$1"; STAGE="$2"; shift 2
DEST="/var/lib/signer/blobs${SUB:+/$SUB}"
sudo mkdir -p "$DEST"
cd "$DEST"
for v in "$@"; do
  if [[ -f "${v}.enc" ]] && [[ ! -f "${v}.enc.v1" ]]; then
    sudo cp "${v}.enc" "${v}.enc.v1"
  fi
  sudo cp "$STAGE/${v}.enc.v2"  "./.${v}.enc.tmp"
  sudo cp "$STAGE/${v}.ctx.json" "./.${v}.ctx.json.tmp"
  sudo mv "./.${v}.enc.tmp"      "${v}.enc"
  sudo mv "./.${v}.ctx.json.tmp" "${v}.ctx.json"
  sudo rm -f "$STAGE/${v}.enc.v2" "$STAGE/${v}.ctx.json"
  sudo chown signer:signer "${v}.enc" "${v}.ctx.json"
  sudo chmod 640 "${v}.enc" "${v}.ctx.json"
done
echo "swap done for ${SUB:-default}. backups at .enc.v1"
EOSSH
}

# ── Run the per-customer rewrap for each configured customer ──
for CID in $CUSTOMER_IDS; do
  rewrap_customer "$CID"
done

if [[ $DRY_RUN -eq 1 ]]; then
  log "DRY-RUN COMPLETE — verified ${#VENUES[@]} venue(s) × $(set -- $CUSTOMER_IDS; echo $#) customer(s)"
  echo "What the dry-run proved (per customer):"
  echo "  • kms:Decrypt (default = live blobs, no context) / staged-plaintext read succeeds"
  echo "  • kms:Encrypt with EncryptionContext{customer_id, venue_id} succeeds"
  echo "  • round-trip decrypt with the same context succeeds (binding works)"
  echo "  • plaintexts validated in-run (mode 600) and SHREDDED on exit — none left on disk"
  echo ""
  echo "NOTHING on EC2 was modified."
  exit 0
fi

# One gateway restart for the whole batch.
# CR095 (AUD-011): poll /healthz with backoff instead of a fixed `sleep 3` so the
# log grep runs only after the gateway is actually up (gateway-only restart, so
# the cap is short). Same readiness-retry discipline as deploy.sh Step 8.
# #220 CodeRabbit follow-up: retries exhausting must fail loud (exit 4, same as
# deploy.sh Step 8), not silently fall through to the journalctl grep.
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=$SSH_HK "$EC2_USER@$EC2_HOST" \
  'sudo systemctl restart signer-gateway; \
   for i in $(seq 1 15); do \
     curl -sS -m 5 http://127.0.0.1:9443/healthz 2>/dev/null | grep -q "\"status\":\"ok\"" && break; \
     sleep 2; \
   done; \
   curl -sS -m 5 http://127.0.0.1:9443/healthz 2>/dev/null | grep -q "\"status\":\"ok\"" || { echo "ERROR: healthz not ready after retries" >&2; exit 4; }; \
   sudo journalctl -u signer-gateway --since "40 sec ago" --no-pager | grep -E "has_context|blob loaded|per-customer" | head -40'

log "REWRAP COMPLETE — customers: ${CUSTOMER_IDS}"
echo "Next step: add SIGNER_REQUIRE_CONTEXT=1 to enclave systemd override,"
echo "  reload + restart enclave, then run zn200-protocol-mismatch.sh"
echo "  (expect PASS — KMS refuses no-context decrypt against the new blobs)."
