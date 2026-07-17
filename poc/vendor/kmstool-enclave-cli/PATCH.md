# Vendored fork of `kmstool-enclave-cli`

## Why this exists

The enclave's KMS-Decrypt path shells out to `/kmstool_enclave_cli` (a binary
shipped by AWS in `aws-nitro-enclaves-sdk-c`). Stage 4 ZN-200 cutover requires
passing an `EncryptionContext={customer_id, venue_id}` map at decrypt time so
KMS rejects context-less or wrong-context decrypts. **Upstream's
`kmstool-enclave-cli` does not support `--encryption-context` at any tagged
release.** Verified against `v0.4.0` → `v0.4.5` and `origin/main` of
`aws/aws-nitro-enclaves-sdk-c` as of 2026-05-27.

The upstream feature branch `feature/pass-encryption-context-as-cli-args`
(commits `5c535bc`, `1f0349e`, `eb739b6` — Dec 2024) added context support
ONLY to `kmstool-instance` (parent-side) and `kmstool-enclave` (socket
daemon). The standalone `kmstool-enclave-cli` binary — the one we use — was
left untouched and remains so on the branch tip.

So we maintain a minimal fork of `bin/kmstool-enclave-cli/main.c` with the
patch ported, layered onto the upstream SDK tree at Docker build time. The
SDK lib itself (which provides `aws_kms_decrypt_blocking_with_context` since
`v0.4.2`) is built unchanged from upstream.

## Base version

Upstream `v0.4.5` (commit `cd61b6187c8b20867ba4368d1ae62c5790c0269a`,
released 2026-03-31). All non-`main.c` files in this directory (CMakeLists.txt,
README.md, build.sh, LICENSE.upstream, NOTICE.upstream) are identity copies
from that tag for reference and license preservation.

## Patch summary

Three additions to `main.c`:

1. **Hash-table storage for the context map** in `struct app_ctx`. Owns its
   key + value `aws_string`s; freed via `aws_hash_table_clean_up` in `main`.
   Initialized in `main` BEFORE `s_parse_options` so the parser can populate it.
2. **`--encryption-context KEY=VALUE` CLI flag**, repeatable. Added to:
   - `s_long_options[]` table with short code `'e'`
   - getopt short-options string (`"r:x:k:s:t:c:K:p:a:e:l:h"`)
   - `DECRYPT_CMD` arg-handler switch (other subcommands reject the flag with
     "Unknown option" since they have no context use case here)
   - decrypt usage text
3. **JSON serialization + SDK API switch.** In `decrypt()`, if the hash table
   is non-empty, build a JSON object via `s_encryption_context_to_json`, pass
   its `JSON_C_TO_STRING_PLAIN` rendering as an `aws_string` to the SDK's
   `aws_kms_decrypt_blocking_with_context()` (instead of the no-context
   `aws_kms_decrypt_blocking()`). Empty hash table → NULL context → SDK
   falls back to the legacy no-context path automatically.

The helper functions `s_parse_encryption_context_arg` and
`s_encryption_context_to_json` are direct ports of the equivalents added
upstream in `bin/kmstool-instance/main.c` by commit `5c535bc`. Their
behavior — silent skip on malformed pairs, no escape-sequence handling — is
preserved verbatim; callers (i.e. `kms_client.rs`) are expected to
pre-validate KEY/VALUE before invocation.

## Patch provenance (upstream commits modeled on)

- `89855e1` — Add API to send prepared Encrypt/Decrypt requests (SDK plumbing prereq, in v0.4.2+)
- `eb739b6` — Add API to add context to Encrypt/Decrypt requests, **#146** (introduces `aws_kms_decrypt_blocking_with_context`, in v0.4.2+)
- `5c535bc` / `1f0349e` — Extend kmstools to get Encryption Context from CLI (patches kmstool-instance + kmstool-enclave; **this fork extends the same pattern to kmstool-enclave-cli**)

## License

`main.c` is derivative of upstream AWS code licensed Apache-2.0 (see
`LICENSE.upstream` in this directory and `NOTICE.upstream`). Our patch
contributes the encryption-context wiring; copyright on the patch lines
remains with the original author (`Mark Kirichenko <mkirich@amazon.de>`,
visible in upstream commit metadata) since we're a mechanical port of the
upstream kmstool-instance approach. The composite file remains under
Apache-2.0.

## Re-applying on SDK bump

When `AWS_NITRO_SDK_C_REF` in `_signer/poc/enclave/Dockerfile` is bumped:

1. Pull upstream tree at the new ref locally.
2. Diff `bin/kmstool-enclave-cli/main.c` between old ref and new ref.
3. If `s_long_options[]` already includes `encryption-context` → upstream
   merged the patch; **remove this vendor dir entirely** and drop the
   Dockerfile COPY overlay.
4. Otherwise: re-apply the three additions above against the new upstream
   `main.c` (likely trivial — the patch sites are all in `s_parse_options` /
   `decrypt` / `main` which change rarely).
5. Re-test against a TEST blob via `/verify-blob` end-to-end before deploying.

## Why not just bump to the feature branch tip

`feature/pass-encryption-context-as-cli-args` is not merged into upstream
main and may never be. Tagged releases (v0.4.0 through v0.4.5) all lack the
flag in `kmstool-enclave-cli`. Pinning a feature-branch commit would leave
us depending on an unmerged AWS branch indefinitely; vendoring is
mechanically smaller and gives us release-tag-pinned SDK with a documented
delta.

## Pre-existing upstream leaks — fixed in this PR

Three review rounds shaped the final patch:
- **Gemini round-1** (Code Assist bot): 4 HIGH leaks via upstream's
  `fail_on` early-return in `decrypt`/`gen_datakey`/`gen_random`/`main`,
  plus 1 MED duplicate-key leak in `s_parse_encryption_context_arg`.
- **Round-2 (manual relay)** after Gemini hit daily quota 2026-05-28:
  CTO surfaced 3 remaining leaks + 1 UX gap (unhandled defaults in
  `genkey`/`genrandom` arg parsers). Initial scope per dispatch hard
  rule #6 deferred upstream-origin leaks to a follow-up PR, but CTO
  override 2026-05-28 elevated them inside this PR — "C in the enclave,
  leaks compound over EIF lifetime + can become side-channel attack
  surface".
- **Round-3 (CodeRabbit)**: caught 3 HIGH that Gemini missed when this
  worker's round-2 commit message overclaimed the fix. (1) `decrypt`
  base64-decode path retained 3 `fail_on` early-returns leaking
  client+credentials+ciphertext. (2) `encode_b64` leaked its freshly-
  init'd out-buffer on `aws_base64_encode` failure (low-probability
  trigger but residue could carry partial plaintext bytes). (3)
  Byte-buf locals (`ciphertext`, `ciphertext_decrypted`) were not
  zero-initialized — masked by the still-broken decrypt path; would
  have crashed inside the enclave the moment round-2's partial fix was
  completed. CodeRabbit also recommended `AWS_ZERO_STRUCT(*text_b64)`
  at `encode_b64` entry so callers can rely on safe unconditional
  cleanup of out-params; applied.

All 5 leak sites + the parser UX gap now share the `goto cleanup`
discipline this PR established. Caller-side defense-in-depth in `main`:
all subcommand out-buffers zero-init'd at declaration and cleaned up on
BOTH success and error paths (round-2 only cleaned on success).

### Leak 1 — `decrypt()` function (FIXED)
The `fail_on(rc != AWS_OP_SUCCESS, "...")` calls at the end of `decrypt`
return early without freeing `client`, `credentials`, `ciphertext`,
`ciphertext_decrypted`, or `plaintext_b64`. Trigger paths:
`aws_kms_decrypt_blocking_with_context` fails, or `encode_b64` fails.
Fix: refactor to `goto cleanup` pattern mirroring our `main()` fix.

### Leak 2 — `gen_datakey()` function (FIXED in this PR)
Same shape: `fail_on` short-circuits cleanup of `client`, `credentials`,
`plaintext`, `ciphertext`, `plaintext_b64`, `ciphertext_b64`. Trigger:
`aws_kms_generate_data_key_blocking` or `encode_b64` fails.

### Leak 3 — `gen_random()` function (FIXED in this PR)
Same shape: leaks `client`, `credentials`, `plaintext`, `plaintext_b64`
on `aws_kms_generate_random_blocking` or `encode_b64` failure.

### Leak 4 — `main()` (our patch interaction; FIXED in this PR)
Original upstream `main()` used `fail_on` to short-circuit on subcommand
failure. Our patch added `aws_hash_table_clean_up(&app_ctx.encryption_
context)` cleanup that the upstream `fail_on` would bypass. **Fixed in
this PR** by replacing the three `fail_on` sites in `main` with explicit
`if (rc != AWS_OP_SUCCESS) { ...; exit_rc = 1; goto cleanup_hash_table; }`
and adding two cleanup labels (`cleanup_hash_table:`, `cleanup_sdk:`).
This pattern is what leaks 1-3 would also need; not back-ported to
upstream functions here to keep scope tight.

### Operational impact

Leaks 1-3 only fire on error paths. Inside the enclave each kmstool
invocation is a short-lived, one-shot process — the kernel reclaims all
process memory on exit. The leaks are real (no Drop equivalent in C,
valgrind would flag them) but operationally bounded by process lifetime.
Defense-in-depth fix tracked separately.

### Leak 5 — unhandled defaults in `genkey` / `genrandom` arg parsers (FIXED in this PR)
Upstream `s_parse_options` had no `default:` arm for unknown options
inside the `GENKEY_CMD` / `GENRANDOM_CMD` blocks (only `DECRYPT_CMD` had
one). Unknown flags were silently ignored on those subcommands instead
of producing usage errors. Not a leak per se but a UX/safety
inconsistency; fixed for parity with `decrypt`.

### Upstream submission

Patch is mechanical port of upstream's own `feature/pass-encryption-
context-as-cli-args` pattern. Plus our goto-cleanup refactor of the
three leaky functions is a strict improvement. Worth submitting back to
AWS — they would likely accept a memory-safety cleanup even if they
don't immediately ship encryption-context for `kmstool-enclave-cli`.
