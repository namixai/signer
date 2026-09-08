# Reproducible EIF build: standalone third-party instructions

**Goal.** Independently rebuild the `signer-enclave` image from source and obtain
its **PCR0**, byte-for-byte, so you can confirm that the code you read is the code
that is running (see [VERIFY-SIGNER-YOURSELF.md](VERIFY-SIGNER-YOURSELF.md))
and the code AWS KMS will release keys to. You do **not** need any Usenami
credentials and no access to our box. The public source at a given commit is enough.

> **What we can and cannot say about our own runs.** For a long time we said "three
> identical PCR0 across independent clean builds" on the strength of
> `scripts/reproducibility-check.sh`. That script built our own tree twice. Building
> the same tree twice measures determinism, and determinism is not what this page is
> about. Reproducibility is two people, two clones, one number. We corrected that in
> September and gated a rotation on the stronger check: two clean anonymous clones of
> the public repository at a tag, built separately, gave one measurement.
>
> We are not asking you to take that on our word either. The point of the page is
> that you produce the number yourself.

---

## What makes the build deterministic

Reproducibility is engineered (Day-3 "Finding F/J" fixes), not incidental:

- **Toolchain pinned exact** — `rust-toolchain.toml` (`1.95.0`), and the builder
  base image `clux/muslrust` is pinned by **digest** (`@sha256:…`), not a floating
  tag. Fully static musl binary (no glibc drift). See `enclave/Dockerfile` header.
- **All external sources pinned by SHA** — every `git clone` in the Dockerfile
  (aws-lc, s2n-tls, aws-c-*, the AWS Nitro SDK) is `git checkout <commit>`; both
  base images are digest-pinned. Recorded in `policies/build-pins.txt`.
- **Vendored NSM deps** — `aws-nitro-enclaves-nsm-api` (the C `libnsm.so`) is
  vendored under `vendor/nsm-api/` and built `--offline --locked`, because
  upstream ships no `Cargo.lock` (that was the last non-determinism source, H5).
- **`Cargo.lock` committed + `--locked`** — the workspace build is
  `cargo build --locked`, so dependency versions cannot drift.
- **Timestamp / locale pinning** — `SOURCE_DATE_EPOCH=1714900000`, `LC_ALL=C`,
  `TZ=UTC`, `umask 022`, which removes the mtime, locale-sort and permission drift that
  would otherwise change file hashes inside the image.
- **Strict flag is PCR0-determining** — `SIGNER_REQUIRE_POLICY=1` is baked into
  the EIF as a build-arg→ENV; the strict image measures to a **different PCR0**
  than the permissive (`0`) image, so attestation itself proves policy
  enforcement is compiled in. `build-eif.sh` asserts the value actually baked
  into the image config (`docker inspect`), guarding Dockerfile drift.

---

## Prerequisites

- A Linux host with **Docker** and **AWS `nitro-cli`** installed (`nitro-cli`
  ships in the `aws-nitro-enclaves-cli` package; it computes the EIF measurements
  offline. No enclave has to *run* to get PCR0, and no AWS account is needed
  for the measurement). `jq` for reading the output.
- Network egress to fetch the pinned crates + the pinned git sources during the
  Docker build (the pins make WHAT is fetched deterministic).
- The public source tree at the commit you are verifying.

## Build + capture PCR0

```bash
git clone <usenami-platform repo> && cd <repo>/_signer/poc
git checkout <COMMIT_SHA>            # the exact revision under audit

# Strict/mainnet EIF (the money-path image). Baked SIGNER_REQUIRE_POLICY=1 →
# distinct, policy-enforcing PCR0. (Use 0 only to reproduce the permissive demo.)
SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh
# … docker --no-cache build … "verified baked SIGNER_REQUIRE_POLICY=1" …
# === PCR0 ===
# <96-hex>
```

`build-eif.sh`, which is short enough to read in full:
1. exports the determinism env, rejects any `SIGNER_REQUIRE_POLICY` other than
   exact `0`/`1` (fail-loud),
2. `docker build --no-cache --build-arg SIGNER_REQUIRE_POLICY=… -f enclave/Dockerfile`,
3. asserts the flag baked into the image ENV,
4. `nitro-cli build-enclave` → `signer.eif`,
5. prints `nitro-cli describe-eif … .Measurements.PCR0`.

## Confirm determinism yourself (two clean builds → identical PCR0)

```bash
./scripts/reproducibility-check.sh
# Build A PCR0: <hex>
# Build B PCR0: <hex>
# REPRODUCIBLE            # (exit 0; "DIVERGED" + exit 1 if they differ)
```

It runs two clean builds in throwaway directories (`rm -rf target/ signer.eif`
each) and compares PCR0. `describe-eif` also prints **PCR1/PCR2** (kernel/boot +
application) if you want to pin those too.

## Close the loop against the live system

Once you have `PCR0_rebuilt`, confirm it equals what is *running*, what is
*published*, and what is *money-authorized*:

```bash
# (a) LIVE: the running enclave's signed attestation (verify the COSE doc, then read pcrs[0]):
#     see ATTESTATION-VERIFICATION.md  →  PCR0_live
# (b) ON-CHAIN: the Base UsenamiAttestationRegistry record (contracts/)  →  PCR0_onchain
# (c) KMS money-gate — check EVERY money-path key (the venue key AND the registry
#     key), for BOTH the attested-decrypt allow-set AND the deny-without-attestation:
#     These alias names are the live ones (us-east-1). Do not "fix" them into the
#     alias/signer/prod/<venue>/v1 shape you may see in our Terraform: that stack was
#     never applied, so those keys do not exist and the command fails on a missing
#     alias rather than telling you anything about the policy.
for KEY in alias/signer-mainnet-binance alias/signer-mainnet-okx \
           alias/signer-mainnet-hyperliquid alias/signer-mainnet-registry ; do
  echo "== $KEY =="
  aws kms get-key-policy --key-id "$KEY" --policy-name default --query Policy --output text \
  | python3 -c 'import sys,json; p=json.load(sys.stdin)
allow=[s["Condition"]["StringEquals"]["kms:RecipientAttestation:ImageSha384"]
       for s in p["Statement"] if s.get("Effect")=="Allow" and "Attestation" in s.get("Sid","")]
deny =[s for s in p["Statement"] if s.get("Effect")=="Deny" and s.get("Principal")=="*"
       and set(s.get("Action",[]))>={"kms:Decrypt","kms:ReEncryptFrom","kms:ReEncryptTo"}]
print("  attested-decrypt PCR0 allow-set:", allow)
print("  deny-without-attestation present:", bool(deny))   # MUST be True on every money key'
done
```

**Acceptance:** on **every** money-path key —
`PCR0_rebuilt ∈ allow-set == PCR0_live == PCR0_onchain`, **and** the
`deny-without-attestation` statement is present. Only then is the claim exact:
the source you audited is the only image that can decrypt a customer key, and no
principal (incl. admin/root) can decrypt off-enclave.

> Note on the KMS check (c): reading the key *policy* needs `kms:GetKeyPolicy`,
> which we can grant an auditor read-only; you do **not** need Decrypt. The
> stronger property, that a non-attested principal is denied Decrypt, is
> demonstrable live: even our own admin identity is `AccessDenied` on the
> registry key without a matching attestation (the `Deny Principal:"*"` statement
> in `infra/kms.tf`).

---

## Caveats an auditor should note

- The determinism guarantee is for the **EIF/PCR0**, given the pinned inputs. If
  a pin is ever bumped (toolchain, base image, a vendored dep), PCR0 changes by
  design — that is a re-attestation event (KMS dual-allow + on-chain re-register),
  not a silent change. `policies/build-pins.txt` records the current pins.
- `nitro-cli` versions have historically been stable for PCR computation, but pin
  your `nitro-cli` version too if you want bit-for-bit repeatability across hosts.
- The permissive (`SIGNER_REQUIRE_POLICY=0`) image is a **different** PCR0 and is
  the demo build only; the mainnet/money-path image is always the strict `=1`
  measurement.
