# Verify Usenami Signer Yourself

Usenami Signer is a **keyless exchange-signing service**: your exchange API keys are
sealed inside an **AWS Nitro Enclave** at provisioning and never leave it. The
enclave signs venue requests under your policy; the plaintext keys are only ever
decryptable *inside an attested enclave measurement* — not by us, not by our
operators, not by AWS IAM/root.

The point of this page is that **you do not have to take that on faith.** You can
independently verify — with your own tools, trusting no Usenami code — that:

1. the live service is running the **exact enclave image** whose fingerprint (PCR0)
   we publish (via AWS Nitro's signed attestation), and
2. that image is what our **published source** builds to (reproducible build), and
3. that image is the **only** code AWS KMS will release a customer key to.

If all three line up, then the code you audited is the code that runs, and there is
no trusted Usenami component between you and your keys.

> **Trust base.** This verification trusts **AWS** (the Nitro hardware, the Nitro
> Attestation PKI, and KMS honoring its own key policy) and standard cryptography.
> It does **not** require trusting Usenami. See [What Signer does and does not
> protect](THREAT_MODEL.md).

---

## Part 1 — Verify the live enclave (`GET /attestation`)

`GET /attestation?nonce=<hex>` returns a **live, NSM-signed COSE attestation
document** from the AWS Nitro Secure Module. It is bound to your nonce
(anti-replay) and served `Cache-Control: no-store`. The gateway is **untrusted**
for this proof — you verify the signature yourself against the AWS Nitro root
certificate and read PCR0 out of the *signed* document.

> Do **not** trust the plaintext `pcr0_sha384` JSON field on its own — it is a
> convenience mirror. The signed COSE document is the source of truth.

### 1.1 What to check

1. **Fetch** a document with a fresh random `nonce`. Confirm the response is
   `Cache-Control: no-store`.
2. **Pin** the AWS Nitro Enclaves root certificate out-of-band (compare its SHA-256
   to a value you obtained independently — from AWS docs / a second channel).
3. **Validate the certificate path** (RFC 5280) — `certificate` (leaf) up through
   `cabundle` to the **pinned** AWS Nitro root, as-of the attestation timestamp. Use a
   vetted validator (below); don't hand-roll chain building.
4. **Verify the COSE `ES384` signature** with the leaf public key over the
   `Signature1` structure.
5. **Read PCR0** from the *verified* `pcrs[0]` and compare it to the value you expect
   — either your **own reproducible rebuild** (Part 2, trusts no one) or the value
   this document publishes below. (The demo is testnet and not on-chain; the on-chain
   registry is a production anchor — see [Where the expected PCR0 comes
   from](#where-the-expected-pcr0-comes-from).)
6. **Check the nonce** inside the verified document equals the one you sent (proves
   it is fresh, not a replay).

### 1.2 Copy-paste verifier (Python, trusts no Usenami code)

Dependency-light (`cbor2` + `cryptography` + `requests`) so you can run it in a
clean venv.

```bash
python3 -m venv v && . v/bin/activate && pip install cbor2 cryptography certvalidator requests

# AWS Nitro Enclaves root — download it, then PIN its hash. The value at the time of
# writing is:
#   6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0
# Confirm that hash OUT-OF-BAND (AWS documentation / a second channel) — do not trust
# the download, or this doc, blindly.
curl -sO https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
unzip -o AWS_NitroEnclaves_Root-G1.zip     # → root.pem
sha256sum root.pem 2>/dev/null || shasum -a 256 root.pem
```

This verifier was run against the live demo endpoint as written. Certificate-path
validation uses **`certvalidator`** (RFC 5280 path validation — issuer/subject
binding, basic constraints, path length, critical extensions, validity), anchored to
the **pinned** AWS Nitro root: we do **not** hand-roll chain building.

```python
#!/usr/bin/env python3
# Reference verifier — trusts no Usenami code. Security checks RAISE explicitly
# (never `assert`; `python -O` strips asserts). The cert path is validated by
# certvalidator, anchored to the PINNED root and as-of the attestation timestamp
# (the leaf certs are short-lived); COSE ES384 / PCR0 / nonce are checked explicitly.
import base64, hashlib, os, datetime, requests, cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError

def check(cond, msg):
    if not cond:
        raise SystemExit(f"ATTESTATION VERIFY FAILED: {msg}")

BASE          = os.environ.get("SIGNER_URL", "https://signer-demo.usenami.io:8443")
# The PCR0 we currently publish for the demo enclave (see "Where the expected PCR0
# comes from", below). To trust NO ONE, override this with your OWN rebuild's PCR0
# from Part 2 — that is the whole point.
EXPECTED_PCR0 = os.environ.get(
    "EXPECTED_PCR0",
    "ff53e1fe23498737e647a3baf0706133c4b157af024a519bf9d983a1f538d356e01f05792e15837728a7829c2908f6c6",
).lower()
ROOT_PEM      = open("root.pem", "rb").read()
# The AWS Nitro root hash you PINNED out-of-band (default = the value shown above).
ROOT_SHA256   = os.environ.get(
    "NITRO_ROOT_SHA256",
    "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0",
).lower()

# 0) Pin the AWS Nitro root before trusting anything.
check(hashlib.sha256(ROOT_PEM).hexdigest() == ROOT_SHA256, "Nitro root cert hash mismatch")

# 1) Fetch a FRESH doc bound to our nonce; confirm it is not cached.
nonce = os.urandom(16).hex()
r = requests.get(f"{BASE}/attestation", params={"nonce": nonce}, timeout=15)
r.raise_for_status()
check(r.headers.get("cache-control") == "no-store", "attestation must be no-store")

# 2) Parse COSE_Sign1 (may be CBOR tag 18) = [protected, unprotected, payload, sig].
cose = cbor2.loads(base64.b64decode(r.json()["attestation_doc_b64"]))
if isinstance(cose, cbor2.CBORTag):        # tag 18 = COSE_Sign1
    cose = cose.value
protected_bstr, _unprotected, payload_bstr, sig = cose
doc = cbor2.loads(payload_bstr)            # the AttestationDocument

# 3) FULL RFC 5280 path validation, anchored to the PINNED root, as-of the
#    attestation time. certvalidator builds + validates the path itself, so
#    cabundle ordering, DN chaining, CA/basic-constraints, path length, and
#    critical extensions are all handled — nothing hand-rolled.
moment = datetime.datetime.fromtimestamp(doc["timestamp"] / 1000, datetime.timezone.utc)
vc = ValidationContext(trust_roots=[ROOT_PEM], allow_fetching=False, moment=moment)
try:
    CertificateValidator(doc["certificate"], intermediate_certs=list(doc["cabundle"]),
                         validation_context=vc).validate_usage(set())
except (PathValidationError, PathBuildingError) as e:
    raise SystemExit(f"ATTESTATION VERIFY FAILED: cert path: {e}")

# 4) Enforce the COSE metadata BEFORE trusting the signature: the protected
#    header must advertise alg = ES384 (-35), the signature must be a 96-byte
#    raw r||s, and the leaf key must be on P-384 — otherwise a document could
#    claim a weaker/mismatched algorithm than we verify with.
phdr = cbor2.loads(protected_bstr) if protected_bstr else {}
check(isinstance(phdr, dict), "COSE protected header is not a map")
check(phdr.get(1) == -35, f"COSE alg is not ES384 (-35): {phdr.get(1)}")
check(len(sig) == 96, f"COSE signature is not 96-byte P-384 r||s: {len(sig)}")
leaf = x509.load_der_x509_certificate(doc["certificate"])
pub = leaf.public_key()
check(isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP384R1),
      "leaf certificate key is not P-384")

# Verify the COSE ES384 signature with the LEAF public key.
# Sig_structure = ["Signature1", protected, external_aad(=b""), payload], CBOR-encoded.
sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
r_int = int.from_bytes(sig[:48], "big"); s_int = int.from_bytes(sig[48:], "big")  # P-384 raw r||s
pub.verify(utils.encode_dss_signature(r_int, s_int), sig_structure,
           ec.ECDSA(hashes.SHA384()))   # raises on mismatch

# 5) Check PCR0 and the nonce INSIDE the verified document.
pcr0 = doc["pcrs"][0].hex()
check(pcr0 == EXPECTED_PCR0, f"PCR0 mismatch: doc={pcr0} expected={EXPECTED_PCR0}")
check(doc["nonce"] == bytes.fromhex(nonce), "nonce not bound — possible replay")

print(f"OK — path valid to pinned root, COSE signature valid, PCR0={pcr0} matches, nonce fresh.")
```

Run it — the published pins are baked in as defaults, so it works as-is against the
public demo:

```bash
python3 verify.py
# For real assurance, supply your OWN rebuilt PCR0 (Part 2) and independently-pinned root:
EXPECTED_PCR0=<your rebuild's PCR0> NITRO_ROOT_SHA256=<pinned> \
  SIGNER_URL=https://signer-demo.usenami.io:8443 python3 verify.py
```

Any tampering fails loudly: a forged document breaks the COSE signature; a document
from a different image fails the PCR0 check; a stale/cached document fails the nonce
check; a non-AWS chain fails the pinned-root path validation.

### Where the expected PCR0 comes from

The value baked in above — `ff53e1fe…f6c6` — is the PCR0 the **public demo** enclave
currently attests. It has two independent sources, in increasing order of trust:

- **This document** (at the commit you are reading) publishes it — a published
  reference, but only as trustworthy as this repo.
- **Your own reproducible rebuild** (Part 2) derives it from source with no input
  from us — this is the source that requires trusting *no one*. The demo runs the
  **strict / money-path** (`SIGNER_REQUIRE_POLICY=1`) build; rebuild with that flag
  to match this value. A permissive (`SIGNER_REQUIRE_POLICY=0`) image measures to a
  *different* PCR0.

> **The demo is testnet and is NOT registered on-chain** (its `/attestation` returns
> `registered_onchain: false`). On-chain PCR0 registration (the Base
> `UsenamiAttestationRegistry`) is a **production/mainnet** anchor, not a demo one —
> so for the demo, trust your rebuild, not a chain lookup. A PCR0 changes whenever any
> build pin changes; that is a re-attestation event, never a silent swap.

The deeper auditor-facing walkthrough (COSE structure, references) follows the
AWS Nitro attestation documentation and the enclave source (`poc/enclave/`).

---

## Part 2 — Rebuild the image from source (reproducible build → same PCR0)

Part 1 proves *what image is running*. This part proves *that image is what the
published source builds to*. The enclave image (EIF) is built **deterministically**,
so anyone can rebuild it from a given source revision and obtain the **same PCR0** —
no Usenami credentials or access to our box required.

### What makes it deterministic

Reproducibility is engineered, not incidental:

- **Toolchain pinned exact** (`rust-toolchain.toml`), builder base image pinned by
  **digest** (not a floating tag), fully static musl binary.
- **All external sources pinned by commit SHA / digest** — every `git clone` in the
  Dockerfile is a `git checkout <commit>`; recorded in `policies/build-pins.txt`.
- **`Cargo.lock` committed + `cargo build --locked`** — dependency versions cannot
  drift; vendored NSM deps built `--offline --locked`.
- **Timestamp / locale / umask pinned** (`SOURCE_DATE_EPOCH`, `LC_ALL=C`, `TZ=UTC`,
  `umask 022`) — removes mtime / locale-sort / permission drift.
- **The strict money-path flag is PCR0-determining** — the policy-enforcing image
  (`SIGNER_REQUIRE_POLICY=1`) measures to a *different* PCR0 than a permissive
  image, so attestation itself proves policy enforcement is compiled in.

### Do it yourself

Prerequisites: a Linux host with **Docker** and AWS **`nitro-cli`**
(`aws-nitro-enclaves-cli`). `nitro-cli` computes the EIF measurements **offline** —
no enclave needs to *run* and **no AWS account is needed** just to get PCR0.

```bash
git clone https://github.com/namixai/signer.git && cd signer/poc
git checkout <COMMIT_SHA>                       # the exact revision under review

# The strict/money-path image (baked SIGNER_REQUIRE_POLICY=1 → distinct PCR0):
SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh
# … docker --no-cache build … "verified baked SIGNER_REQUIRE_POLICY=1" …
# === PCR0 ===
# <96-hex>            ← compare to Part 1's /attestation PCR0 and the published value

# Confirm determinism yourself — two clean builds must yield an identical PCR0:
./scripts/reproducibility-check.sh
# Build A PCR0: <hex>
# Build B PCR0: <hex>
# REPRODUCIBLE        (exit 0; "DIVERGED" + exit 1 if they differ)
```

Build steps and determinism pins are in the repo README ([`poc/README.md`](../poc/README.md)) and `poc/scripts/build-eif.sh`.

### Honest status of this claim

- **The build is deterministic by construction** (the pins above), and we have
  observed an **identical PCR0 across independent clean rebuilds** during our own
  cutovers.
- We are **not** presenting an independent third party's end-to-end reproduction as
  a completed fact. The full loop — *your* rebuild's PCR0 == our live `/attestation`
  PCR0 == the on-chain record == the KMS allow-set — requires `nitro-cli` on a build
  host plus the current box state, and we walk through it live in the mainnet deploy
  window / on request. **We give you the procedure to prove it yourself rather than
  ask you to trust a claim.**
- If a pin is ever bumped (toolchain, base image, a vendored dep), PCR0 changes **by
  design** — that is a re-attestation event (KMS re-allow + on-chain re-register),
  not a silent change.

---

## Part 3 — Close the loop (the money-gate)

The *real* money-gate is AWS KMS: a customer key's wrapped data-key can only be
`Decrypt`-ed when the caller presents a Nitro attestation whose `ImageSha384` (PCR0)
is in the key policy's allow-set — and a non-attested principal (including our own
admin/root) is explicitly **denied**.

```text
  git checkout <SHA>  ──(Part 2)──▶  PCR0_rebuilt
                                         ║   all four must be equal
  /attestation COSE   ──(Part 1)──▶  PCR0_live  ═╬═  PCR0_onchain (Base attestation registry)
                                         ║
  aws kms get-key-policy  ──▶  PCR0 ∈ ImageSha384 allow-set  +  deny-without-attestation present
```

Reading a key **policy** needs only `kms:GetKeyPolicy` (read-only, grantable to a
reviewer — you never need `Decrypt`). The stronger property — a non-attested
principal is denied `Decrypt` — is demonstrable live: even our own admin identity is
`AccessDenied` on the money keys without a matching attestation.

**If `PCR0_rebuilt == PCR0_live == PCR0_onchain == PCR0_in_KMS_policy` and the
deny-without-attestation statement is present on every money-path key, then the
source you read is the only image that can ever decrypt your key — no trust in
Usenami required at any link.**

> **Which links apply to the demo vs. production.** The loop above is the
> **production/mainnet** property. The public **demo is testnet**: its enclave is
> not registered on-chain (`registered_onchain: false`, so the `PCR0_onchain` link
> does not apply to the demo), and the KMS money-gate is exercised against testnet
> keys. On the demo you can still verify `PCR0_rebuilt == PCR0_live` (Parts 1–2) —
> the on-chain + KMS-money-gate links close on the production deployment.

---

## Scope + honesty

- Usenami does **not** yet ship a caller-side verifier *library* — use the reference
  above (a thin verifier crate is a possible fast-follow).
- This page describes **verifiable, live** capabilities (the signed `/attestation`
  is deployed) and a **self-serve** reproducible-build procedure. Where a claim is
  not yet independently demonstrated end-to-end, it is marked as such above.
- Usenami Signer has **not** yet been audited by an external firm; an external
  engagement is planned. What this page gives you is the ability to verify the core
  trust property *without* an audit or our word.
- What Signer protects — and, honestly, what it does **not** — is in
  [`THREAT_MODEL.md`](THREAT_MODEL.md). To report a vulnerability, see
  [`SECURITY.md`](../SECURITY.md).
