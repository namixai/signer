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
   — your **own reproducible rebuild** (Part 2, trusts no one), the value this
   document publishes below, or the **on-chain registry** (Part 1.3 — since the
   2026-08-10 rotation the demo measurement is registered too). See [Where the
   expected PCR0 comes from](#where-the-expected-pcr0-comes-from).
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
# Linux ships sha256sum, macOS ships shasum. Picked by AVAILABILITY, not by failure:
# `sha256sum … || shasum …` would swallow a real error (a missing root.pem) and then
# report the SECOND tool's failure instead of the first one's cause — the wrong trade
# in a document whose whole purpose is not to mislead you.
if command -v sha256sum >/dev/null 2>&1; then sha256sum root.pem; else shasum -a 256 root.pem; fi
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
import base64, hashlib, os, re, datetime, requests, cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError

def check(cond, msg):
    if not cond:
        raise SystemExit(f"ATTESTATION VERIFY FAILED: {msg}")

# 🔴 THERE IS NO DEFAULT HERE ON PURPOSE. This script will not run until you say
# which measurement you expect.
#
# It used to ship a baked-in value, and that value went stale twice — most recently on
# 2026-08-24, when rotation #4 moved production off it while this file kept offering it
# as the answer. A verifier that quietly substitutes last season's number is worse than
# one that refuses: it hands you a mismatch that looks exactly like a dishonest
# service, or a match that proves nothing.
#
# Where to get the value you should expect, best source first:
#   1. Build the enclave yourself from the commit you intend to trust (README,
#      "Reproducible build"). This is the only source that owes nothing to us
#      telling you the truth.
#   2. Ask the on-chain registry which measurement is active and who owns it, then
#      hold this endpoint to that. This file does not print the production value:
#      read it from /attestation of the endpoint you are verifying.
#   3. The measurement table in the README: commit -> flag -> value, and when each
#      was deployed.
#
# Whichever you pick, the enclaves are SEPARATE and their measurements differ. The
# demo box and the mainnet box have not run the same image since 2026-08-24. Check
# WHICH one you queried before concluding anything.
#
# `.strip()` before `.lower()`: a value pasted from a terminal or a CI variable
# routinely carries a trailing newline, and an invisible character is the worst
# possible reason for a verification to fail.
EXPECTED_PCR0 = os.environ.get("EXPECTED_PCR0", "").strip().lower()
if not EXPECTED_PCR0:
    raise SystemExit(
        "EXPECTED_PCR0 is not set, and this script will not guess one for you.\n"
        "Set it to the measurement you expect this endpoint to be running - see the\n"
        "comment above for where to source it - then run again:\n"
        "  EXPECTED_PCR0=<96 hex chars> SIGNER_URL=<endpoint> python3 verify.py"
    )
# Shape first, before any network call or certificate work: a typo should cost
# you a line of output, not a full path validation against the Nitro root.
if not re.fullmatch(r"[0-9a-f]{96}", EXPECTED_PCR0):
    raise SystemExit(
        f"EXPECTED_PCR0 must be 96 hex characters (SHA-384); got {len(EXPECTED_PCR0)}."
    )

# The endpoint to query, and the root pin to hold it to. These are read from the
# SAME environment variable names the bash block below offers — an earlier
# revision of this page used different names internally (and did not define them
# at all), so the documented `SIGNER_URL=…` had no effect and the script died on
# a NameError before its first check. Overriding BASE means overriding
# EXPECTED_PCR0 too — see the note above.
BASE = os.environ.get("SIGNER_URL", "https://signer-demo.usenami.io:8443").strip().rstrip("/")

# The pin you confirmed OUT-OF-BAND in the bash block above. Keeping it here as a
# default (rather than only in a variable) is what makes this script runnable as
# published; supply NITRO_ROOT_SHA256 to hold it to a value YOU sourced.
ROOT_SHA256 = os.environ.get(
    "NITRO_ROOT_SHA256",
    "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0",
).strip().lower()

# root.pem is the file the bash block above downloaded and hashed. Read it from
# disk rather than embedding it: a certificate pasted into a document is exactly
# the kind of thing that silently goes stale.
ROOT_PEM_PATH = os.environ.get("NITRO_ROOT_PEM", "root.pem")
try:
    with open(ROOT_PEM_PATH, "rb") as fh:
        ROOT_PEM = fh.read()
except OSError as e:                       # not just FileNotFoundError: a
    raise SystemExit(                      # permission/EISDIR error must not
        f"ATTESTATION VERIFY FAILED: cannot read {ROOT_PEM_PATH} ({e}) — run "  # traceback either
        f"the download step above (curl … AWS_NitroEnclaves_Root-G1.zip && "
        f"unzip) in this directory first, or point NITRO_ROOT_PEM at the file."
    )

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

Run it. There is no baked-in expectation any more, so you have to say what you
expect — that refusal is the point, not an inconvenience:

```bash
# Strongest form, and the only one that owes us nothing: hold the endpoint to the
# measurement YOUR OWN rebuild produced (Part 2).
EXPECTED_PCR0="$(cat pcr0-from-my-build.txt)" \
  SIGNER_URL=https://signer-demo.usenami.io:8443 python3 verify.py

# Weaker but still useful: hold it to a measurement you decided to trust from
# somewhere other than this file — the registry, the README table, an auditor.
# Whatever you pick, you are the one picking it. That is the whole change.
EXPECTED_PCR0="$MEASUREMENT_YOU_TRUST" SIGNER_URL="$ENDPOINT" python3 verify.py

# For real assurance, pin the root yourself instead of trusting this file too:
#   NITRO_ROOT_SHA256=<the value you sourced> ...
```

Deliberately absent: a copy-paste line with a measurement already filled in. One
lived here for months, went stale twice, and the second time it told readers a
healthy production service was untrustworthy.

Any tampering fails loudly: a forged document breaks the COSE signature; a document
from a different image fails the PCR0 check; a stale/cached document fails the nonce
check; a non-AWS chain fails the pinned-root path validation.

### Where the expected PCR0 comes from

Nothing is baked in above, and that is the point. Earlier revisions of this file
carried a default, which is how it drifted: between 2026-08-10 and 2026-08-24 the two
lanes did run the same image, the file said so, and then rotation #4 moved production
onto `103ccd79…` while the default kept naming the old value.

The lanes diverged on 2026-08-24. This file no longer averages over that, and it no
longer prints for the demo box a number that a rotation can retire behind its back — it
names the source instead:

| endpoint | measurement it attests | on-chain |
|---|---|---|
| mainnet / production | read it from that endpoint's `/attestation`; the dated record of what measured to what is the README table | `(true, 0x21538eBF…)` — the owner is the check, `true` alone is not |
| `signer-demo.usenami.io:8443` | read it from that endpoint's `/attestation` | `true` while the box is on the registered image; `false` inside a rotation window (as on 2026-08-26) |

So pick your expectation deliberately. Build the commit you intend to trust and use
what your own build produced; or take the active measurement from the registry and
hold the production endpoint to it. What you should not do is let a document choose
for you.

The demo measurement has two independent sources, in increasing order of trust:

- **This document** (at the commit you are reading) publishes it — a published
  reference, but only as trustworthy as this repo.
- **Your own reproducible rebuild** (Part 2) derives it from source with no input
  from us — this is the source that requires trusting *no one*. The demo runs the
  **strict / money-path** (`SIGNER_REQUIRE_POLICY=1`) build; rebuild with that flag
  to match this value. A permissive (`SIGNER_REQUIRE_POLICY=0`) image measures to a
  *different* PCR0.

- **The on-chain registry** (Base `UsenamiAttestationRegistry`) — a public,
  timestamped record whose **event log** cannot be rewritten after the fact.
  (The *current* active-owner lookup is mutable state, and registration is
  permissionless — so check the owner address, not just the boolean; Part 1.3
  spells this out.) 🔴 Do not expect a `registered_onchain` field — it was removed on 2026-09-03,
  because a boolean this gateway computes about a public oracle is our word,
  not evidence. Ask the registry yourself and compare the **owner**.
  And know what you are asking: the registry keeps ONE active measurement per
  owner, so registering the production measurement deprecates the demo's in the
  very same transaction. While the two boxes run different images, only one of
  them can answer `true` — a `false` on the other is the design, not a warning. (Earlier revisions of this page said the demo was not
  on-chain and told you a chain lookup did not apply to it. That was true when
  written and is false now — corrected rather than quietly amended.)

> A PCR0 changes whenever any build pin changes; that is a re-attestation event
> (KMS re-allow + on-chain re-register), never a silent swap.

The deeper auditor-facing walkthrough (COSE structure, references) follows the
AWS Nitro attestation documentation and the enclave source (`poc/enclave/`).

### 1.3 Check the measurement against the on-chain registry

The `UsenamiAttestationRegistry` is live on **Base mainnet** at
`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`
([source](../poc/contracts/src/UsenamiAttestationRegistry.sol)). It answers one
question: *is this measurement currently registered as active, and by whom.*

```solidity
function isPCR0Active(bytes calldata pcr0) external view returns (bool active, address owner);
```

🔴 **The parameter is the raw 48 BYTES, not the 96-character hex string.** The
contract enforces `pcr0.length == 48` and reverts `InvalidPCR0Length()` otherwise,
so passing the hex text (96 bytes) reverts — which reads like a broken contract and
is really an encoding mistake. It returns **two** values; decode both.

```bash
# Read-only eth_call — no key, no wallet, nothing is sent or created.
# 0x05d85549 = selector of isPCR0Active(bytes); then offset=32, length=48, the
# 48 raw bytes, right-padded to a 32-byte boundary.
# Same rule as the script above: nothing baked in. Read the measurement from the
# endpoint you are actually asking about, so the question stays "is what this box
# runs registered, and to whom".
# 🔴 `pcr0_sha384` is the CONVENIENCE MIRROR, not the signed document. A gateway
# that wanted to fool you would put a registered measurement in this field while
# the COSE document carries a different one — and the registry would answer
# `true` about a measurement nothing is running. This shortcut is only worth
# anything AFTER verify.py has validated the signed document; treat a `true`
# here without that step as unproven, not as proof.
# Fail closed on the fetch too: an error page or a missing field would otherwise
# walk an empty value straight into the calldata.
SIGNER_URL=${SIGNER_URL:-https://signer-demo.usenami.io:8443}
# Bind the answer to THIS request. Without a nonce an endpoint may hand you a
# document it prepared earlier — including one measured on an image it no longer
# runs. The nonce does not make the mirror field trustworthy; it removes replay
# from the list of things that can be wrong before verify.py has run at all.
NONCE=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
ATT=$(curl -sf "$SIGNER_URL/attestation?nonce=$NONCE") \
  || { echo "no attestation from $SIGNER_URL" >&2; exit 1; }
[ "$(printf '%s' "$ATT" | jq -r '.nonce // empty')" = "$NONCE" ] \
  || { echo "nonce not echoed — document not bound to this request" >&2; exit 1; }
PCR0=$(printf '%s' "$ATT" | jq -r '.pcr0_sha384 // empty')
# POSIX, and case-normalised first: an uppercase hash is the same hash, and
# `[[ =~ ]]` is a bashism that dies in dash — which is /bin/sh on Debian.
# `shopt -s nocasematch` also quietly makes both `[[ =~ ]]` and a bare `case`
# accept uppercase, so normalise rather than rely on the match being strict.
# LC_ALL=C: `tr` ranges and `case` bracket expressions collate per locale, so a
# range like a-f is not guaranteed to mean the six letters everywhere. Not
# reproduced on this machine — every locale available here behaved correctly —
# but the guard costs one line and removes the whole class.
PCR0=$(printf '%s' "$PCR0" | LC_ALL=C tr 'A-F' 'a-f')
case "$PCR0" in
  *[!0123456789abcdef]*) echo "no usable pcr0_sha384 from $SIGNER_URL" >&2; exit 1 ;;
esac
[ ${#PCR0} -eq 96 ] || { echo "no usable pcr0_sha384 from $SIGNER_URL" >&2; exit 1; }
curl -s https://mainnet.base.org -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"eth_call","params":[{
    "to":"0x38b42eED740b0fDeb211bBDf773F2238cAEec240",
    "data":"0x05d85549'"$(printf '%064x' 32)$(printf '%064x' 48)${PCR0}$(printf '%032x' 0)"'"
  },"latest"]}'
# → {"result":"0x0000…0001 0000…21538ebf6598e5866ba496a954de8e39097bfb59"}
#      first word = active (1 = true), second = owner address
```

With `cast` (Foundry), which does the encoding for you:

```bash
cast call 0x38b42eED740b0fDeb211bBDf773F2238cAEec240 \
  "isPCR0Active(bytes)(bool,address)" "0x${PCR0}" --rpc-url https://mainnet.base.org
```

🔴 **Read `active` for what it is: current, mutable state — and check the `owner`.**
`registerPCR0` is permissionless: **any** address may register an unclaimed
measurement and become its owner, and an owner may register a new measurement,
which auto-deprecates their previous one. So `active = true` on its own says
"someone has this measurement registered right now", not "Usenami vouches for it".
Two things make it meaningful:

1. **The `owner` must be the canonical Usenami address**
   `0x21538eBF6598e5866BA496A954dE8E39097bFB59` (published in the repository
   [README](../README.md) and [DEMO.md](../DEMO.md)) — compare it yourself; a
   measurement registered by any other address proves nothing about us.
2. **The append-only part is the event log, not this getter.** Registrations and
   deprecations emit `PCR0Registered` / `PCR0Deprecated`; those logs and their
   blocks cannot be rewritten after the fact, while the mapping this call reads
   can change with the next registration. For an anchor in time, read the event:

```bash
# The registration of the current measurement: Base block 49836503,
# tx 0x8841d01ce96d04a4c0e7d2afdf7377d3aac8382bac12a7c108d6c052052658cf
# topic0 = keccak256("PCR0Registered(address,bytes32,bytes,bytes32,string)")
# topic2 = keccak256(<the 48 raw PCR0 bytes>)
curl -s https://mainnet.base.org -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{
    "address":"0x38b42eED740b0fDeb211bBDf773F2238cAEec240",
    "topics":[
      "0x40074e27ec69a03db88f79da96749aa2d4c9477ae4339f6abf42bf0056d2e267",
      null,
      "0x9b974b9779f0b2b7bbd99892762eee82913d8d17b4b27af15278605b74b1f27e"],
    "fromBlock":"0x2f87173","toBlock":"0x2f8723b"}]}'
# topics[1] is the owner, left-padded — expect …21538ebf6598e5866ba496a954de8e39097bfb59
```

⚠️ Public Base RPCs cap `eth_getLogs` at a **10 000-block range** — `fromBlock:"0x0"`
is rejected outright, and so is `"toBlock":"latest"` once the chain has moved 10 000
blocks past your start. The window above (`49836403`–`49836603`) brackets the
registration; to find a *later* rotation's event, scan forward in ≤10 000-block steps.

Finally, none of this proves the live endpoint *runs* that image — that is Part 1's
job. The chain record is only meaningful together with a live attestation you
verified yourself.

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
  Dockerfile is a `git checkout <commit>`; recorded in
  [`poc/policies/build-pins.txt`](../poc/policies/build-pins.txt).
- **`Cargo.lock` committed + `cargo build --locked`** — dependency versions cannot
  drift *within a commit*; vendored NSM deps built `--offline --locked`. The lockfile
  is itself a PCR0 input: a dependency bump on `main` changes the enclave binary, so a
  measurement is tied to a commit (the repo README names it) and CI
  (`scripts/enclave-closure-check.py`) fails when the enclave's dependency closure
  drifts from the snapshot the published number was measured against.
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

> **Which links apply to the demo vs. production.** The public **demo is testnet**,
> and its KMS money-gate is exercised against testnet keys — that link closes on the
> production deployment. The other three you can check on the demo yourself:
> `PCR0_rebuilt` (Part 2), `PCR0_live` (Part 1), and — since the 2026-08-10 rotation,
> when the demo measurement was registered — `PCR0_onchain` (Part 1.3). An earlier
> revision of this page said the on-chain link did not apply to the demo; it does now.

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
