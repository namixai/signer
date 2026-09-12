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

# AWS Nitro Enclaves root — download it, then PIN its hash.
#
# 🔴 ENCODING MATTERS, and two of our own documents pin DIFFERENT numbers for the same
# certificate because of it. Both are correct; they hash different encodings of it:
#   6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0  sha256 of root.pem
#                                                                    (the PEM FILE as shipped)
#   641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b  sha256 of the DER
#                                                                    (openssl x509 -outform DER)
# Re-measured 2026-09-12 from a fresh download. The command below hashes the PEM file, so
# it is the first value you should expect.
#
# Confirm the hash OUT-OF-BAND (AWS documentation / a second channel) — do not trust
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
#
# 🔴 EVERY refusal is NAMED, and that is a fix, not a flourish. An earlier revision of
# this script promised "any tampering fails loudly" and, for half of a twenty-document
# tampering set, delivered a Python traceback instead: TypeError from unpacking, KeyError
# from a cut field, CBORDecodeEOF, two JSONDecodeError — and worst, a flipped bit in the
# BODY printed `ValueError: Error parsing asn1crypto.x509…`, which reads as a broken
# certificate when the truth is a broken document. A reader cannot tell an attack from a
# crashed gateway that way. The published npm verifier (@usenami/signer-mcp) returned a
# named refusal for all twenty; this one now reports the same way, with the same words.
import base64, hashlib, os, re, sys, datetime, requests, cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from certvalidator import CertificateValidator, ValidationContext

# The AWS Nitro root you confirmed OUT-OF-BAND in the bash block above. Keeping it here
# as a default (rather than only in a variable) is what makes this script runnable as
# published; supply NITRO_ROOT_SHA256 to hold it to a value YOU sourced. This is the
# sha256 of the PEM file as AWS ships it inside AWS_NitroEnclaves_Root-G1.zip.
ROOT_SHA256 = os.environ.get(
    "NITRO_ROOT_SHA256",
    "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0",
).strip().lower()

# The five checks, in the order they are attempted. Same names the npm verifier prints,
# deliberately: two verifiers that disagree about what to call a failure are two answers.
CHECKS = ("root_pinned", "document_readable", "chain_verified",
          "signature_verified", "pcr0_matches", "nonce_echoed")

# Three outcomes, never two. `verified` says the document checked out; `unreadable` says
# we never got a document to check (network, gateway, a body that is not ours) and is the
# ONLY case that is not a statement about the enclave. A corrupt or forged document is a
# FAILURE, not an "unknown": we received it and it does not verify.
def _verdict(nonce_sent):
    return {"verified": False, "checks": {c: False for c in CHECKS},
            "reason": None, "unreadable": False, "nonce_sent": nonce_sent, "notes": []}

def _fail(v, why, *, unreadable=False):
    v["reason"] = why
    v["unreadable"] = unreadable
    return v

def _as_bytes(x):
    return x if isinstance(x, (bytes, bytearray)) else None

def verify_document(body, nonce_sent, expected_pcr0, root_pem, *, no_store=True):
    """Verify one attestation response. Returns a verdict dict; raises nothing.

    `body` is the PARSED JSON body of /attestation, `nonce_sent` the hex nonce we asked
    for, `expected_pcr0` the 96-hex measurement YOU decided to expect, `root_pem` the
    bytes of the AWS Nitro root you downloaded and hashed yourself.
    """
    v = _verdict(nonce_sent)

    # 0) Pin the AWS Nitro root before trusting anything. A wrong anchor makes every
    #    later check theatre, so it is checked first and it is a failure, not an unknown.
    v["root_sha256"] = hashlib.sha256(root_pem).hexdigest()
    if v["root_sha256"] != ROOT_SHA256:
        return _fail(v, f"the root certificate on disk is not the pinned one "
                        f"(sha256 {v['root_sha256']}, expected {ROOT_SHA256})")
    v["checks"]["root_pinned"] = True

    # 1) Did we get an attestation document at all? Everything from here to the COSE
    #    unwrap is "the endpoint did not answer us properly" — a transport or gateway
    #    problem. It is reported as UNREADABLE, never as a failed enclave.
    if not isinstance(body, dict):
        return _fail(v, "the endpoint's response is not a JSON object", unreadable=True)
    b64 = body.get("attestation_doc_b64")
    if not isinstance(b64, str) or not b64:
        return _fail(v, "the response carries no `attestation_doc_b64` string",
                     unreadable=True)
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as e:
        return _fail(v, f"`attestation_doc_b64` is not valid base64 ({type(e).__name__})",
                     unreadable=True)
    if not raw:
        return _fail(v, "`attestation_doc_b64` decoded to zero bytes", unreadable=True)

    # 2) From here on we HAVE a document. Anything wrong with it is tampering or
    #    corruption, and it is reported as a failure with the damaged part named.
    try:
        cose = cbor2.loads(raw)
    except Exception as e:
        return _fail(v, f"the document is not decodable CBOR ({type(e).__name__}) — "
                        f"it is corrupt or forged, not a transport fault")
    if isinstance(cose, cbor2.CBORTag):        # tag 18 = COSE_Sign1
        cose = cose.value
    # 🔴 This unpack is what produced `TypeError: cannot unpack non-iterable`. A document
    # that is not a 4-element array is not a COSE_Sign1, and saying so is the whole job.
    if not isinstance(cose, (list, tuple)) or len(cose) != 4:
        return _fail(v, "the document is not a COSE_Sign1: expected a 4-element array "
                        "[protected, unprotected, payload, signature], got "
                        f"{type(cose).__name__} of length "
                        f"{len(cose) if isinstance(cose, (list, tuple)) else 'n/a'}")
    protected_bstr, _unprotected, payload_bstr, sig = cose
    for name, val in (("protected header", protected_bstr), ("payload", payload_bstr),
                      ("signature", sig)):
        if _as_bytes(val) is None:
            return _fail(v, f"the COSE {name} is not a byte string "
                            f"({type(val).__name__}) — the document is malformed")

    try:
        phdr = cbor2.loads(protected_bstr) if protected_bstr else {}
    except Exception as e:
        return _fail(v, f"the COSE protected header is not decodable CBOR "
                        f"({type(e).__name__})")
    if not isinstance(phdr, dict):
        return _fail(v, f"the COSE protected header is not a map ({type(phdr).__name__})")
    # Enforce the algorithm BEFORE trusting the signature, or a document could claim a
    # weaker one than we verify with.
    if phdr.get(1) != -35:
        return _fail(v, f"the protected header declares alg={phdr.get(1)!r}, not ES384 "
                        f"(-35); a document we cannot interpret is not one we vouch for")

    try:
        doc = cbor2.loads(payload_bstr)
    except Exception as e:
        return _fail(v, f"the signed payload is not decodable CBOR "
                        f"({type(e).__name__}) — the signed bytes are damaged")
    if not isinstance(doc, dict):
        return _fail(v, f"the signed payload is not a CBOR map ({type(doc).__name__})")

    # 🔴 Every field is checked for PRESENCE AND TYPE before it is used. This is the
    # KeyError class: a document with `cabundle` cut out used to die three frames down
    # with the key name and nothing else — no verdict, no indication it was an attack.
    ts = doc.get("timestamp")
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0:
        return _fail(v, "the document has no usable `timestamp` (needed to validate the "
                       f"short-lived certificates as-of signing time): {ts!r}")
    leaf_der = _as_bytes(doc.get("certificate"))
    if not leaf_der:
        return _fail(v, "the document's `certificate` field is missing, empty, or not a "
                        "byte string")
    bundle = doc.get("cabundle")
    if (not isinstance(bundle, list) or not bundle
            or any(_as_bytes(c) is None or not c for c in bundle)):
        return _fail(v, "the document's `cabundle` is missing, empty, or is not a list of "
                        "non-empty byte strings — with no chain there is nothing to "
                        "anchor to the AWS root")
    pcrs = doc.get("pcrs")
    pcr0_raw = pcrs.get(0) if isinstance(pcrs, dict) else None
    if _as_bytes(pcr0_raw) is None or len(pcr0_raw) != 48:
        return _fail(v, "the document's `pcrs[0]` is missing, not a byte string, or not "
                        "48 bytes (SHA-384)")
    nonce_raw = _as_bytes(doc.get("nonce"))
    if nonce_raw is None:
        return _fail(v, "the document carries no `nonce` byte string, so it cannot be "
                        "shown to be fresh rather than replayed")

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception as e:
        # 🔴 THE ONE THAT READ WORST. A single flipped bit in the body lands here, and the
        # old message (`Error parsing asn1crypto.x509…`) blamed the certificate. Name what
        # it means instead: the signed bytes are damaged.
        return _fail(v, f"the certificate inside the document is not parseable DER "
                        f"({type(e).__name__}) — the signed bytes are damaged, which is "
                        f"tampering or corruption, not a gateway fault")

    # The document is structurally sound. Everything below is a cryptographic verdict on
    # it, and the values reported here come out of the SIGNED payload — never out of a
    # plaintext field sitting next to it.
    v["checks"]["document_readable"] = True
    v["pcr0"] = pcr0_raw.hex()
    v["timestamp_ms"] = ts
    v["nonce_in_document"] = nonce_raw.hex()
    if isinstance(doc.get("module_id"), str):
        v["module_id"] = doc["module_id"]

    # 3) FULL RFC 5280 path validation, anchored to the PINNED root, as-of the attestation
    #    time. certvalidator builds and validates the path itself, so cabundle ordering,
    #    DN chaining, CA/basic-constraints, path length and critical extensions are all
    #    handled — nothing hand-rolled. `except Exception` on purpose: asn1crypto raises
    #    ValueError from underneath certvalidator's own error types, and an uncaught one
    #    is exactly the traceback this rewrite exists to remove.
    moment = datetime.datetime.fromtimestamp(ts / 1000, datetime.timezone.utc)
    try:
        vc = ValidationContext(trust_roots=[root_pem], allow_fetching=False, moment=moment)
        CertificateValidator(leaf_der, intermediate_certs=list(bundle),
                             validation_context=vc).validate_usage(set())
        v["checks"]["chain_verified"] = True
    except Exception as e:
        return _fail(v, f"the certificate chain does not validate to the pinned AWS Nitro "
                        f"root as of the document's own timestamp: {e}")

    # 4) COSE ES384 signature under the LEAF public key.
    #    Sig_structure = ["Signature1", protected, external_aad(=b""), payload].
    if len(sig) != 96:
        return _fail(v, f"the COSE signature is {len(sig)} bytes, not the 96-byte P-384 "
                        f"r||s that ES384 requires")
    pub = leaf.public_key()
    if not (isinstance(pub, ec.EllipticCurvePublicKey)
            and isinstance(pub.curve, ec.SECP384R1)):
        return _fail(v, "the leaf certificate's key is not on P-384, so it cannot be the "
                       f"key an ES384 attestation was signed with ({type(pub).__name__})")
    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
    r_int = int.from_bytes(sig[:48], "big")
    s_int = int.from_bytes(sig[48:], "big")
    try:
        pub.verify(utils.encode_dss_signature(r_int, s_int), sig_structure,
                   ec.ECDSA(hashes.SHA384()))
        v["checks"]["signature_verified"] = True
    except Exception:
        return _fail(v, "the ES384 signature does not match the leaf key over these exact "
                        "bytes — the document was altered after it was signed, or it was "
                        "never signed by this certificate")

    # 5) PCR0 and the nonce, taken from INSIDE the verified document.
    v["checks"]["pcr0_matches"] = (v["pcr0"] == expected_pcr0)
    if not v["checks"]["pcr0_matches"]:
        return _fail(v, f"PCR0 mismatch: the signed document measures "
                        f"{v['pcr0']}, you expected {expected_pcr0}")
    try:
        want_nonce = bytes.fromhex(nonce_sent)
    except ValueError:
        return _fail(v, f"the nonce we sent is not hex ({nonce_sent!r}) — this is a bug "
                        f"in the caller, not a finding about the endpoint", unreadable=True)
    v["checks"]["nonce_echoed"] = (nonce_raw == want_nonce)
    if not v["checks"]["nonce_echoed"]:
        return _fail(v, f"the document echoes nonce {nonce_raw.hex()}, not the "
                        f"{nonce_sent} we asked for — it is cached or replayed, not fresh")

    if not no_store:
        v["notes"].append("the response was not marked `cache-control: no-store`")
        return _fail(v, "the endpoint did not mark the attestation `cache-control: "
                        "no-store`; the nonce still binds this document, but an "
                        "intermediary is permitted to hand the next caller a copy")

    v["verified"] = all(v["checks"].values())
    return v


def report(v):
    """Print the verdict the way the npm verifier does: the checklist, then the reason."""
    width = max(len(c) for c in CHECKS)
    for c in CHECKS:
        print(f"  {c.ljust(width)}  {'pass' if v['checks'][c] else 'FAIL'}")
    if v["verified"]:
        print(f"\nVERIFIED — PCR0={v['pcr0']} matches, path valid to the pinned AWS "
              f"root, COSE signature valid, nonce fresh.")
        return 0
    if v["unreadable"]:
        print(f"\nCOULD NOT VERIFY — {v['reason']}.\n"
              f"This is a statement about the connection, NOT about the enclave: we "
              f"never received a document to check.")
        return 2
    print(f"\nVERIFICATION FAILED — {v['reason']}.\n"
          f"A document was received and it does not verify. Treat this as tampering or "
          f"corruption; it is not a transport error.")
    for n in v["notes"]:
        print(f"  note: {n}")
    return 1


def main():
    # 🔴 THERE IS NO DEFAULT MEASUREMENT HERE ON PURPOSE. This script will not run until
    # you say which one you expect.
    #
    # It used to ship a baked-in value, and that value went stale twice — most recently on
    # 2026-08-24, when rotation #4 moved production off it while this file kept offering
    # it as the answer. A verifier that quietly substitutes last season's number is worse
    # than one that refuses: it hands you a mismatch that looks exactly like a dishonest
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
    # Whichever you pick, the enclaves are SEPARATE BOXES on independent rotation
    # schedules. Whether they run the same image is a state with a date on it, not a
    # property: they were apart from 2026-08-24 to 2026-08-27, apart again from
    # 2026-09-03, and apart for one day from 2026-09-10 until the demo box followed on
    # 2026-09-11. Since 2026-09-11 both attest the SAME measurement — which is exactly
    # why you must still check WHICH box you queried: a number that matches today can
    # match for the wrong reason tomorrow.
    #
    # `.strip()` before `.lower()`: a value pasted from a terminal or a CI variable
    # routinely carries a trailing newline, and an invisible character is the worst
    # possible reason for a verification to fail.
    expected_pcr0 = os.environ.get("EXPECTED_PCR0", "").strip().lower()
    if not expected_pcr0:
        print("EXPECTED_PCR0 is not set, and this script will not guess one for you.\n"
              "Set it to the measurement you expect this endpoint to be running - see\n"
              "the comment above for where to source it - then run again:\n"
              "  EXPECTED_PCR0=<96 hex chars> SIGNER_URL=<endpoint> python3 verify.py",
              file=sys.stderr)
        return 2
    # Shape first, before any network call or certificate work: a typo should cost you a
    # line of output, not a full path validation against the Nitro root.
    if not re.fullmatch(r"[0-9a-f]{96}", expected_pcr0):
        print(f"EXPECTED_PCR0 must be 96 hex characters (SHA-384); got "
              f"{len(expected_pcr0)}.", file=sys.stderr)
        return 2

    # The endpoint to query. Read from the SAME environment variable name the bash block
    # below offers — an earlier revision used a different name internally (and did not
    # define it at all), so the documented `SIGNER_URL=…` had no effect and the script
    # died on a NameError before its first check.
    base = os.environ.get("SIGNER_URL", "https://signer-demo.usenami.io:8443").strip().rstrip("/")

    # root.pem is the file the bash block above downloaded and hashed. Read it from disk
    # rather than embedding it: a certificate pasted into a document is exactly the kind
    # of thing that silently goes stale.
    root_path = os.environ.get("NITRO_ROOT_PEM", "root.pem")
    try:
        with open(root_path, "rb") as fh:
            root_pem = fh.read()
    except OSError as e:          # not just FileNotFoundError: a permission/EISDIR error
        print(f"cannot read {root_path} ({e}) — run the download step above "  # must not
              f"(curl … AWS_NitroEnclaves_Root-G1.zip && unzip) in this "      # traceback
              f"directory first, or point NITRO_ROOT_PEM at the file.", file=sys.stderr)
        return 2

    # Fetch a FRESH doc bound to our nonce. A network failure is NOT a finding about the
    # enclave, so it exits 2 and says so — the same split the verdict makes.
    nonce = os.urandom(16).hex()
    try:
        r = requests.get(f"{base}/attestation", params={"nonce": nonce}, timeout=15)
    except requests.RequestException as e:
        print(f"COULD NOT VERIFY — {base} did not answer ({type(e).__name__}: {e}).\n"
              f"This is a statement about the connection, not about the enclave.",
              file=sys.stderr)
        return 2
    if r.status_code != 200:
        print(f"COULD NOT VERIFY — {base}/attestation returned HTTP {r.status_code}.\n"
              f"This is a statement about the gateway, not about the enclave.",
              file=sys.stderr)
        return 2
    try:
        body = r.json()
    except ValueError:
        print(f"COULD NOT VERIFY — {base}/attestation did not return JSON "
              f"(content-type {r.headers.get('content-type')!r}).\n"
              f"This is a statement about the gateway, not about the enclave.",
              file=sys.stderr)
        return 2

    v = verify_document(body, nonce, expected_pcr0, root_pem,
                        no_store=(r.headers.get("cache-control") == "no-store"))
    return report(v)


# Everything above is importable and testable without a network; only this line runs it.
if __name__ == "__main__":
    sys.exit(main())
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

Any tampering fails loudly, and "loudly" means BY NAME. The script prints the checklist
and then one sentence saying what is wrong: a forged document breaks the COSE signature;
a document from a different image fails the PCR0 check; a stale or cached document fails
the nonce check; a non-AWS chain fails the pinned-root path validation; a cut, truncated
or re-encoded document is refused with the damaged field named.

There are THREE outcomes, not two, and the exit code tells them apart:

| exit | meaning | what it says about the enclave |
|---|---|---|
| `0` | every check passed | it is running the measurement you expected |
| `1` | a document arrived and does not verify | treat it as tampering or corruption |
| `2` | no document to check — network, gateway, a body that is not ours, or a setting you did not supply | **nothing**; this is about the connection, not the enclave |

That split is load-bearing. Collapsing "could not check" into either of the other two is
how a verifier starts lying: fold it into `0` and silence passes for proof, fold it into
`1` and every flaky network reads as an attack.

This is measured, not asserted. An earlier revision of the script promised the same
sentence and delivered a Python traceback for 16 of 22 corrupted documents — including
seven that printed `cryptography.exceptions.InvalidSignature` with no message at all, and
one where a flipped bit in the body printed an error about parsing a certificate, which
reads like a broken gateway rather than a tampered document. The set that found it is in
[`poc/scripts/test_verify_doc_block.py`](../poc/scripts/test_verify_doc_block.py): it
extracts this very code block from this very file, runs all 22 against it, and fails CI
if any of them reaches a traceback or if the untouched document stops verifying. Run it
yourself — you do not have to take the claim on our word, which is the point of the whole
page.

### Which commit rebuilds which measurement

"Build it at a tag" is only useful if you know the tag. The tag for each lane is listed
in [Which commit rebuilds which measurement](REPRODUCIBLE-BUILD.md#which-commit-rebuilds-which-measurement),
in the build guide — one table, kept in the document that is about building. Two copies
of a table drift, and the copy that drifts is the one nobody is looking at.

Build at the tag for the lane you are checking, take the measurement out of that lane's
own attestation document, and compare the two.

Do not take the pairing from that table alone. Lanes rotate independently, a table in
prose ages, and the document you fetch is what decides. If a lane's live measurement
does not match the tag named there, the table is stale — that is a reason to ask us, not
a failed build on your side.

### Where the expected PCR0 comes from

Nothing is baked in above, and that is the point. Earlier revisions of this file
carried a default, which is how it drifted: between 2026-08-10 and 2026-08-24 the two
lanes did run the same image, the file said so, and then rotation #4 moved production
onto `103ccd79…` while the default kept naming the old value.

The lanes have diverged and re-converged three times (2026-08-24, 2026-09-03,
2026-09-10); since 2026-09-11 they agree again. This file no longer averages over
that, and it no
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
