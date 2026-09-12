#!/usr/bin/env python3
"""The reader's verifier, held to its own promise.

`docs/VERIFY-SIGNER-YOURSELF.md` tells an outside reviewer to paste a Python block and
run it, and promises "any tampering fails loudly". Nothing ran that block. It drifted:
measured 2026-09-12 against 22 corrupted documents, it produced a Python TRACEBACK for
16 of them — seven of those `cryptography.exceptions.InvalidSignature` with no message
at all, and one where a single flipped bit in the body printed an error about parsing a
certificate. A reviewer cannot tell an attack from a crashed gateway that way, and a
promise nobody runs is a claim nobody checks.

So this test runs the block itself. It EXTRACTS the code out of the markdown — not a
copy kept alongside it, because two copies drift and the one that drifts is the one
nobody looks at — and drives it against the real attestation document plus 21 ways of
breaking it.

What fails this test:
  * any corrupted document that reaches a traceback instead of a named refusal;
  * a corrupted document reported as verified;
  * the UNTOUCHED document failing to verify (a verifier that refuses everything passes
    the first two conditions and is worthless);
  * the markdown no longer containing an extractable block, or the fixture missing.

The document in `fixtures/attestation-live.json` is a real capture from
signer-demo.usenami.io on 2026-09-12, not a hand-built one: a fixture we invented would
only prove our own assumptions. It is a signed, public document — /attestation is a
public endpoint — and carries no secret. Its certificate chain is validated as-of the
timestamp inside it, so this test does not rot when those short-lived certs expire.

Needs: cbor2, cryptography, pyhanko-certvalidator, asn1crypto, requests (the same packages the documented
block tells the reader to install). They are installed in CI immediately before this
step. If they are missing this test FAILS rather than skipping — a skipped guard is the
silence it exists to prevent.
"""
import base64
import contextlib
import datetime
import io
import json
import os
import re
import sys
import traceback
import unittest
from pathlib import Path

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
DOC = HERE.parent.parent / "docs" / "VERIFY-SIGNER-YOURSELF.md"
FIXTURE = HERE / "fixtures" / "attestation-live.json"
# The AWS Nitro root, as the documented block pins it. Read from disk in CI (the
# workflow downloads it) or from NITRO_ROOT_PEM locally.
ROOT_PEM = os.environ.get("NITRO_ROOT_PEM", str(HERE / "fixtures" / "root.pem"))


def extract_block(markdown: str) -> str:
    """Pull the one ```python block out of the page. Ambiguity is a failure, not a guess."""
    blocks = re.findall(r"```python\n(.*?)\n```", markdown, re.S)
    if len(blocks) != 1:
        raise AssertionError(
            f"expected exactly one ```python block in {DOC.name}, found {len(blocks)} — "
            f"this test extracts the reader's verifier from the page and cannot tell "
            f"which one that is"
        )
    return blocks[0]


class Tamper:
    """Twenty-one ways to break one real attestation document, plus the untouched one."""

    def __init__(self, live: dict):
        self.good_b64 = live["attestation_doc_b64"]
        self.nonce = live["nonce"]
        self.expected_pcr0 = live["pcr0_sha384"]
        raw = base64.b64decode(self.good_b64)
        top = cbor2.loads(raw)
        self.tagged = isinstance(top, cbor2.CBORTag)   # tag 18 = COSE_Sign1
        self.cose = list(top.value if self.tagged else top)
        self.raw = raw

    def _pack(self, cose):
        v = list(cose)
        return base64.b64encode(
            cbor2.dumps(cbor2.CBORTag(18, v) if self.tagged else v)
        ).decode()

    def _with(self, i, val):
        c = list(self.cose)
        c[i] = val
        return self._pack(c)

    def _payload(self, fn):
        c = list(self.cose)
        doc = cbor2.loads(c[2])
        fn(doc)
        c[2] = cbor2.dumps(doc)
        return self._pack(c)

    @staticmethod
    def _flip(b, i):
        ba = bytearray(b)
        ba[i] ^= 0x01
        return bytes(ba)

    @staticmethod
    def _selfsigned_der():
        key = ec.generate_private_key(ec.SECP384R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-aws")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA384())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def cases(self):
        """(name, response body, nonce we asked for, content-type, expected exit code)."""
        doc = lambda b64: {"attestation_doc_b64": b64}
        p = self._payload
        out = [
            ("00 untouched_good", doc(self.good_b64), self.nonce, "application/json", 0),
            # ── the signed bytes altered ────────────────────────────────────────────
            ("01 sig_bitflip", doc(self._with(3, self._flip(self.cose[3], 0))), self.nonce, "application/json", 1),
            ("02 body_bitflip", doc(self._with(2, self._flip(self.cose[2], 40))), self.nonce, "application/json", 1),
            ("03 cert_bitflip", doc(p(lambda d: d.__setitem__("certificate", self._flip(d["certificate"], 60)))), self.nonce, "application/json", 1),
            ("04 pcr0_swapped", doc(p(lambda d: d["pcrs"].__setitem__(0, b"\xaa" * 48))), self.nonce, "application/json", 1),
            # ── the chain attacked ─────────────────────────────────────────────────
            ("05 cabundle_cut", doc(p(lambda d: d.pop("cabundle"))), self.nonce, "application/json", 1),
            ("06 cabundle_empty", doc(p(lambda d: d.__setitem__("cabundle", []))), self.nonce, "application/json", 1),
            ("07 selfsigned_leaf", doc(p(lambda d: d.__setitem__("certificate", self._selfsigned_der()))), self.nonce, "application/json", 1),
            # ── the COSE envelope attacked ─────────────────────────────────────────
            ("08 alg_swapped", doc(self._with(0, cbor2.dumps({**cbor2.loads(self.cose[0]), 1: -7}))), self.nonce, "application/json", 1),
            ("09 sig_empty", doc(self._with(3, b"")), self.nonce, "application/json", 1),
            ("10 cose_three_elements", doc(self._pack(self.cose[:3])), self.nonce, "application/json", 1),
            ("11 payload_not_map", doc(self._with(2, cbor2.dumps([1, 2, 3]))), self.nonce, "application/json", 1),
            ("12 cbor_truncated", doc(base64.b64encode(self.raw[: len(self.raw) // 2]).decode()), self.nonce, "application/json", 1),
            # ── fields cut out of the document ─────────────────────────────────────
            ("13 certificate_cut", doc(p(lambda d: d.pop("certificate"))), self.nonce, "application/json", 1),
            ("14 pcrs_cut", doc(p(lambda d: d.pop("pcrs"))), self.nonce, "application/json", 1),
            ("15 pcr0_short", doc(p(lambda d: d["pcrs"].__setitem__(0, b"\xbb" * 16))), self.nonce, "application/json", 1),
            ("16 nonce_cut", doc(p(lambda d: d.pop("nonce"))), self.nonce, "application/json", 1),
            ("17 timestamp_cut", doc(p(lambda d: d.pop("timestamp"))), self.nonce, "application/json", 1),
            # ── replay: a genuine document answering a nonce we never sent ─────────
            ("18 replay_wrong_nonce", doc(self.good_b64), "00" * 16, "application/json", 1),
            # ── never got a document at all: code 2, and it must NOT read as an attack
            ("19 not_json", "<html>502 Bad Gateway</html>", self.nonce, "text/html", 2),
            ("20 no_doc_field", {"error": "enclave unavailable"}, self.nonce, "application/json", 2),
            ("21 bad_base64", doc("!!!! not base64 !!!!"), self.nonce, "application/json", 2),
        ]
        return out


def _response(body, ctype):
    """A real requests.Response, so r.json() raises exactly what requests raises."""
    r = requests.Response()
    r.status_code = 200
    r._content = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    r.headers["content-type"] = ctype
    r.headers["cache-control"] = "no-store"
    r.url = "https://signer-demo.usenami.io:8443/attestation"
    return r


def run_block(source: str, body, nonce: str, ctype: str, expected_pcr0: str):
    """Execute the documented block with the network stubbed.

    Returns (exit_code, output, traceback_or_None). A traceback here is the defect this
    whole file exists to catch, so it is returned rather than raised.
    """
    real_get, real_urandom = requests.get, os.urandom
    requests.get = lambda *a, **k: _response(body, ctype)
    # The block draws its nonce from os.urandom; pin it so the replay case is a real
    # mismatch between what we asked for and what the document echoes.
    os.urandom = lambda n: bytes.fromhex(nonce)[:n]
    env = dict(os.environ)
    os.environ["EXPECTED_PCR0"] = expected_pcr0
    os.environ["NITRO_ROOT_PEM"] = ROOT_PEM
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                exec(compile(source, str(DOC), "exec"),
                     {"__name__": "__main__", "__file__": str(DOC)})
                return 0, buf.getvalue(), None
            except SystemExit as e:
                code = e.code
                if isinstance(code, str):        # SystemExit("message") = exit 1 + text
                    return 1, buf.getvalue() + code, None
                return (code or 0), buf.getvalue(), None
    except BaseException:                        # noqa: BLE001 — reporting it IS the test
        return None, buf.getvalue(), traceback.format_exc()
    finally:
        requests.get, os.urandom = real_get, real_urandom
        os.environ.clear()
        os.environ.update(env)


class VerifierBlockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Wiring first. If any of this is missing the test must FAIL, not pass quietly:
        # an empty suite is the exact failure mode of the thing being guarded.
        assert DOC.is_file(), f"{DOC} is missing — nothing to extract"
        assert FIXTURE.is_file(), f"{FIXTURE} is missing — nothing to tamper with"
        assert Path(ROOT_PEM).is_file(), (
            f"{ROOT_PEM} is missing — download AWS_NitroEnclaves_Root-G1.zip or set "
            f"NITRO_ROOT_PEM; without the pinned root nothing below means anything"
        )
        cls.source = extract_block(DOC.read_text(encoding="utf-8"))
        cls.live = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.cases = Tamper(cls.live).cases()
        assert len(cls.cases) == 22, f"expected 22 cases, built {len(cls.cases)}"

    def test_untouched_document_verifies(self):
        """A verifier that refuses everything would pass every other test in this file."""
        name, body, nonce, ctype, _ = self.cases[0]
        code, out, tb = run_block(self.source, body, nonce, ctype, self.live["pcr0_sha384"])
        self.assertIsNone(tb, f"{name}: the genuine document raised\n{tb}")
        self.assertEqual(code, 0, f"{name}: the genuine document did not verify\n{out}")

    def test_no_tampered_document_is_reported_as_verified(self):
        for name, body, nonce, ctype, want in self.cases[1:]:
            with self.subTest(case=name):
                code, out, _tb = run_block(self.source, body, nonce, ctype,
                                           self.live["pcr0_sha384"])
                self.assertNotEqual(code, 0, f"{name}: reported as VERIFIED\n{out}")

    def test_every_refusal_is_named_not_a_traceback(self):
        """The promise in the page: 'any tampering fails loudly' — loudly means by name."""
        for name, body, nonce, ctype, want in self.cases[1:]:
            with self.subTest(case=name):
                code, out, tb = run_block(self.source, body, nonce, ctype,
                                          self.live["pcr0_sha384"])
                self.assertIsNone(
                    tb, f"{name}: reached a Python traceback instead of a named "
                        f"refusal — a reader cannot tell this from a crashed gateway\n{tb}")
                self.assertRegex(
                    out, r"VERIFICATION FAILED|COULD NOT VERIFY",
                    f"{name}: refused without a verdict line\n{out}")

    def test_could_not_check_is_not_reported_as_tampering(self):
        """Code 2 exists so silence never passes for proof, and never for an attack."""
        for name, body, nonce, ctype, want in self.cases[1:]:
            with self.subTest(case=name):
                code, out, _tb = run_block(self.source, body, nonce, ctype,
                                           self.live["pcr0_sha384"])
                self.assertEqual(
                    code, want,
                    f"{name}: expected exit {want} "
                    f"({'could not verify' if want == 2 else 'verification failed'}), "
                    f"got {code}\n{out}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
