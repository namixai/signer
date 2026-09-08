#!/usr/bin/env python3
"""verify-receipt-yourself.py — check a Usenami decision receipt with nothing but this repo.

WHAT THIS ANSWERS. The gateway can be asked to sign, and it can refuse. When it
refuses it returns a *decision receipt*: a signed statement of what it decided and
why. This script checks that the receipt was signed by the key the enclave attests
to — not by the server, not by us — and that the chain of receipts has no gap.

WHY IT MATTERS THAT YOU RUN IT. Anything we run ourselves proves nothing to you.
The point of the receipt is that a stranger, holding only public material, can take
a refusal we handed them and confirm it came from the measured enclave. So this
script has no dependencies to install, imports nothing from a private tree, and
takes no input from us except the receipt you were given and the attestation you
fetch yourself.

WHAT IT DOES NOT PROVE. It does not tell you the enclave is running the source in
this repo — that is the reproducible-build check, a separate document. It tells you
that whoever signed this receipt holds the key named in the attestation of the lane
you asked, and that the receipt has not been altered by a byte.

  python3 verify-receipt-yourself.py selftest
  python3 verify-receipt-yourself.py verify --attestation att.json --receipt rec.json
  python3 verify-receipt-yourself.py verify --attestation att.json --receipt rec.json \
      --heartbeat hb.json --expect-reason notional_over_cap

Exit: 0 verified · 1 verification FAILED · 2 could not check (missing input).
Three outcomes, not two: "could not check" is never green.
"""
from __future__ import annotations

import argparse
import json
import sys

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
       15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
_M64 = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M64


def _keccak_f(st):
    for rnd in range(24):
        bc = [st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20]
              for i in range(5)]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rol(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                st[j + i] ^= t
        t = st[1]
        for i in range(24):
            j = _PI[i]
            st[j], t = _rol(t, _ROT[i]), st[j]
        for j in range(0, 25, 5):
            row = st[j:j + 5]
            for i in range(5):
                st[j + i] = row[i] ^ ((~row[(i + 1) % 5] & _M64) & row[(i + 2) % 5])
        st[0] ^= _RC[rnd]
    return st


def keccak256(data: bytes) -> bytes:
    rate = 136
    st = [0] * 25
    buf = bytearray(data)
    buf.append(0x01)                       # keccak padding, NOT 0x06 as in SHA3
    while len(buf) % rate:
        buf.append(0x00)
    buf[-1] |= 0x80
    for off in range(0, len(buf), rate):
        blk = buf[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(blk[i * 8:(i + 1) * 8], "little")
        _keccak_f(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


# ── secp256k1: recovering the public key from a signature ────────────────────
_P = 2 ** 256 - 2 ** 32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _pt_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % _P == 0:
            return None
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], _P - 2, _P) % _P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return (x, (lam * (a[0] - x) - a[1]) % _P)


def _pt_mul(k, pt):
    k %= _N
    res, add = None, pt
    while k:
        if k & 1:
            res = _pt_add(res, add)
        add = _pt_add(add, add)
        k >>= 1
    return res


def address_of_point(pt) -> str:
    raw = pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    return "0x" + keccak256(raw)[-20:].hex()


def address_of_privkey(pk_hex: str) -> str:
    return address_of_point(_pt_mul(int(pk_hex, 16), _G))


def recover_pubkey(digest: bytes, r: int, s: int, v: int):
    """Recover the public-key point, exactly as the venue does."""
    recid = v - 27 if v >= 27 else v
    if recid not in (0, 1, 2, 3):
        raise ValueError("invalid recovery id v=%r" % v)
    if not (1 <= r < _N and 1 <= s < _N):
        raise ValueError("r or s out of range")
    x = r + (_N if recid >= 2 else 0)
    if x >= _P:
        raise ValueError("x outside the field")
    alpha = (pow(x, 3, _P) + 7) % _P
    beta = pow(alpha, (_P + 1) // 4, _P)
    if (beta * beta - alpha) % _P:
        raise ValueError("point is not on the curve")
    y = beta if (beta % 2) == (recid % 2) else _P - beta
    e = int.from_bytes(digest, "big")
    q = _pt_mul(pow(r, _N - 2, _N),
                _pt_add(_pt_mul(s, (x, y)), _pt_mul((-e) % _N, _G)))
    if q is None:
        raise ValueError("recovery produced the point at infinity")
    return q



# ── CBOR / COSE / P-384: reading the SIGNED document ─────────────────────────
#
# 🔴 Why this exists at all. The first version of this script took the receipt key
# from `data_pubkey_address` in the attestation JSON. That field is filled from the
# GATEWAY'S OWN CONFIG (`handlers.rs`, `cfg.data_pubkey_address`) — it is not a
# binding to anything. A gateway that is compromised, or merely misconfigured, puts
# any address there and the check passes. The design says plainly what to do instead:
# "verify the COSE document against the AWS root, take `public_key` from the SIGNED
# document, verify the receipt signature with it."
#
# So the key now comes out of the NSM payload, and the JSON field is only ever
# COMPARED against it. A mismatch between them is itself a finding: it means the
# gateway is telling you something the enclave did not sign.
def cbor_load(b: bytes, i: int = 0):
    """Decode one CBOR item. Subset: the shapes an NSM document actually uses."""
    ib = b[i]; mt, ai = ib >> 5, ib & 0x1F; i += 1
    if ai < 24:
        val = ai
    elif ai == 24:
        val = b[i]; i += 1
    elif ai == 25:
        val = int.from_bytes(b[i:i + 2], "big"); i += 2
    elif ai == 26:
        val = int.from_bytes(b[i:i + 4], "big"); i += 4
    elif ai == 27:
        val = int.from_bytes(b[i:i + 8], "big"); i += 8
    elif ai == 31:
        val = None                       # indefinite length
    else:
        raise ValueError("CBOR: reserved additional info %d" % ai)

    if mt == 0: return val, i
    if mt == 1: return -1 - val, i
    # 🔴 Indefinite-length items are not an exotic corner: a live AWS NSM document
    # uses them for the payload map, and the first version of this decoder refused
    # them and never got past the outer array. Found by running against a real
    # document, not by reading the spec — which is the whole argument for doing so.
    if mt in (2, 3):
        if val is None:                             # chunks until the break marker
            parts = []
            while b[i] != 0xFF:
                chunk, i = cbor_load(b, i); parts.append(chunk)
            i += 1
            joined = b"".join(parts) if mt == 2 else "".join(parts)
            return joined, i
        raw = b[i:i + val]; i += val
        return (raw if mt == 2 else raw.decode("utf-8")), i
    if mt == 4:
        out = []
        if val is None:
            while b[i] != 0xFF:
                v, i = cbor_load(b, i); out.append(v)
            return out, i + 1
        for _ in range(val):
            v, i = cbor_load(b, i); out.append(v)
        return out, i
    if mt == 5:
        out = {}
        if val is None:
            while b[i] != 0xFF:
                k, i = cbor_load(b, i)
                v, i = cbor_load(b, i)
                out[k] = v
            return out, i + 1
        for _ in range(val):
            k, i = cbor_load(b, i)
            v, i = cbor_load(b, i)
            out[k] = v
        return out, i
    if mt == 6:
        return cbor_load(b, i)           # tag: value follows
    if mt == 7:
        return {20: False, 21: True, 22: None, 23: None}.get(ai, val), i
    raise ValueError("CBOR: unsupported major type %d" % mt)


def _cbor_head(major: int, n: int) -> bytes:
    base = major << 5
    if n < 24: return bytes([base | n])
    if n < 256: return bytes([base | 24, n])
    if n < 65536: return bytes([base | 25]) + n.to_bytes(2, "big")
    return bytes([base | 26]) + n.to_bytes(4, "big")


def cbor_bstr(x: bytes) -> bytes:
    """Byte string (major type 2)."""
    return _cbor_head(2, len(x)) + x


def cbor_tstr(x: str) -> bytes:
    """Text string (major type 3).

    🔴 Sig_structure's first element is the TEXT "Signature1", not a byte string.
    Encoding it as bytes gives a preimage that differs in exactly one header byte, so
    every real signature fails to verify while every self-made test passes — the test
    signs the same wrong preimage it checks. Found only against a live AWS document.
    """
    b = x.encode("utf-8")
    return _cbor_head(3, len(b)) + b


# NIST P-384 — the curve the NSM signs with. Same group arithmetic as secp256k1,
# different constants; reusing the point helpers would be wrong, they carry the
# secp256k1 modulus.
_P384_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
_P384_A = _P384_P - 3
_P384_N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
_P384_GX = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
_P384_GY = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f


def _p384_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % _P384_P == 0: return None
    if a == b:
        l = (3 * a[0] * a[0] + _P384_A) * pow(2 * a[1], _P384_P - 2, _P384_P) % _P384_P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], _P384_P - 2, _P384_P) % _P384_P
    x = (l * l - a[0] - b[0]) % _P384_P
    return (x, (l * (a[0] - x) - a[1]) % _P384_P)


def _p384_mul(k, pt):
    r = None
    while k:
        if k & 1: r = _p384_add(r, pt)
        pt = _p384_add(pt, pt); k >>= 1
    return r


def p384_verify(pub_xy: tuple, digest: bytes, r: int, s: int) -> bool:
    if not (1 <= r < _P384_N and 1 <= s < _P384_N): return False
    e = int.from_bytes(digest, "big")
    w = pow(s, _P384_N - 2, _P384_N)
    p = _p384_add(_p384_mul(e * w % _P384_N, (_P384_GX, _P384_GY)),
                  _p384_mul(r * w % _P384_N, pub_xy))
    return p is not None and p[0] % _P384_N == r


# ── DER: just enough X.509 to walk a chain ───────────────────────────────────
def der_tlv(b: bytes, i: int = 0):
    """Return (tag, content_bytes, next_index) for one DER element."""
    tag = b[i]; i += 1
    n = b[i]; i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big"); i += k
    return tag, b[i:i + n], i + n


def der_seq(b: bytes):
    """Split a SEQUENCE's content into its elements, each as (tag, content, raw)."""
    out, i = [], 0
    while i < len(b):
        start = i
        tag, content, i = der_tlv(b, i)
        out.append((tag, content, b[start:i]))
    return out


def cert_parts(der: bytes):
    """(tbs_raw, spki_point, sig_rs) from an X.509 certificate. P-384 keys only —
    that is what the NSM chain uses, and guessing at other curves here would give a
    verifier that appears to check more than it does."""
    body = der_seq(der_tlv(der)[1])
    tbs_raw = body[0][2]
    sigval = body[2][1]
    if sigval and sigval[0] == 0:
        sigval = sigval[1:]                     # BIT STRING unused-bits octet
    rs = der_seq(der_tlv(sigval)[1])
    r, s = int.from_bytes(rs[0][1], "big"), int.from_bytes(rs[1][1], "big")

    # subjectPublicKeyInfo is the last SEQUENCE inside tbsCertificate before the
    # optional extensions; find it by shape rather than by index, because the
    # version/issuerUniqueID fields are optional and shift everything.
    spki = None
    for tag, content, _ in der_seq(der_tlv(tbs_raw)[1]):
        if tag != 0x30:
            continue
        inner = der_seq(content)
        if len(inner) == 2 and inner[1][0] == 0x03:
            bits = inner[1][1]
            if bits and bits[0] == 0:
                bits = bits[1:]
            if len(bits) == 97 and bits[0] == 0x04:      # uncompressed P-384 point
                spki = (int.from_bytes(bits[1:49], "big"), int.from_bytes(bits[49:], "big"))
    if spki is None:
        raise ValueError("certificate carries no uncompressed P-384 public key")
    return tbs_raw, spki, (r, s)


# ── canonical-v1 (RFC 8785 JCS, restricted) ──────────────────────────────────
#
# The enclave signs a canonical serialisation, not "the JSON it happened to
# produce": two byte-different encodings of the same object would otherwise give
# two different signatures, and the check would be a coin flip. Keys are sorted by
# UTF-16 code unit, exactly as RFC 8785 §3.2.3 requires.
#
# Numbers are REFUSED rather than encoded. Every numeric in a receipt (`seq`,
# `supplied_ts_ms`) travels as a decimal STRING, so there is no float to round and
# no integer whose JSON spelling differs between languages. A number reaching this
# function means the receipt is not the shape we sign, and guessing an encoding
# would produce a signature check that passes for the wrong reason.
DOMAIN = b"usenami-decision-receipt-v1"


def _jcs_string(s: str, out: bytearray) -> None:
    out.append(0x22)
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.extend(b'\\"')
        elif ch == "\\":
            out.extend(b"\\\\")
        elif c == 0x08:
            out.extend(b"\\b")
        elif c == 0x0C:
            out.extend(b"\\f")
        elif c == 0x0A:
            out.extend(b"\\n")
        elif c == 0x0D:
            out.extend(b"\\r")
        elif c == 0x09:
            out.extend(b"\\t")
        elif c < 0x20:
            out.extend(("\\u%04x" % c).encode())
        else:
            out.extend(ch.encode("utf-8"))
    out.append(0x22)


def canonical_v1(value, out: bytearray = None) -> bytes:
    top = out is None
    if top:
        out = bytearray()
    if value is None:
        out.extend(b"null")
    elif value is True:
        out.extend(b"true")
    elif value is False:
        out.extend(b"false")
    elif isinstance(value, (int, float)):
        raise ValueError("canonical-v1: JSON numbers are forbidden — receipts carry numerics as decimal strings")
    elif isinstance(value, str):
        _jcs_string(value, out)
    elif isinstance(value, list):
        out.append(0x5B)
        for i, v in enumerate(value):
            if i:
                out.append(0x2C)
            canonical_v1(v, out)
        out.append(0x5D)
    elif isinstance(value, dict):
        out.append(0x7B)
        for i, k in enumerate(sorted(value, key=lambda s: s.encode("utf-16-be"))):
            if i:
                out.append(0x2C)
            _jcs_string(k, out)
            out.append(0x3A)
            canonical_v1(value[k], out)
        out.append(0x7D)
    else:
        raise ValueError("canonical-v1: unsupported type %r" % type(value))
    return bytes(out) if top else None


HEARTBEAT_DOMAIN = b"usenami-receipt-heartbeat-v1"
# Named explicitly rather than "everything except signature": a field the gateway adds
# later would silently join the preimage and break every check with a confusing error.
HEARTBEAT_SIGNED_FIELDS = ["v", "boot_id", "customer_id", "seq_next", "client_nonce",
                           "registry_version", "entry_hash"]
KNOWN_RECEIPT_VERSIONS = {"1"}
KNOWN_DECISIONS = {"allow", "deny"}

# The signature covers every receipt field EXCEPT `signature` itself.
SIGNED_FIELDS = [
    "v", "decision", "reason_code", "customer_id", "action", "request_hash",
    "intent_sig_hash", "policy_hash", "supplied_ts_ms", "boot_id", "seq",
]


def receipt_digest(receipt: dict) -> bytes:
    missing = [f for f in SIGNED_FIELDS if f not in receipt]
    if missing:
        raise ValueError("receipt is missing signed field(s): %s" % ", ".join(missing))
    body = {f: receipt[f] for f in SIGNED_FIELDS}
    return keccak256(DOMAIN + canonical_v1(body))


def canonical_sig(sig, what: str = "receipt") -> tuple:
    """(r, s, v) from a signature object, or a named refusal.

    Shared by receipts and heartbeats on purpose. The low-s rule was on receipts only,
    and the heartbeat — whose counter every continuity check rests on — took whatever
    it was handed. One rule, one place, so the next signed thing cannot quietly get a
    weaker one.
    """
    if not isinstance(sig, dict):
        raise ValueError("%s signature is missing or is not an object" % what)
    for f in ("r", "s", "v"):
        if f not in sig:
            raise ValueError("%s signature is missing '%s'" % (what, f))
    try:
        r_i, s_i, v_i = int(str(sig["r"]), 16), int(str(sig["s"]), 16), int(sig["v"])
    except (TypeError, ValueError):
        raise ValueError("%s signature fields are not hex/int" % what) from None
    if s_i > _N // 2:
        raise ValueError("%s signature uses the high-s form; canonical signatures are low-s only" % what)
    if v_i not in (27, 28):
        raise ValueError("%s recovery id is %d; 27 or 28 expected" % (what, v_i))
    return r_i, s_i, v_i


def recover_receipt_signer(receipt: dict) -> str:
    r_i, s_i, v_i = canonical_sig(receipt.get("signature"), "receipt")
    digest = receipt_digest(receipt)
    return address_of_point(recover_pubkey(digest, r_i, s_i, v_i))


# ── the attestation, actually verified ───────────────────────────────────────
AWS_NITRO_ROOT_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"


def parse_attestation_doc(doc_b64: str):
    """Unwrap COSE_Sign1 → (payload, protected, sig, payload_bytes, cert, cabundle).

    `payload_bytes` is carried out as-is. The signature covers those exact bytes, and
    re-encoding a parsed map would produce different ones — the first version did that
    and the signature failed against a real AWS document for no other reason.
    """
    import base64
    cose, _ = cbor_load(base64.b64decode(doc_b64))
    if not isinstance(cose, list) or len(cose) != 4:
        raise ValueError("not a COSE_Sign1 array of 4 elements")
    protected, _unprotected, payload_bytes, sig = cose
    payload, _ = cbor_load(payload_bytes)
    return payload, protected, sig, payload_bytes, payload.get("certificate"), payload.get("cabundle") or []


def verify_attestation(doc_b64: str, report):
    """Verify the document itself, and return its payload only if it holds up.

    🔴 Three separate facts, and the script must not blur them: the COSE signature is
    self-consistent; the certificate that made it chains to the pinned AWS Nitro root;
    and only then is anything inside the payload worth reading. Skipping the chain and
    checking the signature alone proves nothing at all — an attacker generates their
    own key, signs their own document, and it verifies.
    """
    import base64, hashlib
    payload, protected, sig, payload_bytes, leaf, cabundle = parse_attestation_doc(doc_b64)

    # The pinned root is checked FIRST, and deliberately so. Verifying the COSE
    # signature against the certificate that came inside the same document proves
    # nothing: an attacker generates a key, signs their own document with it, and it
    # is self-consistent. The only thing that makes any of it evidence is that the
    # chain ends at a root you pinned out of band.
    chain = list(cabundle) + [leaf]
    if not chain or not isinstance(chain[0], (bytes, bytearray)):
        report.bad("the chain ends at the pinned AWS Nitro root", "no certificate chain in the document")
        return None
    root_fp = hashlib.sha256(chain[0]).hexdigest()
    if root_fp != AWS_NITRO_ROOT_SHA256:
        report.bad("the chain ends at the pinned AWS Nitro root",
                   "chain starts at sha256 %s…, pinned root is %s… — this document was not "
                   "issued by AWS Nitro, whatever else it says"
                   % (root_fp[:16], AWS_NITRO_ROOT_SHA256[:16]))
        return None

    sig_struct = b"\x84" + cbor_tstr("Signature1") + cbor_bstr(protected) \
        + cbor_bstr(b"") + cbor_bstr(payload_bytes)
    digest = hashlib.sha384(sig_struct).digest()
    r, s_ = int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big")
    _tbs, leaf_key, _ = cert_parts(leaf)
    if not p384_verify(leaf_key, digest, r, s_):
        report.bad("attestation document is signed by its own certificate",
                   "COSE signature does not verify")
        return None
    report.ok("attestation document is signed by its own certificate")

    # Every certificate must be signed by the one above it, up to that root.
    for child, parent in zip(chain[1:], chain[:-1]):
        _pk, parent_key, _ = cert_parts(parent)
        tbs, _k, (cr, cs) = cert_parts(child)
        if not p384_verify(parent_key, hashlib.sha384(tbs).digest(), cr, cs):
            report.bad("the chain ends at the pinned AWS Nitro root",
                       "a certificate in the bundle is not signed by the one above it")
            return None
    report.ok("the chain ends at the pinned AWS Nitro root (%d certificates)" % len(chain))
    return payload


# ── checks ───────────────────────────────────────────────────────────────────
class Report:
    def __init__(self):
        self.fail = 0
        self.skip = 0
        # The names of what failed, not just how many. A test that asserts "it went red"
        # passes when it goes red for the wrong reason — which is how a check that only
        # ever fails in the parser gets mistaken for a check of the thing it names.
        self.failed = []

    def ok(self, what: str) -> None:
        print("  ok    %s" % what)

    def bad(self, what: str, detail: str = "") -> None:
        print("  FAIL  %s%s" % (what, (" — " + detail) if detail else ""))
        self.fail += 1
        self.failed.append(what)

    def cant(self, what: str, why: str) -> None:
        # Not a pass. A check you could not run is a hole, and calling it green is
        # how a watchdog becomes decorative.
        print("  ?     %s — NOT CHECKED: %s" % (what, why))
        self.skip += 1


def address_from_compressed(pub: bytes) -> str:
    """secp256k1 compressed point -> Ethereum-style address."""
    x = int.from_bytes(pub[1:], "big")
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if (y & 1) != (pub[0] & 1):
        y = _P - y
    return address_of_point((x, y))


def attested_signer(payload: dict) -> str | None:
    """The receipt key, taken from the SIGNED NSM payload.

    🔴 Never from `data_pubkey_address` in the JSON. That field is filled from the
    gateway's own config; it binds nothing, and a gateway that is compromised or
    simply misconfigured puts whatever it likes there.
    """
    pk = payload.get("public_key")
    if not pk:
        return None
    if isinstance(pk, str):
        pk = bytes.fromhex(pk[2:] if pk.startswith("0x") else pk)
    if len(pk) == 33 and pk[0] in (2, 3):
        return address_from_compressed(pk)
    if len(pk) == 65 and pk[0] == 4:
        return address_of_point((int.from_bytes(pk[1:33], "big"), int.from_bytes(pk[33:], "big")))
    if len(pk) == 20:
        return "0x" + pk.hex()
    raise ValueError("public_key in the attestation is %d bytes — unrecognised form" % len(pk))


def check(payload: dict, att_json: dict, receipt: dict, heartbeat: dict | None,
          expect_reason: str | None, expect_nonce: str | None = None) -> Report:
    r = Report()

    # 1. Signed by the key the ENCLAVE attests to — the whole point.
    want = attested_signer(payload)
    if not want:
        r.cant("receipt is signed by the attested key",
               "the signed document carries no public_key — this lane issues no receipts yet "
               "(the demo lane is in that state), so there is nothing to check against")
    else:
        try:
            got = recover_receipt_signer(receipt)
        except Exception as e:                                    # noqa: BLE001
            r.bad("receipt is signed by the attested key", "signature does not recover: %s" % e)
            got = None
        if got is not None:
            if got == want:
                r.ok("receipt is signed by the attested key (%s)" % got)
            else:
                r.bad("receipt is signed by the attested key",
                      "recovered %s, attestation names %s" % (got, want))

    # 1b. The JSON field is COMPARED, never trusted. A gateway saying something the
    #     enclave did not sign is itself the finding.
    claimed = att_json.get("data_pubkey_address")
    if want and isinstance(claimed, str) and claimed:
        # A bare hex address without the 0x prefix is a formatting difference, not a
        # disagreement; reporting it as one would send the reader hunting a phantom.
        claimed = claimed.strip().lower()
        claimed = claimed if claimed.startswith("0x") else "0x" + claimed
        if claimed == want:
            r.ok("the gateway's data_pubkey_address agrees with the signed document")
        else:
            r.bad("the gateway's data_pubkey_address agrees with the signed document",
                  "gateway says %s, the signed document says %s — the gateway is not "
                  "reporting what the enclave attested" % (claimed, want))

    # 2. Bound to the measurement of the lane you asked. We deliberately do NOT
    #    print an expected measurement here: a number written into a script is
    #    stale the day after a rotation, and a reader trusting it would compare
    #    against a value we no longer run — a mismatch that looks like THEIR error.
    pcrs = payload.get("pcrs") or {}
    pcr0 = pcrs.get(0) or pcrs.get("0")
    if isinstance(pcr0, (bytes, bytearray)):
        pcr0 = pcr0.hex()
    if isinstance(pcr0, str) and pcr0:
        r.ok("attestation carries a measurement (%s…) — pin it out-of-band, it is not asserted here" % pcr0[:8])
    else:
        r.cant("attestation carries a measurement", "the signed payload has no pcrs[0]")

    # 3. Continuity. A receipt proves one decision; the chain proves nobody quietly
    #    dropped decisions between them. `seq` counts per customer since `boot_id`,
    #    so a receipt from a DIFFERENT boot tells you the enclave restarted — which
    #    is not itself wrong, but it means the count you hold cannot be compared.
    if heartbeat is None:
        r.cant("receipt belongs to the current chain", "no heartbeat supplied (--heartbeat)")
    else:
        hb = heartbeat.get("heartbeat") or heartbeat
        # 🔴 An unsigned heartbeat is a claim by the gateway, and the gateway is the
        #    party this whole page exists to not trust. Without a signature it can
        #    name any seq_next it likes and every continuity check below becomes
        #    theatre. Same for the nonce: a heartbeat that does not echo the nonce
        #    YOU chose may be one the gateway cached long ago.
        hb_sig = heartbeat.get("signature") or hb.get("signature")
        if not hb_sig:
            r.cant("heartbeat is signed by the attested key",
                   "the heartbeat carries no signature — the counter in it is the "
                   "gateway's word, and continuity cannot be checked against a word")
        elif want:
            try:
                body = {k: hb[k] for k in HEARTBEAT_SIGNED_FIELDS if k in hb}
                d = keccak256(HEARTBEAT_DOMAIN + canonical_v1(body))
                hr, hs, hv = canonical_sig(hb_sig, "heartbeat")
                got_hb = address_of_point(recover_pubkey(d, hr, hs, hv))
                if got_hb == want:
                    r.ok("heartbeat is signed by the attested key")
                else:
                    r.bad("heartbeat is signed by the attested key",
                          "recovered %s, expected %s" % (got_hb, want))
            except Exception as e:                                # noqa: BLE001
                r.bad("heartbeat is signed by the attested key", "signature does not verify: %s" % e)
        if expect_nonce is not None:
            if hb.get("client_nonce") == expect_nonce:
                r.ok("heartbeat echoes the nonce you chose")
            else:
                r.bad("heartbeat echoes the nonce you chose",
                      "sent %r, got %r — this may be a cached heartbeat"
                      % (expect_nonce, hb.get("client_nonce")))
        hb_boot, seq_next = hb.get("boot_id"), hb.get("seq_next")
        if not hb_boot or seq_next is None:
            r.cant("receipt belongs to the current chain", "heartbeat has no boot_id/seq_next")
        elif hb_boot != receipt.get("boot_id"):
            r.bad("receipt belongs to the current chain",
                  "receipt boot_id %s, heartbeat %s — different boot, counts are not comparable"
                  % (receipt.get("boot_id"), hb_boot))
        else:
            seq = receipt.get("seq")
            try:
                if seq is None:
                    r.bad("receipt is inside the current chain", "the receipt carries no seq")
                elif int(seq) < int(seq_next):
                    r.ok("receipt is inside the current chain (seq %s < next %s)" % (seq, seq_next))
                else:
                    r.bad("receipt is inside the current chain",
                          "seq %s is not below next %s — the receipt claims a decision the enclave has not issued"
                          % (seq, seq_next))
            except (TypeError, ValueError) as e:
                r.bad("receipt is inside the current chain", "seq/seq_next not decimal strings: %s" % e)

    # 3b. Version and vocabulary. An unknown receipt version means this script was
    #     written against a different shape; guessing is how a verifier passes a
    #     receipt it does not actually understand.
    if receipt.get("v") not in KNOWN_RECEIPT_VERSIONS:
        r.cant("receipt version is one this script understands",
               "receipt says v=%r, this script knows %s" % (receipt.get("v"), sorted(KNOWN_RECEIPT_VERSIONS)))
    if receipt.get("decision") not in KNOWN_DECISIONS:
        r.cant("decision is a known value",
               "receipt says %r, known: %s" % (receipt.get("decision"), sorted(KNOWN_DECISIONS)))

    # 4. The refusal says WHY, and the policy it judged against is named. An empty
    #    policy_hash on a denial is a real gap in OUR audit trail, not a pass.
    decision, reason = receipt.get("decision"), receipt.get("reason_code")
    if expect_reason:
        if reason == expect_reason:
            r.ok("reason_code is %s, as expected" % reason)
        else:
            r.bad("reason_code is %s" % expect_reason, "receipt says %r" % reason)
    if decision == "deny" or (reason and reason not in ("", "allow")):
        if receipt.get("policy_hash"):
            r.ok("the refusal names the policy it judged against (%s…)" % receipt["policy_hash"][:12])
        else:
            r.bad("the refusal names the policy it judged against",
                  "policy_hash is empty — the receipt says no, but not against what")
    return r



# ── building a forgery, for the selftest only ────────────────────────────────
#
# An attacker does not send garbage. They send a document that is well-formed in every
# respect and signed by their own key. To test that the pinned root is what refuses it,
# the test has to be able to build exactly that.
def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + n.to_bytes(2, "big")
    return bytes([tag]) + ln + content


def _der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    return _der(0x02, (b"\x00" + b) if b[0] & 0x80 else b)


def _p384_sign(d: int, digest: bytes) -> tuple:
    """Test-only P-384 ECDSA; nonce derived from the message, as in `_sign_digest`."""
    import hashlib
    z = int.from_bytes(digest[:48], "big")
    k = int.from_bytes(hashlib.sha384(digest + b"forged-attestation").digest(), "big") % _P384_N or 1
    R = _p384_mul(k, (_P384_GX, _P384_GY))
    r = R[0] % _P384_N
    return r, (pow(k, _P384_N - 2, _P384_N) * (z + r * d)) % _P384_N


def _forged_cert(d: int, pub: tuple) -> bytes:
    """A self-signed certificate that this verifier's own parser accepts.

    Minimal on purpose: exactly the shape `cert_parts` reads — a tbsCertificate whose
    SubjectPublicKeyInfo carries an uncompressed P-384 point, and a signature over that
    tbs made with the matching key. An attacker has no reason to send more than the
    verifier looks at.
    """
    import hashlib
    point = b"\x04" + pub[0].to_bytes(48, "big") + pub[1].to_bytes(48, "big")
    algid = _der(0x30, b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01")      # id-ecPublicKey
    spki = _der(0x30, algid + _der(0x03, b"\x00" + point))
    tbs = _der(0x30, _der_int(1) + spki)
    r, sg = _p384_sign(d, hashlib.sha384(tbs).digest())
    return _der(0x30, tbs + algid + _der(0x03, b"\x00" + _der(0x30, _der_int(r) + _der_int(sg))))


def _forged_attestation() -> tuple:
    """(base64 COSE_Sign1, the leaf certificate). Signed for real, chains to itself."""
    import base64, hashlib
    d_att = 0xA77AC4E12F9B3D7615C0E48A2B6D91F03E5C87A4D2B90F16E3C7A85B4D2F901E6C3A79B5
    pub = _p384_mul(d_att, (_P384_GX, _P384_GY))
    cert = _forged_cert(d_att, pub)
    prot = b"\xa1\x01\x38\x22"                                       # {1: -35} — ES384
    payload_bytes = (_cbor_head(5, 4)
                     + cbor_tstr("pcrs") + _cbor_head(5, 1) + _cbor_head(0, 0) + cbor_bstr(b"\xbb" * 48)
                     + cbor_tstr("public_key") + cbor_bstr(b"\x02" + b"\x11" * 32)
                     + cbor_tstr("certificate") + cbor_bstr(cert)
                     + cbor_tstr("cabundle") + _cbor_head(4, 1) + cbor_bstr(cert))
    sig_struct = b"\x84" + cbor_tstr("Signature1") + cbor_bstr(prot) \
        + cbor_bstr(b"") + cbor_bstr(payload_bytes)
    r, sg = _p384_sign(d_att, hashlib.sha384(sig_struct).digest())
    cose = (bytes([0x84]) + cbor_bstr(prot) + bytes([0xA0]) + cbor_bstr(payload_bytes)
            + cbor_bstr(r.to_bytes(48, "big") + sg.to_bytes(48, "big")))
    return base64.b64encode(cose).decode(), cert


# ── selftest: offline, and it FALSIFIES itself ───────────────────────────────
#
# A checker that only ever sees good input has not been tested — it has been
# demonstrated. So the selftest builds a receipt, signs it, confirms the check
# passes, and then breaks each guarded property in turn and requires the check to
# go red. If any tamper still passes, the corresponding guard is decorative.
def _sign_digest(pk: int, digest: bytes) -> dict:
    """Test-only ECDSA over secp256k1.

    The nonce is derived from the message, so two different digests never share one.
    That is not a stylistic point: ECDSA leaks the private key outright to anyone who
    sees two signatures made under the same k, by subtracting the two equations. The
    earlier version took a fixed k as an argument and the selftest passed the same one
    to four different receipts — harmless with a hardcoded test key, and exactly the
    shape a reader would copy into something that is not a test.

    Still not what real signing should use: RFC 6979 also mixes in the private key, so
    the nonce cannot be predicted from the message alone. This derivation is enough to
    keep the selftest honest and nothing more.
    """
    k = int.from_bytes(keccak256(digest + b"verify-receipt-yourself/selftest"), "big") % _N or 1
    z = int.from_bytes(digest, "big")
    R = _pt_mul(k, _G)
    r = R[0] % _N
    s = (pow(k, _N - 2, _N) * (z + r * pk)) % _N
    recid = (R[1] & 1) ^ (1 if s > _N // 2 else 0)
    if s > _N // 2:
        s = _N - s
    return {"r": "0x%064x" % r, "s": "0x%064x" % s, "v": 27 + recid}


def known_answer_vectors() -> int:
    """Check each primitive against a value this code did not produce.

    🔴 Why this runs before anything else. The rest of the selftest signs with the same
    keccak, the same canonical form and the same recovery code it then checks — so a
    primitive that is WRONG BUT SELF-CONSISTENT stays green forever while nothing real
    ever verifies. That is not hypothetical: `Sig_structure`'s first element was encoded
    as a byte string instead of a text string, one header byte, and every self-made test
    passed while every genuine AWS signature failed. It was caught only by a signature
    this code did not make.

    So: values from outside. Keccak-256 published digests, an Ethereum key/address pair
    from public test material, and the RFC 8785 key-ordering example.
    """
    bad = 0
    cases = [
        ("keccak256 of the empty string", keccak256(b"").hex(),
         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        ("keccak256 of 'abc'", keccak256(b"abc").hex(),
         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        ("address from a published private key",
         address_of_privkey("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"),
         "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"),
        # RFC 8785 sorts object keys by UTF-16 code unit, which is NOT byte order:
        # get it wrong and every signature over a multi-key object is wrong with it.
        ("canonical-v1 key order (RFC 8785)",
         canonical_v1({"\u20ac": "Euro", "\u05d3\u05bc": "Hebrew", "1": "One",
                       "\U0001f602": "Emoji"}).decode("utf-8"),
         '{"1":"One","\u05d3\u05bc":"Hebrew","\u20ac":"Euro","\U0001f602":"Emoji"}'),
    ]
    for name, got, want in cases:
        if got == want:
            print("  ok    %s" % name)
        else:
            print("  FAIL  %s\n        got  %s\n        want %s" % (name, got, want)); bad += 1
    return bad


def selftest() -> int:
    pk = 0xB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF
    addr = address_of_privkey("%064x" % pk)
    # The SIGNED payload is what the checks read now. The selftest supplies it
    # directly: a document that chains to the real AWS Nitro root cannot be
    # manufactured here, and pretending otherwise would be the very theatre this
    # script is against. The attestation layer is falsified separately, below.
    y2 = (pow(_pt_mul(pk, _G)[0], 3, _P) + 7) % _P  # noqa: F841  (kept for clarity)
    px, py = _pt_mul(pk, _G)
    payload = {"pcrs": {0: b"\xaa" * 48},
               "public_key": bytes([2 + (py & 1)]) + px.to_bytes(32, "big")}
    att = {"data_pubkey_address": addr}
    rec = {
        "v": "1", "decision": "deny", "reason_code": "notional_over_cap",
        "customer_id": "acme", "action": "sign_binance_order",
        "request_hash": "0x" + "11" * 32, "intent_sig_hash": "",
        "policy_hash": "0x" + "22" * 32, "supplied_ts_ms": "1757000000000",
        "boot_id": "boot-abc", "seq": "41",
    }
    rec["signature"] = _sign_digest(pk, receipt_digest(rec))
    hb_body = {"v": "1", "boot_id": "boot-abc", "customer_id": "acme",
               "seq_next": "42", "client_nonce": "n0"}
    hb_sig = _sign_digest(pk, keccak256(HEARTBEAT_DOMAIN + canonical_v1(
        {k: hb_body[k] for k in HEARTBEAT_SIGNED_FIELDS if k in hb_body})))
    hb = {"heartbeat": dict(hb_body, signature=hb_sig)}

    print("── primitives against values this code did not produce")
    fails_kav = known_answer_vectors()

    print("── the receipt as issued")
    base = check(payload, att, json.loads(json.dumps(rec)), hb, "notional_over_cap", "n0")
    fails = fails_kav
    if base.fail or base.skip:
        print("  FAIL  a well-formed receipt must verify cleanly")
        fails += 1

    def tamper(name: str, mutate, resign: bool = False) -> None:
        """`resign=True` re-signs the tampered receipt with the SAME attested key.

        🔴 This is the half that makes the selftest worth running. The signature
        covers every signed field, so a naive tamper is always caught BY THE
        SIGNATURE — and the seq / policy_hash / reason guards would never fire as
        the cause. They would look tested while never having been exercised.
        Re-signing removes the signature as the explanation and asks each guard to
        stand on its own. An attacker who holds the key is exactly the case those
        guards exist for.
        """
        nonlocal fails
        bad = json.loads(json.dumps(rec))
        mutate(bad)
        if resign:
            bad["signature"] = _sign_digest(pk, receipt_digest(bad))
        print("── tampered%s: %s" % (" and re-signed" if resign else "", name))
        rep = check(payload, att, bad, hb, "notional_over_cap", "n0")
        if rep.fail == 0:
            print("  FAIL  tampering with %s was NOT caught — that guard is decorative" % name)
            fails += 1
        elif resign:
            # And it must not be the signature doing the work: we re-signed it.
            print("        (caught with a VALID signature — the guard itself bit)")

    tamper("one byte of the signature",
           lambda d: d["signature"].__setitem__("r", d["signature"]["r"][:-1] + ("0" if d["signature"]["r"][-1] != "0" else "1")))
    tamper("seq (claims a decision that was never issued)", lambda d: d.__setitem__("seq", "99"))
    tamper("policy_hash (says no, but not against what)", lambda d: d.__setitem__("policy_hash", ""))
    tamper("policy_hash swapped for another policy", lambda d: d.__setitem__("policy_hash", "0x" + "33" * 32))
    tamper("reason_code (refusal relabelled)", lambda d: d.__setitem__("reason_code", "allow"))
    tamper("customer_id (receipt reused for another tenant)", lambda d: d.__setitem__("customer_id", "someone-else"))
    tamper("boot_id (receipt from a different enclave life)", lambda d: d.__setitem__("boot_id", "boot-xyz"))

    # The same tampering, but with a VALID signature: this is how each guard gets
    # tested on its own instead of the signature answering for all of them.
    tamper("seq, re-signed by the key holder", lambda d: d.__setitem__("seq", "99"), resign=True)
    tamper("policy_hash emptied, re-signed", lambda d: d.__setitem__("policy_hash", ""), resign=True)
    tamper("reason_code relabelled, re-signed", lambda d: d.__setitem__("reason_code", "allow"), resign=True)
    tamper("boot_id, re-signed", lambda d: d.__setitem__("boot_id", "boot-xyz"), resign=True)

    # ── the findings security reproduced against this script, each falsified ──
    def must_fail(name, fn):
        nonlocal fails
        print("── %s" % name)
        try:
            rep = fn()
            bad = rep.fail == 0 and rep.skip == 0
        except Exception as e:                                    # noqa: BLE001
            print("  ok    refused with: %s" % str(e)[:90]); return
        if bad:
            print("  FAIL  accepted — this guard is decorative"); fails += 1

    # C: malleability. (r, N-s, v^1) verifies to the same key; accepting it means two
    # byte-different receipts are both "authentic" records of one decision.
    def high_s():
        d = json.loads(json.dumps(rec))
        s_hi = _N - int(d["signature"]["s"], 16)
        d["signature"] = {"r": d["signature"]["r"], "s": "0x%064x" % s_hi,
                          "v": 27 if d["signature"]["v"] == 28 else 28}
        return check(payload, att, d, hb, "notional_over_cap", "n0")
    must_fail("high-s signature (malleable twin of a valid one)", high_s)

    # B: the gateway naming an address the enclave did not sign.
    print("── gateway reports an address the signed document does not")
    rep = check(payload, {"data_pubkey_address": "0x" + "11" * 20},
                json.loads(json.dumps(rec)), hb, "notional_over_cap", "n0")
    if rep.fail == 0:
        print("  FAIL  a lying gateway was accepted"); fails += 1

    # D: an unsigned heartbeat is the gateway's word, and a wrong nonce may be cached.
    print("── heartbeat with no signature")
    rep = check(payload, att, json.loads(json.dumps(rec)),
                {"heartbeat": {k: v for k, v in hb["heartbeat"].items() if k != "signature"}},
                "notional_over_cap", "n0")
    if rep.skip == 0 and rep.fail == 0:
        print("  FAIL  an unsigned heartbeat was taken on trust"); fails += 1

    print("── heartbeat echoing a different nonce")
    rep = check(payload, att, json.loads(json.dumps(rec)), hb, "notional_over_cap", "not-the-nonce-i-sent")
    if rep.fail == 0:
        print("  FAIL  a heartbeat that did not echo your nonce was accepted"); fails += 1

    # E: a receipt shape this script does not understand must not be waved through.
    print("── receipt of an unknown version")
    d = json.loads(json.dumps(rec)); d["v"] = "9"
    d["signature"] = _sign_digest(pk, receipt_digest(d))
    rep = check(payload, att, d, hb, "notional_over_cap", "n0")
    if rep.skip == 0 and rep.fail == 0:
        print("  FAIL  an unknown receipt version was accepted"); fails += 1

    # G: a lane that issues no receipts yet — no public_key in the signed document.
    print("── lane whose signed document carries no public_key")
    rep = check({"pcrs": {0: b"\xaa" * 48}}, att, json.loads(json.dumps(rec)), hb, None, "n0")
    if rep.skip == 0:
        print("  FAIL  a document with no public_key was treated as checkable"); fails += 1

    # A: a document forged end to end, and forged WELL. This is the finding that made
    # the first version of this script worthless: it never looked at the COSE document
    # at all, so an attacker's own attestation plus a receipt under their own key
    # printed VERIFIED.
    #
    # 🔴 The version after that fixed the script but not the test. It handed
    #    `verify_attestation` a stub — an empty CBOR map, a zero signature, the literal
    #    bytes `not-a-cert` — which died in the certificate parser, and the test called
    #    that "rejected". A parse error says nothing about the guard the test names.
    #    The document below is well-formed in every respect: a real P-384 key, a real
    #    self-signed certificate, a real COSE signature over the real payload bytes. It
    #    verifies perfectly against itself. The only thing that can refuse it is the
    #    pinned root — so the test asserts not merely that it went red, but WHICH check
    #    went red, and then proves the forgery was sound by pinning the attacker's own
    #    root and requiring the very same document to pass.
    global AWS_NITRO_ROOT_SHA256
    import hashlib
    forged_b64, forged_cert = _forged_attestation()

    print("── attestation forged whole (own key, own chain, valid signature)")
    r_fake = Report()
    try:
        got = verify_attestation(forged_b64, r_fake)
    except Exception as e:                                        # noqa: BLE001
        got = None
        r_fake.bad("forged attestation is rejected", "parse failed: %s" % e)
    if got is not None:
        print("  FAIL  a forged attestation document was accepted"); fails += 1
    elif not any("pinned AWS Nitro root" in w for w in r_fake.failed):
        print("  FAIL  the forgery was refused, but NOT by the root pin: %s" % r_fake.failed)
        fails += 1
    else:
        print("  ok    forged attestation refused by the pinned root")

    print("── the same forged document, with the attacker's own root pinned")
    real_root = AWS_NITRO_ROOT_SHA256
    AWS_NITRO_ROOT_SHA256 = hashlib.sha256(forged_cert).hexdigest()
    try:
        r_pin = Report()
        got2 = verify_attestation(forged_b64, r_pin)
    finally:
        AWS_NITRO_ROOT_SHA256 = real_root
    if got2 is None or r_pin.fail:
        print("  FAIL  the forgery is malformed, so the rejection above was the parser, "
              "not the pin (%s)" % r_pin.failed)
        fails += 1
    else:
        print("  ok    it passes once its own root is pinned — the document was sound,")
        print("        and the pin is what refused it")

    print()
    print("selftest: every guard bites" if fails == 0 else "selftest: %d GUARD(S) DECORATIVE" % fails)
    return 1 if fails else 0


def _load(path: str, what: str):
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            return json.load(fh)
    except Exception as e:                                        # noqa: BLE001
        # 2, not 1. "I could not read your file" is not "your receipt failed": exit 1
        # tells the reader the thing they hold is bad, when in fact nothing was checked.
        print("NOT CHECKED: cannot read %s (%s): %s" % (what, path, e))
        sys.exit(2)


def _load_obj(path: str, what: str):
    """`_load`, and the result must be a JSON object.

    🔴 Three different things must not print the same way, and the difference is the
    whole point of this script. "Your receipt does not hold up" is exit 1. "I could not
    check it" is exit 2. And "the file you handed me is not the thing you think it is"
    is also exit 2, but it has to SAY that — otherwise a reader who passed a JSON array
    by mistake reads `no attestation_doc_b64` and concludes the enclave failed to
    attest, or reads `the gateway refused` and concludes something about the gateway.
    Neither happened. Nothing was checked at all.
    """
    v = _load(path, what)
    if v is None or isinstance(v, dict):
        return v
    print("NOT CHECKED: %s (%s) is a JSON %s, not an object — this is about the file you"
          % (what, path, type(v).__name__))
    print("passed, not about the %s itself. Nothing was verified." % what)
    sys.exit(2)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="offline: sign a receipt, then tamper with it and require every guard to bite")
    at = sub.add_parser("attestation", help="check only the attestation document — chain, signature, measurement")
    at.add_argument("--attestation", required=True, help="JSON you fetched yourself from GET /attestation")
    at.add_argument("--nonce", help="the nonce you asked for; the signed document must echo it")
    v = sub.add_parser("verify", help="check a receipt you were handed")
    v.add_argument("--attestation", required=True, help="JSON you fetched yourself from GET /attestation")
    v.add_argument("--receipt", required=True, help="the receipt object from the response you were given")
    v.add_argument("--heartbeat", help="JSON from POST /receipts/heartbeat — proves the receipt is in the current chain")
    v.add_argument("--expect-reason", help="fail unless reason_code equals this")
    v.add_argument("--nonce", help="the client_nonce you sent to /receipts/heartbeat; the heartbeat must echo it")
    a = p.parse_args()

    if a.cmd == "selftest":
        return selftest()

    if a.cmd == "attestation":
        att = _load_obj(a.attestation, "attestation")
        doc = att.get("attestation_doc_b64")
        if not doc:
            print("NOT CHECKED: no attestation_doc_b64 in that file")
            return 2
        r = Report()
        payload = verify_attestation(doc, r)
        if payload is None:
            print("\nVERIFICATION FAILED: the document did not hold up")
            return 1
        pcr0 = (payload.get("pcrs") or {}).get(0)
        if isinstance(pcr0, (bytes, bytearray)):
            r.ok("measurement in the signed document: %s… (pin it out of band)" % pcr0.hex()[:16])
        if a.nonce:
            got = payload.get("nonce")
            got = got.hex() if isinstance(got, (bytes, bytearray)) else got
            if got == a.nonce:
                r.ok("the signed document echoes the nonce you asked for")
            else:
                r.bad("the signed document echoes the nonce you asked for",
                      "asked %r, document says %r — this may be a cached document" % (a.nonce, got))
        key = attested_signer(payload)
        if key:
            r.ok("receipt key in the signed document: %s" % key)
            claimed = (att.get("data_pubkey_address") or "").lower()
            if claimed and claimed != key:
                r.bad("the gateway agrees with the signed document",
                      "gateway says %s, document says %s" % (claimed, key))
        else:
            r.cant("this lane issues receipts",
                   "the signed document carries no public_key — no data key provisioned here")
        print()
        if r.fail: print("VERIFICATION FAILED"); return 1
        if r.skip: print("NOT FULLY CHECKED — this is not a pass"); return 2
        print("VERIFIED: this attestation document was issued by AWS Nitro and says what it says")
        return 0

    att = _load_obj(a.attestation, "attestation")
    rec = _load_obj(a.receipt, "receipt")
    if isinstance(rec, dict) and "receipt" in rec and isinstance(rec["receipt"], dict):
        rec = rec["receipt"]          # a whole response was passed; take the receipt out of it
    # 🔴 A refusal WITHOUT a receipt is not a failed verification — there is nothing to
    #    verify. Reporting it as FAILED would tell the reader the receipt is bad when
    #    the gateway simply did not issue one.
    if "signature" not in rec:
        print("NOT CHECKED: the response carries no receipt — the gateway refused before")
        print("the enclave decided, or this lane issues no receipts. Nothing to verify.")
        return 2

    print("── the attestation document")
    r0 = Report()
    doc = att.get("attestation_doc_b64")
    if not doc:
        r0.cant("attestation document present",
                "no attestation_doc_b64 — without the signed document there is nothing to "
                "bind the receipt key to, and the JSON fields beside it are the gateway's word")
        payload = {}
    else:
        try:
            payload = verify_attestation(doc, r0)
        except Exception as e:                                    # noqa: BLE001
            r0.bad("attestation document parses", "%s" % e)
            payload = None
        if payload is None:
            payload = {}
    print()
    rep = check(payload, att, rec,
                _load_obj(a.heartbeat, "heartbeat"), a.expect_reason, a.nonce)
    rep.fail += r0.fail
    rep.skip += r0.skip
    print()
    if rep.fail:
        print("VERIFICATION FAILED: %d check(s) did not hold" % rep.fail)
        return 1
    if rep.skip:
        print("NOT FULLY CHECKED: %d check(s) could not run — this is not a pass" % rep.skip)
        return 2
    print("VERIFIED: this receipt was signed by the key the enclave attests to, and it has not been altered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
