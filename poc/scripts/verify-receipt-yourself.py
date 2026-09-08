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
    buf.append(0x01)                       # keccak-padding, НЕ 0x06 как в SHA3
    while len(buf) % rate:
        buf.append(0x00)
    buf[-1] |= 0x80
    for off in range(0, len(buf), rate):
        blk = buf[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(blk[i * 8:(i + 1) * 8], "little")
        _keccak_f(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


# ── secp256k1: восстановление открытого ключа из подписи ──────────────────
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
    """Восстановить точку открытого ключа — ровно так, как это делает площадка."""
    recid = v - 27 if v >= 27 else v
    if recid not in (0, 1, 2, 3):
        raise ValueError("недопустимый v=%r" % v)
    if not (1 <= r < _N and 1 <= s < _N):
        raise ValueError("r или s вне диапазона")
    x = r + (_N if recid >= 2 else 0)
    if x >= _P:
        raise ValueError("x вне поля")
    alpha = (pow(x, 3, _P) + 7) % _P
    beta = pow(alpha, (_P + 1) // 4, _P)
    if (beta * beta - alpha) % _P:
        raise ValueError("точка не на кривой")
    y = beta if (beta % 2) == (recid % 2) else _P - beta
    e = int.from_bytes(digest, "big")
    q = _pt_mul(pow(r, _N - 2, _N),
                _pt_add(_pt_mul(s, (x, y)), _pt_mul((-e) % _N, _G)))
    if q is None:
        raise ValueError("восстановление дало точку в бесконечности")
    return q



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


def recover_receipt_signer(receipt: dict) -> str:
    sig = receipt.get("signature") or {}
    for f in ("r", "s", "v"):
        if f not in sig:
            raise ValueError("receipt signature is missing '%s'" % f)
    digest = receipt_digest(receipt)
    pt = recover_pubkey(digest, int(sig["r"], 16), int(sig["s"], 16), int(sig["v"]))
    return address_of_point(pt)


# ── checks ───────────────────────────────────────────────────────────────────
class Report:
    def __init__(self):
        self.fail = 0
        self.skip = 0

    def ok(self, what: str) -> None:
        print("  ok    %s" % what)

    def bad(self, what: str, detail: str = "") -> None:
        print("  FAIL  %s%s" % (what, (" — " + detail) if detail else ""))
        self.fail += 1

    def cant(self, what: str, why: str) -> None:
        # Not a pass. A check you could not run is a hole, and calling it green is
        # how a watchdog becomes decorative.
        print("  ?     %s — NOT CHECKED: %s" % (what, why))
        self.skip += 1


def attested_signer(att: dict) -> str | None:
    a = att.get("data_pubkey_address")
    return a.lower() if isinstance(a, str) and a else None


def check(att: dict, receipt: dict, heartbeat: dict | None, expect_reason: str | None) -> Report:
    r = Report()

    # 1. Signed by the key the ENCLAVE attests to — the whole point.
    want = attested_signer(att)
    if not want:
        r.cant("receipt is signed by the attested key",
               "the attestation carries no data_pubkey_address; this lane issues no receipts, or you fetched the wrong document")
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

    # 2. Bound to the measurement of the lane you asked. We deliberately do NOT
    #    print an expected measurement here: a number written into a script is
    #    stale the day after a rotation, and a reader trusting it would compare
    #    against a value we no longer run — a mismatch that looks like THEIR error.
    pcr0 = att.get("pcr0_sha384") or att.get("pcr0")
    if isinstance(pcr0, str) and pcr0:
        r.ok("attestation carries a measurement (%s…) — pin it out-of-band, it is not asserted here" % pcr0[:8])
    else:
        r.cant("attestation carries a measurement", "no pcr0 field in the document you supplied")

    # 3. Continuity. A receipt proves one decision; the chain proves nobody quietly
    #    dropped decisions between them. `seq` counts per customer since `boot_id`,
    #    so a receipt from a DIFFERENT boot tells you the enclave restarted — which
    #    is not itself wrong, but it means the count you hold cannot be compared.
    if heartbeat is None:
        r.cant("receipt belongs to the current chain", "no heartbeat supplied (--heartbeat)")
    else:
        hb = heartbeat.get("heartbeat") or heartbeat
        hb_boot, seq_next = hb.get("boot_id"), hb.get("seq_next")
        if not hb_boot or seq_next is None:
            r.cant("receipt belongs to the current chain", "heartbeat has no boot_id/seq_next")
        elif hb_boot != receipt.get("boot_id"):
            r.bad("receipt belongs to the current chain",
                  "receipt boot_id %s, heartbeat %s — different boot, counts are not comparable"
                  % (receipt.get("boot_id"), hb_boot))
        else:
            try:
                if int(receipt["seq"]) < int(seq_next):
                    r.ok("receipt is inside the current chain (seq %s < next %s)" % (receipt["seq"], seq_next))
                else:
                    r.bad("receipt is inside the current chain",
                          "seq %s is not below next %s — the receipt claims a decision the enclave has not issued"
                          % (receipt["seq"], seq_next))
            except (TypeError, ValueError) as e:
                r.bad("receipt is inside the current chain", "seq/seq_next not decimal strings: %s" % e)

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


# ── selftest: offline, and it FALSIFIES itself ───────────────────────────────
#
# A checker that only ever sees good input has not been tested — it has been
# demonstrated. So the selftest builds a receipt, signs it, confirms the check
# passes, and then breaks each guarded property in turn and requires the check to
# go red. If any tamper still passes, the corresponding guard is decorative.
def _sign_digest(pk: int, digest: bytes, k: int) -> dict:
    """Test-only ECDSA. Fixed nonce `k` — fine here (one key, one message per run),
    NEVER acceptable for real signing: two signatures under one k leak the key."""
    z = int.from_bytes(digest, "big")
    R = _pt_mul(k, _G)
    r = R[0] % _N
    s = (pow(k, _N - 2, _N) * (z + r * pk)) % _N
    recid = (R[1] & 1) ^ (1 if s > _N // 2 else 0)
    if s > _N // 2:
        s = _N - s
    return {"r": "0x%064x" % r, "s": "0x%064x" % s, "v": 27 + recid}


def selftest() -> int:
    pk = 0xB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF
    addr = address_of_privkey("%064x" % pk)
    att = {"data_pubkey_address": addr, "pcr0_sha384": "a" * 96}
    rec = {
        "v": "1", "decision": "deny", "reason_code": "notional_over_cap",
        "customer_id": "acme", "action": "sign_binance_order",
        "request_hash": "0x" + "11" * 32, "intent_sig_hash": "",
        "policy_hash": "0x" + "22" * 32, "supplied_ts_ms": "1757000000000",
        "boot_id": "boot-abc", "seq": "41",
    }
    rec["signature"] = _sign_digest(pk, receipt_digest(rec), k=0x1234567890ABCDEF)
    hb = {"heartbeat": {"boot_id": "boot-abc", "seq_next": "42"}}

    print("── the receipt as issued")
    base = check(att, json.loads(json.dumps(rec)), hb, "notional_over_cap")
    fails = 0
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
            bad["signature"] = _sign_digest(pk, receipt_digest(bad), k=0x0FEDCBA987654321)
        print("── tampered%s: %s" % (" and re-signed" if resign else "", name))
        rep = check(att, bad, hb, "notional_over_cap")
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

    # The same tampering, но с ВАЛИДНОЙ подписью: так проверяется каждый страж
    # по отдельности, а не подпись за всех.
    tamper("seq, re-signed by the key holder", lambda d: d.__setitem__("seq", "99"), resign=True)
    tamper("policy_hash emptied, re-signed", lambda d: d.__setitem__("policy_hash", ""), resign=True)
    tamper("reason_code relabelled, re-signed", lambda d: d.__setitem__("reason_code", "allow"), resign=True)
    tamper("boot_id, re-signed", lambda d: d.__setitem__("boot_id", "boot-xyz"), resign=True)

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
        sys.exit("cannot read %s (%s): %s" % (what, path, e))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="offline: sign a receipt, then tamper with it and require every guard to bite")
    v = sub.add_parser("verify", help="check a receipt you were handed")
    v.add_argument("--attestation", required=True, help="JSON you fetched yourself from GET /attestation")
    v.add_argument("--receipt", required=True, help="the receipt object from the response you were given")
    v.add_argument("--heartbeat", help="JSON from POST /receipts/heartbeat — proves the receipt is in the current chain")
    v.add_argument("--expect-reason", help="fail unless reason_code equals this")
    a = p.parse_args()

    if a.cmd == "selftest":
        return selftest()

    att = _load(a.attestation, "attestation")
    rec = _load(a.receipt, "receipt")
    if isinstance(rec, dict) and "receipt" in rec and isinstance(rec["receipt"], dict):
        rec = rec["receipt"]          # a whole response was passed; take the receipt out of it
    rep = check(att, rec, _load(a.heartbeat, "heartbeat"), a.expect_reason)
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
