#!/usr/bin/env python3
"""The README's receipt promise, held against the handlers that keep it.

🔴 Why. README.md said "Every signed call returns a Verifiable Policy Proof". Measured
2026-09-13: `/sign/data` is a signed call and returns none — the word `receipt` does not
appear once in `post_sign_data` (lines 898–1073). The claim was wider than the mechanism,
in the file a judge reads first, and nothing checked it, so it drifted quietly.

It also drifted in the other direction for a while inside my own head: I first reported
that no cancel route issues receipts, because I grepped `take_receipt` inside each handler
body and did not follow `sign_structured_request`, which calls it once for all six
structured callers. Checking a LIST OF PLACES instead of a PROPERTY is the same mistake
the claim itself made. So this test follows both paths to the receipt, not one.

What it enforces: the set of signing routes that carry a receipt, and the exception list
printed in the README, must agree. A new `/sign/…` route with no receipt fails here until
the README names it. Removing an exception from the README while the route still lacks a
receipt fails too.

Standard library only. No network, no gateway, no build.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HANDLERS = ROOT / "poc" / "gateway" / "src" / "handlers.rs"
README = ROOT / "README.md"

# Routes the promise is about: they ask the enclave to sign or decide. Reads, health,
# blob verification and the heartbeat are not "signed calls" and are out of scope —
# naming them here rather than leaving the scope to a reader's guess.
NOT_A_SIGNING_CALL = {
    "get_healthz", "post_verify_blob", "post_receipt_heartbeat",
    "get_attestation", "get_account", "get_open_orders", "get_user_trades",
}


def _functions(src_lines):
    """Every fn in the file, private ones included, mapped to its body.

    🔴 Cut at `mod tests` first. The LAST handler's body otherwise runs to EOF and
    swallows the test module, which mentions `sign_structured_request` twice — enough to
    classify `post_cancel_all` as carrying a receipt on the strength of test comments.
    Measured: its real body (3990–4102) contains neither marker. Raised by review on #100,
    and the parser was right about that route only by accident.
    """
    cut = next((i for i, l in enumerate(src_lines) if l.strip().startswith("mod tests")),
               len(src_lines))
    code = src_lines[:cut]
    sig = re.compile(r"^\s*(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
    starts = [(i, m.group(1)) for i, l in enumerate(code) if (m := sig.match(l))]
    out = {}
    for n, (i, name) in enumerate(starts):
        j = starts[n + 1][0] if n + 1 < len(starts) else len(code)
        out[name] = "\n".join(code[i:j])
    return out, [name for _, name in starts]


def _reaches_receipt(name, fns, seen=None):
    """Does this function reach `take_receipt`, directly or through what it calls?

    The receipt is reached by three different paths in this file — a direct call, the
    structured helper, and the account-read helper — and following only the first two is
    how I mis-reported cancels once already. So this walks the call graph instead of
    matching two names.
    """
    seen = seen or set()
    if name in seen or name not in fns:
        return False
    seen.add(name)
    body = fns[name]
    if "take_receipt(" in body:
        return True
    for callee in set(re.findall(r"\b([a-z][A-Za-z0-9_]*)\s*\(", body)):
        if callee != name and callee in fns and _reaches_receipt(callee, fns, seen):
            return True
    return False


def handlers_with_receipt():
    """(carries, lacks) — handler names, split by whether a receipt can reach a response."""
    src = HANDLERS.read_text(encoding="utf-8", errors="replace").splitlines()
    fns, order = _functions(src)
    handlers = [n for n in order if n.startswith(("post_", "get_"))
                and re.search(rf"pub async fn {re.escape(n)}\b", fns[n])]
    if not handlers:
        raise AssertionError(f"{HANDLERS}: no `pub async fn` handlers found — the file "
                             f"moved or changed shape, and this guard is checking nothing")
    carries, lacks = set(), set()
    for name in handlers:
        if name in NOT_A_SIGNING_CALL:
            continue
        (carries if _reaches_receipt(name, fns) else lacks).add(name)
    return carries, lacks


def exceptions_named_in_readme():
    """Handler names the README admits have no receipt — read from an explicit marker.

    🔴 NOT parsed out of the prose. The first version of this function looked for the
    route string near the words "no" and "receipt", and a mutation that deleted the
    exception from the page left it GREEN, because the route still appeared in a third
    sentence that happened to contain both words. A guard that guesses at English passes
    when it should not — which is the exact defect class this file exists to catch, so it
    had no business being inside it. The page now carries one machine-readable line and
    this reads that.
    """
    text = README.read_text(encoding="utf-8")
    if "Verifiable Policy Proof" not in text:
        raise AssertionError("README no longer mentions the Verifiable Policy Proof — if "
                             "the claim was dropped, retire this file rather than leaving "
                             "it green against nothing")
    m = re.search(r"<!--\s*receipt-exceptions:([^>]*?)-->", text)
    if not m:
        raise AssertionError(
            "README has no `<!-- receipt-exceptions: … -->` marker. The prose alone cannot "
            "be checked without guessing at English; add the marker next to the exception "
            "paragraph and keep the two in step.")
    return {w for w in m.group(1).split() if w.startswith("post_")}


class ReceiptClaimTest(unittest.TestCase):
    def test_readme_names_every_signing_route_that_has_no_receipt(self):
        carries, lacks = handlers_with_receipt()
        self.assertTrue(carries, "no handler carries a receipt — detection is broken, and "
                                 "a broken detector would pass every other case here")
        named = exceptions_named_in_readme()
        unnamed = lacks - named
        self.assertFalse(
            unnamed,
            f"these signing routes return no receipt and the README does not say so: "
            f"{sorted(unnamed)}. The promise would be wider than the mechanism — narrow "
            f"the claim or give the route a receipt.")

    def test_named_exceptions_are_really_exceptions(self):
        """An exception list that outlives the exception is its own kind of false claim."""
        carries, lacks = handlers_with_receipt()
        named = exceptions_named_in_readme()
        # /cancel-all reaches the helper, so it is listed for the SUCCESS branch only;
        # that branch is not visible to this parser, so it is allowed to appear in either
        # set. /sign/data must genuinely lack one.
        self.assertIn("post_sign_data", lacks,
                      "README names /sign/data as having no receipt, but the handler now "
                      "reaches one — remove the exception, do not leave the page claiming "
                      "a hole that was filled")
        self.assertIn("post_sign_data", named,
                      "the README stopped naming /sign/data while the route still has no "
                      "receipt")

    def test_the_money_path_all_carries_receipts(self):
        """The positive half: without it, deleting every receipt would pass the tests above."""
        carries, _ = handlers_with_receipt()
        for name in ["post_sign", "post_sign_binance_order", "post_sign_binance_cancel",
                     "post_sign_okx_order", "post_sign_okx_cancel",
                     "post_sign_binance_spot_order", "post_sign_binance_spot_cancel"]:
            with self.subTest(handler=name):
                self.assertIn(name, carries,
                              f"{name} no longer reaches a receipt — the money-path half "
                              f"of the README's promise is now false")


if __name__ == "__main__":
    unittest.main(verbosity=2)
