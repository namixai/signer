#!/usr/bin/env python3
"""The shell recipes we hand a reviewer, held to their own behaviour.

🔴 Why this file exists, and it is not hypothetical. `jq` was used by the registry check
in BOTH copies of the recipe and declared in neither. Measured 2026-09-12 in a PATH
sandbox without it, our own script printed:

    nonce not echoed — document not bound to this request

A missing tool on the reviewer's machine made our script accuse OUR service of replaying
a document at them — the worst possible answer to give someone who came to check us. The
mechanism is the one we keep meeting: a failed command yields an empty string, the empty
string is compared, and the diagnostic decides the outcome.

The fix is a preflight that names the shortage, the way the shell's own
`cast: command not found` does. A test on the TEXT of that preflight would be worthless —
the next edit could reword it into uselessness and stay green. So this tests BEHAVIOUR:
run the recipe with jq removed from PATH and require that it names jq and says NOTHING
about the nonce.

Both copies are covered. They have drifted from each other before, and a guard on one is
a guard on one.

Standard library only, no network: the happy path runs against a stub `curl`.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RECIPES = {
    "docs/VERIFY-SIGNER-YOURSELF.md": "### 1.3",
    "README.md": "### How to verify",
}
# A real 96-hex measurement shape; the value itself is irrelevant to these tests.
FAKE_PCR0 = "ab" * 48
FAKE_RPC = ('{"jsonrpc":"2.0","result":"0x' + "0" * 63 + "1"
            + "0" * 24 + '21538ebf6598e5866ba496a954de8e39097bfb59","id":1}')


def extract_recipe(rel_path: str, anchor: str) -> str:
    """Pull the registry-check bash block out of the page. Ambiguity is a failure."""
    text = (ROOT / rel_path).read_text(encoding="utf-8")
    if anchor not in text:
        raise AssertionError(f"{rel_path}: anchor {anchor!r} is gone — the recipe moved "
                             f"and this guard is pointed at nothing")
    block = re.search(r"```bash\n(.*?)\n```", text[text.index(anchor):], re.S)
    if not block:
        raise AssertionError(f"{rel_path}: no bash block after {anchor!r}")
    return block.group(1)


def sandbox_bin(tmp: Path, *, with_jq: bool, with_curl_stub: bool) -> Path:
    """A PATH holding the usual tools, minus whatever this case is about."""
    d = tmp / "bin"
    d.mkdir()
    needed = ["sh", "bash", "od", "tr", "sed", "grep", "cat", "cut", "head", "tail",
              "env", "printf", "awk", "expr", "cast"]
    if with_jq:
        needed.append("jq")
    if not with_curl_stub:
        needed.append("curl")
    for tool in needed:
        real = shutil.which(tool)
        if real:
            (d / tool).symlink_to(real)
    if with_curl_stub:
        # Answers the attestation fetch with the nonce it was asked for, and the JSON-RPC
        # POST with a canned result. No network, and no dependence on a live endpoint.
        (d / "curl").write_text(
            "#!/bin/sh\n"
            "for a in \"$@\"; do\n"
            "  case \"$a\" in\n"
            "    *attestation?nonce=*)\n"
            f"      n=${{a##*nonce=}}\n"
            f"      printf '{{\"nonce\":\"%s\",\"pcr0_sha384\":\"{FAKE_PCR0}\"}}' \"$n\"\n"
            "      exit 0 ;;\n"
            "  esac\n"
            "done\n"
            f"printf '%s' '{FAKE_RPC}'\n"
        )
        (d / "curl").chmod(0o755)
    return d


def run_recipe(recipe: str, bindir: Path, tmp: Path):
    script = tmp / "recipe.sh"
    script.write_text(recipe + "\n")
    proc = subprocess.run(
        ["/bin/sh", str(script)],
        env={"PATH": str(bindir), "HOME": str(tmp), "LC_ALL": "C"},
        capture_output=True, text=True, timeout=60, cwd=str(tmp),
    )
    return proc.returncode, proc.stdout + proc.stderr


class JudgeRecipeTest(unittest.TestCase):
    def test_missing_jq_names_the_shortage(self):
        """Without jq: say it is jq. This is the finding, stated as a test."""
        for rel, anchor in RECIPES.items():
            with self.subTest(page=rel):
                recipe = extract_recipe(rel, anchor)
                self.assertIn("jq", recipe, f"{rel}: recipe no longer uses jq — if that is "
                                            f"deliberate, retire this case rather than "
                                            f"leaving it green against nothing")
                with tempfile.TemporaryDirectory() as td:
                    tmp = Path(td)
                    code, out = run_recipe(recipe, sandbox_bin(tmp, with_jq=False,
                                                               with_curl_stub=True), tmp)
                self.assertNotEqual(code, 0, f"{rel}: succeeded without jq\n{out}")
                self.assertRegex(out, r"jq",
                                 f"{rel}: refused without naming jq\n{out}")

    def test_missing_jq_does_not_accuse_the_service(self):
        """🔴 The actual defect: a missing local tool must not read as replay or forgery."""
        for rel, anchor in RECIPES.items():
            with self.subTest(page=rel):
                recipe = extract_recipe(rel, anchor)
                with tempfile.TemporaryDirectory() as td:
                    tmp = Path(td)
                    code, out = run_recipe(recipe, sandbox_bin(tmp, with_jq=False,
                                                               with_curl_stub=True), tmp)
                for word in ("nonce", "not bound", "replay"):
                    self.assertNotIn(
                        word, out.lower(),
                        f"{rel}: a missing jq produced {word!r} — that blames the service "
                        f"for the reviewer's missing tool, which is the whole reason this "
                        f"guard exists\n{out}")

    def test_with_jq_the_guard_does_not_fire(self):
        """A preflight that blocks the happy path would pass both tests above."""
        if not shutil.which("jq"):
            self.skipTest("jq is not installed on this machine; the negative cases above "
                          "still ran, but this positive control cannot")
        for rel, anchor in RECIPES.items():
            with self.subTest(page=rel):
                recipe = extract_recipe(rel, anchor)
                with tempfile.TemporaryDirectory() as td:
                    tmp = Path(td)
                    code, out = run_recipe(recipe, sandbox_bin(tmp, with_jq=True,
                                                               with_curl_stub=True), tmp)
                self.assertNotIn("jq is not installed", out,
                                 f"{rel}: the preflight fired with jq present\n{out}")
                self.assertNotIn("nonce not echoed", out,
                                 f"{rel}: the stub echoed the nonce and the recipe still "
                                 f"rejected it\n{out}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
