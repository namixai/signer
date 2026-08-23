#!/usr/bin/env python3
"""Tests for the ROT-8 stdin secret parser (vendor/kmstool-enclave-cli/secrets_stdin.h).

WHY THIS EXISTS AT ALL. The kmstool binary cannot be run on a normal host:
`aws_nitro_enclaves_library_init` and the entropy seed execute BEFORE argument
parsing and abort outside an enclave (measured 2026-08-09 during gate-0). So any
parsing logic added to that binary would otherwise ship having never executed
anywhere — the exact "second unverified path in vendored C" that got ROT-8
deferred once already. The parser is therefore plain C in a header with no SDK
types, and this file compiles it standalone and runs it.

WHAT IT PROTECTS. Fail-closed on every malformed stream: unknown key, duplicate
key, missing '=', over-long line, too many lines, empty value. And the property
that matters most for a secret reader — on ANY error the partially-filled struct
is wiped, so a caller that ignores the status cannot find a usable half-credential
in it.

Run: ``python3 test_secrets_stdin.py``   (needs a C compiler; skips loudly if absent)
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEADER_DIR = HERE.parent / "vendor" / "kmstool-enclave-cli"
HEADER = HEADER_DIR / "secrets_stdin.h"

# A harness that exercises the parser and prints a machine-readable summary.
# It also re-reads the freed slots' former contents is NOT possible in portable
# C, so the wipe-on-error property is asserted structurally: every error path
# must leave all four pointers NULL.
HARNESS = r"""
#include "secrets_stdin.h"

int main(void) {
    struct kmstool_stdin_secrets s;
    enum kmstool_stdin_status st = kmstool_stdin_read_secrets(stdin, &s);
    printf("status=%d (%s)\n", (int)st, kmstool_stdin_strerror(st));
    printf("access_key_id=%s\n", s.access_key_id ? s.access_key_id : "<null>");
    printf("secret_access_key=%s\n", s.secret_access_key ? s.secret_access_key : "<null>");
    printf("session_token=%s\n", s.session_token ? s.session_token : "<null>");
    printf("plaintext_b64=%s\n", s.plaintext_b64 ? s.plaintext_b64 : "<null>");
    kmstool_stdin_secrets_clean_up(&s);
    printf("after_cleanup_all_null=%d\n",
           (s.access_key_id == NULL && s.secret_access_key == NULL &&
            s.session_token == NULL && s.plaintext_b64 == NULL) ? 1 : 0);
    return 0;
}
"""

BIN: Path | None = None


def build() -> Path:
    cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise RuntimeError("no C compiler (cc/gcc/clang) — cannot test the parser")
    # Removed at exit rather than left behind: this runs in CI on every push, and
    # a harness binary per run adds up (Gemini, #417).
    tmp = Path(tempfile.mkdtemp(prefix="rot8-parser-"))
    atexit.register(shutil.rmtree, tmp, True)
    src = tmp / "harness.c"
    src.write_text(HARNESS)
    out = tmp / "harness"
    # -Wall -Wextra -Werror: the parser ships inside an enclave binary; a warning
    # here is a defect there, where nobody is watching the build output.
    # TWO standards on purpose:
    #   gnu99  — what the real build uses (see the compile line in the kmstool
    #            stage: `-std=gnu99 -Wall -Wextra -pedantic`). Testing under
    #            different flags than production tests a different program.
    #   c99    — strict ISO, where POSIX-only functions are NOT declared. This is
    #            the one that caught `strdup` in CI on 2026-08-09 while the Mac
    #            toolchain compiled it happily. Keeping it means the header stays
    #            free of assumptions about the includer's visibility macros.
    last = None
    try:
        subprocess.run([cc, "--version"], capture_output=True, check=True)
    except (FileNotFoundError, OSError, subprocess.CalledProcessError) as e:
        # A CC that does not exist must read like "no compiler", not like a
        # Python traceback — the operator's next step is the same either way.
        raise RuntimeError(f"C compiler {cc!r} is not usable: {e}") from e
    for std in ("-std=gnu99", "-std=c99"):
        out_std = out.with_name(f"harness{std.replace('-std=', '_')}")
        subprocess.run(
            [cc, std, "-Wall", "-Wextra", "-Werror", f"-I{HEADER_DIR}", str(src), "-o", str(out_std)],
            check=True, capture_output=True, text=True,
        )
        last = out_std
    assert last is not None
    return last


def run(payload: bytes) -> dict[str, str]:
    assert BIN is not None
    p = subprocess.run([str(BIN)], input=payload, capture_output=True, timeout=30)
    out = {}
    # Split on "\n" ONLY. `splitlines()` also breaks on \r, which would chop a
    # value containing a carriage return in half — and one of the cases below
    # deliberately feeds exactly that. The first version of this helper used
    # splitlines() and turned a passing parser into a failing test.
    for line in p.stdout.decode().split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


OK = "0 (ok)"


def test_all_four_keys_parse():
    r = run(
        b"AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n"
        b"AWS_SECRET_ACCESS_KEY=shhh\n"
        b"AWS_SESSION_TOKEN=tok\n"
        b"PLAINTEXT_B64=ZGVr\n"
    )
    assert r["status"] == OK, r
    assert r["access_key_id"] == "AKIAEXAMPLE", r
    assert r["secret_access_key"] == "shhh", r
    assert r["session_token"] == "tok", r
    assert r["plaintext_b64"] == "ZGVr", r


def test_order_does_not_matter_and_plaintext_is_optional():
    r = run(b"AWS_SESSION_TOKEN=tok\nAWS_ACCESS_KEY_ID=A\nAWS_SECRET_ACCESS_KEY=S\n")
    assert r["status"] == OK, r
    assert r["plaintext_b64"] == "<null>", "absent key must stay absent, not empty-string"


def test_missing_trailing_newline_is_accepted():
    """The last line without \\n is the normal shape of a piped write."""
    r = run(b"AWS_ACCESS_KEY_ID=A\nAWS_SECRET_ACCESS_KEY=S\nAWS_SESSION_TOKEN=T")
    assert r["status"] == OK, r
    assert r["session_token"] == "T", r


def test_value_may_contain_equals_and_spaces():
    """Split on the FIRST '=' — base64 padding and tokens carry '='."""
    r = run(b"PLAINTEXT_B64=ZGVr==\nAWS_ACCESS_KEY_ID=A\nAWS_SECRET_ACCESS_KEY=S\nAWS_SESSION_TOKEN=T\n")
    assert r["status"] == OK, r
    assert r["plaintext_b64"] == "ZGVr==", r


def test_crlf_writer_is_tolerated_at_line_end():
    r = run(b"AWS_ACCESS_KEY_ID=A\r\nAWS_SECRET_ACCESS_KEY=S\r\nAWS_SESSION_TOKEN=T\r\n")
    assert r["status"] == OK, r
    assert r["access_key_id"] == "A", "a trailing CR must not become part of the secret"


def test_embedded_cr_is_kept_not_repaired():
    """Edge-trim, never byte-delete — the same rule the deploy manifest learned."""
    r = run(b"AWS_ACCESS_KEY_ID=A\rB\nAWS_SECRET_ACCESS_KEY=S\nAWS_SESSION_TOKEN=T\n")
    assert r["status"] == OK, r
    assert r["access_key_id"] == "A\rB", "an embedded CR must survive so AWS rejects it"


# ── fail-closed cases ────────────────────────────────────────────────────────


def _assert_failed_and_wiped(r, expect: str):
    assert r["status"] != OK, f"must fail: {r}"
    assert expect in r["status"], r
    for k in ("access_key_id", "secret_access_key", "session_token", "plaintext_b64"):
        assert r[k] == "<null>", f"{k} survived an error path — half-credential: {r}"


def test_unknown_key_fails_and_wipes():
    _assert_failed_and_wiped(
        run(b"AWS_ACCESS_KEY_ID=A\nAWS_REGION=us-east-1\n"), "unknown key"
    )


def test_prefix_of_a_real_key_is_not_a_real_key():
    _assert_failed_and_wiped(
        run(b"AWS_SESSION_TOKEN_EXTRA=x\n"), "unknown key"
    )


def test_duplicate_key_fails_and_wipes():
    _assert_failed_and_wiped(
        run(b"AWS_ACCESS_KEY_ID=A\nAWS_ACCESS_KEY_ID=B\n"), "duplicate key"
    )


def test_line_without_equals_fails_and_wipes():
    _assert_failed_and_wiped(run(b"AWS_ACCESS_KEY_ID=A\ngarbage\n"), "no '='")


def test_empty_value_fails_and_wipes():
    """An empty secret would otherwise satisfy the 'was it provided' check."""
    _assert_failed_and_wiped(run(b"AWS_ACCESS_KEY_ID=\n"), "empty value")


def test_over_long_line_fails_and_wipes():
    payload = b"AWS_SESSION_TOKEN=" + b"x" * 9000 + b"\n"
    _assert_failed_and_wiped(run(payload), "exceeded the value cap")


def test_too_many_lines_fails_and_wipes():
    payload = b"".join(b"AWS_ACCESS_KEY_ID=A\n" for _ in range(20))
    r = run(payload)
    assert r["status"] != OK, r
    # Whichever guard fires first, both are fail-closed and both wipe.
    assert ("too many lines" in r["status"]) or ("duplicate key" in r["status"]), r
    for k in ("access_key_id", "secret_access_key", "session_token", "plaintext_b64"):
        assert r[k] == "<null>", r


def test_blank_lines_are_framing_not_data():
    r = run(b"\nAWS_ACCESS_KEY_ID=A\n\nAWS_SECRET_ACCESS_KEY=S\n\nAWS_SESSION_TOKEN=T\n")
    assert r["status"] == OK, r
    assert r["access_key_id"] == "A", r


def test_empty_stream_is_not_an_error_but_yields_nothing():
    """Truncation to zero must look like 'absent', which the caller refuses."""
    r = run(b"")
    assert r["status"] == OK, r
    for k in ("access_key_id", "secret_access_key", "session_token", "plaintext_b64"):
        assert r[k] == "<null>", r


def test_cleanup_nulls_every_slot():
    r = run(b"AWS_ACCESS_KEY_ID=A\nAWS_SECRET_ACCESS_KEY=S\nAWS_SESSION_TOKEN=T\n")
    assert r["after_cleanup_all_null"] == "1", r


def main() -> int:
    global BIN
    if not HEADER.exists():
        print(f"FATAL: {HEADER} not found", file=sys.stderr)
        return 2
    try:
        BIN = build()
    except RuntimeError as e:
        # A SKIP here means the ONLY test of the C parser silently did not run —
        # in CI that is a green tick over an unverified security path, which is
        # the exact always-green shape this repository keeps removing
        # (CodeRabbit, #417). Fail, unless a human explicitly opts out on a
        # machine that genuinely has no compiler.
        if os.environ.get("ALLOW_MISSING_CC") == "1":
            print(f"SKIP (ALLOW_MISSING_CC=1): {e}", file=sys.stderr)
            return 0
        print(f"FATAL: {e}", file=sys.stderr)
        print("       Set ALLOW_MISSING_CC=1 to skip deliberately.", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print("FATAL: the parser does not compile cleanly:", file=sys.stderr)
        print(e.stderr, file=sys.stderr)
        return 1
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
