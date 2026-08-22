#!/usr/bin/env python3
"""Guard the enclave's dependency closure — the part of Cargo.lock that is
INSIDE the measured image.

Why this exists (2026-08-20). The enclave Dockerfile copies the workspace
`Cargo.lock` into the builder and compiles `signer-enclave` from it, so every
crate in the enclave's transitive closure is an input to PCR0. Dependabot
bumps merged after the last measurement (anyhow 1.0.102→1.0.104, thiserror
1→2) changed that closure; a clean clone of HEAD then measured
`b502601b…` while the README still promised the production `32d25d8c…`
(measured on db68182). CI was green throughout, because it builds the
workspace, not the EIF. This check closes that gap without nitro-cli: it
recomputes the closure from Cargo.lock and compares it to the committed
snapshot that the published PCR0 was measured against.

Exit 0: closure identical to the snapshot (PCR0 inputs unchanged on the
lockfile axis). Exit 1: closure differs — the measured PCR0 no longer
describes this tree. The fix is NOT to edit the snapshot by hand: re-measure
on the build host, then update the snapshot header + README in the same PR.

Conservative by design: Cargo.lock carries no target information, so
platform-only crates (windows-*) are part of the closure too. A mismatch
caused only by those will re-measure to the SAME PCR0 — still update the
snapshot (with the same number) so the next diff is meaningful.

Usage:
  enclave-closure-check.py                # compare poc/Cargo.lock to snapshot
  enclave-closure-check.py --write        # regenerate snapshot body (keep header!)
  enclave-closure-check.py --lock <file>  # compare an arbitrary lockfile
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # poc/
DEFAULT_LOCK = ROOT / "Cargo.lock"
SNAPSHOT = ROOT / "enclave" / "DEPENDENCY-CLOSURE.lock"
ROOT_PACKAGE = "signer-enclave"


def parse_lock(text: str) -> dict[tuple[str, str], list[tuple[str, str | None]]]:
    """{(name, version): [(dep_name, dep_version_or_None), ...]}"""
    pkgs: dict[tuple[str, str], list[tuple[str, str | None]]] = {}
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        ver = re.search(r'^version = "([^"]+)"', block, re.M)
        if not name or not ver:
            continue
        deps: list[tuple[str, str | None]] = []
        m = re.search(r"^dependencies = \[(.*?)^\]", block, re.M | re.S)
        if m:
            for line in m.group(1).splitlines():
                line = line.strip().strip(",").strip('"')
                if not line:
                    continue
                parts = line.split()
                deps.append((parts[0], parts[1] if len(parts) > 1 else None))
        pkgs[(name.group(1), ver.group(1))] = deps
    return pkgs


def closure(pkgs, root_name: str) -> list[str]:
    by_name: dict[str, list[tuple[str, str]]] = {}
    for key in pkgs:
        by_name.setdefault(key[0], []).append(key)
    roots = by_name.get(root_name, [])
    if not roots:
        sys.exit(f"enclave-closure-check: package {root_name!r} not found in lockfile")
    seen: set[tuple[str, str]] = set()
    stack = list(roots)
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        for dep_name, dep_ver in pkgs.get(key, []):
            if dep_ver is not None:
                cands = [(dep_name, dep_ver)]
            else:
                cands = by_name.get(dep_name, [])
            for c in cands:
                if c in pkgs and c not in seen:
                    stack.append(c)
    return sorted(f"{n} {v}" for (n, v) in seen if n != root_name)


def read_snapshot(path: Path) -> tuple[list[str], list[str]]:
    header, body = [], []
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            header.append(line)
        elif line.strip():
            body.append(line.strip())
    return header, body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    ap.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    ap.add_argument("--write", action="store_true", help="rewrite the snapshot body from --lock (header kept)")
    args = ap.parse_args()

    current = closure(parse_lock(args.lock.read_text()), ROOT_PACKAGE)

    if args.write:
        header = read_snapshot(args.snapshot)[0] if args.snapshot.exists() else [
            "# Transitive dependency closure of signer-enclave, from poc/Cargo.lock.",
            "# Header lines (#) are maintained by hand: commit + measured PCR0 + host.",
        ]
        args.snapshot.write_text("\n".join(header) + "\n\n" + "\n".join(current) + "\n")
        print(f"enclave-closure-check: wrote {len(current)} entries to {args.snapshot}")
        return 0

    if not args.snapshot.exists():
        sys.exit(f"enclave-closure-check: snapshot {args.snapshot} missing")
    header, expected = read_snapshot(args.snapshot)
    if current == expected:
        print(f"enclave-closure-check: OK — {len(current)} crates, closure matches the measured snapshot")
        for h in header:
            if h.startswith("#   ") and ":" in h:
                print(f"  {h.lstrip('# ')}")
        return 0

    added = sorted(set(current) - set(expected))
    removed = sorted(set(expected) - set(current))
    print("enclave-closure-check: FAIL — the enclave's dependency closure changed since the measured snapshot.")
    print("  These crates are compiled INTO the measured image, so PCR0 of this tree is no longer the published one.")
    for r in removed:
        print(f"  - {r}")
    for a in added:
        print(f"  + {a}")
    print("  Fix: re-measure on the build host (SIGNER_REQUIRE_POLICY=1 ./scripts/build-eif.sh), then update")
    print("  enclave/DEPENDENCY-CLOSURE.lock (--write) AND its header AND the README numbers in the same PR.")
    print("  Do not edit the snapshot by hand to make CI green — that is exactly the drift this check exists to catch.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
