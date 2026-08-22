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


# A package is identified by (name, version, source). `source` is part of the
# identity on purpose: a `[patch]`/`replace` that swaps a registry crate for a
# git checkout, or bumps a git revision, keeps name+version and still changes
# the compiled enclave (CodeRabbit). Workspace members and path deps have no
# `source` line in Cargo.lock and are keyed as "path".
PkgKey = tuple[str, str, str]


def parse_lock(text: str) -> dict[PkgKey, list[tuple[str, str | None, str | None]]]:
    """{(name, version, source): [(dep_name, dep_version|None, dep_source|None), ...]}"""
    pkgs: dict[PkgKey, list[tuple[str, str | None, str | None]]] = {}
    # Split only at a `[[package]]` that starts a line — the literal could in
    # principle appear inside a string elsewhere in the file.
    for block in re.split(r"^\[\[package\]\]", text, flags=re.M)[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        ver = re.search(r'^version = "([^"]+)"', block, re.M)
        if not name or not ver:
            # Skipping would yield a PARTIAL closure, and --write would persist
            # it as the truth. Refuse (CodeRabbit).
            head = block.strip().splitlines()[0] if block.strip() else "<empty>"
            raise ValueError(f"malformed [[package]] entry (missing name/version) near: {head!r}")
        src_m = re.search(r'^source = "([^"]+)"', block, re.M)
        source = src_m.group(1) if src_m else "path"
        deps: list[tuple[str, str | None, str | None]] = []
        m = re.search(r"^dependencies = \[(.*?)^\]", block, re.M | re.S)
        if m:
            for raw in m.group(1).splitlines():
                entry = raw.strip().strip(",").strip('"')
                if not entry:
                    continue
                # forms: `name` | `name ver` | `name ver (source)`
                dm = re.match(r"^(\S+)(?: (\S+))?(?: \((.+)\))?$", entry)
                if not dm:
                    raise ValueError(f"unparseable dependency entry in Cargo.lock: {entry!r}")
                deps.append((dm.group(1), dm.group(2), dm.group(3)))
        pkgs[(name.group(1), ver.group(1), source)] = deps
    return pkgs


def closure(pkgs: dict[PkgKey, list], root_name: str) -> list[str]:
    by_name: dict[str, list[PkgKey]] = {}
    for key in pkgs:
        by_name.setdefault(key[0], []).append(key)
    roots = by_name.get(root_name, [])
    if not roots:
        raise ValueError(f"package {root_name!r} not found in lockfile")
    seen: set[PkgKey] = set()
    stack = list(roots)
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        for dep_name, dep_ver, dep_src in pkgs.get(key, []):
            cands = [
                k for k in by_name.get(dep_name, [])
                if (dep_ver is None or k[1] == dep_ver) and (dep_src is None or k[2] == dep_src)
            ]
            stack.extend(c for c in cands if c not in seen)
    return sorted(f"{n} {v} ({src})" for (n, v, src) in seen if n != root_name)


def read_snapshot(path: Path) -> tuple[list[str], list[str]]:
    header, body = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
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
    try:
        return run(args.lock, args.snapshot, args.write)
    except (ValueError, OSError) as e:
        # One controlled exit for both bad content and bad paths — never a
        # traceback from a CI gate (CodeRabbit).
        sys.exit(f"enclave-closure-check: {e}")


def run(lock: Path, snapshot: Path, write: bool) -> int:
    args = argparse.Namespace(lock=lock, snapshot=snapshot, write=write)
    current = closure(parse_lock(args.lock.read_text(encoding="utf-8")), ROOT_PACKAGE)

    if args.write:
        header = read_snapshot(args.snapshot)[0] if args.snapshot.exists() else [
            "# Transitive dependency closure of signer-enclave, from poc/Cargo.lock.",
            "# Header lines (#) are maintained by hand: commit + measured PCR0 + host.",
        ]
        args.snapshot.write_text("\n".join(header) + "\n\n" + "\n".join(current) + "\n", encoding="utf-8")
        print(f"enclave-closure-check: wrote {len(current)} entries to {args.snapshot}")
        return 0

    if not args.snapshot.exists():
        raise OSError(f"snapshot {args.snapshot} missing")
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
