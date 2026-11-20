#!/usr/bin/env python3
"""Copy the LumoAuth Guard contract from ../agent-guard into this package.

The contract (SPEC.md, the catalog, the test vectors and the lumoauth-guard
skill) lives in the agent-guard repository. This plugin ships a copy inside
the Python package so that it works without that repository; the vectors are
copied to tests/contract/vectors.

    python scripts/sync_contract.py           # copy
    python scripts/sync_contract.py --check   # exit 1 when the copy differs

The source is ../agent-guard next to this repository, or the directory named
by LUMOAUTH_AGENT_GUARD_DIR.
"""

from __future__ import annotations

import argparse
import filecmp
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "lumoauth_hermes"
CONTRACT = PACKAGE / "contract"
SKILLS = PACKAGE / "skills"
# The vectors hold hostile example commands: they live with the tests, outside the package,
# so that Hermes's install scan reads them as test fixtures.
VECTORS = ROOT / "tests" / "contract" / "vectors"


def source_dir() -> Path:
    override = os.environ.get("LUMOAUTH_AGENT_GUARD_DIR", "").strip()
    return Path(override).expanduser() if override else ROOT.parent / "agent-guard"


def contract_pairs(source: Path) -> list[tuple[Path, Path]]:
    """(source file, vendored file) for every file of the contract."""
    pairs = [(source / "SPEC.md", CONTRACT / "SPEC.md"), (source / "LICENSE", CONTRACT / "LICENSE")]
    for path in sorted((source / "catalog").glob("*.json")):
        pairs.append((path, CONTRACT / "catalog" / path.name))
    for path in sorted((source / "vectors").glob("*.json")):
        pairs.append((path, VECTORS / path.name))
    pairs.append((source / "skills" / "lumoauth-guard" / "SKILL.md", SKILLS / "lumoauth-guard" / "SKILL.md"))
    return pairs


def vendored_extras(source: Path) -> list[Path]:
    """Vendored contract files that no longer exist in the source."""
    expected = {dest for _src, dest in contract_pairs(source)}
    found = list((CONTRACT / "catalog").glob("*.json")) + list(VECTORS.glob("*.json"))
    return sorted(p for p in found if p not in expected)


def differences(source: Path) -> list[str]:
    """Human-readable list of differences between the source and the vendored copy."""
    problems = []
    for src, dest in contract_pairs(source):
        if not src.is_file():
            problems.append(f"missing in source: {src}")
        elif not dest.is_file():
            problems.append(f"not vendored: {dest.relative_to(ROOT)}")
        elif not filecmp.cmp(src, dest, shallow=False):
            problems.append(f"differs: {dest.relative_to(ROOT)}")
    problems.extend(f"no longer in source: {p.relative_to(ROOT)}" for p in vendored_extras(source))
    return problems


def sync(source: Path) -> int:
    for src, dest in contract_pairs(source):
        if not src.is_file():
            print(f"missing in source: {src}", file=sys.stderr)
            return 1
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
    for extra in vendored_extras(source):
        extra.unlink()
    print(f"Contract copied from {source}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="report differences and exit 1 when there are any")
    args = parser.parse_args(argv)
    source = source_dir()
    if not source.is_dir():
        print(f"agent-guard not found at {source}", file=sys.stderr)
        return 2
    if args.check:
        problems = differences(source)
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            print("Run: python scripts/sync_contract.py", file=sys.stderr)
            return 1
        print("Vendored contract matches agent-guard.")
        return 0
    return sync(source)


if __name__ == "__main__":
    sys.exit(main())
