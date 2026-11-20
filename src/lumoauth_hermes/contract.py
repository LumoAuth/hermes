"""Access to the vendored LumoAuth Guard contract (catalog, presets, vectors).

The files under ``contract/`` are a byte-for-byte copy of the agent-guard
repository (``scripts/sync_contract.py``). They are read once and cached. The
test vectors are vendored under ``tests/contract/vectors``: they hold hostile
example commands, so they stay out of the installed package.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
CONTRACT_DIR = PACKAGE_DIR / "contract"
SKILL_PATH = PACKAGE_DIR / "skills" / "lumoauth-guard" / "SKILL.md"

HOST = "hermes"
RISKS = ("read", "write", "execute", "external", "destructive", "admin")


@cache
def load(relative: str) -> Any:
    """Parse one JSON file of the contract, for example ``catalog/hermes.json``."""
    return json.loads((CONTRACT_DIR / relative).read_text(encoding="utf-8"))


def host_catalog() -> dict[str, Any]:
    return load(f"catalog/{HOST}.json")


def capabilities_catalog() -> dict[str, Any]:
    return load("catalog/capabilities.json")


def mcp_verbs() -> dict[str, Any]:
    return load("catalog/mcp-verbs.json")


def presets() -> dict[str, Any]:
    return load("catalog/presets.json")


@cache
def host_capabilities() -> tuple[str, ...]:
    """Every capability that the host catalog names, in catalog order, without duplicates."""
    seen: dict[str, None] = {}
    for tool in host_catalog()["tools"]:
        seen.setdefault(tool["capability"], None)
    return tuple(seen)
