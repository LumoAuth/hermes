"""Risk of an MCP tool from its server and tool names (SPEC §4.3, catalog/mcp-verbs.json)."""

from __future__ import annotations

import re
from functools import lru_cache

from . import contract

_SEPARATORS = re.compile(r"[_\-.\s]+")
# camelCase and acronym boundaries: "listIssues" -> list, Issues; "HTTPGet" -> HTTP, Get.
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z0-9])|[A-Z]?[a-z0-9]+|[A-Z]+|[^A-Za-z0-9]+")


def split_words(name: str) -> list[str]:
    """Lower-case words of a name, split at ``_ - .``, spaces and camelCase boundaries."""
    words: list[str] = []
    for part in _SEPARATORS.split(name or ""):
        if not part:
            continue
        for word in _CAMEL.findall(part):
            if word:
                words.append(word.lower())
    return words


@lru_cache(maxsize=1)
def _tables() -> tuple[tuple[str, ...], dict[str, frozenset[str]], frozenset[str], frozenset[str]]:
    data = contract.mcp_verbs()
    order = tuple(data["order"])
    verbs = {risk: frozenset(words) for risk, words in data["verbs"].items()}
    return order, verbs, frozenset(data["untrustedServerWords"]), frozenset(data["untrustedToolWords"])


def mcp_risk(server: str, tool: str) -> tuple[str, bool]:
    """``(risk, ingestsUntrusted)`` for MCP tool ``tool`` of server ``server``."""
    order, verbs, server_words, tool_words = _tables()
    words = split_words(tool)
    risk = "execute"
    for word in words:
        found = next((r for r in order if word in verbs.get(r, ())), None)
        if found is not None:
            risk = found
            break
    if risk in ("read", "write") and any(word in verbs.get("admin", ()) for word in words):
        risk = "admin"
    ingests = False
    if risk == "read":
        ingests = any(w in server_words for w in split_words(server)) or any(w in tool_words for w in words)
    return risk, ingests
