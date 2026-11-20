"""Turn ``(tool name, arguments)`` into a classification (SPEC §4)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from . import contract
from .environment import Env
from .mcp_risk import mcp_risk
from .paths import resolve_path

_UNSAFE = re.compile(r"[^a-z0-9_-]")
# Hermes builds MCP names with this component rule (tools/mcp_tool_schema.py).
_HERMES_MCP_COMPONENT = re.compile(r"[^A-Za-z0-9_]")


def sanitize(name: str) -> str:
    """Lower-case; every character outside ``[a-z0-9_-]`` becomes ``_`` (SPEC §4.1)."""
    return _UNSAFE.sub("_", (name or "").lower())


def hermes_mcp_server_name(configured: str) -> str:
    """The server part that Hermes puts in ``mcp__<server>__<tool>`` for a configured server name."""
    return sanitize(_HERMES_MCP_COMPONENT.sub("_", configured or ""))


@dataclass
class Classification:
    tool: str
    capability: str
    risk: str
    ingestsUntrusted: bool = False
    persistsInstructions: bool = False
    egress: bool = False
    paths: list[str] = field(default_factory=list)
    command: str | None = None
    server: str | None = None
    mcpTool: str | None = None
    hardRule: str | None = None
    # Not part of the vectors: what the rules need from the catalog entry.
    raw_name: str = ""
    path_args: tuple[str, ...] = ()
    command_args: tuple[str, ...] = ()
    patch_args: tuple[str, ...] = ()
    catalogued: bool = False
    #: Every absolute form of every path (lexical and, when it differs, the real path).
    path_forms: list[str] = field(default_factory=list)
    #: SPEC §4.1a: the wrapper tool when this call came through a dispatcher, and the
    #: arguments of the dispatched call (what the rules, the approval text and the receipt use).
    dispatchedBy: str | None = None
    call_args: dict[str, Any] = field(default_factory=dict)

    @property
    def is_mcp(self) -> bool:
        return self.server is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "capability": self.capability, "risk": self.risk,
            "ingestsUntrusted": self.ingestsUntrusted, "persistsInstructions": self.persistsInstructions,
            "egress": self.egress, "paths": list(self.paths), "command": self.command, "server": self.server,
            "mcpTool": self.mcpTool, "hardRule": self.hardRule, "dispatchedBy": self.dispatchedBy,
        }


@lru_cache(maxsize=1)
def _catalog() -> tuple[dict[str, str], str, dict[str, dict[str, Any]], tuple[tuple[str, dict[str, Any]], ...]]:
    cat = contract.host_catalog()
    exact: dict[str, dict[str, Any]] = {}
    prefixes: list[tuple[str, dict[str, Any]]] = []
    for entry in cat["tools"]:
        name = entry["name"]
        if name.endswith("*"):
            prefixes.append((name[:-1], entry))
        else:
            exact[name] = entry
    prefixes.sort(key=lambda item: len(item[0]), reverse=True)
    mcp_prefix = cat.get("mcp", {}).get("prefix", "mcp__")
    return dict(cat.get("aliases", {})), mcp_prefix, exact, tuple(prefixes)


def catalog_entry(tool: str) -> dict[str, Any] | None:
    _aliases, _prefix, exact, prefixes = _catalog()
    entry = exact.get(tool)
    if entry is not None:
        return entry
    for prefix, candidate in prefixes:
        if tool.startswith(prefix):
            return candidate
    return None


def split_mcp_name(name: str) -> tuple[str, str] | None:
    """``mcp__<server>__<tool>`` -> ``(server, tool)``; the first ``__`` after the prefix splits."""
    _aliases, prefix, _exact, _prefixes = _catalog()
    if not prefix or not name.startswith(prefix):
        return None
    rest = name[len(prefix):]
    index = rest.find("__")
    if index <= 0 or index + 2 >= len(rest):
        return None
    return rest[:index], rest[index + 2:]


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value if isinstance(v, str)]
    return []


_PATCH_MARKERS = ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: ")


def patch_paths(patch: str) -> list[str]:
    """Paths named by an ``apply_patch`` patch or a unified diff, in order of first appearance."""
    found: list[str] = []
    for line in patch.splitlines():
        candidate: str | None = None
        for marker in _PATCH_MARKERS:
            if line.startswith(marker):
                candidate = line[len(marker):].strip()
                break
        else:
            if line.startswith("--- ") or line.startswith("+++ "):
                candidate = line[4:].split("\t")[0].strip()
                if candidate == "/dev/null":
                    candidate = None
                elif candidate.startswith(("a/", "b/")):
                    candidate = candidate[2:]
            elif line.startswith("diff --git "):
                for part in line[len("diff --git "):].split():
                    if part.startswith(("a/", "b/")) and part[2:] not in found:
                        found.append(part[2:])
        if candidate and candidate not in found:
            found.append(candidate)
    return found


def hard_rule_for(entry: dict[str, Any], args: dict[str, Any]) -> str | None:
    """The catalog's tool rule (SPEC §5.2): ``deny``, ``approve`` or None."""
    rule = entry.get("hardRule")
    if rule in ("deny", "approve"):
        return rule
    actions = entry.get("hardRuleActions")
    if not isinstance(actions, dict):
        return None
    value = args.get(actions.get("argument", "action"))
    value = value if isinstance(value, str) else None
    if "approve" in actions and value in actions["approve"]:
        return "approve"
    if "deny" in actions and value in actions["deny"]:
        return "deny"
    if actions.get("approveOtherwise") and value not in actions.get("allowWithoutHardRule", []):
        return "approve"
    return None


def workdir_for(classification: "Classification", args: dict[str, Any], env: Env) -> str:
    """The working directory of a shell or code tool: its ``workdir``/``cwd`` argument, else the host's."""
    for name in ("workdir", "cwd"):
        value = args.get(name)
        if isinstance(value, str) and value.strip():
            forms = resolve_path(value, env)
            if forms:
                return forms[0]
    return env.cwd


def canonical_tool_name(name: str) -> str:
    """A tool name after the catalog's aliases."""
    aliases, _prefix, _exact, _prefixes = _catalog()
    return aliases.get(name, name)


def dispatched_call(entry: dict[str, Any], args: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """``(tool name, arguments)`` of the call that a dispatcher tool runs, or None (SPEC §4.1a)."""
    spec = entry.get("dispatcher")
    if not isinstance(spec, dict):
        return None
    name = next((args[n] for n in spec.get("nameArgs", ()) if isinstance(args.get(n), str) and args[n].strip()),
                None)
    if name is None:
        return None
    inner = args.get(spec.get("argsArg", "args"))
    # SPEC §4.1a.4: a tool-search id such as ``openclaw:core:web_fetch`` names
    # the tool that the host runs (and hooks) as ``web_fetch``.
    name = name.strip().rsplit(":", 1)[-1].strip()
    if not name:
        return None
    return name, inner if isinstance(inner, dict) else {}


def classify(tool_name: str, args: Any, env: Env, *, _depth: int = 0) -> Classification:
    """The classification of one call (SPEC §4); a dispatcher is classified as the call it runs (§4.1a)."""
    args = args if isinstance(args, dict) else {}
    raw = tool_name if isinstance(tool_name, str) else ""
    tool = canonical_tool_name(raw)

    entry = catalog_entry(tool)
    if entry is not None and isinstance(entry.get("dispatcher"), dict):
        inner = dispatched_call(entry, args) if _depth == 0 else None
        if inner is None:
            # No resolvable tool name (or a dispatcher inside a dispatcher): an unknown tool, which asks.
            return Classification(tool=tool, capability=f"tool:{sanitize(tool)}", risk="execute", raw_name=raw,
                                  call_args=args)
        result = classify(inner[0], inner[1], env, _depth=_depth + 1)
        result.dispatchedBy = tool
        return result

    if entry is None:
        mcp = split_mcp_name(tool)
        if mcp is not None:
            server_raw, mcp_tool = mcp
            server = sanitize(server_raw)
            risk, ingests = mcp_risk(server_raw, mcp_tool)
            return Classification(
                tool=tool, capability=f"mcp:{server}:{risk}:{sanitize(mcp_tool)}", risk=risk,
                ingestsUntrusted=ingests, server=server, mcpTool=mcp_tool, raw_name=raw, call_args=args,
            )
        return Classification(tool=tool, capability=f"tool:{sanitize(tool)}", risk="execute", raw_name=raw,
                              call_args=args)

    path_args = tuple(entry.get("pathArgs", ()))
    command_args = tuple(entry.get("commandArgs", ()))
    patch_args = tuple(entry.get("patchArgs", ()))
    paths: list[str] = []
    forms: list[str] = []

    def add(raw_path: str) -> None:
        resolved = resolve_path(raw_path, env)
        if resolved and resolved[0] not in paths:
            paths.append(resolved[0])
        for form in resolved:
            if form not in forms:
                forms.append(form)

    for name in path_args:
        for value in _strings(args.get(name)):
            add(value)
    for name in patch_args:
        for value in _strings(args.get(name)):
            for named in patch_paths(value):
                add(named)

    command = None
    for name in command_args:
        value = args.get(name)
        if isinstance(value, str) and value.strip():
            command = value
            break

    return Classification(
        tool=tool, capability=entry["capability"], risk=entry["risk"],
        ingestsUntrusted=bool(entry.get("ingestsUntrusted")),
        persistsInstructions=bool(entry.get("persistsInstructions")),
        egress=bool(entry.get("egress")), paths=paths, command=command,
        hardRule=hard_rule_for(entry, args), raw_name=raw, path_args=path_args,
        command_args=command_args, patch_args=patch_args, catalogued=True, path_forms=forms, call_args=args,
    )
