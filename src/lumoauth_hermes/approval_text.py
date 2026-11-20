"""Approval text (SPEC §6.4): built only from the classification and the arguments.

Never from the model's own explanation. ``vectors/approval-text.json`` is the
reference.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .canonical import compact_json

TITLE_LIMIT = 80
DESCRIPTION_LIMIT = 480
VALUE_LIMIT = 80
COMMAND_LIMIT = 240
MAX_ARGUMENT_LINES = 5

# Control characters and bidi/zero-width characters (the set that LumoAuth strips from untrusted
# text) become U+FFFD, so that model-chosen text cannot disguise itself (SPEC §6.4).
_DISGUISE = re.compile("[\x00-\x1f\x7f-\x9f\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064"
                       "\u2066-\u2069\ufeff]")
_HIDDEN_WORDS = ("password", "secret", "token", "key", "auth", "cookie", "credential")
IMPACT = {"read": "low", "write": "medium", "execute": "high", "external": "high", "destructive": "critical",
          "admin": "critical"}
SEVERITY = {"read": "info", "write": "info", "execute": "warning", "external": "warning", "destructive": "critical",
            "admin": "critical"}


@dataclass(frozen=True)
class ApprovalText:
    title: str
    description: str
    impact: str
    severity: str
    #: The argument lines alone (at most 5, cut, secrets hidden): ``meta.args`` of SPEC §7.5.
    arg_lines: tuple[str, ...] = ()


def cut(text: str, limit: int) -> str:
    """The first ``limit - 1`` characters and ``…`` when the text is longer than ``limit``."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _one_line(text: str) -> str:
    return text.replace("\r\n", "⏎").replace("\n", "⏎").replace("\r", "⏎")


def visible(text: str) -> str:
    """Replace control, bidi-override and zero-width characters with U+FFFD."""
    return _DISGUISE.sub("\ufffd", text)


def is_hidden_name(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in _HIDDEN_WORDS)


def _value_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return compact_json(value)
    except ValueError:
        return "…"


def argument_lines(args: dict[str, Any], command_args: Iterable[str] = (), command: str | None = None) -> list[str]:
    """Up to five ``name: value`` lines: command arguments first, then the others by name."""
    command_names = [n for n in command_args if n in args]
    if command is not None:
        command_names.extend(n for n, v in args.items() if v == command and n not in command_names)
    others = sorted((n for n in args if n not in command_names), key=lambda n: [ord(c) for c in n])
    lines: list[str] = []
    for name in command_names + others:
        if len(lines) >= MAX_ARGUMENT_LINES:
            break
        if is_hidden_name(name):
            lines.append(f"{name}: [hidden]")
            continue
        limit = COMMAND_LIMIT if name in command_names else VALUE_LIMIT
        lines.append(f"{name}: {cut(_one_line(_value_text(args[name])), limit)}")
    return lines


def build(
    *,
    tool: str,
    capability: str,
    risk: str,
    why: str,
    args: Any,
    server: str | None = None,
    mcp_tool: str | None = None,
    command_args: Iterable[str] = (),
    command: str | None = None,
    hard_rule: bool = False,
) -> ApprovalText:
    args = args if isinstance(args, dict) else {}
    title = f"Allow {mcp_tool} on {server}?" if server and mcp_tool else f"Allow {tool}?"
    arg_lines = [visible(line) for line in argument_lines(args, command_args, command)]
    lines = [f"Why: {why}", f"Capability: {capability}", f"Risk: {risk}"]
    lines.extend(arg_lines)
    return ApprovalText(
        title=cut(visible(title), TITLE_LIMIT),
        description=cut("\n".join(visible(line) for line in lines), DESCRIPTION_LIMIT),
        impact=IMPACT.get(risk, "high"),
        severity="critical" if hard_rule else SEVERITY.get(risk, "warning"),
        arg_lines=tuple(arg_lines),
    )
