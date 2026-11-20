"""Capability matching, exactly as the LumoAuth server does it (SPEC §4.1).

``vectors/agent-capabilities.json`` is the reference: normalise both sides,
then an exact match, ``*``, or a ``<prefix>:*`` wildcard covers an action.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# PHP trim() default characters: space, tab, LF, CR, NUL, vertical tab.
_TRIM = " \t\n\r\x00\x0b"
_COLONS = re.compile(r":+")


def _ascii_lower(value: str) -> str:
    # PHP strtolower: A-Z only; other letters keep their case.
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in value)


def normalize(value: object) -> str:
    """Canonical form of a capability: ``Invoices.Read`` -> ``invoices:read``."""
    if not isinstance(value, str):
        return ""
    text = _ascii_lower(value.strip(_TRIM)).replace(".", ":")
    return _COLONS.sub(":", text).strip(":")


def covers(capability: object, action: object) -> bool:
    """True when ``capability`` allows ``action``."""
    cap = normalize(capability)
    act = normalize(action)
    if not cap or not act:
        return False
    if cap == "*" or cap == act:
        return True
    return cap.endswith(":*") and act.startswith(cap[:-1])


def any_covers(capabilities: Iterable[object], action: object) -> bool:
    return any(covers(cap, action) for cap in capabilities or ())
