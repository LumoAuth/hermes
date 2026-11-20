"""JSON text that matches JavaScript's ``JSON.stringify`` (SPEC §7.4, §6.4).

``canonical_json`` sorts object keys at every level (by UTF-16 code units,
like ``Array.prototype.sort``), writes no whitespace and formats numbers and
strings the way ``JSON.stringify`` does, so that a receipt's
``arguments_sha256`` is the same in every plugin. ``compact_json`` keeps the
key order as given (used for approval text).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
_MAX_SAFE_INT = 2**53
_MAX_DEPTH = 200


def _js_string(value: str) -> str:
    text = json.dumps(value, ensure_ascii=False)
    # A Python str holds a lone surrogate as one code point; JSON.stringify escapes it.
    return _LONE_SURROGATE.sub(lambda m: f"\\u{ord(m.group(0)):04x}", text)


def js_number(value: float | int) -> str:
    """``Number.prototype.toString`` for a finite number (NaN and infinities become ``null``)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if -_MAX_SAFE_INT <= value <= _MAX_SAFE_INT:
            return str(value)
        value = float(value)
    if not math.isfinite(value):
        return "null"
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits, point = _shortest_digits(abs(value))
    k = len(digits)
    n = point  # value = 0.digits * 10**n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    exponent = n - 1
    mark = "+" if exponent >= 0 else "-"
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{sign}{mantissa}e{mark}{abs(exponent)}"


def _shortest_digits(value: float) -> tuple[str, int]:
    """Shortest round-trip digits of a positive float and the position of the decimal point."""
    text = repr(value)
    exponent = 0
    if "e" in text or "E" in text:
        mantissa, exp = text.lower().split("e")
        exponent = int(exp)
    else:
        mantissa = text
    if "." in mantissa:
        whole, frac = mantissa.split(".")
    else:
        whole, frac = mantissa, ""
    if frac == "0":
        frac = ""
    raw = whole + frac
    point = len(whole) + exponent
    stripped = raw.lstrip("0")
    point -= len(raw) - len(stripped)
    stripped = stripped.rstrip("0") or "0"
    return stripped, point


def _encode(value: Any, sort_keys: bool, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise ValueError("arguments are nested too deeply")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, dict):
        items = [(str(k), v) for k, v in value.items()]
        if sort_keys:
            items.sort(key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(f"{_js_string(k)}:{_encode(v, sort_keys, depth + 1)}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v, sort_keys, depth + 1) for v in value) + "]"
    return _js_string(str(value))


def canonical_json(value: Any) -> str:
    """Keys sorted at every level, no whitespace, ``JSON.stringify`` number and string forms."""
    return _encode(value, True, 0)


def compact_json(value: Any) -> str:
    """``JSON.stringify(value)``: key order as given, no whitespace."""
    return _encode(value, False, 0)


def arguments_sha256(arguments: Any) -> str:
    """Hex SHA-256 of the canonical JSON of a tool call's arguments."""
    data = canonical_json(arguments if arguments is not None else {}).encode("utf-8", "surrogatepass")
    return hashlib.sha256(data).hexdigest()
