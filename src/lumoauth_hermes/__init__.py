"""LumoAuth Guard for Hermes Agent.

Every tool call that a Hermes agent makes is classified and allowed, sent to a
person for approval, or blocked, outside the model. Policy lives in LumoAuth.

Hermes loads this plugin as ``lumoauth`` (a directory plugin with
``plugin.yaml``, or the ``hermes_agent.plugins`` entry point) and calls
:func:`register`.
"""

from __future__ import annotations

import logging
from typing import Any

from ._version import __version__

__all__ = ["__version__", "register"]

logger = logging.getLogger("lumoauth_hermes")

SKILL_DESCRIPTION = ("Explains LumoAuth Guard, which checks every tool call this agent makes. Read it when a tool "
                     "call is blocked or waits for approval.")

_guard: Any | None = None


def register(ctx: Any) -> None:
    """Hermes plugin entry point: hooks first, then the commands and the skill."""
    global _guard
    from . import cli, status
    from .contract import SKILL_PATH
    from .guard import Guard

    guard = Guard()
    _guard = guard
    ctx.register_hook("pre_tool_call", guard.pre_tool_call)
    ctx.register_hook("post_tool_call", guard.post_tool_call)
    ctx.register_hook("post_approval_response", guard.post_approval_response)
    ctx.register_hook("post_api_request", guard.post_api_request)
    ctx.register_hook("on_session_start", guard.on_session_start)

    def slash(raw_args: str = "", **_: Any) -> str:
        words = (raw_args or "").split()
        action = words[0].lower() if words else "status"
        if action == "status":
            return status.chat_status(guard, guard.home)
        if action == "lock":
            guard.home.lock(" ".join(words[1:]) or "locked from a chat with /lumoauth lock")
            return "LumoAuth Guard is locked: every tool call is blocked until the owner runs " \
                   "`hermes lumoauth unlock` in a terminal."
        if action == "unlock":
            return "Unlocking is a terminal command for the owner: `hermes lumoauth unlock`."
        return "Usage: /lumoauth [status|lock [reason]]"

    for name, call in (
        ("command", lambda: ctx.register_command("lumoauth", handler=slash,
                                                 description="LumoAuth Guard: status, or lock every tool call",
                                                 args_hint="[status|lock]")),
        ("CLI command", lambda: ctx.register_cli_command(name="lumoauth", help="LumoAuth Guard: setup, status, "
                                                         "doctor, lock, unlock, reset", setup_fn=cli.build_parser,
                                                         handler_fn=cli.handle, description=cli.DESCRIPTION)),
        ("skill", lambda: ctx.register_skill("lumoauth-guard", SKILL_PATH, SKILL_DESCRIPTION)),
        ("unload callback", lambda: ctx.on_unload(guard.shutdown) if hasattr(ctx, "on_unload") else None),
    ):
        try:
            call()
        except Exception as exc:  # the hooks above are what protects; the rest is convenience
            logger.warning("LumoAuth Guard could not register its %s: %s", name, exc)
