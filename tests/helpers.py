"""Shared test helpers: a set-up Guard against the mock LumoAuth, and a fake Hermes ctx."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lumoauth_hermes import keys
from lumoauth_hermes.config import GuardHome
from lumoauth_hermes.environment import Env
from lumoauth_hermes.guard import Guard
from mock_lumoauth import MockLumoAuth


class FakeHost:
    """Stands in for Hermes's approval state and hook timeout."""

    def __init__(self, bypass: str | None = None, hook_timeout: float = 180.0) -> None:
        self.bypass = bypass
        self.timeout = hook_timeout

    def auto_grant_reason(self) -> str | None:
        return self.bypass

    def hook_timeout(self) -> float:
        return self.timeout


def make_env(root: Path) -> Env:
    home = root / "home"
    (home / "project").mkdir(parents=True, exist_ok=True)
    (home / ".hermes").mkdir(parents=True, exist_ok=True)
    return Env(home=str(home), hermes_home=str(home / ".hermes"), guard_home=str(home / ".lumoauth/guard/hermes"),
               cwd=str(home / "project"), plugin_dirs=(str(root / "plugin"),), hermes_root=str(home / ".hermes"))


@dataclass
class Setup:
    mock: MockLumoAuth
    env: Env
    home: GuardHome
    guard: Guard
    host: FakeHost
    key: keys.AgentKey


def set_up_guard(root: Path, mock: MockLumoAuth, *, host: FakeHost | None = None, configure: bool = True,
                 **config: Any) -> Setup:
    env = make_env(root)
    home = GuardHome(env.guard_home)
    key = keys.generate(home)
    mock.register_key(key.public_jwk, key.kid)
    if configure:
        home.write_config(mock.config(key.kid, **config))
    host = host or FakeHost()
    guard = Guard(home=home, host=host, env_provider=lambda: env, start_worker=False, sleep=lambda _s: None)
    return Setup(mock, env, home, guard, host, key)


@dataclass
class FakeCtx:
    """The parts of Hermes's PluginContext that the plugin uses."""

    hooks: dict[str, list[Callable[..., Any]]] = field(default_factory=dict)
    commands: dict[str, dict[str, Any]] = field(default_factory=dict)
    cli: dict[str, dict[str, Any]] = field(default_factory=dict)
    skills: dict[str, Path] = field(default_factory=dict)
    unload: list[Callable[[], None]] = field(default_factory=list)

    def register_hook(self, name: str, callback: Callable[..., Any], **_: Any) -> None:
        self.hooks.setdefault(name, []).append(callback)

    def register_command(self, name: str, handler: Callable[..., Any], description: str = "",
                         args_hint: str = "", **_: Any) -> None:
        self.commands[name] = {"handler": handler, "description": description, "args_hint": args_hint}

    def register_cli_command(self, name: str, help: str, setup_fn: Callable[..., Any],  # noqa: A002
                             handler_fn: Callable[..., Any] | None = None, description: str = "") -> None:
        self.cli[name] = {"help": help, "setup_fn": setup_fn, "handler_fn": handler_fn, "description": description}

    def register_skill(self, name: str, path: Path, description: str = "", **_: Any) -> None:
        if not Path(path).exists():
            raise FileNotFoundError(path)
        self.skills[name] = Path(path)

    def on_unload(self, callback: Callable[[], None]) -> None:
        self.unload.append(callback)


def call_kwargs(tool: str, args: dict[str, Any], *, call_id: str = "call-1", session: str = "s-1",
                conversation: str = "conv-1") -> dict[str, Any]:
    """The keyword arguments that Hermes passes to pre_tool_call (empty values are '')."""
    return {"tool_name": tool, "args": args, "task_id": "task-1", "session_id": session, "tool_call_id": call_id,
            "turn_id": "turn-1", "api_request_id": "req-1", "middleware_trace": [],
            "conversation_id": conversation, "telemetry_schema_version": 1}


def post_kwargs(tool: str, args: dict[str, Any], status: str = "ok", *, call_id: str = "call-1",
                session: str = "s-1", duration_ms: int = 12) -> dict[str, Any]:
    return {"tool_name": tool, "args": args, "result": "{}", "task_id": "task-1", "session_id": session,
            "tool_call_id": call_id, "turn_id": "turn-1", "api_request_id": "req-1", "conversation_id": "conv-1",
            "duration_ms": duration_ms, "status": status, "error_type": None if status == "ok" else "tool_error",
            "error_message": None, "middleware_trace": []}
