"""Conformance against a real Hermes Agent (skipped when hermes-agent is not importable).

Modelled on hermes-agent's tests/plugins/conformance/test_plugin_surface_conformance.py:
the directory plugin is copied into a temporary HERMES_HOME, enabled in that
home's config.yaml and loaded by Hermes's own plugin manager; tool calls go
through ``model_tools.handle_function_call`` as the agent loop sends them.

Run it with a Python that has hermes-agent's dependencies, for example:

    PYTHONPATH=/path/to/hermes-agent /path/to/venv/bin/python -m pytest tests/test_real_hermes.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("hermes_cli.plugins")
pytest.importorskip("model_tools")

import hermes_yaml as yaml  # noqa: E402

from conftest import ROOT  # noqa: E402
from lumoauth_hermes import keys  # noqa: E402
from lumoauth_hermes.config import GuardHome  # noqa: E402
from mock_lumoauth import MockLumoAuth  # noqa: E402


def _install(home: Path) -> None:
    target = home / "plugins" / "lumoauth"
    target.mkdir(parents=True)
    for name in ("plugin.yaml", "__init__.py", "pyproject.toml", "README.md", "LICENSE"):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, target / name)
    shutil.copytree(ROOT / "src", target / "src", ignore=shutil.ignore_patterns("__pycache__"))


@pytest.fixture
def hermes(tmp_path, monkeypatch):
    from hermes_cli import plugins

    mock = MockLumoAuth().start()
    os_home = tmp_path / "home"
    project = os_home / "project"
    project.mkdir(parents=True)
    home = os_home / ".hermes"
    home.mkdir()
    _install(home)
    bundled = tmp_path / "no-bundled-plugins"
    bundled.mkdir()
    for name in ("LUMOAUTH_GUARD_HOME", "HERMES_YOLO_MODE", "HERMES_INTERACTIVE", "HERMES_GATEWAY_SESSION",
                 "HERMES_EXEC_ASK", "HERMES_SAFE_MODE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(os_home))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_BUNDLED_PLUGINS", str(bundled))
    monkeypatch.setenv("TERMINAL_CWD", str(project))
    monkeypatch.chdir(project)

    guard_home = GuardHome(os_home / ".lumoauth" / "guard" / "hermes")
    key = keys.generate(guard_home)
    mock.register_key(key.public_jwk, key.kid)
    guard_home.write_config(mock.config(key.kid, approvals="host"))
    mock.state.capabilities = ["files:read"]

    def load(approvals_mode: str = "manual") -> object:
        (home / "config.yaml").write_text(yaml.safe_dump({
            "plugins": {"enabled": ["lumoauth"], "hook_callback_timeout": 60},
            "approvals": {"mode": approvals_mode},
        }), encoding="utf-8")
        plugins._reset_plugin_managers_for_tests()
        plugins.discover_plugins()
        import lumoauth_hermes

        return plugins.get_plugin_manager(), lumoauth_hermes._guard

    yield load, mock, os_home, project
    plugins._reset_plugin_managers_for_tests()
    mock.stop()


def _call(tool: str, args: dict, call_id: str = "call-1") -> str:
    import model_tools

    return model_tools.handle_function_call(tool, args, task_id="task-1", session_id="session-1",
                                            tool_call_id=call_id, turn_id="turn-1", api_request_id="req-1")


def test_plugin_loads_with_hooks_commands_and_skill(hermes):
    load, _mock, _home, _project = hermes
    manager, guard = load()
    [row] = [p for p in manager.list_plugins() if p["name"] == "lumoauth"]
    assert row["enabled"] is True and not row.get("error"), row
    for hook in ("pre_tool_call", "post_tool_call", "post_approval_response", "post_api_request",
                 "on_session_start"):
        assert manager.has_hook(hook), hook
    assert "lumoauth" in manager._cli_commands
    assert any(key.endswith(":lumoauth-guard") for key in manager._plugin_skills)
    from hermes_cli.plugins import get_plugin_command_handler

    assert "LumoAuth Guard is on" in get_plugin_command_handler("lumoauth")("status")
    assert guard is not None


def test_secret_read_is_blocked(hermes):
    load, mock, os_home, _project = hermes
    load()
    (os_home / ".ssh").mkdir()
    (os_home / ".ssh" / "id_rsa").write_text("-----BEGIN PRIVATE KEY----- TOPSECRET")
    result = _call("read_file", {"path": "~/.ssh/id_rsa"})
    assert "Blocked by LumoAuth Guard" in result and "TOPSECRET" not in result, result


def test_granted_tool_runs_and_is_receipted(hermes):
    load, mock, _home, project = hermes
    _manager, guard = load()
    (project / "notes.md").write_text("hello from the guard test")
    result = _call("read_file", {"path": "notes.md"})
    assert "hello from the guard test" in result, result
    assert guard.flush()
    receipts = [r for r in mock.state.receipts if r["tool"] == "read_file"]
    assert receipts and receipts[-1]["decision"] == "allowed" and receipts[-1]["outcome"] == "succeeded"
    assert mock.state.errors == []


def test_ungranted_tool_gets_an_approve_directive(hermes):
    load, _mock, _home, _project = hermes
    load()
    from hermes_cli.plugins import get_pre_tool_call_directive

    action, message = get_pre_tool_call_directive("write_file", {"path": "out.txt", "content": "x"},
                                                  task_id="t", session_id="s", tool_call_id="c")
    assert action == "approve"
    assert message.startswith("Why: Not granted to this agent\nCapability: files:write")


def test_person_approves_once_then_the_tool_runs(hermes, monkeypatch):
    load, mock, _home, project = hermes
    _manager, guard = load()
    from tools.terminal_tool import set_approval_callback

    seen = []
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    set_approval_callback(lambda command, description, **kw: seen.append(description) or "once")
    try:
        result = _call("write_file", {"path": "out.txt", "content": "approved content"})
    finally:
        set_approval_callback(None)
    assert (project / "out.txt").read_text() == "approved content", result
    assert seen and "Capability: files:write" in seen[0]
    assert guard.flush()
    receipt = [r for r in mock.state.receipts if r["tool"] == "write_file"][-1]
    assert (receipt["decision"], receipt["outcome"]) == ("approved", "succeeded")


def test_person_refuses_and_the_tool_does_not_run(hermes, monkeypatch):
    load, mock, _home, project = hermes
    _manager, guard = load()
    from tools.terminal_tool import set_approval_callback

    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    set_approval_callback(lambda *a, **kw: "deny")
    try:
        result = _call("write_file", {"path": "refused.txt", "content": "x"})
    finally:
        set_approval_callback(None)
    assert not (project / "refused.txt").exists(), result
    assert guard.flush()
    receipt = [r for r in mock.state.receipts if r["tool"] == "write_file"][-1]
    assert (receipt["decision"], receipt["outcome"]) == ("refused", "not_run")


def test_no_person_present_means_blocked(hermes):
    load, _mock, _home, project = hermes
    load()
    result = _call("write_file", {"path": "nobody.txt", "content": "x"})
    assert not (project / "nobody.txt").exists()
    assert "no interactive user or gateway" in result, result


def test_hermes_approvals_off_makes_the_guard_block(hermes):
    load, _mock, _home, project = hermes
    load(approvals_mode="off")
    result = _call("write_file", {"path": "off.txt", "content": "x"})
    assert not (project / "off.txt").exists()
    assert "Blocked by LumoAuth Guard" in result and "without asking" in result, result


def test_hermes_cli_runs_the_lumoauth_command(hermes):
    load, _mock, os_home, _project = hermes
    load()
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    proc = subprocess.run([sys.executable, "-m", "hermes_cli.main", "lumoauth", "status", "--offline"],
                          env=env, capture_output=True, text=True, timeout=180, check=False)
    assert "Agent:" in proc.stdout and proc.returncode == 0, (proc.returncode, proc.stdout[-2000:],
                                                              proc.stderr[-2000:])
    proc = subprocess.run([sys.executable, "-m", "hermes_cli.main", "lumoauth", "doctor", "--json", "--offline"],
                          env=env, capture_output=True, text=True, timeout=180, check=False)
    checks = {c["id"]: c["level"] for c in json.loads(proc.stdout[proc.stdout.index("{"):])["checks"]}
    assert checks["guard.setup"] == "ok" and checks["hermes.approvals-mode"] == "ok", checks


def _entry_point_installed() -> bool:
    from importlib.metadata import entry_points

    return any(ep.name == "lumoauth" for ep in entry_points(group="hermes_agent.plugins"))


@pytest.mark.skipif(not _entry_point_installed(), reason="lumoauth-hermes is not pip-installed here")
def test_entry_point_plugin_loads_without_a_plugin_directory(hermes):
    load, _mock, os_home, _project = hermes
    shutil.rmtree(os_home / ".hermes" / "plugins" / "lumoauth")
    manager, _guard = load()
    [row] = [p for p in manager.list_plugins() if p["name"] == "lumoauth"]
    assert row["enabled"] is True and not row.get("error"), row
    (os_home / ".aws").mkdir()
    (os_home / ".aws" / "credentials").write_text("aws_secret_access_key = TOPSECRET")
    result = _call("read_file", {"path": "~/.aws/credentials"})
    assert "Blocked by LumoAuth Guard" in result and "TOPSECRET" not in result, result
