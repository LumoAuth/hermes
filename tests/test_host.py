"""What the Guard reads from and writes to Hermes's config.yaml, without a Hermes install."""

from __future__ import annotations

import pytest

from lumoauth_hermes import hermes_host
from lumoauth_hermes.hermes_host import HermesHost, configure_hermes, hook_callback_timeout, read_config_file


@pytest.fixture
def no_hermes(monkeypatch):
    """Make sure Hermes's own modules are not used, even when they are importable."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.split(".")[0] in ("tools", "hermes_cli", "hermes_constants"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_auto_grant_from_config_and_env(tmp_path, monkeypatch, no_hermes):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    host = HermesHost()
    (tmp_path / "config.yaml").write_text("approvals:\n  mode: manual\n")
    assert host.auto_grant_reason() is None
    (tmp_path / "config.yaml").write_text("approvals:\n  mode: off\n")
    assert host.auto_grant_reason() == "approvals.mode is off"
    (tmp_path / "config.yaml").write_text("approvals:\n  mode: manual\n")
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    assert host.auto_grant_reason() == "yolo mode is on"


def _fake_hermes_approval(monkeypatch, config: dict, **attrs):
    """A stand-in for Hermes's tools.approval module, and Hermes's config as the Guard reads it."""
    import sys
    import types

    approval = types.ModuleType("tools.approval")
    for name, value in attrs.items():
        setattr(approval, name, value)
    package = types.ModuleType("tools")
    package.approval = approval  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "tools", package)
    monkeypatch.setitem(sys.modules, "tools.approval", approval)
    monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    monkeypatch.setattr(hermes_host, "load_config", lambda home=None: config)
    return HermesHost()


def _raise(*_args):
    raise RuntimeError("changed in this Hermes release")


def test_config_is_asked_first_whatever_hermes_internals_say(monkeypatch):
    host = _fake_hermes_approval(monkeypatch, {"approvals": {"mode": "off"}},
                                 is_approval_bypass_active=lambda: False, _yolo_active=lambda: False)
    assert host.auto_grant_reason() == "approvals.mode is off"
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    assert host.auto_grant_reason() == "yolo mode is on"


def test_hermes_public_bypass_check_sees_session_yolo(monkeypatch):
    host = _fake_hermes_approval(monkeypatch, {"approvals": {"mode": "manual"}},
                                 is_approval_bypass_active=lambda: True)
    assert host.auto_grant_reason() == "approvals are switched off"


def test_private_helpers_only_add_reasons(monkeypatch):
    manual = {"approvals": {"mode": "manual"}}
    # Missing or broken private helpers: the public sources still answer, nothing raises.
    assert _fake_hermes_approval(monkeypatch, manual, is_approval_bypass_active=lambda: False) \
        .auto_grant_reason() is None
    assert _fake_hermes_approval(monkeypatch, manual, is_approval_bypass_active=lambda: False,
                                 _yolo_active=_raise).auto_grant_reason() is None
    # hermes -z, and an unattended context in approve mode, are known only to the private helpers.
    assert _fake_hermes_approval(monkeypatch, manual, is_approval_bypass_active=lambda: False,
                                 _yolo_active=lambda: True).auto_grant_reason() == "yolo mode is on"
    cron = types_namespace(cfg_key="cron_mode", mode=lambda: "approve")
    host = _fake_hermes_approval(monkeypatch, manual, is_approval_bypass_active=lambda: False,
                                 _yolo_active=lambda: False, _presence=lambda: (None, False, False, False),
                                 _unattended_contexts=lambda: [cron])
    assert host.auto_grant_reason() == "approvals.cron_mode is approve"
    host = _fake_hermes_approval(monkeypatch, manual, is_approval_bypass_active=lambda: False,
                                 _yolo_active=lambda: False, _presence=lambda: (None, True, False, False),
                                 _unattended_contexts=lambda: [cron])
    assert host.auto_grant_reason() is None   # a person is at the terminal


def test_unreadable_config_blocks_unless_hermes_answers_itself(monkeypatch):
    def unreadable(home=None):
        raise hermes_host.HostConfigError("config.yaml is not valid YAML")

    host = _fake_hermes_approval(monkeypatch, {}, is_approval_bypass_active=_raise)
    monkeypatch.setattr(hermes_host, "load_config", unreadable)
    assert host.auto_grant_reason() == "Hermes's approval settings cannot be read"
    host = _fake_hermes_approval(monkeypatch, {}, is_approval_bypass_active=lambda: False)
    monkeypatch.setattr(hermes_host, "load_config", unreadable)
    assert host.auto_grant_reason() is None


def types_namespace(**values):
    import types

    return types.SimpleNamespace(**values)


def test_hook_timeout_from_config():
    assert hook_callback_timeout({}) == 30
    assert hook_callback_timeout({"plugins": {"hook_callback_timeout": 180}}) == 180
    assert hook_callback_timeout({"plugins": {"hook_callback_timeout": 0}}) == 0
    assert hook_callback_timeout({"plugins": {"hook_callback_timeout": 9999}}) == 600
    assert hook_callback_timeout({"plugins": {"hook_callback_timeout": "x"}}) == 30


@pytest.mark.parametrize("before,timeout,expected_timeout", [
    ("plugins:\n  hook_callback_timeout: 300\n", 180, 300),   # never lowered
    ("plugins:\n  hook_callback_timeout: 0\n", 180, 0),       # 0 means no limit: kept
    ("plugins:\n  hook_callback_timeout: 30\n", 180, 180),
    ("", 180, 180),
    ("plugins:\n  hook_callback_timeout: 30\n", None, 30),
])
def test_configure_hermes(tmp_path, before, timeout, expected_timeout):
    path = tmp_path / "config.yaml"
    if before:
        path.write_text("# keep me\n" + before)
    changes = configure_hermes(timeout, home=tmp_path)
    cfg = read_config_file(path)
    assert cfg["plugins"]["enabled"] == ["lumoauth"]
    assert cfg["plugins"].get("hook_callback_timeout", 30) == expected_timeout
    assert changes
    if before:
        assert path.read_text().startswith("# keep me")
    assert configure_hermes(timeout, home=tmp_path) == [], "a second run changes nothing"


def test_configure_hermes_removes_lumoauth_from_disabled(tmp_path):
    (tmp_path / "config.yaml").write_text("plugins:\n  enabled: [a]\n  disabled: [lumoauth, b]\n")
    configure_hermes(None, home=tmp_path)
    cfg = read_config_file(tmp_path / "config.yaml")
    assert cfg["plugins"] == {"enabled": ["a", "lumoauth"], "disabled": ["b"]}


def test_configure_hermes_refuses_broken_yaml(tmp_path):
    (tmp_path / "config.yaml").write_text("plugins: [unclosed\n")
    with pytest.raises(hermes_host.HostConfigError):
        configure_hermes(None, home=tmp_path)
    assert (tmp_path / "config.yaml").read_text() == "plugins: [unclosed\n"


def test_region_setup_needs_an_organization(tmp_path):
    from lumoauth_hermes.config import GuardHome
    from lumoauth_hermes.setup_flow import SetupIO, SetupOptions, run_setup

    lines: list[str] = []
    code = run_setup(SetupOptions(region="eu", yes=True),
                     SetupIO(out=lines.append, interactive=False, hermes_home=tmp_path), GuardHome(tmp_path / "g"))
    assert code == 1 and "--org" in "\n".join(lines)
