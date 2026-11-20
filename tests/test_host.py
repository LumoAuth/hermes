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
