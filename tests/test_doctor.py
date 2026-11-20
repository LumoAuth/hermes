"""Doctor checks (SPEC §9) on a temporary Hermes home."""

from __future__ import annotations

import os

import pytest

from lumoauth_hermes import doctor, keys
from lumoauth_hermes.config import GuardHome


def _inp(tmp_path, config_yaml: str = "", env: dict | None = None, dotenv: str = "", setup: dict | None = None):
    hermes = tmp_path / "hermes"
    hermes.mkdir(exist_ok=True)
    if config_yaml:
        (hermes / "config.yaml").write_text(config_yaml, encoding="utf-8")
        os.chmod(hermes / "config.yaml", 0o600)
    if dotenv:
        (hermes / ".env").write_text(dotenv, encoding="utf-8")
        os.chmod(hermes / ".env", 0o600)
    home = GuardHome(tmp_path / "guard")
    if setup is not None:
        key = keys.generate(home)
        home.write_config({"version": 1, "baseUrl": "https://app.lumoauth.dev", "orgId": "acme", "agentId": "agt_1",
                           "issuer": "https://app.lumoauth.dev/orgs/acme/api/v1",
                           "tokenEndpoint": "https://app.lumoauth.dev/orgs/acme/api/v1/oauth/token",
                           "keyId": key.kid, **setup})
    return doctor.gather(home, hermes, environ=env or {})


def _checks(inp) -> dict[str, doctor.Check]:
    return {c.id: c for c in doctor.run(inp=inp, offline=True)}


def test_every_required_check_is_present(tmp_path):
    ids = set(_checks(_inp(tmp_path)))
    assert {"guard.setup", "guard.connectivity", "guard.approvals", "guard.hook-timeout", "secrets.plaintext",
            "fs.permissions", "hermes.approvals-mode", "hermes.terminal-backend", "hermes.allowed-users",
            "hermes.approvers", "hermes.hook-timeout", "hermes.safe-mode"} <= ids


def test_not_set_up_is_critical(tmp_path):
    assert _checks(_inp(tmp_path))["guard.setup"].level == "critical"


def test_set_up_is_ok_and_permissions_are_checked(tmp_path):
    inp = _inp(tmp_path, setup={})
    assert _checks(inp)["guard.setup"].level == "ok"
    os.chmod(inp.home.key_path, 0o644)
    check = _checks(inp)["guard.setup"]
    assert check.level == "critical" and "chmod 600" in check.fix


def test_hermes_approvals_off_and_yolo_are_critical(tmp_path):
    checks = _checks(_inp(tmp_path, "approvals:\n  mode: off\n", setup={"approvals": "host"}))
    assert checks["hermes.approvals-mode"].level == "critical"
    assert checks["guard.approvals"].level == "critical"
    checks = _checks(_inp(tmp_path, "approvals:\n  mode: manual\n", env={"HERMES_YOLO_MODE": "1"}))
    assert checks["hermes.approvals-mode"].level == "critical"


def test_local_backend_warns_docker_is_ok(tmp_path):
    assert _checks(_inp(tmp_path, "terminal:\n  backend: local\n"))["hermes.terminal-backend"].level == "warn"
    assert _checks(_inp(tmp_path, "terminal:\n  backend: docker\n"))["hermes.terminal-backend"].level == "ok"


def test_gateway_allow_lists(tmp_path):
    assert _checks(_inp(tmp_path))["hermes.allowed-users"].level == "ok"
    checks = _checks(_inp(tmp_path, env={"TELEGRAM_BOT_TOKEN": "x"}))
    assert checks["hermes.allowed-users"].level == "info"
    assert "TELEGRAM_ALLOWED_USERS" in checks["hermes.allowed-users"].fix
    assert checks["hermes.approvers"].level == "warn"
    ok = _checks(_inp(tmp_path, "approvals:\n  approvers: []\n",
                      env={"TELEGRAM_BOT_TOKEN": "x", "TELEGRAM_ALLOWED_USERS": "123"}))
    assert ok["hermes.allowed-users"].level == "ok" and ok["hermes.approvers"].level == "ok"
    open_all = _checks(_inp(tmp_path, dotenv="GATEWAY_ALLOW_ALL_USERS=true\n"))
    assert open_all["hermes.allowed-users"].level == "critical"


def test_hook_timeout_needed_for_lumoauth_approvals(tmp_path):
    inp = _inp(tmp_path, "plugins:\n  hook_callback_timeout: 30\n", setup={"canActOnBehalfOfUsers": True})
    checks = _checks(inp)
    assert checks["guard.hook-timeout"].level == "warn" and checks["hermes.hook-timeout"].level == "warn"
    assert "hook_callback_timeout 180" in checks["hermes.hook-timeout"].fix
    inp = _inp(tmp_path, "plugins:\n  hook_callback_timeout: 180\n", setup={"canActOnBehalfOfUsers": True})
    assert _checks(inp)["hermes.hook-timeout"].level == "ok"
    inp = _inp(tmp_path, "plugins:\n  hook_callback_timeout: 30\n", setup={"approvals": "host"})
    assert _checks(inp)["hermes.hook-timeout"].level == "ok"


def test_plaintext_secrets_are_counted_never_printed(tmp_path):
    inp = _inp(tmp_path, "model:\n  api_key: sk-live-1234567890\n", dotenv="OPENAI_API_KEY=sk-abcdef123456\nX=1\n")
    check = _checks(inp)["secrets.plaintext"]
    assert check.level == "warn" and "1 value" in check.finding and "1 more" in check.finding
    rendered = doctor.format_text(doctor.run(inp=inp, offline=True))
    assert "sk-live" not in rendered and "sk-abc" not in rendered


def test_permissions_of_hermes_files(tmp_path):
    inp = _inp(tmp_path, dotenv="OPENAI_API_KEY=sk-abcdef123456\n")
    os.chmod(inp.hermes_home / ".env", 0o644)
    check = _checks(inp)["fs.permissions"]
    assert check.level == "critical" and ".env" in check.finding and "chmod 600" in check.fix


def test_safe_mode(tmp_path):
    assert _checks(_inp(tmp_path))["hermes.safe-mode"].level == "info"
    assert _checks(_inp(tmp_path, env={"HERMES_SAFE_MODE": "1"}))["hermes.safe-mode"].level == "critical"


@pytest.mark.parametrize("levels", [doctor.LEVELS])
def test_json_shape(tmp_path, levels):
    data = doctor.as_json(doctor.run(inp=_inp(tmp_path), offline=True))
    assert set(data["summary"]) == set(levels)
    assert all(set(c) == {"id", "level", "finding", "fix"} for c in data["checks"])
