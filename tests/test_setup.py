"""``hermes lumoauth setup`` end to end against the mock, non-interactive; and the other CLI commands."""

from __future__ import annotations

import json

import pytest

from conftest import file_mode, read_json
from lumoauth_hermes import cli, jose
from lumoauth_hermes.config import GuardHome
from lumoauth_hermes.setup_flow import SetupIO, SetupOptions, checklist, parse_dashboard_url, run_setup
from mock_lumoauth import ORG, MockLumoAuth

CONFIG_YAML = """# My Hermes settings
model:
  default: some-model   # keep this comment
plugins:
  enabled: [other-plugin]
mcp_servers:
  github:
    command: github-mcp
  my-mail:
    url: https://mail.example.com/mcp
"""


@pytest.fixture
def mock():
    server = MockLumoAuth().start()
    yield server
    server.stop()


@pytest.fixture
def env(tmp_path, monkeypatch):
    guard = tmp_path / "home" / ".lumoauth" / "guard" / "hermes"
    hermes = tmp_path / "home" / ".hermes"
    hermes.mkdir(parents=True)
    (hermes / "config.yaml").write_text(CONFIG_YAML, encoding="utf-8")
    monkeypatch.setenv("LUMOAUTH_GUARD_HOME", str(guard))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    return GuardHome(guard), hermes


def _run(mock, env, **opts):
    home, hermes = env
    lines: list[str] = []
    io = SetupIO(out=lines.append, ask=lambda _q: "", interactive=False, sleep=lambda _s: None, hermes_home=hermes)
    options = SetupOptions(url=f"{mock.base}/orgs/{ORG}/portal", yes=True, **opts)
    code = run_setup(options, io, home)
    return code, "\n".join(lines)


def test_setup_enrolls_configures_hermes_and_self_tests(mock, env):
    home, hermes = env
    mock.state.enroll_polls.extend(["pending", "slow_down", "pending", "ok"])
    code, output = _run(mock, env, name="Hermes test")
    assert code == 0, output
    assert mock.state.errors == []
    # The four steps, with the user code and the key fingerprint.
    cfg = read_json(home.config_path)
    fingerprint = jose.fingerprint(cfg["keyId"])
    assert "BCDF-GHJK" in output and fingerprint in output and "/portal/agents/enroll?code=" in output
    # Files and modes.
    assert file_mode(home.config_path) == 0o600 and file_mode(home.key_path) == 0o600
    assert file_mode(home.path) == 0o700
    assert file_mode(home.path.parent.parent) == 0o700  # ~/.lumoauth
    assert cfg["agentId"] == "agt_0123456789abcdef" and cfg["orgId"] == ORG and cfg["approvals"] == "auto"
    assert cfg["canActOnBehalfOfUsers"] is True and cfg["preset"] == "assistant"
    # The enrollment request.
    [body] = mock.state.enrollments
    assert body["host"] == "hermes" and body["name"] == "Hermes test" and body["delegation"] is True
    assert set(body["jwks"]["keys"][0]) == {"kty", "crv", "x", "y", "kid", "use", "alg"}
    scopes = {c["scope"]: c["checked"] for c in body["capabilities"]}
    assert scopes["files:read"] is True and scopes["shell:exec"] is False and scopes["messages:send"] is False
    assert scopes["mcp:github:read:*"] is True and scopes["mcp:github:write:*"] is True
    assert scopes["mcp:my_mail:external:*"] is False, "server names as Hermes writes them in tool names"
    assert body["inventory"]["mcp_servers"] == [{"name": "github"}, {"name": "my_mail"}]
    # Hermes's config.yaml: plugin enabled, hook timeout raised, comments kept.
    text = (hermes / "config.yaml").read_text(encoding="utf-8")
    assert "# keep this comment" in text and "# My Hermes settings" in text
    assert "lumoauth" in text and "hook_callback_timeout: 180" in text
    # Self-test receipt.
    assert mock.state.receipts[0]["tool"] == "lumoauth.selftest"
    assert "Granted capabilities" in output


def test_setup_without_delegation_leaves_hook_timeout(mock, env):
    home, hermes = env
    mock.state.enroll_result["can_act_on_behalf_of_users"] = False
    code, output = _run(mock, env, approvals="host", preset="observer")
    assert code == 0, output
    assert mock.state.enrollments[0]["delegation"] is False
    assert "hook_callback_timeout" not in (hermes / "config.yaml").read_text(encoding="utf-8")


@pytest.mark.parametrize("step,message", [("denied", "refused"), ("expired", "expired")])
def test_setup_refused_or_expired_saves_nothing(mock, env, step, message):
    home, _ = env
    mock.state.enroll_polls.extend(["pending", step])
    code, output = _run(mock, env)
    assert code == 1 and message in output
    assert not home.config_path.exists() and not home.key_path.exists()


def test_setup_stops_on_fingerprint_mismatch(mock, env):
    home, _ = env
    mock.state.enroll_fingerprint_override = "AAAA-BBBB-CCCC-DDDD"
    code, output = _run(mock, env)
    assert code == 1 and "different key fingerprint" in output
    assert not home.key_path.exists()


def test_setup_stops_when_a_different_key_was_registered(mock, env):
    home, _ = env
    mock.state.enroll_result["key_id"] = "not-my-key"
    code, output = _run(mock, env)
    assert code == 1 and "different key" in output
    assert not home.config_path.exists()


def test_setup_refuses_to_overwrite(mock, env):
    assert _run(mock, env)[0] == 0
    code, output = _run(mock, env)
    assert code == 1 and "already set up" in output
    mock.state.used_jti.clear()
    assert _run(mock, env, force=True)[0] == 0


def test_setup_needs_an_address_when_not_interactive(env):
    home, hermes = env
    lines: list[str] = []
    code = run_setup(SetupOptions(yes=True), SetupIO(out=lines.append, interactive=False, hermes_home=hermes), home)
    assert code == 1 and "--url" in "\n".join(lines)


def test_setup_reports_server_validation_errors(mock, env, monkeypatch):
    monkeypatch.setattr("lumoauth_hermes.setup_flow.checklist", lambda preset, servers: [])
    code, output = _run(mock, env)
    assert code == 1 and "capabilities" in output


def test_parse_dashboard_url():
    assert parse_dashboard_url("https://app.lumoauth.dev/orgs/acme/portal") == ("https://app.lumoauth.dev", "acme")
    assert parse_dashboard_url("eu.app.lumoauth.dev/orgs/beta/portal/agents") == ("https://eu.app.lumoauth.dev",
                                                                                   "beta")
    assert parse_dashboard_url("https://app.lumoauth.dev/") == ("https://app.lumoauth.dev", None)
    with pytest.raises(Exception):
        parse_dashboard_url("http://example.com/orgs/x/portal")


def test_checklist_offers_every_catalog_capability():
    entries = checklist("builder", ["github"])
    scopes = [e["scope"] for e in entries]
    assert len(scopes) == len(set(scopes))
    assert "host:admin" in scopes and "shell:exec" in scopes
    assert all(e["checked"] is False for e in entries if e["scope"] in ("host:admin", "messages:send",
                                                                        "secrets:read", "skills:write"))
    assert [e["scope"] for e in entries if e["scope"].startswith("mcp:")] == [
        "mcp:github:read:*", "mcp:github:write:*", "mcp:github:external:*", "mcp:github:destructive:*",
        "mcp:github:execute:*", "mcp:github:admin:*"]


def test_cli_status_lock_unlock_reset(mock, env, capsys):
    home, _ = env
    assert _run(mock, env)[0] == 0
    assert cli.main(["status", "--json", "--offline"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["setUp"] is True and data["agentId"] == "agt_0123456789abcdef"
    assert "privateKey" not in json.dumps(data) and "BEGIN" not in json.dumps(data)
    assert cli.main(["status"]) == 0
    text = capsys.readouterr().out
    assert "Granted:" in text and "files:read" in text
    assert cli.main(["lock", "--reason", "away"]) == 0
    assert home.is_locked() and "away" in home.lock_path.read_text()
    assert cli.main(["unlock"]) == 0 and not home.is_locked()
    assert "Unlocked" in capsys.readouterr().out
    assert cli.main(["doctor", "--json", "--offline"]) == 0
    checks = {c["id"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["guard.setup"]["level"] == "ok"
    assert cli.main(["reset", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "stays in LumoAuth" in out and "/portal/agents/" in out
    assert not home.config_path.exists() and not home.key_path.exists()
    assert cli.main(["status", "--offline"]) == 1


def test_cli_reset_needs_confirmation_without_a_terminal(env, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["reset"]) == 1
    assert "--yes" in capsys.readouterr().out


def test_hermes_cli_registration_builds_the_same_tree():
    import argparse

    parser = argparse.ArgumentParser(prog="hermes lumoauth")
    cli.build_parser(parser)
    args = parser.parse_args(["setup", "--url", "https://app.lumoauth.dev/orgs/acme/portal", "--preset", "builder",
                              "--approvals", "host", "--yes", "--name", "x"])
    assert (args.lumoauth_command, args.la_preset, args.la_approvals, args.la_yes) == ("setup", "builder", "host",
                                                                                         True)
