"""The Hermes hooks end to end: register(ctx) with a fake ctx, the Guard against the mock LumoAuth."""

from __future__ import annotations

import pytest

import lumoauth_hermes
from helpers import FakeCtx, FakeHost, call_kwargs, post_kwargs, set_up_guard
from lumoauth_hermes.canonical import arguments_sha256
from lumoauth_hermes.guard import Guard
from lumoauth_hermes.status import chat_status, format_text, gather
from mock_lumoauth import MockLumoAuth


@pytest.fixture
def mock():
    server = MockLumoAuth().start()
    yield server
    server.stop()


def test_register_wires_hooks_commands_cli_and_skill(monkeypatch, tmp_path):
    monkeypatch.setenv("LUMOAUTH_GUARD_HOME", str(tmp_path / "guard"))
    ctx = FakeCtx()
    lumoauth_hermes.register(ctx)
    assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call", "post_approval_response", "post_api_request",
                              "on_session_start"}
    assert "lumoauth" in ctx.commands and "lumoauth" in ctx.cli
    assert ctx.skills["lumoauth-guard"].name == "SKILL.md"
    assert ctx.unload
    # Not set up: every call is blocked, with the setup command in the message.
    result = ctx.hooks["pre_tool_call"][0](**call_kwargs("read_file", {"path": "README.md"}))
    assert result["action"] == "block"
    assert "hermes lumoauth setup" in result["message"]


def test_slash_command_status_and_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("LUMOAUTH_GUARD_HOME", str(tmp_path / "guard"))
    ctx = FakeCtx()
    lumoauth_hermes.register(ctx)
    handler = ctx.commands["lumoauth"]["handler"]
    assert "not set up" in handler("")
    assert "locked" in handler("lock leaving for lunch")
    assert (tmp_path / "guard" / "lock").exists()
    assert "LOCKED" in handler("status")
    assert "terminal" in handler("unlock")
    assert (tmp_path / "guard" / "lock").exists(), "unlock is not possible from a chat"


def test_granted_call_is_allowed_and_receipt_completed(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    args = {"path": "notes.md"}
    assert s.guard.pre_tool_call(**call_kwargs("read_file", args)) is None
    s.guard.post_tool_call(**post_kwargs("read_file", args, duration_ms=840))
    assert s.guard.flush()
    [receipt] = mock.state.receipts
    assert receipt["tool"] == "read_file" and receipt["decision"] == "allowed"
    assert receipt["outcome"] == "succeeded" and receipt["duration_ms"] == 840
    assert receipt["arguments_sha256"] == arguments_sha256(args)
    assert mock.state.errors == []


def test_secret_read_is_blocked_whatever_the_grants(tmp_path, mock):
    mock.state.capabilities = ["*"]
    s = set_up_guard(tmp_path, mock)
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "~/.ssh/id_rsa"}))
    assert result["action"] == "block"
    assert "cannot be changed" in result["message"] and "credential store" in result["message"]
    assert s.guard.flush()
    [receipt] = mock.state.receipts
    assert (receipt["decision"], receipt["outcome"], receipt["error_code"]) == ("blocked", "not_run", "hard_rule")


def test_guard_files_and_hermes_config_are_blocked(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    for tool, args in (
        ("read_file", {"path": f"{s.env.guard_home}/agent-key.pem"}),
        ("write_file", {"path": f"{s.env.hermes_home}/config.yaml", "content": "plugins: {}"}),
        ("terminal", {"command": "hermes plugins disable lumoauth"}),
        ("execute_code", {"code": "import os; os.environ['HERMES_SAFE_MODE'] = '1'"}),
    ):
        result = s.guard.pre_tool_call(**call_kwargs(tool, args))
        assert result and result["action"] == "block", (tool, args)


def test_ungranted_call_asks_hermes_with_capability_rule_key(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "npm test"}))
    assert result["action"] == "approve"
    assert result["rule_key"] == "lumoauth:shell:exec"
    assert result["message"].startswith("Why: Not granted to this agent\nCapability: shell:exec\nRisk: execute")
    assert "command: npm test" in result["message"]
    # The person allowed it once: Hermes reports the answer, then the call runs.
    s.guard.post_approval_response(choice="once", pattern_key="plugin_rule:lumoauth:shell:exec",
                                   tool_call_id="call-1")
    s.guard.post_tool_call(**post_kwargs("terminal", {"command": "npm test"}))
    assert s.guard.flush()
    [receipt] = mock.state.receipts
    assert (receipt["decision"], receipt["outcome"]) == ("approved", "succeeded")


def test_refused_host_approval_is_recorded(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    args = {"command": "rm -rf build"}
    assert s.guard.pre_tool_call(**call_kwargs("terminal", args))["action"] == "approve"
    s.guard.post_approval_response(choice="deny", pattern_key="plugin_rule:lumoauth:shell:exec", tool_call_id="")
    s.guard.post_tool_call(**post_kwargs("terminal", args, status="blocked"))
    assert s.guard.flush()
    [receipt] = mock.state.receipts
    assert (receipt["decision"], receipt["outcome"]) == ("refused", "not_run")


def test_hermes_approvals_off_turns_approve_into_block(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, host=FakeHost(bypass="approvals.mode is off"))
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "ls"}))
    assert result["action"] == "block"
    assert "approvals.mode is off" in result["message"]
    assert "shell:exec" in result["message"], "says which capability to grant"
    assert s.guard.flush()
    assert mock.state.receipts[0]["decision"] == "denied"


def test_hard_rule_approval_never_remembered(tmp_path, mock):
    mock.state.capabilities = ["*"]
    s = set_up_guard(tmp_path, mock)
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": ".env"}))
    assert result["action"] == "approve"
    assert result["rule_key"].startswith("lumoauth:files:read:") and len(result["rule_key"]) > len(
        "lumoauth:files:read:")
    assert result["message"].startswith("Why: Touches something protected")


def test_remember_approvals_off_uses_random_rule_keys(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, rememberApprovals=False)
    first = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "ls"}))
    second = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "ls"}, call_id="call-2"))
    assert first["rule_key"] != second["rule_key"]


def test_taint_escalates_external_calls(tmp_path, mock):
    mock.state.capabilities = ["web:search", "mcp:gmail:external:*"]
    s = set_up_guard(tmp_path, mock)
    send = call_kwargs("mcp__gmail__send_email", {"to": "a@example.com"}, call_id="c2")
    assert s.guard.pre_tool_call(**send) is None, "granted and clean"
    assert s.guard.pre_tool_call(**call_kwargs("web_search", {"query": "news"}, call_id="c3")) is None
    result = s.guard.pre_tool_call(**call_kwargs("mcp__gmail__send_email", {"to": "a@example.com"}, call_id="c4"))
    assert result["action"] == "approve"
    assert result["message"].startswith("Why: After the agent read untrusted content")
    # Another session is not tainted.
    other = call_kwargs("mcp__gmail__send_email", {"to": "a@example.com"}, call_id="c5", session="s-2",
                        conversation="conv-2")
    assert s.guard.pre_tool_call(**other) is None


def test_taint_follows_the_conversation_across_session_rotation(tmp_path, mock):
    mock.state.capabilities = ["web:search", "messages:send"]
    s = set_up_guard(tmp_path, mock)
    s.guard.pre_tool_call(**call_kwargs("web_search", {"query": "x"}, session="s-old", conversation="conv-9"))
    result = s.guard.pre_tool_call(**call_kwargs("discord", {"message": "hi"}, session="s-new",
                                                 conversation="conv-9"))
    assert result["action"] == "approve"


def test_memory_write_after_untrusted_content_needs_approval(tmp_path, mock):
    mock.state.capabilities = ["web:fetch", "memory:write"]
    s = set_up_guard(tmp_path, mock)
    assert s.guard.pre_tool_call(**call_kwargs("memory", {"action": "add", "content": "x"})) is None
    s.guard.pre_tool_call(**call_kwargs("web_extract", {"urls": ["https://example.com"]}))
    assert s.guard.pre_tool_call(**call_kwargs("memory", {"action": "add", "content": "x"}))["action"] == "approve"


def test_lock_blocks_everything(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    s.home.lock("test")
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "notes.md"}))
    assert result["action"] == "block" and "hermes lumoauth unlock" in result["message"]
    s.home.unlock()
    assert s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "notes.md"})) is None


def test_suspended_agent_is_blocked(tmp_path, mock):
    mock.state.status = "suspended"
    s = set_up_guard(tmp_path, mock)
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "notes.md"}))
    assert result["action"] == "block" and "not active" in result["message"]
    # A hard-rule approval is not even offered while the agent is suspended (kill switch).
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": ".env"}))
    assert result["action"] == "block"


def test_unreachable_lumoauth_blocks_without_a_snapshot(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    mock.stop()
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "notes.md"}))
    assert result["action"] == "block" and "cannot confirm" in result["message"]


def test_offline_grace_keeps_the_last_snapshot(tmp_path, mock, monkeypatch):
    s = set_up_guard(tmp_path, mock)
    assert s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"})) is None
    mock.stop()
    snap = s.guard.snapshots.snapshot
    s.guard.snapshots.snapshot = type(snap)(snap.capabilities, snap.status, snap.agent_id, snap.fetched_at - 200,
                                            snap.fetched_wall)
    assert s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"})) is None, "within the grace period"
    s.guard.snapshots.snapshot = type(snap)(snap.capabilities, snap.status, snap.agent_id, snap.fetched_at - 400,
                                            snap.fetched_wall)
    s.guard.snapshots.last_attempt = 0
    assert s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"}))["action"] == "block"


def test_push_approval_approved(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, canActOnBehalfOfUsers=True)
    mock.state.approval_statuses.extend(["pending", "approved"])
    args = {"command": "make deploy"}
    assert s.guard.pre_tool_call(**call_kwargs("terminal", args)) is None
    [request] = mock.state.approvals
    assert request["task_id"] == "hermes-call-1"
    assert request["impact"] == "high" and request["on_behalf_of"]
    assert request["expires_in"] == 175  # the hook timeout (180) minus 5 s
    assert request["meta"] == {"kind": "tool_call", "host": "hermes", "tool": "terminal", "capability": "shell:exec",
                               "risk": "execute", "why": "Not granted to this agent", "title": "Allow terminal?",
                               "args": ["command: make deploy"], "arguments_sha256": arguments_sha256(args)}
    assert request["reason"].startswith("Why: Not granted to this agent")
    s.guard.post_tool_call(**post_kwargs("terminal", args))
    assert s.guard.flush()
    assert (mock.state.receipts[0]["decision"], mock.state.receipts[0]["outcome"]) == ("approved", "succeeded")


def test_push_approval_denied_and_expired(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, approvals="lumoauth", canActOnBehalfOfUsers=True)
    mock.state.approval_statuses.extend(["denied"])
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    assert result["action"] == "block" and "refused" in result["message"]
    mock.state.approval_statuses.extend(["expired"])
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}, call_id="c2"))
    assert result["action"] == "block" and "did not answer" in result["message"]
    assert s.guard.flush()
    assert [r["decision"] for r in mock.state.receipts] == ["refused", "expired"]


def test_push_polling_is_capped_by_the_hook_timeout(tmp_path, mock):
    clock = {"t": 0.0}
    s = set_up_guard(tmp_path, mock, approvals="lumoauth", canActOnBehalfOfUsers=True,
                     host=FakeHost(hook_timeout=30))
    import lumoauth_hermes.guard as guard_module

    real = guard_module.time.monotonic
    guard_module.time.monotonic = lambda: real() + clock["t"]
    try:
        def sleep(seconds):
            clock["t"] += seconds

        s.guard.sleep = sleep
        result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    finally:
        guard_module.time.monotonic = real
    assert result["action"] == "block"
    assert 20 <= clock["t"] <= 26, clock
    assert mock.state.approval_polls <= 13


@pytest.mark.parametrize("status", [202, 428, 403])
def test_push_unavailable_falls_back_to_host_in_auto(tmp_path, mock, status):
    s = set_up_guard(tmp_path, mock, canActOnBehalfOfUsers=True)
    mock.state.approval_create_status = status
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    assert result["action"] == "approve"


def test_push_unavailable_blocks_in_lumoauth_mode(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, approvals="lumoauth", canActOnBehalfOfUsers=True)
    mock.state.approval_create_status = 428
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    assert result["action"] == "block" and "LumoAuth app" in result["message"]


def test_approvals_off_blocks(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, approvals="off")
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    assert result["action"] == "block" and "switched off" in result["message"]
    assert "shell:exec" in result["message"]


def test_on_ungranted_block(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, onUngranted="block")
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    assert result["action"] == "block"
    assert "Ask the owner to add the capability `shell:exec`" in result["message"]
    assert "/portal/agents/" in result["message"]


def test_server_mode_uses_ask_with_audit_id(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, decisionMode="server")
    args = {"command": "ls"}
    assert s.guard.pre_tool_call(**call_kwargs("terminal", args)) is None
    assert mock.state.asks[0]["action"] == "shell:exec"
    assert mock.state.asks[0]["context"] == {"tool": "terminal", "server": None, "host": "hermes"}
    s.guard.post_tool_call(**post_kwargs("terminal", args))
    assert s.guard.flush()
    assert mock.state.receipts[0]["audit_id"] == "0123456789abcdef"
    # Cached for 30 s.
    s.guard.pre_tool_call(**call_kwargs("terminal", args, call_id="c2"))
    assert len(mock.state.asks) == 1


def test_server_mode_falls_back_to_snapshot_on_plan_limit(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, decisionMode="server")
    mock.state.ask_status = 403
    assert s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"})) is None  # files:read is in the snapshot
    assert s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "ls"}))["action"] == "approve"


def test_internal_error_fails_closed(tmp_path, mock, monkeypatch):
    s = set_up_guard(tmp_path, mock)
    monkeypatch.setattr("lumoauth_hermes.guard.classify", lambda *a, **k: 1 / 0)
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"}))
    assert result == {"action": "block", "message": "Blocked by LumoAuth Guard. The Guard could not check this call "
                                                    "(ZeroDivisionError), so it does not run."}


def test_corrupt_config_blocks(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    s.home.config_path.write_text("{not json", encoding="utf-8")
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"}))
    assert result["action"] == "block" and "not set up" in result["message"]


def test_key_mismatch_blocks(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, keyId="someone-elses-key")
    result = s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"}))
    assert result["action"] == "block" and "does not match" in result["message"]


def test_usage_is_reported(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"}))
    s.guard.post_api_request(usage={"total_tokens": 1200, "prompt_tokens": 1000})
    s.guard.post_api_request(usage={"total_tokens": 300})
    s.guard.post_api_request(usage=None)
    assert s.guard.flush()
    assert mock.state.usage == [1500]


def test_receipts_off_sends_nothing(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, receipts=False)
    s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"}))
    s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "~/.ssh/x"}))
    s.guard.flush()
    assert mock.state.receipts == []


def test_unfinished_call_is_sent_without_outcome(tmp_path, mock, monkeypatch):
    s = set_up_guard(tmp_path, mock)
    s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"}))
    import lumoauth_hermes.guard as guard_module

    real = guard_module.time.monotonic
    monkeypatch.setattr(guard_module.time, "monotonic", lambda: real() + 601)
    assert s.guard.flush()
    [receipt] = mock.state.receipts
    assert "outcome" not in receipt and receipt["decision"] == "allowed"


def test_mcp_filesystem_tool_cannot_read_guard_key(tmp_path, mock):
    mock.state.capabilities = ["*"]
    s = set_up_guard(tmp_path, mock)
    result = s.guard.pre_tool_call(**call_kwargs("mcp__filesystem__read_file",
                                                 {"path": f"{s.env.guard_home}/agent-key.pem"}))
    assert result["action"] == "block"


def test_shutdown_saves_unsent_receipts_for_the_next_process(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "~/.ssh/x"}))
    mock.state.receipt_responses.extend([503] * 10)
    s.guard.shutdown(timeout=1)
    assert s.home.queue_path.exists()
    fresh = Guard(home=s.home, host=s.host, env_provider=lambda: s.env, start_worker=True)
    fresh.ensure_worker()
    fresh._stop.set()
    mock.state.receipt_responses.clear()
    assert len(fresh.receipts) == 1
    assert fresh.flush()
    assert mock.state.receipts[0]["decision"] == "blocked"


def test_taint_approvals_are_never_remembered(tmp_path, mock):
    mock.state.capabilities = ["web:search", "mcp:gmail:external:*"]
    s = set_up_guard(tmp_path, mock)
    s.guard.pre_tool_call(**call_kwargs("web_search", {"query": "news"}))
    result = s.guard.pre_tool_call(**call_kwargs("mcp__gmail__send_email", {"to": "a@example.com"}, call_id="c2"))
    assert result["action"] == "approve"
    assert result["rule_key"].startswith("lumoauth:mcp:gmail:external:send_email:")


def test_push_network_error_falls_back_to_host_in_auto(tmp_path, mock, monkeypatch):
    s = set_up_guard(tmp_path, mock, canActOnBehalfOfUsers=True)
    assert s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "a"})) is None  # snapshot loaded

    from lumoauth_hermes.client import NetworkError

    def unreachable(*_a, **_k):
        raise NetworkError("cannot reach LumoAuth")

    monkeypatch.setattr(s.guard.client, "request_approval", unreachable)
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}, call_id="c2"))
    assert result["action"] == "approve"


@pytest.mark.parametrize("hook_timeout,expires_in", [(180, 175), (30, 60), (0, 600), (900, 600)])
def test_approval_expires_in_follows_the_polling_time(tmp_path, mock, hook_timeout, expires_in):
    s = set_up_guard(tmp_path, mock, approvals="lumoauth", canActOnBehalfOfUsers=True,
                     host=FakeHost(hook_timeout=hook_timeout))
    mock.state.approval_statuses.extend(["denied"])
    s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    assert mock.state.approvals[0]["expires_in"] == expires_in


def test_mcp_approval_meta_names_the_server_and_hides_secrets(tmp_path, mock):
    s = set_up_guard(tmp_path, mock, approvals="lumoauth", canActOnBehalfOfUsers=True)
    mock.state.approval_statuses.extend(["denied"])
    args = {"to": "alex@example.com", "api_key": "sk-123", "body": "line1\nline2"}
    s.guard.pre_tool_call(**call_kwargs("mcp__gmail__send_email", args))
    meta = mock.state.approvals[0]["meta"]
    assert (meta["server"], meta["tool"], meta["title"]) == ("gmail", "mcp__gmail__send_email",
                                                            "Allow send_email on gmail?")
    assert meta["args"] == ["api_key: [hidden]", "body: line1⏎line2", "to: alex@example.com"]
    assert "sk-123" not in str(mock.state.approvals[0])


@pytest.mark.parametrize("delivery,where", [(["push", "slack"], "the LumoAuth app and Slack"),
                                            (["slack"], "Slack"), (["push", "slack", "discord"],
                                                                   "the LumoAuth app, Slack and Discord"),
                                            (None, "LumoAuth"), (["pager"], "LumoAuth")])
def test_where_to_answer_is_shown_while_waiting_and_after(tmp_path, mock, delivery, where):
    s = set_up_guard(tmp_path, mock, approvals="lumoauth", canActOnBehalfOfUsers=True)
    mock.state.approval_delivery = delivery
    mock.state.approval_statuses.extend(["pending", "denied"])
    seen = []

    def sleep(_seconds):
        status = s.home.read_status() or {}
        seen.append([w["where"] for w in status.get("waiting", [])])
        seen.append(chat_status(s.guard, s.home))
        seen.append(format_text(gather(s.home, live=False)))

    s.guard.sleep = sleep
    result = s.guard.pre_tool_call(**call_kwargs("terminal", {"command": "x"}))
    assert result["action"] == "block" and f"refused it (asked in {where})" in result["message"]
    assert seen[0] == [where] and f"Waiting for approval in {where}: terminal." in seen[1]
    assert f"for approval in {where}: terminal (shell:exec)" in seen[2]
    assert (s.home.read_status() or {}).get("waiting") == []
