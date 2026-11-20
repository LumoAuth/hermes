"""SPEC §4.1a dispatcher tools, driven by the catalog's ``dispatcher`` field.

The Hermes catalog has no dispatcher today (Hermes unwraps its ``tool_call`` bridge before
pre_tool_call), so these tests add one to a copy of the catalog.
"""

from __future__ import annotations

import pytest

from conftest import vector_env
from helpers import call_kwargs, post_kwargs, set_up_guard
from lumoauth_hermes import classify as classify_module
from lumoauth_hermes import hard_rules
from lumoauth_hermes.canonical import arguments_sha256
from lumoauth_hermes.classify import classify
from lumoauth_hermes.runtime import PreDecisions
from mock_lumoauth import MockLumoAuth

WRAPPER = {"name": "run_tool", "capability": "tool:run_tool", "risk": "execute",
           "dispatcher": {"nameArgs": ["id", "name"], "argsArg": "args"}}


@pytest.fixture(autouse=True)
def dispatcher_catalog(monkeypatch):
    aliases, prefix, exact, prefixes = classify_module._catalog()
    patched = (aliases, prefix, {**exact, "run_tool": WRAPPER}, prefixes)
    monkeypatch.setattr(classify_module, "_catalog", lambda: patched)


@pytest.fixture
def mock():
    server = MockLumoAuth().start()
    yield server
    server.stop()


def test_wrapper_is_classified_as_the_dispatched_call():
    got = classify("run_tool", {"id": "read_file", "args": {"path": "notes.md"}}, vector_env())
    assert (got.tool, got.capability, got.risk, got.dispatchedBy) == ("read_file", "files:read", "read", "run_tool")
    assert got.paths == ["/home/ada/projects/site/notes.md"]
    mcp = classify("run_tool", {"name": "mcp__github__list_issues"}, vector_env())
    assert (mcp.capability, mcp.ingestsUntrusted, mcp.call_args) == ("mcp:github:read:list_issues", True, {})


def test_a_tool_search_id_is_reduced_to_the_tool_name():
    # SPEC §4.1a.4: the host runs and hooks openclaw:core:web_extract as web_extract.
    call = {"id": "openclaw:core:web_extract", "args": {"url": "https://example.com"}}
    got = classify("run_tool", call, vector_env())
    assert (got.tool, got.capability, got.dispatchedBy) == ("web_extract", "web:fetch", "run_tool")
    unresolvable = classify("run_tool", {"id": "core:"}, vector_env())
    assert (unresolvable.capability, unresolvable.risk) == ("tool:run_tool", "execute")


@pytest.mark.parametrize("args", [{"args": {}}, {"id": "  "}, {"id": 5},
                                  {"id": "run_tool", "args": {"id": "read_file", "args": {}}}])
def test_unresolvable_or_nested_wrapper_asks(args):
    got = classify("run_tool", args, vector_env())
    assert (got.tool, got.capability, got.risk, got.dispatchedBy) == ("run_tool", "tool:run_tool", "execute", None) \
        or (got.dispatchedBy == "run_tool" and got.capability == "tool:run_tool")


def test_hard_rules_apply_to_the_dispatched_call():
    env = vector_env()
    args = {"id": "read_file", "args": {"path": "~/.ssh/id_rsa"}}
    cls = classify("run_tool", args, env)
    result = hard_rules.evaluate(cls, cls.call_args, env)
    assert (result.rule, result.cls) == ("deny", "secrets")


def test_allowed_dispatch_leaves_one_single_use_pre_decision(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    inner = {"path": "notes.md"}
    wrapper_args = {"id": "read_file", "args": inner}
    assert s.guard.pre_tool_call(**call_kwargs("run_tool", wrapper_args, call_id="w1")) is None
    # The host runs the inner call through the hook too: allowed, no second receipt.
    assert s.guard.pre_tool_call(**call_kwargs("read_file", inner, call_id="i1")) is None
    s.guard.post_tool_call(**post_kwargs("read_file", inner, call_id="i1"))
    s.guard.post_tool_call(**post_kwargs("run_tool", wrapper_args, call_id="w1"))
    assert s.guard.flush()
    [receipt] = mock.state.receipts
    assert receipt["tool"] == "read_file" and receipt["arguments_sha256"] == arguments_sha256(inner)
    assert (receipt["decision"], receipt["outcome"]) == ("allowed", "succeeded")
    # Used once: the next direct call is decided (and receipted) on its own.
    assert s.guard.pre_tool_call(**call_kwargs("read_file", inner, call_id="i2")) is None
    s.guard.post_tool_call(**post_kwargs("read_file", inner, call_id="i2"))
    assert s.guard.flush()
    assert len(mock.state.receipts) == 2


def test_blocked_dispatch_leaves_no_pre_decision(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    result = s.guard.pre_tool_call(**call_kwargs("run_tool", {"id": "read_file", "args": {"path": "~/.ssh/k"}}))
    assert result["action"] == "block"
    assert s.guard.pre_tool_call(**call_kwargs("read_file", {"path": "~/.ssh/k"}))["action"] == "block"


def test_host_approved_dispatch_does_not_ask_twice(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    inner = {"command": "make test"}
    result = s.guard.pre_tool_call(**call_kwargs("run_tool", {"id": "terminal", "args": inner}, call_id="w1"))
    assert result["action"] == "approve" and "Capability: shell:exec" in result["message"]
    s.guard.post_approval_response(choice="once", pattern_key=f"plugin_rule:{result['rule_key']}",
                                   tool_call_id="w1")
    assert s.guard.pre_tool_call(**call_kwargs("terminal", inner, call_id="i1")) is None
    s.guard.post_tool_call(**post_kwargs("run_tool", {"id": "terminal", "args": inner}, call_id="w1"))
    assert s.guard.flush()
    [receipt] = mock.state.receipts
    assert (receipt["tool"], receipt["decision"], receipt["outcome"]) == ("terminal", "approved", "succeeded")


def test_refused_dispatch_leaves_no_pre_decision(tmp_path, mock):
    s = set_up_guard(tmp_path, mock)
    inner = {"command": "make test"}
    result = s.guard.pre_tool_call(**call_kwargs("run_tool", {"id": "terminal", "args": inner}, call_id="w1"))
    s.guard.post_approval_response(choice="deny", pattern_key=f"plugin_rule:{result['rule_key']}",
                                   tool_call_id="w1")
    assert s.guard.pre_tool_call(**call_kwargs("terminal", inner, call_id="i1"))["action"] == "approve"


def test_pre_decisions_expire_after_60_seconds():
    now = {"t": 0.0}
    store = PreDecisions(clock=lambda: now["t"])
    store.add(("s", "read_file", "x"))
    now["t"] = 61
    assert store.take(("s", "read_file", "x")) is False
    store.add(("s", "read_file", "x"))
    store.add(("s", "read_file", "x"))
    assert store.take(("s", "read_file", "x")) and store.take(("s", "read_file", "x"))
    assert not store.take(("s", "read_file", "x"))
    assert not store.take(("other-session", "read_file", "x"))
