"""Conformance: every vector that applies to Hermes or is host-neutral (SPEC preamble)."""

from __future__ import annotations

import pytest

from conftest import vector_env, vectors
from lumoauth_hermes import approval_text, hard_rules
from lumoauth_hermes.capabilities import any_covers, covers, normalize
from lumoauth_hermes.classify import classify
from lumoauth_hermes.decide import DecisionConfig, SnapshotView, TaintPolicy, decide
from lumoauth_hermes.mcp_risk import mcp_risk

CAPS = vectors("agent-capabilities")


@pytest.mark.parametrize("case", CAPS["normalize"], ids=lambda c: repr(c["input"]))
def test_capability_normalize(case):
    assert normalize(case["input"]) == case["expected"]


@pytest.mark.parametrize("case", CAPS["covers"], ids=lambda c: f'{c["capability"]}~{c["action"]}')
def test_capability_covers(case):
    assert covers(case["capability"], case["action"]) is case["expected"]


@pytest.mark.parametrize("case", CAPS["any_covers"], ids=lambda c: c["action"])
def test_capability_any_covers(case):
    assert any_covers(case["capabilities"], case["action"]) is case["expected"]


@pytest.mark.parametrize("case", vectors("mcp-risk")["cases"], ids=lambda c: f'{c["server"]}/{c["tool"]}')
def test_mcp_risk(case):
    assert mcp_risk(case["server"], case["tool"]) == (case["risk"], case["ingestsUntrusted"])


_CLASSIFY = [c for c in vectors("classify")["cases"] if c["host"] == "hermes"]
_DEFAULTS = {"dispatchedBy": None, "ingestsUntrusted": False, "persistsInstructions": False, "egress": False,
             "paths": [],
             "command": None, "server": None, "mcpTool": None, "hardRule": None}


@pytest.mark.parametrize("case", _CLASSIFY, ids=lambda c: c["tool"])
def test_classify(case):
    got = classify(case["tool"], case["args"], vector_env()).as_dict()
    expected = {**_DEFAULTS, **case["expected"]}
    for key, value in expected.items():
        assert got[key] == value, (key, got)
    if "tool" not in case["expected"]:
        assert got["tool"] == case["tool"]


def test_classify_vectors_cover_hermes():
    assert len(_CLASSIFY) >= 13


_HARD = [c for c in vectors("hard-rules")["cases"] if c["host"] == "hermes"]


@pytest.mark.parametrize("case", _HARD, ids=lambda c: c["id"])
def test_hard_rules(case):
    env = vector_env()
    cls = classify(case["tool"], case["args"], env)
    result = hard_rules.evaluate(cls, case["args"], env, tainted=case.get("tainted", False))
    assert result.rule == case["expected"]["rule"], result
    if case["expected"]["rule"] is not None:
        assert result.cls == case["expected"]["class"], result


_DECIDE = vectors("decide")


def _config(raw: dict) -> DecisionConfig:
    taint = raw.get("taint", {"enabled": True, "windowSeconds": 1800, "escalate": ["external"]})
    return DecisionConfig(
        approvals=raw.get("approvals", "auto"),
        on_ungranted=raw.get("onUngranted", "ask"),
        refresh_seconds=raw.get("refreshSeconds", 60),
        offline_grace_seconds=raw.get("offlineGraceSeconds", 300),
        taint=TaintPolicy(taint["enabled"], taint["windowSeconds"], tuple(taint["escalate"])),
    )


@pytest.mark.parametrize("case", _DECIDE["cases"], ids=lambda c: c["id"])
def test_decide(case):
    state = {"locked": False, "setUp": True, **case.get("state", {})}
    if "snapshot" in case and case["snapshot"] is None:
        snapshot = None
    else:
        raw = {"status": "active", "ageSeconds": 10, "capabilities": [], **(case.get("snapshot") or {})}
        snapshot = SnapshotView(tuple(raw["capabilities"]), raw["status"], raw["ageSeconds"])
    c = case["classification"]
    decision = decide(
        capability=c["capability"], risk=c["risk"], egress=c.get("egress", False),
        persists_instructions=c.get("persistsInstructions", False), hard_rule=case.get("hardRule"),
        locked=state["locked"], set_up=state["setUp"], snapshot=snapshot, tainted=case.get("tainted", False),
        config=_config(case.get("config", {})),
    )
    assert (decision.outcome, decision.reason) == (case["expected"]["outcome"], case["expected"]["reason"])


def test_decide_receipt_decisions():
    blocked = decide(capability="x:y", risk="read", locked=True)
    denied = decide(capability="x:y", risk="read", snapshot=SnapshotView(), config=DecisionConfig(on_ungranted="block"))
    assert blocked.receipt_decision == "blocked"
    assert denied.receipt_decision == "denied"


def test_decide_reason_texts_match_the_vectors():
    from lumoauth_hermes.decide import REASONS

    assert REASONS == _DECIDE["reasons"]


@pytest.mark.parametrize("case", vectors("approval-text")["cases"], ids=lambda c: c["id"])
def test_approval_text(case):
    c = case["classification"]
    text = approval_text.build(
        tool=c["tool"], capability=c["capability"], risk=c["risk"], why=case["why"], args=case["args"],
        server=c.get("server"), mcp_tool=c.get("mcpTool"), command=c.get("command"),
        hard_rule=case.get("hardRule") == "approve",
    )
    expected = case["expected"]
    assert text.title == expected["title"]
    assert text.description == expected["description"]
    assert text.impact == expected["impact"]
    assert text.severity == expected["severity"]
