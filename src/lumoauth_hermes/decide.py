"""The decision for one call (SPEC §6.1), before any approval channel is used.

Pure: the caller supplies the classification, the hard-rule result, the
state and the snapshot. ``vectors/decide.json`` is the reference.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from .capabilities import any_covers

ALLOW = "allow"
BLOCK = "block"
APPROVE = "approve"

#: Reason texts by code; ``vectors/decide.json`` holds the same texts (a test compares them).
REASONS = {
    "locked": "Locked by the owner",
    "not_set_up": "LumoAuth Guard is not set up",
    "hard_rule": "Protected by a rule that cannot be changed",
    "hard_rule_approve": "Touches something protected",
    "snapshot_unavailable": "LumoAuth cannot confirm this agent's permissions",
    "agent_inactive": "The agent is not active in LumoAuth",
    "granted": "Granted",
    "tainted": "After the agent read untrusted content",
    "not_granted": "Not granted to this agent",
    "approvals_off": "Needs approval, and approvals are switched off",
}

#: Receipt decision for a block, by reason code (vectors/decide.json).
BLOCKED_REASONS = frozenset({"locked", "not_set_up", "hard_rule", "snapshot_unavailable", "agent_inactive"})
DENIED_REASONS = frozenset({"not_granted", "approvals_off"})


@dataclass(frozen=True)
class SnapshotView:
    capabilities: Sequence[str] = ()
    status: str = "active"
    age_seconds: float = 0.0


@dataclass(frozen=True)
class TaintPolicy:
    enabled: bool = True
    window_seconds: int = 1800
    escalate: tuple[str, ...] = ("external",)


@dataclass(frozen=True)
class DecisionConfig:
    approvals: str = "auto"
    on_ungranted: str = "ask"
    refresh_seconds: int = 60
    offline_grace_seconds: int = 300
    taint: TaintPolicy = field(default_factory=TaintPolicy)


@dataclass(frozen=True)
class Decision:
    outcome: str  # allow / block / approve
    reason: str  # reason code
    #: True when the capability was confirmed by the server's Ask API (server mode).
    asked_server: bool = False

    @property
    def receipt_decision(self) -> str:
        """The receipt's ``decision`` for a block (SPEC §7.4)."""
        if self.outcome == ALLOW:
            return "allowed"
        if self.reason in DENIED_REASONS:
            return "denied"
        return "blocked"


def decide(
    *,
    capability: str,
    risk: str,
    egress: bool = False,
    persists_instructions: bool = False,
    hard_rule: str | None = None,
    locked: bool = False,
    set_up: bool = True,
    snapshot: SnapshotView | None = None,
    tainted: bool = False,
    config: DecisionConfig = DecisionConfig(),
    ask: Callable[[str], bool | None] | None = None,
) -> Decision:
    """SPEC §6.1 steps 1-7 (the approval itself happens later).

    ``ask`` is the server-mode check (§6.2): it returns True/False, or None when
    the Ask API cannot answer, in which case the snapshot decides.
    """
    # 1. Local lock.
    if locked:
        return Decision(BLOCK, "locked")
    # 2. Not set up.
    if not set_up:
        return Decision(BLOCK, "not_set_up")
    # 3. Hard rules: deny blocks at once.
    if hard_rule == "deny":
        return Decision(BLOCK, "hard_rule")
    # 4. Snapshot. Checked before a hard-rule approval too: a suspended agent
    #    (the kill switch, SPEC §1) must not even ask a person.
    if snapshot is None or snapshot.age_seconds > config.refresh_seconds + config.offline_grace_seconds:
        return Decision(BLOCK, "snapshot_unavailable")
    if snapshot.status != "active":
        return Decision(BLOCK, "agent_inactive")
    if hard_rule == "approve":
        return _approval(config, "hard_rule_approve")
    # 5. Capability granted?
    granted: bool | None = None
    asked = False
    if ask is not None:
        granted = ask(capability)
        asked = granted is not None
    if granted is None:
        granted = any_covers(snapshot.capabilities, capability)
    if granted:
        taint = config.taint
        if tainted and taint.enabled and (
            risk in taint.escalate or ("egress" in taint.escalate and egress) or persists_instructions
        ):
            return _approval(config, "tainted")
        return Decision(ALLOW, "granted", asked_server=asked)
    # 6. Not granted.
    if config.on_ungranted == "block":
        return Decision(BLOCK, "not_granted", asked_server=asked)
    # 7. Approval.
    return _approval(config, "not_granted")


def _approval(config: DecisionConfig, reason: str) -> Decision:
    if config.approvals == "off":
        return Decision(BLOCK, "approvals_off")
    return Decision(APPROVE, reason)
