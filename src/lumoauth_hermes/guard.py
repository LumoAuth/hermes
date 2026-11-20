"""The Guard at run time: Hermes hooks -> classification, hard rules, decision, approval, receipt."""

from __future__ import annotations

import atexit
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from . import approval_text, hard_rules
from .canonical import arguments_sha256
from .capabilities import any_covers
from .classify import Classification, classify
from .client import AgentClient, AuthError, LumoAuthError
from .config import ConfigError, GuardConfig, GuardHome
from .decide import ALLOW, APPROVE, BLOCK, REASONS, Decision, decide
from .environment import Env, current_env
from .hermes_host import HermesHost
from .keys import AgentKey
from .keys import load as load_key
from .runtime import (
    FLUSH_SECONDS,
    MAX_BACKOFF,
    USAGE_SECONDS,
    Pending,
    PreDecisions,
    ReceiptQueue,
    RuntimeCounters,
    SnapshotStore,
    TaintTracker,
    UsageMeter,
    adopt_queue_file,
    error_code,
    iso,
    save_queue_file,
    send_receipts,
)

logger = logging.getLogger("lumoauth_hermes")

HOST = "hermes"
ON_DEMAND_TIMEOUT = 5.0
ON_DEMAND_MIN_INTERVAL = 10.0
ON_DEMAND_RETRY_MISSING = 2.0
ASK_TIMEOUT = 5.0
ASK_CACHE_SECONDS = 30.0
POLL_SECONDS = 2.0
MIN_APPROVAL_SECONDS = 60
MAX_APPROVAL_SECONDS = 600
_DELIVERY = {"push": "the LumoAuth app", "slack": "Slack", "discord": "Discord"}


def delivery_text(delivery: Any) -> str:
    """Where a LumoAuth approval request went, for people: "the LumoAuth app and Slack"."""
    names: list[str] = []
    for item in delivery if isinstance(delivery, list) else []:
        name = _DELIVERY.get(item) if isinstance(item, str) else None
        if name and name not in names:
            names.append(name)
    if not names:
        return "LumoAuth"
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
STATUS_WRITE_SECONDS = 10.0
PREFIX = "Blocked by LumoAuth Guard."


def _sig(path: Any) -> tuple[int, int, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


class Guard:
    """One Guard per Hermes process (``lumoauth_hermes.register`` creates it)."""

    def __init__(
        self,
        *,
        home: GuardHome | None = None,
        host: HermesHost | None = None,
        env_provider: Callable[[], Env] = current_env,
        transport: httpx.BaseTransport | None = None,
        start_worker: bool = True,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.home = home or GuardHome()
        self.host = host or HermesHost()
        self.env_provider = env_provider
        self.transport = transport
        self.start_worker_enabled = start_worker
        self.sleep = sleep
        self.snapshots = SnapshotStore()
        self.taint = TaintTracker()
        self.predecisions = PreDecisions()
        self.receipts = ReceiptQueue()
        self.usage = UsageMeter()
        self.counters = RuntimeCounters()
        self._lock = threading.RLock()
        self._config: GuardConfig | None = None
        self._config_sig: Any = None
        self._config_error: str | None = None
        self._key: AgentKey | None = None
        self._key_sig: Any = None
        self._key_error: str | None = None
        self._client: AgentClient | None = None
        self._refresh_lock = threading.Lock()
        self._ask_cache: dict[str, float] = {}
        self._ask_note: str | None = None
        #: LumoAuth approvals that a call is waiting for: task id -> what and where.
        self.waiting: dict[str, dict[str, str]] = {}
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._adopted = False

    # ── State ────────────────────────────────────────────────────────────────
    def state(self) -> tuple[GuardConfig | None, AgentKey | None, str | None]:
        """Current config and key (reloaded when the files change), and why setup is incomplete."""
        with self._lock:
            config_sig = _sig(self.home.config_path)
            key_sig = _sig(self.home.key_path)
            changed = False
            if config_sig != self._config_sig:
                self._config_sig = config_sig
                changed = True
                try:
                    self._config = self.home.read_config()
                    self._config_error = None
                except ConfigError as exc:
                    self._config, self._config_error = None, str(exc)
            if key_sig != self._key_sig:
                self._key_sig = key_sig
                changed = True
                if key_sig is None:
                    self._key, self._key_error = None, None
                else:
                    try:
                        self._key, self._key_error = load_key(self.home), None
                    except (OSError, ValueError) as exc:
                        self._key, self._key_error = None, f"agent-key.pem cannot be loaded ({type(exc).__name__})"
            if changed:
                self._reset_client()
            cfg, key = self._config, self._key
            if cfg is None:
                return None, key, self._config_error or "config.json is missing"
            if key is None:
                return cfg, None, self._key_error or "agent-key.pem is missing"
            if key.kid != cfg.key_id:
                return cfg, key, "agent-key.pem does not match keyId in config.json"
            if self._client is None:
                self._client = AgentClient(cfg, key, transport=self.transport)
            return cfg, key, None

    def _reset_client(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: S110 (closing an old client)
                pass
        self._client = None
        self.snapshots.clear("the configuration changed")
        self._ask_cache.clear()

    @property
    def client(self) -> AgentClient | None:
        return self._client

    # ── Snapshot ────────────────────────────────────────────────────────────
    def refresh_snapshot(self, timeout: float = 10.0) -> bool:
        cfg, _key, problem = self.state()
        client = self._client
        if problem or client is None or cfg is None:
            return False
        if not self._refresh_lock.acquire(timeout=timeout):
            return False
        try:
            return self.snapshots.refresh(client, timeout)
        finally:
            self._refresh_lock.release()

    def _snapshot_for_decision(self, cfg: GuardConfig):
        age = self.snapshots.age()
        if age is None or age > cfg.get("refreshSeconds"):
            since = time.monotonic() - self.snapshots.last_attempt
            # No snapshot at all: try again soon. A stale one: at most every 10 s on the hot path.
            if since >= (ON_DEMAND_RETRY_MISSING if age is None else ON_DEMAND_MIN_INTERVAL):
                self.refresh_snapshot(ON_DEMAND_TIMEOUT)
        return self.snapshots.view()

    # ── Worker ──────────────────────────────────────────────────────────────
    def ensure_worker(self) -> None:
        if not self.start_worker_enabled:
            return
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            if not self._adopted:
                self._adopted = True
                for receipt in adopt_queue_file(self.home):
                    self.receipts.add(receipt)
                atexit.register(self.shutdown)
            self._worker = threading.Thread(target=self._run, name="lumoauth-guard", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        next_flush = time.monotonic() + FLUSH_SECONDS
        next_usage = time.monotonic() + USAGE_SECONDS
        next_status = 0.0
        backoff = FLUSH_SECONDS
        while not self._stop.is_set():
            self.receipts.wake.wait(1.0)
            self.receipts.wake.clear()
            if self._stop.is_set():
                break
            try:
                now = time.monotonic()
                cfg, _key, problem = self.state()
                self.receipts.expire_pending(now)
                if cfg is not None and problem is None:
                    # Refresh a little early, so that a call rarely has to wait for it.
                    refresh = cfg.get("refreshSeconds")
                    age = self.snapshots.age()
                    if (age is None or age >= max(refresh - 5, 25)) and \
                            now - self.snapshots.last_attempt >= min(refresh, 30):
                        self.refresh_snapshot()
                    if (len(self.receipts) >= 20 or now >= next_flush) and self._client is not None:
                        if not cfg.get("receipts"):
                            self.receipts.take(10**6)
                        wait = None
                        while len(self.receipts) and wait is None:
                            wait = send_receipts(self._client, self.receipts)
                        if wait is None:
                            backoff = FLUSH_SECONDS
                            next_flush = now + FLUSH_SECONDS
                        else:
                            backoff = min(max(backoff * 2, wait), MAX_BACKOFF)
                            next_flush = now + backoff
                    if now >= next_usage and self._client is not None:
                        next_usage = now + USAGE_SECONDS
                        self._flush_usage(cfg)
                if now >= next_status:
                    next_status = now + STATUS_WRITE_SECONDS
                    self.write_status()
            except Exception:
                logger.debug("LumoAuth Guard worker step failed", exc_info=True)

    def _flush_usage(self, cfg: GuardConfig) -> None:
        tokens = self.usage.take()
        if tokens <= 0 or not cfg.get("reportUsage") or self._client is None:
            return
        try:
            response = self._client.report_usage(tokens, timeout=10.0)
        except LumoAuthError:
            self.usage.put_back(tokens)
            return
        if response.status_code == 200:
            self.usage.reported += tokens
        elif response.status_code in (429,) or response.status_code >= 500:
            self.usage.put_back(tokens)

    def flush(self, timeout: float = 10.0) -> bool:
        """Send queued receipts and usage now (tests, status). True when the queue is empty."""
        cfg, _key, problem = self.state()
        if cfg is None or problem or self._client is None:
            return False
        self.receipts.expire_pending(time.monotonic())
        if not cfg.get("receipts"):
            self.receipts.take(10**6)
        while len(self.receipts):
            if send_receipts(self._client, self.receipts, timeout=timeout) is not None:
                return False
        self._flush_usage(cfg)
        return True

    def shutdown(self, timeout: float = 3.0) -> None:
        """Stop the worker; send what can be sent quickly and keep the rest for the next process."""
        self._stop.set()
        self.receipts.wake.set()
        deadline = time.monotonic() + timeout
        cfg = self._config
        if self._client is not None and cfg is not None and cfg.get("receipts"):
            while len(self.receipts) and time.monotonic() < deadline:
                if send_receipts(self._client, self.receipts, timeout=max(0.5, deadline - time.monotonic())):
                    break
        if cfg is not None and cfg.get("receipts"):
            save_queue_file(self.home, self.receipts.drain_all())
        self.write_status()

    def write_status(self) -> None:
        cfg = self._config
        if cfg is None:
            return
        snap = self.snapshots.snapshot
        data = {
            "pid": os.getpid(),
            "updatedAt": iso(),
            "agentId": cfg.agent_id,
            "snapshot": None if snap is None else {
                "status": snap.status, "capabilityCount": len(snap.capabilities),
                "fetchedAt": datetime.fromtimestamp(snap.fetched_wall, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "lastError": self.snapshots.last_error,
            "askFallback": self._ask_note,
            "senderConstrained": None if self._client is None else self._client.sender_constrained,
            "receipts": {"queued": len(self.receipts), "pending": self.receipts.pending_count,
                         "sent": self.receipts.sent, "dropped": self.receipts.dropped,
                         "rejected": self.receipts.rejected},
            "usageReported": self.usage.reported,
            "taintedSessions": self.taint.count(cfg.taint.window_seconds),
            "waiting": list(self.waiting.values()),
            "decisions": dict(self.counters.counts),
            "recent": [vars(r) for r in self.counters.recent],
        }
        try:
            self.home.write_private(self.home.status_path, (json.dumps(data, indent=2) + "\n").encode("utf-8"))
        except OSError:
            pass

    # ── Hooks ───────────────────────────────────────────────────────────────
    def pre_tool_call(self, tool_name: str = "", args: Any = None, task_id: str = "", session_id: str = "",
                      tool_call_id: str = "", conversation_id: str = "", **_: Any) -> dict[str, Any] | None:
        try:
            return self._pre_tool_call(str(tool_name or ""), args if isinstance(args, dict) else {},
                                       str(task_id or ""), str(session_id or ""), str(tool_call_id or ""),
                                       str(conversation_id or ""))
        except Exception as exc:  # fail closed, never raise into Hermes
            logger.error("LumoAuth Guard could not check a call to %s: %s", str(tool_name)[:100],
                         type(exc).__name__)
            logger.debug("LumoAuth Guard internal error", exc_info=True)
            return {"action": "block", "message": f"{PREFIX} The Guard could not check this call "
                                                  f"({type(exc).__name__}), so it does not run."}

    def _taint_keys(self, session_id: str, task_id: str, conversation_id: str) -> tuple[str, ...]:
        primary = session_id or task_id
        keys = [f"s:{primary}"] if primary else []
        if conversation_id:
            keys.append(f"c:{conversation_id}")
        return tuple(keys)

    def _pre_tool_call(self, tool_name: str, args: dict[str, Any], task_id: str, session_id: str,
                       tool_call_id: str, conversation_id: str) -> dict[str, Any] | None:
        cfg, key, problem = self.state()
        if cfg is not None and problem is None:
            self.ensure_worker()
        env = self.env_provider()
        cls = classify(tool_name, args, env)
        # SPEC §4.1a: a dispatcher call is decided as the call it runs, on that call's arguments.
        call_args = cls.call_args
        hook_sha = arguments_sha256(args)
        sha = hook_sha if cls.dispatchedBy is None else arguments_sha256(call_args)
        primary = session_id or task_id
        locked = self.home.is_locked()
        set_up = cfg is not None and problem is None
        if cls.dispatchedBy is None and set_up and not locked and \
                self.predecisions.take((primary, cls.tool, hook_sha)):
            # The inner call of a dispatcher call that was just allowed: one decision, one receipt.
            self._record(tool_name, "allowed", "pre_decided")
            return None
        link = _Link(tool_name, hook_sha, (primary, cls.tool, sha) if cls.dispatchedBy else None)
        taint_keys = self._taint_keys(session_id, task_id, conversation_id)
        policy = cfg.taint if cfg is not None else None
        tainted = bool(policy and policy.enabled and self.taint.is_tainted(taint_keys, policy.window_seconds))
        hard = hard_rules.evaluate(cls, call_args, env, tainted=tainted,
                                   extra_protected=tuple(cfg.get("extraProtectedPaths")) if cfg else (),
                                   allow_paths=tuple(cfg.get("allowPaths")) if cfg else ())
        snapshot = None
        if not locked and set_up and hard.rule != "deny":
            snapshot = self._snapshot_for_decision(cfg)  # type: ignore[arg-type]
        context: dict[str, Any] = {}
        ask = self._ask_function(cfg, cls, context) if set_up and cfg.decision_mode == "server" else None  # type: ignore[union-attr]
        decision = decide(
            capability=cls.capability, risk=cls.risk, egress=cls.egress,
            persists_instructions=cls.persistsInstructions, hard_rule=hard.rule, locked=locked, set_up=set_up,
            snapshot=snapshot, tainted=tainted, config=cfg.decision_config() if cfg else _default_decision_config(),
            ask=ask,
        )
        audit_id = context.get("audit_id")
        name = cls.raw_name or cls.tool
        if decision.outcome == ALLOW:
            self._record(name, "allowed", decision.reason)
            self._pending(cls, sha, "allowed", tool_call_id, session_id, taint_keys, audit_id=audit_id, link=link)
            if link.predecision:
                self.predecisions.add(link.predecision)
            if cls.ingestsUntrusted:
                self.taint.mark(taint_keys)
            return None
        if decision.outcome == BLOCK:
            self._record(name, decision.receipt_decision, decision.reason)
            self._final_receipt(cls, sha, decision.receipt_decision, decision.reason, audit_id=audit_id)
            return {"action": "block", "message": self._block_message(decision, cfg, cls, hard, problem)}
        if decision.outcome != APPROVE or cfg is None:
            raise RuntimeError("unexpected decision")
        return self._approve(cfg, cls, call_args, sha, decision, hard, tool_call_id, session_id, taint_keys,
                             audit_id, link)

    def _approve(self, cfg: GuardConfig, cls: Classification, args: dict[str, Any], sha: str, decision: Decision,
                 hard: hard_rules.HardRule, tool_call_id: str, session_id: str, taint_keys: tuple[str, ...],
                 audit_id: str | None, link: _Link) -> dict[str, Any] | None:
        why = REASONS.get(decision.reason, decision.reason)
        text = approval_text.build(
            tool=cls.tool, capability=cls.capability, risk=cls.risk, why=why, args=args, server=cls.server,
            mcp_tool=cls.mcpTool, command_args=cls.command_args, command=cls.command,
            hard_rule=decision.reason == "hard_rule_approve",
        )
        name = cls.raw_name or cls.tool
        channel = cfg.approvals
        if channel == "auto":
            channel = "lumoauth" if cfg.can_act_on_behalf else "host"
        if channel == "lumoauth":
            result, detail = self._push_approval(cfg, cls, sha, text, tool_call_id, why)
            if result == "approved":
                self._record(name, "approved", decision.reason)
                self._pending(cls, sha, "approved", tool_call_id, session_id, taint_keys, audit_id=audit_id,
                              link=link)
                if link.predecision:
                    self.predecisions.add(link.predecision)
                if cls.ingestsUntrusted:
                    self.taint.mark(taint_keys)
                return None
            if result in ("refused", "expired"):
                self._record(name, result, decision.reason)
                self._final_receipt(cls, sha, result, decision.reason, audit_id=audit_id)
                return {"action": "block", "message": self._block_message(decision, cfg, cls, hard, None,
                                                                          outcome=result, detail=detail)}
            if cfg.approvals != "auto":
                self._record(name, "denied", decision.reason)
                self._final_receipt(cls, sha, "denied", "approval_unavailable", audit_id=audit_id)
                return {"action": "block", "message": self._block_message(
                    decision, cfg, cls, hard, None, outcome="push_unavailable", detail=detail)}
            # auto: fall back to the host's approval prompt for this call.
        bypass = self.host.auto_grant_reason()
        if bypass:
            self._record(name, "denied", decision.reason)
            self._final_receipt(cls, sha, "denied", "host_approvals_off", audit_id=audit_id)
            return {"action": "block", "message": self._block_message(decision, cfg, cls, hard, None,
                                                                      outcome="host_off", detail=bypass)}
        # SPEC §6.4: "session"/"always" answers count only for a capability that is not granted;
        # hard-rule and taint approvals ask every time.
        remember = cfg.get("rememberApprovals") and decision.reason == "not_granted"
        rule_key = f"lumoauth:{cls.capability}" if remember else \
            f"lumoauth:{cls.capability}:{secrets.token_hex(6)}"
        self._record(name, "approval_requested", decision.reason)
        self._pending(cls, sha, "approved", tool_call_id, session_id, taint_keys, audit_id=audit_id,
                      host_approval=True, rule_key=rule_key, link=link)
        return {"action": "approve", "message": text.description, "rule_key": rule_key}

    def _push_approval(self, cfg: GuardConfig, cls: Classification, sha: str, text: approval_text.ApprovalText,
                       tool_call_id: str, why: str) -> tuple[str, str]:
        """LumoAuth approval in the app, Slack or Discord (SPEC §7.5): approved / refused / expired /
        unavailable, and a detail (for refused and expired: where the person was asked)."""
        client = self._client
        if client is None:
            return "unavailable", "LumoAuth is not set up on this machine"
        if not cfg.owner_user_id:
            return "unavailable", "the agent has no owner to ask"
        started = time.monotonic()
        hook_timeout = self.host.hook_timeout()
        budget = (hook_timeout - 5.0) if hook_timeout > 0 else 600.0
        if budget < 5.0:
            return "unavailable", "Hermes's hook timeout is too short to wait for an answer"
        deadline = started + budget
        task = f"{HOST}-{tool_call_id or secrets.token_hex(8)}"[:128]
        meta: dict[str, Any] = {"kind": "tool_call", "host": HOST, "tool": (cls.raw_name or cls.tool)[:200]}
        if cls.server:
            meta["server"] = cls.server
        meta.update({"capability": cls.capability, "risk": cls.risk, "why": why, "title": text.title,
                     "args": list(text.arg_lines), "arguments_sha256": sha})
        # How long a person may answer: as long as this call keeps polling (SPEC §7.5).
        expires_in = int(min(max(budget, MIN_APPROVAL_SECONDS), MAX_APPROVAL_SECONDS))
        body = {"task_id": task, "reason": approval_text.cut(text.description, 480), "impact": text.impact,
                "on_behalf_of": cfg.owner_user_id, "expires_in": expires_in, "meta": meta}
        try:
            response = client.request_approval(body, timeout=min(10.0, budget))
        except LumoAuthError as exc:
            return "unavailable", f"LumoAuth could not send the request ({exc})"
        try:
            answer = response.json()
        except ValueError:
            answer = {}
        answer = answer if isinstance(answer, dict) else {}
        if response.status_code == 202:
            return "unavailable", "the owner has no LumoAuth app enrolled (LumoAuth sent an e-mail instead)"
        if response.status_code == 428:
            return "unavailable", "the owner has no LumoAuth app enrolled"
        if response.status_code == 403:
            return "unavailable", f"LumoAuth does not allow it ({answer.get('error') or 'forbidden'})"
        if response.status_code != 201 or not isinstance(answer.get("approval_token"), str):
            return "unavailable", f"LumoAuth answered HTTP {response.status_code}"
        token = answer["approval_token"]
        where = delivery_text(answer.get("delivery"))
        expires_at = _parse_time(answer.get("expires_at"))
        if expires_at is not None:
            deadline = min(deadline, time.monotonic() + max(0.0, expires_at - time.time()))
        logger.info("LumoAuth Guard: waiting for approval in %s (%s)", where, cls.capability)
        self.waiting[task] = {"tool": (cls.raw_name or cls.tool)[:200], "capability": cls.capability,
                              "where": where, "since": iso()}
        self.write_status()
        try:
            return self._poll_approval(client, token, deadline, where)
        finally:
            self.waiting.pop(task, None)
            self.write_status()

    def _poll_approval(self, client: AgentClient, token: str, deadline: float, where: str) -> tuple[str, str]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "expired", where
            self.sleep(min(POLL_SECONDS, remaining))
            try:
                status_response = client.approval_status(token, timeout=min(5.0, max(0.5, remaining)))
            except LumoAuthError:
                continue
            if status_response.status_code != 200:
                if status_response.status_code in (403, 404):
                    return "expired", where
                continue
            try:
                status = status_response.json().get("status")
            except (ValueError, AttributeError):
                continue
            if status == "approved":
                return "approved", where
            if status == "denied":
                return "refused", where
            if status == "expired":
                return "expired", where

    def _ask_function(self, cfg: GuardConfig, cls: Classification,
                      context: dict[str, Any]) -> Callable[[str], bool | None]:
        def ask(capability: str) -> bool | None:
            client = self._client
            if client is None:
                return None
            cached = self._ask_cache.get(capability)
            if cached is not None and cached > time.monotonic():
                return True
            try:
                answer = client.ask(capability, {"tool": cls.tool, "server": cls.server, "host": HOST},
                                    timeout=ASK_TIMEOUT)
            except AuthError:
                return None
            except LumoAuthError as exc:
                if exc.status == 429 and exc.error == "budget_exceeded":
                    self._ask_note = "the agent's budget is spent"
                    return False
                self._ask_note = "Ask API unavailable; the snapshot decided" + (
                    f" ({exc.error})" if exc.error else "")
                return None
            audit = answer.get("audit_id")
            if isinstance(audit, str) and len(audit) == 16:
                context["audit_id"] = audit
            allowed = answer.get("allowed") is True
            if allowed:
                self._ask_cache[capability] = time.monotonic() + ASK_CACHE_SECONDS
            self._ask_note = None
            return allowed

        return ask

    def post_tool_call(self, tool_name: str = "", args: Any = None, status: str = "", duration_ms: Any = None,
                       error_type: Any = None, tool_call_id: str = "", session_id: str = "", task_id: str = "",
                       conversation_id: str = "", **_: Any) -> None:
        try:
            self._post_tool_call(str(tool_name or ""), args if isinstance(args, dict) else {}, str(status or ""),
                                 duration_ms, error_type, str(tool_call_id or ""), str(session_id or ""))
        except Exception:
            logger.debug("LumoAuth Guard post_tool_call failed", exc_info=True)

    def _post_tool_call(self, tool_name: str, args: dict[str, Any], status: str, duration_ms: Any,
                        error_type: Any, tool_call_id: str, session_id: str) -> None:
        key = (session_id, tool_name, arguments_sha256(args))
        pending = self.receipts.find_pending(tool_call_id, key, pop=True)
        if pending is None:
            return
        receipt = pending.receipt
        ran = status not in ("blocked", "cancelled")
        receipt["outcome"] = {"ok": "succeeded", "error": "failed", "timeout": "failed"}.get(status, "not_run")
        if pending.host_approval:
            if pending.choice is not None:
                receipt["decision"] = {"once": "approved", "session": "approved", "always": "approved",
                                       "smart_approve": "approved", "deny": "refused",
                                       "smart_deny": "refused"}.get(pending.choice, "expired")
            else:
                receipt["decision"] = "approved" if ran else ("expired" if status == "cancelled" else "denied")
            if receipt["decision"] != "approved":
                receipt["outcome"] = "not_run"
        if isinstance(duration_ms, (int, float)) and not isinstance(duration_ms, bool) and duration_ms >= 0:
            receipt["duration_ms"] = min(int(duration_ms), 86_400_000)
        if receipt["outcome"] == "failed":
            code = error_code(error_type)
            if code:
                receipt["error_code"] = code
        if pending.send:
            self.receipts.add(receipt)
        if ran and pending.ingests_untrusted:
            self.taint.mark(pending.taint_keys)

    def post_approval_response(self, choice: str = "", pattern_key: str = "", tool_call_id: str = "",
                               **_: Any) -> None:
        try:
            key = str(pattern_key or "")
            if not key.startswith("plugin_rule:lumoauth:"):
                return
            pending = self.receipts.find_approval(str(tool_call_id or ""), key[len("plugin_rule:"):])
            if pending is not None:
                pending.choice = str(choice or "")
                if pending.predecision and pending.choice in ("once", "session", "always"):
                    self.predecisions.add(pending.predecision)
                self._record(pending.receipt.get("tool", ""), f"answer_{pending.choice}", "host_approval")
        except Exception:
            logger.debug("LumoAuth Guard post_approval_response failed", exc_info=True)

    def post_api_request(self, usage: Any = None, **_: Any) -> None:
        try:
            if isinstance(usage, dict):
                self.usage.add(usage.get("total_tokens"))
        except Exception:
            logger.debug("LumoAuth Guard post_api_request failed", exc_info=True)

    def on_session_start(self, **_: Any) -> None:
        try:
            cfg, _key, problem = self.state()
            if cfg is not None and problem is None:
                self.ensure_worker()
                self.receipts.wake.set()
        except Exception:
            logger.debug("LumoAuth Guard on_session_start failed", exc_info=True)

    # ── Receipts and messages ─────────────────────────────────────────────────
    def _record(self, tool: str, decision: str, reason: str) -> None:
        self.counters.record(tool, decision, reason)

    def _granted(self, capability: str) -> bool:
        snap = self.snapshots.snapshot
        return snap is not None and any_covers(snap.capabilities, capability)

    def _base_receipt(self, cls: Classification, sha: str, decision: str,
                      audit_id: str | None) -> dict[str, Any]:
        receipt: dict[str, Any] = {"tool": (cls.raw_name or cls.tool)[:200] or "unknown", "decision": decision,
                                   "arguments_sha256": sha, "occurred_at": iso()}
        if cls.server:
            receipt["server_id"] = cls.server[:100]
        if audit_id:
            receipt["audit_id"] = audit_id
        return receipt

    def _receipts_on(self) -> bool:
        cfg = self._config
        return cfg is not None and bool(cfg.get("receipts"))

    def _final_receipt(self, cls: Classification, sha: str, decision: str, reason: str,
                       audit_id: str | None = None) -> None:
        if not self._receipts_on():
            return
        receipt = self._base_receipt(cls, sha, decision, audit_id)
        receipt["outcome"] = "not_run"
        code = error_code(reason)
        if code:
            receipt["error_code"] = code
        self.receipts.add(receipt)

    def _pending(self, cls: Classification, sha: str, decision: str, tool_call_id: str, session_id: str,
                 taint_keys: tuple[str, ...], *, audit_id: str | None = None, host_approval: bool = False,
                 rule_key: str = "", link: _Link | None = None) -> None:
        send = self._receipts_on()
        # A host approval of a tool that reads untrusted content taints the session once it ran,
        # so it is tracked even when receipts are off.
        if not send and not (cls.ingestsUntrusted and host_approval):
            return
        receipt = self._base_receipt(cls, sha, decision, audit_id)
        self.receipts.add_pending(Pending(
            receipt=receipt, created=time.monotonic(), tool_call_id=tool_call_id,
            match_key=(session_id, link.hook_name, link.hook_sha) if link else (session_id, cls.raw_name or cls.tool,
                                                                                    sha),
            host_approval=host_approval, rule_key=rule_key, ingests_untrusted=cls.ingestsUntrusted,
            taint_keys=taint_keys, send=send, predecision=link.predecision if link else None,
        ))

    def _block_message(self, decision: Decision, cfg: GuardConfig | None, cls: Classification,
                       hard: hard_rules.HardRule, problem: str | None, *, outcome: str = "",
                       detail: str = "") -> str:
        reason = decision.reason
        if reason == "locked":
            return f"{PREFIX} Locked by the owner: run `hermes lumoauth unlock`."
        if reason == "not_set_up":
            extra = f" ({problem})" if problem and "missing" not in problem else ""
            return f"{PREFIX} LumoAuth Guard is not set up{extra}: run `hermes lumoauth setup`."
        if reason == "hard_rule":
            return f"{PREFIX} {REASONS['hard_rule']}: {hard.describe or 'protected'}."
        if reason == "snapshot_unavailable":
            return f"{PREFIX} {REASONS['snapshot_unavailable']}. Check the connection with `hermes lumoauth status`."
        if reason == "agent_inactive":
            snap = self.snapshots.snapshot
            status = snap.status if snap else "inactive"
            return f"{PREFIX} {REASONS['agent_inactive']} (status: {status})."
        hint = ""
        if reason == "not_granted" and cfg is not None:
            hint = (f" Ask the owner to add the capability `{cls.capability}` to the agent in LumoAuth: "
                    f"{cfg.agent_url}")
        why = REASONS.get(reason, reason)
        if reason == "hard_rule_approve" and hard.describe:
            why = f"{why}: {hard.describe}"
        asked = f" (asked in {detail})" if detail else ""
        if outcome == "refused":
            return f"{PREFIX} {why}, and the owner refused it{asked}.{hint}"
        if outcome == "expired":
            return f"{PREFIX} {why}, and the owner did not answer in time{asked}.{hint}"
        if outcome == "push_unavailable":
            return f"{PREFIX} {why}, and approval in the LumoAuth app is not possible: {detail}.{hint}"
        if outcome == "host_off":
            return (f"{PREFIX} {why}. It needs a person's approval, but Hermes would allow it without asking "
                    f"({detail}), so the Guard blocks it.{hint}")
        if reason == "approvals_off":
            if cfg is not None and hard.rule != "approve" and not self._granted(cls.capability):
                hint = (f" Ask the owner to add the capability `{cls.capability}` to the agent in LumoAuth: "
                        f"{cfg.agent_url}")
            return f"{PREFIX} {REASONS['approvals_off']}.{hint}"
        return f"{PREFIX} {why}.{hint}"


@dataclass(frozen=True)
class _Link:
    """How a decision ties back to the hook call: its name and argument digest (for the post hook), and
    the pre-decision key of a dispatcher call (SPEC §4.1a)."""

    hook_name: str
    hook_sha: str
    predecision: tuple[str, str, str] | None


def _default_decision_config():
    from .decide import DecisionConfig

    return DecisionConfig()


def _parse_time(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
