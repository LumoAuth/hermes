"""``hermes lumoauth status`` and the ``/lumoauth`` chat command."""

from __future__ import annotations

from typing import Any

from ._version import __version__
from .client import AgentClient, AuthError, LumoAuthError
from .config import ConfigError, GuardHome, mode_of
from .keys import load as load_key


def gather(home: GuardHome | None = None, *, live: bool = True) -> dict[str, Any]:
    """Status as data (``status --json``). Never contains the key or tokens."""
    home = home or GuardHome()
    data: dict[str, Any] = {"version": __version__, "guardHome": str(home.path), "setUp": False,
                            "locked": home.lock_info()}
    try:
        cfg = home.read_config()
    except ConfigError as exc:
        data["problem"] = str(exc)
        return data
    if cfg is None:
        data["problem"] = "not set up"
        return data
    try:
        key = load_key(home)
    except (OSError, ValueError):
        data["problem"] = "agent-key.pem is missing or cannot be loaded"
        key = None
    data.update({
        "agentId": cfg.agent_id, "orgId": cfg.org_id, "baseUrl": cfg.base_url, "agentUrl": cfg.agent_url,
        "keyFingerprint": key.fingerprint if key else None, "keyMode": _octal(mode_of(home.key_path)),
        "preset": cfg.get("preset"), "decisionMode": cfg.decision_mode, "approvals": cfg.approvals,
        "approvalChannel": _channel(cfg), "onUngranted": cfg.get("onUngranted"),
        "taint": cfg.get("taint"), "receiptsEnabled": cfg.get("receipts"),
        "reportUsage": cfg.get("reportUsage"),
        "configWarnings": cfg.warnings,
    })
    if key is not None and key.kid != cfg.key_id:
        data["problem"] = "agent-key.pem does not match keyId in config.json"
    data["setUp"] = "problem" not in data
    runtime = home.read_status()
    if runtime:
        data["runtime"] = runtime
    queued = 0
    try:
        queued = sum(1 for line in home.queue_path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        pass
    data["queuedReceiptsOnDisk"] = queued
    if live and key is not None and data["setUp"]:
        client = AgentClient(cfg, key)
        try:
            me = client.me(timeout=10.0)
            identity = me.get("identity") if isinstance(me.get("identity"), dict) else {}
            caps = me.get("capabilities")
            data["connectivity"] = {"ok": True, "agentStatus": identity.get("status"),
                                    "dpop": client.sender_constrained,
                                    "capabilities": sorted(c for c in caps if isinstance(c, str))
                                    if isinstance(caps, list) else []}
        except AuthError as exc:
            data["connectivity"] = {"ok": False, "error": str(exc), "refused": True}
        except LumoAuthError as exc:
            data["connectivity"] = {"ok": False, "error": str(exc)}
        finally:
            client.close()
    return data


def _octal(mode: int | None) -> str | None:
    return None if mode is None else f"{mode:o}"


def _channel(cfg) -> str:
    if cfg.approvals == "off":
        return "none: calls that need approval are blocked"
    if cfg.approvals == "host":
        return "Hermes prompt"
    if cfg.approvals == "lumoauth":
        return "LumoAuth app" if cfg.can_act_on_behalf else "none: delegation is off in LumoAuth"
    return "LumoAuth app, then Hermes prompt" if cfg.can_act_on_behalf else "Hermes prompt"


def format_text(data: dict[str, Any]) -> str:
    lines = [f"LumoAuth Guard for Hermes {data['version']}"]

    def row(label: str, value: Any) -> None:
        lines.append(f"  {label:<14}{value}")

    row("Guard home:", data["guardHome"])
    row("Lock:", f"ON ({data['locked']}) - run `hermes lumoauth unlock`" if data.get("locked") else "off")
    if not data.get("setUp"):
        problem = data.get("problem", "not set up")
        detail = "" if problem == "not set up" else f" ({problem})"
        row("Set up:", f"no{detail}: every tool call is blocked. Run `hermes lumoauth setup`.")
        return "\n".join(lines)
    row("Agent:", f"{data['agentId']} in {data['orgId']} ({data['baseUrl']})")
    row("Manage:", data["agentUrl"])
    row("Key:", f"{data['keyFingerprint']} (agent-key.pem, mode {data['keyMode']})")
    row("Decisions:", "local: this machine checks the capabilities" if data["decisionMode"] == "local"
        else "server: LumoAuth's Ask API checks each call")
    row("Approvals:", f"{data['approvals']} ({data['approvalChannel']})")
    row("Not granted:", "ask a person" if data["onUngranted"] == "ask" else "block")
    taint = data.get("taint") or {}
    row("Taint:", f"on, {taint.get('windowSeconds')} s, escalates {', '.join(taint.get('escalate', []))}"
        if taint.get("enabled") else "off")
    row("Reporting:", f"receipts {'on' if data.get('receiptsEnabled') else 'off'}, "
                      f"token counts {'on' if data.get('reportUsage') else 'off'}")
    for warning in data.get("configWarnings", []):
        row("Config:", warning)
    conn = data.get("connectivity")
    if conn:
        if conn.get("ok"):
            caps = conn.get("capabilities", [])
            row("LumoAuth:", f"ok, agent {conn.get('agentStatus')}" + ("" if conn.get("dpop") else
                                                                       " (token not DPoP-bound)"))
            row("Granted:", f"{len(caps)}: {', '.join(caps)}" if caps else "nothing")
        else:
            row("LumoAuth:", f"NOT OK: {conn.get('error')}")
    runtime = data.get("runtime")
    if runtime:
        receipts = runtime.get("receipts", {})
        row("Running:", f"pid {runtime.get('pid')}, last update {runtime.get('updatedAt')}")
        row("Receipts:", f"{receipts.get('queued', 0)} queued, {receipts.get('sent', 0)} sent, "
                         f"{receipts.get('dropped', 0)} dropped, {receipts.get('rejected', 0)} refused")
        if runtime.get("lastError"):
            row("Last error:", runtime["lastError"])
        if runtime.get("askFallback"):
            row("Ask API:", runtime["askFallback"])
        for item in runtime.get("waiting") or []:
            row("Waiting:", f"for approval in {item.get('where')}: {item.get('tool')} ({item.get('capability')}), "
                            f"since {item.get('since')}")
        recent = runtime.get("recent") or []
        if recent:
            lines.append("  Recent decisions:")
            for item in recent[-10:]:
                lines.append(f"    {item.get('at')}  {item.get('decision'):<18} {item.get('tool')} "
                             f"({item.get('reason')})")
    if data.get("queuedReceiptsOnDisk"):
        row("Unsent:", f"{data['queuedReceiptsOnDisk']} receipt(s) saved for the next run")
    return "\n".join(lines)


def chat_status(guard: Any = None, home: GuardHome | None = None) -> str:
    """Short status for ``/lumoauth``: no capability list, no paths."""
    home = home or GuardHome()
    data = gather(home, live=False)
    if data.get("locked"):
        state = "LOCKED: every tool call is blocked until the owner runs `hermes lumoauth unlock`."
    elif not data.get("setUp"):
        state = "not set up: every tool call is blocked. The owner runs `hermes lumoauth setup` in a terminal."
    else:
        state = f"on (agent {data['agentId']}, approvals: {data['approvalChannel']})."
    lines = [f"LumoAuth Guard is {state}"]
    if guard is not None and data.get("setUp"):
        snap = guard.snapshots.snapshot
        if snap is None:
            lines.append("LumoAuth has not confirmed this agent's permissions yet.")
        else:
            lines.append(f"LumoAuth status: agent {snap.status}, {len(snap.capabilities)} capabilities granted.")
        for item in list(guard.waiting.values()):
            lines.append(f"Waiting for approval in {item['where']}: {item['tool']}.")
        counts = dict(guard.counters.counts)
        if counts:
            lines.append("Decisions so far: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    return "\n".join(lines)
