"""``hermes lumoauth setup`` (SPEC §8.1): enroll this Hermes as a LumoAuth agent.

No administrator token is needed on this machine: a person approves the
enrollment in the LumoAuth dashboard after checking the code and the key
fingerprint shown here.
"""

from __future__ import annotations

import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import contract, doctor
from .canonical import arguments_sha256
from .classify import hermes_mcp_server_name
from .client import AgentClient, LumoAuthError, NetworkError, poll_enrollment, start_enrollment
from .config import APPROVALS, DEFAULT_TAINT, PRESETS, GuardHome, is_allowed_url
from .hermes_host import HostConfigError, configure_hermes, hermes_home, read_config_file
from .keys import generate as generate_key
from .runtime import iso

REGIONS = {"us": "https://app.lumoauth.dev", "eu": "https://eu.app.lumoauth.dev"}
MCP_RISK_ORDER = ("read", "write", "external", "destructive", "execute", "admin")
HOOK_TIMEOUT = 180


class SetupError(Exception):
    pass


@dataclass
class SetupOptions:
    url: str | None = None
    region: str | None = None
    org: str | None = None
    preset: str | None = None
    approvals: str | None = None
    name: str | None = None
    yes: bool = False
    host_config: bool = True
    force: bool = False


@dataclass
class SetupIO:
    out: Callable[[str], None] = print
    ask: Callable[[str], str] = input
    interactive: bool = field(default_factory=lambda: sys.stdin.isatty() and sys.stdout.isatty())
    sleep: Callable[[float], None] = time.sleep
    transport: httpx.BaseTransport | None = None
    hermes_home: Path | None = None


def parse_dashboard_url(url: str) -> tuple[str, str | None]:
    """``https://app.lumoauth.dev/orgs/acme/portal`` -> (``https://app.lumoauth.dev``, ``acme``)."""
    text = url.strip()
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    base = f"{parts.scheme}://{parts.netloc}"
    if not is_allowed_url(base):
        raise SetupError(f"{url} is not an https address")
    segments = [s for s in parts.path.split("/") if s]
    org = segments[segments.index("orgs") + 1] if "orgs" in segments[:-1] else None
    return base, org


def mcp_servers(hermes_config: dict[str, Any]) -> list[str]:
    servers = hermes_config.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    names: list[str] = []
    for configured in servers:
        name = hermes_mcp_server_name(str(configured))
        if name and name not in names:
            names.append(name)
    return names


def checklist(preset: str, servers: list[str]) -> list[dict[str, Any]]:
    """The enrollment checklist: every capability of the catalog, the preset's ones ticked."""
    meta = contract.capabilities_catalog()
    chosen = contract.presets()["presets"][preset]
    entries = []
    for cap in contract.host_capabilities():
        info = meta["capabilities"].get(cap, {"label": cap, "risk": "execute"})
        entries.append({"scope": cap, "risk": info["risk"], "label": info["label"][:120],
                        "checked": cap in chosen["capabilities"]})
    labels = meta["mcpRiskLabels"]
    for server in servers:
        for risk in MCP_RISK_ORDER:
            entries.append({"scope": f"mcp:{server}:{risk}:*", "risk": risk,
                            "label": labels[risk].format(server=server)[:120], "checked": risk in chosen["mcp"]})
    return entries[:200]


def _choose(io: SetupIO, question: str, options: list[tuple[str, str]], default: str) -> str:
    io.out(question)
    for index, (value, label) in enumerate(options, 1):
        mark = " (default)" if value == default else ""
        io.out(f"  {index}. {label}{mark}")
    while True:
        answer = io.ask(f"Choose 1-{len(options)} [{[v for v, _ in options].index(default) + 1}]: ").strip()
        if not answer:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]
        if answer in [v for v, _ in options]:
            return answer


def _remove(paths: list[Path]) -> None:
    for path in paths:
        try:
            path.unlink()
        except OSError:
            pass


def run_setup(opts: SetupOptions, io: SetupIO | None = None, home: GuardHome | None = None) -> int:
    io = io or SetupIO()
    home = home or GuardHome()
    try:
        return _run(opts, io, home)
    except SetupError as exc:
        io.out(f"Setup stopped: {exc}")
        return 1


def _run(opts: SetupOptions, io: SetupIO, home: GuardHome) -> int:
    out = io.out
    interactive = io.interactive and not opts.yes
    out("LumoAuth Guard for Hermes: setup")
    out("")
    existing = None
    try:
        existing = home.read_config()
    except Exception:
        existing = None
    if (existing is not None or home.key_path.exists()) and not opts.force:
        agent = f" as agent {existing.agent_id}" if existing else ""
        raise SetupError(f"this machine is already set up{agent}. Run `hermes lumoauth reset` first, "
                         "or run setup with --force.")

    # 1. Find LumoAuth.
    base, org = None, opts.org
    if opts.url:
        base, from_url = parse_dashboard_url(opts.url)
        org = org or from_url
    elif opts.region:
        base = REGIONS[opts.region]
    if base is None and interactive:
        answer = io.ask("Your LumoAuth dashboard address (for example https://app.lumoauth.dev/orgs/acme/portal): ")
        base, from_url = parse_dashboard_url(answer)
        org = org or from_url
    if base is None:
        raise SetupError("pass --url with your LumoAuth dashboard address, for example "
                         "--url https://app.lumoauth.dev/orgs/acme/portal")
    if not org and interactive:
        org = io.ask("Your LumoAuth organization (the part after /orgs/ in the dashboard address): ").strip()
    if not org:
        raise SetupError("the address names no organization: use a dashboard address with /orgs/<organization>/, "
                         "or pass --org")

    # 2. Inventory.
    hpath = io.hermes_home or hermes_home()
    try:
        hermes_cfg = read_config_file(hpath / "config.yaml")
    except HostConfigError as exc:
        out(f"Note: {exc}; MCP servers are not listed.")
        hermes_cfg = {}
    servers = mcp_servers(hermes_cfg)
    tools = len(contract.host_catalog()["tools"])
    out(f"LumoAuth:     {base}/orgs/{org}")
    out(f"Hermes home:  {hpath}")
    out(f"Inventory:    {tools} built-in tools" + (f", MCP servers: {', '.join(servers)}" if servers else
                                                   ", no MCP servers"))
    out("")

    # 3. Preset and approvals.
    preset_data = contract.presets()
    preset = opts.preset
    if preset is None and interactive:
        preset = _choose(io, "What may the agent do without asking?",
                         [(name, preset_data["presets"][name]["label"]) for name in PRESETS], preset_data["default"])
        out("")
    preset = preset or preset_data["default"]
    if preset not in PRESETS:
        raise SetupError(f"unknown preset {preset!r}")
    approvals = opts.approvals
    if approvals is None and interactive:
        approvals = _choose(io, "Where should a person approve calls that need approval?", [
            ("auto", "The LumoAuth app when the agent may ask its owner, else Hermes's own prompt"),
            ("lumoauth", "Only the LumoAuth app on the owner's phone"),
            ("host", "Only Hermes's own prompt (terminal or chat buttons)"),
            ("off", "Nowhere: block every call that needs approval"),
        ], "auto")
        out("")
    approvals = approvals or "auto"
    if approvals not in APPROVALS:
        raise SetupError(f"unknown approvals setting {approvals!r}")

    # 4. Key.
    home.ensure()
    for stale in (home.config_path, home.key_path):
        if opts.force:
            _remove([stale])
    key = generate_key(home)

    # 5. Enrollment.
    host_label = (socket.gethostname() or "this machine")[:100]
    body = {
        "name": (opts.name or f"Hermes on {host_label}")[:100],
        "host": "hermes",
        "host_label": host_label,
        "jwks": key.jwks(),
        "capabilities": checklist(preset, servers),
        "delegation": approvals in ("auto", "lumoauth"),
        "inventory": {"tools": tools, "mcp_servers": [{"name": s[:64]} for s in servers[:100]]},
    }
    try:
        started = start_enrollment(base, org, body, transport=io.transport)
    except LumoAuthError as exc:
        _remove([home.key_path])
        detail = f": {exc.description}" if exc.description else ""
        raise SetupError(f"LumoAuth did not start the enrollment ({exc}){detail}") from exc
    code = started.get("enrollment_code")
    if not isinstance(code, str) or not code:
        _remove([home.key_path])
        raise SetupError("LumoAuth's answer has no enrollment code")
    server_fp = started.get("key_fingerprint")
    if isinstance(server_fp, str) and server_fp and server_fp != key.fingerprint:
        _remove([home.key_path])
        raise SetupError("LumoAuth reports a different key fingerprint than this machine's key. "
                         "Do not approve that enrollment.")
    link = started.get("verification_uri_complete") or started.get("verification_uri") or ""
    user_code = started.get("user_code", "")
    out("Approve this agent in LumoAuth:")
    out("")
    out(f"  1. Open        {link}")
    out(f"  2. Check code  {user_code}")
    out(f"  3. Check key   {key.fingerprint}")
    out("  4. Review what the agent may do, then approve.")
    out("")
    out("Approve only if you ran this command yourself just now and the code and key match.")
    out("Waiting for approval (Ctrl-C to stop)...")

    try:
        result = _poll(io, base, org, code, started)
    except KeyboardInterrupt:
        _remove([home.key_path])
        out("Setup stopped. Nothing was saved.")
        return 130
    if result is None:
        _remove([home.key_path])
        return 1

    # 6. Check the result.
    if result.get("key_id") and result["key_id"] != key.kid:
        _remove([home.key_path])
        raise SetupError("LumoAuth registered a different key than this machine's key")
    for name in ("agent_id", "issuer", "token_endpoint"):
        if not isinstance(result.get(name), str) or not result[name]:
            _remove([home.key_path])
            raise SetupError(f"LumoAuth's answer has no {name}")
    for name in ("issuer", "token_endpoint"):
        if not is_allowed_url(result[name]):
            _remove([home.key_path])
            raise SetupError(f"LumoAuth's {name} is not an https address")
    can_act = result.get("can_act_on_behalf_of_users") is True

    # 7. Save, configure Hermes, self-test.
    data: dict[str, Any] = {
        "version": 1, "baseUrl": base, "orgId": org, "agentId": result["agent_id"], "issuer": result["issuer"],
        "tokenEndpoint": result["token_endpoint"], "keyId": key.kid,
        "ownerUserId": str(result.get("owner_user_id") or ""), "canActOnBehalfOfUsers": can_act,
        "preset": preset, "decisionMode": "local", "approvals": approvals, "onUngranted": "ask",
        "taint": dict(DEFAULT_TAINT), "refreshSeconds": 60, "offlineGraceSeconds": 300, "receipts": True,
        "rememberApprovals": True, "extraProtectedPaths": [], "allowPaths": [],
    }
    if isinstance(result.get("agent_url"), str) and is_allowed_url(result["agent_url"]):
        data["agentUrl"] = result["agent_url"]
    home.write_config(data)
    out("")
    out(f"Approved. Agent {data['agentId']} is set up; settings are in {home.config_path}.")

    lumoauth_possible = approvals == "lumoauth" or (approvals == "auto" and can_act)
    if approvals == "lumoauth" and not can_act:
        out("Note: the agent may not act on behalf of its owner, so LumoAuth app approvals are not possible. "
            "Calls that need approval are blocked until you allow delegation in LumoAuth.")
    if opts.host_config:
        try:
            changes = configure_hermes(HOOK_TIMEOUT if lumoauth_possible else None, home=io.hermes_home)
            out("Hermes: " + ("; ".join(changes) if changes else "already configured") + ".")
        except (HostConfigError, OSError) as exc:
            out(f"Hermes's config.yaml was not changed ({exc}). Run these commands yourself:")
            out("  hermes plugins enable lumoauth")
            if lumoauth_possible:
                out(f"  hermes config set plugins.hook_callback_timeout {HOOK_TIMEOUT}")

    ok, granted = _self_test(io, home, data)
    out("")
    if granted is None:
        granted = [c for c in result.get("capabilities", []) if isinstance(c, str)]
    out(f"Granted capabilities ({len(granted)}): " + (", ".join(sorted(granted)) if granted else "none"))
    out("Everything else asks a person first" + (" or is blocked." if approvals != "off" else ": it is blocked."))
    out("")
    checks = doctor.run(home, offline=True, inp=doctor.gather(home, io.hermes_home))
    worth = [c for c in checks if c.level in ("warn", "critical")]
    out("Doctor: " + ("no problems found." if not worth else f"{len(worth)} thing(s) to look at:"))
    for check in worth:
        out(f"  {check.level.upper()} {check.id}: {check.finding}")
        if check.fix:
            out(f"      Fix: {check.fix}")
    out("")
    out("Restart Hermes (or the gateway) so that it loads the Guard. Check it any time with "
        "`hermes lumoauth status`.")
    return 0 if ok else 1


def _poll(io: SetupIO, base: str, org: str, code: str, started: dict[str, Any]) -> dict[str, Any] | None:
    try:
        interval = max(1.0, float(started.get("interval", 5)))
    except (TypeError, ValueError):
        interval = 5.0
    try:
        expires_in = max(30.0, float(started.get("expires_in", 900)))
    except (TypeError, ValueError):
        expires_in = 900.0
    # An approval made in the last seconds can still be fetched shortly after expires_in.
    deadline = time.monotonic() + expires_in + min(120.0, 2 * interval)
    failures = 0
    while time.monotonic() < deadline:
        io.sleep(interval)
        try:
            status, body = poll_enrollment(base, org, code, transport=io.transport)
        except NetworkError as exc:
            failures += 1
            if failures >= 20:
                io.out(f"LumoAuth cannot be reached ({exc}). Setup stopped.")
                return None
            continue
        failures = 0
        if status == 200:
            return body
        error = body.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5.0
            continue
        if error == "access_denied":
            io.out("The enrollment was refused in LumoAuth. Nothing was saved.")
            return None
        if error == "expired_token":
            io.out("The enrollment expired. Run `hermes lumoauth setup` again.")
            return None
        if status == 429 or status >= 500:
            continue
        io.out(f"LumoAuth answered HTTP {status} {error or ''}. Setup stopped.")
        return None
    io.out("The enrollment expired. Run `hermes lumoauth setup` again.")
    return None


def _self_test(io: SetupIO, home: GuardHome, data: dict[str, Any]) -> tuple[bool, list[str] | None]:
    from .keys import load as load_key

    cfg = home.read_config()
    if cfg is None:
        return False, None
    client = AgentClient(cfg, load_key(home), transport=io.transport)
    granted: list[str] | None = None
    try:
        try:
            client.token()
            io.out("Self-test: token ............ ok" + ("" if client.sender_constrained else " (not DPoP-bound)"))
        except LumoAuthError as exc:
            io.out(f"Self-test: token ............ FAILED ({exc})")
            return False, None
        try:
            me = client.me()
            identity = me.get("identity") if isinstance(me.get("identity"), dict) else {}
            caps = me.get("capabilities")
            granted = [c for c in caps if isinstance(c, str)] if isinstance(caps, list) else []
            io.out(f"Self-test: capabilities ..... ok (agent {identity.get('status', 'unknown')})")
        except LumoAuthError as exc:
            io.out(f"Self-test: capabilities ..... FAILED ({exc})")
            return False, None
        receipt = {"tool": "lumoauth.selftest", "decision": "allowed", "outcome": "succeeded", "duration_ms": 0,
                   "arguments_sha256": arguments_sha256({}), "occurred_at": iso()}
        try:
            response = client.report_tool_calls([receipt])
            if response.status_code != 200:
                io.out(f"Self-test: receipt .......... FAILED (HTTP {response.status_code})")
                return False, granted
            io.out("Self-test: receipt .......... ok")
        except LumoAuthError as exc:
            io.out(f"Self-test: receipt .......... FAILED ({exc})")
            return False, granted
        return True, granted
    finally:
        client.close()
