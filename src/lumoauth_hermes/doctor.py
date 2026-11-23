"""Doctor (SPEC §9): checks of the Guard and of Hermes's own security settings.

Doctor never changes anything. It never reads Hermes's ``.env`` file or looks for secret values
in ``config.yaml``, which Hermes forbids plugins to do. The settings that live in ``.env`` (gateway
tokens and allow-lists) come from the environment, where the ``hermes`` command loads them when it
starts. For the files themselves, doctor looks only at who may read them.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .client import AgentClient, AuthError, LumoAuthError
from .config import ConfigError, GuardConfig, GuardHome, mode_of
from .hermes_host import (
    HostConfigError,
    approval_mode,
    hermes_home,
    hook_callback_timeout,
    load_config,
    section,
    yolo_env,
)
from .keys import load as load_key

LEVELS = ("ok", "info", "warn", "critical")
REQUIRED_HOOK_TIMEOUT = 150
SUGGESTED_HOOK_TIMEOUT = 180

#: Gateway platforms whose ``<P>_ALLOWED_USERS`` / ``<P>_ALLOW_ALL_USERS`` Hermes reads (gateway/run_startup.py).
PLATFORMS = ("TELEGRAM", "DISCORD", "WHATSAPP", "WHATSAPP_CLOUD", "SLACK", "SIGNAL", "EMAIL", "SMS", "MATTERMOST",
             "MATRIX", "DINGTALK", "FEISHU", "WECOM", "WECOM_CALLBACK", "WEIXIN", "BLUEBUBBLES", "QQ")
#: Platforms whose bot token in the environment shows that they are set up (gateway/config.py).
PLATFORM_TOKENS = {"TELEGRAM": "TELEGRAM_BOT_TOKEN", "DISCORD": "DISCORD_BOT_TOKEN", "SLACK": "SLACK_BOT_TOKEN",
                   "MATTERMOST": "MATTERMOST_TOKEN", "MATRIX": "MATRIX_ACCESS_TOKEN", "WEIXIN": "WEIXIN_TOKEN"}
_TRUE = {"1", "true", "yes", "on"}


@dataclass
class Check:
    id: str
    level: str
    finding: str
    fix: str = ""


@dataclass
class DoctorInput:
    home: GuardHome
    hermes_home: Path
    hermes_config: dict[str, Any]
    hermes_config_error: str | None
    environ: Mapping[str, str]
    hook_timeout: float
    #: False in the standalone ``lumoauth-hermes`` command: Hermes's .env is not in its environment.
    sees_hermes_env: bool = True


def inside_hermes_command() -> bool:
    """True inside the ``hermes`` command, which loads Hermes's .env into the environment when it starts."""
    return "hermes_cli.main" in sys.modules


def gather(home: GuardHome | None = None, hermes_home_path: Path | None = None,
           environ: Mapping[str, str] | None = None) -> DoctorInput:
    home = home or GuardHome()
    hpath = hermes_home_path or hermes_home()
    error = None
    try:
        cfg = load_config(hpath if hermes_home_path else None)
    except HostConfigError as exc:
        cfg, error = {}, str(exc)
    sees = environ is not None or inside_hermes_command()
    env = os.environ if environ is None else environ
    timeout = hook_callback_timeout(cfg)
    return DoctorInput(home, hpath, cfg, error, env, timeout, sees)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE


def check_setup(inp: DoctorInput) -> tuple[Check, GuardConfig | None]:
    home = inp.home
    try:
        cfg = home.read_config()
    except ConfigError as exc:
        return Check("guard.setup", "critical", f"config.json cannot be used: {exc}",
                     "Run `hermes lumoauth reset --yes` and then `hermes lumoauth setup`."), None
    if cfg is None:
        return Check("guard.setup", "critical", "LumoAuth Guard is not set up: every tool call is blocked.",
                     "Run `hermes lumoauth setup`."), None
    try:
        key = load_key(home)
    except FileNotFoundError:
        return Check("guard.setup", "critical", "agent-key.pem is missing.",
                     "Run `hermes lumoauth reset --yes` and then `hermes lumoauth setup`."), cfg
    except (OSError, ValueError):
        return Check("guard.setup", "critical", "agent-key.pem cannot be loaded.",
                     "Run `hermes lumoauth reset --yes` and then `hermes lumoauth setup`."), cfg
    if key.kid != cfg.key_id:
        return Check("guard.setup", "critical", "agent-key.pem does not match keyId in config.json.",
                     "Run `hermes lumoauth reset --yes` and then `hermes lumoauth setup`."), cfg
    problems = []
    fixes = []
    for path, wanted in ((home.config_path, 0o600), (home.key_path, 0o600), (home.path, 0o700)):
        mode = mode_of(path)
        if mode is not None and mode & 0o077:
            problems.append(f"{path.name} has mode {mode:o}")
            fixes.append(f"chmod {wanted:o} '{path}'")
    if problems:
        level = "critical" if (mode_of(home.key_path) or 0) & 0o044 else "warn"
        return Check("guard.setup", level, "Set up, but other users may read Guard files: " + "; ".join(problems) + ".",
                     "Run: " + " && ".join(fixes)), cfg
    finding = f"Set up as agent {cfg.agent_id} in {cfg.org_id} (key {key.fingerprint})."
    if cfg.warnings:
        finding += " config.json: " + "; ".join(cfg.warnings)
        return Check("guard.setup", "warn", finding, "Correct the values in config.json."), cfg
    return Check("guard.setup", "ok", finding), cfg


def check_connectivity(inp: DoctorInput, cfg: GuardConfig | None, offline: bool) -> Check:
    if cfg is None:
        return Check("guard.connectivity", "info", "Skipped: not set up.")
    if offline:
        return Check("guard.connectivity", "info", "Skipped (--offline).")
    try:
        key = load_key(inp.home)
    except (OSError, ValueError):
        return Check("guard.connectivity", "info", "Skipped: no usable key.")
    client = AgentClient(cfg, key)
    try:
        body = client.me(timeout=10.0)
    except AuthError as exc:
        return Check("guard.connectivity", "critical", f"LumoAuth refused the agent ({exc}).",
                     f"Check the agent in LumoAuth: {cfg.agent_url}")
    except LumoAuthError as exc:
        return Check("guard.connectivity", "warn", f"LumoAuth cannot be reached: {exc}.",
                     "Check the network; calls are blocked once the offline grace period ends.")
    finally:
        client.close()
    identity = body.get("identity") if isinstance(body.get("identity"), dict) else {}
    status = identity.get("status", "unknown")
    caps = body.get("capabilities") if isinstance(body.get("capabilities"), list) else []
    if status != "active":
        return Check("guard.connectivity", "critical", f"The agent's status in LumoAuth is {status}: every call is "
                     "blocked.", f"Reactivate the agent in LumoAuth: {cfg.agent_url}")
    tail = "" if client.sender_constrained else " The token is not DPoP-bound."
    return Check("guard.connectivity", "ok" if client.sender_constrained else "warn",
                 f"Token and capabilities work: agent active, {len(caps)} capabilities.{tail}")


def _hermes_bypass(inp: DoctorInput) -> str | None:
    if yolo_env() or _truthy(inp.environ.get("HERMES_YOLO_MODE")):
        return "HERMES_YOLO_MODE is set"
    if approval_mode(inp.hermes_config) == "off":
        return "approvals.mode is off"
    return None


def check_approvals(inp: DoctorInput, cfg: GuardConfig | None) -> Check:
    if cfg is None:
        return Check("guard.approvals", "info", "Skipped: not set up.")
    if cfg.approvals == "off":
        return Check("guard.approvals", "info", "approvals is off: calls that need a person are blocked.")
    if cfg.approvals == "lumoauth" and not cfg.can_act_on_behalf:
        return Check("guard.approvals", "critical", "approvals is lumoauth, but the agent may not act on behalf of "
                     "its owner, so every call that needs approval is blocked.",
                     f"Allow delegation for the agent in LumoAuth ({cfg.agent_url}) or set approvals to auto.")
    bypass = _hermes_bypass(inp)
    if cfg.lumoauth_approvals_possible():
        finding = "Approvals go to the owner's LumoAuth app."
        if cfg.approvals == "auto":
            finding += " If the app cannot be reached, Hermes asks in the chat or terminal."
        if bypass and cfg.approvals == "auto":
            finding += f" That fallback is blocked: {bypass}."
        return Check("guard.approvals", "ok", finding)
    if bypass:
        return Check("guard.approvals", "critical", f"Approvals use Hermes's prompt, and {bypass}: the Guard blocks "
                     "every call that needs approval.", "Run `hermes config set approvals.mode manual`.")
    return Check("guard.approvals", "ok", "Approvals use Hermes's own prompt (terminal or chat buttons).")


def check_hook_timeout(inp: DoctorInput, cfg: GuardConfig | None, check_id: str) -> Check:
    if cfg is None or not cfg.lumoauth_approvals_possible():
        return Check(check_id, "ok", "No LumoAuth app approvals, so the default hook timeout is enough.")
    timeout = inp.hook_timeout
    if timeout <= 0:
        return Check(check_id, "ok", "plugins.hook_callback_timeout is 0 (no limit).")
    if timeout < REQUIRED_HOOK_TIMEOUT:
        return Check(check_id, "warn", f"Hermes waits at most {timeout:g} s for a hook, so an approval in the "
                     f"LumoAuth app has only {max(timeout - 5, 0):g} s.",
                     f"Run `hermes config set plugins.hook_callback_timeout {SUGGESTED_HOOK_TIMEOUT}`.")
    return Check(check_id, "ok", f"plugins.hook_callback_timeout is {timeout:g} s.")


def check_plaintext(inp: DoctorInput) -> Check:
    """Hermes keeps API keys in plaintext in its .env. Plugins may not read that file, so this looks
    only at who may read it (SPEC §9)."""
    path = inp.hermes_home / ".env"
    mode = mode_of(path)
    if mode is None:
        return Check("secrets.plaintext", "ok", f"There is no {path}, where Hermes keeps API keys in plaintext.")
    if mode & 0o077:
        return Check("secrets.plaintext", "critical" if mode & 0o004 else "warn",
                     f"Hermes keeps API keys in plaintext in {path}, and other users may read it (mode {mode:o}).",
                     f"Run: chmod 600 '{path}'")
    return Check("secrets.plaintext", "ok", f"Hermes keeps API keys in plaintext in {path}, which only you may "
                 "read. The Guard never reads it, and blocks tools from reading it.")


def check_permissions(inp: DoctorInput) -> Check:
    home = inp.hermes_home
    files = [home / "config.yaml", home / ".env", home / "auth.json"]
    tokens = home / "mcp-tokens"
    if tokens.is_dir():
        try:
            files.extend(sorted(p for p in tokens.iterdir() if p.is_file())[:200])
        except OSError:
            pass
    worst = "ok"
    found = []
    for path in files:
        mode = mode_of(path)
        if mode is None or not mode & 0o077:
            continue
        sensitive = path.name != "config.yaml"
        level = "critical" if sensitive and mode & 0o004 else "warn"
        if LEVELS.index(level) > LEVELS.index(worst):
            worst = level
        found.append(path)
    if not found:
        return Check("fs.permissions", "ok", "Hermes configuration and credential files are readable by you only.")
    shown = ", ".join(f"{p.name} ({mode_of(p):o})" for p in found[:5])  # type: ignore[str-format]
    return Check("fs.permissions", worst, f"Other users may read: {shown}.",
                 "Run: " + " && ".join(f"chmod 600 '{p}'" for p in found[:5]))


def check_hermes_approvals(inp: DoctorInput) -> Check:
    bypass = _hermes_bypass(inp)
    if bypass:
        return Check("hermes.approvals-mode", "critical", f"{bypass}: Hermes would run flagged calls without "
                     "asking, so the Guard blocks every call that needs approval.",
                     "Run `hermes config set approvals.mode manual` and start Hermes without --yolo.")
    return Check("hermes.approvals-mode", "ok", f"approvals.mode is {approval_mode(inp.hermes_config)}.")


def check_backend(inp: DoctorInput) -> Check:
    backend = str(section(inp.hermes_config, "terminal").get("backend") or "local").strip().lower()
    if backend == "local":
        return Check("hermes.terminal-backend", "warn", "Commands and code run directly on this machine "
                     "(terminal.backend: local). The Guard scans them, but a scan is not a sandbox.",
                     "Run `hermes config set terminal.backend docker`.")
    return Check("hermes.terminal-backend", "ok", f"Commands run in an isolated backend ({backend}).")


def messaging_platforms(inp: DoctorInput) -> list[str]:
    found = []
    platforms_cfg = section(inp.hermes_config, "platforms")
    for name in PLATFORMS:
        token = PLATFORM_TOKENS.get(name)
        entry = platforms_cfg.get(name.lower()) if isinstance(platforms_cfg.get(name.lower()), dict) else {}
        if (token and inp.environ.get(token)) or entry.get("enabled") is True:
            found.append(name)
    return found


def check_allowed_users(inp: DoctorInput) -> Check:
    check = _allowed_users(inp)
    if not inp.sees_hermes_env and check.level in ("ok", "info"):
        return Check(check.id, "info", f"{check.finding} This command does not see Hermes's .env, where the "
                     "gateway settings usually are.", "Run `hermes lumoauth doctor`, which sees them.")
    return check


def _allowed_users(inp: DoctorInput) -> Check:
    env = inp.environ
    open_all = [v for v in ["GATEWAY_ALLOW_ALL_USERS", *(f"{p}_ALLOW_ALL_USERS" for p in PLATFORMS)]
                if _truthy(env.get(v))]
    if open_all:
        return Check("hermes.allowed-users", "critical", f"Anyone may message the agent: {', '.join(open_all)} "
                     "is on.", f"Remove {open_all[0]} from the Hermes .env and set an allow-list such as "
                     "TELEGRAM_ALLOWED_USERS.")
    platforms = messaging_platforms(inp)
    open_policy = []
    for name, entry in section(inp.hermes_config, "platforms").items():
        if isinstance(entry, dict) and "open" in (str(entry.get("dm_policy", "")), str(entry.get("group_policy", ""))):
            open_policy.append(str(name))
    if open_policy:
        return Check("hermes.allowed-users", "critical", f"dm_policy or group_policy is open on: "
                     f"{', '.join(open_policy)}.", "Set the policy to allowlist or pairing in config.yaml.")
    if not platforms:
        return Check("hermes.allowed-users", "ok", "No gateway messaging platform is set up.")
    missing = [p for p in platforms if not env.get(f"{p}_ALLOWED_USERS") and not env.get("GATEWAY_ALLOWED_USERS")]
    if missing:
        return Check("hermes.allowed-users", "info", f"No allow-list for: {', '.join(p.title() for p in missing)}"
                     ". Hermes then relies on pairing codes to admit people.",
                     f"Set {missing[0]}_ALLOWED_USERS in the Hermes .env to your own user id.")
    return Check("hermes.allowed-users", "ok", f"Allow-lists are set for {', '.join(p.title() for p in platforms)}.")


def check_approvers(inp: DoctorInput) -> Check:
    approvers = section(inp.hermes_config, "approvals").get("approvers", ["*"])
    platforms = messaging_platforms(inp)
    if approvers == ["*"] and platforms:
        return Check("hermes.approvers", "warn", "approvals.approvers is [\"*\"]: in a group chat, anyone admitted "
                     "may answer an approval prompt.",
                     "Set approvals.approvers in config.yaml to [] (the requester and admins) or to your user ids.")
    return Check("hermes.approvers", "ok", "Only chosen people answer approval prompts in chats."
                 if approvers != ["*"] else "No group chat platform is set up.")


def check_safe_mode(inp: DoctorInput) -> Check:
    if _truthy(inp.environ.get("HERMES_SAFE_MODE")):
        return Check("hermes.safe-mode", "critical", "HERMES_SAFE_MODE is set: Hermes loads no plugin, so the Guard "
                     "is off.", "Remove HERMES_SAFE_MODE from the environment.")
    return Check("hermes.safe-mode", "info", "`hermes --safe-mode` and HERMES_SAFE_MODE=1 start Hermes without "
                 "any plugin, so without the Guard.", "Use safe mode only in a session that you watch.")


def run(home: GuardHome | None = None, *, offline: bool = False,
        inp: DoctorInput | None = None) -> list[Check]:
    inp = inp or gather(home)
    setup, cfg = check_setup(inp)
    checks = [
        setup,
        check_connectivity(inp, cfg, offline),
        check_approvals(inp, cfg),
        check_hook_timeout(inp, cfg, "guard.hook-timeout"),
        check_plaintext(inp),
        check_permissions(inp),
        check_hermes_approvals(inp),
        check_backend(inp),
        check_allowed_users(inp),
        check_approvers(inp),
        check_hook_timeout(inp, cfg, "hermes.hook-timeout"),
        check_safe_mode(inp),
    ]
    if inp.hermes_config_error:
        checks.append(Check("hermes.config", "warn", f"Hermes's config.yaml could not be read: "
                            f"{inp.hermes_config_error}.", "Fix config.yaml; the Hermes checks above used defaults."))
    return checks


def as_json(checks: list[Check]) -> dict[str, Any]:
    summary = {level: sum(1 for c in checks if c.level == level) for level in LEVELS}
    return {"checks": [asdict(c) for c in checks], "summary": summary}


_MARK = {"ok": "ok", "info": "info", "warn": "WARN", "critical": "CRITICAL"}


def format_text(checks: list[Check]) -> str:
    width = max(len(c.id) for c in checks)
    lines = []
    for check in checks:
        lines.append(f"  {_MARK[check.level]:<8} {check.id:<{width}}  {check.finding}")
        if check.fix and check.level != "ok":
            lines.append(f"  {'':<8} {'':<{width}}  Fix: {check.fix}")
    summary = as_json(checks)["summary"]
    lines.append("")
    lines.append(f"  {summary['critical']} critical, {summary['warn']} warnings, {summary['info']} notes, "
                 f"{summary['ok']} ok.")
    return "\n".join(lines)
