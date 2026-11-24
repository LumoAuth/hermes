"""The Guard home and its files (SPEC §3): config.json, agent-key.pem, lock, receipts queue."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contract import RISKS
from .decide import DecisionConfig, TaintPolicy
from .environment import default_guard_home

CONFIG_FILE = "config.json"
KEY_FILE = "agent-key.pem"
LOCK_FILE = "lock"
QUEUE_FILE = "receipts-queue.jsonl"
STATUS_FILE = "runtime-status.json"

APPROVALS = ("auto", "lumoauth", "host", "off")
DECISION_MODES = ("local", "server")
ON_UNGRANTED = ("ask", "block")
PRESETS = ("observer", "assistant", "builder")

DEFAULT_TAINT = {"enabled": True, "windowSeconds": 1800, "escalate": ["external"]}
# Reporting is opt-in (SPEC §3.1): receipts and token usage are sent only when the user said yes.
DEFAULTS: dict[str, Any] = {
    "preset": "assistant",
    "decisionMode": "local",
    "approvals": "auto",
    "onUngranted": "ask",
    "taint": DEFAULT_TAINT,
    "refreshSeconds": 60,
    "offlineGraceSeconds": 300,
    "receipts": False,
    "rememberApprovals": True,
    "extraProtectedPaths": [],
    "allowPaths": [],
    "reportUsage": False,
}
REQUIRED = ("baseUrl", "orgId", "agentId", "issuer", "tokenEndpoint", "keyId")


class ConfigError(Exception):
    """config.json exists but cannot be used."""


def is_allowed_url(url: str) -> bool:
    """https, or http to this machine only (a local LumoAuth for development)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if not parts.netloc or parts.username or parts.password:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and (parts.hostname or "") in ("localhost", "127.0.0.1", "::1")


@dataclass
class GuardConfig:
    data: dict[str, Any]
    warnings: list[str] = field(default_factory=list)

    # Identity ---------------------------------------------------------------
    @property
    def base_url(self) -> str:
        return str(self.data["baseUrl"]).rstrip("/")

    @property
    def org_id(self) -> str:
        return str(self.data["orgId"])

    @property
    def agent_id(self) -> str:
        return str(self.data["agentId"])

    @property
    def issuer(self) -> str:
        return str(self.data["issuer"])

    @property
    def token_endpoint(self) -> str:
        return str(self.data["tokenEndpoint"])

    @property
    def key_id(self) -> str:
        return str(self.data["keyId"])

    @property
    def owner_user_id(self) -> str:
        return str(self.data.get("ownerUserId") or "")

    @property
    def can_act_on_behalf(self) -> bool:
        return self.data.get("canActOnBehalfOfUsers") is True

    @property
    def agent_url(self) -> str:
        url = self.data.get("agentUrl")
        if isinstance(url, str) and is_allowed_url(url):
            return url
        return f"{self.base_url}/orgs/{self.org_id}/portal/agents/{self.agent_id}"

    # Settings ---------------------------------------------------------------
    def get(self, key: str) -> Any:
        return self.data.get(key, DEFAULTS.get(key))

    @property
    def approvals(self) -> str:
        return self.get("approvals")

    @property
    def decision_mode(self) -> str:
        return self.get("decisionMode")

    @property
    def taint(self) -> TaintPolicy:
        t = self.get("taint")
        return TaintPolicy(bool(t["enabled"]), int(t["windowSeconds"]), tuple(t["escalate"]))

    def decision_config(self) -> DecisionConfig:
        return DecisionConfig(approvals=self.approvals, on_ungranted=self.get("onUngranted"),
                              refresh_seconds=self.get("refreshSeconds"),
                              offline_grace_seconds=self.get("offlineGraceSeconds"), taint=self.taint)

    def lumoauth_approvals_possible(self) -> bool:
        """Whether a call may wait for the LumoAuth app (and needs a long hook timeout)."""
        return self.approvals == "lumoauth" or (self.approvals == "auto" and self.can_act_on_behalf)


def _bounded_int(data: dict[str, Any], key: str, low: int, high: int, warnings: list[str]) -> None:
    value = data.get(key, DEFAULTS[key])
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        warnings.append(f"{key}: {value!r} is out of range {low}-{high}; using {DEFAULTS[key]}")
        data[key] = DEFAULTS[key]


def _choice(data: dict[str, Any], key: str, choices: tuple[str, ...], warnings: list[str]) -> None:
    value = data.get(key, DEFAULTS[key])
    if value not in choices:
        warnings.append(f"{key}: {value!r} is not one of {', '.join(choices)}; using {DEFAULTS[key]}")
        data[key] = DEFAULTS[key]


def _bool(data: dict[str, Any], key: str, warnings: list[str]) -> None:
    value = data.get(key, DEFAULTS[key])
    if not isinstance(value, bool):
        warnings.append(f"{key}: {value!r} is not true or false; using {DEFAULTS[key]}")
        data[key] = DEFAULTS[key]


def _paths(data: dict[str, Any], key: str, warnings: list[str]) -> None:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        warnings.append(f"{key}: must be a list of paths; using []")
        data[key] = []


def parse_config(raw: Any) -> GuardConfig:
    """Validate config.json (SPEC §3.1). Unknown keys are ignored; bad values fall back with a warning."""
    if not isinstance(raw, dict):
        raise ConfigError("config.json must hold a JSON object")
    data = dict(raw)
    missing = [k for k in REQUIRED if not isinstance(data.get(k), str) or not data.get(k)]
    if missing:
        raise ConfigError("config.json lacks " + ", ".join(missing))
    for key in ("baseUrl", "issuer", "tokenEndpoint"):
        if not is_allowed_url(data[key]):
            raise ConfigError(f"{key} must be an https URL")
    if data.get("version", 1) != 1:
        raise ConfigError(f"config.json version {data.get('version')!r} is not supported")
    warnings: list[str] = []
    _choice(data, "decisionMode", DECISION_MODES, warnings)
    _choice(data, "approvals", APPROVALS, warnings)
    _choice(data, "onUngranted", ON_UNGRANTED, warnings)
    _bounded_int(data, "refreshSeconds", 30, 600, warnings)
    _bounded_int(data, "offlineGraceSeconds", 0, 3600, warnings)
    for key in ("receipts", "rememberApprovals", "reportUsage"):
        _bool(data, key, warnings)
    for key in ("extraProtectedPaths", "allowPaths"):
        _paths(data, key, warnings)
    taint = data.get("taint", DEFAULT_TAINT)
    clean = dict(DEFAULT_TAINT)
    if isinstance(taint, dict):
        if isinstance(taint.get("enabled"), bool):
            clean["enabled"] = taint["enabled"]
        elif "enabled" in taint:
            warnings.append("taint.enabled is not true or false; using true")
        window = taint.get("windowSeconds", 1800)
        if isinstance(window, int) and not isinstance(window, bool) and 60 <= window <= 86400:
            clean["windowSeconds"] = window
        else:
            warnings.append(f"taint.windowSeconds: {window!r} is out of range 60-86400; using 1800")
        escalate = taint.get("escalate", ["external"])
        allowed = set(RISKS) | {"egress"}
        if isinstance(escalate, list) and all(isinstance(e, str) and e in allowed for e in escalate):
            clean["escalate"] = list(escalate)
        else:
            warnings.append("taint.escalate must list risks or egress; using [\"external\"]")
    else:
        warnings.append("taint must be an object; using the defaults")
    data["taint"] = clean
    return GuardConfig(data, warnings)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class GuardHome:
    """The Guard home directory (mode 0700) and its files (mode 0600)."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else Path(default_guard_home())

    @property
    def config_path(self) -> Path:
        return self.path / CONFIG_FILE

    @property
    def key_path(self) -> Path:
        return self.path / KEY_FILE

    @property
    def lock_path(self) -> Path:
        return self.path / LOCK_FILE

    @property
    def queue_path(self) -> Path:
        return self.path / QUEUE_FILE

    @property
    def status_path(self) -> Path:
        return self.path / STATUS_FILE

    def ensure(self) -> None:
        """Create the Guard home (and ``~/.lumoauth`` above it) with mode 0700."""
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        targets = [self.path]
        # The default home is ~/.lumoauth/guard/hermes: ~/.lumoauth as a whole is the Guard's.
        if ".lumoauth" in self.path.parts:
            for parent in self.path.parents:
                targets.append(parent)
                if parent.name == ".lumoauth":
                    break
        for directory in targets:
            try:
                if stat.S_IMODE(directory.stat().st_mode) & 0o077:
                    os.chmod(directory, 0o700)
            except OSError:
                pass

    def write_private(self, path: Path, data: bytes) -> None:
        """Atomically write a file with mode 0600."""
        self.ensure()
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
        try:
            # mkstemp creates the file with mode 0600.
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def write_json(self, path: Path, value: Any) -> None:
        self.write_private(path, (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8"))

    # config ------------------------------------------------------------------
    def read_config(self) -> GuardConfig | None:
        """The parsed config, None when there is none; raises ConfigError when it is unusable."""
        try:
            text = self.config_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConfigError(f"cannot read config.json: {exc.strerror}") from exc
        try:
            raw = json.loads(text)
        except ValueError as exc:
            raise ConfigError("config.json is not valid JSON") from exc
        return parse_config(raw)

    def write_config(self, data: dict[str, Any]) -> None:
        self.write_json(self.config_path, data)

    # lock --------------------------------------------------------------------
    def is_locked(self) -> bool:
        return self.lock_path.exists()

    def lock_info(self) -> str | None:
        try:
            return self.lock_path.read_text(encoding="utf-8").strip() or "locked"
        except FileNotFoundError:
            return None
        except OSError:
            return "locked"

    def lock(self, reason: str = "") -> None:
        text = _now_iso() + (" " + " ".join(reason.split()) if reason else "")
        self.write_private(self.lock_path, (text[:500] + "\n").encode("utf-8"))

    def unlock(self) -> bool:
        try:
            self.lock_path.unlink()
            return True
        except FileNotFoundError:
            return False

    # status ------------------------------------------------------------------
    def read_status(self) -> dict[str, Any] | None:
        try:
            value = json.loads(self.status_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None


def mode_of(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
