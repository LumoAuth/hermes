"""What the Guard reads from Hermes, and what setup writes to Hermes's config.yaml.

Inside a Hermes process the Guard asks Hermes's own functions (the approval
mode, yolo, the hook timeout, the session's working directory). Outside one
(the ``lumoauth-hermes`` command, tests) it reads ``config.yaml`` itself.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("lumoauth_hermes")

DEFAULT_HOOK_TIMEOUT = 30.0
MAX_HOOK_TIMEOUT = 600.0
PLUGIN_NAME = "lumoauth"
_TRUE = {"1", "true", "yes", "on"}


class HostConfigError(Exception):
    """Hermes's config.yaml could not be read or written."""


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # type: ignore[import-not-found]

        return Path(get_hermes_home())
    except Exception:
        value = os.environ.get("HERMES_HOME", "").strip()
        return Path(value).expanduser() if value else Path.home() / ".hermes"


def _yaml_load(text: str) -> Any:
    try:
        from ruamel.yaml import YAML  # type: ignore[import-not-found]

        return YAML(typ="safe", pure=True).load(text)
    except ImportError:
        pass
    try:
        import yaml  # type: ignore[import-not-found]

        return yaml.safe_load(text)
    except ImportError as exc:
        raise HostConfigError("reading config.yaml needs ruamel.yaml or PyYAML (Hermes ships ruamel.yaml)") from exc


def read_config_file(path: Path) -> dict[str, Any]:
    """Parse a config.yaml; {} when it does not exist."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise HostConfigError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        data = _yaml_load(text)
    except HostConfigError:
        raise
    except Exception as exc:
        raise HostConfigError(f"{path} is not valid YAML") from exc
    return data if isinstance(data, dict) else {}


def load_config(home: Path | None = None) -> dict[str, Any]:
    """Hermes's effective config: Hermes's own loader when available, else the file."""
    if home is None:
        try:
            from hermes_cli.config import load_config_readonly  # type: ignore[import-not-found]

            value = load_config_readonly()
            if isinstance(value, dict):
                return value
        except Exception:  # noqa: S110 (fall back to reading the file)
            pass
    return read_config_file((home or hermes_home()) / "config.yaml")


def section(cfg: dict[str, Any], name: str) -> dict[str, Any]:
    value = cfg.get(name)
    return value if isinstance(value, dict) else {}


def approval_mode(cfg: dict[str, Any]) -> str:
    raw = section(cfg, "approvals").get("mode", "smart")
    if raw is False:
        return "off"
    text = str(raw).strip().lower()
    return text if text in ("manual", "smart", "off") else "manual"


def yolo_env() -> bool:
    return os.environ.get("HERMES_YOLO_MODE", "").strip().lower() in _TRUE


def hook_callback_timeout(cfg: dict[str, Any] | None = None) -> float:
    """``plugins.hook_callback_timeout`` as Hermes applies it (0 means no limit)."""
    if cfg is None:
        try:
            cfg = load_config()
        except HostConfigError:
            return DEFAULT_HOOK_TIMEOUT
    raw = section(cfg, "plugins").get("hook_callback_timeout")
    if raw is None:
        return DEFAULT_HOOK_TIMEOUT
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_HOOK_TIMEOUT
    if value < 0:
        return DEFAULT_HOOK_TIMEOUT
    return min(value, MAX_HOOK_TIMEOUT)


class HermesHost:
    """Questions that the runtime asks Hermes; tests replace it with a fake."""

    def auto_grant_reason(self) -> str | None:
        """Why Hermes would grant an ``approve`` directive without asking a person (SPEC §6.4), or None.

        Hermes has no public function for this, so this reads ``tools.approval`` (the same
        checks that ``request_tool_approval`` makes) and falls back to config.yaml and
        ``HERMES_YOLO_MODE`` when those internals change.

        Hermes grants without asking under ``approvals.mode: off``, ``--yolo`` or
        ``/yolo``, and in an unattended context (cron, ``-q``, webhook) whose
        ``approvals.<context>_mode`` is ``approve``.
        """
        try:
            from tools import approval as hermes_approval  # type: ignore[import-not-found]
            from tools import approval_context  # type: ignore[import-not-found]
        except Exception:
            return self._auto_grant_from_config()
        try:
            if hermes_approval._yolo_active():
                return "yolo mode is on"
            if approval_context._get_approval_mode() == "off":
                return "approvals.mode is off"
            _callback, is_cli, is_gateway, is_ask = hermes_approval._presence()
            if not (is_cli or is_gateway or is_ask):
                for context in hermes_approval._unattended_contexts():
                    if context.mode() == "approve":
                        return f"approvals.{context.cfg_key} is approve"
                    break
            return None
        except AttributeError:
            pass
        except Exception:
            logger.debug("Hermes approval state could not be read", exc_info=True)
        try:
            if hermes_approval.is_approval_bypass_active():
                return "approvals are switched off"
            return None
        except Exception:
            return self._auto_grant_from_config()

    def _auto_grant_from_config(self) -> str | None:
        if yolo_env():
            return "yolo mode is on"
        try:
            if approval_mode(load_config()) == "off":
                return "approvals.mode is off"
        except HostConfigError:
            return "Hermes's approval settings cannot be read"
        return None

    def hook_timeout(self) -> float:
        return hook_callback_timeout()


# ── Writing config.yaml (setup only) ────────────────────────────────────────

def _apply(cfg: Any, hook_timeout: int | None, changes: list[str]) -> None:
    plugins = cfg.get("plugins")
    if plugins is None:
        cfg["plugins"] = {}
        plugins = cfg["plugins"]
    if not hasattr(plugins, "get"):
        raise HostConfigError("plugins in config.yaml is not a mapping")
    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        plugins["enabled"] = [PLUGIN_NAME]
        changes.append("plugins.enabled: [lumoauth]")
    elif PLUGIN_NAME not in enabled:
        enabled.append(PLUGIN_NAME)
        changes.append("plugins.enabled += lumoauth")
    disabled = plugins.get("disabled")
    if isinstance(disabled, list) and PLUGIN_NAME in disabled:
        disabled.remove(PLUGIN_NAME)
        changes.append("plugins.disabled -= lumoauth")
    if hook_timeout:
        current = plugins.get("hook_callback_timeout")
        try:
            number = float(current) if current is not None else None
        except (TypeError, ValueError):
            number = None
        # 0 means "no limit" in Hermes: leave it. Never lower a larger value.
        if number is None or 0 < number < hook_timeout:
            plugins["hook_callback_timeout"] = hook_timeout
            changes.append(f"plugins.hook_callback_timeout: {hook_timeout}")


def configure_hermes(hook_timeout: int | None, home: Path | None = None) -> list[str]:
    """Enable the plugin and raise the hook timeout. Returns the changes made.

    Uses Hermes's own comment-preserving writer when this runs inside Hermes,
    else a ruamel.yaml round trip that keeps comments.
    """
    changes: list[str] = []
    if home is None:
        try:
            from hermes_cli.config import (  # type: ignore[import-not-found]
                atomic_config_write,
                get_config_path,
                read_user_config_raw,
            )
        except Exception:
            atomic_config_write = None  # type: ignore[assignment]
        if atomic_config_write is not None:
            path = get_config_path()
            data = read_user_config_raw(path)
            _apply(data, hook_timeout, changes)
            if changes:
                atomic_config_write(path, data)
            return changes
    path = (home or hermes_home()) / "config.yaml"
    try:
        from ruamel.yaml import YAML  # type: ignore[import-not-found]
    except ImportError as exc:
        raise HostConfigError("editing config.yaml needs ruamel.yaml (Hermes ships it)") from exc
    yaml = YAML()
    yaml.preserve_quotes = True
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        text = ""
    except OSError as exc:
        raise HostConfigError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        data = yaml.load(text) if text.strip() else None
    except Exception as exc:
        raise HostConfigError(f"{path} is not valid YAML; fix it first") from exc
    if data is None:
        from ruamel.yaml.comments import CommentedMap  # type: ignore[import-not-found]

        data = CommentedMap()
    if not hasattr(data, "get"):
        raise HostConfigError(f"{path} does not hold a mapping")
    _apply(data, hook_timeout, changes)
    if not changes:
        return changes
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = 0o600
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".config-", suffix=".yaml", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.dump(data, handle)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return changes
