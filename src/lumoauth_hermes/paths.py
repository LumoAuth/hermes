"""Path expansion and the protected path classes of SPEC §5.1 (Hermes)."""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote

from .environment import Env

GUARD = "guard"
HOST_CONFIG = "hostConfig"
HOST_SKILLS = "hostSkills"
HOST_STATE = "hostState"
SECRETS = "secrets"
SECRET_FILE = "secretFile"  # noqa: S105 (a class name)
PERSISTENCE = "persistence"
CLASS_ORDER = (GUARD, HOST_CONFIG, HOST_SKILLS, HOST_STATE, SECRETS, SECRET_FILE, PERSISTENCE)

DENY = "deny"
APPROVE = "approve"

# What each class means for a path, by the column of SPEC §5.1.
COLUMNS: dict[str, dict[str, str | None]] = {
    "read": {GUARD: DENY, HOST_CONFIG: DENY, HOST_SKILLS: None, HOST_STATE: DENY, SECRETS: DENY,
             SECRET_FILE: APPROVE, PERSISTENCE: None},
    "write": {GUARD: DENY, HOST_CONFIG: DENY, HOST_SKILLS: DENY, HOST_STATE: DENY, SECRETS: DENY,
              SECRET_FILE: APPROVE, PERSISTENCE: APPROVE},
    "shell": {GUARD: DENY, HOST_CONFIG: DENY, HOST_SKILLS: APPROVE, HOST_STATE: APPROVE, SECRETS: DENY,
              SECRET_FILE: APPROVE, PERSISTENCE: APPROVE},
}

CLASS_TEXT = {
    GUARD: "LumoAuth Guard's own files",
    HOST_CONFIG: "Hermes configuration, credentials or plugins",
    HOST_SKILLS: "Hermes's skills (instructions for every future session)",
    HOST_STATE: "Hermes's own data",
    SECRETS: "a credential store",
    SECRET_FILE: "a file that usually holds secrets",
    PERSISTENCE: "a file that runs at login or start-up",
}

_HOST_CONFIG_FILES = ("config.yaml", ".env", "auth.json", "mcp-tokens/**", "plugins/**", "plugin-data/**",
                      "shell-hooks-allowlist.json")

_SECRETS = (
    "~/.ssh/**", "~/.gnupg/**", "~/.aws/**", "~/.azure/**", "~/.config/gcloud/**", "~/.kube/**",
    "~/.docker/config.json", "~/.npmrc", "~/.pypirc", "~/.netrc", "~/.git-credentials", "~/.config/gh/hosts.yml",
    "~/.password-store/**", "~/Library/Keychains/**", "~/.config/google-chrome/**", "~/.config/chromium/**",
    "~/.mozilla/**", "~/Library/Application Support/Google/Chrome/**", "~/Library/Application Support/Firefox/**",
)

_PERSISTENCE = (
    "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.config/fish/config.fish",
    "~/.config/autostart/**", "~/.config/systemd/user/**", "~/Library/LaunchAgents/**",
)

_ENV_EXAMPLES = frozenset({".env.example", ".env.sample", ".env.template", ".env.dist"})
_KEY_PREFIXES = ("id_rsa", "id_ed25519", "id_ecdsa")


def is_secret_file_name(name: str, case_insensitive: bool = False) -> bool:
    """SPEC §5.1 ``secretFile`` by file name: ``.env``/``.env.*``, ``*.pem``, ``*.key``, ``id_rsa*`` ..."""
    if not name:
        return False
    n = name.lower() if case_insensitive else name
    if n == ".env" or (n.startswith(".env.") and n not in _ENV_EXAMPLES):
        return True
    if n.endswith(".pem") or n.endswith(".key"):
        return True
    return n.startswith(_KEY_PREFIXES)


def expand_variables(text: str, env: Env) -> str:
    """Replace ``$NAME`` and ``${NAME}`` for the variables that the rules know (HOME ...)."""
    values = env.expansions()
    for name in sorted(values, key=len, reverse=True):
        value = values[name]
        text = text.replace("${" + name + "}", value)
        text = re.sub(r"\$" + re.escape(name) + r"(?![A-Za-z0-9_])", lambda _m, v=value: v, text)
    return text


def _clean(path: str) -> str:
    normalized = posixpath.normpath(path)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def resolve_path(raw: str, env: Env, cwd: str | None = None) -> list[str]:
    """Absolute forms of a path argument: the lexical form, plus the real path when it differs.

    ``~``, ``$HOME`` and ``${HOME}`` are expanded, a relative path is joined
    to ``cwd`` (default: the host's working directory), ``..`` is resolved
    lexically and, when the path exists on this machine, symlinks too.
    """
    if not isinstance(raw, str):
        return []
    text = raw.strip()
    if not text:
        return []
    if text.lower().startswith("file://"):
        text = unquote(text[7:])
        if text.lower().startswith("localhost/"):
            text = text[9:]
    text = expand_variables(text, env)
    if text == "~" or text.startswith("~/"):
        text = env.home + text[1:]
    base = cwd or env.cwd
    if not text.startswith("/"):
        text = posixpath.join(base, text)
    lexical = _clean(text)
    forms = [lexical]
    if env.resolve_symlinks:
        try:
            real = os.path.realpath(lexical)
        except (OSError, ValueError):
            real = lexical
        if real != lexical:
            forms.append(_clean(real))
    return forms


def _home_pattern(pattern: str, env: Env) -> str:
    if pattern == "~" or pattern.startswith("~/"):
        return env.home + pattern[1:]
    return pattern


def _config_path(raw: str, env: Env) -> str | None:
    """An owner-supplied path from config.json (``extraProtectedPaths``, ``allowPaths``)."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    forms = resolve_path(raw, env, cwd=env.home)
    return forms[0] if forms else None


def _compile(pattern: str, case_insensitive: bool) -> re.Pattern[str]:
    """``<dir>/**`` matches the directory and everything below; ``*`` stays inside one segment."""
    if pattern.endswith("/**"):
        base, tail = pattern[:-3], r"(?:/.*)?"
    else:
        base, tail = pattern, ""
    body = "".join("[^/]*" if ch == "*" else re.escape(ch) for ch in base)
    return re.compile("^" + body + tail + "$", re.IGNORECASE | re.DOTALL if case_insensitive else re.DOTALL)


def _substring(pattern: str, case_insensitive: bool, relative: bool = False) -> re.Pattern[str]:
    """The root of a pattern, searched for inside a command or code text.

    A home-relative root (``.ssh``) must start a word or follow ``./``, so that a
    project's own ``app/.ssh`` folder is not taken for the home one.
    """
    base = pattern[:-3] if pattern.endswith("/**") else pattern
    body = "".join("[^/\\s'\"`;|&<>()]*" if ch == "*" else re.escape(ch) for ch in base)
    boundary = r"(?=$|[/\s'\"`;|&<>()=,:\]}\\])"
    if relative:
        body = r"(?:^|(?<=[\s'\"`;|&<>()=,:\[{]))(?:\./)?" + body
    return re.compile(body + boundary, re.IGNORECASE if case_insensitive else 0)


@dataclass(frozen=True)
class _Rule:
    cls: str
    pattern: str
    regex: re.Pattern[str]


class PathRules:
    """The protected path classes for one environment and configuration."""

    def __init__(self, env: Env, extra_protected: Iterable[str] = (), allow_paths: Iterable[str] = ()) -> None:
        self.env = env
        ci = env.case_insensitive
        guard = [f"{env.home}/.lumoauth/**", f"{env.guard_home}/**"]
        host_config: list[str] = []
        for home in env.hermes_homes:
            host_config.extend(f"{home}/{name}" for name in _HOST_CONFIG_FILES)
        root = env.hermes_root or env.hermes_home
        host_config.extend(f"{root}/profiles/*/{name}" for name in _HOST_CONFIG_FILES)
        host_config.extend(f"{d}/**" for d in env.plugin_dirs)
        host_skills = [f"{home}/skills/**" for home in env.hermes_homes]
        host_skills.append(f"{root}/profiles/*/skills/**")
        host_state = [f"{home}/**" for home in env.hermes_homes]
        secrets = [_home_pattern(p, env) for p in _SECRETS]
        for raw in extra_protected:
            path = _config_path(raw, env)
            if path:
                secrets.append(f"{path}/**")
        persistence = [_home_pattern(p, env) for p in _PERSISTENCE]
        allow = [p for p in (_config_path(r, env) for r in allow_paths) if p]
        self._allow = [_compile(f"{p}/**", ci) for p in _with_real_paths(allow, env)]
        self._rules: list[_Rule] = []
        for cls, patterns in ((GUARD, guard), (HOST_CONFIG, host_config), (HOST_SKILLS, host_skills),
                              (HOST_STATE, host_state),
                              (SECRETS, secrets), (PERSISTENCE, persistence)):
            for pattern in dict.fromkeys(_with_real_paths([_clean_pattern(p) for p in patterns], env)):
                self._rules.append(_Rule(cls, pattern, _compile(pattern, ci)))
        # Roots that a command or code text must not mention (SPEC §5.3 "Substrings").
        self.substring_roots: list[tuple[str, re.Pattern[str]]] = []
        home_prefix = _clean(env.home).rstrip("/") + "/"
        for rule in self._rules:
            if rule.cls not in (GUARD, HOST_CONFIG, SECRETS):
                continue
            self.substring_roots.append((rule.cls, _substring(rule.pattern, ci)))
            # The home-relative form, as written after `cd ~` (`.ssh/id_rsa`, `.hermes/.env`).
            matches_home = rule.pattern.lower().startswith(home_prefix.lower()) if ci else \
                rule.pattern.startswith(home_prefix)
            if matches_home and len(rule.pattern) > len(home_prefix):
                self.substring_roots.append((rule.cls, _substring(rule.pattern[len(home_prefix):], ci,
                                                                  relative=True)))

    def _allowed_state(self, path: str) -> bool:
        return any(rx.match(path) for rx in self._allow)

    def classify(self, path: str) -> str | None:
        """The first class of SPEC §5.1 that matches an absolute, normalised path."""
        for cls in CLASS_ORDER:
            if cls == SECRET_FILE:
                if is_secret_file_name(posixpath.basename(path), self.env.case_insensitive):
                    return SECRET_FILE
                continue
            for rule in self._rules:
                if rule.cls != cls or not rule.regex.match(path):
                    continue
                if cls == HOST_STATE and self._allowed_state(path):
                    continue
                return cls
        return None


def _with_real_paths(patterns: list[str], env: Env) -> list[str]:
    """Each pattern, plus its form with symlinks resolved in the fixed part (``/var`` -> ``/private/var``).

    A path argument is checked in its real form too, so the patterns need it as well.
    """
    if not env.resolve_symlinks:
        return patterns
    out: list[str] = []
    for pattern in patterns:
        out.append(pattern)
        fixed = pattern.split("*", 1)[0]
        base = fixed if fixed.endswith("/") else posixpath.dirname(fixed) + "/"
        try:
            real = os.path.realpath(base.rstrip("/") or "/")
        except (OSError, ValueError):
            continue
        real = _clean(real) + "/"
        if real != base and real != "//":
            out.append(real + pattern[len(base):])
    return out


def _clean_pattern(pattern: str) -> str:
    if pattern.endswith("/**"):
        return _clean(pattern[:-3]) + "/**"
    return _clean(pattern)


@lru_cache(maxsize=32)
def path_rules(env: Env, extra_protected: tuple[str, ...] = (), allow_paths: tuple[str, ...] = ()) -> PathRules:
    return PathRules(env, extra_protected, allow_paths)
