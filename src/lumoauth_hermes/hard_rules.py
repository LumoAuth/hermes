"""Hard rules (SPEC §5): what no setting, capability or approval can lift.

Two outcomes: ``deny`` (the call is blocked) and ``approve`` (a person must
approve this call even when the capability is granted). The shell and code
scan (§5.3) is a tripwire, not a sandbox.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .classify import Classification, workdir_for
from .environment import Env
from .paths import (
    APPROVE,
    CLASS_TEXT,
    COLUMNS,
    DENY,
    PathRules,
    expand_variables,
    is_secret_file_name,
    path_rules,
    resolve_path,
)

COMMAND = "command"
TOOL = "tool"

_MAX_TOKENS = 20000
_MAX_PATH_TOKENS = 4000


@dataclass(frozen=True)
class HardRule:
    rule: str | None = None  # "deny", "approve" or None
    cls: str | None = None  # a path class, "command" or "tool"
    detail: str = ""

    @property
    def describe(self) -> str:
        return self.detail or (CLASS_TEXT.get(self.cls or "", "") if self.cls else "")


NO_RULE = HardRule()


def strictest(results: Iterable[HardRule]) -> HardRule:
    """Deny over approve over nothing; the first result of the strongest kind wins."""
    first_approve: HardRule | None = None
    for result in results:
        if result.rule == DENY:
            return result
        if result.rule == APPROVE and first_approve is None:
            first_approve = result
    return first_approve or NO_RULE


# ── Shell text ───────────────────────────────────────────────────────────────

_TOKEN_SPLIT = re.compile(r"[\s;|&<>()'\"`=]+")
_TILDE = re.compile(r"(^|[\s;|&<>()'\"`=:,\[{])~(?=[/\s;|&<>()'\"`,\]}]|$)")


def expand_shell_text(text: str, env: Env) -> str:
    """Expand ``$HOME``, ``${HOME}`` (and the other known variables) and ``~`` at word starts."""
    expanded = expand_variables(text, env)
    return _TILDE.sub(lambda m: m.group(1) + env.home, expanded)


def _path_like(token: str, env: Env) -> bool:
    if "/" in token or token.startswith("~") or token.startswith("."):
        return True
    return is_secret_file_name(posixpath.basename(token), env.case_insensitive)


def _path_results(forms: Iterable[str], rules: PathRules, column: str) -> Iterator[HardRule]:
    for form in forms:
        cls = rules.classify(form)
        if cls is None:
            continue
        rule = COLUMNS[column][cls]
        if rule is not None:
            yield HardRule(rule, cls, f"{CLASS_TEXT[cls]} ({form})")


# Words and separators of a command or code text. Quotes, commas and brackets
# are dropped so that `subprocess.run(["hermes", "plugins"])` reads as words.
_LEX = re.compile(r"\$\(|[;|&()`\n{}]|[^\s;|&()`'\",\[\]{}]+")
_SEPARATORS = frozenset({"$(", ";", "|", "&", "(", ")", "`", "\n", "{", "}"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = frozenset({"sudo", "doas", "env", "nohup", "exec", "command", "builtin", "time", "nice", "ionice",
                       "timeout", "stdbuf", "setsid", "xargs", "watch", "strace", "chrt", "taskset", "unbuffer"})
_WRAPPER_VALUE_OPTIONS = frozenset({"-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-n", "-c", "-s", "-k"})
_PYTHON = re.compile(r"^python[0-9.]*$")
_PIP = re.compile(r"^pip[0-9.]*$")

HERMES_ADMIN = frozenset({"plugins", "plugin", "config", "lumoauth", "setup", "update", "hooks"})
_HERMES_VALUE_OPTIONS = frozenset({"-p", "--profile", "-m", "--model", "-t", "--toolsets", "--provider", "--resume",
                                   "-r", "--worktree", "-w"})
OPENCLAW_ADMIN = frozenset({"plugins", "plugin", "config", "lumoauth", "hooks", "security", "update"})
_PIP_VERBS = frozenset({"install", "uninstall", "upgrade", "reinstall", "remove", "add", "inject"})
_NPM = frozenset({"npm", "pnpm", "yarn", "bun"})
_NPM_VERBS = frozenset({"install", "i", "add", "uninstall", "remove", "rm", "update", "upgrade", "link"})
_HOST_PACKAGES = ("hermes-agent", "lumoauth-hermes")
_STOP_VERBS = frozenset({"stop", "disable", "unload", "bootout", "kill", "mask", "remove"})
_HOST_NAMES = ("hermes", "openclaw")

_PROTECTED_VARS = ("HERMES_SAFE_MODE", "HERMES_HOME", "LUMOAUTH_GUARD_HOME", "OPENCLAW_CONFIG_PATH",
                   "OPENCLAW_STATE_DIR", "OPENCLAW_PROFILE", "OPENCLAW_HOME")
_VARS = "|".join(_PROTECTED_VARS)
_ENV_SET = re.compile(
    rf"(?<![A-Za-z0-9_$])(?:{_VARS})(?:['\"]\s*\]|\])?\s*=(?!=)"
    rf"|\b(?:export|setenv|declare\s+-x|typeset\s+-x)\s+(?:-\w+\s+)*(?:{_VARS})\b"
    rf"|\b(?:putenv|setdefault|setenv|SetEnvironmentVariable)\s*\(\s*['\"](?:{_VARS})['\"]"
    rf"|['\"](?:{_VARS})['\"]\s*:"
)
_PROC_ENVIRON = re.compile(r"/proc/[^/\s'\"]+/environ")
_PIPE_TO_SHELL = re.compile(
    r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:\S*/)?"
    r"(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|perl|ruby|php|pwsh)(?![\w.-])"
)
_DECODE = re.compile(r"\bbase64\s+(?:-\w+\s+)*(?:-\w*[dD]\w*|--decode)\b|\bxxd\s+(?:-\w+\s+)*-r\b|\bopenssl\s+.*-d\b")
_RUN_WORD = re.compile(r"\b(?:sh|bash|eval|exec)\b")


def _simple_commands(text: str) -> list[list[str]]:
    commands: list[list[str]] = []
    current: list[str] = []
    for index, match in enumerate(_LEX.finditer(text)):
        if index > _MAX_TOKENS:
            break
        word = match.group(0)
        if word in _SEPARATORS:
            if current:
                commands.append(current)
            current = []
        else:
            current.append(word)
    if current:
        commands.append(current)
    return commands


def _base(word: str) -> str:
    return posixpath.basename(word.rstrip("/")).lower()


def _program(words: list[str]) -> tuple[str, list[str]]:
    """The program of a simple command and its arguments, past assignments and wrappers."""
    i = 0
    while i < len(words):
        word = words[i]
        if _ASSIGNMENT.match(word):
            i += 1
            continue
        name = _base(word)
        if name in _WRAPPERS:
            i += 1
            while i < len(words) and (words[i].startswith("-") or words[i].isdigit() or _ASSIGNMENT.match(words[i])):
                if words[i] in _WRAPPER_VALUE_OPTIONS and i + 1 < len(words):
                    i += 1
                i += 1
            continue
        break
    if i >= len(words):
        return "", []
    program, args = _base(words[i]), words[i + 1:]
    if _PYTHON.match(program) and "-m" in args:
        module_index = args.index("-m") + 1
        if module_index < len(args):
            module = args[module_index].lower()
            rest = args[module_index + 1:]
            if module.split(".")[0] in ("hermes_cli", "hermes"):
                return "hermes", rest
            if module in ("pip", "pip3"):
                return "pip", rest
    if program == "uv" and args and args[0] in ("pip", "tool"):
        return "pip", args[1:]
    if program.endswith(".exe"):
        program = program[:-4]
    return program, args


def _first_positional(args: list[str], value_options: frozenset[str]) -> str | None:
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            if arg in value_options:
                skip = True
            continue
        return arg.lower()
    return None


def _names_package(args: list[str], packages: Iterable[str]) -> str | None:
    for arg in args:
        normalized = arg.lower().replace("_", "-")
        for package in packages:
            if package in normalized:
                return package
    return None


def command_patterns(text: str, tainted: bool) -> list[HardRule]:
    """SPEC §5.3 command patterns, on the expanded text."""
    results: list[HardRule] = []
    commands = _simple_commands(text)
    programs: list[tuple[str, list[str]]] = [_program(words) for words in commands]
    for program, args in programs:
        if not program:
            continue
        lowered = [a.lower() for a in args]
        if program in ("hermes", "hermes-agent"):
            if any(a == "--safe-mode" or a.startswith("--safe-mode=") for a in lowered):
                results.append(HardRule(DENY, COMMAND, "runs Hermes in safe mode, which turns every plugin off"))
            positional = _first_positional(args, _HERMES_VALUE_OPTIONS)
            if positional in HERMES_ADMIN:
                results.append(HardRule(DENY, COMMAND, f"runs the Hermes admin command `hermes {positional}`"))
        elif program == "openclaw":
            if "--safe-mode" in lowered:
                results.append(HardRule(DENY, COMMAND, "runs OpenClaw in safe mode"))
            positional = _first_positional(args, frozenset())
            repairs = positional == "doctor" and ("--fix" in lowered or "--repair" in lowered)
            gateway = positional == "gateway" and any(a in ("stop", "restart", "install", "uninstall")
                                                      for a in lowered)
            if positional in OPENCLAW_ADMIN or repairs or gateway:
                results.append(HardRule(DENY, COMMAND, f"runs the OpenClaw admin command `openclaw {positional}`"))
        elif _PIP.match(program) or program == "pipx":
            if any(a in _PIP_VERBS for a in lowered):
                package = _names_package(args, _HOST_PACKAGES)
                if package:
                    results.append(HardRule(DENY, COMMAND, f"installs, removes or updates {package}"))
        elif program in _NPM:
            if any(a in _NPM_VERBS for a in lowered):
                for arg in lowered:
                    name = arg.rsplit("@", 1)[0] if arg.count("@") > (1 if arg.startswith("@") else 0) else arg
                    if name in ("openclaw", "@lumoauth/openclaw"):
                        results.append(HardRule(DENY, COMMAND, f"installs, removes or updates {name}"))
                        break
        elif program in ("pkill", "killall"):
            if any(host in a for a in lowered for host in _HOST_NAMES):
                results.append(HardRule(DENY, COMMAND, "stops the agent host's process"))
        elif program in ("systemctl", "launchctl", "service"):
            if any(a in _STOP_VERBS for a in lowered) and any(host in a for a in lowered for host in _HOST_NAMES):
                results.append(HardRule(DENY, COMMAND, "stops the agent host's service"))
        elif program == "crontab":
            remaining = list(args)
            if "-u" in remaining:
                index = remaining.index("-u")
                del remaining[index:index + 2]
            if any(a in ("-e", "-r", "-i", "-") for a in remaining) or any(not a.startswith("-") for a in remaining):
                results.append(HardRule(APPROVE, COMMAND, "changes the crontab"))
        elif program in ("at", "batch"):
            results.append(HardRule(APPROVE, COMMAND, "schedules a command with `at`"))
    names_host = any(p in ("pgrep", "pidof") and any(h in a.lower() for a in args for h in _HOST_NAMES)
                     for p, args in programs)
    if names_host and any(p == "kill" for p, _ in programs):
        results.append(HardRule(DENY, COMMAND, "stops the agent host's process"))
    if _PROC_ENVIRON.search(text):
        results.append(HardRule(APPROVE, COMMAND, "reads another process's environment"))
    if tainted:
        if _PIPE_TO_SHELL.search(text):
            results.append(HardRule(APPROVE, COMMAND, "pipes text into a shell or interpreter after untrusted input"))
        elif _DECODE.search(text) and _RUN_WORD.search(text):
            results.append(HardRule(APPROVE, COMMAND, "decodes and runs text after untrusted input"))
    return results


def scan_command(text: str, env: Env, cwd: str, tainted: bool, rules: PathRules) -> list[HardRule]:
    """SPEC §5.3 for one command or code text: tokens, substrings and command patterns."""
    results: list[HardRule] = []
    if _ENV_SET.search(text):
        results.append(HardRule(DENY, COMMAND, "changes an environment variable that controls Hermes or the Guard"))
    expanded = expand_shell_text(text, env)
    checked = 0
    for index, token in enumerate(_TOKEN_SPLIT.split(expanded)):
        if index > _MAX_TOKENS or checked > _MAX_PATH_TOKENS:
            break
        if not token or not _path_like(token, env):
            continue
        checked += 1
        results.extend(_path_results(resolve_path(token, env, cwd), rules, "shell"))
    for cls, regex in rules.substring_roots:
        found = regex.search(expanded)
        if found:
            results.append(HardRule(DENY, cls, f"{CLASS_TEXT[cls]} ({found.group(0)})"))
    results.extend(command_patterns(expanded, tainted))
    return results


# ── Arguments of tools without catalog rules (MCP and plugin tools) ─────────

_MAX_ARG_PATHS = 200


def _walk_strings(value: Any, depth: int = 0) -> Iterator[str]:
    if depth > 64:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item, depth + 1)


def argument_paths(args: dict[str, Any], env: Env) -> list[str]:
    """SPEC §4.4: for MCP and uncatalogued tools, every string value (any depth, at most 200
    values) that starts with ``/`` or ``~/``, or is exactly ``~``, is a path."""
    forms: list[str] = []
    for count, value in enumerate(_walk_strings(args)):
        if count >= _MAX_ARG_PATHS:
            break
        if not (value.startswith("/") or value.startswith("~/") or value == "~"):
            continue
        for form in resolve_path(value, env):
            if form not in forms:
                forms.append(form)
    return forms


# ── Entry point ─────────────────────────────────────────────────────────────

def evaluate(
    classification: Classification,
    args: Any,
    env: Env,
    *,
    tainted: bool = False,
    extra_protected: Iterable[str] = (),
    allow_paths: Iterable[str] = (),
) -> HardRule:
    """The hard rule for one call: the strictest of the tool, path and command rules."""
    args = args if isinstance(args, dict) else {}
    rules = path_rules(env, tuple(extra_protected), tuple(allow_paths))
    results: list[HardRule] = []
    if classification.hardRule:
        results.append(HardRule(classification.hardRule, TOOL, "this tool always needs a person's approval"
                                if classification.hardRule == APPROVE else "this tool is never allowed"))
    if classification.command_args:
        column = "shell"
    elif classification.risk == "read":
        column = "read"
    else:
        column = "write"
    results.extend(_path_results(classification.path_forms, rules, column))
    if not classification.catalogued:
        # SPEC §4.4: an MCP or plugin tool has no pathArgs, so path-shaped values are checked.
        results.extend(_path_results(argument_paths(args, env), rules, "read" if classification.risk == "read"
                                     else "write"))
    if classification.command_args:
        cwd = workdir_for(classification, args, env)
        for name in classification.command_args:
            value = args.get(name)
            if isinstance(value, str) and value.strip():
                results.extend(scan_command(value, env, cwd, tainted, rules))
    return strictest(results)
