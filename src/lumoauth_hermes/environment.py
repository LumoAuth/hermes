"""The machine that the rules look at: home, Hermes home, Guard home, working directory.

The rules never read ``os.environ`` directly; they get an :class:`Env`. The
runtime builds one from the real process (:func:`current_env`), the tests build
one from ``vectors/environment.json``.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Env:
    home: str
    hermes_home: str
    guard_home: str
    cwd: str
    #: The plugin's own install directories (SPEC §5.1 hostConfig).
    plugin_dirs: tuple[str, ...] = ()
    #: The default Hermes root (``~/.hermes``) when a profile home is active; its
    #: profiles are protected too.
    hermes_root: str = ""
    case_insensitive: bool = False
    resolve_symlinks: bool = True
    #: Extra variables that path expansion replaces (``$XDG_CONFIG_HOME`` ...), as pairs.
    variables: tuple[tuple[str, str], ...] = ()

    @property
    def hermes_homes(self) -> tuple[str, ...]:
        homes = [self.hermes_home]
        if self.hermes_root and self.hermes_root != self.hermes_home:
            homes.append(self.hermes_root)
        return tuple(homes)

    def expansions(self) -> dict[str, str]:
        """Variable name -> value for ``$NAME`` / ``${NAME}`` expansion."""
        values = {"HOME": self.home, "HERMES_HOME": self.hermes_home, "LUMOAUTH_GUARD_HOME": self.guard_home}
        for name, value in self.variables:
            if value:
                values.setdefault(name, value)
        return values


def default_guard_home(home: str | None = None, environ: dict[str, str] | None = None) -> str:
    """``$LUMOAUTH_GUARD_HOME``, else ``~/.lumoauth/guard/hermes`` (SPEC §3)."""
    env = os.environ if environ is None else environ
    override = (env.get("LUMOAUTH_GUARD_HOME") or "").strip()
    if override:
        return os.path.abspath(os.path.expanduser(override))
    base = home or os.path.expanduser("~")
    return os.path.join(base, ".lumoauth", "guard", "hermes")


def _hermes_home() -> str:
    try:
        from hermes_constants import get_hermes_home  # type: ignore[import-not-found]

        return str(get_hermes_home())
    except Exception:
        value = (os.environ.get("HERMES_HOME") or "").strip()
        return os.path.abspath(os.path.expanduser(value)) if value else os.path.join(os.path.expanduser("~"), ".hermes")


def _hermes_root(home: str) -> str:
    try:
        from hermes_constants import get_default_hermes_root  # type: ignore[import-not-found]

        return str(get_default_hermes_root())
    except Exception:
        return os.path.join(home, ".hermes")


def _agent_cwd() -> str:
    try:
        from agent.runtime_cwd import resolve_agent_cwd  # type: ignore[import-not-found]

        return str(resolve_agent_cwd())
    except Exception:
        try:
            return os.getcwd()
        except OSError:
            return os.path.expanduser("~")


def plugin_install_dirs() -> tuple[str, ...]:
    """Where this plugin's code lives: the package, and a directory-plugin wrapper above it."""
    package = Path(__file__).resolve().parent
    dirs = [str(package)]
    # A checkout or directory plugin: <root>/src/lumoauth_hermes with plugin.yaml at <root>.
    root = package.parent.parent
    if (root / "plugin.yaml").is_file():
        dirs.append(str(root))
    return tuple(dirs)


def current_env() -> Env:
    """The environment of this process, as Hermes sees it right now."""
    home = os.path.expanduser("~")
    hermes_home = _hermes_home()
    variables = []
    for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
        value = os.environ.get(name, "").strip()
        if value:
            variables.append((name, value))
    return Env(
        home=home,
        hermes_home=hermes_home,
        guard_home=default_guard_home(home),
        cwd=_agent_cwd(),
        plugin_dirs=plugin_install_dirs(),
        hermes_root=_hermes_root(home),
        case_insensitive=sys.platform in ("darwin", "win32"),
        resolve_symlinks=True,
        variables=tuple(variables),
    )
