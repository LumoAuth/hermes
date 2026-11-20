"""Shared settings of the end-to-end scripts: where the run lives and how Hermes is started."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_URL = "https://localhost:8000/orgs/northwind-labs/portal"


@dataclass
class Run:
    root: str
    python: str
    hermes_src: str
    ca_file: str

    @property
    def home(self) -> Path:
        return Path(self.root) / "home"

    @property
    def hermes_home(self) -> Path:
        return self.home / ".hermes"

    @property
    def guard_home(self) -> Path:
        return self.home / ".lumoauth" / "guard" / "hermes"

    @property
    def project(self) -> Path:
        return self.home / "project"

    @property
    def bundled(self) -> Path:
        return Path(self.root) / "no-bundled-plugins"

    @property
    def setup_log(self) -> Path:
        return Path(self.root) / "setup.log"

    def env(self) -> dict[str, str]:
        """The environment of every Hermes process of this run (a fake HOME: nothing touches yours)."""
        env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "LUMOAUTH_"))}
        env.update({
            "HOME": str(self.home),
            "HERMES_HOME": str(self.hermes_home),
            "LUMOAUTH_GUARD_HOME": str(self.guard_home),
            "HERMES_BUNDLED_PLUGINS": str(self.bundled),
            "TERMINAL_CWD": str(self.project),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        if self.ca_file:
            env["SSL_CERT_FILE"] = self.ca_file
        if self.hermes_src:
            env["PYTHONPATH"] = self.hermes_src
        return env

    def save(self) -> None:
        (Path(self.root) / "run.json").write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, root: str) -> Run:
        return cls(**json.loads((Path(root) / "run.json").read_text(encoding="utf-8")))


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", default=os.environ.get("E2E_ROOT", ""),
                        help="directory of the run (default: $E2E_ROOT, else $TMPDIR/lumoauth-hermes-e2e)")


def default_root(value: str) -> str:
    if value:
        return str(Path(value).resolve())
    return str(Path(os.environ.get("TMPDIR", "/tmp")) / "lumoauth-hermes-e2e")


def install_plugin(run: Run) -> None:
    """Copy this repository into the Hermes home as the directory plugin ``lumoauth``."""
    target = run.hermes_home / "plugins" / "lumoauth"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for name in ("plugin.yaml", "__init__.py", "pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(REPO / name, target / name)
    shutil.copytree(REPO / "src", target / "src", ignore=shutil.ignore_patterns("__pycache__"))


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(2)
