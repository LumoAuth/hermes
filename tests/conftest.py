from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from lumoauth_hermes.environment import Env  # noqa: E402

VECTORS = TESTS / "contract" / "vectors"


def vectors(name: str):
    """One vendored vector file (tests/contract/vectors/<name>.json)."""
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


def vector_env() -> Env:
    """The machine that every vector assumes (vectors/environment.json)."""
    data = vectors("environment")
    hermes = data["hermes"]
    return Env(
        home=data["home"],
        hermes_home=hermes["hermesHome"],
        guard_home=hermes["guardHome"],
        cwd=hermes["cwd"],
        plugin_dirs=(hermes["pluginDir"],),
        hermes_root=hermes["hermesHome"],
        case_insensitive=False,
        resolve_symlinks=False,
    )


@pytest.fixture
def venv_env() -> Env:
    return vector_env()


@pytest.fixture
def guard_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "guard"
    monkeypatch.setenv("LUMOAUTH_GUARD_HOME", str(home))
    return home


@pytest.fixture
def hermes_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "hermes-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def file_mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
