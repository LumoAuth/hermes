"""Directory-plugin wrapper: Hermes imports this file and calls ``register(ctx)``.

The code lives in the ``lumoauth_hermes`` package (``src/``). Hermes's
package manager installs it from ``pyproject.toml``; a plain copy of this
directory works too, because the package next to this file is used when it
is not installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from lumoauth_hermes import register
except ImportError:
    _src = Path(__file__).resolve().parent / "src"
    if (_src / "lumoauth_hermes" / "__init__.py").is_file() and str(_src) not in sys.path:
        sys.path.insert(0, str(_src))
    from lumoauth_hermes import register

__all__ = ["register"]
