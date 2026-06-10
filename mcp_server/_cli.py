"""Console entrypoint with path bootstrap for editable installs."""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_package_path() -> None:
    root = Path(__file__).resolve().parent.parent
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


def main() -> None:
    _ensure_package_path()
    from mcp_server.server import main as run_server

    run_server()
