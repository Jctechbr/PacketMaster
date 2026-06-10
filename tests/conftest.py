"""Shared pytest configuration."""

import shutil
from pathlib import Path

import pytest

_MACOS_TSHARK = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")


def tshark_available() -> bool:
    return shutil.which("tshark") is not None or _MACOS_TSHARK.is_file()


pytestmark = pytest.mark.skipif(
    not tshark_available(), reason="tshark not installed"
)
