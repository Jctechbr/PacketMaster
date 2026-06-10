"""Integration tests requiring tshark on PATH."""

import shutil
from pathlib import Path

import pytest

from mcp_server.config import settings
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tools import file_ops, workflows
from tests.conftest import tshark_available

pytestmark = pytest.mark.skipif(
    not tshark_available(), reason="tshark not installed"
)


@pytest.fixture(autouse=True)
def _allow_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "allowed_dirs", [tmp_path])
    monkeypatch.setattr(settings, "require_allowed_dirs", True)


@pytest.fixture
def sample_pcap(tmp_path) -> Path:
    """Create minimal PCAP via text2pcap or tshark if available."""
    pcap = tmp_path / "sample.pcap"
    text2pcap = shutil.which("text2pcap")
    if text2pcap:
        hex_file = tmp_path / "sample.hex"
        hex_file.write_text("0000  00 00 00 00 00 01 00 00 00 00 00 02 08 00\n")
        import subprocess

        subprocess.run(
            [text2pcap, str(hex_file), str(pcap)],
            check=True,
            capture_output=True,
        )
    else:
        pcap.write_bytes(
            b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
        )
    return pcap


@pytest.mark.asyncio
async def test_check_install():
    runner = TsharkRunner()
    result = await file_ops.check_install(runner)
    assert result.ok
    assert result.data["tshark_path"]


@pytest.mark.asyncio
async def test_file_info(sample_pcap):
    runner = TsharkRunner()
    result = await file_ops.file_info(runner, str(sample_pcap))
    assert result.ok
    assert result.data["size_bytes"] > 0


@pytest.mark.asyncio
async def test_quick_scan(sample_pcap):
    runner = TsharkRunner()
    result = await workflows.troubleshoot_quick_scan(runner, str(sample_pcap))
    assert result.ok
    assert "file_info" in result.data
    assert "recommended_next_tools" in result.data
