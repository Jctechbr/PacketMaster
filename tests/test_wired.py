"""Tests for wired analysis and capture detection."""

import pytest

from mcp_server.config import settings
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tools import capture_detect, wired_analysis
from tests.conftest import tshark_available


@pytest.fixture(autouse=True)
def _allow_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "allowed_dirs", [tmp_path])
    monkeypatch.setattr(settings, "require_allowed_dirs", True)


@pytest.mark.asyncio
@pytest.mark.skipif(not tshark_available(), reason="tshark not installed")
async def test_detect_capture_type_ethernet(tmp_path):
    pcap = tmp_path / "eth.pcap"
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    )
    runner = TsharkRunner()
    result = await capture_detect.detect_capture_type(runner, str(pcap.resolve()))
    assert result.ok
    assert result.data["capture_type"] == "ethernet_l3"
    assert result.data["recommended_entrypoint"] == "pm_wired_quick_scan"


@pytest.mark.asyncio
@pytest.mark.skipif(not tshark_available(), reason="tshark not installed")
async def test_wired_quick_scan_on_minimal_pcap(tmp_path):
    pcap = tmp_path / "eth.pcap"
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    )
    runner = TsharkRunner()
    result = await wired_analysis.wired_quick_scan(runner, str(pcap.resolve()))
    assert result.ok
    assert "dhcp" in result.data
    assert "recommended_next_tools" in result.data


@pytest.mark.asyncio
@pytest.mark.skipif(not tshark_available(), reason="tshark not installed")
async def test_dhcp_analysis_empty_capture(tmp_path):
    pcap = tmp_path / "eth.pcap"
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    )
    runner = TsharkRunner()
    result = await wired_analysis.dhcp_analysis(runner, str(pcap.resolve()))
    assert result.ok
    assert result.data["counts"]["all"] == 0
