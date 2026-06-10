"""Tests for Wi-Fi analysis tools and MAC validation."""

import pytest

from mcp_server.config import settings
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import normalize_mac
from mcp_server.tools import wifi_analysis
from tests.conftest import tshark_available


def test_normalize_mac_colon():
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_invalid():
    with pytest.raises(ValueError):
        normalize_mac("not-a-mac")


@pytest.fixture(autouse=True)
def _allow_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "allowed_dirs", [tmp_path])
    monkeypatch.setattr(settings, "require_allowed_dirs", True)


@pytest.mark.asyncio
@pytest.mark.skipif(not tshark_available(), reason="tshark not installed")
async def test_wifi_quick_scan_rejects_ethernet_only(tmp_path):
    pcap = tmp_path / "eth.pcap"
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    )
    runner = TsharkRunner()
    result = await wifi_analysis.wifi_quick_scan(runner, str(pcap.resolve()))
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "NOT_WLAN_CAPTURE"
