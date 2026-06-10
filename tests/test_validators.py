"""Tests for path and filter validation."""

import os
from pathlib import Path

import pytest

from mcp_server.config import settings
from mcp_server.tshark.validators import (
    ip_filter_literal,
    validate_display_filter,
    validate_ip_address,
    validate_pcap_path,
)


@pytest.fixture(autouse=True)
def _allow_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "allowed_dirs", [tmp_path])
    monkeypatch.setattr(settings, "require_allowed_dirs", True)


def test_validate_pcap_path_requires_absolute(tmp_path):
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\x00" * 100)
    with pytest.raises(ValueError, match="absolute"):
        validate_pcap_path(str(p.name))


def test_validate_pcap_path_success(tmp_path):
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 96)
    result = validate_pcap_path(str(p.resolve()))
    assert result == p.resolve()


def test_validate_pcap_path_rejects_symlink(tmp_path):
    real = tmp_path / "real.pcap"
    real.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 96)
    link = tmp_path / "link.pcap"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="Symlinks"):
        validate_pcap_path(str(link))


def test_validate_pcap_path_allows_anywhere_when_sandbox_off(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 96)
    monkeypatch.setattr(settings, "allowed_dirs", [])
    monkeypatch.setattr(settings, "require_allowed_dirs", False)
    result = validate_pcap_path(str(outside.resolve()))
    assert result == outside.resolve()


def test_validate_pcap_path_rejects_outside_allowed(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 96)
    monkeypatch.setattr(settings, "allowed_dirs", [allowed])
    with pytest.raises(PermissionError, match="outside PM_ALLOWED_DIRS"):
        validate_pcap_path(str(outside.resolve()))


def test_validate_display_filter_rejects_shell_chars():
    with pytest.raises(ValueError, match="metachar"):
        validate_display_filter("tcp.port == 80; rm -rf /")


def test_validate_display_filter_accepts_tcp_filter():
    assert validate_display_filter("tcp.analysis.retransmission") == "tcp.analysis.retransmission"


def test_validate_display_filter_accepts_in_set_syntax():
    filt = "wlan.fixed.action_code in {4, 5}"
    assert validate_display_filter(filt) == filt


def test_validate_ip_address_ipv4():
    assert validate_ip_address("192.168.1.1") == "192.168.1.1"


def test_validate_ip_address_rejects_injection():
    with pytest.raises(ValueError, match="Invalid IP"):
        validate_ip_address("1.2.3.4 or dns")


def test_ip_filter_literal_quotes_address():
    assert ip_filter_literal("10.0.0.5") == 'ip.addr == "10.0.0.5"'
