"""Tests for tshark output parsers."""

from mcp_server.tshark.parser import parse_capinfos, parse_expert_info, parse_protocol_hierarchy


def test_parse_capinfos():
    text = "File name:   test.pcap\nNumber of packets:   42\n"
    result = parse_capinfos(text)
    assert result.get("number_of_packets") == "42"


def test_parse_expert_info():
    text = """
=== Expert Information ===
Warnings (2):
   tcp.analysis.out_of_order (8 occurrences)
Notes (1):
   tcp.analysis.retransmission (5 occurrences)
"""
    result = parse_expert_info(text)
    assert len(result["warnings"]) >= 1
    assert len(result["notes"]) >= 1


def test_parse_protocol_hierarchy():
    text = """
===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:100 bytes:10000
  ip                                     frames:90 bytes:9000
    tcp                                  frames:80 bytes:8000
"""
    rows = parse_protocol_hierarchy(text)
    assert any(r["protocol"] == "eth" for r in rows)
    assert any(r["protocol"] == "tcp" for r in rows)
