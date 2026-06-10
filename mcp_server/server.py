"""PacketMaster MCP server entrypoint."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import structlog
from fastmcp import FastMCP

from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tools import (
    capture_detect,
    extraction,
    file_ops,
    statistics,
    tcp_analysis,
    wifi_analysis,
    wired_analysis,
    workflows,
)

# MCP uses stdio for JSON-RPC — logs MUST go to stderr only.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

mcp = FastMCP(
    "PacketMaster",
    instructions=(
        "PCAP troubleshooting via tshark. Start with pm_detect_capture_type. "
        "Ethernet/EPC: pm_wired_quick_scan. 802.11 monitor: pm_wifi_quick_scan. "
        "PCAP paths must be absolute. Optional PM_ALLOWED_DIRS sandbox. "
        "Sensitive stream data is redacted by default."
    ),
)

_runner = TsharkRunner()


def _dump(response: Any) -> str:
    if hasattr(response, "model_dump"):
        return json.dumps(response.model_dump(), indent=2)
    return json.dumps(response, indent=2)


@mcp.tool()
async def pm_check_install() -> str:
    """Verify tshark/capinfos installation and configuration."""
    return _dump(await file_ops.check_install(_runner))


@mcp.tool()
async def pm_file_info(file_path: str, compute_hash: bool = False) -> str:
    """Return capinfos metadata and optional SHA-256 hash for a PCAP file."""
    return _dump(await file_ops.file_info(_runner, file_path, compute_hash=compute_hash))


@mcp.tool()
async def pm_protocol_hierarchy(file_path: str) -> str:
    """Protocol distribution tree from tshark -z io,phs."""
    return _dump(await statistics.protocol_hierarchy(_runner, file_path))


@mcp.tool()
async def pm_conversations(
    file_path: str, conv_type: str = "ip", limit: int = 20
) -> str:
    """Top conversations by bytes (ip, tcp, or udp)."""
    return _dump(
        await statistics.conversations(_runner, file_path, conv_type=conv_type, limit=limit)
    )


@mcp.tool()
async def pm_endpoints(file_path: str, limit: int = 20) -> str:
    """Top IP endpoints by traffic volume."""
    return _dump(await statistics.endpoints(_runner, file_path, limit=limit))


@mcp.tool()
async def pm_expert_info(file_path: str, severity: str | None = None) -> str:
    """Wireshark expert information (errors, warnings, notes, chats)."""
    return _dump(await tcp_analysis.expert_info(_runner, file_path, severity=severity))


@mcp.tool()
async def pm_tcp_anomalies(
    file_path: str,
    display_filter: str | None = None,
    sample_limit: int = 5,
) -> str:
    """Count and sample TCP anomalies: retrans, dup ACK, zero window, OOO, RST."""
    return _dump(
        await tcp_analysis.tcp_anomalies(
            _runner, file_path, display_filter=display_filter, sample_limit=sample_limit
        )
    )


@mcp.tool()
async def pm_latency_summary(
    file_path: str,
    display_filter: str | None = None,
    limit: int = 20,
) -> str:
    """Per-flow RTT statistics from tcp.analysis.ack_rtt."""
    return _dump(
        await tcp_analysis.latency_summary(
            _runner, file_path, display_filter=display_filter, limit=limit
        )
    )


@mcp.tool()
async def pm_io_stats(file_path: str, interval_seconds: int = 1) -> str:
    """Traffic volume over time intervals."""
    return _dump(
        await statistics.io_stats(_runner, file_path, interval_seconds=interval_seconds)
    )


@mcp.tool()
async def pm_extract_fields(
    file_path: str,
    fields: list[str],
    display_filter: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """Extract specific tshark fields with pagination."""
    return _dump(
        await extraction.extract_fields(
            _runner,
            file_path,
            fields,
            display_filter=display_filter,
            offset=offset,
            limit=limit,
        )
    )


@mcp.tool()
async def pm_follow_stream(
    file_path: str,
    stream_type: str = "tcp",
    stream_index: int = 0,
    max_bytes: int = 8192,
    redact: bool = True,
) -> str:
    """Follow a TCP/UDP/HTTP/TLS stream (truncated, redacted by default)."""
    return _dump(
        await extraction.follow_stream(
            _runner,
            file_path,
            stream_type=stream_type,
            stream_index=stream_index,
            max_bytes=max_bytes,
            redact=redact,
        )
    )


@mcp.tool()
async def pm_filter_packets(
    file_path: str,
    display_filter: str,
    offset: int = 0,
    limit: int = 50,
) -> str:
    """Return packet summaries matching a display filter."""
    return _dump(
        await extraction.filter_packets(
            _runner, file_path, display_filter, offset=offset, limit=limit
        )
    )


@mcp.tool()
async def pm_troubleshoot_quick_scan(
    file_path: str, compute_hash: bool = False
) -> str:
    """Composite triage: file info, expert, top conversations, TCP anomalies, protocol hierarchy."""
    return _dump(
        await workflows.troubleshoot_quick_scan(
            _runner, file_path, compute_hash=compute_hash
        )
    )


@mcp.tool()
async def pm_troubleshoot_flow(
    file_path: str, ip_a: str, ip_b: str, port: int | None = None
) -> str:
    """Deep dive on traffic between two IP addresses (optional port)."""
    return _dump(
        await workflows.troubleshoot_flow(_runner, file_path, ip_a, ip_b, port=port)
    )


@mcp.tool()
async def pm_detect_capture_type(file_path: str) -> str:
    """Detect wlan vs ethernet capture and recommend entry-point tool."""
    return _dump(await capture_detect.detect_capture_type(_runner, file_path))


@mcp.tool()
async def pm_wired_quick_scan(
    file_path: str, compute_hash: bool = False
) -> str:
    """Wired/EPC triage: DHCP, DNS, ICMP, L2 infra, VLAN, TCP anomalies, asymmetric hints."""
    return _dump(
        await wired_analysis.wired_quick_scan(
            _runner, file_path, compute_hash=compute_hash
        )
    )


@mcp.tool()
async def pm_dhcp_analysis(
    file_path: str, mac_address: str | None = None, sample_limit: int = 10
) -> str:
    """DHCP transaction analysis with stuck-pattern detection (optional STA MAC)."""
    return _dump(
        await wired_analysis.dhcp_analysis(
            _runner, file_path, mac_address=mac_address, sample_limit=sample_limit
        )
    )


@mcp.tool()
async def pm_dns_analysis(
    file_path: str, ip_address: str | None = None, sample_limit: int = 15
) -> str:
    """DNS query/response analysis, top names, and failure samples (optional client IP)."""
    return _dump(
        await wired_analysis.dns_analysis(
            _runner, file_path, ip_address=ip_address, sample_limit=sample_limit
        )
    )


@mcp.tool()
async def pm_asymmetric_hints(
    file_path: str, display_filter: str | None = None
) -> str:
    """Detect one-sided capture symptoms: SYN without ACK, lost segments, ICMP-in-tunnel."""
    return _dump(
        await wired_analysis.asymmetric_hints(
            _runner, file_path, display_filter=display_filter
        )
    )


@mcp.tool()
async def pm_wifi_quick_scan(
    file_path: str, rssi_threshold: int = -75
) -> str:
    """802.11 monitor-mode triage: retries, mgmt frames, security, roaming, top BSSIDs."""
    return _dump(
        await wifi_analysis.wifi_quick_scan(
            _runner, file_path, rssi_threshold=rssi_threshold
        )
    )


@mcp.tool()
async def pm_wifi_client_analysis(
    file_path: str, wlan_addr: str, sample_limit: int = 5
) -> str:
    """Deep dive on one Wi-Fi client STA by MAC (wlan.addr, bidirectional)."""
    return _dump(
        await wifi_analysis.wifi_client_analysis(
            _runner, file_path, wlan_addr, sample_limit=sample_limit
        )
    )


@mcp.tool()
async def pm_wifi_roaming_analysis(
    file_path: str, wlan_addr: str, sample_limit: int = 20
) -> str:
    """802.11k/v roaming timeline: reassoc, neighbor reports, BSS transition, deauth."""
    return _dump(
        await wifi_analysis.wifi_roaming_analysis(
            _runner, file_path, wlan_addr, sample_limit=sample_limit
        )
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
