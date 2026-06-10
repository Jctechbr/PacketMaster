"""Composite troubleshooting workflows."""

from __future__ import annotations

from typing import Any

from mcp_server.config import settings
from mcp_server.models import ToolResponse
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import (
    ip_filter_literal,
    validate_display_filter,
    validate_ip_address,
    validate_pcap_path,
)
from mcp_server.tools import file_ops, statistics, tcp_analysis


def _recommendations(data: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    counts = data.get("tcp_anomalies", {}).get("counts", {})
    if counts.get("retransmission", 0) > 0 or counts.get("fast_retransmission", 0) > 0:
        recs.append("pm_troubleshoot_flow on top conversation to isolate retransmission source")
    if counts.get("zero_window", 0) > 0 or counts.get("window_full", 0) > 0:
        recs.append("Check receiver buffer exhaustion; inspect pm_latency_summary for affected flows")
    if counts.get("connection_rst", 0) > 0:
        recs.append("pm_filter_packets with tcp.flags.reset == 1 to find RST endpoints")
    expert = data.get("expert", {}).get("expert", {})
    if expert.get("warnings"):
        recs.append("Review expert warnings before deep packet inspection")
    if not recs:
        recs.append("No critical TCP anomalies; review top conversations for unexpected peers")
    return recs


async def troubleshoot_quick_scan(
    runner: TsharkRunner,
    file_path: str,
    *,
    compute_hash: bool = False,
) -> ToolResponse:
    """Single-workflow triage: metadata, expert, conversations, TCP anomalies, hierarchy."""
    warnings: list[str] = []
    data: dict[str, Any] = {}

    try:
        path = validate_pcap_path(file_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    info = await file_ops.file_info(runner, file_path, compute_hash=compute_hash)
    if not info.ok:
        return info
    data["file_info"] = info.data

    packet_count = 0
    capinfos = info.data.get("capinfos", {})
    for key in ("number_of_packets", "number_of_packets:", "number_of_packets_"):
        if key in capinfos:
            try:
                packet_count = int(str(capinfos[key]).replace(",", ""))
            except ValueError:
                pass
    if packet_count > settings.large_packet_threshold:
        warnings.append(
            f"Large capture ({packet_count} packets). Consider editcap trim for faster drill-down."
        )

    hierarchy, conv, expert = await statistics.triage_stats_bundle(runner, path)
    if expert.ok:
        data["expert"] = expert.data
    else:
        warnings.append(f"expert_info: {expert.error.message if expert.error else 'failed'}")

    if conv.ok:
        data["conversations"] = conv.data
    else:
        warnings.append("conversations failed")

    anomalies = await tcp_analysis.tcp_anomalies(runner, file_path, sample_limit=3)
    if anomalies.ok:
        data["tcp_anomalies"] = anomalies.data
    else:
        warnings.append("tcp_anomalies failed")

    if hierarchy.ok:
        data["protocol_hierarchy"] = hierarchy.data
    else:
        warnings.append("protocol_hierarchy failed")

    data["recommended_next_tools"] = _recommendations(data)
    resp = ToolResponse.success(**data)
    resp.warnings = warnings
    return resp


async def troubleshoot_flow(
    runner: TsharkRunner,
    file_path: str,
    ip_a: str,
    ip_b: str,
    *,
    port: int | None = None,
) -> ToolResponse:
    """Deep dive on a specific flow between two endpoints."""
    try:
        validate_pcap_path(file_path)
        validate_ip_address(ip_a)
        validate_ip_address(ip_b)
        if port is not None and not (1 <= port <= 65535):
            raise ValueError("port must be between 1 and 65535")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    flow_filter = f"({ip_filter_literal(ip_a)} and {ip_filter_literal(ip_b)})"
    if port is not None:
        flow_filter += f" and (tcp.port == {port} or udp.port == {port})"

    try:
        flow_filter = validate_display_filter(flow_filter)
    except ValueError as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    assert flow_filter is not None
    data: dict[str, Any] = {"flow_filter": flow_filter, "ip_a": ip_a, "ip_b": ip_b, "port": port}

    anomalies = await tcp_analysis.tcp_anomalies(
        runner, file_path, display_filter=flow_filter, sample_limit=10
    )
    if anomalies.ok:
        data["tcp_anomalies"] = anomalies.data

    latency = await tcp_analysis.latency_summary(
        runner, file_path, display_filter=flow_filter, limit=10
    )
    if latency.ok:
        data["latency"] = latency.data

    packets = await statistics.conversations(runner, file_path, conv_type="tcp", limit=20)
    if packets.ok:
        convs = packets.data.get("conversations", [])
        data["matching_conversations"] = [
            c for c in convs if ip_a in str(c) and ip_b in str(c)
        ]

    io = await statistics.io_stats(runner, file_path, interval_seconds=1)
    if io.ok:
        data["io_stats"] = io.data

    return ToolResponse.success(**data)
