"""TCP expert info, anomalies, and latency analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_server.config import settings
from mcp_server.models import ToolResponse
from mcp_server.tshark.parser import parse_expert_info, parse_fields_output
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import validate_display_filter, validate_pcap_path
from mcp_server.tools.batch_counts import batch_tcp_anomaly_counts

ANOMALY_FILTERS: dict[str, str] = {
    "retransmission": "tcp.analysis.retransmission",
    "fast_retransmission": "tcp.analysis.fast_retransmission",
    "duplicate_ack": "tcp.analysis.duplicate_ack",
    "zero_window": "tcp.analysis.zero_window",
    "window_full": "tcp.analysis.window_full",
    "out_of_order": "tcp.analysis.out_of_order",
    "connection_rst": "tcp.flags.reset == 1",
}


async def expert_info(
    runner: TsharkRunner,
    file_path: str,
    *,
    severity: str | None = None,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    z_arg = "expert"
    if severity and severity in ("error", "warn", "note", "chat"):
        z_arg = f"expert,{severity}"

    result = await runner.tshark(path, ["-q", "-z", z_arg])
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])

    parsed = parse_expert_info(result.stdout)
    return ToolResponse.success(expert=parsed, raw_excerpt=result.stdout[:3000])


async def _sample_rows(
    runner: TsharkRunner,
    path: Path,
    display_filter: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    fields = [
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.analysis.flags",
    ]
    args = ["-T", "fields", "-c", str(limit)]
    for f in fields:
        args.extend(["-e", f])
    result = await runner.tshark(path, args, display_filter=display_filter)
    if result.returncode != 0:
        return []
    rows = parse_fields_output(result.stdout)
    samples = []
    for row in rows[:limit]:
        samples.append(dict(zip(fields, row + [""] * (len(fields) - len(row)))))
    return samples


async def tcp_anomalies(
    runner: TsharkRunner,
    file_path: str,
    *,
    display_filter: str | None = None,
    sample_limit: int = 5,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
        extra_filter = validate_display_filter(display_filter)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    combined_filter = extra_filter
    counts = await batch_tcp_anomaly_counts(
        runner, path, display_filter=combined_filter
    )
    samples: dict[str, list[dict[str, Any]]] = {}
    for name, filt in ANOMALY_FILTERS.items():
        if counts.get(name, 0) > 0:
            sample_filter = filt
            if extra_filter:
                sample_filter = f"({filt}) and ({extra_filter})"
            samples[name] = await _sample_rows(
                runner, path, sample_filter, limit=sample_limit
            )

    total_anomalies = sum(counts.values())
    tcp_analysis_enabled = total_anomalies > 0 or await _tcp_analysis_probe(runner, path)

    return ToolResponse.success(
        counts=counts,
        samples=samples,
        total_anomaly_packets=total_anomalies,
        tcp_analysis_enabled=tcp_analysis_enabled,
        applied_filter=extra_filter,
    )


async def _tcp_analysis_probe(runner: TsharkRunner, path: Path) -> bool:
    """Check if tcp.analysis fields are populated."""
    result = await runner.tshark(
        path,
        ["-T", "fields", "-e", "tcp.analysis.flags", "-c", "50"],
        display_filter="tcp",
    )
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        if line.strip():
            return True
    return False


async def latency_summary(
    runner: TsharkRunner,
    file_path: str,
    *,
    display_filter: str | None = None,
    limit: int = 20,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
        extra_filter = validate_display_filter(display_filter)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    base = "tcp.analysis.ack_rtt"
    filt = base
    if extra_filter:
        filt = f"({base}) and ({extra_filter})"

    fields = [
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.analysis.ack_rtt",
        "tcp.analysis.initial_rtt",
    ]
    args = ["-T", "fields", "-c", str(min(limit * 10, settings.max_packets))]
    for f in fields:
        args.extend(["-e", f])

    result = await runner.tshark(path, args, display_filter=filt)
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])

    flows: dict[str, dict[str, Any]] = {}
    for row in parse_fields_output(result.stdout):
        padded = row + [""] * (len(fields) - len(row))
        data = dict(zip(fields, padded))
        key = f"{data['ip.src']}:{data['tcp.srcport']} -> {data['ip.dst']}:{data['tcp.dstport']}"
        try:
            rtt = float(data["tcp.analysis.ack_rtt"]) if data["tcp.analysis.ack_rtt"] else None
        except ValueError:
            rtt = None
        if key not in flows:
            flows[key] = {
                "flow": key,
                "rtt_samples": [],
                "initial_rtt": data.get("tcp.analysis.initial_rtt"),
            }
        if rtt is not None:
            flows[key]["rtt_samples"].append(rtt)

    summaries = []
    for flow_data in flows.values():
        samples = flow_data["rtt_samples"]
        if samples:
            summaries.append(
                {
                    "flow": flow_data["flow"],
                    "sample_count": len(samples),
                    "rtt_min": min(samples),
                    "rtt_max": max(samples),
                    "rtt_avg": sum(samples) / len(samples),
                    "initial_rtt": flow_data.get("initial_rtt"),
                }
            )
    summaries.sort(key=lambda x: x.get("rtt_max", 0), reverse=True)
    return ToolResponse.success(flows=summaries[:limit], applied_filter=extra_filter)
