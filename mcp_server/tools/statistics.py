"""Protocol hierarchy, conversations, endpoints, and I/O stats."""

from __future__ import annotations

from pathlib import Path

from mcp_server.models import ToolResponse
from mcp_server.tshark.parser import (
    parse_conversations,
    parse_endpoints,
    parse_expert_info,
    parse_io_stats,
    parse_protocol_hierarchy,
)
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import validate_pcap_path


async def _validated_path(file_path: str) -> tuple[Path | None, ToolResponse | None]:
    try:
        return validate_pcap_path(file_path), None
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return None, ToolResponse.failure("VALIDATION_ERROR", str(e))


async def triage_stats_bundle(
    runner: TsharkRunner, path: Path
) -> tuple[ToolResponse | None, ToolResponse | None, ToolResponse | None]:
    """Single tshark invocation for phs + conv,ip + expert (wired quick scan hot path)."""
    result = await runner.tshark(
        path, ["-q", "-z", "io,phs", "-z", "conv,ip", "-z", "expert"]
    )
    if result.returncode != 0:
        err = ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])
        return err, err, err
    hierarchy = ToolResponse.success(
        protocols=parse_protocol_hierarchy(result.stdout),
        raw_excerpt=result.stdout[:2000],
    )
    conversations = ToolResponse.success(
        conversations=parse_conversations(result.stdout, limit=10),
        conv_type="ip",
    )
    expert = ToolResponse.success(expert=parse_expert_info(result.stdout))
    return hierarchy, conversations, expert


async def protocol_hierarchy(runner: TsharkRunner, file_path: str) -> ToolResponse:
    path, err = await _validated_path(file_path)
    if err:
        return err
    assert path is not None
    result = await runner.tshark(path, ["-q", "-z", "io,phs"])
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])
    rows = parse_protocol_hierarchy(result.stdout)
    return ToolResponse.success(protocols=rows, raw_excerpt=result.stdout[:2000])


async def conversations(
    runner: TsharkRunner,
    file_path: str,
    *,
    conv_type: str = "ip",
    limit: int = 20,
) -> ToolResponse:
    path, err = await _validated_path(file_path)
    if err:
        return err
    assert path is not None
    conv = conv_type if conv_type in ("ip", "tcp", "udp") else "ip"
    result = await runner.tshark(path, ["-q", "-z", f"conv,{conv}"])
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])
    rows = parse_conversations(result.stdout, limit=limit)
    return ToolResponse.success(conversations=rows, conv_type=conv)


async def endpoints(
    runner: TsharkRunner,
    file_path: str,
    *,
    limit: int = 20,
) -> ToolResponse:
    path, err = await _validated_path(file_path)
    if err:
        return err
    assert path is not None
    result = await runner.tshark(path, ["-q", "-z", "endpoints,ip"])
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])
    rows = parse_endpoints(result.stdout, limit=limit)
    return ToolResponse.success(endpoints=rows)


async def io_stats(
    runner: TsharkRunner,
    file_path: str,
    *,
    interval_seconds: int = 1,
) -> ToolResponse:
    path, err = await _validated_path(file_path)
    if err:
        return err
    assert path is not None
    interval = max(1, min(interval_seconds, 3600))
    result = await runner.tshark(
        path, ["-q", "-z", f"io,stat,{interval}"]
    )
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])
    rows = parse_io_stats(result.stdout)
    return ToolResponse.success(interval_seconds=interval, intervals=rows)
