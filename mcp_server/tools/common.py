"""Shared tshark helpers for PacketMaster tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_server.config import settings
from mcp_server.tshark.parser import parse_fields_output
from mcp_server.tshark.runner import TsharkRunner


async def count_filter(
    runner: TsharkRunner, path: Path, display_filter: str
) -> int:
    result = await runner.tshark(
        path,
        ["-q", "-T", "fields", "-e", "frame.number"],
        display_filter=display_filter,
    )
    if result.returncode != 0:
        return 0
    return len([ln for ln in result.stdout.splitlines() if ln.strip()])


async def extract_field_values(
    runner: TsharkRunner,
    path: Path,
    field: str,
    *,
    display_filter: str | None = None,
    limit: int = 50000,
) -> list[str]:
    result = await runner.tshark(
        path,
        ["-T", "fields", "-e", field, "-c", str(min(limit, settings.max_packets))],
        display_filter=display_filter,
    )
    if result.returncode != 0:
        return []
    values: list[str] = []
    for row in parse_fields_output(result.stdout):
        if row and row[0].strip():
            values.append(row[0].strip())
    return values


async def protocol_presence_counts(
    runner: TsharkRunner,
    path: Path,
    protocols: dict[str, str],
) -> dict[str, int]:
    """Count frames matching protocol keys in one tshark pass via frame.protocols."""
    result = await runner.tshark(
        path,
        ["-T", "fields", "-e", "frame.protocols", "-c", str(settings.max_packets)],
    )
    counts = {name: 0 for name in protocols}
    if result.returncode != 0:
        return counts
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        lower = line.lower()
        tokens = f":{lower}:"
        for name, needle in protocols.items():
            if f":{needle.lower()}:" in tokens:
                counts[name] += 1
    return counts


async def extract_field_rows(
    runner: TsharkRunner,
    path: Path,
    fields: list[str],
    *,
    display_filter: str | None = None,
    limit: int = 50000,
) -> list[dict[str, str]]:
    """Extract multiple tshark fields per frame in one pass."""
    args = ["-T", "fields", "-c", str(min(limit, settings.max_packets))]
    for field in fields:
        args.extend(["-e", field])
    result = await runner.tshark(path, args, display_filter=display_filter)
    if result.returncode != 0:
        return []
    rows: list[dict[str, str]] = []
    for row in parse_fields_output(result.stdout):
        padded = row + [""] * (len(fields) - len(row))
        rows.append(dict(zip(fields, padded)))
    return rows


async def sample_fields(
    runner: TsharkRunner,
    path: Path,
    fields: list[str],
    display_filter: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    args = ["-T", "fields", "-c", str(limit)]
    for f in fields:
        args.extend(["-e", f])
    result = await runner.tshark(path, args, display_filter=display_filter)
    if result.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for row in parse_fields_output(result.stdout)[:limit]:
        padded = row + [""] * (len(fields) - len(row))
        rows.append(dict(zip(fields, padded)))
    return rows
