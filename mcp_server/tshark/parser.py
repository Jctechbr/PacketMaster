"""Parse tshark text output into structured data."""

from __future__ import annotations

import re
from typing import Any


def parse_capinfos(text: str) -> dict[str, Any]:
    """Parse capinfos -M output or key-value lines."""
    info: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower().replace(" ", "_")
        info[key] = value.strip()
    return info


def parse_protocol_hierarchy(text: str) -> list[dict[str, Any]]:
    """Parse tshark -z io,phs output into a tree list."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("=") or "Protocol Hierarchy" in line:
            continue
        if "Filter:" in line or "frames" not in line.lower():
            if "frames" in line.lower() and "bytes" in line.lower():
                pass
            elif not re.search(r"\d+\s+frames", line):
                continue
        indent = len(line) - len(line.lstrip())
        level = indent // 2
        match = re.search(
            r"^(\S+)\s+frames:\s*(\d+)\s+bytes:\s*(\d+)", line.strip()
        )
        if match:
            rows.append(
                {
                    "protocol": match.group(1),
                    "frames": int(match.group(2)),
                    "bytes": int(match.group(3)),
                    "level": level,
                }
            )
    return rows


def parse_conversations(text: str, limit: int = 20) -> list[dict[str, Any]]:
    """Parse tshark -z conv,ip|tcp output."""
    rows: list[dict[str, Any]] = []
    in_table = False
    for line in text.splitlines():
        if "<->" in line or "Frames" in line and "Bytes" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if line.strip().startswith("=") or not line.strip():
            if rows:
                break
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            rows.append(
                {
                    "addr_a": parts[0],
                    "port_a": parts[1] if parts[1].isdigit() else None,
                    "addr_b": parts[2] if parts[2] != "<->" else parts[3],
                    "frames_a_to_b": int(parts[-8]) if len(parts) >= 10 else 0,
                    "bytes_a_to_b": int(parts[-7]) if len(parts) >= 10 else 0,
                    "frames_b_to_a": int(parts[-4]) if len(parts) >= 10 else 0,
                    "bytes_b_to_a": int(parts[-3]) if len(parts) >= 10 else 0,
                    "total_frames": int(parts[-2]) if len(parts) >= 2 else 0,
                    "total_bytes": int(parts[-1]) if len(parts) >= 1 else 0,
                    "raw": line.strip(),
                }
            )
        except (ValueError, IndexError):
            rows.append({"raw": line.strip()})
        if len(rows) >= limit:
            break
    return _sort_by_bytes(rows)[:limit]


def parse_endpoints(text: str, limit: int = 20) -> list[dict[str, Any]]:
    """Parse tshark -z endpoints,ip output."""
    rows: list[dict[str, Any]] = []
    in_table = False
    for line in text.splitlines():
        if "Endpoints" in line and "ip" in line.lower():
            in_table = True
            continue
        if not in_table:
            continue
        if line.strip().startswith("="):
            if rows:
                break
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            rows.append(
                {
                    "address": parts[0],
                    "port": parts[1] if parts[1].isdigit() else None,
                    "tx_frames": int(parts[-4]) if len(parts) >= 4 else 0,
                    "tx_bytes": int(parts[-3]) if len(parts) >= 3 else 0,
                    "rx_frames": int(parts[-2]) if len(parts) >= 2 else 0,
                    "rx_bytes": int(parts[-1]) if len(parts) >= 1 else 0,
                    "raw": line.strip(),
                }
            )
        except (ValueError, IndexError):
            rows.append({"raw": line.strip()})
        if len(rows) >= limit:
            break
    return rows[:limit]


def parse_expert_info(text: str) -> dict[str, Any]:
    """Parse tshark -z expert output."""
    result: dict[str, Any] = {
        "errors": [],
        "warnings": [],
        "notes": [],
        "chats": [],
        "summary": {},
    }
    current: str | None = None
    for line in text.splitlines():
        line_stripped = line.strip()
        lower = line_stripped.lower()
        if "error" in lower and ("(" in line_stripped or line_stripped.endswith(":")):
            current = "errors"
            continue
        if "warn" in lower and ("(" in line_stripped or line_stripped.endswith(":")):
            current = "warnings"
            continue
        if "note" in lower and ("(" in line_stripped or line_stripped.endswith(":")):
            current = "notes"
            continue
        if "chat" in lower and ("(" in line_stripped or line_stripped.endswith(":")):
            current = "chats"
            continue
        match = re.match(r"(\S+)\s+\((\d+)\s+occurrences?\)", line_stripped)
        if match and current:
            entry = {
                "label": match.group(1),
                "count": int(match.group(2)),
            }
            result[current].append(entry)
            result["summary"][match.group(1)] = int(match.group(2))
        elif line_stripped and not line_stripped.startswith("="):
            match2 = re.match(r"(\S+)\s+(\d+)", line_stripped)
            if match2 and current:
                entry = {"label": match2.group(1), "count": int(match2.group(2))}
                result[current].append(entry)
    return result


def parse_io_stats(text: str) -> list[dict[str, Any]]:
    """Parse tshark -z io,stat output."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit():
            try:
                rows.append(
                    {
                        "interval_start": int(parts[0]),
                        "interval_end": int(parts[1]),
                        "frames": int(parts[2]),
                        "bytes": int(parts[3]),
                        "bits_per_second": float(parts[4]) if len(parts) > 4 else 0,
                    }
                )
            except ValueError:
                continue
    return rows


def parse_fields_output(text: str) -> list[list[str]]:
    """Parse tshark -T fields tab-separated output."""
    rows: list[list[str]] = []
    for line in text.splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def _sort_by_bytes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(r: dict[str, Any]) -> int:
        return int(r.get("total_bytes", 0) or 0)

    return sorted(rows, key=key, reverse=True)
