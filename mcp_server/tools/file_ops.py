"""File metadata and capinfos tools."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_server.config import settings
from mcp_server.models import ToolResponse
from mcp_server.tshark.parser import parse_capinfos
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import validate_pcap_path


def _stream_hash(path: Path, max_bytes: int) -> tuple[str | None, str]:
    size = path.stat().st_size
    if size > max_bytes:
        return None, "skipped_large_file"
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest(), "computed"


async def check_install(runner: TsharkRunner) -> ToolResponse:
    version = await runner.tshark_version()
    tcp_test_ok = False
    warnings: list[str] = []

    if not runner.tshark_path:
        return ToolResponse.failure(
            "TSHARK_NOT_FOUND",
            "tshark not found. Install Wireshark: brew install wireshark",
        )
    if not runner.capinfos_path:
        warnings.append("capinfos not found on PATH")

    return ToolResponse.success(
        tshark_path=runner.tshark_path,
        capinfos_path=runner.capinfos_path,
        editcap_path=runner.editcap_path,
        tshark_version=version,
        tcp_analysis_enforced=runner.base_tshark_args()[1:3],
        tcp_self_test_ok=tcp_test_ok,
        allowed_dirs=[str(d) for d in settings.allowed_dirs],
        require_allowed_dirs=settings.require_allowed_dirs,
        warnings=warnings,
    )


async def file_info(
    runner: TsharkRunner,
    file_path: str,
    *,
    compute_hash: bool = False,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    stat = path.stat()
    hash_value: str | None = None
    hash_status = "not_requested"
    if compute_hash:
        hash_value, hash_status = _stream_hash(path, settings.hash_max_bytes)

    capinfos_data: dict[str, Any] = {}
    warnings: list[str] = []
    if runner.capinfos_path:
        try:
            result = await runner.capinfos(path)
            if result.returncode == 0:
                capinfos_data = parse_capinfos(result.stdout)
            else:
                warnings.append(f"capinfos failed: {result.stderr[:200]}")
        except Exception as e:
            warnings.append(f"capinfos error: {e}")
    else:
        warnings.append("capinfos not available")

    return ToolResponse.success(
        path=str(path),
        size_bytes=stat.st_size,
        modified_utc=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        sha256=hash_value,
        hash_status=hash_status,
        capinfos=capinfos_data,
        warnings=warnings,
    )
