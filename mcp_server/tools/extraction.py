"""Field extraction, packet filtering, and stream following."""

from __future__ import annotations

from mcp_server.config import settings
from mcp_server.models import ToolResponse
from mcp_server.tshark.parser import parse_fields_output
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import validate_display_filter, validate_pcap_path
from mcp_server.tools.redaction import redact_text


async def extract_fields(
    runner: TsharkRunner,
    file_path: str,
    fields: list[str],
    *,
    display_filter: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
        filt = validate_display_filter(display_filter)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    if not fields:
        return ToolResponse.failure("VALIDATION_ERROR", "fields list is required")
    if len(fields) > 20:
        return ToolResponse.failure("VALIDATION_ERROR", "Maximum 20 fields per request")

    limit = max(1, min(limit, settings.max_packets))
    args = ["-T", "fields", "-c", str(offset + limit)]
    for f in fields:
        args.extend(["-e", f])

    result = await runner.tshark(path, args, display_filter=filt)
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])

    all_rows = parse_fields_output(result.stdout)
    page = all_rows[offset : offset + limit]
    rows = []
    for row in page:
        row_dict = dict(zip(fields, row + [""] * (len(fields) - len(row))))
        if settings.redact_sensitive:
            row_dict = {k: redact_text(v) for k, v in row_dict.items()}
        rows.append(row_dict)

    return ToolResponse.success(
        fields=fields,
        rows=rows,
        offset=offset,
        limit=limit,
        returned=len(rows),
        has_more=len(all_rows) > offset + limit,
        applied_filter=filt,
    )


async def filter_packets(
    runner: TsharkRunner,
    file_path: str,
    display_filter: str,
    *,
    offset: int = 0,
    limit: int = 50,
) -> ToolResponse:
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "frame.protocols",
        "frame.len",
        "_ws.col.Info",
    ]
    return await extract_fields(
        runner,
        file_path,
        fields,
        display_filter=display_filter,
        offset=offset,
        limit=limit,
    )


async def follow_stream(
    runner: TsharkRunner,
    file_path: str,
    *,
    stream_type: str = "tcp",
    stream_index: int = 0,
    max_bytes: int = 8192,
    redact: bool | None = None,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    stype = stream_type if stream_type in ("tcp", "udp", "http", "tls") else "tcp"
    max_bytes = max(256, min(max_bytes, settings.max_stdout_bytes))

    args = [
        "-q",
        "-z",
        f"follow,{stype},ascii,{stream_index}",
    ]
    result = await runner.tshark(path, args)
    if result.returncode != 0:
        return ToolResponse.failure("TSHARK_ERROR", result.stderr[:500])

    payload = result.stdout
    truncated = len(payload) > max_bytes
    if truncated:
        payload = payload[:max_bytes]

    do_redact = settings.redact_sensitive if redact is None else redact
    if do_redact:
        payload = redact_text(payload)

    return ToolResponse.success(
        stream_type=stype,
        stream_index=stream_index,
        payload=payload,
        truncated=truncated,
        redacted=do_redact,
        warning="Stream may contain credentials; use only for troubleshooting with user consent.",
    )
