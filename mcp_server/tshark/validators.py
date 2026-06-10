"""Input validation for PCAP paths and display filters."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

from mcp_server.config import settings

# Block shell injection chars; allow {} for Wireshark "in {4,5}" set syntax.
_SHELL_METACHAR_RE = re.compile(r"[;&|`$()<>]")
_FILTER_ALLOWED_RE = re.compile(r"^[\w\s.:=!<>\-+\[\](),\"'/\\@#*%&|~^${}]+$")
_MAC_RE = re.compile(
    r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{12}$"
)


def _path_under_allowed_dirs(path: Path) -> bool:
    for root in settings.allowed_dirs:
        root_resolved = root.expanduser().resolve()
        try:
            path.relative_to(root_resolved)
            return True
        except ValueError:
            continue
    return False


def validate_pcap_path(path: str) -> Path:
    """Validate and resolve a PCAP file path."""
    if not path or not path.strip():
        raise ValueError("file_path is required")

    expanded = Path(os.path.expanduser(path.strip()))
    if not expanded.is_absolute():
        raise ValueError("file_path must be an absolute path")
    abs_path = Path(os.path.abspath(expanded))
    if abs_path.is_symlink():
        raise ValueError("Symlinks are not allowed for PCAP paths")
    for parent in abs_path.parents:
        if parent.is_symlink():
            raise ValueError("Symlinks are not allowed for PCAP paths")

    real_path = Path(os.path.realpath(abs_path))

    # Opt-in sandbox: set PM_ALLOWED_DIRS to restrict reads; PM_REQUIRE_ALLOWED_DIRS=true
    # forces that list to be configured.
    if settings.require_allowed_dirs and not settings.allowed_dirs:
        raise PermissionError(
            "PM_REQUIRE_ALLOWED_DIRS is enabled but PM_ALLOWED_DIRS is empty. "
            "Set colon-separated absolute paths, e.g. PM_ALLOWED_DIRS=/tmp:~/captures"
        )

    if settings.allowed_dirs:
        if not _path_under_allowed_dirs(abs_path):
            raise PermissionError(f"Path outside PM_ALLOWED_DIRS: {abs_path}")
        if real_path != abs_path and not _path_under_allowed_dirs(real_path):
            raise PermissionError(
                f"Path resolves outside PM_ALLOWED_DIRS: {real_path}"
            )

    p = real_path
    if not p.exists():
        raise FileNotFoundError(f"PCAP not found: {p}")
    if not p.is_file():
        raise ValueError(f"Not a regular file: {p}")

    size = p.stat().st_size
    if size > settings.max_file_size_bytes:
        raise ValueError(
            f"File exceeds PM_MAX_FILE_SIZE ({settings.max_file_size_bytes} bytes): {size}"
        )
    if size == 0:
        raise ValueError("PCAP file is empty")

    return p


def validate_ip_address(ip: str) -> str:
    """Validate and return an IP literal safe for display filters."""
    ip = ip.strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc


def ip_filter_literal(ip: str) -> str:
    """Return ip.addr filter fragment with quoted address."""
    validated = validate_ip_address(ip)
    return f'ip.addr == "{validated}"'


def normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase aa:bb:cc:dd:ee:ff."""
    mac = mac.strip()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {mac}")
    cleaned = mac.replace("-", "").replace(":", "").lower()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def validate_display_filter(display_filter: str | None) -> str | None:
    """Validate a Wireshark display filter string."""
    if display_filter is None or display_filter.strip() == "":
        return None

    filt = display_filter.strip()
    if len(filt) > settings.max_filter_length:
        raise ValueError(f"Display filter exceeds {settings.max_filter_length} characters")
    if _SHELL_METACHAR_RE.search(filt):
        raise ValueError("Display filter contains disallowed shell metacharacters")
    if not _FILTER_ALLOWED_RE.match(filt):
        raise ValueError("Display filter contains disallowed characters")

    return filt
