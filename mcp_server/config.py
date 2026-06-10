"""Runtime configuration from environment variables."""

from __future__ import annotations

import os
from pathlib import Path


def _parse_dirs(raw: str | None) -> list[Path]:
    if not raw:
        return []
    return [Path(p.strip()).expanduser().resolve() for p in raw.split(":") if p.strip()]


class Settings:
    schema_version: str = "1.0"
    max_file_size_bytes: int = int(os.getenv("PM_MAX_FILE_SIZE", str(10 * 1024**3)))
    max_packets: int = int(os.getenv("PM_MAX_PACKETS", "10000"))
    max_stdout_bytes: int = int(os.getenv("PM_MAX_STDOUT_BYTES", str(10 * 1024**2)))
    timeout_seconds: int = int(os.getenv("PM_TIMEOUT", "300"))
    hash_max_bytes: int = int(os.getenv("PM_HASH_MAX_BYTES", str(500 * 1024**2)))
    max_filter_length: int = int(os.getenv("PM_MAX_FILTER_LENGTH", "512"))
    tmp_dir: Path = Path(os.getenv("PM_TMP_DIR", "/tmp/packetmaster")).expanduser()
    tshark_path: str | None = os.getenv("TSHARK_PATH")
    capinfos_path: str | None = os.getenv("CAPINFOS_PATH")
    editcap_path: str | None = os.getenv("EDITCAP_PATH")
    allowed_dirs: list[Path] = _parse_dirs(os.getenv("PM_ALLOWED_DIRS"))
    require_allowed_dirs: bool = os.getenv("PM_REQUIRE_ALLOWED_DIRS", "false").lower() in (
        "1",
        "true",
        "yes",
    )
    redact_sensitive: bool = os.getenv("PM_REDACT_SENSITIVE", "true").lower() in (
        "1",
        "true",
        "yes",
    )
    large_packet_threshold: int = int(os.getenv("PM_LARGE_PACKET_THRESHOLD", "1000000"))


settings = Settings()
