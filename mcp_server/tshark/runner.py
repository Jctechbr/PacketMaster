"""Subprocess wrapper for tshark and related Wireshark CLI tools."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
from pathlib import Path

import structlog

from mcp_server.config import settings

logger = structlog.get_logger()

TCP_ANALYSIS_PREF = "tcp.analyze_sequence_numbers:TRUE"

_MACOS_WIRESHARK_BIN = Path("/Applications/Wireshark.app/Contents/MacOS")


def _find_binary(name: str, override: str | None) -> str | None:
    if override:
        return override
    found = shutil.which(name)
    if found:
        return found
    if _MACOS_WIRESHARK_BIN.exists():
        candidate = _MACOS_WIRESHARK_BIN / name
        if candidate.is_file():
            return str(candidate)
    return None


class TsharkRunner:
    """Execute Wireshark CLI tools with safety limits."""

    _semaphore: asyncio.Semaphore | None = None

    def __init__(self) -> None:
        self._tshark = _find_binary("tshark", settings.tshark_path)
        self._capinfos = _find_binary("capinfos", settings.capinfos_path)
        self._editcap = _find_binary("editcap", settings.editcap_path)

    @classmethod
    def _get_semaphore(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(1)
        return cls._semaphore

    @property
    def tshark_path(self) -> str | None:
        return self._tshark

    @property
    def capinfos_path(self) -> str | None:
        return self._capinfos

    @property
    def editcap_path(self) -> str | None:
        return self._editcap

    def base_tshark_args(self) -> list[str]:
        if not self._tshark:
            raise RuntimeError("tshark not found on PATH")
        return [self._tshark, "-o", TCP_ANALYSIS_PREF]

    async def run(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
        tool_name: str = "subprocess",
    ) -> subprocess.CompletedProcess[str]:
        """Run a command with concurrency limit, timeout, and stdout cap."""
        timeout = timeout or settings.timeout_seconds
        env = os.environ.copy()
        env["LC_ALL"] = "C"

        async with self._get_semaphore():
            logger.info("subprocess_start", tool=tool_name, cmd=cmd[:3])
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                start_new_session=True,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    proc.kill()
                await proc.wait()
                raise TimeoutError(f"{tool_name} timed out after {timeout}s")

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            truncated = False
            if len(stdout) > settings.max_stdout_bytes:
                stdout_str = stdout_str[: settings.max_stdout_bytes]
                truncated = True

            logger.info(
                "subprocess_done",
                tool=tool_name,
                returncode=proc.returncode,
                stdout_bytes=len(stdout),
                truncated=truncated,
            )

            if truncated:
                stderr_str += "\n[stdout truncated at PM_MAX_STDOUT_BYTES]"

            return subprocess.CompletedProcess(
                args=cmd,
                returncode=proc.returncode if proc.returncode is not None else 0,
                stdout=stdout_str,
                stderr=stderr_str,
            )

    async def tshark(
        self,
        pcap: Path,
        extra_args: list[str],
        *,
        display_filter: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = self.base_tshark_args() + ["-r", str(pcap), "-n"]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        cmd.extend(extra_args)
        return await self.run(cmd, timeout=timeout, tool_name="tshark")

    async def capinfos(self, pcap: Path) -> subprocess.CompletedProcess[str]:
        if not self._capinfos:
            raise RuntimeError("capinfos not found on PATH")
        cmd = [self._capinfos, str(pcap)]
        return await self.run(cmd, tool_name="capinfos")

    async def tshark_version(self) -> str | None:
        if not self._tshark:
            return None
        result = await self.run([self._tshark, "-v"], tool_name="tshark_version")
        return result.stdout.splitlines()[0] if result.stdout else None
