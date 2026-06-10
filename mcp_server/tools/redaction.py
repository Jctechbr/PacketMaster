"""Redact sensitive patterns from PCAP-derived text."""

from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"Authorization:\s*\S+(?:\s+\S+)?", re.I), "Authorization: [REDACTED]"),
    (re.compile(r"Bearer\s+\S+", re.I), "Bearer [REDACTED]"),
    (re.compile(r"(password[=:]\s*)(\S+)", re.I), r"\1[REDACTED]"),
    (re.compile(r"(PASS\s+)(\S+)", re.I), r"\1[REDACTED]"),
    (re.compile(r"(USER\s+)(\S+)", re.I), r"\1[REDACTED]"),
    (re.compile(r"(Cookie:\s*)(.+)", re.I), r"\1[REDACTED]"),
]


def redact_text(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text
