"""Single-pass tshark field extraction with in-Python tallies (internal helpers)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp_server.config import settings
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tools.common import extract_field_rows

_ASYMMETRIC_FIELDS = [
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.analysis.lost_segment",
    "tcp.analysis.ack_lost_segment",
    "ip.addr",
]

_WIFI_TALLY_FIELDS = [
    "frame.protocols",
    "wlan.fc.retry",
    "wlan.fc.tods",
    "wlan.fc.fromds",
    "wlan.fc.type_subtype",
    "wlan.fixed.action_code",
    "radiotap.dbm_antsignal",
]

_TCP_ANOMALY_FIELDS = [
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
    "tcp.analysis.out_of_order",
    "tcp.flags.reset",
]


def _flag_true(value: str) -> bool:
    v = value.strip().lower()
    if not v:
        return False
    if v in ("1", "true", "yes", "on"):
        return True
    if v.startswith("0x"):
        try:
            return int(v, 16) != 0
        except ValueError:
            return False
    try:
        return int(v) != 0
    except ValueError:
        return False


def _int_field(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _ip_addr_count(value: str) -> int:
    return len([part for part in value.split(",") if part.strip()])


def _has_protocol(protocols: str, needle: str) -> bool:
    return f":{needle.lower()}:" in f":{protocols.lower()}:"


def tally_asymmetric_hints(rows: list[dict[str, str]]) -> dict[str, int]:
    """Match pm_asymmetric_hints keys from one field-extraction pass."""
    counts = {
        "syn_without_ack": 0,
        "lost_segment": 0,
        "ack_lost_segment": 0,
        "connection_rst": 0,
        "multi_ip_addr_frames": 0,
    }
    for row in rows:
        syn = _flag_true(row.get("tcp.flags.syn", ""))
        ack = _flag_true(row.get("tcp.flags.ack", ""))
        if syn and not ack:
            counts["syn_without_ack"] += 1
        if _flag_true(row.get("tcp.analysis.lost_segment", "")):
            counts["lost_segment"] += 1
        if _flag_true(row.get("tcp.analysis.ack_lost_segment", "")):
            counts["ack_lost_segment"] += 1
        if _flag_true(row.get("tcp.flags.reset", "")):
            counts["connection_rst"] += 1
        if _ip_addr_count(row.get("ip.addr", "")) > 2:
            counts["multi_ip_addr_frames"] += 1
    return counts


def tally_wifi_scan(
    rows: list[dict[str, str]],
    *,
    mgmt_subtypes: dict[str, int],
    roaming_action_codes: dict[str, int],
    rssi_threshold: int,
) -> dict[str, Any]:
    """Wi-Fi quick-scan / client metrics from one wlan field pass."""
    retries = {name: 0 for name in ("retry_all", "retry_to_ap", "retry_from_ap")}
    management = {name: 0 for name in mgmt_subtypes}
    roaming = {name: 0 for name in roaming_action_codes}
    security = {"eapol": 0, "eap": 0}
    low_rssi_frames = 0
    wlan_frames = 0

    action_by_code = {int(code): name for name, code in roaming_action_codes.items()}

    for row in rows:
        protocols = row.get("frame.protocols", "")
        if not _has_protocol(protocols, "wlan"):
            continue
        wlan_frames += 1

        retry = _flag_true(row.get("wlan.fc.retry", ""))
        to_ds = _flag_true(row.get("wlan.fc.tods", ""))
        from_ds = _flag_true(row.get("wlan.fc.fromds", ""))
        if retry:
            retries["retry_all"] += 1
            if to_ds:
                retries["retry_to_ap"] += 1
            if from_ds:
                retries["retry_from_ap"] += 1

        subtype = _int_field(row.get("wlan.fc.type_subtype", ""))
        if subtype is not None:
            for name, expected in mgmt_subtypes.items():
                if subtype == expected:
                    management[name] += 1

        action = _int_field(row.get("wlan.fixed.action_code", ""))
        if action is not None:
            roam_name = action_by_code.get(action)
            if roam_name:
                roaming[roam_name] += 1

        if _has_protocol(protocols, "eapol"):
            security["eapol"] += 1
        if _has_protocol(protocols, "eap"):
            security["eap"] += 1

        rssi = _int_field(row.get("radiotap.dbm_antsignal", ""))
        if rssi is not None and rssi < rssi_threshold:
            low_rssi_frames += 1

    return {
        "wlan_frames": wlan_frames,
        "retries": retries,
        "management": management,
        "roaming": roaming,
        "security": security,
        "low_rssi_frames": low_rssi_frames,
    }


def tally_wifi_roam_counts(
    rows: list[dict[str, str]],
    *,
    mgmt_subtypes: dict[str, int],
    roaming_action_codes: dict[str, int],
) -> dict[str, int]:
    """pm_wifi_roaming_analysis roam_counts from one client-filtered pass."""
    roam_mgmt = {
        "reassociation_request": mgmt_subtypes["reassociation_request"],
        "reassociation_response": mgmt_subtypes["reassociation_response"],
        "disassociation": mgmt_subtypes["disassociation"],
        "deauthentication": mgmt_subtypes["deauthentication"],
    }
    counts: dict[str, int] = {name: 0 for name in roam_mgmt}
    counts.update({name: 0 for name in roaming_action_codes})

    action_by_code = {int(v): k for k, v in roaming_action_codes.items()}

    for row in rows:
        subtype = _int_field(row.get("wlan.fc.type_subtype", ""))
        if subtype is not None:
            for name, expected in roam_mgmt.items():
                if subtype == expected:
                    counts[name] += 1
        action = _int_field(row.get("wlan.fixed.action_code", ""))
        if action is not None:
            roam_name = action_by_code.get(action)
            if roam_name:
                counts[roam_name] += 1
    return counts


def tally_tcp_anomalies(rows: list[dict[str, str]]) -> dict[str, int]:
    """TCP anomaly packet counts (matches ANOMALY_FILTERS semantics)."""
    return {
        "retransmission": sum(
            1 for r in rows if _flag_true(r.get("tcp.analysis.retransmission", ""))
        ),
        "fast_retransmission": sum(
            1 for r in rows if _flag_true(r.get("tcp.analysis.fast_retransmission", ""))
        ),
        "duplicate_ack": sum(
            1 for r in rows if _flag_true(r.get("tcp.analysis.duplicate_ack", ""))
        ),
        "zero_window": sum(
            1 for r in rows if _flag_true(r.get("tcp.analysis.zero_window", ""))
        ),
        "window_full": sum(
            1 for r in rows if _flag_true(r.get("tcp.analysis.window_full", ""))
        ),
        "out_of_order": sum(
            1 for r in rows if _flag_true(r.get("tcp.analysis.out_of_order", ""))
        ),
        "connection_rst": sum(
            1 for r in rows if _flag_true(r.get("tcp.flags.reset", ""))
        ),
    }


async def _tally_rows(
    runner: TsharkRunner,
    path: Path,
    fields: list[str],
    *,
    display_filter: str | None,
    tally: Callable[[list[dict[str, str]]], Any],
) -> Any:
    rows = await extract_field_rows(
        runner,
        path,
        fields,
        display_filter=display_filter,
        limit=settings.max_packets,
    )
    return tally(rows)


async def batch_asymmetric_hints(
    runner: TsharkRunner,
    path: Path,
    *,
    display_filter: str | None = None,
) -> dict[str, int]:
    return await _tally_rows(
        runner,
        path,
        _ASYMMETRIC_FIELDS,
        display_filter=display_filter,
        tally=tally_asymmetric_hints,
    )


async def batch_wifi_scan_metrics(
    runner: TsharkRunner,
    path: Path,
    *,
    display_filter: str | None,
    mgmt_subtypes: dict[str, int],
    roaming_action_codes: dict[str, int],
    rssi_threshold: int,
) -> dict[str, Any]:
    def _tally(rows: list[dict[str, str]]) -> dict[str, Any]:
        return tally_wifi_scan(
            rows,
            mgmt_subtypes=mgmt_subtypes,
            roaming_action_codes=roaming_action_codes,
            rssi_threshold=rssi_threshold,
        )

    return await _tally_rows(
        runner,
        path,
        _WIFI_TALLY_FIELDS,
        display_filter=display_filter or "wlan",
        tally=_tally,
    )


async def batch_wifi_roam_counts(
    runner: TsharkRunner,
    path: Path,
    *,
    display_filter: str,
    mgmt_subtypes: dict[str, int],
    roaming_action_codes: dict[str, int],
) -> dict[str, int]:
    fields = ["wlan.fc.type_subtype", "wlan.fixed.action_code"]

    def _tally(rows: list[dict[str, str]]) -> dict[str, int]:
        return tally_wifi_roam_counts(
            rows,
            mgmt_subtypes=mgmt_subtypes,
            roaming_action_codes=roaming_action_codes,
        )

    return await _tally_rows(
        runner,
        path,
        fields,
        display_filter=display_filter,
        tally=_tally,
    )


async def batch_tcp_anomaly_counts(
    runner: TsharkRunner,
    path: Path,
    *,
    display_filter: str | None = None,
) -> dict[str, int]:
    return await _tally_rows(
        runner,
        path,
        _TCP_ANOMALY_FIELDS,
        display_filter=display_filter,
        tally=tally_tcp_anomalies,
    )
