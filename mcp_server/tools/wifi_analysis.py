"""802.11 Wi-Fi frame analysis for monitor-mode captures."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from mcp_server.config import settings
from mcp_server.models import ToolResponse
from mcp_server.tshark.parser import parse_fields_output
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import normalize_mac, validate_pcap_path
from mcp_server.tools import file_ops
from mcp_server.tools.batch_counts import (
    batch_wifi_roam_counts,
    batch_wifi_scan_metrics,
)
from mcp_server.tools.common import count_filter

# 802.11 management frame subtypes (wlan.fc.type_subtype)
WLAN_MGMT: dict[str, int] = {
    "association_request": 0,
    "association_response": 1,
    "reassociation_request": 2,
    "reassociation_response": 3,
    "probe_request": 4,
    "probe_response": 5,
    "beacon": 8,
    "disassociation": 10,
    "authentication": 11,
    "deauthentication": 12,
}

WLAN_ROAMING_ACTION_CODE_INT: dict[str, int] = {
    "neighbor_request": 4,
    "neighbor_response": 5,
    "bss_transition_query": 7,
    "bss_transition_request": 8,
}


async def detect_capture_type(
    runner: TsharkRunner, path: Path
) -> dict[str, Any]:
    wlan_count = await count_filter(runner, path, "wlan")
    if wlan_count > 0:
        return {
            "capture_type": "wlan_monitor",
            "wlan_frames": wlan_count,
            "message": "802.11 frames detected; Wi-Fi tools applicable.",
        }
    return {
        "capture_type": "ethernet_only",
        "wlan_frames": 0,
        "message": (
            "No 802.11 frames found. This capture is likely EPC/SPAN (L3). "
            "Use pm_troubleshoot_quick_scan instead."
        ),
    }


async def _require_wlan(
    runner: TsharkRunner, path: Path
) -> tuple[dict[str, Any] | None, ToolResponse | None]:
    meta = await detect_capture_type(runner, path)
    if meta["capture_type"] != "wlan_monitor":
        return None, ToolResponse.failure(
            "NOT_WLAN_CAPTURE",
            meta["message"],
            capture_type=meta["capture_type"],
            wlan_frames=0,
        )
    return meta, None


async def _top_bssids(
    runner: TsharkRunner, path: Path, limit: int = 10
) -> list[dict[str, Any]]:
    result = await runner.tshark(
        path,
        [
            "-T",
            "fields",
            "-e",
            "wlan.bssid",
            "-c",
            str(min(settings.max_packets, 50000)),
        ],
        display_filter="wlan.bssid",
    )
    if result.returncode != 0:
        return []
    counter: Counter[str] = Counter()
    for row in parse_fields_output(result.stdout):
        if row and row[0].strip():
            counter[row[0].strip()] += 1
    return [{"bssid": bssid, "frames": count} for bssid, count in counter.most_common(limit)]


def _wifi_recommendations(data: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    retries = data.get("retries", {})
    if retries.get("retry_all", 0) > 0:
        recs.append("pm_wifi_client_analysis on top STA MAC to isolate retry source")
    deauth = data.get("management", {}).get("deauthentication", 0)
    disassoc = data.get("management", {}).get("disassociation", 0)
    if deauth > 0 or disassoc > 0:
        recs.append("pm_filter_packets with wlan.fc.type_subtype == 12 for deauth details")
    roaming = data.get("roaming", {})
    if any(roaming.values()):
        recs.append("pm_wifi_roaming_analysis on affected client MAC")
    eapol = data.get("security", {}).get("eapol", 0)
    if eapol > 0:
        recs.append("pm_filter_packets with eapol to inspect 4-way handshake")
    if not recs:
        recs.append("Review top_bssids and management frame counts for anomalies")
    return recs


async def wifi_quick_scan(
    runner: TsharkRunner,
    file_path: str,
    *,
    rssi_threshold: int = -75,
) -> ToolResponse:
    """Composite 802.11 triage for monitor-mode captures."""
    try:
        path = validate_pcap_path(file_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    capture_meta, err = await _require_wlan(runner, path)
    if err:
        return err

    assert capture_meta is not None
    warnings: list[str] = []
    data: dict[str, Any] = {"capture": capture_meta}

    info = await file_ops.file_info(runner, file_path)
    if info.ok:
        data["file_info"] = info.data

    wifi_metrics = await batch_wifi_scan_metrics(
        runner,
        path,
        display_filter="wlan",
        mgmt_subtypes=WLAN_MGMT,
        roaming_action_codes=WLAN_ROAMING_ACTION_CODE_INT,
        rssi_threshold=rssi_threshold,
    )
    data["retries"] = wifi_metrics["retries"]
    data["management"] = wifi_metrics["management"]
    data["security"] = wifi_metrics["security"]
    data["roaming"] = wifi_metrics["roaming"]
    data["low_rssi_frames"] = wifi_metrics["low_rssi_frames"]
    data["rssi_threshold_dbm"] = rssi_threshold
    data["top_bssids"] = await _top_bssids(runner, path, limit=10)

    total_wlan = capture_meta["wlan_frames"]
    if total_wlan > 0:
        data["retry_rate_pct"] = round(
            (data["retries"].get("retry_all", 0) / total_wlan) * 100, 2
        )

    data["recommended_next_tools"] = _wifi_recommendations(data)
    resp = ToolResponse.success(**data)
    resp.warnings = warnings
    return resp


async def wifi_client_analysis(
    runner: TsharkRunner,
    file_path: str,
    wlan_addr: str,
    *,
    sample_limit: int = 5,
) -> ToolResponse:
    """Deep dive on a single client STA by wlan.addr (bidirectional)."""
    try:
        path = validate_pcap_path(file_path)
        mac = normalize_mac(wlan_addr)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    _, err = await _require_wlan(runner, path)
    if err:
        return err

    client_filter = f"wlan.addr == {mac}"

    wifi_metrics = await batch_wifi_scan_metrics(
        runner,
        path,
        display_filter=client_filter,
        mgmt_subtypes=WLAN_MGMT,
        roaming_action_codes=WLAN_ROAMING_ACTION_CODE_INT,
        rssi_threshold=-75,
    )
    retries = wifi_metrics["retries"]
    mgmt = wifi_metrics["management"]
    security = wifi_metrics["security"]
    roaming = wifi_metrics["roaming"]

    samples = await _client_event_samples(runner, path, client_filter, sample_limit)

    return ToolResponse.success(
        wlan_addr=mac,
        client_filter=client_filter,
        retries=retries,
        management=mgmt,
        security=security,
        roaming=roaming,
        event_samples=samples,
        recommended_next_tools=_client_recommendations(retries, mgmt, roaming, security),
    )


async def _client_event_samples(
    runner: TsharkRunner,
    path: Path,
    client_filter: str,
    limit: int,
) -> list[dict[str, str]]:
    event_filter = (
        f"({client_filter}) and (wlan.fc.type == 0 or eapol or eap)"
    )
    fields = [
        "frame.time_relative",
        "wlan.fc.type_subtype",
        "wlan.bssid",
        "wlan.ta",
        "wlan.ra",
        "wlan_mgt.ssid",
        "radiotap.dbm_antsignal",
    ]
    args = ["-T", "fields", "-c", str(limit)]
    for f in fields:
        args.extend(["-e", f])
    result = await runner.tshark(path, args, display_filter=event_filter)
    if result.returncode != 0:
        return []
    rows = []
    for row in parse_fields_output(result.stdout)[:limit]:
        padded = row + [""] * (len(fields) - len(row))
        rows.append(dict(zip(fields, padded)))
    return rows


def _client_recommendations(
    retries: dict[str, int],
    mgmt: dict[str, int],
    roaming: dict[str, int],
    security: dict[str, int],
) -> list[str]:
    recs: list[str] = []
    if retries.get("retry_all", 0) > 0:
        recs.append("Check RSSI in event_samples; retries often indicate RF issues")
    if mgmt.get("deauthentication", 0) > 0:
        recs.append("Inspect deauth reason codes via pm_filter_packets wlan.fc.type_subtype == 12")
    if roaming.get("neighbor_request", 0) > 0:
        recs.append("pm_wifi_roaming_analysis for full roam timeline")
    if security.get("eapol", 0) > 0 and mgmt.get("association_response", 0) == 0:
        recs.append("EAPOL without association — possible auth failure")
    if not recs:
        recs.append("Compare with pm_wifi_quick_scan baseline for other STAs")
    return recs


async def wifi_roaming_analysis(
    runner: TsharkRunner,
    file_path: str,
    wlan_addr: str,
    *,
    sample_limit: int = 20,
) -> ToolResponse:
    """Analyze 802.11k/v roaming frames for a client STA."""
    try:
        path = validate_pcap_path(file_path)
        mac = normalize_mac(wlan_addr)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    _, err = await _require_wlan(runner, path)
    if err:
        return err

    client_filter = f"wlan.addr == {mac}"
    roam_filter = (
        f"({client_filter}) and ("
        f"wlan.fc.type_subtype in {{{2}, {3}, {10}, {12}}} or "
        f"wlan.fixed.action_code in {{{4}, {5}, {7}, {8}}})"
    )

    counts = await batch_wifi_roam_counts(
        runner,
        path,
        display_filter=client_filter,
        mgmt_subtypes=WLAN_MGMT,
        roaming_action_codes=WLAN_ROAMING_ACTION_CODE_INT,
    )

    fields = [
        "frame.time_relative",
        "wlan.fc.type_subtype",
        "wlan.fixed.action_code",
        "wlan.bssid",
        "wlan.ta",
        "wlan.ra",
        "wlan_mgt.ssid",
    ]
    args = ["-T", "fields", "-c", str(sample_limit)]
    for f in fields:
        args.extend(["-e", f])
    result = await runner.tshark(path, args, display_filter=roam_filter)
    timeline: list[dict[str, str]] = []
    if result.returncode == 0:
        for row in parse_fields_output(result.stdout)[:sample_limit]:
            padded = row + [""] * (len(fields) - len(row))
            timeline.append(dict(zip(fields, padded)))

    sticky_hint = (
        counts["reassociation_request"] == 0
        and counts["neighbor_request"] == 0
        and counts["deauthentication"] == 0
    )

    return ToolResponse.success(
        wlan_addr=mac,
        roam_counts=counts,
        timeline=timeline,
        sticky_client_suspected=sticky_hint,
        note="Use wlan.fixed.action_code (not deprecated wlan.rm.action_code).",
    )
