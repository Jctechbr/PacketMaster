"""Detect capture type and recommend entry-point tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_server.models import ToolResponse
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import validate_pcap_path
from mcp_server.tools.common import count_filter, protocol_presence_counts

_ETHERNET_PROTOCOLS = {
    "vlan": "vlan",
    "tcp": "tcp",
    "udp": "udp",
    "dhcp": "bootp",
    "dns": "dns",
    "icmpv4": "icmp",
    "icmpv6": "icmpv6",
}


async def detect_capture_type(
    runner: TsharkRunner, file_path: str
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    wlan = await count_filter(runner, path, "wlan")
    proto = await protocol_presence_counts(runner, path, _ETHERNET_PROTOCOLS)
    vlan = proto["vlan"]
    tcp = proto["tcp"]
    udp = proto["udp"]
    dhcp = proto["dhcp"]
    dns = proto["dns"]
    icmp = proto["icmpv4"] + proto["icmpv6"]

    if wlan > 0:
        capture_type = "wlan_monitor"
        recommended_entrypoint = "pm_wifi_quick_scan"
        message = "802.11 frames present — use Wi-Fi tools."
    else:
        capture_type = "ethernet_l3"
        recommended_entrypoint = "pm_wired_quick_scan"
        message = "Ethernet/L3 capture — use wired tools (typical for EPC/SPAN)."

    alt_tools: list[str] = ["pm_troubleshoot_quick_scan"]
    if dhcp > 0:
        alt_tools.append("pm_dhcp_analysis")
    if dns > 0:
        alt_tools.append("pm_dns_analysis")
    if tcp > 0:
        alt_tools.append("pm_asymmetric_hints")

    data: dict[str, Any] = {
        "capture_type": capture_type,
        "recommended_entrypoint": recommended_entrypoint,
        "message": message,
        "frame_counts": {
            "wlan": wlan,
            "vlan": vlan,
            "tcp": tcp,
            "udp": udp,
            "dhcp": dhcp,
            "dns": dns,
            "icmp": icmp,
        },
        "also_consider": alt_tools,
    }
    return ToolResponse.success(**data)
