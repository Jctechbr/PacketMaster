"""Wired Ethernet / L3 analysis for EPC, SPAN, and tap captures."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from mcp_server.models import ToolResponse
from mcp_server.tshark.runner import TsharkRunner
from mcp_server.tshark.validators import (
    ip_filter_literal,
    normalize_mac,
    validate_display_filter,
    validate_ip_address,
    validate_pcap_path,
)
from mcp_server.tools import file_ops, statistics, tcp_analysis
from mcp_server.tools.capture_detect import detect_capture_type
from mcp_server.tools.batch_counts import batch_asymmetric_hints
from mcp_server.tools.common import (
    count_filter,
    extract_field_rows,
    extract_field_values,
    sample_fields,
)

_L3_TRIAGE_FIELDS = [
    "frame.protocols",
    "dns.flags.response",
    "dns.flags.rcode",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
]

DHCP_MESSAGE_TYPES: dict[str, int] = {
    "discover": 1,
    "offer": 2,
    "request": 3,
    "decline": 4,
    "ack": 5,
    "nak": 6,
    "release": 7,
    "inform": 8,
}
_DHCP_MSG_TYPE_BY_CODE: dict[int, str] = {
    code: name for name, code in DHCP_MESSAGE_TYPES.items()
}

INFRA_PROTOCOLS: dict[str, str] = {
    "stp": "stp",
    "cdp": "cdp",
    "lldp": "lldp",
    "hsrp": "hsrp",
    "vrrp": "vrrp",
    "igmp": "igmp",
    "eapol": "eapol",
    "eap": "eap",
}

NOISE_FILTER = "arp or dhcp or bootp or mdns or ssdp or browser"


async def _require_ethernet(
    runner: TsharkRunner, path: Path
) -> tuple[dict[str, Any] | None, ToolResponse | None]:
    meta_resp = await detect_capture_type(runner, str(path))
    if not meta_resp.ok:
        return None, meta_resp
    meta = meta_resp.data
    if meta.get("capture_type") == "wlan_monitor":
        return None, ToolResponse.failure(
            "WLAN_CAPTURE",
            "802.11 monitor capture detected. Use pm_wifi_quick_scan instead.",
            **meta,
        )
    return meta, None


async def _dhcp_counts(runner: TsharkRunner, path: Path, base: str | None = None) -> dict[str, int]:
    """Single-pass DHCP message type counts via field extraction."""
    filt = f"bootp and ({base})" if base else "bootp"
    values = await extract_field_values(
        runner, path, "bootp.option.dhcp", display_filter=filt
    )
    counts = {name: 0 for name in DHCP_MESSAGE_TYPES}
    counts["all"] = len(values)
    for raw in values:
        try:
            msg_type = int(raw)
        except ValueError:
            continue
        name = _DHCP_MSG_TYPE_BY_CODE.get(msg_type)
        if name:
            counts[name] += 1
    return counts


def _empty_dns_counts() -> dict[str, int]:
    return {"queries": 0, "responses": 0, "nxdomain": 0, "servfail": 0, "all": 0}


def _empty_icmp_counts() -> dict[str, int]:
    return {"unreachable": 0, "ttl_exceeded": 0, "frag_needed": 0, "all": 0}


def _empty_infra_counts() -> dict[str, int]:
    return {name: 0 for name in INFRA_PROTOCOLS}


def _int_field(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _is_dns_response(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes")


def _protocol_tokens(protocols: str) -> str:
    return f":{protocols.lower()}:"


def _has_protocol(protocols: str, needle: str) -> bool:
    return f":{needle.lower()}:" in _protocol_tokens(protocols)


def accumulate_dns_counts(
    counts: dict[str, int], *, response: str, rcode: str, protocols: str
) -> None:
    if not (
        _has_protocol(protocols, "dns")
        or response.strip()
        or rcode.strip()
    ):
        return
    counts["all"] += 1
    if _is_dns_response(response):
        counts["responses"] += 1
    else:
        counts["queries"] += 1
    rc = _int_field(rcode)
    if rc == 3:
        counts["nxdomain"] += 1
    elif rc == 2:
        counts["servfail"] += 1


def accumulate_icmp_counts(
    counts: dict[str, int],
    *,
    icmp_type: str,
    icmp_code: str,
    icmpv6_type: str,
    icmpv6_code: str,
    protocols: str,
) -> None:
    it = _int_field(icmp_type)
    ic = _int_field(icmp_code)
    i6t = _int_field(icmpv6_type)
    i6c = _int_field(icmpv6_code)
    if not (
        _has_protocol(protocols, "icmp")
        or _has_protocol(protocols, "icmpv6")
        or it is not None
        or i6t is not None
    ):
        return
    counts["all"] += 1
    if it == 3 or i6t == 1:
        counts["unreachable"] += 1
    if it == 11 or i6t == 3:
        counts["ttl_exceeded"] += 1
    if (it == 3 and ic == 4) or (i6t == 1 and i6c == 4):
        counts["frag_needed"] += 1


def accumulate_infra_counts(counts: dict[str, int], protocols: str) -> None:
    if not protocols.strip():
        return
    tokens = _protocol_tokens(protocols)
    for name, needle in INFRA_PROTOCOLS.items():
        if f":{needle.lower()}:" in tokens:
            counts[name] += 1


def parse_l3_triage_rows(rows: list[dict[str, str]]) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    dns = _empty_dns_counts()
    icmp = _empty_icmp_counts()
    infra = _empty_infra_counts()
    for row in rows:
        protocols = row.get("frame.protocols", "")
        accumulate_dns_counts(
            dns,
            response=row.get("dns.flags.response", ""),
            rcode=row.get("dns.flags.rcode", ""),
            protocols=protocols,
        )
        accumulate_icmp_counts(
            icmp,
            icmp_type=row.get("icmp.type", ""),
            icmp_code=row.get("icmp.code", ""),
            icmpv6_type=row.get("icmpv6.type", ""),
            icmpv6_code=row.get("icmpv6.code", ""),
            protocols=protocols,
        )
        accumulate_infra_counts(infra, protocols)
    return dns, icmp, infra


async def _l3_triage_counts(
    runner: TsharkRunner,
    path: Path,
    *,
    display_filter: str | None = None,
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    """Single-pass DNS, ICMP, and infrastructure counts."""
    rows = await extract_field_rows(
        runner, path, _L3_TRIAGE_FIELDS, display_filter=display_filter
    )
    return parse_l3_triage_rows(rows)


async def _dns_counts(runner: TsharkRunner, path: Path, base: str | None = None) -> dict[str, int]:
    filt = f"dns and ({base})" if base else "dns"
    rows = await extract_field_rows(
        runner,
        path,
        ["frame.protocols", "dns.flags.response", "dns.flags.rcode"],
        display_filter=filt,
    )
    counts = _empty_dns_counts()
    for row in rows:
        accumulate_dns_counts(
            counts,
            response=row.get("dns.flags.response", ""),
            rcode=row.get("dns.flags.rcode", ""),
            protocols=row.get("frame.protocols", ""),
        )
    return counts


async def _icmp_counts(runner: TsharkRunner, path: Path) -> dict[str, int]:
    _, icmp, _ = await _l3_triage_counts(runner, path)
    return icmp


async def _infra_counts(runner: TsharkRunner, path: Path) -> dict[str, int]:
    _, _, infra = await _l3_triage_counts(runner, path)
    return infra


async def _wired_l3_bundle(
    runner: TsharkRunner, path: Path
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    return await _l3_triage_counts(runner, path)


async def _vlan_summary(runner: TsharkRunner, path: Path, limit: int = 15) -> list[dict[str, Any]]:
    values = await extract_field_values(runner, path, "vlan.id", display_filter="vlan")
    counter = Counter(values)
    return [{"vlan_id": vid, "frames": n} for vid, n in counter.most_common(limit)]


def _dhcp_stuck_pattern(counts: dict[str, int]) -> list[str]:
    patterns: list[str] = []
    if counts.get("discover", 0) > 0 and counts.get("offer", 0) > 0:
        if counts.get("request", 0) == 0 and counts.get("ack", 0) == 0:
            patterns.append("discover_offer_no_request_ack — client may not accept offered lease")
    if counts.get("request", 0) > 0 and counts.get("ack", 0) == 0:
        patterns.append("request_no_ack — server may reject or unicast ACK not visible on SPAN")
    if counts.get("nak", 0) > 0:
        patterns.append("dhcp_nak_present — check pool, relay, or option mismatch")
    return patterns


def _wired_recommendations(data: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    dhcp = data.get("dhcp", {})
    if _dhcp_stuck_pattern(dhcp):
        recs.append("pm_dhcp_analysis for transaction detail")
    dns = data.get("dns", {})
    if dns.get("nxdomain", 0) > 0 or dns.get("servfail", 0) > 0:
        recs.append("pm_dns_analysis for failing query names")
    icmp = data.get("icmp", {})
    if icmp.get("unreachable", 0) > 0 or icmp.get("frag_needed", 0) > 0:
        recs.append("pm_filter_packets with icmp.type == 3 or icmp.type == 11")
    hints = data.get("asymmetric_hints", {})
    if hints.get("syn_without_ack", 0) > 0 or hints.get("lost_segment", 0) > 0:
        recs.append("pm_asymmetric_hints — capture may be one-sided; mirror other path")
    tcp = data.get("tcp_anomalies", {}).get("counts", {})
    if tcp.get("retransmission", 0) > 0:
        recs.append("pm_troubleshoot_flow on top TCP conversation")
    infra = data.get("infrastructure", {})
    if any(infra.get(k, 0) > 0 for k in ("stp", "cdp", "lldp")):
        recs.append("pm_filter_packets with stp or cdp or lldp for L2 control plane")
    if not recs:
        recs.append("pm_troubleshoot_flow if a specific host pair is suspect")
    return recs


async def asymmetric_hints(
    runner: TsharkRunner, file_path: str,
    *,
    display_filter: str | None = None,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
        base = validate_display_filter(display_filter)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    hints = await batch_asymmetric_hints(runner, path, display_filter=base)

    notes: list[str] = []
    if hints["syn_without_ack"] > 0:
        notes.append("SYNs without SYN-ACK visible — asymmetric capture or firewall drop")
    if hints["lost_segment"] > 0 or hints["ack_lost_segment"] > 0:
        notes.append("TCP gap detected — mid-stream capture start or packet loss")
    if hints["multi_ip_addr_frames"] > 0:
        notes.append("ICMP errors or tunnels present (count(ip.addr) > 2)")

    return ToolResponse.success(
        hints=hints,
        notes=notes,
        applied_filter=base,
        recommendation="Capture both directions on the path if hints are elevated.",
    )


async def dhcp_analysis(
    runner: TsharkRunner,
    file_path: str,
    *,
    mac_address: str | None = None,
    sample_limit: int = 10,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
        mac_filter: str | None = None
        if mac_address:
            mac = normalize_mac(mac_address)
            mac_filter = f"eth.addr == {mac} or bootp.hw.mac_addr == {mac}"
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    _, err = await _require_ethernet(runner, path)
    if err:
        return err

    counts = await _dhcp_counts(runner, path, mac_filter)
    patterns = _dhcp_stuck_pattern(counts)

    filt = f"bootp and ({mac_filter})" if mac_filter else "bootp"
    samples = await sample_fields(
        runner,
        path,
        [
            "frame.time_relative",
            "bootp.option.dhcp",
            "bootp.hw.mac_addr",
            "bootp.ip.client",
            "bootp.ip.your",
            "bootp.option.hostname",
            "bootp.option.dhcp_server_id",
        ],
        filt,
        limit=sample_limit,
    )

    return ToolResponse.success(
        mac_filter=mac_filter,
        counts=counts,
        stuck_patterns=patterns,
        samples=samples,
        note="Missing ACK on SPAN may mean unicast DHCP reply not mirrored to capture port.",
    )


async def dns_analysis(
    runner: TsharkRunner,
    file_path: str,
    *,
    ip_address: str | None = None,
    sample_limit: int = 15,
) -> ToolResponse:
    try:
        path = validate_pcap_path(file_path)
        ip_filter: str | None = None
        if ip_address:
            validate_ip_address(ip_address)
            ip_filter = ip_filter_literal(ip_address)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    _, err = await _require_ethernet(runner, path)
    if err:
        return err

    counts = await _dns_counts(runner, path, ip_filter)

    name_filter = "dns.qry.name"
    if ip_filter:
        name_filter = f"dns and ({ip_filter})"
    names = await extract_field_values(
        runner, path, "dns.qry.name", display_filter=name_filter, limit=10000
    )
    top_queries = [{"name": n, "count": c} for n, c in Counter(names).most_common(15)]

    fail_filt = "dns.flags.rcode != 0"
    if ip_filter:
        fail_filt = f"({fail_filt}) and ({ip_filter})"
    failures = await sample_fields(
        runner,
        path,
        ["frame.time_relative", "dns.qry.name", "dns.flags.rcode", "ip.src", "ip.dst"],
        fail_filt,
        limit=sample_limit,
    )

    return ToolResponse.success(
        ip_filter=ip_filter,
        counts=counts,
        top_query_names=top_queries,
        failure_samples=failures,
    )


async def wired_quick_scan(
    runner: TsharkRunner,
    file_path: str,
    *,
    compute_hash: bool = False,
) -> ToolResponse:
    """Composite wired/EPC triage."""
    try:
        path = validate_pcap_path(file_path)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        return ToolResponse.failure("VALIDATION_ERROR", str(e))

    capture_meta, err = await _require_ethernet(runner, path)
    if err:
        return err

    warnings: list[str] = []
    data: dict[str, Any] = {"capture": capture_meta}

    info = await file_ops.file_info(runner, file_path, compute_hash=compute_hash)
    if info.ok:
        data["file_info"] = info.data

    data["dhcp"] = await _dhcp_counts(runner, path)
    data["dhcp_stuck_patterns"] = _dhcp_stuck_pattern(data["dhcp"])
    data["dns"], data["icmp"], data["infrastructure"] = await _wired_l3_bundle(runner, path)
    data["vlan_summary"] = await _vlan_summary(runner, path)

    noise = await count_filter(runner, path, NOISE_FILTER)
    total_ip = await count_filter(runner, path, "ip")
    data["noise"] = {
        "noise_packets": noise,
        "ip_packets": total_ip,
        "noise_pct_of_ip": round((noise / total_ip) * 100, 2) if total_ip else 0,
    }

    anomalies = await tcp_analysis.tcp_anomalies(runner, file_path, sample_limit=3)
    if anomalies.ok:
        data["tcp_anomalies"] = anomalies.data

    hierarchy, conv, expert = await statistics.triage_stats_bundle(runner, path)
    if hierarchy.ok:
        data["protocol_hierarchy"] = hierarchy.data
    if conv.ok:
        data["conversations"] = conv.data
    if expert.ok:
        data["expert"] = expert.data

    asym = await asymmetric_hints(runner, file_path)
    if asym.ok:
        data["asymmetric_hints"] = asym.data.get("hints", {})
        if asym.data.get("notes"):
            warnings.extend(asym.data["notes"])

    data["recommended_next_tools"] = _wired_recommendations(data)
    resp = ToolResponse.success(**data)
    resp.warnings = warnings
    return resp
