"""Unit tests for single-pass DNS/ICMP/infra triage parsing."""

from mcp_server.tools.wired_analysis import (
    _empty_dns_counts,
    _empty_icmp_counts,
    _empty_infra_counts,
    accumulate_dns_counts,
    accumulate_icmp_counts,
    accumulate_infra_counts,
    parse_l3_triage_rows,
)


def test_dns_query_and_response_counts():
    counts = _empty_dns_counts()
    accumulate_dns_counts(
        counts,
        response="False",
        rcode="0",
        protocols="eth:ethertype:ip:udp:dns",
    )
    accumulate_dns_counts(
        counts,
        response="True",
        rcode="0",
        protocols="eth:ethertype:ip:udp:dns",
    )
    assert counts == {"queries": 1, "responses": 1, "nxdomain": 0, "servfail": 0, "all": 2}


def test_dns_nxdomain_and_servfail():
    counts = _empty_dns_counts()
    accumulate_dns_counts(
        counts, response="True", rcode="3", protocols="eth:ip:udp:dns"
    )
    accumulate_dns_counts(
        counts, response="True", rcode="2", protocols="eth:ip:udp:dns"
    )
    assert counts["nxdomain"] == 1
    assert counts["servfail"] == 1
    assert counts["all"] == 2


def test_icmp_unreachable_and_ttl():
    counts = _empty_icmp_counts()
    accumulate_icmp_counts(
        counts,
        icmp_type="3",
        icmp_code="0",
        icmpv6_type="",
        icmpv6_code="",
        protocols="eth:ip:icmp",
    )
    accumulate_icmp_counts(
        counts,
        icmp_type="11",
        icmp_code="0",
        icmpv6_type="",
        icmpv6_code="",
        protocols="eth:ip:icmp",
    )
    assert counts["unreachable"] == 1
    assert counts["ttl_exceeded"] == 1
    assert counts["all"] == 2


def test_icmp_frag_needed_icmpv6():
    counts = _empty_icmp_counts()
    accumulate_icmp_counts(
        counts,
        icmp_type="",
        icmp_code="",
        icmpv6_type="1",
        icmpv6_code="4",
        protocols="eth:ipv6:icmpv6",
    )
    assert counts["frag_needed"] == 1
    assert counts["unreachable"] == 1


def test_infra_protocol_presence():
    counts = _empty_infra_counts()
    accumulate_infra_counts(counts, "eth:ethertype:stp")
    accumulate_infra_counts(counts, "eth:ethertype:cdp:cdp")
    assert counts["stp"] == 1
    assert counts["cdp"] == 1
    assert counts["lldp"] == 0


def test_parse_l3_triage_rows_combined():
    rows = [
        {
            "frame.protocols": "eth:ip:udp:dns",
            "dns.flags.response": "False",
            "dns.flags.rcode": "0",
            "icmp.type": "",
            "icmp.code": "",
            "icmpv6.type": "",
            "icmpv6.code": "",
        },
        {
            "frame.protocols": "eth:ip:icmp",
            "dns.flags.response": "",
            "dns.flags.rcode": "",
            "icmp.type": "3",
            "icmp.code": "4",
            "icmpv6.type": "",
            "icmpv6.code": "",
        },
        {
            "frame.protocols": "eth:ethertype:lldp",
            "dns.flags.response": "",
            "dns.flags.rcode": "",
            "icmp.type": "",
            "icmp.code": "",
            "icmpv6.type": "",
            "icmpv6.code": "",
        },
    ]
    dns, icmp, infra = parse_l3_triage_rows(rows)
    assert dns["queries"] == 1
    assert icmp["frag_needed"] == 1
    assert infra["lldp"] == 1
