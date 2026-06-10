"""Unit tests for single-pass batch tally helpers."""

from mcp_server.tools.batch_counts import (
    tally_asymmetric_hints,
    tally_tcp_anomalies,
    tally_wifi_roam_counts,
    tally_wifi_scan,
)
from mcp_server.tools.wifi_analysis import (
    WLAN_MGMT,
    WLAN_ROAMING_ACTION_CODE_INT,
)


def test_tally_asymmetric_hints_syn_and_rst():
    rows = [
        {
            "tcp.flags.syn": "True",
            "tcp.flags.ack": "False",
            "tcp.flags.reset": "",
            "tcp.analysis.lost_segment": "",
            "tcp.analysis.ack_lost_segment": "",
            "ip.addr": "10.0.0.1,10.0.0.2",
        },
        {
            "tcp.flags.syn": "",
            "tcp.flags.ack": "",
            "tcp.flags.reset": "1",
            "tcp.analysis.lost_segment": "",
            "tcp.analysis.ack_lost_segment": "",
            "ip.addr": "10.0.0.1",
        },
    ]
    counts = tally_asymmetric_hints(rows)
    assert counts["syn_without_ack"] == 1
    assert counts["connection_rst"] == 1
    assert counts["multi_ip_addr_frames"] == 0


def test_tally_asymmetric_multi_ip():
    rows = [{"ip.addr": "10.0.0.1,10.0.0.2,10.0.0.3", "tcp.flags.syn": "", "tcp.flags.ack": "", "tcp.flags.reset": "", "tcp.analysis.lost_segment": "", "tcp.analysis.ack_lost_segment": ""}]
    counts = tally_asymmetric_hints(rows)
    assert counts["multi_ip_addr_frames"] == 1


def test_tally_wifi_scan_retries_and_mgmt():
    rows = [
        {
            "frame.protocols": "wlan:radiotap:wlan",
            "wlan.fc.retry": "1",
            "wlan.fc.tods": "1",
            "wlan.fc.fromds": "0",
            "wlan.fc.type_subtype": "12",
            "wlan.fixed.action_code": "",
            "radiotap.dbm_antsignal": "-80",
        },
    ]
    out = tally_wifi_scan(
        rows,
        mgmt_subtypes=WLAN_MGMT,
        roaming_action_codes=WLAN_ROAMING_ACTION_CODE_INT,
        rssi_threshold=-75,
    )
    assert out["wlan_frames"] == 1
    assert out["retries"]["retry_all"] == 1
    assert out["retries"]["retry_to_ap"] == 1
    assert out["management"]["deauthentication"] == 1
    assert out["low_rssi_frames"] == 1


def test_tally_wifi_roam_counts():
    rows = [
        {"wlan.fc.type_subtype": "2", "wlan.fixed.action_code": ""},
        {"wlan.fc.type_subtype": "", "wlan.fixed.action_code": "4"},
    ]
    counts = tally_wifi_roam_counts(
        rows,
        mgmt_subtypes=WLAN_MGMT,
        roaming_action_codes=WLAN_ROAMING_ACTION_CODE_INT,
    )
    assert counts["reassociation_request"] == 1
    assert counts["neighbor_request"] == 1


def test_tally_tcp_anomalies():
    rows = [
        {
            "tcp.analysis.retransmission": "1",
            "tcp.analysis.fast_retransmission": "",
            "tcp.analysis.duplicate_ack": "",
            "tcp.analysis.zero_window": "",
            "tcp.analysis.window_full": "",
            "tcp.analysis.out_of_order": "",
            "tcp.flags.reset": "",
        },
    ]
    counts = tally_tcp_anomalies(rows)
    assert counts["retransmission"] == 1
    assert counts["connection_rst"] == 0
