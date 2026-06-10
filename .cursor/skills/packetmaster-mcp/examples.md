# PacketMaster MCP — Example Sequences

Concrete argument patterns for agents. Replace paths, IPs, and MACs with values from the user's capture.

---

## 1. New session smoke test

```json
// pm_check_install — no arguments
{}
```

Expected: `ok: true`, non-null `tshark_path`.

---

## 2. Standard wired/EPC triage

```json
// Step 1: pm_detect_capture_type
{ "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng" }

// Step 2 (if capture_type == "ethernet_l3"): pm_wired_quick_scan
{ "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng" }
```

Review `data.expert`, `data.tcp_anomalies.counts`, `data.dhcp_stuck_patterns`, `data.recommended_next_tools`.

---

## 3. DHCP failure on new device

After wired quick scan shows DHCP stuck patterns:

```json
// pm_dhcp_analysis
{
  "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "sample_limit": 15
}
```

Look at `stuck_patterns` and `samples` for discover/offer/request/ack sequence.

---

## 4. DNS resolution failure

```json
// pm_dns_analysis
{
  "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng",
  "ip_address": "10.0.0.50",
  "sample_limit": 20
}
```

Check `counts.nxdomain`, `counts.servfail`, `failure_samples`, `top_queries`.

---

## 5. TCP retransmissions between two hosts

From `data.conversations` in quick scan, pick suspect IPs:

```json
// pm_troubleshoot_flow
{
  "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng",
  "ip_a": "10.0.0.50",
  "ip_b": "10.0.0.1",
  "port": 443
}
```

Then if needed:

```json
// pm_latency_summary
{
  "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng",
  "display_filter": "ip.addr == 10.0.0.50 and ip.addr == 10.0.0.1 and tcp.port == 443",
  "limit": 10
}
```

---

## 6. One-sided capture suspicion

```json
// pm_asymmetric_hints
{
  "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng"
}
```

Elevated `syn_without_ack` or `lost_segment` → recommend dual-sided capture in report.

---

## 7. Wi-Fi monitor capture

```json
// pm_detect_capture_type → capture_type: "wlan_monitor"

// pm_wifi_quick_scan
{
  "file_path": "/Users/analyst/captures/roam-test.pcapng",
  "rssi_threshold": -70
}
```

Pick top STA from retries or `top_bssids`:

```json
// pm_wifi_client_analysis
{
  "file_path": "/Users/analyst/captures/roam-test.pcapng",
  "wlan_addr": "11:22:33:44:55:66",
  "sample_limit": 10
}
```

If roaming frames present:

```json
// pm_wifi_roaming_analysis
{
  "file_path": "/Users/analyst/captures/roam-test.pcapng",
  "wlan_addr": "11:22:33:44:55:66",
  "sample_limit": 25
}
```

---

## 8. Targeted packet list (RST storm)

```json
// pm_filter_packets
{
  "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng",
  "display_filter": "tcp.flags.reset == 1",
  "offset": 0,
  "limit": 30
}
```

Paginate with `offset: 30`, `limit: 30` if `has_more` (via pm_extract_fields) or repeat with higher offset.

---

## 9. Custom field extraction

```json
// pm_extract_fields
{
  "file_path": "/Users/analyst/captures/site-sw1-ge0-1-20250610.pcapng",
  "fields": [
    "frame.number",
    "frame.time_relative",
    "tcp.analysis.ack_rtt",
    "ip.src",
    "ip.dst"
  ],
  "display_filter": "tcp.analysis.ack_rtt > 0.1",
  "offset": 0,
  "limit": 50
}
```

Use `has_more: true` → next page with `"offset": 50`.

---

## 10. Stream follow (with user consent)

Only after user confirms:

```json
// pm_follow_stream
{
  "file_path": "/Users/analyst/captures/http-debug.pcapng",
  "stream_type": "http",
  "stream_index": 0,
  "max_bytes": 4096,
  "redact": true
}
```

Never paste raw credentials from `payload` into chat.

---

## 11. NetOps EPC integration

External MCP returns:

```json
{ "local_path": "/tmp/epc-dump-20250610.pcapng", "device": "SW1", "interface": "Gi0/1" }
```

Agent sequence:

1. Verify file exists (shell `test -f` or `pm_file_info`)
2. `pm_detect_capture_type(local_path)`
3. `pm_wired_quick_scan(local_path)`
4. Follow `recommended_next_tools`
5. Report includes device/interface metadata from EPC handoff

---

## 12. Handling failures

**Relative path rejected:**

```json
// BAD
{ "file_path": "./captures/file.pcap" }

// GOOD
{ "file_path": "/Users/analyst/project/captures/file.pcap" }
```

**Wrong tool class:**

```json
// Response: error.code == "WLAN_CAPTURE"
// Fix: switch to pm_wifi_quick_scan
```

**Sandbox violation (when PM_ALLOWED_DIRS set):**

```json
// error.message: "Path outside PM_ALLOWED_DIRS"
// Fix: copy PCAP into allowed dir or update env in mcp.json
```

---

## 13. Cursor CallMcpTool pattern

```
server: packetmaster
toolName: pm_wired_quick_scan
arguments: {
  "file_path": "/absolute/path/capture.pcapng"
}
```

Parse `result` string as JSON → check `ok` → read `data` → honor `warnings` and `data.recommended_next_tools`.

---

## 14. Anti-patterns

| Bad | Good |
|-----|------|
| Shell: `tshark -r file.pcap -Y ...` | `pm_filter_packets` or `pm_extract_fields` |
| Parallel: 5× `pm_conversations` + `pm_expert_info` + … | One `pm_wired_quick_scan` |
| `pm_wifi_quick_scan` on EPC capture | `pm_wired_quick_scan` (no 802.11 in SPAN) |
| `pm_follow_stream` without asking user | Ask consent first |
| Relative `./capture.pcap` | Absolute path always |
