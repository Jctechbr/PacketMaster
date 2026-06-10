# PacketMaster MCP — Tool Catalog

All tools are **async**, return a **JSON string**, and use the [response envelope](SKILL.md#response-envelope-all-tools). Unless noted, the only required argument is `file_path` (absolute path to `.pcap` or `.pcapng`).

---

## pm_check_install

**Purpose:** Verify tshark/capinfos availability before analysis.

**Parameters:** none

**Returns (`data`):**

| Key | Type | Description |
|-----|------|-------------|
| `tshark_path` | string | Resolved binary path |
| `capinfos_path` | string \| null | capinfos path |
| `editcap_path` | string \| null | editcap path |
| `tshark_version` | string | First line of `tshark -v` |
| `tcp_analysis_enforced` | array | Always enables `tcp.analyze_sequence_numbers:TRUE` |
| `allowed_dirs` | string[] | Active sandbox roots |
| `require_allowed_dirs` | bool | Whether sandbox is mandatory |

**Errors:** `TSHARK_NOT_FOUND`

**Example:**

```json
{}
```

---

## pm_file_info

**Purpose:** File metadata + capinfos summary + optional SHA-256.

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `file_path` | string | required | Absolute PCAP path |
| `compute_hash` | bool | false | SHA-256 (skipped if file > `PM_HASH_MAX_BYTES`) |

**Returns (`data`):**

| Key | Type | Description |
|-----|------|-------------|
| `path` | string | Resolved absolute path |
| `size_bytes` | int | File size |
| `modified_utc` | string | ISO timestamp |
| `sha256` | string \| null | Hash if computed |
| `hash_status` | string | `not_requested`, `computed`, or `skipped_large_file` |
| `capinfos` | object | Parsed capinfos key/value pairs |
| `warnings` | string[] | e.g. capinfos unavailable |

---

## pm_detect_capture_type

**Purpose:** **Start here** — classify capture and recommend entry tool.

**Parameters:** `file_path`

**Returns (`data`):**

| Key | Type | Description |
|-----|------|-------------|
| `capture_type` | string | `ethernet_l3` or `wlan_monitor` |
| `recommended_entrypoint` | string | `pm_wired_quick_scan` or `pm_wifi_quick_scan` |
| `message` | string | Human routing hint |
| `frame_counts` | object | Counts: wlan, vlan, tcp, udp, dhcp, dns, icmp |
| `also_consider` | string[] | e.g. `pm_dhcp_analysis`, `pm_asymmetric_hints` |

---

## pm_wired_quick_scan

**Purpose:** Primary triage for EPC, SPAN, tap, Ethernet L3 captures.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `compute_hash` | bool | false |

**Returns (`data`):** Composite object including:

| Key | Description |
|-----|-------------|
| `capture` | Output from detect_capture_type |
| `file_info` | capinfos metadata |
| `dhcp` | Message-type counts: discover, offer, request, ack, nak, … |
| `dhcp_stuck_patterns` | Heuristic strings (e.g. discover_offer_no_request_ack) |
| `dns` | queries, responses, nxdomain, servfail, all |
| `icmp` | unreachable, ttl_exceeded, frag_needed, all |
| `infrastructure` | stp, cdp, lldp, hsrp, vrrp, igmp, eapol, eap counts |
| `vlan_summary` | Top VLAN IDs by frame count |
| `noise` | ARP/DHCP/mDNS noise vs IP traffic percentage |
| `tcp_anomalies` | counts + samples |
| `protocol_hierarchy` | Protocol tree |
| `conversations` | Top IP conversations |
| `expert` | Wireshark expert info |
| `asymmetric_hints` | syn_without_ack, lost_segment, ack_lost_segment, multi_ip_addr_frames |
| `recommended_next_tools` | Suggested follow-up tool names |

**Errors:** `WLAN_CAPTURE` if 802.11 frames present — use Wi-Fi tools instead.

---

## pm_wifi_quick_scan

**Purpose:** Primary triage for 802.11 monitor-mode captures.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `rssi_threshold` | int | -75 | Frames below this dBm counted as low RSSI |

**Returns (`data`):**

| Key | Description |
|-----|-------------|
| `capture` | wlan_monitor metadata |
| `file_info` | capinfos |
| `retries` | retry_all, retry_tods, retry_fromds |
| `management` | association, reassociation, deauth, disassoc, beacon, … |
| `security` | eapol, eap counts |
| `roaming` | neighbor_request/response, bss_transition_query/request |
| `low_rssi_frames` | Count below threshold |
| `retry_rate_pct` | Retries / total WLAN frames |
| `top_bssids` | Top BSSIDs by frame count |
| `recommended_next_tools` | Follow-up suggestions |

**Errors:** `NOT_WLAN_CAPTURE` on Ethernet-only captures.

---

## pm_troubleshoot_quick_scan

**Purpose:** L3-focused composite (lighter than wired scan). Good alternate when DHCP/DNS/VLAN detail is not needed.

**Parameters:** `file_path`, `compute_hash` (default false)

**Returns (`data`):** `file_info`, `expert`, `conversations`, `tcp_anomalies`, `protocol_hierarchy`, `recommended_next_tools`

**Warnings:** Large capture (>1M packets) suggests editcap trim.

---

## pm_troubleshoot_flow

**Purpose:** Deep dive on traffic between two IP endpoints.

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `file_path` | string | required | |
| `ip_a` | string | required | IPv4 or IPv6 |
| `ip_b` | string | required | IPv4 or IPv6 |
| `port` | int \| null | null | Optional TCP/UDP port filter |

**Returns (`data`):** `flow_filter`, `ip_a`, `ip_b`, `port`, `tcp_anomalies`, `latency`, `matching_conversations`, `io_stats`

---

## pm_dhcp_analysis

**Purpose:** DHCP transaction detail and stuck-pattern detection.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `mac_address` | string \| null | null | Filter to STA MAC |
| `sample_limit` | int | 10 |

**Returns (`data`):** `mac_filter`, `counts`, `stuck_patterns`, `samples` (time, msg type, MAC, IPs, hostname), `note`

**Errors:** `WLAN_CAPTURE`

---

## pm_dns_analysis

**Purpose:** DNS query/response breakdown and failure samples.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `ip_address` | string \| null | null | Filter to client IP |
| `sample_limit` | int | 15 |

**Returns (`data`):** `ip_filter`, `counts`, `top_queries`, `failure_samples`, `note`

**Errors:** `WLAN_CAPTURE`

---

## pm_asymmetric_hints

**Purpose:** Detect one-sided capture symptoms.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `display_filter` | string \| null | null |

**Returns (`data`):**

| Key | Description |
|-----|-------------|
| `hints` | syn_without_ack, lost_segment, ack_lost_segment, multi_ip_addr_frames |
| `notes` | Interpretive strings |
| `recommendation` | Capture both directions if elevated |

---

## pm_wifi_client_analysis

**Purpose:** Deep dive on one STA by MAC (`wlan.addr`, bidirectional).

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `wlan_addr` | string | required | MAC (aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff) |
| `sample_limit` | int | 5 |

**Returns (`data`):** `wlan_addr`, `client_filter`, `retries`, `management`, `security`, `roaming`, `event_samples`, `recommended_next_tools`

**Errors:** `NOT_WLAN_CAPTURE`, `VALIDATION_ERROR` (bad MAC)

---

## pm_wifi_roaming_analysis

**Purpose:** 802.11k/v roaming timeline for one STA.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `wlan_addr` | string | required |
| `sample_limit` | int | 20 |

**Returns (`data`):** `wlan_addr`, `roam_counts`, `timeline`, `sticky_client_suspected`, `note`

---

## pm_protocol_hierarchy

**Purpose:** Protocol distribution (`tshark -z io,phs`).

**Parameters:** `file_path`

**Returns (`data`):** `protocols` (tree rows), `raw_excerpt`

---

## pm_conversations

**Purpose:** Top conversations by bytes.

**Parameters:**

| Name | Type | Default | Values |
|------|------|---------|--------|
| `file_path` | string | required | |
| `conv_type` | string | `"ip"` | `ip`, `tcp`, `udp` |
| `limit` | int | 20 | |

**Returns (`data`):** `conversations`, `conv_type`

---

## pm_endpoints

**Purpose:** Top IP endpoints by traffic.

**Parameters:** `file_path`, `limit` (default 20)

**Returns (`data`):** `endpoints`

---

## pm_expert_info

**Purpose:** Wireshark expert information.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `severity` | string \| null | null | `error`, `warn`, `note`, `chat` |

**Returns (`data`):** `expert` (grouped by severity), `raw_excerpt`

---

## pm_tcp_anomalies

**Purpose:** Count and sample TCP problems.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `display_filter` | string \| null | null |
| `sample_limit` | int | 5 |

**Returns (`data`):**

| Key | Description |
|-----|-------------|
| `counts` | retransmission, fast_retransmission, duplicate_ack, zero_window, window_full, out_of_order, connection_rst |
| `samples` | Per-anomaly sample rows (time, IPs, ports, flags) |
| `total_anomaly_packets` | Sum of counts |
| `tcp_analysis_enabled` | Whether tcp.analysis fields populated |
| `applied_filter` | Filter used |

---

## pm_latency_summary

**Purpose:** Per-flow RTT from `tcp.analysis.ack_rtt`.

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `display_filter` | string \| null | null |
| `limit` | int | 20 |

**Returns (`data`):** `flows[]` with `flow`, `sample_count`, `rtt_min`, `rtt_max`, `rtt_avg`, `initial_rtt`; sorted by max RTT desc.

---

## pm_io_stats

**Purpose:** Traffic volume over time buckets.

**Parameters:**

| Name | Type | Default | Range |
|------|------|---------|-------|
| `file_path` | string | required | |
| `interval_seconds` | int | 1 | 1–3600 |

**Returns (`data`):** `interval_seconds`, `intervals[]`

---

## pm_extract_fields

**Purpose:** Paginated extraction of arbitrary tshark fields.

**Parameters:**

| Name | Type | Default | Constraints |
|------|------|---------|-------------|
| `file_path` | string | required | |
| `fields` | string[] | required | Max 20 field names |
| `display_filter` | string \| null | null | Max 512 chars |
| `offset` | int | 0 | |
| `limit` | int | 100 | Max `PM_MAX_PACKETS` |

**Returns (`data`):** `fields`, `rows[]`, `offset`, `limit`, `returned`, `has_more`, `applied_filter`

**Notes:** Values redacted when `PM_REDACT_SENSITIVE=true`.

---

## pm_filter_packets

**Purpose:** Packet summaries for a display filter (wrapper over extract_fields).

**Parameters:**

| Name | Type | Default |
|------|------|---------|
| `file_path` | string | required |
| `display_filter` | string | required |
| `offset` | int | 0 |
| `limit` | int | 50 |

**Default fields:** frame.number, frame.time_relative, ip.src, ip.dst, frame.protocols, frame.len, _ws.col.Info

---

## pm_follow_stream

**Purpose:** Follow TCP/UDP/HTTP/TLS stream (ASCII, truncated).

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `file_path` | string | required | |
| `stream_type` | string | `"tcp"` | `tcp`, `udp`, `http`, `tls` |
| `stream_index` | int | 0 | Stream index |
| `max_bytes` | int | 8192 | 256 – PM_MAX_STDOUT_BYTES |
| `redact` | bool | true | Override `PM_REDACT_SENSITIVE` |

**Returns (`data`):** `stream_type`, `stream_index`, `payload`, `truncated`, `redacted`, `warning`

**Requires user consent** on production captures.

---

## Error Code Reference

| Code | HTTP-like severity | Typical message fragment |
|------|-------------------|--------------------------|
| `VALIDATION_ERROR` | Client error | "must be an absolute path", "Invalid MAC", "Display filter" |
| `TSHARK_NOT_FOUND` | Config error | "tshark not found" |
| `TSHARK_ERROR` | Server/runtime | tshark stderr excerpt |
| `WLAN_CAPTURE` | Wrong tool class | "Use pm_wifi_quick_scan instead" |
| `NOT_WLAN_CAPTURE` | Wrong tool class | "No 802.11 frames found" |

Subprocess **timeouts** surface as tool exceptions (not always wrapped in ToolResponse) — increase `PM_TIMEOUT` or trim PCAP.

---

## Internal Optimizations (for agent planning)

Agents do not call these directly, but understanding them explains latency:

| Composite tool | Batched work |
|----------------|--------------|
| `pm_wired_quick_scan` | `triage_stats_bundle` (phs + conv,ip + expert in one tshark), batch asymmetric hints, batch TCP anomalies |
| `pm_wifi_quick_scan` | `batch_wifi_scan_metrics` single pass |
| `pm_tcp_anomalies` | `batch_tcp_anomaly_counts` single pass |
| All tshark calls | Serialized via semaphore (one at a time) |

**Implication:** Calling `pm_protocol_hierarchy`, `pm_conversations`, and `pm_expert_info` separately after a quick scan **re-reads the PCAP three extra times** — avoid unless you need only one slice.
