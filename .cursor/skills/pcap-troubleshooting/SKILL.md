---
name: pcap-troubleshooting
description: >-
  Perform network-troubleshooting PCAP analysis using PacketMaster MCP tools.
  Use when the user mentions PCAP/PCAPNG files, Wireshark, tshark, packet
  captures, latency, retransmissions, TCP issues, Wi-Fi/802.11, WLAN retries,
  deauth, roaming, or Catalyst EPC captures.
---

# PCAP Troubleshooting

For **MCP setup, tool parameters, response parsing, and efficiency patterns**, use the companion skill [packetmaster-mcp](../packetmaster-mcp/SKILL.md). This skill covers **what to look for** in captures and how to report findings.

## When to Use

- Analyzing `.pcap` / `.pcapng` files for latency, drops, retransmissions, or protocol errors
- Triage after `ios_xe_epc_capture_run` from user-netops MCP
- Network troubleshooting workflows (not IR/malware forensics unless user requests)

## Prerequisites

- PacketMaster MCP configured in Cursor
- Wireshark installed (`tshark`, `capinfos` on PATH)
- PCAP at an absolute path (any location unless `PM_ALLOWED_DIRS` sandbox is enabled)

## Workflow

### 1. Verify toolchain

Call `pm_check_install`. If tshark is missing, instruct user to install Wireshark.

### 2. Validate handoff (EPC captures)

When PCAP comes from `ios_xe_epc_capture_run`:

1. Confirm `local_path` exists and size > 0
2. Record metadata: device, interface, ACL, duration, timezone
3. Pass absolute path to PacketMaster tools

### 3. Quick triage (default start)

1. **`pm_detect_capture_type`** — routes to the right workflow
2. **Ethernet/EPC captures:** `pm_wired_quick_scan` (DHCP, DNS, ICMP, VLAN, L2 infra + TCP)
3. **802.11 monitor-mode captures:** `pm_wifi_quick_scan`
4. Legacy/alternate L3-only: `pm_troubleshoot_quick_scan`

Review in order:

1. **file_info** — packet count, duration, file size
2. **expert** — errors and warnings first
3. **tcp_anomalies** — retrans, dup ACK, zero window, OOO, RST
4. **conversations** — top talkers
5. **protocol_hierarchy** — noise check (ARP/DHCP/mDNS >30% = note it)

### 4. Deep dive

**Ethernet:** `pm_dhcp_analysis` / `pm_dns_analysis` → `pm_asymmetric_hints` → `pm_troubleshoot_flow`

**Wi-Fi:** `pm_wifi_client_analysis` (STA MAC) → `pm_wifi_roaming_analysis` if roaming/deauth suspected.

Escalation tools:

- `pm_latency_summary` — RTT spikes per flow
- `pm_io_stats` — throughput bursts over time
- `pm_filter_packets` — targeted display filter
- `pm_follow_stream` — **only with user consent** (may contain credentials; redacted by default)

### 5. Never do this

- Do not open Wireshark GUI unless user explicitly asks
- Do not run raw `tshark` shell commands when PacketMaster tools exist
- Do not paste unredacted credentials from stream follows
- If `PM_ALLOWED_DIRS` is configured, do not analyze paths outside that allowlist

## Report Template

```markdown
## PCAP Troubleshooting Summary

**Capture:** <path> | **Packets:** <n> | **Duration:** <s>
**Source:** <EPC device/interface or manual upload>

### Findings

| Symptom | Evidence | Count | Confidence |
|---------|----------|-------|------------|
| e.g. TCP retransmissions | tcp.analysis.retransmission | 42 | medium |

### Root Cause Hypothesis

<1-2 paragraphs with confidence: high/medium/low>

### Limitations

- Capture point (single interface, mid-stream start, encrypted payload)

### Recommended Next Steps

- Next capture: interface, ACL, duration
- Suggested PacketMaster tool: pm_troubleshoot_flow / pm_latency_summary
```

## NetOps EPC Integration

```
User request → ios_xe_epc_capture_run(pull_pcap=true) → local_path
            → pm_detect_capture_type(local_path)
            → pm_wired_quick_scan(local_path)   # EPC / Ethernet
            → pm_dhcp_analysis / pm_dns_analysis / pm_asymmetric_hints (as needed)
            → pm_troubleshoot_flow (if needed)
            → Report
```

## Display Filter Quick Reference

See [reference.md](reference.md).
