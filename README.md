# PacketMaster

MCP server for network-troubleshooting PCAP analysis via `tshark`. Pairs with Cursor skills `pcap-troubleshooting` (domain workflows) and `packetmaster-mcp` (MCP tool usage).

## Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- Wireshark with CLI tools: `tshark`, `capinfos`

```bash
brew install wireshark   # macOS

PacketMaster auto-detects `/Applications/Wireshark.app/Contents/MacOS/tshark` if not on PATH.
```

## Install

```bash
cd "/Users/networkze/Documents/Claude Projects/PacketMaster"
uv sync --extra dev
```

## Cursor MCP Configuration

Install the launcher (once), then add to `~/.cursor/mcp.json`:

```bash
mkdir -p ~/.packetmaster-mcp
cp scripts/start-mcp.sh ~/.packetmaster-mcp/start-mcp.sh
chmod +x ~/.packetmaster-mcp/start-mcp.sh
```

```json
{
  "mcpServers": {
    "packetmaster": {
      "command": "/Users/networkze/.packetmaster-mcp/start-mcp.sh",
      "env": {
        "FASTMCP_SHOW_SERVER_BANNER": "false"
      }
    }
  }
}
```

Uses a launcher script (like flipper-zero) because Cursor can break `uv run` paths that contain spaces.

PCAP paths must be **absolute**. By default any readable `.pcap` on disk is allowed. Set `PM_ALLOWED_DIRS` only if you want an opt-in sandbox.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PM_ALLOWED_DIRS` | (unset) | Optional colon-separated allowlist; when set, paths must stay inside |
| `PM_REQUIRE_ALLOWED_DIRS` | false | If true, `PM_ALLOWED_DIRS` must be set or startup validation fails |
| `PM_MAX_FILE_SIZE` | 10GB | Max PCAP file size |
| `PM_MAX_PACKETS` | 10000 | Max packets per extraction request |
| `PM_MAX_STDOUT_BYTES` | 10MB | Max subprocess stdout |
| `PM_TIMEOUT` | 300 | Subprocess timeout (seconds) |
| `PM_HASH_MAX_BYTES` | 500MB | Skip SHA-256 above this size unless requested |
| `PM_REDACT_SENSITIVE` | true | Redact credentials in stream/field output |
| `TSHARK_PATH` | auto | Override tshark binary path |

## Tools

| Tool | Description |
|------|-------------|
| `pm_check_install` | Verify tshark/capinfos installation |
| `pm_file_info` | capinfos + optional SHA-256 |
| `pm_protocol_hierarchy` | Protocol distribution |
| `pm_conversations` | Top conversations by bytes |
| `pm_endpoints` | Top IP endpoints |
| `pm_expert_info` | Wireshark expert information |
| `pm_tcp_anomalies` | TCP retrans/dup ACK/zero window/OOO/RST |
| `pm_latency_summary` | Per-flow RTT statistics |
| `pm_io_stats` | Traffic over time |
| `pm_extract_fields` | Paginated field extraction |
| `pm_follow_stream` | Follow TCP/UDP/HTTP/TLS stream (redacted) |
| `pm_filter_packets` | Packet summaries by display filter |
| `pm_detect_capture_type` | **Start here** — wlan vs ethernet + tool routing |
| `pm_wired_quick_scan` | **EPC/SPAN** — DHCP, DNS, ICMP, VLAN, L2 infra, TCP |
| `pm_dhcp_analysis` | DHCP phases, stuck patterns, optional MAC filter |
| `pm_dns_analysis` | DNS queries/responses, NXDOMAIN, top names |
| `pm_asymmetric_hints` | One-sided capture / path asymmetry heuristics |
| `pm_troubleshoot_quick_scan` | L3 TCP-focused composite (alternate to wired scan) |
| `pm_troubleshoot_flow` | Deep dive between two IPs |
| `pm_wifi_quick_scan` | **802.11 monitor** — retries, mgmt, roaming, BSSIDs |
| `pm_wifi_client_analysis` | Deep dive on one STA by MAC |
| `pm_wifi_roaming_analysis` | 802.11k/v roam timeline for one STA |

## Workflow with NetOps EPC

1. Capture via `ios_xe_epc_capture_run` (user-netops MCP) with `pull_pcap=true`
2. Run `pm_troubleshoot_quick_scan` on the returned `local_path`
3. Drill down with `pm_troubleshoot_flow` on suspect IPs

## Development

```bash
uv run pytest -q
uv run packetmaster-mcp   # stdio MCP server
```

## Security

- PCAP paths must be absolute; optional `PM_ALLOWED_DIRS` sandbox for locked-down setups
- Symlinks rejected
- Stream/field output redacts Authorization, Bearer tokens, passwords by default
- Confirm with user before `pm_follow_stream` on production captures
