---
name: packetmaster-mcp
description: >-
  Operate the PacketMaster MCP server efficiently: setup, tool selection,
  response parsing, workflows, and error handling. Use when configuring,
  calling, or debugging PacketMaster MCP tools (pm_*), integrating PCAP
  analysis into agents, or adapting tshark-based MCP calls outside Cursor.
---

# PacketMaster MCP — Agent Reference

PacketMaster is a **stdio MCP server** (FastMCP + tshark) that exposes 22 `pm_*` tools for PCAP/PCAPNG troubleshooting. All tools return a **JSON string** with a consistent envelope.

For **domain troubleshooting workflows** (what to look for in captures), use the companion skill [pcap-troubleshooting](../pcap-troubleshooting/SKILL.md). This skill covers **how to call the MCP layer correctly**.

## When to Use PacketMaster MCP

| Use PacketMaster | Do NOT use PacketMaster |
|------------------|-------------------------|
| Analyze `.pcap` / `.pcapng` with structured JSON results | Live packet capture (use tcpdump/Wireshark on host) |
| Triage EPC/SPAN/Ethernet or 802.11 monitor captures | Malware/IR forensics unless user explicitly requests |
| Drill into TCP/DHCP/DNS/Wi-Fi with display filters | Replace Wireshark GUI when user wants visual decode |
| Follow NetOps EPC handoff (`local_path` from another MCP) | Run raw `tshark` shell when `pm_*` tools exist |

## Prerequisites

1. **Wireshark CLI** — `tshark` and `capinfos` on PATH (macOS: `brew install wireshark`; auto-detects `/Applications/Wireshark.app/...`).
2. **Python 3.10+** with project deps: `uv sync --extra dev` in repo root.
3. **MCP client** configured to launch the server (see Setup below).
4. **Absolute PCAP path** — relative paths are rejected. Symlinks are rejected.

## Setup and Configuration

### Cursor (project or user)

1. Install launcher once:

```bash
mkdir -p ~/.packetmaster-mcp
cp scripts/start-mcp.sh ~/.packetmaster-mcp/start-mcp.sh
chmod +x ~/.packetmaster-mcp/start-mcp.sh
```

2. Edit `PACKETMASTER_ROOT` inside `start-mcp.sh` if the repo moves.

3. Add to `~/.cursor/mcp.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "packetmaster": {
      "command": "/Users/you/.packetmaster-mcp/start-mcp.sh",
      "env": { "FASTMCP_SHOW_SERVER_BANNER": "false" }
    }
  }
}
```

The launcher uses a **shell script** (not `uv run`) because Cursor breaks commands whose paths contain spaces.

4. Restart Cursor or reload MCP servers after config changes.

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PM_ALLOWED_DIRS` | unset | Colon-separated allowlist; paths must stay inside |
| `PM_REQUIRE_ALLOWED_DIRS` | false | Fail startup if allowlist empty |
| `PM_MAX_FILE_SIZE` | 10GB | Max PCAP size |
| `PM_MAX_PACKETS` | 10000 | Max frames per extraction |
| `PM_MAX_STDOUT_BYTES` | 10MB | Subprocess stdout cap |
| `PM_TIMEOUT` | 300 | Subprocess timeout (seconds) |
| `PM_HASH_MAX_BYTES` | 500MB | Skip SHA-256 above this unless requested |
| `PM_REDACT_SENSITIVE` | true | Redact credentials in stream/field output |
| `PM_MAX_FILTER_LENGTH` | 512 | Display filter char limit |
| `TSHARK_PATH` | auto | Override tshark binary |

**Note:** The bundled `start-mcp.sh` **unsets `PM_ALLOWED_DIRS`** so any readable absolute path works. Set allowlist in `mcp.json` `env` if you need a sandbox.

### Verify installation

Always call `pm_check_install` first in a new session or after MCP errors:

```json
{ "ok": true, "data": { "tshark_path": "...", "tshark_version": "...", "allowed_dirs": [] } }
```

If `ok: false` with `TSHARK_NOT_FOUND`, instruct the user to install Wireshark.

## Response Envelope (all tools)

Every tool returns **pretty-printed JSON** (string). Parse it before acting:

```json
{
  "ok": true,
  "schema_version": "1.0",
  "data": { },
  "error": null,
  "warnings": []
}
```

| Field | Meaning |
|-------|---------|
| `ok` | `true` = success; `false` = hard failure — read `error` |
| `data` | Tool-specific payload |
| `error.code` | Machine-readable failure (see Error Handling) |
| `error.message` | Human-readable detail |
| `warnings` | Non-fatal issues (partial results, large capture, etc.) |

Composite tools (`pm_*_quick_scan`) often include `data.recommended_next_tools` — **follow these** before guessing the next call.

## Mandatory Agent Workflow

Copy this checklist for every PCAP task:

```
PCAP Analysis Progress:
- [ ] 1. pm_check_install (if MCP untested this session)
- [ ] 2. Confirm absolute file_path; file exists and size > 0
- [ ] 3. pm_detect_capture_type(file_path)
- [ ] 4. Route: ethernet_l3 → pm_wired_quick_scan | wlan_monitor → pm_wifi_quick_scan
- [ ] 5. Review data in order: file_info → expert → tcp_anomalies/retries → conversations/top_bssids
- [ ] 6. Follow recommended_next_tools for drill-down
- [ ] 7. Report using template (see pcap-troubleshooting skill)
```

### Routing decision tree

```
pm_detect_capture_type
├── capture_type: "ethernet_l3"
│   └── pm_wired_quick_scan
│       ├── DHCP issues → pm_dhcp_analysis
│       ├── DNS failures → pm_dns_analysis
│       ├── One-sided capture → pm_asymmetric_hints
│       └── Specific flow → pm_troubleshoot_flow(ip_a, ip_b, port?)
└── capture_type: "wlan_monitor"
    └── pm_wifi_quick_scan
        ├── STA deep dive → pm_wifi_client_analysis(wlan_addr)
        └── Roaming/deauth → pm_wifi_roaming_analysis(wlan_addr)
```

**Alternate L3-only triage:** `pm_troubleshoot_quick_scan` (lighter than wired scan; no DHCP/DNS/VLAN bundle).

## Efficiency Rules

### Prefer composite tools over fan-out

| Instead of… | Use… |
|-------------|------|
| `pm_file_info` + `pm_expert_info` + `pm_conversations` + `pm_tcp_anomalies` + `pm_protocol_hierarchy` | `pm_troubleshoot_quick_scan` or `pm_wired_quick_scan` |
| Multiple parallel `pm_*` on same PCAP | One quick scan, then targeted drill-down |
| Raw `tshark -r …` in shell | Matching `pm_*` tool |

**Why:** The server runs tshark with a **concurrency limit of 1** (`asyncio.Semaphore(1)`). Parallel MCP calls queue; composite tools batch work (e.g. `triage_stats_bundle` = phs + conv + expert in one pass).

### Pagination and limits

- `pm_extract_fields`: max **20 fields**, default `limit=100`, use `offset` for pages.
- `pm_filter_packets`: default `limit=50`; increase only when needed.
- `pm_follow_stream`: default `max_bytes=8192`; payload truncated at `PM_MAX_STDOUT_BYTES`.
- Large captures (>1M packets): heed `warnings` suggesting `editcap` trim before deep extraction.

### When NOT to call a tool

| Tool | Skip when… |
|------|------------|
| `pm_wifi_*` | `pm_detect_capture_type` says `ethernet_l3` (EPC/SPAN has no 802.11) |
| `pm_wired_*` / `pm_dhcp_*` / `pm_dns_*` | Capture is `wlan_monitor` |
| `pm_follow_stream` | User has not consented; credentials may appear (redacted but still sensitive) |
| `compute_hash: true` | File > 500MB unless integrity proof required |
| Individual stats tools | Initial triage — use quick scan first |

### Batching in Cursor

1. **Read tool schema** from MCP descriptors before first call in a session (`mcps/.../tools/pm_*.json` or list tools).
2. **Independent setup checks** can run in parallel with user prompts; **PCAP analysis calls should be sequential** on the same file (server serializes tshark anyway).
3. Parse JSON once; extract `recommended_next_tools` and `warnings` before the next call.

## Error Handling

| `error.code` | Cause | Agent action |
|--------------|-------|--------------|
| `VALIDATION_ERROR` | Bad path, relative path, symlink, empty file, oversize file, bad IP/MAC, invalid display filter | Fix inputs; ensure absolute path |
| `TSHARK_NOT_FOUND` | Wireshark CLI missing | Run `pm_check_install`; tell user to install Wireshark |
| `TSHARK_ERROR` | tshark failed (corrupt PCAP, bad filter at runtime) | Check `error.message`; simplify filter; verify PCAP integrity |
| `WLAN_CAPTURE` | Wired tool on 802.11 capture | Switch to `pm_wifi_quick_scan` |
| `NOT_WLAN_CAPTURE` | Wi-Fi tool on Ethernet capture | Switch to `pm_wired_quick_scan` |
| (timeout) | Capture too large / slow disk | Increase `PM_TIMEOUT` in env or trim PCAP |

**Partial success:** Composite tools may set `ok: true` with `warnings` (e.g. expert failed but TCP anomalies succeeded). Report warnings to the user; do not treat as full success silently.

**Display filter rules:** Max 512 chars; no shell metacharacters (`;`, `|`, `` ` ``, `$`, etc.). Use Wireshark display filter syntax. See [reference.md](../pcap-troubleshooting/reference.md) for filter gotchas.

## Security and Privacy

- Paths must be absolute; optional `PM_ALLOWED_DIRS` sandbox.
- Symlinks rejected (path traversal protection).
- `PM_REDACT_SENSITIVE=true` redacts Authorization, Bearer, password, Cookie, FTP USER/PASS in field and stream output.
- **Always ask user consent** before `pm_follow_stream` on production captures.
- Do not paste unredacted credentials into chat even if redaction is enabled.

## Cursor Integration

### Calling tools

Use `CallMcpTool` with server name **`packetmaster`** (or `project-0-PacketMaster-packetmaster` / `user-packetmaster` depending on config).

**Always read the tool JSON schema first** — required parameters vary (`file_path` is always required for PCAP tools).

Example sequence:

```
CallMcpTool server=packetmaster toolName=pm_detect_capture_type
  arguments={ "file_path": "/absolute/path/to/capture.pcapng" }

CallMcpTool server=packetmaster toolName=pm_wired_quick_scan
  arguments={ "file_path": "/absolute/path/to/capture.pcapng" }
```

Server instructions (injected by MCP): start with `pm_detect_capture_type`; Ethernet → `pm_wired_quick_scan`; 802.11 → `pm_wifi_quick_scan`.

### Pairing with other MCPs

**NetOps EPC handoff:**

```
ios_xe_epc_capture_run(pull_pcap=true) → local_path
→ pm_detect_capture_type(local_path)
→ pm_wired_quick_scan(local_path)
→ pm_dhcp_analysis / pm_dns_analysis / pm_troubleshoot_flow (as recommended)
```

Record EPC metadata (device, interface, ACL, duration) in the report.

## Adapting for Other LLM Agents

PacketMaster is **transport-agnostic stdio MCP** — not Cursor-specific.

| Client | Configuration |
|--------|---------------|
| Claude Desktop | Add to `claude_desktop_config.json` under `mcpServers` with same `command` as Cursor |
| Generic MCP SDK | Spawn `python -m mcp_server.server` from repo with venv activated, or use `start-mcp.sh` |
| CI / scripts | Call Python functions in `mcp_server.tools.*` directly (bypass MCP) for tests |

Requirements for any client:

1. Launch server via stdio (no HTTP port).
2. Pass **absolute** `file_path` strings.
3. Parse JSON string results; check `ok` before reading `data`.
4. Respect single-process tshark serialization — avoid parallel tool storms.

Manual smoke test:

```bash
cd "/path/to/PacketMaster"
uv run packetmaster-mcp   # blocks on stdio; use MCP inspector or client
```

## Tool Catalog

Complete parameters, return shapes, and examples: **[tool-catalog.md](tool-catalog.md)**

Quick index (22 tools):

| Category | Tools |
|----------|-------|
| Setup | `pm_check_install` |
| Routing | `pm_detect_capture_type` |
| Composite triage | `pm_wired_quick_scan`, `pm_wifi_quick_scan`, `pm_troubleshoot_quick_scan` |
| Wired L3 | `pm_dhcp_analysis`, `pm_dns_analysis`, `pm_asymmetric_hints` |
| Wi-Fi | `pm_wifi_client_analysis`, `pm_wifi_roaming_analysis` |
| TCP / stats | `pm_tcp_anomalies`, `pm_latency_summary`, `pm_expert_info`, `pm_conversations`, `pm_endpoints`, `pm_protocol_hierarchy`, `pm_io_stats` |
| Extraction | `pm_extract_fields`, `pm_filter_packets`, `pm_follow_stream` |
| Metadata | `pm_file_info` |
| Flow drill-down | `pm_troubleshoot_flow` |

## Example Call Sequences

See **[examples.md](examples.md)** for copy-paste MCP argument patterns.

## Related Resources

- [tool-catalog.md](tool-catalog.md) — full API reference
- [examples.md](examples.md) — worked sequences
- [pcap-troubleshooting/SKILL.md](../pcap-troubleshooting/SKILL.md) — triage workflow and report template
- [pcap-troubleshooting/reference.md](../pcap-troubleshooting/reference.md) — display filter reference
- [README.md](../../README.md) — install and env vars
