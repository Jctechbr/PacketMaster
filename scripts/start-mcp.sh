#!/usr/bin/env bash
# Cursor MCP launcher — paths with spaces break uv/console scripts in mcp.json.
# Install: cp scripts/start-mcp.sh ~/.packetmaster-mcp/start-mcp.sh && chmod +x ~/.packetmaster-mcp/start-mcp.sh
set -euo pipefail
PACKETMASTER_ROOT="/Users/networkze/Documents/Claude Projects/PacketMaster"
# No path sandbox: clear PM_ALLOWED_DIRS even if set by Cursor UI or shell profile.
unset PM_ALLOWED_DIRS
export FASTMCP_SHOW_SERVER_BANNER="${FASTMCP_SHOW_SERVER_BANNER:-false}"
cd "${PACKETMASTER_ROOT}"
exec "${PACKETMASTER_ROOT}/.venv/bin/python" -m mcp_server.server "$@"
