#!/usr/bin/env bash
# Cursor MCP launcher. Paths with spaces break uv/console scripts in mcp.json.
# Inside a checkout, the repo root is the parent of this script.
# If this file is copied out of the repo, set PACKETMASTER_ROOT to the checkout.
set -euo pipefail
if [[ -z "${PACKETMASTER_ROOT:-}" ]]; then
  _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "${_script_dir}/../pyproject.toml" ]]; then
    PACKETMASTER_ROOT="$(cd "${_script_dir}/.." && pwd)"
  else
    echo "PACKETMASTER_ROOT is not set, and this script is outside the checkout." >&2
    exit 1
  fi
fi
# No path sandbox: clear PM_ALLOWED_DIRS even if set by Cursor UI or shell profile.
unset PM_ALLOWED_DIRS
export FASTMCP_SHOW_SERVER_BANNER="${FASTMCP_SHOW_SERVER_BANNER:-false}"
cd "${PACKETMASTER_ROOT}"
exec "${PACKETMASTER_ROOT}/.venv/bin/python" -m mcp_server.server "$@"
