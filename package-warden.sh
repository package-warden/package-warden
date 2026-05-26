#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Package Warden — run script
#
# Usage:
#   ./package-warden.sh
#
# Environment variables (all optional):
#   PW_PORT        Listening port       (default: 5050)
#   PW_DATA_DIR    Root data directory  (default: platform user data dir)
#   PW_LOG_LEVEL   ASP.NET log level    (default: Information)
#
#   Platform defaults for PW_DATA_DIR:
#     Linux:   $XDG_DATA_HOME/package-warden  (~/.local/share/package-warden)
#     macOS:   ~/Library/Application Support/PackageWarden
#     Windows: %APPDATA%\PackageWarden  (use package-warden.bat instead)
#
# Examples:
#   PW_PORT=8080 ./package-warden.sh
#   PW_DATA_DIR=/var/lib/package-warden ./package-warden.sh
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/package-warden"

PW_PORT="${PW_PORT:-5050}"
PW_LOG_LEVEL="${PW_LOG_LEVEL:-Information}"

# Export PW_DATA_DIR so the app can read it; let the app apply the platform default if unset.
if [ -n "${PW_DATA_DIR:-}" ]; then
    export PW_DATA_DIR
fi

echo "Package Warden — http://localhost:$PW_PORT/ui"

export ASPNETCORE_URLS="http://+:$PW_PORT"
export Logging__LogLevel__Default="$PW_LOG_LEVEL"
export PackageWarden__BaseUrl="http://localhost:$PW_PORT"

exec "$BINARY"
