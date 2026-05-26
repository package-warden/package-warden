#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Package Warden — local dev runner
#
# Usage:
#   ./run.sh
#
# Environment variables:
#   PW_PORT       Listening port     (default: 5050)
#   PW_DATA_DIR   Root data dir      (default: <repo>/data)
#   PW_LOG_LEVEL  ASP.NET log level  (default: Information)
#
# Examples:
#   PW_PORT=8080 ./run.sh
#   PW_LOG_LEVEL=Debug ./run.sh
#   PW_DATA_DIR=/tmp/pw-data ./run.sh
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_PROJECT="$SCRIPT_DIR/src/PackageWarden.Host/PackageWarden.Host.csproj"

PW_PORT="${PW_PORT:-5050}"
PW_LOG_LEVEL="${PW_LOG_LEVEL:-Information}"

export PW_DATA_DIR="${PW_DATA_DIR:-$SCRIPT_DIR/data}"

echo "Package Warden — http://localhost:$PW_PORT/ui  (data: $PW_DATA_DIR, log: $PW_LOG_LEVEL)"

export ASPNETCORE_URLS="http://+:$PW_PORT"
export ASPNETCORE_ENVIRONMENT="Development"
export Logging__LogLevel__Default="$PW_LOG_LEVEL"
export PackageWarden__BaseUrl="http://localhost:$PW_PORT"

exec dotnet run --project "$HOST_PROJECT" --no-launch-profile --configuration Debug
