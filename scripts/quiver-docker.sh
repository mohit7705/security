#!/usr/bin/env sh
# Run Quiver inside the Docker container from any directory:  quiver -u https://site/
set -eu
SCRIPT=$(readlink -f "$0")
ROOT=$(CDPATH= cd -- "$(dirname -- "$SCRIPT")/.." && pwd)
cd "$ROOT"

# Start the stack if it is not already running.
if ! docker compose ps --status running --services 2>/dev/null | grep -qx "security-analyzer"; then
    echo "[quiver] Starting containers..." >&2
    docker compose up -d >&2
fi

exec docker compose exec security-analyzer quiver "$@"