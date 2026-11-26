#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SCANNER_UID=1000
SCANNER_GID=1000

if [ "$(id -u)" -eq 0 ]; then
    install -d -m 0700 -o "$SCANNER_UID" -g "$SCANNER_GID" \
        "$ROOT_DIR/output" "$ROOT_DIR/secrets"
else
    if [ "$(id -u)" -ne "$SCANNER_UID" ]; then
        echo "Run with sudo so bind-mounted directories are owned by container UID ${SCANNER_UID}." >&2
        exit 1
    fi
    install -d -m 0700 "$ROOT_DIR/output" "$ROOT_DIR/secrets"
fi

printf 'Prepared private Docker storage directories:\n'
printf '  %s/output (UID:GID %s:%s, mode 0700)\n' "$ROOT_DIR" "$SCANNER_UID" "$SCANNER_GID"
printf '  %s/secrets (UID:GID %s:%s, mode 0700)\n' "$ROOT_DIR" "$SCANNER_UID" "$SCANNER_GID"
