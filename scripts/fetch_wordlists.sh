#!/usr/bin/env sh
# Build Quiver's ordered directory list from SecLists.
set -eu

SCRIPT=$(readlink -f "$0")
ROOT=$(CDPATH= cd -- "$(dirname -- "$SCRIPT")/.." && pwd)
OUT_DIR="$ROOT/config/wordlists"
OUT_FILE="$OUT_DIR/quiver-directories.txt"
MAX_LINES="${MAX_LINES:-10000}"
BASE_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content"
FILES="quickhits.txt api/api-endpoints.txt common.txt raft-medium-directories.txt"

case "$MAX_LINES" in ''|*[!0-9]*) echo "MAX_LINES must be a positive integer" >&2; exit 2 ;; esac
[ "$MAX_LINES" -gt 0 ] || { echo "MAX_LINES must be greater than zero" >&2; exit 2; }
mkdir -p "$OUT_DIR"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
: > "$WORK/all.txt"
FOUND=0

for rel in $FILES; do
    name=$(basename "$rel")
    if [ -n "${SECLISTS_DIR:-}" ]; then
        src="$SECLISTS_DIR/Discovery/Web-Content/$rel"
        if [ -f "$src" ]; then cp "$src" "$WORK/$name"; else echo "[wordlists] missing locally: $rel" >&2; continue; fi
    else
        if ! curl -fsSL --retry 2 --max-time 60 -o "$WORK/$name" "$BASE_URL/$rel"; then
            echo "[wordlists] could not download: $rel (skipped)" >&2
            continue
        fi
    fi
    tr -d '\r' < "$WORK/$name" \
        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's#^/*##' \
        | grep -v -e '^$' -e '^#' -e '[?#\\ ]' -e '://' \
        >> "$WORK/all.txt" || true
    FOUND=$((FOUND + 1))
    echo "[wordlists] added: $rel" >&2
done

if [ "$FOUND" -eq 0 ]; then
    echo "[wordlists] ERROR: no list could be read. Check internet access or set SECLISTS_DIR." >&2
    exit 1
fi
awk '!seen[$0]++' "$WORK/all.txt" | head -n "$MAX_LINES" > "$WORK/output.txt" || [ -s "$WORK/output.txt" ]
mv "$WORK/output.txt" "$OUT_FILE"
echo "[wordlists] wrote $(wc -l < "$OUT_FILE" | tr -d ' ') entries to $OUT_FILE" >&2
echo "[wordlists] Quiver uses up to limits.max_directory_words entries from this list." >&2
