#!/usr/bin/env bash
set -Eeuo pipefail

APP_USER="${1:-security-analyzer}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] Run this script with sudo." >&2
    exit 1
fi
if ! id "${APP_USER}" >/dev/null 2>&1; then
    echo "[ERROR] User does not exist: ${APP_USER}" >&2
    exit 1
fi
APP_UID="$(id -u "${APP_USER}")"
if [[ "${APP_UID}" -eq 0 ]]; then
    echo "[ERROR] Refusing to restrict root UID." >&2
    exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
    echo "[ERROR] nftables is not installed." >&2
    exit 1
fi

nft delete table inet security_analyzer_guard 2>/dev/null || true
nft -f - <<EOF
 table inet security_analyzer_guard {
    chain output {
        type filter hook output priority -50; policy accept;
        meta skuid ${APP_UID} oifname "lo" accept
        meta skuid ${APP_UID} drop
    }
}
EOF

echo "[SUCCESS] Direct egress restricted for ${APP_USER} (UID ${APP_UID})."
echo "[INFO] The proxy must run under a different UID."
echo "[INFO] The firewall rule remains active until removed or rebooted."
