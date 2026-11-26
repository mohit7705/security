#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "[ERROR] Do not run the analyzer as root." >&2
    exit 1
fi
APP_UID="$(id -u)"
if ! nft list chain inet security_analyzer_guard output 2>/dev/null \
    | grep -Fq "meta skuid ${APP_UID}"; then
    echo "[ERROR] No egress firewall rule found for UID ${APP_UID}." >&2
    exit 1
fi
if ! systemctl is-active --quiet security-analyzer-proxy; then
    echo "[ERROR] Scope-aware proxy is not running." >&2
    exit 1
fi
python3 - <<'PYTEST'
import socket
with socket.create_connection(("127.0.0.1", 3128), timeout=3):
    pass
PYTEST
export SECURITY_ANALYZER_PROXY="http://127.0.0.1:3128"
export SECURITY_ANALYZER_EGRESS_ENFORCED="1"
export HTTP_PROXY="${SECURITY_ANALYZER_PROXY}"
export HTTPS_PROXY="${SECURITY_ANALYZER_PROXY}"
export ALL_PROXY="${SECURITY_ANALYZER_PROXY}"
export http_proxy="${HTTP_PROXY}"
export https_proxy="${HTTPS_PROXY}"
export all_proxy="${ALL_PROXY}"
export NO_PROXY="localhost,127.0.0.1,::1"
export no_proxy="${NO_PROXY}"
if [[ "$#" -eq 0 ]]; then
    echo "[ERROR] Supply the security-analyzer command and arguments." >&2
    exit 2
fi
exec "$@"
