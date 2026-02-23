#!/bin/bash
#
# Safe code deploy helper for already-installed systems.
# Copies repository code into /opt/tg-assistant without deleting runtime assets
# like /opt/tg-assistant/venv and /opt/tg-assistant/models.
#
# Usage:
#   sudo ./scripts/deploy-update.sh
#   sudo ./scripts/deploy-update.sh /path/to/repo/tg-assistant
#   sudo ./scripts/deploy-update.sh --no-restart
#

set -euo pipefail

INSTALL_DIR="/opt/tg-assistant"
SOURCE_DIR=""
DO_RESTART=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-restart)
            DO_RESTART=false
            shift
            ;;
        -*)
            echo "Unknown flag: $1" >&2
            exit 1
            ;;
        *)
            SOURCE_DIR="$1"
            shift
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo ./scripts/deploy-update.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${SOURCE_DIR}" ]]; then
    SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi

if [[ ! -d "${SOURCE_DIR}/src" ]]; then
    echo "Source directory invalid: ${SOURCE_DIR}" >&2
    echo "Expected ${SOURCE_DIR}/src to exist." >&2
    exit 1
fi

echo "[INFO] Deploying code from ${SOURCE_DIR} to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

# Replace code/config assets explicitly, but preserve runtime data such as
# /opt/tg-assistant/venv and /opt/tg-assistant/models.
for dir in src scripts systemd nftables docs config tests; do
    if [[ -d "${SOURCE_DIR}/${dir}" ]]; then
        rm -rf "${INSTALL_DIR:?}/${dir}"
        cp -a "${SOURCE_DIR}/${dir}" "${INSTALL_DIR}/${dir}"
    fi
done

for file in requirements.txt .gitignore; do
    if [[ -f "${SOURCE_DIR}/${file}" ]]; then
        cp -a "${SOURCE_DIR}/${file}" "${INSTALL_DIR}/${file}"
    fi
done

chown -R root:root "${INSTALL_DIR}/src" "${INSTALL_DIR}/scripts" "${INSTALL_DIR}/systemd" "${INSTALL_DIR}/nftables" "${INSTALL_DIR}/docs" "${INSTALL_DIR}/config" 2>/dev/null || true
chmod -R a+rX "${INSTALL_DIR}/src" "${INSTALL_DIR}/scripts" "${INSTALL_DIR}/systemd" "${INSTALL_DIR}/nftables" "${INSTALL_DIR}/docs" "${INSTALL_DIR}/config" 2>/dev/null || true

if [[ -d "${INSTALL_DIR}/scripts" ]]; then
    chmod +x "${INSTALL_DIR}/scripts/"*.sh "${INSTALL_DIR}/scripts/telenad" 2>/dev/null || true
    ln -sf "${INSTALL_DIR}/scripts/telenad" /usr/local/bin/telenad
fi

for svc in tg-syncer.service tg-querybot.service tg-refresh-api-ipsets.service tg-refresh-api-ipsets.timer; do
    if [[ -f "${INSTALL_DIR}/systemd/${svc}" ]]; then
        install -m 0644 "${INSTALL_DIR}/systemd/${svc}" "/etc/systemd/system/${svc}"
    fi
done

systemctl daemon-reload

if [[ "${DO_RESTART}" == true ]]; then
    systemctl restart --no-block tg-syncer tg-querybot
    echo "[OK] Deploy complete. Restart requested (non-blocking)."
else
    echo "[OK] Deploy complete. Services were not restarted (--no-restart)."
fi

echo "[INFO] Verify status with: telenad status"
