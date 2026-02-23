#!/bin/bash
#
# prune-history.sh — Enforce rolling message retention in PostgreSQL
#
# Deletes messages older than syncer.max_history_days from settings.toml,
# then removes orphaned chats (chats with no remaining messages).
#
# Usage:
#   sudo ./scripts/prune-history.sh
#   TG_ASSISTANT_CONFIG=/etc/tg-assistant/settings.toml ./scripts/prune-history.sh
#

set -euo pipefail

CONFIG_PATH="${TG_ASSISTANT_CONFIG:-/etc/tg-assistant/settings.toml}"

run_psql() {
    local db_name="$1"
    local sql="$2"
    if [[ "$(id -un)" == "postgres" ]]; then
        psql -d "${db_name}" -tAc "${sql}"
    else
        sudo -u postgres psql -d "${db_name}" -tAc "${sql}"
    fi
}

if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "[ERROR] Config file not found: ${CONFIG_PATH}" >&2
    exit 1
fi

read -r DB_NAME RETENTION_DAYS <<< "$(python3 - <<'PY' "${CONFIG_PATH}"
import sys
import tomllib

path = sys.argv[1]
with open(path, "rb") as f:
    cfg = tomllib.load(f)

db_name = cfg.get("database", {}).get("database", "tg_assistant")
days = cfg.get("syncer", {}).get("max_history_days", 0)
print(db_name, days)
PY
)"

if ! [[ "${RETENTION_DAYS}" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] Invalid syncer.max_history_days value in ${CONFIG_PATH}: ${RETENTION_DAYS}" >&2
    exit 1
fi

if [[ "${RETENTION_DAYS}" -le 0 ]]; then
    echo "[INFO] Retention pruning disabled (syncer.max_history_days=${RETENTION_DAYS})."
    exit 0
fi

echo "[INFO] Pruning messages older than ${RETENTION_DAYS} days from ${DB_NAME}..."

DELETED_MESSAGES="$(run_psql "${DB_NAME}" "WITH deleted AS (
    DELETE FROM messages
    WHERE timestamp < NOW() - INTERVAL '${RETENTION_DAYS} days'
    RETURNING 1
) SELECT COUNT(*) FROM deleted;" | tr -d '[:space:]')"

DELETED_CHATS="$(run_psql "${DB_NAME}" "WITH deleted AS (
    DELETE FROM chats c
    WHERE NOT EXISTS (
        SELECT 1 FROM messages m WHERE m.chat_id = c.chat_id
    )
    RETURNING 1
) SELECT COUNT(*) FROM deleted;" | tr -d '[:space:]')"

if [[ -z "${DELETED_MESSAGES}" ]]; then
    DELETED_MESSAGES=0
fi
if [[ -z "${DELETED_CHATS}" ]]; then
    DELETED_CHATS=0
fi

echo "[OK] Prune complete: deleted_messages=${DELETED_MESSAGES} deleted_chats=${DELETED_CHATS}"
