#!/bin/bash
#
# sync-status.sh — Show sync progress for Telegram Personal Assistant
#
# Displays:
#   - Whether the syncer service is running
#   - Total messages synced and total chats
#   - Per-chat breakdown (title, message count, oldest/newest message date)
#   - Time since last sync activity
#
# Usage: ./scripts/sync-status.sh
#        telenad sync-status
#

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DB_NAME="tg_assistant"

# ---------------------------------------------------------------------------
# Check syncer service status
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Syncer Service${NC}"
echo ""

if systemctl is-active --quiet tg-syncer 2>/dev/null; then
    UPTIME=$(systemctl show tg-syncer --property=ActiveEnterTimestamp --value 2>/dev/null)
    echo -e "  Status: ${GREEN}running${NC} (since ${UPTIME})"
else
    echo -e "  Status: ${YELLOW}not running${NC}"
fi

# ---------------------------------------------------------------------------
# Check database connectivity
# ---------------------------------------------------------------------------
if ! command -v psql &>/dev/null; then
    echo ""
    echo "  PostgreSQL client (psql) not found."
    exit 1
fi

if ! systemctl is-active --quiet postgresql 2>/dev/null; then
    echo ""
    echo "  PostgreSQL is not running."
    exit 1
fi

if ! sudo -u postgres psql -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw "${DB_NAME}"; then
    echo ""
    echo "  Database '${DB_NAME}' does not exist yet."
    exit 0
fi

# Helper to run a query against the database
db_query() {
    sudo -u postgres psql -d "${DB_NAME}" -tAc "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Overall summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Sync Summary${NC}"
echo ""

TOTAL_MESSAGES=$(db_query "SELECT COUNT(*) FROM messages;")
TOTAL_CHATS=$(db_query "SELECT COUNT(*) FROM chats;")

echo "  Total messages: ${TOTAL_MESSAGES}"
echo "  Total chats:    ${TOTAL_CHATS}"

# Time since last sync activity (most recent message timestamp in DB)
LAST_SYNCED=$(db_query "SELECT TO_CHAR(MAX(timestamp), 'YYYY-MM-DD HH24:MI:SS') FROM messages;" 2>/dev/null || echo "")
if [[ -n "${LAST_SYNCED}" && "${LAST_SYNCED}" != "" ]]; then
    SINCE_LAST=$(db_query "SELECT NOW() - MAX(timestamp) FROM messages;" 2>/dev/null || echo "unknown")
    echo "  Last activity:  ${LAST_SYNCED} (${SINCE_LAST} ago)"
else
    echo "  Last activity:  no messages synced yet"
fi

# ---------------------------------------------------------------------------
# Current activity (from most recent sync_chat* audit event)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Current Activity${NC}"
echo ""

LATEST_CHAT_EVENT=$(db_query "
SELECT action || E'\t' || details::text || E'\t' ||
       EXTRACT(EPOCH FROM (NOW() - timestamp))::int
FROM audit_log
WHERE service = 'syncer'
  AND action IN ('sync_chat', 'sync_chat_progress')
  AND success = true
ORDER BY timestamp DESC LIMIT 1;
" 2>/dev/null || echo "")

if [[ -n "${LATEST_CHAT_EVENT}" && "${LATEST_CHAT_EVENT}" != "" ]]; then
    IFS=$'\t' read -r EVENT_ACTION EVENT_DETAILS EVENT_AGE <<< "${LATEST_CHAT_EVENT}"
    if ! [[ "${EVENT_AGE:-}" =~ ^[0-9]+$ ]]; then
        EVENT_AGE=999999
    fi

    # Parse JSON fields using python3
    CHAT_INDEX=$(echo "${EVENT_DETAILS}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('chat_index','?'))" 2>/dev/null || echo "?")
    TOTAL_CHATS=$(echo "${EVENT_DETAILS}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_chats','?'))" 2>/dev/null || echo "?")
    CHAT_TITLE=$(echo "${EVENT_DETAILS}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('chat_title','unknown'))" 2>/dev/null || echo "unknown")
    NEW_MSGS=$(echo "${EVENT_DETAILS}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('new_messages',0))" 2>/dev/null || echo "0")
    MSG_RATE=$(echo "${EVENT_DETAILS}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('rate_msg_per_sec','n/a'))" 2>/dev/null || echo "n/a")
    ELAPSED=$(echo "${EVENT_DETAILS}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('elapsed_seconds','n/a'))" 2>/dev/null || echo "n/a")
    SCANNED=$(echo "${EVENT_DETAILS}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('messages_scanned','n/a'))" 2>/dev/null || echo "n/a")

    echo "  Last synced chat: ${CHAT_INDEX}/${TOTAL_CHATS} — ${CHAT_TITLE}"
    echo "  New messages:     ${NEW_MSGS}"
    echo "  Messages scanned: ${SCANNED}"
    echo "  Rate:             ${MSG_RATE} msg/s"
    echo "  Elapsed:          ${ELAPSED}s"
    echo "  Last event:       ${EVENT_ACTION} (${EVENT_AGE}s ago)"

    # Check if sync is in progress.
    if [[ "${EVENT_AGE}" -lt 180 && "${CHAT_INDEX}" != "${TOTAL_CHATS}" ]]; then
        echo -e "  State:            ${GREEN}Sync in progress${NC}"
    elif [[ "${EVENT_AGE}" -lt 600 && "${CHAT_INDEX}" != "${TOTAL_CHATS}" ]]; then
        echo -e "  State:            ${YELLOW}Slow / possible stall${NC}"
    else
        echo -e "  State:            ${BLUE}Idle${NC}"
    fi
else
    echo "  No sync activity recorded yet."
fi

# ---------------------------------------------------------------------------
# Per-chat breakdown
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Per-Chat Breakdown${NC}"
echo ""

# Column headers
printf "  ${BOLD}%-40s %8s  %-12s  %-12s${NC}\n" "Chat" "Messages" "Oldest" "Newest"
printf "  %-40s %8s  %-12s  %-12s\n" "$(printf '%0.s-' {1..40})" "--------" "------------" "------------"

# Query: join chats and messages, group by chat, order by message count descending
db_query "
SELECT
    COALESCE(c.title, 'Chat ' || c.chat_id::text),
    COUNT(m.message_id),
    TO_CHAR(MIN(m.timestamp), 'YYYY-MM-DD'),
    TO_CHAR(MAX(m.timestamp), 'YYYY-MM-DD')
FROM chats c
LEFT JOIN messages m ON m.chat_id = c.chat_id
GROUP BY c.chat_id, c.title
ORDER BY COUNT(m.message_id) DESC;
" | while IFS='|' read -r title count oldest newest; do
    # Truncate long chat titles
    if [[ ${#title} -gt 38 ]]; then
        title="${title:0:35}..."
    fi
    printf "  %-40s %8s  %-12s  %-12s\n" "${title}" "${count}" "${oldest:-n/a}" "${newest:-n/a}"
done

# ---------------------------------------------------------------------------
# Sync pass history (from audit_log)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Sync Pass Status${NC}"
echo ""

FIRST_PASS=$(db_query "
SELECT TO_CHAR(timestamp, 'YYYY-MM-DD HH24:MI:SS')
FROM audit_log
WHERE service = 'syncer' AND action = 'sync_pass' AND success = true
ORDER BY timestamp ASC LIMIT 1;
" 2>/dev/null || echo "")

LATEST_PASS=$(db_query "
SELECT TO_CHAR(timestamp, 'YYYY-MM-DD HH24:MI:SS')
FROM audit_log
WHERE service = 'syncer' AND action = 'sync_pass' AND success = true
ORDER BY timestamp DESC LIMIT 1;
" 2>/dev/null || echo "")

PASS_COUNT=$(db_query "
SELECT COUNT(*)
FROM audit_log
WHERE service = 'syncer' AND action = 'sync_pass' AND success = true;
" 2>/dev/null || echo "0")

if [[ -n "${FIRST_PASS}" && "${FIRST_PASS}" != "" ]]; then
    echo "  Completed passes: ${PASS_COUNT}"
    echo "  First pass:       ${FIRST_PASS}"
    echo "  Latest pass:      ${LATEST_PASS}"
else
    echo "  No completed sync passes recorded yet."
    echo "  The initial sync may still be in progress."
fi

echo ""
