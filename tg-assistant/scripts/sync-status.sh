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
LAST_SYNCED=$(db_query "SELECT TO_CHAR(MAX(synced_at), 'YYYY-MM-DD HH24:MI:SS') FROM messages;" 2>/dev/null || echo "")
if [[ -n "${LAST_SYNCED}" && "${LAST_SYNCED}" != "" ]]; then
    SINCE_LAST=$(db_query "SELECT NOW() - MAX(synced_at) FROM messages;" 2>/dev/null || echo "unknown")
    echo "  Last activity:  ${LAST_SYNCED} (${SINCE_LAST} ago)"
else
    echo "  Last activity:  no messages synced yet"
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
    COALESCE(c.title, 'Chat ' || c.telegram_id::text),
    COUNT(m.id),
    TO_CHAR(MIN(m.message_date), 'YYYY-MM-DD'),
    TO_CHAR(MAX(m.message_date), 'YYYY-MM-DD')
FROM chats c
LEFT JOIN messages m ON m.chat_id = c.id
GROUP BY c.id, c.title, c.telegram_id
ORDER BY COUNT(m.id) DESC;
" | while IFS='|' read -r title count oldest newest; do
    # Truncate long chat titles
    if [[ ${#title} -gt 38 ]]; then
        title="${title:0:35}..."
    fi
    printf "  %-40s %8s  %-12s  %-12s\n" "${title}" "${count}" "${oldest:-n/a}" "${newest:-n/a}"
done

echo ""
