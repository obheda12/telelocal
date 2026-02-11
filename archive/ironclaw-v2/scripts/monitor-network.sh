#!/bin/bash
#
# Network Monitor for IronClaw
# Monitors network traffic to verify only expected connections are made.
#
# Usage: sudo ./monitor-network.sh [duration_seconds]
#

set -euo pipefail

DURATION="${1:-60}"

echo "=============================================="
echo "  IronClaw Network Monitor"
echo "=============================================="
echo ""
echo "Monitoring for ${DURATION} seconds..."
echo "Expected: ONLY traffic to api.telegram.org"
echo ""
echo "Press Ctrl+C to stop early"
echo ""
echo "----------------------------------------------"

# Capture traffic NOT to telegram or localhost
# This should ideally show nothing if properly configured

tcpdump -i any -n \
    'not host api.telegram.org and not host localhost and not host 127.0.0.1' \
    -c 100 \
    -W 1 \
    -G "${DURATION}" \
    2>/dev/null || true

echo ""
echo "----------------------------------------------"
echo ""

# Now show telegram traffic summary
echo "Telegram API traffic (last ${DURATION}s):"
echo ""

timeout "${DURATION}" tcpdump -i any -n 'host api.telegram.org' -c 50 2>/dev/null || true

echo ""
echo "=============================================="
echo "  Monitor complete"
echo "=============================================="
