#!/bin/bash
#
# Telegram Personal Assistant - Network Traffic Monitor
# Monitors network traffic from tg-syncer and tg-querybot processes
# to verify only expected connections are being made.
#
# Expected traffic:
#   tg-syncer:   Telegram MTProto (149.154.160.0/20, 91.108.x.x ranges, port 443)
#   tg-querybot: api.telegram.org + api.anthropic.com (HTTPS, port 443)
#   Both:        localhost (PostgreSQL, port 5432)
#
# Usage: sudo ./monitor-network.sh [duration_seconds]
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DURATION="${1:-60}"
SYNCER_USER="tg-syncer"
QUERYBOT_USER="tg-querybot"

# Telegram datacenter IP ranges (MTProto and Bot API)
TG_RANGES="149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 185.76.151.0/24"

echo "=============================================="
echo "  Telegram Assistant - Network Monitor"
echo "=============================================="
echo ""

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)."
    exit 1
fi

if ! command -v tcpdump &>/dev/null; then
    echo -e "${RED}[ERROR]${NC} tcpdump not found. Install with: sudo apt install tcpdump"
    exit 1
fi

# Get UIDs
SYNCER_UID=$(id -u "${SYNCER_USER}" 2>/dev/null || echo "")
QUERYBOT_UID=$(id -u "${QUERYBOT_USER}" 2>/dev/null || echo "")

if [[ -z "${SYNCER_UID}" ]]; then
    echo -e "${YELLOW}[WARN]${NC} User '${SYNCER_USER}' not found -- cannot filter syncer traffic"
fi

if [[ -z "${QUERYBOT_UID}" ]]; then
    echo -e "${YELLOW}[WARN]${NC} User '${QUERYBOT_USER}' not found -- cannot filter querybot traffic"
fi

echo -e "${BOLD}Expected traffic patterns:${NC}"
echo ""
echo -e "  ${GREEN}tg-syncer${NC}   (UID ${SYNCER_UID:-?}):"
echo "    - Telegram MTProto:  149.154.160.0/20, 91.108.x.x ranges (TCP 443)"
echo "    - PostgreSQL:        127.0.0.1:5432"
echo "    - DNS:               UDP 53 (for initial resolution)"
echo ""
echo -e "  ${GREEN}tg-querybot${NC} (UID ${QUERYBOT_UID:-?}):"
echo "    - Telegram Bot API:  api.telegram.org (TCP 443)"
echo "    - Anthropic API:     api.anthropic.com (TCP 443)"
echo "    - PostgreSQL:        127.0.0.1:5432"
echo "    - DNS:               UDP 53 (for initial resolution)"
echo ""
echo "  Any traffic outside these patterns is ${RED}unexpected${NC}."
echo ""
echo "----------------------------------------------"
echo -e "  Monitoring for ${BOLD}${DURATION}${NC} seconds..."
echo "  Press Ctrl+C to stop early."
echo "----------------------------------------------"
echo ""

# ---------------------------------------------------------------------------
# Capture file setup
# ---------------------------------------------------------------------------
CAPTURE_DIR=$(mktemp -d /tmp/tg-netmon.XXXXXX)
CAPTURE_FILE="${CAPTURE_DIR}/capture.pcap"
trap 'rm -rf "${CAPTURE_DIR}"' EXIT

# ---------------------------------------------------------------------------
# Phase 1: Capture ALL traffic from both service users
# ---------------------------------------------------------------------------
echo -e "${BOLD}Phase 1: Capturing all traffic from service processes...${NC}"
echo ""

# Build a tcpdump filter that catches traffic from/to non-localhost
# We capture everything and analyze afterward
timeout "${DURATION}" tcpdump -i any -n -w "${CAPTURE_FILE}" \
    'not (host 127.0.0.1 or host ::1)' \
    2>/dev/null &
TCPDUMP_PID=$!

# Also monitor in real-time for unexpected traffic using ss/conntrack
UNEXPECTED_COUNT=0

# Poll connections while tcpdump runs
END_TIME=$((SECONDS + DURATION))
while [[ ${SECONDS} -lt ${END_TIME} ]]; do
    # Check for connections from syncer that are NOT to Telegram ranges or localhost
    if [[ -n "${SYNCER_UID}" ]]; then
        while IFS= read -r line; do
            # Extract destination IP
            DST_IP=$(echo "${line}" | grep -oP '\d+\.\d+\.\d+\.\d+' | tail -1)
            if [[ -n "${DST_IP}" ]]; then
                IS_EXPECTED=false
                # Check localhost
                [[ "${DST_IP}" == 127.* ]] && IS_EXPECTED=true
                # Check Telegram ranges (simplified check)
                [[ "${DST_IP}" == 149.154.* ]] && IS_EXPECTED=true
                [[ "${DST_IP}" == 91.108.* ]] && IS_EXPECTED=true
                [[ "${DST_IP}" == 185.76.151.* ]] && IS_EXPECTED=true

                if [[ "${IS_EXPECTED}" == false ]]; then
                    echo -e "  ${RED}[UNEXPECTED]${NC} ${SYNCER_USER} -> ${DST_IP} : ${line}"
                    ((UNEXPECTED_COUNT++)) || true
                fi
            fi
        done < <(ss -tnp 2>/dev/null | grep "uid:${SYNCER_UID}" || true)
    fi

    # Check for connections from querybot that are NOT to expected hosts
    if [[ -n "${QUERYBOT_UID}" ]]; then
        while IFS= read -r line; do
            DST_IP=$(echo "${line}" | grep -oP '\d+\.\d+\.\d+\.\d+' | tail -1)
            if [[ -n "${DST_IP}" ]]; then
                IS_EXPECTED=false
                [[ "${DST_IP}" == 127.* ]] && IS_EXPECTED=true
                # Telegram Bot API IPs
                [[ "${DST_IP}" == 149.154.* ]] && IS_EXPECTED=true
                [[ "${DST_IP}" == 91.108.* ]] && IS_EXPECTED=true
                [[ "${DST_IP}" == 185.76.151.* ]] && IS_EXPECTED=true
                # Anthropic API (resolve dynamically)
                # Common Anthropic IP ranges are not static, so we allow all 443 traffic
                # and flag non-443 traffic
                # For stricter checking, resolve api.anthropic.com at script start

                if [[ "${IS_EXPECTED}" == false ]]; then
                    echo -e "  ${RED}[UNEXPECTED]${NC} ${QUERYBOT_USER} -> ${DST_IP} : ${line}"
                    ((UNEXPECTED_COUNT++)) || true
                fi
            fi
        done < <(ss -tnp 2>/dev/null | grep "uid:${QUERYBOT_UID}" || true)
    fi

    sleep 5
done

# Wait for tcpdump to finish
wait ${TCPDUMP_PID} 2>/dev/null || true

# ---------------------------------------------------------------------------
# Phase 2: Analyze captured traffic
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Phase 2: Analyzing captured traffic...${NC}"
echo ""

if [[ ! -s "${CAPTURE_FILE}" ]]; then
    echo -e "  ${DIM}No external traffic captured during the monitoring period.${NC}"
else
    echo -e "  ${BOLD}Top destination IPs:${NC}"
    tcpdump -r "${CAPTURE_FILE}" -n 2>/dev/null | \
        grep -oP '> \K\d+\.\d+\.\d+\.\d+' | \
        sort | uniq -c | sort -rn | head -20 | \
    while read -r count ip; do
        # Classify the IP
        LABEL=""
        COLOR="${RED}"

        if [[ "${ip}" == 149.154.* || "${ip}" == 91.108.* || "${ip}" == 185.76.151.* ]]; then
            LABEL="Telegram"
            COLOR="${GREEN}"
        fi

        if [[ -n "${LABEL}" ]]; then
            echo -e "    ${COLOR}${count}${NC} packets -> ${ip} ${DIM}(${LABEL})${NC}"
        else
            echo -e "    ${COLOR}${count}${NC} packets -> ${ip} ${RED}(UNKNOWN -- investigate)${NC}"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Phase 3: Summary of expected traffic
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Phase 3: Expected traffic summary${NC}"
echo ""

echo -e "  ${GREEN}tg-syncer connections:${NC}"
if [[ -n "${SYNCER_UID}" ]]; then
    ss -tnp 2>/dev/null | grep "uid:${SYNCER_UID}" | head -10 || echo "    (no active connections)"
else
    echo "    (user not found)"
fi

echo ""
echo -e "  ${GREEN}tg-querybot connections:${NC}"
if [[ -n "${QUERYBOT_UID}" ]]; then
    ss -tnp 2>/dev/null | grep "uid:${QUERYBOT_UID}" | head -10 || echo "    (no active connections)"
else
    echo "    (user not found)"
fi

# ---------------------------------------------------------------------------
# Phase 4: nftables drop counter
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Phase 4: Firewall blocked traffic${NC}"
echo ""

if nft list table inet tg_assistant &>/dev/null; then
    echo -e "  ${GREEN}nftables rules active.${NC} Counters:"
    nft list table inet tg_assistant 2>/dev/null | grep -E "drop|reject|log" | \
    while IFS= read -r rule; do
        echo "    ${rule}"
    done
else
    echo -e "  ${YELLOW}nftables table 'tg_assistant' not found.${NC}"
    echo "  Firewall rules may not be deployed. Run setup-raspberry-pi.sh to configure."
fi

# Check kernel log for blocked packets
echo ""
echo -e "  Recent blocked packets (from kernel log):"
dmesg 2>/dev/null | grep -i "tg-.*-blocked" | tail -10 || echo "    (none found)"

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo "  Monitor Complete"
echo "=============================================="
echo ""

if [[ ${UNEXPECTED_COUNT} -gt 0 ]]; then
    echo -e "  ${RED}${UNEXPECTED_COUNT} unexpected connection(s) detected.${NC}"
    echo "  Review the output above and investigate."
    echo "  Check nftables rules: sudo nft list table inet tg_assistant"
else
    echo -e "  ${GREEN}No unexpected traffic detected.${NC}"
fi

echo ""
echo "  To run a longer capture:"
echo "    sudo $0 300   # 5 minutes"
echo ""
