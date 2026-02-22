#!/bin/bash
#
# Telegram Personal Assistant - Credential Wipe
#
# Removes ALL credentials, sessions, and sensitive state from the system.
# After running this, the Pi is clean — as if setup was never run.
#
# What this removes:
#   - Encrypted credentials in /etc/credstore.encrypted/
#   - Telethon session files (encrypted + any plaintext leftovers)
#   - System keychain entries (secret-tool / libsecret)
#   - Fernet key temp files (if shred failed during setup)
#   - PostgreSQL roles and database
#   - Log files (may contain metadata)
#   - Systemd service state (stopped + disabled)
#
# What this does NOT remove:
#   - System users (tg-syncer, tg-querybot) — harmless, no login shell
#   - Python venv and source code at /opt/tg-assistant/
#   - nftables rules — harmless when services aren't running
#   - System packages (postgresql, python3, etc.)
#
# After running this, you can re-run setup.sh for a fresh deployment.
#
# IMPORTANT: This does NOT terminate the Telethon session on Telegram's
# servers. To fully revoke access, also go to:
#   Telegram > Settings > Devices > Terminate the session manually
#
# Usage: sudo ./scripts/wipe-credentials.sh
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
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)."
    exit 1
fi

echo ""
echo "=============================================="
echo -e "  ${BOLD}${RED}Credential Wipe${NC}"
echo "=============================================="
echo ""
echo "  This will PERMANENTLY DESTROY all credentials and sessions."
echo "  You will need to re-run setup.sh to use the system again."
echo ""
echo -e "  ${YELLOW}REMINDER: Also terminate the Telethon session manually:${NC}"
echo "    Telegram > Settings > Devices > Terminate session"
echo ""
echo "----------------------------------------------"
echo ""

read -rp "  Type 'WIPE' to confirm: " CONFIRM
if [[ "${CONFIRM}" != "WIPE" ]]; then
    echo ""
    log_info "Aborted. Nothing was changed."
    exit 0
fi

echo ""

# ---------------------------------------------------------------------------
# 1. Stop and disable services
# ---------------------------------------------------------------------------
log_info "Stopping services..."

for SVC in tg-syncer tg-querybot; do
    if systemctl is-active --quiet "${SVC}" 2>/dev/null; then
        systemctl stop "${SVC}"
        log_success "Stopped ${SVC}"
    fi
    if systemctl is-enabled --quiet "${SVC}" 2>/dev/null; then
        systemctl disable "${SVC}" 2>/dev/null
        log_success "Disabled ${SVC}"
    fi
done

# Reset failed state so services don't show as errored
systemctl reset-failed tg-syncer 2>/dev/null || true
systemctl reset-failed tg-querybot 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Shred encrypted credentials (credstore)
# ---------------------------------------------------------------------------
log_info "Wiping encrypted credentials..."

if [[ -d /etc/credstore.encrypted ]]; then
    for f in /etc/credstore.encrypted/*; do
        if [[ -f "${f}" ]]; then
            shred -u "${f}" 2>/dev/null || rm -f "${f}"
            log_success "Shredded $(basename "${f}")"
        fi
    done
    rmdir /etc/credstore.encrypted 2>/dev/null || true
fi

# Also check legacy plaintext credstore
if [[ -d /etc/credstore ]]; then
    for f in /etc/credstore/*; do
        if [[ -f "${f}" ]]; then
            shred -u "${f}" 2>/dev/null || rm -f "${f}"
            log_success "Shredded plaintext $(basename "${f}")"
        fi
    done
    rmdir /etc/credstore 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 3. Shred Telethon session files
# ---------------------------------------------------------------------------
log_info "Wiping Telethon session files..."

for DIR in /var/lib/tg-syncer /home/tg-syncer/.telethon; do
    if [[ -d "${DIR}" ]]; then
        # Shred all session-related files
        for f in "${DIR}"/*.session "${DIR}"/*.session.enc "${DIR}"/*.session-journal "${DIR}"/.fernet_key.tmp; do
            if [[ -f "${f}" ]]; then
                shred -u "${f}" 2>/dev/null || rm -f "${f}"
                log_success "Shredded $(basename "${f}")"
            fi
        done
        # Clean up any verify files left from failed setup
        for f in "${DIR}"/_verify_session "${DIR}"/_verify_session.session; do
            if [[ -f "${f}" ]]; then
                shred -u "${f}" 2>/dev/null || rm -f "${f}"
                log_success "Shredded $(basename "${f}")"
            fi
        done
    fi
done

# ---------------------------------------------------------------------------
# 4. Remove system keychain entries
# ---------------------------------------------------------------------------
log_info "Removing keychain entries..."

if command -v secret-tool &>/dev/null; then
    for KEY in bot_token anthropic_api_key session_encryption_key \
               tg-assistant-bot-token tg-assistant-claude-api-key; do
        # timeout prevents hanging on headless systems where the keyring
        # daemon is unavailable or waiting for interactive authentication.
        if timeout 5 secret-tool lookup service tg-assistant key "${KEY}" &>/dev/null; then
            timeout 5 secret-tool clear service tg-assistant key "${KEY}" 2>/dev/null || true
            log_success "Removed keychain entry: ${KEY}"
        fi
    done
else
    log_info "secret-tool not found — skipping keychain cleanup"
fi

# ---------------------------------------------------------------------------
# 5. Drop PostgreSQL database and roles
# ---------------------------------------------------------------------------
log_info "Removing PostgreSQL database and roles..."

if command -v psql &>/dev/null && systemctl is-active --quiet postgresql 2>/dev/null; then
    # Drop database first (roles can't be dropped while they own objects)
    if sudo -u postgres psql -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw tg_assistant; then
        sudo -u postgres psql -c "DROP DATABASE tg_assistant;" 2>/dev/null && \
            log_success "Dropped database tg_assistant" || \
            log_warn "Could not drop database tg_assistant"
    fi

    for ROLE in tg_syncer tg_querybot; do
        if sudo -u postgres psql -c "\du" 2>/dev/null | grep -qw "${ROLE}"; then
            sudo -u postgres psql -c "DROP ROLE ${ROLE};" 2>/dev/null && \
                log_success "Dropped role ${ROLE}" || \
                log_warn "Could not drop role ${ROLE}"
        fi
    done

    # Remove peer auth entries from pg_hba.conf and pg_ident.conf
    HBA_FILE=$(sudo -u postgres psql -qAt -c "SHOW hba_file" 2>/dev/null)
    IDENT_FILE=$(sudo -u postgres psql -qAt -c "SHOW ident_file" 2>/dev/null)

    # Fallback to standard Debian path
    if [[ -z "${HBA_FILE}" || -z "${IDENT_FILE}" ]]; then
        PG_VERSION=$(ls /etc/postgresql/ 2>/dev/null | head -1)
        PG_CONF="/etc/postgresql/${PG_VERSION}/main"
        HBA_FILE="${HBA_FILE:-${PG_CONF}/pg_hba.conf}"
        IDENT_FILE="${IDENT_FILE:-${PG_CONF}/pg_ident.conf}"
    fi

    if [[ -f "${HBA_FILE}" ]]; then
        sed -i '/tg_syncer.*peer.*tg-assistant/d' "${HBA_FILE}"
        sed -i '/tg_querybot.*peer.*tg-assistant/d' "${HBA_FILE}"
        log_success "Removed peer auth rules from pg_hba.conf"
    fi

    if [[ -f "${IDENT_FILE}" ]]; then
        sed -i '/tg-assistant/d' "${IDENT_FILE}"
        log_success "Removed identity mappings from pg_ident.conf"
    fi

    systemctl reload postgresql 2>/dev/null || true
else
    log_warn "PostgreSQL not running — skipping database cleanup"
fi

# ---------------------------------------------------------------------------
# 6. Clear log files (may contain query metadata)
# ---------------------------------------------------------------------------
log_info "Clearing log files..."

if [[ -d /var/log/tg-assistant ]]; then
    find /var/log/tg-assistant -type f -exec shred -u {} \; 2>/dev/null || \
        rm -rf /var/log/tg-assistant/*
    log_success "Log files cleared"
fi

# ---------------------------------------------------------------------------
# 7. Reset settings.toml to defaults (remove injected values)
# ---------------------------------------------------------------------------
log_info "Resetting configuration..."

CONFIG_FILE="/etc/tg-assistant/settings.toml"
if [[ -f "${CONFIG_FILE}" ]]; then
    # Reset owner_telegram_id to placeholder
    sed -i 's/^owner_telegram_id = [0-9]*/owner_telegram_id = 0/' "${CONFIG_FILE}" 2>/dev/null
    # Reset API credentials to placeholders
    sed -i 's/^api_id = [0-9]*/api_id = YOUR_API_ID/' "${CONFIG_FILE}" 2>/dev/null
    sed -i 's/^api_hash = "[^"]*"/api_hash = "YOUR_API_HASH"/' "${CONFIG_FILE}" 2>/dev/null
    log_success "Configuration reset to defaults"
fi

# ---------------------------------------------------------------------------
# 8. Clear terminal scrollback reminder
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo -e "  ${GREEN}Credential Wipe Complete${NC}"
echo "=============================================="
echo ""
echo "  Destroyed:"
echo "    - Encrypted credentials (credstore)"
echo "    - Telethon session files"
echo "    - Keychain entries"
echo "    - PostgreSQL database + roles + auth rules"
echo "    - Log files"
echo "    - Config values (reset to placeholders)"
echo ""
echo -e "  ${BOLD}${YELLOW}Manual steps remaining:${NC}"
echo ""
echo "    1. Terminate the Telethon session on Telegram's servers:"
echo "       Telegram > Settings > Devices > Terminate session"
echo ""
echo "    2. Clear your terminal scrollback (credentials may be visible):"
echo "       Press Ctrl+L, then run: clear && history -c"
echo ""
echo "    3. If you entered credentials via SSH, clear that terminal too."
echo ""
echo "  To redeploy: sudo ./scripts/setup.sh"
echo ""
