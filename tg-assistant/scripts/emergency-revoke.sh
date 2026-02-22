#!/bin/bash
#
# Telegram Personal Assistant - Emergency Credential Revocation
#
# Single script for incident response when compromise is suspected:
# stolen session, leaked API key, breached device, etc.
#
# Modes:
#   --all              Full incident response (default)
#   --session-only     Session compromise: shred session, clear session key
#   --credentials-only API key leak: clear all keychain entries
#
# What this script does NOT do:
#   - It does NOT automatically re-provision credentials or restart services.
#     After revocation, re-run: sudo ./scripts/setup.sh
#   - It does NOT terminate remote Telegram sessions or rotate keys on
#     external services — those require manual action (checklist printed).
#
# Usage: sudo ./scripts/emergency-revoke.sh [--all | --session-only | --credentials-only]
#

set -uo pipefail
# NOTE: -e is intentionally omitted. Each phase uses || log_warn so that
# partial failures do not block the rest of the revocation sequence.

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
phase_header() {
    echo ""
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo -e "${BOLD}${BLUE}  Phase $1: $2${NC}"
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Configuration (matches setup.sh / setup-raspberry-pi.sh)
# ---------------------------------------------------------------------------
CONFIG_DIR="/etc/tg-assistant"
CONFIG_FILE="${CONFIG_DIR}/settings.toml"
LOG_DIR="/var/log/tg-assistant"

SYNCER_USER="tg-syncer"
SYNCER_HOME="/home/${SYNCER_USER}"
SESSION_DIR="${SYNCER_HOME}/.telethon"
SESSION_NAME="tg_syncer_session"
ENCRYPTED_FILE="${SESSION_DIR}/${SESSION_NAME}.session.enc"

DB_NAME="tg_assistant"
DB_SYNCER_USER="tg_syncer"
DB_QUERYBOT_USER="tg_querybot"

INCIDENT_DIR="/root/tg-incident-$(date +%Y%m%d-%H%M%S)"

# Keychain keys (service = tg-assistant)
KEYCHAIN_KEYS=(
    "bot_token"
    "anthropic_api_key"
    "telethon_session_key"
)

# Track what was done for the summary
ACTIONS_TAKEN=()

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
MODE="all"

case "${1:-}" in
    --all)              MODE="all" ;;
    --session-only)     MODE="session" ;;
    --credentials-only) MODE="credentials" ;;
    -h|--help)
        echo "Usage: sudo $0 [--all | --session-only | --credentials-only]"
        echo ""
        echo "  --all              Full incident response (default)"
        echo "  --session-only     Shred session file, clear session key"
        echo "  --credentials-only Clear all API keys from keychain"
        exit 0
        ;;
    "")                 MODE="all" ;;
    *)
        echo "Unknown option: $1"
        echo "Usage: sudo $0 [--all | --session-only | --credentials-only]"
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Display plan and confirm
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${RED}=============================================${NC}"
echo -e "${BOLD}${RED}  EMERGENCY CREDENTIAL REVOCATION${NC}"
echo -e "${BOLD}${RED}=============================================${NC}"
echo ""
echo -e "  Mode: ${BOLD}--${MODE}${NC}"
echo -e "  Time: $(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"
echo ""

case "${MODE}" in
    all)
        echo "  This will:"
        echo "    1. Stop tg-syncer and tg-querybot services"
        echo "    2. Preserve logs and config to ${INCIDENT_DIR}"
        echo "    3. Shred the Telethon session file"
        echo "    4. Clear ALL credentials from the system keychain"
        echo "    5. Rotate database passwords"
        echo "    6. Print external action checklist"
        ;;
    session)
        echo "  This will:"
        echo "    1. Stop tg-syncer service"
        echo "    2. Preserve logs to ${INCIDENT_DIR}"
        echo "    3. Shred the Telethon session file"
        echo "    4. Clear telethon_session_key from keychain"
        ;;
    credentials)
        echo "  This will:"
        echo "    1. Stop tg-syncer and tg-querybot services"
        echo "    2. Clear ALL API keys from the system keychain"
        echo "    3. Print rotation links for each service"
        ;;
esac

echo ""
echo -e "  ${BOLD}${RED}This is destructive and cannot be undone.${NC}"
echo ""
read -rp "  Are you sure? [y/N] " CONFIRM
echo ""

if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
    log_info "Aborted. No changes were made."
    exit 0
fi

log_info "Starting emergency revocation (mode: --${MODE})..."

# =========================================================================
# Phase 1: Stop services
# =========================================================================
phase_stop_services() {
    phase_header 1 "Stop services"

    local services=()
    case "${MODE}" in
        all)        services=(tg-syncer tg-querybot) ;;
        session)    services=(tg-syncer) ;;
        credentials) services=(tg-syncer tg-querybot) ;;
    esac

    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            if systemctl stop "${svc}" 2>/dev/null; then
                log_success "Stopped ${svc}"
                ACTIONS_TAKEN+=("Stopped ${svc}")
            else
                log_warn "Could not stop ${svc} — may need manual intervention"
            fi
        else
            log_info "${svc} is not running"
        fi
    done
}

# =========================================================================
# Phase 2: Preserve forensic evidence
# =========================================================================
phase_preserve_evidence() {
    phase_header 2 "Preserve forensic evidence"

    mkdir -p "${INCIDENT_DIR}"
    chmod 700 "${INCIDENT_DIR}"
    log_success "Created incident directory: ${INCIDENT_DIR}"

    # Copy logs
    if [[ -d "${LOG_DIR}" ]]; then
        cp -a "${LOG_DIR}" "${INCIDENT_DIR}/logs" 2>/dev/null && \
            log_success "Preserved logs from ${LOG_DIR}" || \
            log_warn "Could not copy logs from ${LOG_DIR}"
    else
        log_info "No log directory found at ${LOG_DIR}"
    fi

    # Copy config
    if [[ -f "${CONFIG_FILE}" ]]; then
        cp -a "${CONFIG_FILE}" "${INCIDENT_DIR}/settings.toml" 2>/dev/null && \
            log_success "Preserved config from ${CONFIG_FILE}" || \
            log_warn "Could not copy config"
    else
        log_info "No config file found at ${CONFIG_FILE}"
    fi

    # Copy systemd journal entries for our services
    for svc in tg-syncer tg-querybot; do
        journalctl -u "${svc}" --no-pager -n 500 \
            > "${INCIDENT_DIR}/${svc}-journal.log" 2>/dev/null || true
    done
    log_info "Captured recent systemd journal entries"

    # Record incident metadata
    {
        echo "incident_start=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"
        echo "mode=${MODE}"
        echo "hostname=$(hostname)"
        echo "user=${SUDO_USER:-root}"
    } > "${INCIDENT_DIR}/incident-metadata.txt"
    log_success "Recorded incident metadata"

    ACTIONS_TAKEN+=("Forensic evidence preserved to ${INCIDENT_DIR}")
}

# =========================================================================
# Phase 3: Shred Telethon session
# =========================================================================
phase_shred_session() {
    phase_header 3 "Shred Telethon session"

    local shredded=false

    # Shred the encrypted session file
    if [[ -f "${ENCRYPTED_FILE}" ]]; then
        if shred -u "${ENCRYPTED_FILE}" 2>/dev/null; then
            log_success "Shredded encrypted session: ${ENCRYPTED_FILE}"
            shredded=true
        else
            # Fallback: overwrite then remove
            dd if=/dev/urandom of="${ENCRYPTED_FILE}" bs=1k count=10 2>/dev/null
            rm -f "${ENCRYPTED_FILE}"
            log_warn "Could not shred (filesystem may not support it) — overwrote and removed"
            shredded=true
        fi
    else
        log_info "No encrypted session file found at ${ENCRYPTED_FILE}"
    fi

    # Shred any leftover unencrypted .session files
    if [[ -d "${SESSION_DIR}" ]]; then
        local found_sessions=false
        for f in "${SESSION_DIR}"/*.session; do
            if [[ -f "${f}" ]]; then
                shred -u "${f}" 2>/dev/null || rm -f "${f}"
                log_success "Shredded leftover session: ${f}"
                found_sessions=true
                shredded=true
            fi
        done
        if [[ "${found_sessions}" == false ]]; then
            log_info "No leftover .session files found"
        fi
    fi

    # Shred any .fernet_key.tmp that might have been left from setup
    if [[ -f "${SESSION_DIR}/.fernet_key.tmp" ]]; then
        shred -u "${SESSION_DIR}/.fernet_key.tmp" 2>/dev/null || rm -f "${SESSION_DIR}/.fernet_key.tmp"
        log_success "Shredded leftover Fernet key file"
        shredded=true
    fi

    # Clear the session encryption key from keychain
    if command -v secret-tool &>/dev/null; then
        if secret-tool clear service tg-assistant key telethon_session_key 2>/dev/null; then
            log_success "Cleared telethon_session_key from keychain"
        else
            log_info "telethon_session_key not found in keychain (already cleared or never set)"
        fi
    else
        log_warn "secret-tool not available — cannot clear keychain entries"
    fi

    if [[ "${shredded}" == true ]]; then
        ACTIONS_TAKEN+=("Shredded Telethon session files")
    fi
    ACTIONS_TAKEN+=("Cleared session encryption key from keychain")
}

# =========================================================================
# Phase 4: Clear keychain credentials
# =========================================================================
phase_clear_keychain() {
    phase_header 4 "Clear keychain credentials"

    if ! command -v secret-tool &>/dev/null; then
        log_warn "secret-tool not available — cannot clear keychain entries"
        log_warn "If credentials were stored as environment variables, clear them manually"
        return
    fi

    for key in "${KEYCHAIN_KEYS[@]}"; do
        if secret-tool clear service tg-assistant key "${key}" 2>/dev/null; then
            log_success "Cleared ${key} from keychain"
        else
            log_info "${key} not found in keychain (already cleared or never set)"
        fi
    done

    # Also shred encrypted credstore entries (systemd-creds)
    if [[ -d /etc/credstore.encrypted ]]; then
        for f in /etc/credstore.encrypted/*; do
            if [[ -f "${f}" ]]; then
                shred -u "${f}" 2>/dev/null || rm -f "${f}"
                log_success "Shredded credstore entry: $(basename "${f}")"
            fi
        done
    fi

    # Also clear any temp credential files
    if [[ -f "${CONFIG_DIR}/.db_credentials" ]]; then
        shred -u "${CONFIG_DIR}/.db_credentials" 2>/dev/null || rm -f "${CONFIG_DIR}/.db_credentials"
        log_success "Shredded ${CONFIG_DIR}/.db_credentials"
    fi

    ACTIONS_TAKEN+=("Cleared all keychain credentials")
}

# =========================================================================
# Phase 5: Rotate database passwords
# =========================================================================
phase_rotate_db_passwords() {
    phase_header 5 "Rotate database passwords"

    # Check if PostgreSQL is running
    if ! command -v psql &>/dev/null; then
        log_warn "psql not found — skipping database password rotation"
        log_warn "Rotate DB passwords manually when PostgreSQL is available"
        return
    fi

    if ! sudo -u postgres psql -c "SELECT 1" &>/dev/null; then
        log_warn "Cannot connect to PostgreSQL — skipping password rotation"
        log_warn "Rotate DB passwords manually when PostgreSQL is available"
        return
    fi

    local new_syncer_pass new_querybot_pass
    new_syncer_pass="$(openssl rand -base64 24)"
    new_querybot_pass="$(openssl rand -base64 24)"

    # Rotate syncer password
    if sudo -u postgres psql -c "ALTER ROLE ${DB_SYNCER_USER} PASSWORD '${new_syncer_pass//\'/\'\'}'" "${DB_NAME}" 2>/dev/null; then
        log_success "Rotated password for DB role ${DB_SYNCER_USER}"
    else
        log_warn "Could not rotate password for ${DB_SYNCER_USER}"
    fi

    # Rotate querybot password
    if sudo -u postgres psql -c "ALTER ROLE ${DB_QUERYBOT_USER} PASSWORD '${new_querybot_pass//\'/\'\'}'" "${DB_NAME}" 2>/dev/null; then
        log_success "Rotated password for DB role ${DB_QUERYBOT_USER}"
    else
        log_warn "Could not rotate password for ${DB_QUERYBOT_USER}"
    fi

    # Update settings.toml with new passwords
    if [[ -f "${CONFIG_FILE}" ]]; then
        # Replace syncer password line
        if grep -q "syncer_password" "${CONFIG_FILE}" 2>/dev/null; then
            sed -i "s|syncer_password = \".*\"|syncer_password = \"${new_syncer_pass}\"|" "${CONFIG_FILE}"
            log_success "Updated syncer_password in ${CONFIG_FILE}"
        fi

        # Replace querybot password line
        if grep -q "querybot_password" "${CONFIG_FILE}" 2>/dev/null; then
            sed -i "s|querybot_password = \".*\"|querybot_password = \"${new_querybot_pass}\"|" "${CONFIG_FILE}"
            log_success "Updated querybot_password in ${CONFIG_FILE}"
        fi
    else
        log_warn "Config file not found at ${CONFIG_FILE} — new passwords not persisted"
        log_warn "You will need to set passwords manually during re-setup"
    fi

    # Clear passwords from shell variables
    new_syncer_pass="REDACTED"
    new_querybot_pass="REDACTED"

    ACTIONS_TAKEN+=("Rotated database passwords for ${DB_SYNCER_USER} and ${DB_QUERYBOT_USER}")
}

# =========================================================================
# Phase 6: External action checklist
# =========================================================================
phase_print_checklist() {
    echo ""
    echo -e "${BOLD}${RED}=============================================${NC}"
    echo -e "${BOLD}${RED}  MANUAL ACTIONS REQUIRED${NC}"
    echo -e "${BOLD}${RED}=============================================${NC}"
    echo ""
    echo "  The following actions CANNOT be automated and must be"
    echo "  completed by you immediately:"
    echo ""

    case "${MODE}" in
        all)
            echo "  [ ] Terminate ALL Telegram sessions:"
            echo "        Telegram > Settings > Devices > Terminate All Other Sessions"
            echo ""
            echo "  [ ] Change your Telegram 2FA password:"
            echo "        Telegram > Settings > Privacy > Two-Step Verification"
            echo ""
            echo "  [ ] Revoke bot token:"
            echo "        Message @BotFather > /revoke > select your bot"
            echo ""
            echo "  [ ] Rotate Anthropic API key:"
            echo "        https://console.anthropic.com/settings/keys"
            echo "        Delete the compromised key and create a new one"
            echo ""
            echo "  [ ] Review Telegram login activity for unauthorized access"
            echo ""
            echo "  [ ] After completing ALL of the above, re-provision:"
            echo "        sudo ./scripts/setup.sh"
            ;;
        session)
            echo "  [ ] Terminate ALL Telegram sessions:"
            echo "        Telegram > Settings > Devices > Terminate All Other Sessions"
            echo ""
            echo "  [ ] Change your Telegram 2FA password:"
            echo "        Telegram > Settings > Privacy > Two-Step Verification"
            echo ""
            echo "  [ ] Review Telegram login activity for unauthorized access"
            echo ""
            echo "  [ ] After completing the above, recreate the session:"
            echo "        sudo ./scripts/setup-telethon-session.sh"
            ;;
        credentials)
            echo "  [ ] Revoke bot token:"
            echo "        Message @BotFather > /revoke > select your bot"
            echo ""
            echo "  [ ] Rotate Anthropic API key:"
            echo "        https://console.anthropic.com/settings/keys"
            echo ""
            echo "  [ ] Rotate Telegram API hash:"
            echo "        https://my.telegram.org > API development tools"
            echo ""
            echo "  [ ] After completing ALL of the above, re-provision:"
            echo "        sudo ./scripts/setup.sh"
            ;;
    esac

    echo ""
}

# =========================================================================
# Phase 7: Summary
# =========================================================================
phase_summary() {
    echo -e "${BOLD}${GREEN}=============================================${NC}"
    echo -e "${BOLD}${GREEN}  REVOCATION COMPLETE${NC}"
    echo -e "${BOLD}${GREEN}=============================================${NC}"
    echo ""
    echo -e "${BOLD}Actions taken locally:${NC}"
    for action in "${ACTIONS_TAKEN[@]}"; do
        echo "  - ${action}"
    done
    echo ""

    if [[ -d "${INCIDENT_DIR}" ]]; then
        echo -e "${BOLD}Forensic evidence:${NC}"
        echo "  ${INCIDENT_DIR}/"
        echo ""
    fi

    echo -e "${BOLD}Services status:${NC}"
    echo "  tg-syncer and tg-querybot are STOPPED."
    echo "  They will NOT restart automatically."
    echo ""

    echo -e "${BOLD}${YELLOW}Next steps:${NC}"
    echo "  1. Complete ALL items in the manual action checklist above"
    echo "  2. Re-provision with fresh credentials: sudo ./scripts/setup.sh"
    echo "  3. Verify services are working: systemctl status tg-syncer tg-querybot"
    echo ""
}

# =========================================================================
# Main — execute phases based on mode
# =========================================================================
main() {
    case "${MODE}" in
        all)
            phase_stop_services
            phase_preserve_evidence
            phase_shred_session
            phase_clear_keychain
            phase_rotate_db_passwords
            phase_print_checklist
            phase_summary
            ;;
        session)
            phase_stop_services
            phase_preserve_evidence
            phase_shred_session
            phase_print_checklist
            phase_summary
            ;;
        credentials)
            phase_stop_services
            phase_clear_keychain
            phase_print_checklist
            phase_summary
            ;;
    esac
}

main
