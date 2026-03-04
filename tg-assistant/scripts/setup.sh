#!/bin/bash
#
# Telelocal - Unified Setup
#
# Single guided script that handles the entire deployment:
#   Phase 1: Pre-flight checks
#   Phase 2: System setup (deps, Python, PostgreSQL, users, dirs, services)
#   Phase 3: Credential collection (all prompts in one block)
#   Phase 4: Configure settings.toml
#   Phase 5: Telethon session creation (interactive)
#   Phase 6: Security verification
#   Phase 7: Service activation
#
# For granular control, use setup-raspberry-pi.sh and setup-telethon-session.sh
# individually instead.
#
# Usage: sudo ./scripts/setup.sh
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
phase_header() {
    echo ""
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo -e "${BOLD}${BLUE}  [$1/7] $2${NC}"
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTALL_DIR="/opt/tg-assistant"
CONFIG_DIR="/etc/tg-assistant"
LOG_DIR="/var/log/tg-assistant"
VENV_DIR="${INSTALL_DIR}/venv"

SYNCER_USER="tg-syncer"
QUERYBOT_USER="tg-querybot"
SYNCER_HOME="/home/${SYNCER_USER}"
QUERYBOT_HOME="/home/${QUERYBOT_USER}"

SESSION_DIR="/var/lib/tg-syncer"
SESSION_NAME="tg_syncer_session"
SESSION_FILE="${SESSION_DIR}/${SESSION_NAME}.session"
ENCRYPTED_FILE="${SESSION_DIR}/${SESSION_NAME}.session.enc"

DB_NAME="tg_assistant"
DB_SYNCER_USER="tg_syncer"
DB_QUERYBOT_USER="tg_querybot"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo ""
echo "=============================================="
echo "  Telelocal"
echo "  Unified Setup"
echo "=============================================="
echo ""
echo "  This script will guide you through the entire deployment."
echo "  You will be prompted for credentials partway through."
echo "  The full process takes 15-20 minutes."
echo ""
echo "----------------------------------------------"

# =========================================================================
# Phase 1: Pre-flight
# =========================================================================
phase_preflight() {
    phase_header 1 "Pre-flight checks"

    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)."
        exit 1
    fi

    if [[ -f /proc/device-tree/model ]]; then
        MODEL=$(tr -d '\0' < /proc/device-tree/model)
        log_info "Detected: ${MODEL}"
    else
        log_warn "Not running on Raspberry Pi -- proceeding in development mode"
    fi

    ARCH=$(uname -m)
    if [[ "${ARCH}" != "aarch64" && "${ARCH}" != "arm64" ]]; then
        log_warn "Architecture is ${ARCH} -- 64-bit ARM recommended"
    fi

    # Internet check
    if curl -sf --max-time 5 https://api.telegram.org > /dev/null 2>&1; then
        log_success "Internet connectivity verified"
    else
        log_warn "Could not reach api.telegram.org -- some steps may fail"
    fi

    log_success "Pre-flight checks complete"
}

# =========================================================================
# Phase 2: System setup
# =========================================================================
phase_system_setup() {
    phase_header 2 "System setup"

    log_info "This phase installs system packages, Python, PostgreSQL, pgvector,"
    log_info "creates system users, directories, venv, and deploys config/services."
    echo ""

    # Run the existing setup-raspberry-pi.sh which handles all of this
    # and is already idempotent (checks for existing users, DB, etc.)
    bash "${SCRIPT_DIR}/setup-raspberry-pi.sh"

    log_success "System setup complete"
}

# =========================================================================
# Phase 3: Credential collection
# =========================================================================
phase_collect_credentials() {
    phase_header 3 "Credential collection"

    echo "  You will now be prompted for all required credentials."
    echo "  Have these ready (see docs/QUICKSTART.md for links):"
    echo ""
    echo "    1. Telegram API ID + hash   -> https://my.telegram.org"
    echo "    2. Bot token                 -> @BotFather on Telegram"
    echo "    3. Anthropic API key         -> https://console.anthropic.com"
    echo "    4. Your Telegram user ID     -> @userinfobot on Telegram"
    echo ""
    echo "----------------------------------------------"
    echo ""

    # --- Telegram API credentials ---
    echo -e "${BOLD}Telegram API credentials${NC}"
    echo "  Get these from https://my.telegram.org > API development tools"
    echo ""
    read -rp "  API ID (numeric): " COLLECT_API_ID
    read -rsp "  API hash (hex string): " COLLECT_API_HASH
    echo ""  # newline after silent input

    if [[ -z "${COLLECT_API_ID}" || -z "${COLLECT_API_HASH}" ]]; then
        log_error "API ID and API hash are required."
        exit 1
    fi

    if ! [[ "${COLLECT_API_ID}" =~ ^[0-9]+$ ]]; then
        log_error "API ID must be a number."
        exit 1
    fi

    if ! [[ "${COLLECT_API_HASH}" =~ ^[0-9a-fA-F]{32}$ ]]; then
        log_error "API hash must be a 32-character hex string."
        exit 1
    fi

    # --- Bot token ---
    echo -e "${BOLD}Bot token${NC}"
    echo "  Get this from @BotFather on Telegram (send /newbot)"
    echo ""
    read -rsp "  Bot token: " COLLECT_BOT_TOKEN
    echo ""  # newline after silent input

    if [[ -z "${COLLECT_BOT_TOKEN}" ]]; then
        log_error "Bot token is required."
        exit 1
    fi

    # --- Anthropic API key ---
    echo -e "${BOLD}Anthropic API key${NC}"
    echo "  Get this from https://console.anthropic.com/settings/keys"
    echo ""
    read -rsp "  Anthropic API key: " COLLECT_ANTHROPIC_KEY
    echo ""  # newline after silent input

    if [[ -z "${COLLECT_ANTHROPIC_KEY}" ]]; then
        log_error "Anthropic API key is required."
        exit 1
    fi

    # --- Owner Telegram ID ---
    echo -e "${BOLD}Your Telegram user ID${NC}"
    echo "  Message @userinfobot on Telegram to get your numeric ID."
    echo "  The bot will ONLY respond to this user."
    echo ""
    read -rp "  Owner Telegram ID (numeric): " COLLECT_OWNER_ID
    echo ""

    if [[ -z "${COLLECT_OWNER_ID}" ]]; then
        log_error "Owner Telegram ID is required."
        exit 1
    fi

    if ! [[ "${COLLECT_OWNER_ID}" =~ ^[0-9]+$ ]]; then
        log_error "Owner Telegram ID must be a number."
        exit 1
    fi

    # --- Encrypt credentials with systemd-creds (encrypted at rest) ---
    echo "----------------------------------------------"
    echo ""
    log_info "Encrypting credentials with systemd-creds..."
    echo ""

    # Create encrypted credstore directory (root:root, mode 700)
    mkdir -p /etc/credstore.encrypted
    chmod 700 /etc/credstore.encrypted
    chown root:root /etc/credstore.encrypted

    if ! command -v systemd-creds &>/dev/null; then
        log_error "systemd-creds not found. Requires systemd 250+."
        log_error "Check: systemctl --version"
        exit 1
    fi

    # Encrypt each credential with systemd-creds.
    # --name binds the blob to a specific credential name (prevents swapping).
    # The encrypted blob is stored on disk; plaintext exists only in RAM
    # when systemd decrypts it at service start via LoadCredentialEncrypted=.
    _encrypt_credential() {
        local name="$1" value="$2"
        printf '%s' "${value}" | systemd-creds encrypt --name="${name}" - "/etc/credstore.encrypted/${name}"
        chmod 600 "/etc/credstore.encrypted/${name}"
        chown root:root "/etc/credstore.encrypted/${name}"
        log_success "Encrypted credential: ${name}"
    }

    _encrypt_credential "tg-assistant-bot-token" "${COLLECT_BOT_TOKEN}"
    _encrypt_credential "tg-assistant-claude-api-key" "${COLLECT_ANTHROPIC_KEY}"
    _encrypt_credential "tg-assistant-api-id" "${COLLECT_API_ID}"
    _encrypt_credential "tg-assistant-api-hash" "${COLLECT_API_HASH}"

    log_success "Credential collection complete"
}

# =========================================================================
# Phase 4: Configure settings.toml
# =========================================================================
phase_configure() {
    phase_header 4 "Configure settings.toml"

    CONFIG_FILE="${CONFIG_DIR}/settings.toml"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Config file not found at ${CONFIG_FILE}"
        log_info "Phase 2 should have deployed it. Skipping configuration."
        return
    fi

    # Inject owner_telegram_id
    if grep -q "OWNER_ID_PLACEHOLDER" "${CONFIG_FILE}" 2>/dev/null; then
        sed -i "s|OWNER_ID_PLACEHOLDER|${COLLECT_OWNER_ID}|g" "${CONFIG_FILE}"
        log_success "Owner Telegram ID set to ${COLLECT_OWNER_ID}"
    elif grep -q 'owner_telegram_id = 0' "${CONFIG_FILE}" 2>/dev/null; then
        sed -i "s|owner_telegram_id = 0|owner_telegram_id = ${COLLECT_OWNER_ID}|g" "${CONFIG_FILE}"
        log_success "Owner Telegram ID set to ${COLLECT_OWNER_ID}"
    else
        log_info "owner_telegram_id already configured"
    fi

    # NOTE: API ID/hash are stored in systemd credstore; config is left as placeholders.
    # NOTE: Chat scope configuration (include_chat_types + per-chat exclusions) is
    #       handled in Phase 7 after the Telethon session is live, so all chat
    #       selection happens in one place.

    log_success "Configuration updated"
}

# =========================================================================
# Phase 5: Telethon session
# =========================================================================
phase_telethon_session() {
    phase_header 5 "Telethon session creation"

    echo -e "  ${BOLD}${RED}Security note:${NC} The Telethon session grants FULL access to"
    echo "  your Telegram account. It will be encrypted and stored securely."
    echo ""
    echo "  You will be prompted for:"
    echo "    - Your phone number"
    echo "    - A verification code (sent to your Telegram)"
    echo "    - Your 2FA password (if enabled)"
    echo ""
    echo "----------------------------------------------"
    echo ""

    if [[ ! -d "${VENV_DIR}" ]]; then
        log_error "Virtual environment not found at ${VENV_DIR}."
        log_error "Phase 2 may have failed. Fix and re-run."
        return 1
    fi

    # Ensure session directory exists
    mkdir -p "${SESSION_DIR}"
    chown "${SYNCER_USER}:${SYNCER_USER}" "${SESSION_DIR}"
    chmod 700 "${SESSION_DIR}"

    # Write a temporary Python script for session creation
    TEMP_SCRIPT=$(mktemp /tmp/create_session_XXXXXX.py)
    chmod 600 "${TEMP_SCRIPT}"

    cat > "${TEMP_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""Create a Telethon session, encrypt it, and verify it works."""
import asyncio
import os
import sys

from telethon import TelegramClient
from cryptography.fernet import Fernet


async def main():
    api_id = int(os.environ["TG_API_ID"])
    api_hash = os.environ["TG_API_HASH"]
    session_dir = os.environ["SESSION_DIR"]
    session_name = os.environ["SESSION_NAME"]
    encrypted_path = os.environ["ENCRYPTED_FILE"]

    session_path = os.path.join(session_dir, session_name)

    print("\n  Connecting to Telegram...\n")

    client = TelegramClient(session_path, api_id, api_hash)
    await client.start()

    me = await client.get_me()
    print(f"\n  Authenticated as: {me.first_name} (@{me.username or 'no username'})")
    print(f"  User ID: {me.id}")

    await client.disconnect()

    # Encrypt the session file
    raw_session_file = session_path + ".session"
    if not os.path.exists(raw_session_file):
        candidates = [session_path, session_path + ".session"]
        raw_session_file = None
        for c in candidates:
            if os.path.exists(c):
                raw_session_file = c
                break
        if raw_session_file is None:
            print(f"\n  ERROR: Could not find session file in {session_dir}")
            sys.exit(1)

    print(f"\n  Encrypting session file: {raw_session_file}")

    fernet_key = Fernet.generate_key()
    cipher = Fernet(fernet_key)

    with open(raw_session_file, "rb") as f:
        raw_data = f.read()

    encrypted_data = cipher.encrypt(raw_data)

    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    os.remove(raw_session_file)
    print(f"  Encrypted session saved to: {encrypted_path}")
    print(f"  Unencrypted session file removed.")

    # Write the Fernet key to a temp file for the shell script to encrypt
    # with systemd-creds. The temp file is shredded immediately after.
    key_tmp = os.path.join(session_dir, ".fernet_key.tmp")
    with open(key_tmp, "w") as f:
        f.write(fernet_key.decode())
    os.chmod(key_tmp, 0o600)
    print(f"  Fernet key written to temp file (will be encrypted + shredded).")

    # Verify the encrypted session works
    print("\n  Verifying encrypted session can be decrypted and used...")

    try:
        with open(encrypted_path, "rb") as f:
            enc_data = f.read()

        decrypted_data = cipher.decrypt(enc_data)

        # Telethon appends ".session" to the path, so we must match that.
        verify_base = os.path.join(session_dir, "_verify_session")
        verify_file = verify_base + ".session"
        with open(verify_file, "wb") as f:
            f.write(decrypted_data)

        verify_client = TelegramClient(verify_base, api_id, api_hash)
        await verify_client.connect()
        verify_me = await verify_client.get_me()

        if verify_me and verify_me.id == me.id:
            print(f"  Verification PASSED: session decrypts and authenticates correctly.")
        else:
            print(f"  Verification FAILED: decrypted session returned unexpected identity.")
            sys.exit(1)

        await verify_client.disconnect()

        for p in (verify_file, verify_base):
            if os.path.exists(p):
                os.remove(p)

    except Exception as e:
        print(f"  Verification FAILED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
PYEOF

    export TG_API_ID="${COLLECT_API_ID}"
    export TG_API_HASH="${COLLECT_API_HASH}"
    export SESSION_DIR="${SESSION_DIR}"
    export SESSION_NAME="${SESSION_NAME}"
    export ENCRYPTED_FILE="${ENCRYPTED_FILE}"

    if "${VENV_DIR}/bin/python" "${TEMP_SCRIPT}"; then
        # Clean up temp script
        shred -u "${TEMP_SCRIPT}" 2>/dev/null || rm -f "${TEMP_SCRIPT}"

        # Set file permissions
        chown "${SYNCER_USER}:${SYNCER_USER}" "${ENCRYPTED_FILE}"
        chmod 600 "${ENCRYPTED_FILE}"
        chown "${SYNCER_USER}:${SYNCER_USER}" "${SESSION_DIR}"
        chmod 700 "${SESSION_DIR}"

        # Clean up any leftover unencrypted session files
        for f in "${SESSION_DIR}"/*.session; do
            if [[ -f "${f}" && "${f}" != "${ENCRYPTED_FILE}" ]]; then
                log_warn "Removing leftover unencrypted session file: ${f}"
                shred -u "${f}" 2>/dev/null || rm -f "${f}"
            fi
        done

        # Encrypt the Fernet key with systemd-creds and shred the temp file
        KEY_TMP="${SESSION_DIR}/.fernet_key.tmp"
        if [[ -f "${KEY_TMP}" ]]; then
            log_info "Encrypting session key with systemd-creds..."
            systemd-creds encrypt --name=session_encryption_key \
                "${KEY_TMP}" /etc/credstore.encrypted/session_encryption_key
            chmod 600 /etc/credstore.encrypted/session_encryption_key
            chown root:root /etc/credstore.encrypted/session_encryption_key
            log_success "Session key encrypted in credstore"

            # Shred the plaintext temp file
            shred -u "${KEY_TMP}" 2>/dev/null || rm -f "${KEY_TMP}"
            log_success "Plaintext key file shredded"
        else
            log_error "Fernet key temp file not found — session key NOT stored"
            return 1
        fi

        log_success "Telethon session created and encrypted"
    else
        shred -u "${TEMP_SCRIPT}" 2>/dev/null || rm -f "${TEMP_SCRIPT}"
        log_error "Telethon session creation failed."
        log_warn "You can retry this step later with: sudo ./scripts/setup-telethon-session.sh"
        return 1
    fi

    # Clear sensitive variables from environment
    unset TG_API_ID TG_API_HASH
}

# =========================================================================
# Phase 6: Security verification
# =========================================================================
phase_security_verification() {
    phase_header 6 "Security verification"

    SECURITY_SCRIPT="${PROJECT_ROOT}/tests/security-verification.sh"

    if [[ -f "${SECURITY_SCRIPT}" ]]; then
        log_info "Running security verification tests..."
        echo ""

        # Run but don't abort the whole setup if some checks fail
        # (e.g., nftables may not be active yet)
        if bash "${SECURITY_SCRIPT}"; then
            log_success "All security checks passed"
        else
            log_warn "Some security checks failed or had warnings."
            log_warn "Review the output above. Non-critical issues can be fixed later."
        fi
    else
        log_warn "Security verification script not found at ${SECURITY_SCRIPT}"
        log_info "Skipping -- run it manually after setup."
    fi
}

# =========================================================================
# Phase 7: Service activation
# =========================================================================
phase_service_activation() {
    phase_header 7 "Service activation"

    # Enable services
    SERVICES_ENABLED=true
    for SVC in tg-syncer tg-querybot; do
        if [[ -f "/etc/systemd/system/${SVC}.service" ]]; then
            systemctl enable "${SVC}" 2>/dev/null && \
                log_success "Enabled ${SVC}" || \
                { log_warn "Could not enable ${SVC}"; SERVICES_ENABLED=false; }
        else
            log_warn "${SVC}.service not found -- skipping"
            SERVICES_ENABLED=false
        fi
    done

    if [[ "${SERVICES_ENABLED}" == false ]]; then
        log_warn "Not all services could be enabled. You may need to deploy"
        log_warn "systemd service files manually (check systemd/ directory)."
        return
    fi

    # --- Chat type scope ---
    CONFIG_FILE="${CONFIG_DIR}/settings.toml"
    echo ""
    echo -e "${BOLD}Chat ingestion scope${NC}"
    echo "  Choose which chat types to sync. Group chats are always included."
    echo ""
    read -rp "  Exclude channels from ingestion? [y/N] " EXCLUDE_CHANNELS
    read -rp "  Exclude direct user DMs from ingestion? [y/N] " EXCLUDE_USERS

    INCLUDE_CHAT_TYPES=("group")
    if [[ ! "${EXCLUDE_CHANNELS}" =~ ^[Yy] ]]; then
        INCLUDE_CHAT_TYPES+=("channel")
    fi
    if [[ ! "${EXCLUDE_USERS}" =~ ^[Yy] ]]; then
        INCLUDE_CHAT_TYPES+=("user")
    fi

    INCLUDE_CHAT_TYPES_TOML="["
    for i in "${!INCLUDE_CHAT_TYPES[@]}"; do
        if [[ "${i}" -gt 0 ]]; then
            INCLUDE_CHAT_TYPES_TOML+=", "
        fi
        INCLUDE_CHAT_TYPES_TOML+="\"${INCLUDE_CHAT_TYPES[$i]}\""
    done
    INCLUDE_CHAT_TYPES_TOML+="]"

    if grep -q '^include_chat_types' "${CONFIG_FILE}" 2>/dev/null; then
        sed -i -E "s|^include_chat_types\\s*=\\s*\\[[^]]*\\]|include_chat_types = ${INCLUDE_CHAT_TYPES_TOML}|g" "${CONFIG_FILE}"
    else
        sed -i "/^max_active_chats/a include_chat_types = ${INCLUDE_CHAT_TYPES_TOML}" "${CONFIG_FILE}"
    fi
    log_success "Configured include_chat_types = ${INCLUDE_CHAT_TYPES_TOML}"

    # --- Per-chat exclusions ---
    echo ""
    read -rp "  Configure per-chat include/exclude list before first sync? [Y/n] " CONFIGURE_CHATS
    echo ""
    if [[ ! "${CONFIGURE_CHATS}" =~ ^[Nn] ]]; then
        if [[ -x "${VENV_DIR}/bin/python3" ]]; then
            log_info "Opening chat selector (supports keyword pre-filter; checked = included)..."
            if PYTHONPATH="${INSTALL_DIR}/src" TG_ASSISTANT_CONFIG="${CONFIG_DIR}/settings.toml" \
                "${VENV_DIR}/bin/python3" -m syncer.manage_chats; then
                log_success "Chat include/exclude list saved"
            else
                log_warn "Chat selector failed; continuing with configured include_chat_types behavior"
            fi
        else
            log_warn "Python venv not found at ${VENV_DIR}; skipping chat selector"
        fi
    fi

    echo ""
    read -rp "  Start services now? [Y/n] " START_NOW
    echo ""

    if [[ "${START_NOW}" =~ ^[Nn] ]]; then
        log_info "Services enabled but not started."
        log_info "Start later with: sudo systemctl start tg-syncer tg-querybot"
    else
        for SVC in tg-syncer tg-querybot; do
            if systemctl start "${SVC}" 2>/dev/null; then
                log_success "Started ${SVC}"
            else
                log_warn "Could not start ${SVC} -- check: journalctl -u ${SVC} -n 50"
            fi
        done

        echo ""
        log_info "Service status:"
        systemctl --no-pager status tg-syncer tg-querybot 2>/dev/null || true

        # Brief polling to confirm sync is pulling messages
        echo ""
        log_info "Waiting for first messages to confirm sync is working..."
        POLL_OK=false
        for i in $(seq 1 6); do
            MSG_COUNT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "SELECT COUNT(*) FROM messages;" 2>/dev/null || echo "0")
            CHAT_COUNT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "SELECT COUNT(*) FROM chats;" 2>/dev/null || echo "0")
            if [[ "${MSG_COUNT}" -gt 0 ]]; then
                log_success "Sync is working: ${MSG_COUNT} messages across ${CHAT_COUNT} chat(s)"
                POLL_OK=true
                break
            fi
            echo -e "  Waiting for first messages... (${i}/6)"
            sleep 5
        done
        if [[ "${POLL_OK}" == false ]]; then
            log_info "No messages yet (initial sync can take 10-30 minutes)."
            log_info "Monitor progress with: telelocal sync-status"
            log_info "Check syncer logs with: telelocal logs"
        fi
    fi
}

# =========================================================================
# Summary
# =========================================================================
print_final_summary() {
    # Clear collected credentials from memory
    unset COLLECT_BOT_TOKEN COLLECT_ANTHROPIC_KEY

    echo ""
    echo "=============================================="
    echo -e "  ${GREEN}${BOLD}Setup Complete${NC}"
    echo "=============================================="
    echo ""
    log_success "Telelocal has been deployed."
    echo ""
    echo -e "${BOLD}What was configured:${NC}"
    echo "  - System packages, Python, PostgreSQL + pgvector"
    echo "  - Dedicated system users (tg-syncer, tg-querybot)"
    echo "  - nftables firewall rules"
    echo "  - Credentials stored in system keychain"
    echo "  - settings.toml configured with your values"
    echo "  - Telethon session encrypted and stored"
    echo "  - systemd services enabled"
    echo ""
    echo -e "${BOLD}Next:${NC}"
    echo "  1. The syncer is now pulling messages using your configured max_history_days window."
    echo "     Initial sync takes 10-30 minutes depending on history size."
    echo "     Monitor progress with: telelocal sync-status"
    echo "  2. You can message the bot right away — it will tell you when"
    echo "     the sync is still in progress and show current message counts."
    echo "  3. Use /stats in the bot to see sync status and message counts."
    echo "  4. Check service logs: telelocal logs"
    echo ""
    echo -e "${BOLD}Useful commands:${NC}"
    echo "  telelocal status                           # Check service health"
    echo "  telelocal sync-status                      # Sync progress per chat"
    echo "  telelocal logs                             # Tail service logs"
    echo "  telelocal manage-chats                     # Include/exclude chats from sync"
    echo "  telelocal update                           # Deploy latest code safely"
    echo "  telelocal prune                            # Prune history to retention window"
    echo "  telelocal restart                          # Restart after changes"
    echo "  telelocal session                          # Recreate Telethon session"
    echo ""
    echo -e "${BOLD}${RED}Security reminders:${NC}"
    echo "  - Regularly check active sessions: Telegram > Settings > Devices"
    echo "  - Back up the session encryption key from your keychain"
    echo "  - Keep the system updated: sudo apt update && sudo apt upgrade"
    echo ""
}

# =========================================================================
# Main
# =========================================================================
main() {
    phase_preflight

    phase_system_setup

    phase_collect_credentials

    phase_configure

    if ! phase_telethon_session; then
        log_warn "Telethon session was not created. You can set it up later with:"
        log_warn "  sudo ./scripts/setup-telethon-session.sh"
        echo ""
    fi

    phase_security_verification

    phase_service_activation

    print_final_summary
}

main "$@"
