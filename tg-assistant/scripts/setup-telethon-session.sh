#!/bin/bash
#
# Telegram Personal Assistant - Telethon Session Setup
# Creates an encrypted Telethon session file for the TG Syncer service.
#
# This is interactive: you will be prompted for your phone number,
# verification code, and 2FA password (if enabled).
#
# Usage: sudo ./setup-telethon-session.sh
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
# Configuration
# ---------------------------------------------------------------------------
SYNCER_USER="tg-syncer"
SYNCER_HOME="/home/${SYNCER_USER}"
SESSION_DIR="${SYNCER_HOME}/.telethon"
SESSION_NAME="tg_syncer_session"
SESSION_FILE="${SESSION_DIR}/${SESSION_NAME}.session"
ENCRYPTED_FILE="${SESSION_DIR}/${SESSION_NAME}.session.enc"
VENV_DIR="/opt/tg-assistant/venv"

echo "=============================================="
echo "  Telethon Session Setup"
echo "=============================================="
echo ""

# ---------------------------------------------------------------------------
# Explanation
# ---------------------------------------------------------------------------
echo -e "${BOLD}What is a Telethon session?${NC}"
echo ""
echo "  Telethon uses the MTProto protocol to connect to Telegram as a user"
echo "  (not a bot). This requires a session file that contains authentication"
echo "  tokens generated after you log in with your phone number and 2FA."
echo ""
echo -e "${BOLD}${RED}Security implications:${NC}"
echo ""
echo "  - The session file grants FULL ACCESS to your Telegram account."
echo "  - Anyone who obtains this file can read, send, and delete messages,"
echo "    change settings, and impersonate you."
echo "  - This is equivalent to being logged in on another device."
echo ""
echo "  This script mitigates this risk by:"
echo "  1. Encrypting the session file with Fernet (AES-128-CBC + HMAC-SHA256)"
echo "  2. Storing the encryption key in the system keychain"
echo "  3. Setting file permissions to 0600, owned by the tg-syncer user"
echo "  4. The tg-syncer user has no login shell (cannot be logged into)"
echo ""
echo -e "${YELLOW}You can verify (and terminate) active sessions at any time:${NC}"
echo "  Telegram > Settings > Devices"
echo ""
echo "----------------------------------------------"
echo ""

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)."
    exit 1
fi

if ! id "${SYNCER_USER}" &>/dev/null; then
    log_error "System user '${SYNCER_USER}' does not exist. Run setup-raspberry-pi.sh first."
    exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
    log_error "Virtual environment not found at ${VENV_DIR}. Run setup-raspberry-pi.sh first."
    exit 1
fi

# Ensure session directory exists
mkdir -p "${SESSION_DIR}"
chown "${SYNCER_USER}:${SYNCER_USER}" "${SESSION_DIR}"
chmod 700 "${SESSION_DIR}"

# ---------------------------------------------------------------------------
# Prompt for Telegram API credentials
# ---------------------------------------------------------------------------
echo -e "${BOLD}Step 1: Telegram API Credentials${NC}"
echo ""
echo "  You need an API ID and API hash from https://my.telegram.org"
echo "  1. Log in at https://my.telegram.org"
echo "  2. Go to 'API development tools'"
echo "  3. Create an application (any name/description)"
echo "  4. Copy the api_id (number) and api_hash (hex string)"
echo ""

read -rp "  Enter your API ID: " API_ID
read -rp "  Enter your API hash: " API_HASH

if [[ -z "${API_ID}" || -z "${API_HASH}" ]]; then
    log_error "API ID and API hash are required."
    exit 1
fi

echo ""

# ---------------------------------------------------------------------------
# Create the session via Python
# ---------------------------------------------------------------------------
echo -e "${BOLD}Step 2: Creating Telethon session${NC}"
echo ""
echo "  You will be prompted for your phone number, then a verification code"
echo "  sent to your Telegram account, and your 2FA password if enabled."
echo ""

# Write a temporary Python script for session creation
TEMP_SCRIPT=$(mktemp /tmp/create_session_XXXXXX.py)
chmod 600 "${TEMP_SCRIPT}"

cat > "${TEMP_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""
Create a Telethon session, encrypt it, and verify it works.
This script is meant to be run once during setup.
"""
import asyncio
import os
import sys
import getpass

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

    # -----------------------------------------------------------------------
    # Encrypt the session file
    # -----------------------------------------------------------------------
    raw_session_file = session_path + ".session"
    if not os.path.exists(raw_session_file):
        # Telethon may name it differently depending on version
        candidates = [
            session_path,
            session_path + ".session",
        ]
        raw_session_file = None
        for c in candidates:
            if os.path.exists(c):
                raw_session_file = c
                break

        if raw_session_file is None:
            print(f"\n  ERROR: Could not find session file in {session_dir}")
            sys.exit(1)

    print(f"\n  Encrypting session file: {raw_session_file}")

    # Generate Fernet key
    fernet_key = Fernet.generate_key()
    cipher = Fernet(fernet_key)

    with open(raw_session_file, "rb") as f:
        raw_data = f.read()

    encrypted_data = cipher.encrypt(raw_data)

    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    # Remove the unencrypted session file
    os.remove(raw_session_file)
    print(f"  Encrypted session saved to: {encrypted_path}")
    print(f"  Unencrypted session file removed.")

    # Store the Fernet key in the system keychain
    try:
        import keyring
        keyring.set_password("tg-assistant", "telethon_session_key", fernet_key.decode())
        print("  Encryption key stored in system keychain.")
    except Exception as e:
        # Fallback: print the key for manual storage
        print(f"\n  WARNING: Could not store key in system keychain: {e}")
        print(f"  You MUST store this encryption key securely:")
        print(f"  {fernet_key.decode()}")
        print(f"\n  Store it with:")
        print(f"  secret-tool store --label='tg-session-key' service tg-assistant key telethon_session_key")
        # Write to a temporary file that will be shredded
        key_file = os.path.join(session_dir, ".fernet_key.tmp")
        with open(key_file, "w") as f:
            f.write(fernet_key.decode())
        os.chmod(key_file, 0o600)
        print(f"\n  Key also written to: {key_file}")
        print(f"  DELETE THIS FILE after storing the key: sudo shred -u {key_file}")

    # -----------------------------------------------------------------------
    # Verify the encrypted session works
    # -----------------------------------------------------------------------
    print("\n  Verifying encrypted session can be decrypted and used...")

    try:
        with open(encrypted_path, "rb") as f:
            enc_data = f.read()

        decrypted_data = cipher.decrypt(enc_data)

        # Write to a temporary file for verification
        verify_path = os.path.join(session_dir, "_verify_session")
        with open(verify_path, "wb") as f:
            f.write(decrypted_data)

        verify_client = TelegramClient(verify_path, api_id, api_hash)
        await verify_client.connect()
        verify_me = await verify_client.get_me()

        if verify_me and verify_me.id == me.id:
            print(f"  Verification PASSED: session decrypts and authenticates correctly.")
        else:
            print(f"  Verification FAILED: decrypted session returned unexpected identity.")
            sys.exit(1)

        await verify_client.disconnect()

        # Clean up verification file
        if os.path.exists(verify_path + ".session"):
            os.remove(verify_path + ".session")
        if os.path.exists(verify_path):
            os.remove(verify_path)

    except Exception as e:
        print(f"  Verification FAILED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
PYEOF

# Run the Python script as root (it needs to write to the syncer's directory)
export TG_API_ID="${API_ID}"
export TG_API_HASH="${API_HASH}"
export SESSION_DIR="${SESSION_DIR}"
export SESSION_NAME="${SESSION_NAME}"
export ENCRYPTED_FILE="${ENCRYPTED_FILE}"

"${VENV_DIR}/bin/python" "${TEMP_SCRIPT}"
RESULT=$?

# Clean up temp script
shred -u "${TEMP_SCRIPT}" 2>/dev/null || rm -f "${TEMP_SCRIPT}"

if [[ ${RESULT} -ne 0 ]]; then
    log_error "Session creation failed."
    exit 1
fi

# ---------------------------------------------------------------------------
# Set file permissions
# ---------------------------------------------------------------------------
echo ""
log_info "Setting file permissions..."

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

log_success "File permissions set (0600, owned by ${SYNCER_USER})"

# ---------------------------------------------------------------------------
# Store API credentials in keychain
# ---------------------------------------------------------------------------
echo ""
log_info "Storing API credentials in keychain..."

# Try to store via secret-tool (GNOME keyring)
if command -v secret-tool &>/dev/null; then
    echo -n "${API_ID}" | secret-tool store --label="tg-api-id" service tg-assistant key api_id 2>/dev/null && \
        log_success "API ID stored in keychain" || \
        log_warn "Could not store API ID in keychain -- store manually"

    echo -n "${API_HASH}" | secret-tool store --label="tg-api-hash" service tg-assistant key api_hash 2>/dev/null && \
        log_success "API hash stored in keychain" || \
        log_warn "Could not store API hash in keychain -- store manually"
else
    log_warn "secret-tool not available -- store API credentials manually"
fi

# Clear sensitive variables
unset TG_API_ID TG_API_HASH API_ID API_HASH

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo -e "  ${GREEN}Telethon Session Created Successfully${NC}"
echo "=============================================="
echo ""
echo "  Session file:  ${ENCRYPTED_FILE}"
echo "  Permissions:   $(stat -c '%a' "${ENCRYPTED_FILE}" 2>/dev/null || echo '0600')"
echo "  Owner:         ${SYNCER_USER}"
echo "  Encryption:    Fernet (AES-128-CBC + HMAC-SHA256)"
echo "  Key storage:   System keychain"
echo ""
echo "----------------------------------------------"
echo ""
echo -e "${BOLD}${RED}Security Reminders:${NC}"
echo ""
echo "  1. NEVER copy the session file to another machine."
echo "  2. NEVER share the encryption key."
echo "  3. Regularly check active sessions: Telegram > Settings > Devices"
echo "  4. If you suspect compromise, IMMEDIATELY terminate the session"
echo "     from another Telegram client and run:"
echo "       sudo systemctl stop tg-syncer"
echo "       sudo shred -u ${ENCRYPTED_FILE}"
echo "  5. The encryption key in the keychain is only accessible to root"
echo "     and the tg-syncer service (via systemd credential injection)."
echo "  6. Back up the encryption key to your password manager (offline)."
echo "     If you lose the key, you must create a new session."
echo ""
echo "  To recreate the session later:"
echo "    sudo systemctl stop tg-syncer"
echo "    sudo $0"
echo "    sudo systemctl start tg-syncer"
echo ""
