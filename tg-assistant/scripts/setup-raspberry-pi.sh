#!/bin/bash
#
# Telegram Personal Assistant - Raspberry Pi Setup Script
# Installs and configures: Python 3.11+, PostgreSQL + pgvector,
# dedicated system users, systemd services, nftables firewall rules.
#
# Prerequisites:
# - Raspberry Pi 4 (4GB+) or Pi 5
# - Raspberry Pi OS (64-bit) or Ubuntu 22.04+ ARM64
# - Internet connection
# - sudo access
#
# Usage: sudo ./setup-raspberry-pi.sh
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors for output
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
log_step()    { echo -e "\n${BOLD}${BLUE}>>> $1${NC}"; }

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

DB_NAME="tg_assistant"
DB_SYNCER_USER="tg_syncer"
DB_QUERYBOT_USER="tg_querybot"
DB_SYNCER_PASS="$(openssl rand -base64 24)"
DB_QUERYBOT_PASS="$(openssl rand -base64 24)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=============================================="
echo "  Telegram Personal Assistant"
echo "  Raspberry Pi Setup"
echo "=============================================="
echo ""

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
check_platform() {
    log_step "Checking platform"

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)."
        exit 1
    fi

    if [[ -f /proc/device-tree/model ]]; then
        MODEL=$(tr -d '\0' < /proc/device-tree/model)
        log_info "Detected: ${MODEL}"
    else
        log_warn "Not running on Raspberry Pi -- proceeding anyway (development mode)"
    fi

    ARCH=$(uname -m)
    if [[ "${ARCH}" != "aarch64" && "${ARCH}" != "arm64" ]]; then
        log_warn "Architecture is ${ARCH} -- 64-bit ARM recommended for best performance"
    fi

    log_success "Platform check complete"
}

# ---------------------------------------------------------------------------
# System dependencies
# ---------------------------------------------------------------------------
install_dependencies() {
    log_step "Installing system dependencies"

    apt-get update
    apt-get upgrade -y

    apt-get install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        libpq-dev \
        libffi-dev \
        postgresql \
        postgresql-contrib \
        nftables \
        tcpdump \
        curl \
        git \
        jq \
        gnome-keyring \
        libsecret-tools \
        libsecret-1-dev

    log_success "System dependencies installed"
}

# ---------------------------------------------------------------------------
# Python 3.11+
# ---------------------------------------------------------------------------
install_python() {
    log_step "Installing Python 3.11+"

    # Check if a suitable Python is already installed
    if command -v python3.11 &>/dev/null; then
        PY_BIN="python3.11"
        log_info "Python 3.11 already installed: $(${PY_BIN} --version)"
    elif command -v python3.12 &>/dev/null; then
        PY_BIN="python3.12"
        log_info "Python 3.12 already installed: $(${PY_BIN} --version)"
    elif command -v python3 &>/dev/null; then
        PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(echo "${PY_VERSION}" | cut -d. -f1)
        PY_MINOR=$(echo "${PY_VERSION}" | cut -d. -f2)
        if [[ "${PY_MAJOR}" -ge 3 && "${PY_MINOR}" -ge 11 ]]; then
            PY_BIN="python3"
            log_info "Python ${PY_VERSION} already installed"
        else
            log_info "Python ${PY_VERSION} is too old -- installing Python 3.11"
            apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip || {
                # Fallback: use deadsnakes or build from source on Debian
                apt-get install -y software-properties-common
                add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
                apt-get update
                apt-get install -y python3.11 python3.11-venv python3.11-dev
            }
            PY_BIN="python3.11"
        fi
    else
        apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
        PY_BIN="python3.11"
    fi

    # Ensure pip and venv modules are available
    apt-get install -y python3-pip python3-venv 2>/dev/null || true

    log_success "Python ready: $(${PY_BIN} --version)"
}

# ---------------------------------------------------------------------------
# pgvector
# ---------------------------------------------------------------------------
install_pgvector() {
    log_step "Installing pgvector extension"

    PG_VERSION=$(pg_config --version | grep -oP '\d+' | head -1)

    if dpkg -l 2>/dev/null | grep -q "postgresql-${PG_VERSION}-pgvector"; then
        log_info "pgvector already installed for PostgreSQL ${PG_VERSION}"
        return
    fi

    if apt-cache show "postgresql-${PG_VERSION}-pgvector" &>/dev/null; then
        apt-get install -y "postgresql-${PG_VERSION}-pgvector"
        log_success "pgvector installed from apt"
    else
        log_warn "pgvector not in apt -- building from source"

        apt-get install -y "postgresql-server-dev-${PG_VERSION}"
        PGVECTOR_VERSION="0.7.4"
        PREV_DIR="$(pwd)"
        cd /tmp
        git clone --branch "v${PGVECTOR_VERSION}" https://github.com/pgvector/pgvector.git
        cd pgvector
        make
        make install
        cd "${PREV_DIR}"
        rm -rf /tmp/pgvector

        log_success "pgvector built and installed from source"
    fi
}

# ---------------------------------------------------------------------------
# System users
# ---------------------------------------------------------------------------
create_system_users() {
    log_step "Creating dedicated system users"

    for SVC_USER in "${SYNCER_USER}" "${QUERYBOT_USER}"; do
        if id "${SVC_USER}" &>/dev/null; then
            log_info "User ${SVC_USER} already exists"
        else
            useradd \
                --system \
                --shell /usr/sbin/nologin \
                --home-dir "/home/${SVC_USER}" \
                --create-home \
                "${SVC_USER}"
            log_success "Created system user: ${SVC_USER}"
        fi
    done

    # Telethon session directory for syncer
    mkdir -p "${SYNCER_HOME}/.telethon"
    chown -R "${SYNCER_USER}:${SYNCER_USER}" "${SYNCER_HOME}/.telethon"
    chmod 700 "${SYNCER_HOME}/.telethon"

    log_success "System users configured"
}

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
setup_directories() {
    log_step "Creating application directories"

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${LOG_DIR}"
    mkdir -p "${LOG_DIR}/syncer"
    mkdir -p "${LOG_DIR}/querybot"

    # Log directory: both service users need write access
    chown root:root "${LOG_DIR}"
    chmod 755 "${LOG_DIR}"
    chown "${SYNCER_USER}:${SYNCER_USER}" "${LOG_DIR}/syncer"
    chmod 750 "${LOG_DIR}/syncer"
    chown "${QUERYBOT_USER}:${QUERYBOT_USER}" "${LOG_DIR}/querybot"
    chmod 750 "${LOG_DIR}/querybot"

    log_success "Directories created:"
    log_info "  Application: ${INSTALL_DIR}"
    log_info "  Config:      ${CONFIG_DIR}"
    log_info "  Logs:        ${LOG_DIR}"
}

# ---------------------------------------------------------------------------
# Python virtual environment
# ---------------------------------------------------------------------------
setup_venv() {
    log_step "Setting up Python virtual environment"

    "${PY_BIN}" -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"

    pip install --upgrade pip setuptools wheel

    if [[ -f "${PROJECT_ROOT}/requirements.txt" ]]; then
        pip install -r "${PROJECT_ROOT}/requirements.txt"
        log_success "Python dependencies installed from requirements.txt"
    else
        log_warn "requirements.txt not found at ${PROJECT_ROOT}/requirements.txt"
        log_info "Installing core dependencies manually"
        pip install \
            telethon \
            python-telegram-bot \
            anthropic \
            psycopg2-binary \
            pgvector \
            cryptography \
            tomli \
            keyring \
            keyrings.alt
    fi

    deactivate

    # Make venv accessible to both service users
    chown -R root:root "${VENV_DIR}"
    chmod -R 755 "${VENV_DIR}"

    log_success "Virtual environment ready at ${VENV_DIR}"
}

# ---------------------------------------------------------------------------
# Deploy configuration files
# ---------------------------------------------------------------------------
deploy_config() {
    log_step "Deploying configuration files"

    CONFIG_SOURCE="${PROJECT_ROOT}/config"

    if [[ -f "${CONFIG_SOURCE}/settings.toml" ]]; then
        cp "${CONFIG_SOURCE}/settings.toml" "${CONFIG_DIR}/settings.toml"

        # Inject generated database passwords
        sed -i "s|SYNCER_DB_PASS_PLACEHOLDER|${DB_SYNCER_PASS}|g" "${CONFIG_DIR}/settings.toml"
        sed -i "s|QUERYBOT_DB_PASS_PLACEHOLDER|${DB_QUERYBOT_PASS}|g" "${CONFIG_DIR}/settings.toml"

        chmod 600 "${CONFIG_DIR}/settings.toml"
        chown root:root "${CONFIG_DIR}/settings.toml"
        log_success "settings.toml deployed"
    else
        log_warn "settings.toml not found in ${CONFIG_SOURCE} -- you will need to create it"
    fi

    if [[ -f "${CONFIG_SOURCE}/system_prompt.md" ]]; then
        cp "${CONFIG_SOURCE}/system_prompt.md" "${CONFIG_DIR}/system_prompt.md"
        chmod 644 "${CONFIG_DIR}/system_prompt.md"
        log_success "system_prompt.md deployed"
    else
        log_warn "system_prompt.md not found in ${CONFIG_SOURCE}"
    fi

    log_success "Configuration deployed to ${CONFIG_DIR}"
}

# ---------------------------------------------------------------------------
# Deploy systemd service files
# ---------------------------------------------------------------------------
deploy_systemd_services() {
    log_step "Deploying systemd service files"

    SYSTEMD_SOURCE="${PROJECT_ROOT}/systemd"

    for SVC_FILE in tg-syncer.service tg-querybot.service; do
        if [[ -f "${SYSTEMD_SOURCE}/${SVC_FILE}" ]]; then
            cp "${SYSTEMD_SOURCE}/${SVC_FILE}" "/etc/systemd/system/${SVC_FILE}"
            log_success "Deployed ${SVC_FILE}"
        else
            log_warn "${SVC_FILE} not found in ${SYSTEMD_SOURCE} -- skipping"
        fi
    done

    systemctl daemon-reload
    log_success "Systemd services registered"
}

# ---------------------------------------------------------------------------
# Deploy nftables firewall rules
# ---------------------------------------------------------------------------
deploy_nftables() {
    log_step "Deploying nftables firewall rules"

    NFTABLES_SOURCE="${PROJECT_ROOT}/nftables"
    NFTABLES_DEST="/etc/nftables.d"

    mkdir -p "${NFTABLES_DEST}"

    if [[ -f "${NFTABLES_SOURCE}/tg-assistant-firewall.conf" ]]; then
        cp "${NFTABLES_SOURCE}/tg-assistant-firewall.conf" "${NFTABLES_DEST}/tg-assistant-firewall.conf"
        log_success "Firewall rules deployed"
    else
        log_warn "tg-assistant-firewall.conf not found -- creating basic rules"

        # Get UIDs for nftables rules
        SYNCER_UID=$(id -u "${SYNCER_USER}" 2>/dev/null || echo "UNKNOWN")
        QUERYBOT_UID=$(id -u "${QUERYBOT_USER}" 2>/dev/null || echo "UNKNOWN")

        cat > "${NFTABLES_DEST}/tg-assistant-firewall.conf" << NFTEOF
#!/usr/sbin/nft -f
#
# Telegram Personal Assistant - Per-process network restrictions
#
# tg-syncer:   Only Telegram MTProto IPs (port 443)
# tg-querybot: Only api.telegram.org + api.anthropic.com (HTTPS)
#

table inet tg_assistant {
    chain output {
        type filter hook output priority 0; policy accept;

        # tg-syncer: allow only Telegram datacenter IP ranges (MTProto)
        # Telegram DC IPs: 149.154.160.0/20, 91.108.4.0/22, 91.108.8.0/22,
        #                  91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22,
        #                  91.108.56.0/22, 185.76.151.0/24
        meta skuid ${SYNCER_UID} ip daddr 127.0.0.0/8 accept
        meta skuid ${SYNCER_UID} ip daddr 149.154.160.0/20 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr 91.108.4.0/22 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr 91.108.8.0/22 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr 91.108.12.0/22 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr 91.108.16.0/22 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr 91.108.20.0/22 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr 91.108.56.0/22 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr 185.76.151.0/24 tcp dport 443 accept
        meta skuid ${SYNCER_UID} ip daddr != 127.0.0.0/8 drop

        # tg-querybot: allow only Bot API + Anthropic API (HTTPS)
        meta skuid ${QUERYBOT_UID} ip daddr 127.0.0.0/8 accept
        meta skuid ${QUERYBOT_UID} tcp dport 443 ip daddr 149.154.160.0/20 accept
        meta skuid ${QUERYBOT_UID} tcp dport 443 ip daddr 91.108.4.0/22 accept
        meta skuid ${QUERYBOT_UID} ip daddr != 127.0.0.0/8 log prefix "tg-querybot-blocked: " drop

        # DNS is needed for initial resolution
        meta skuid ${SYNCER_UID} udp dport 53 accept
        meta skuid ${QUERYBOT_UID} udp dport 53 accept
    }
}
NFTEOF
        log_success "Basic firewall rules generated"
    fi

    # Try to apply rules (non-fatal if nftables service is not yet configured)
    if systemctl is-active --quiet nftables; then
        nft -f "${NFTABLES_DEST}/tg-assistant-firewall.conf" 2>/dev/null && \
            log_success "Firewall rules applied" || \
            log_warn "Could not apply firewall rules -- apply manually after review"
    else
        systemctl enable nftables 2>/dev/null || true
        log_info "nftables will be applied on next boot (or run: sudo systemctl start nftables)"
    fi
}

# ---------------------------------------------------------------------------
# PostgreSQL: database, roles, schema
# ---------------------------------------------------------------------------
setup_postgresql() {
    log_step "Setting up PostgreSQL database and roles"

    systemctl enable postgresql
    systemctl start postgresql

    # Wait for PostgreSQL
    until sudo -u postgres pg_isready -q; do
        log_info "Waiting for PostgreSQL to start..."
        sleep 2
    done

    sudo -u postgres psql <<EOF
-- =========================================================================
-- Database
-- =========================================================================
SELECT 'CREATE DATABASE ${DB_NAME}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec

\c ${DB_NAME}

-- =========================================================================
-- Extensions
-- =========================================================================
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;     -- for fuzzy text search

-- =========================================================================
-- Roles
-- =========================================================================
DO \$\$
BEGIN
    -- Syncer login role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_SYNCER_USER}') THEN
        CREATE ROLE ${DB_SYNCER_USER} WITH LOGIN PASSWORD '${DB_SYNCER_PASS}';
    END IF;

    -- Querybot login role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_QUERYBOT_USER}') THEN
        CREATE ROLE ${DB_QUERYBOT_USER} WITH LOGIN PASSWORD '${DB_QUERYBOT_PASS}';
    END IF;

    -- Abstract roles for permission grouping
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'syncer_role') THEN
        CREATE ROLE syncer_role;
    END IF;

    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'querybot_role') THEN
        CREATE ROLE querybot_role;
    END IF;
END
\$\$;

GRANT syncer_role TO ${DB_SYNCER_USER};
GRANT querybot_role TO ${DB_QUERYBOT_USER};

-- =========================================================================
-- Schema: messages
-- =========================================================================
CREATE TABLE IF NOT EXISTS messages (
    id              BIGSERIAL PRIMARY KEY,
    telegram_msg_id BIGINT NOT NULL,
    chat_id         BIGINT NOT NULL,
    chat_title      VARCHAR(255),
    sender_id       BIGINT,
    sender_name     VARCHAR(255),
    content         TEXT NOT NULL,
    message_type    VARCHAR(50) DEFAULT 'text',
    reply_to_msg_id BIGINT,
    timestamp       TIMESTAMPTZ NOT NULL,
    synced_at       TIMESTAMPTZ DEFAULT NOW(),
    embedding       vector(1024),
    UNIQUE(telegram_msg_id, chat_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_content_trgm ON messages USING gin(content gin_trgm_ops);

-- =========================================================================
-- Schema: chats
-- =========================================================================
CREATE TABLE IF NOT EXISTS chats (
    id              BIGSERIAL PRIMARY KEY,
    chat_id         BIGINT UNIQUE NOT NULL,
    chat_title      VARCHAR(255),
    chat_type       VARCHAR(50),
    last_synced_id  BIGINT DEFAULT 0,
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chats_chat_id ON chats(chat_id);

-- =========================================================================
-- Schema: audit_log
-- =========================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ DEFAULT NOW(),
    service         VARCHAR(50) NOT NULL,
    action          VARCHAR(100) NOT NULL,
    details         JSONB,
    user_id         BIGINT,
    success         BOOLEAN DEFAULT true,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_service ON audit_log(service);

-- =========================================================================
-- Permissions: syncer_role (INSERT + SELECT on messages/chats, INSERT on audit_log)
-- =========================================================================
GRANT SELECT, INSERT, UPDATE ON messages TO syncer_role;
GRANT SELECT, INSERT, UPDATE ON chats TO syncer_role;
GRANT INSERT ON audit_log TO syncer_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO syncer_role;

-- =========================================================================
-- Permissions: querybot_role (SELECT only on messages/chats, INSERT on audit_log)
-- =========================================================================
GRANT SELECT ON messages TO querybot_role;
GRANT SELECT ON chats TO querybot_role;
GRANT INSERT ON audit_log TO querybot_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO querybot_role;

-- =========================================================================
-- Revoke dangerous permissions explicitly (defense in depth)
-- =========================================================================
REVOKE DELETE, TRUNCATE ON messages FROM syncer_role;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON messages FROM querybot_role;
REVOKE DELETE, TRUNCATE ON chats FROM syncer_role;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON chats FROM querybot_role;

-- Prevent either role from modifying schema
REVOKE CREATE ON SCHEMA public FROM syncer_role;
REVOKE CREATE ON SCHEMA public FROM querybot_role;

EOF

    log_success "PostgreSQL configured"
    log_info "Database:     ${DB_NAME}"
    log_info "Syncer role:  ${DB_SYNCER_USER}"
    log_info "Querybot role: ${DB_QUERYBOT_USER}"
}

# ---------------------------------------------------------------------------
# Copy application source
# ---------------------------------------------------------------------------
deploy_application() {
    log_step "Deploying application source"

    if [[ -d "${PROJECT_ROOT}/src" ]]; then
        cp -r "${PROJECT_ROOT}/src" "${INSTALL_DIR}/src"
        chown -R root:root "${INSTALL_DIR}/src"
        chmod -R 755 "${INSTALL_DIR}/src"
        log_success "Application source deployed to ${INSTALL_DIR}/src"
    else
        log_warn "Source directory not found at ${PROJECT_ROOT}/src -- deploy manually later"
    fi
}

# ---------------------------------------------------------------------------
# Set final permissions
# ---------------------------------------------------------------------------
set_permissions() {
    log_step "Setting final permissions"

    # Config directory: root-owned, readable by service users
    chown root:root "${CONFIG_DIR}"
    chmod 755 "${CONFIG_DIR}"

    # settings.toml: root-only (services read via systemd LoadCredential or env injection)
    if [[ -f "${CONFIG_DIR}/settings.toml" ]]; then
        chmod 600 "${CONFIG_DIR}/settings.toml"
        chown root:root "${CONFIG_DIR}/settings.toml"
    fi

    # Install directory
    chown -R root:root "${INSTALL_DIR}"
    chmod -R 755 "${INSTALL_DIR}"

    # Syncer home: only syncer can access
    chown -R "${SYNCER_USER}:${SYNCER_USER}" "${SYNCER_HOME}"
    chmod 700 "${SYNCER_HOME}"

    # Querybot home: only querybot can access
    chown -R "${QUERYBOT_USER}:${QUERYBOT_USER}" "${QUERYBOT_HOME}"
    chmod 700 "${QUERYBOT_HOME}"

    log_success "Permissions set"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo "=============================================="
    echo -e "  ${GREEN}Setup Complete${NC}"
    echo "=============================================="
    echo ""
    log_success "Telegram Personal Assistant has been installed and configured"
    echo ""
    echo -e "${BOLD}Installed Components:${NC}"
    echo "  - Python:       $(${PY_BIN} --version 2>&1)"
    echo "  - PostgreSQL:   $(pg_config --version 2>/dev/null || echo 'installed')"
    echo "  - pgvector:     installed"
    echo "  - nftables:     configured"
    echo "  - Virtual env:  ${VENV_DIR}"
    echo ""
    echo -e "${BOLD}System Users:${NC}"
    echo "  - ${SYNCER_USER}   (UID $(id -u ${SYNCER_USER}))"
    echo "  - ${QUERYBOT_USER} (UID $(id -u ${QUERYBOT_USER}))"
    echo ""
    echo -e "${BOLD}Directories:${NC}"
    echo "  - Application:  ${INSTALL_DIR}"
    echo "  - Config:       ${CONFIG_DIR}"
    echo "  - Logs:         ${LOG_DIR}"
    echo "  - Syncer home:  ${SYNCER_HOME}"
    echo ""
    echo -e "${BOLD}Database:${NC}"
    echo "  - Name:         ${DB_NAME}"
    echo "  - Syncer role:  ${DB_SYNCER_USER}"
    echo "  - Querybot role: ${DB_QUERYBOT_USER}"
    echo ""
    echo "----------------------------------------------"
    echo ""
    echo -e "${BOLD}Next Steps:${NC}"
    echo ""
    echo "  1. Create your Telethon session (interactive -- requires your phone + 2FA):"
    echo "     ${PROJECT_ROOT}/scripts/setup-telethon-session.sh"
    echo ""
    echo "  2. Create a Telegram bot via @BotFather and save the token:"
    echo "     - Message @BotFather on Telegram"
    echo "     - Send /newbot and follow prompts"
    echo "     - Store token: secret-tool store --label='tg-querybot-token' service tg-assistant key bot_token"
    echo ""
    echo "  3. Add your Anthropic API key:"
    echo "     secret-tool store --label='tg-claude-key' service tg-assistant key anthropic_api_key"
    echo ""
    echo "  4. Set your Telegram user ID (owner_id) in ${CONFIG_DIR}/settings.toml"
    echo ""
    echo "  5. Run security verification:"
    echo "     ${PROJECT_ROOT}/tests/security-verification.sh"
    echo ""
    echo "  6. Start services:"
    echo "     sudo systemctl enable tg-syncer tg-querybot"
    echo "     sudo systemctl start tg-syncer tg-querybot"
    echo ""

    # Save database passwords to a temporary secure file
    CREDS_FILE="${CONFIG_DIR}/.db_credentials"
    cat > "${CREDS_FILE}" << CREDEOF
# Telegram Personal Assistant -- Database Credentials
# Generated: $(date -Iseconds)
# DELETE THIS FILE after storing credentials in your password manager.

DB_NAME=${DB_NAME}
DB_SYNCER_USER=${DB_SYNCER_USER}
DB_SYNCER_PASS=${DB_SYNCER_PASS}
DB_QUERYBOT_USER=${DB_QUERYBOT_USER}
DB_QUERYBOT_PASS=${DB_QUERYBOT_PASS}
CREDEOF
    chmod 600 "${CREDS_FILE}"
    chown root:root "${CREDS_FILE}"

    log_warn "Database passwords saved to ${CREDS_FILE}"
    log_warn "Store these in your password manager, then delete the file:"
    log_warn "  sudo shred -u ${CREDS_FILE}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    check_platform
    install_dependencies
    install_python
    install_pgvector
    create_system_users
    setup_directories
    setup_venv
    deploy_config
    deploy_systemd_services
    deploy_nftables
    setup_postgresql
    deploy_application
    set_permissions
    print_summary
}

main "$@"
