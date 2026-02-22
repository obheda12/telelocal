#!/bin/bash
#
# Telegram Personal Assistant - Raspberry Pi Setup Script
# Installs and configures: Python 3.11+, PostgreSQL + pgvector,
# dedicated system users, systemd services, nftables firewall rules.
#
# NOTE: For a complete guided setup (including credentials, session
# creation, and service activation), use setup.sh instead:
#   sudo ./scripts/setup.sh
#
# This script handles only infrastructure. Use it for granular control
# or when re-running system setup independently.
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
    mkdir -p /var/lib/tg-syncer
    mkdir -p "${LOG_DIR}/syncer"
    mkdir -p "${LOG_DIR}/querybot"

    # Log directory: both service users need write access to the shared audit log.
    # Create a tg-assistant group that both users belong to.
    if ! getent group tg-assistant >/dev/null 2>&1; then
        groupadd --system tg-assistant
    fi
    usermod -aG tg-assistant "${SYNCER_USER}" 2>/dev/null || true
    usermod -aG tg-assistant "${QUERYBOT_USER}" 2>/dev/null || true

    chown root:tg-assistant "${LOG_DIR}"
    chmod 775 "${LOG_DIR}"
    chown "${SYNCER_USER}:${SYNCER_USER}" "${LOG_DIR}/syncer"
    chmod 750 "${LOG_DIR}/syncer"
    chown "${QUERYBOT_USER}:${QUERYBOT_USER}" "${LOG_DIR}/querybot"
    chmod 750 "${LOG_DIR}/querybot"

    # Shared audit log writable by both services
    touch "${LOG_DIR}/audit.log"
    chown root:tg-assistant "${LOG_DIR}/audit.log"
    chmod 664 "${LOG_DIR}/audit.log"

    # Syncer state directory (session updates during sync)
    chown "${SYNCER_USER}:${SYNCER_USER}" /var/lib/tg-syncer
    chmod 700 /var/lib/tg-syncer

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

    # Look for requirements.txt in project root, then install dir
    REQ_FILE=""
    if [[ -f "${PROJECT_ROOT}/requirements.txt" ]]; then
        REQ_FILE="${PROJECT_ROOT}/requirements.txt"
    elif [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
        REQ_FILE="${INSTALL_DIR}/requirements.txt"
    fi

    if [[ -n "${REQ_FILE}" ]]; then
        pip install -r "${REQ_FILE}"
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

    # Pre-download the sentence-transformers model so the syncer doesn't need
    # internet access at runtime (nftables blocks HuggingFace from tg-syncer).
    MODEL_DIR="${INSTALL_DIR}/models"
    mkdir -p "${MODEL_DIR}"
    log_info "Pre-downloading embedding model (this may take a few minutes on Pi)..."
    HF_HOME="${MODEL_DIR}" SENTENCE_TRANSFORMERS_HOME="${MODEL_DIR}" \
        python3 -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2', device='cpu')" \
        && log_success "Embedding model cached at ${MODEL_DIR}" \
        || log_warn "Model pre-download failed (embeddings will be unavailable until fixed)"

    # Export ONNX model with ARM64 INT8 quantization for faster inference.
    # Falls back to PyTorch at runtime if this step fails.
    log_info "Exporting ONNX model with ARM64 quantization..."
    HF_HOME="${MODEL_DIR}" SENTENCE_TRANSFORMERS_HOME="${MODEL_DIR}" \
        python3 -c "
from sentence_transformers import SentenceTransformer, export_dynamic_quantized_onnx_model
model = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
export_dynamic_quantized_onnx_model(
    model,
    quantization_config='arm64',
    model_name_or_path='all-MiniLM-L6-v2',
)
print('ONNX ARM64 quantized model exported successfully')
" \
        && log_success "ONNX ARM64 quantized model exported" \
        || log_warn "ONNX export failed (will fall back to PyTorch at runtime)"

    deactivate

    # Make venv accessible to both service users
    chown -R root:root "${VENV_DIR}"
    chmod -R 755 "${VENV_DIR}"

    # Model cache readable by syncer service
    chown -R root:root "${MODEL_DIR}"
    chmod -R 755 "${MODEL_DIR}"

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
        log_success "settings.toml deployed"
    elif [[ -f "${CONFIG_DIR}/settings.toml" ]]; then
        log_info "settings.toml already present at ${CONFIG_DIR}"
    else
        log_warn "settings.toml not found -- you will need to create it"
    fi

    # settings.toml contains no secrets (credentials are in /etc/credstore/).
    # Readable by service users so they can load non-secret config at startup.
    if [[ -f "${CONFIG_DIR}/settings.toml" ]]; then
        chmod 644 "${CONFIG_DIR}/settings.toml"
        chown root:root "${CONFIG_DIR}/settings.toml"
    fi

    if [[ -f "${CONFIG_SOURCE}/system_prompt.md" ]]; then
        cp "${CONFIG_SOURCE}/system_prompt.md" "${CONFIG_DIR}/system_prompt.md"
        chmod 644 "${CONFIG_DIR}/system_prompt.md"
        log_success "system_prompt.md deployed"
    elif [[ -f "${CONFIG_DIR}/system_prompt.md" ]]; then
        log_info "system_prompt.md already present"
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
        elif [[ -f "/etc/systemd/system/${SVC_FILE}" ]]; then
            log_info "${SVC_FILE} already present in /etc/systemd/system/"
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

        # DNS is needed for initial resolution
        meta skuid ${SYNCER_UID} udp dport 53 accept
        meta skuid ${SYNCER_UID} tcp dport 53 accept
        meta skuid ${QUERYBOT_UID} udp dport 53 accept
        meta skuid ${QUERYBOT_UID} tcp dport 53 accept

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
-- NOTE: This schema MUST match src/shared/db.py init_database() exactly.
-- The application code references these column names directly.
-- =========================================================================
CREATE TABLE IF NOT EXISTS messages (
    message_id         BIGINT NOT NULL,
    chat_id            BIGINT NOT NULL,
    sender_id          BIGINT,
    sender_name        TEXT,
    timestamp          TIMESTAMPTZ NOT NULL,
    text               TEXT,
    raw_json           JSONB,
    embedding          vector(384),
    text_search_vector TSVECTOR
        GENERATED ALWAYS AS (
            to_tsvector('english', COALESCE(text, ''))
        ) STORED,
    text_search_vector_simple TSVECTOR
        GENERATED ALWAYS AS (
            to_tsvector('simple', COALESCE(text, ''))
        ) STORED,
    PRIMARY KEY (message_id, chat_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_fts
    ON messages USING GIN (text_search_vector);
CREATE INDEX IF NOT EXISTS idx_messages_fts_simple
    ON messages USING GIN (text_search_vector_simple);
CREATE INDEX IF NOT EXISTS idx_messages_chat_timestamp
    ON messages (chat_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp
    ON messages (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_messages_embedding
    ON messages USING hnsw (embedding vector_cosine_ops);

-- =========================================================================
-- Schema: chats
-- =========================================================================
CREATE TABLE IF NOT EXISTS chats (
    chat_id           BIGINT PRIMARY KEY,
    title             TEXT,
    chat_type         TEXT,
    participant_count INTEGER,
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

-- =========================================================================
-- Schema: audit_log
-- =========================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id        BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    service   TEXT NOT NULL,
    action    TEXT NOT NULL,
    details   JSONB,
    success   BOOLEAN NOT NULL
);

-- =========================================================================
-- Permissions: syncer_role (INSERT + SELECT on messages/chats, INSERT on audit_log)
-- NOTE: messages are immutable after sync. No UPDATE on messages.
-- =========================================================================
GRANT SELECT, INSERT ON messages TO syncer_role;
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

    # -----------------------------------------------------------------------
    # Configure peer authentication for Unix socket connections.
    # Maps system users (tg-syncer, tg-querybot) to PG roles (tg_syncer,
    # tg_querybot) so no passwords are needed — the kernel verifies identity.
    #
    # NOTE: We query SHOW hba_file / ident_file directly (not data_directory)
    # because on Debian/Ubuntu the config dir (/etc/postgresql/<ver>/main/)
    # differs from the data dir (/var/lib/postgresql/<ver>/main/).
    # -----------------------------------------------------------------------
    HBA_FILE=$(sudo -u postgres psql -qAt -c "SHOW hba_file" 2>/dev/null)
    IDENT_FILE=$(sudo -u postgres psql -qAt -c "SHOW ident_file" 2>/dev/null)

    # Fallback if psql query failed
    if [[ -z "${HBA_FILE}" || -z "${IDENT_FILE}" ]]; then
        PG_CONF_DIR="/etc/postgresql/$(ls /etc/postgresql/ 2>/dev/null | tail -1)/main"
        HBA_FILE="${HBA_FILE:-${PG_CONF_DIR}/pg_hba.conf}"
        IDENT_FILE="${IDENT_FILE:-${PG_CONF_DIR}/pg_ident.conf}"
    fi

    if [[ -f "${HBA_FILE}" && -f "${IDENT_FILE}" ]]; then
        # pg_ident.conf: map system user → PG role
        for MAPPING in "tg-assistant tg-syncer tg_syncer" "tg-assistant tg-querybot tg_querybot"; do
            if ! grep -qF "${MAPPING}" "${IDENT_FILE}" 2>/dev/null; then
                echo "${MAPPING}" >> "${IDENT_FILE}"
            fi
        done
        log_success "pg_ident.conf: system user → PG role mappings added"

        # pg_hba.conf: allow peer auth for our users on the tg_assistant DB
        for PG_USER in "${DB_SYNCER_USER}" "${DB_QUERYBOT_USER}"; do
            HBA_LINE="local   ${DB_NAME}       ${PG_USER}                              peer map=tg-assistant"
            if ! grep -qF "${PG_USER}" "${HBA_FILE}" 2>/dev/null || ! grep -qF "tg-assistant" "${HBA_FILE}" 2>/dev/null; then
                # Insert before the first generic "local all all" line
                if grep -qn "^local.*all.*all" "${HBA_FILE}"; then
                    LINE_NUM=$(grep -n "^local.*all.*all" "${HBA_FILE}" | head -1 | cut -d: -f1)
                    sed -i "${LINE_NUM}i\\${HBA_LINE}" "${HBA_FILE}"
                else
                    echo "${HBA_LINE}" >> "${HBA_FILE}"
                fi
            fi
        done
        log_success "pg_hba.conf: peer authentication rules added"

        # Reload PostgreSQL to pick up config changes
        PG_CONF_DIR=$(dirname "${HBA_FILE}")
        systemctl reload postgresql 2>/dev/null || sudo -u postgres pg_ctl reload -D "${PG_CONF_DIR}" 2>/dev/null || true
        log_success "PostgreSQL configuration reloaded"
    else
        log_warn "Could not find pg_hba.conf (${HBA_FILE}) or pg_ident.conf (${IDENT_FILE}) -- configure manually"
    fi

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

    # Detect self-deploy: when running from the installed location
    # (e.g., via 'telenad setup'), PROJECT_ROOT == INSTALL_DIR.
    # In that case, source is already in place — just fix permissions.
    REAL_PROJECT=$(realpath "${PROJECT_ROOT}" 2>/dev/null || echo "${PROJECT_ROOT}")
    REAL_INSTALL=$(realpath "${INSTALL_DIR}" 2>/dev/null || echo "${INSTALL_DIR}")

    if [[ "${REAL_PROJECT}" == "${REAL_INSTALL}" ]]; then
        log_info "Running from installed location — source already in place"
        if [[ -d "${INSTALL_DIR}/src" ]]; then
            chown -R root:root "${INSTALL_DIR}/src"
            chmod -R 755 "${INSTALL_DIR}/src"
            log_success "Permissions verified on ${INSTALL_DIR}/src"
        fi
    elif [[ -d "${PROJECT_ROOT}/src" ]]; then
        cp -r "${PROJECT_ROOT}/src" "${INSTALL_DIR}/src"
        chown -R root:root "${INSTALL_DIR}/src"
        chmod -R 755 "${INSTALL_DIR}/src"
        log_success "Application source deployed to ${INSTALL_DIR}/src"
    else
        log_warn "Source directory not found at ${PROJECT_ROOT}/src -- deploy manually later"
    fi

    # Deploy requirements.txt so venv setup can find it on re-runs
    if [[ "${REAL_PROJECT}" != "${REAL_INSTALL}" && -f "${PROJECT_ROOT}/requirements.txt" ]]; then
        cp "${PROJECT_ROOT}/requirements.txt" "${INSTALL_DIR}/requirements.txt"
        log_success "requirements.txt deployed"
    fi

    # Deploy scripts and install CLI
    if [[ "${REAL_PROJECT}" != "${REAL_INSTALL}" && -d "${PROJECT_ROOT}/scripts" ]]; then
        cp -r "${PROJECT_ROOT}/scripts" "${INSTALL_DIR}/scripts"
    fi
    if [[ -d "${INSTALL_DIR}/scripts" ]]; then
        chmod +x "${INSTALL_DIR}/scripts/"*.sh "${INSTALL_DIR}/scripts/telenad" 2>/dev/null || true
        ln -sf "${INSTALL_DIR}/scripts/telenad" /usr/local/bin/telenad
        log_success "CLI installed: telenad"
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

    # settings.toml: readable by service users (contains no secrets —
    # all credentials are in /etc/credstore/ via systemd LoadCredential)
    if [[ -f "${CONFIG_DIR}/settings.toml" ]]; then
        chmod 644 "${CONFIG_DIR}/settings.toml"
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
    echo -e "${BOLD}Next:${NC}"
    echo "  For a complete guided setup (credentials, session, services):"
    echo "    sudo ${PROJECT_ROOT}/scripts/setup.sh"
    echo ""
    echo "  Or continue manually -- see docs/QUICKSTART.md for steps."
    echo ""

    # DB passwords are only needed for the initial role creation above.
    # Production services use peer auth (Unix socket) — no passwords required.
    log_info "Database uses peer auth over Unix socket — no password files needed."
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
