#!/bin/bash
#
# IronClaw Raspberry Pi Setup Script
# Option A: Native Security with Read-Only Telegram Access
#
# Prerequisites:
# - Raspberry Pi 4 (4GB+) or Pi 5
# - Raspberry Pi OS (64-bit recommended)
# - Internet connection
# - sudo access
#
# Usage: ./setup-raspberry-pi.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
IRONCLAW_USER="${IRONCLAW_USER:-pi}"
IRONCLAW_HOME="/home/${IRONCLAW_USER}"
IRONCLAW_DIR="${IRONCLAW_HOME}/ironclaw"
NOTES_DIR="${IRONCLAW_HOME}/ironclaw-notes"
LOG_DIR="/var/log/ironclaw"
CONFIG_DIR="${IRONCLAW_HOME}/.ironclaw"

# Database configuration
DB_NAME="ironclaw"
DB_USER="ironclaw"
DB_PASS="${DB_PASS:-$(openssl rand -base64 24)}"

echo "=============================================="
echo "  IronClaw Raspberry Pi Setup"
echo "  Secure Telegram Agent Deployment"
echo "=============================================="
echo ""

# Check if running on Raspberry Pi
check_platform() {
    log_info "Checking platform..."

    if [[ ! -f /proc/device-tree/model ]]; then
        log_warn "Not running on Raspberry Pi - proceeding anyway for development"
    else
        MODEL=$(cat /proc/device-tree/model)
        log_info "Detected: $MODEL"
    fi

    # Check architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
        log_warn "Architecture is $ARCH - 64-bit ARM recommended for best performance"
    fi
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."

    sudo apt update
    sudo apt upgrade -y

    sudo apt install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        libpq-dev \
        postgresql \
        postgresql-contrib \
        curl \
        git \
        jq

    log_success "System dependencies installed"
}

# Install Rust
install_rust() {
    log_info "Installing Rust..."

    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version)
        log_info "Rust already installed: $RUST_VERSION"

        # Update to latest stable
        rustup update stable
    else
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "${IRONCLAW_HOME}/.cargo/env"
    fi

    rustup default stable

    log_success "Rust installed: $(rustc --version)"
}

# Setup PostgreSQL
setup_postgresql() {
    log_info "Setting up PostgreSQL..."

    # Start PostgreSQL if not running
    sudo systemctl enable postgresql
    sudo systemctl start postgresql

    # Wait for PostgreSQL to be ready
    until sudo -u postgres pg_isready; do
        log_info "Waiting for PostgreSQL to start..."
        sleep 2
    done

    # Create database and user
    sudo -u postgres psql << EOF
-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '${DB_USER}') THEN
        CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec

-- Connect to database and setup extensions
\c ${DB_NAME}

-- Enable pgvector extension (required for IronClaw)
CREATE EXTENSION IF NOT EXISTS vector;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${DB_USER};
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ${DB_USER};
EOF

    log_success "PostgreSQL configured"
    log_info "Database: ${DB_NAME}"
    log_info "User: ${DB_USER}"
}

# Install pgvector if not available
install_pgvector() {
    log_info "Checking pgvector installation..."

    # Check if pgvector is available
    PG_VERSION=$(pg_config --version | grep -oP '\d+' | head -1)

    if dpkg -l | grep -q "postgresql-${PG_VERSION}-pgvector"; then
        log_info "pgvector already installed for PostgreSQL ${PG_VERSION}"
        return
    fi

    # Try to install from apt
    if apt-cache show "postgresql-${PG_VERSION}-pgvector" &> /dev/null; then
        sudo apt install -y "postgresql-${PG_VERSION}-pgvector"
        log_success "pgvector installed from apt"
    else
        log_warn "pgvector not in apt - building from source..."

        # Build pgvector from source
        PGVECTOR_VERSION="0.7.4"
        cd /tmp
        git clone --branch "v${PGVECTOR_VERSION}" https://github.com/pgvector/pgvector.git
        cd pgvector
        make
        sudo make install
        cd -
        rm -rf /tmp/pgvector

        log_success "pgvector built and installed from source"
    fi
}

# Clone and build IronClaw
build_ironclaw() {
    log_info "Building IronClaw (this may take 15-30 minutes on Raspberry Pi)..."

    # Clone repository
    if [[ -d "${IRONCLAW_DIR}" ]]; then
        log_info "IronClaw directory exists, updating..."
        cd "${IRONCLAW_DIR}"
        git pull
    else
        git clone https://github.com/nearai/ironclaw.git "${IRONCLAW_DIR}"
        cd "${IRONCLAW_DIR}"
    fi

    # Build in release mode
    # Note: This is CPU-intensive - ensure good cooling
    log_warn "Building IronClaw - ensure Raspberry Pi has adequate cooling!"

    cargo build --release

    log_success "IronClaw built successfully"
    log_info "Binary location: ${IRONCLAW_DIR}/target/release/ironclaw"
}

# Setup directories and configuration
setup_directories() {
    log_info "Setting up directories and configuration..."

    # Create directories
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${NOTES_DIR}"
    sudo mkdir -p "${LOG_DIR}"

    # Set permissions
    sudo chown "${IRONCLAW_USER}:${IRONCLAW_USER}" "${LOG_DIR}"
    chmod 750 "${LOG_DIR}"

    log_success "Directories created"
}

# Deploy configuration files
deploy_config() {
    log_info "Deploying configuration files..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CONFIG_SOURCE="${SCRIPT_DIR}/../config"

    # Copy settings.toml and update database password
    if [[ -f "${CONFIG_SOURCE}/settings.toml" ]]; then
        sed "s/CHANGE_ME/${DB_PASS}/g" "${CONFIG_SOURCE}/settings.toml" > "${CONFIG_DIR}/settings.toml"
        chmod 600 "${CONFIG_DIR}/settings.toml"
        log_success "settings.toml deployed"
    else
        log_warn "settings.toml not found in ${CONFIG_SOURCE}"
    fi

    # Copy system prompt
    if [[ -f "${CONFIG_SOURCE}/system_prompt.md" ]]; then
        cp "${CONFIG_SOURCE}/system_prompt.md" "${CONFIG_DIR}/system_prompt.md"
        log_success "system_prompt.md deployed"
    else
        log_warn "system_prompt.md not found in ${CONFIG_SOURCE}"
    fi

    log_success "Configuration deployed to ${CONFIG_DIR}"
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SERVICE_FILE="${SCRIPT_DIR}/../systemd/ironclaw.service"

    if [[ -f "${SERVICE_FILE}" ]]; then
        sudo cp "${SERVICE_FILE}" /etc/systemd/system/ironclaw.service
        sudo systemctl daemon-reload
        log_success "Systemd service installed"
        log_info "Enable with: sudo systemctl enable ironclaw"
        log_info "Start with: sudo systemctl start ironclaw"
    else
        log_warn "Service file not found at ${SERVICE_FILE}"
    fi
}

# Print summary and next steps
print_summary() {
    echo ""
    echo "=============================================="
    echo "  Setup Complete!"
    echo "=============================================="
    echo ""
    log_success "IronClaw has been installed and configured"
    echo ""
    echo "Configuration:"
    echo "  - Config directory: ${CONFIG_DIR}"
    echo "  - Notes directory: ${NOTES_DIR}"
    echo "  - Log directory: ${LOG_DIR}"
    echo "  - Database: postgresql://${DB_USER}:****@localhost:5432/${DB_NAME}"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "1. Create a Telegram bot:"
    echo "   - Message @BotFather on Telegram"
    echo "   - Send /newbot and follow prompts"
    echo "   - Copy the bot token"
    echo ""
    echo "2. Add your Telegram bot token:"
    echo "   ${IRONCLAW_DIR}/target/release/ironclaw secrets add TELEGRAM_BOT_TOKEN"
    echo ""
    echo "3. Run IronClaw setup wizard:"
    echo "   ${IRONCLAW_DIR}/target/release/ironclaw setup"
    echo ""
    echo "4. Start IronClaw:"
    echo "   ${IRONCLAW_DIR}/target/release/ironclaw"
    echo ""
    echo "5. (Optional) Enable auto-start on boot:"
    echo "   sudo systemctl enable ironclaw"
    echo "   sudo systemctl start ironclaw"
    echo ""

    # Save database password to secure file
    echo "${DB_PASS}" > "${CONFIG_DIR}/.db_password"
    chmod 600 "${CONFIG_DIR}/.db_password"
    log_warn "Database password saved to ${CONFIG_DIR}/.db_password"
    log_warn "Consider moving this to a password manager and deleting the file"
}

# Main execution
main() {
    check_platform
    install_dependencies
    install_rust
    install_pgvector
    setup_postgresql
    build_ironclaw
    setup_directories
    deploy_config
    install_systemd_service
    print_summary
}

# Run main function
main "$@"
