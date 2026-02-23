#!/bin/bash
#
# Telegram Personal Assistant - Security Verification Tests
#
# Run these tests after deployment to verify all security controls are in place.
# Some tests require the services to be configured (not necessarily running).
#
# Usage: ./security-verification.sh
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

PASSED=0
FAILED=0
WARNINGS=0

log_test() { echo -e "\n${BLUE}[TEST]${NC} ${BOLD}$1${NC}"; }
log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAILED++)); }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
log_info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CONFIG_DIR="/etc/tg-assistant"
CONFIG_FILE="${CONFIG_DIR}/settings.toml"
LOG_DIR="/var/log/tg-assistant"
SYNCER_USER="tg-syncer"
QUERYBOT_USER="tg-querybot"
SYNCER_HOME="/home/${SYNCER_USER}"
QUERYBOT_HOME="/home/${QUERYBOT_USER}"
SESSION_DIR="/var/lib/tg-syncer"
SESSION_FILE="${SESSION_DIR}/tg_syncer_session.session.enc"
DB_NAME="tg_assistant"

echo "=============================================="
echo "  Security Verification Tests"
echo "  Telegram Personal Assistant"
echo "=============================================="

# =============================================================================
# Test 1: Configuration file permissions
# =============================================================================
test_config_permissions() {
    log_test "1. Configuration file permissions"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Configuration file not found: ${CONFIG_FILE}"
        log_info "Deploy config first with setup-raspberry-pi.sh"
        return
    fi

    # Check permissions (should be 644; no secrets in file)
    PERMS=$(stat -c %a "${CONFIG_FILE}")
    if [[ "${PERMS}" == "644" ]]; then
        log_pass "settings.toml has correct permissions (644)"
    else
        log_fail "settings.toml has permissions ${PERMS} (expected 644)"
    fi

    # Check ownership (should be root:root)
    OWNER=$(stat -c '%U:%G' "${CONFIG_FILE}")
    if [[ "${OWNER}" == "root:root" ]]; then
        log_pass "settings.toml owned by root:root"
    else
        log_fail "settings.toml owned by ${OWNER} (expected root:root)"
    fi
}

# =============================================================================
# Test 2: System users exist and have no shell
# =============================================================================
test_system_users() {
    log_test "2. System users exist and have no login shell"

    for SVC_USER in "${SYNCER_USER}" "${QUERYBOT_USER}"; do
        if id "${SVC_USER}" &>/dev/null; then
            log_pass "User '${SVC_USER}' exists (UID $(id -u "${SVC_USER}"))"

            # Check shell is nologin or false
            USER_SHELL=$(getent passwd "${SVC_USER}" | cut -d: -f7)
            if [[ "${USER_SHELL}" == "/usr/sbin/nologin" || \
                  "${USER_SHELL}" == "/bin/false" || \
                  "${USER_SHELL}" == "/sbin/nologin" ]]; then
                log_pass "User '${SVC_USER}' has no login shell (${USER_SHELL})"
            else
                log_fail "User '${SVC_USER}' has shell: ${USER_SHELL} (expected /usr/sbin/nologin)"
            fi
        else
            log_fail "User '${SVC_USER}' does not exist"
        fi
    done
}

# =============================================================================
# Test 3: Telethon session file permissions
# =============================================================================
test_session_permissions() {
    log_test "3. Telethon session file permissions"

    if [[ ! -d "${SESSION_DIR}" ]]; then
        log_warn "Session directory not found: ${SESSION_DIR}"
        log_info "Run setup-telethon-session.sh to create the session"
        return
    fi

    # Check directory permissions (should be 700)
    DIR_PERMS=$(stat -c %a "${SESSION_DIR}")
    if [[ "${DIR_PERMS}" == "700" ]]; then
        log_pass "Session directory has correct permissions (700)"
    else
        log_fail "Session directory has permissions ${DIR_PERMS} (expected 700)"
    fi

    # Check directory ownership
    DIR_OWNER=$(stat -c '%U' "${SESSION_DIR}")
    if [[ "${DIR_OWNER}" == "${SYNCER_USER}" ]]; then
        log_pass "Session directory owned by ${SYNCER_USER}"
    else
        log_fail "Session directory owned by ${DIR_OWNER} (expected ${SYNCER_USER})"
    fi

    # Check session file if it exists
    if [[ -f "${SESSION_FILE}" ]]; then
        FILE_PERMS=$(stat -c %a "${SESSION_FILE}")
        if [[ "${FILE_PERMS}" == "600" ]]; then
            log_pass "Session file has correct permissions (600)"
        else
            log_fail "Session file has permissions ${FILE_PERMS} (expected 600)"
        fi

        FILE_OWNER=$(stat -c '%U' "${SESSION_FILE}")
        if [[ "${FILE_OWNER}" == "${SYNCER_USER}" ]]; then
            log_pass "Session file owned by ${SYNCER_USER}"
        else
            log_fail "Session file owned by ${FILE_OWNER} (expected ${SYNCER_USER})"
        fi
    else
        log_warn "Session file not found: ${SESSION_FILE}"
        log_info "Run setup-telethon-session.sh to create the session"
    fi

    # Check for any unencrypted .session files (should not exist)
    UNENCRYPTED=$(find "${SESSION_DIR}" -name "*.session" ! -name "*.session.enc" 2>/dev/null | wc -l)
    if [[ "${UNENCRYPTED}" -gt 0 ]]; then
        log_fail "Found ${UNENCRYPTED} unencrypted .session file(s) in ${SESSION_DIR}"
        log_info "These should be encrypted. Run setup-telethon-session.sh"
    else
        log_pass "No unencrypted .session files found"
    fi
}

# =============================================================================
# Test 4: Telethon session file is encrypted (not raw SQLite)
# =============================================================================
test_session_encrypted() {
    log_test "4. Telethon session file is encrypted"

    if [[ ! -f "${SESSION_FILE}" ]]; then
        log_warn "Encrypted session file not found: ${SESSION_FILE}"
        return
    fi

    # Raw Telethon sessions are SQLite databases. Check the file magic.
    FILE_TYPE=$(file -b "${SESSION_FILE}" 2>/dev/null || echo "unknown")

    if echo "${FILE_TYPE}" | grep -qi "sqlite"; then
        log_fail "Session file is raw SQLite (NOT encrypted): ${FILE_TYPE}"
        log_info "The session file must be Fernet-encrypted. Re-run setup-telethon-session.sh"
    elif echo "${FILE_TYPE}" | grep -qi "data\|octet"; then
        log_pass "Session file is not raw SQLite (appears encrypted)"
    else
        # Fernet tokens start with 'gAAAAA' (base64-encoded). Check first bytes.
        FIRST_BYTES=$(head -c 6 "${SESSION_FILE}" 2>/dev/null | cat -v)
        if echo "${FIRST_BYTES}" | grep -q "gAAAAA"; then
            log_pass "Session file has Fernet token prefix (encrypted)"
        else
            log_warn "Session file type: ${FILE_TYPE} -- verify manually that it is encrypted"
        fi
    fi
}

# =============================================================================
# Test 5: nftables rules are active
# =============================================================================
test_nftables() {
    log_test "5. nftables firewall rules"

    if ! command -v nft &>/dev/null; then
        log_fail "nft command not found -- nftables not installed"
        return
    fi

    # Check if nftables service is active
    if systemctl is-active --quiet nftables 2>/dev/null; then
        log_pass "nftables service is active"
    else
        log_fail "nftables service is not active"
        log_info "Enable with: sudo systemctl enable --now nftables"
    fi

    # Check for tg_assistant table (either name is acceptable)
    if nft list tables 2>/dev/null | grep -Eq "tg_assistant(_isolation)?"; then
        log_pass "nftables table exists (tg_assistant or tg_assistant_isolation)"

        # Check for per-user rules
        if nft list table inet tg_assistant 2>/dev/null; then
            RULES=$(nft list table inet tg_assistant 2>/dev/null || echo "")
        else
            RULES=$(nft list table inet tg_assistant_isolation 2>/dev/null || echo "")
        fi

        SYNCER_UID=$(id -u "${SYNCER_USER}" 2>/dev/null || echo "NONE")
        QUERYBOT_UID=$(id -u "${QUERYBOT_USER}" 2>/dev/null || echo "NONE")

        if echo "${RULES}" | grep -Eq "skuid (${SYNCER_UID}|\"${SYNCER_USER}\")"; then
            log_pass "Firewall rules exist for ${SYNCER_USER} (UID ${SYNCER_UID})"
        else
            log_fail "No firewall rules found for ${SYNCER_USER}"
        fi

        if echo "${RULES}" | grep -Eq "skuid (${QUERYBOT_UID}|\"${QUERYBOT_USER}\")"; then
            log_pass "Firewall rules exist for ${QUERYBOT_USER} (UID ${QUERYBOT_UID})"
        else
            log_fail "No firewall rules found for ${QUERYBOT_USER}"
        fi

        if echo "${RULES}" | grep -q "drop"; then
            log_pass "Firewall has drop rules (default-deny for service users)"
        else
            log_warn "No drop rules found -- verify traffic is restricted"
        fi

        if nft list set inet tg_assistant_isolation querybot_api_ipv4 >/dev/null 2>&1 \
           && nft list set inet tg_assistant_isolation querybot_api_ipv6 >/dev/null 2>&1; then
            log_pass "Dynamic querybot API IP sets exist"
        else
            log_warn "Dynamic querybot API IP sets not found (legacy/static ruleset may be in use)"
        fi

        if nft list set inet tg_assistant_isolation dns_resolver_ipv4 >/dev/null 2>&1 \
           && nft list set inet tg_assistant_isolation dns_resolver_ipv6 >/dev/null 2>&1; then
            log_pass "DNS resolver allowlist sets exist"
        else
            log_warn "DNS resolver allowlist sets not found (DNS may be too broad)"
        fi
    else
        log_fail "nftables table 'tg_assistant' not found"
        log_info "Deploy rules with setup-raspberry-pi.sh"
    fi
}

# =============================================================================
# Test 6: Systemd services have security hardening
# =============================================================================
test_systemd_hardening() {
    log_test "6. Systemd service security hardening"

    REQUIRED_DIRECTIVES=(
        "NoNewPrivileges"
        "ProtectSystem"
        "ProtectHome"
        "PrivateTmp"
        "ReadOnlyPaths"
    )

    for SVC in tg-syncer tg-querybot; do
        SERVICE_FILE="/etc/systemd/system/${SVC}.service"

        if [[ ! -f "${SERVICE_FILE}" ]]; then
            log_warn "Service file not found: ${SERVICE_FILE}"
            continue
        fi

        log_info "Checking ${SVC}.service..."

        for DIRECTIVE in "${REQUIRED_DIRECTIVES[@]}"; do
            if grep -q "${DIRECTIVE}" "${SERVICE_FILE}"; then
                log_pass "${SVC}: ${DIRECTIVE} is configured"
            else
                log_fail "${SVC}: ${DIRECTIVE} is MISSING"
            fi
        done

        # Check that the correct user is specified
        if grep -q "User=${SVC/tg-/tg-}" "${SERVICE_FILE}" || grep -q "User=${SVC}" "${SERVICE_FILE}"; then
            log_pass "${SVC}: runs as dedicated user"
        else
            log_fail "${SVC}: not configured to run as dedicated user"
        fi
    done
}

# =============================================================================
# Test 7: Database role separation
# =============================================================================
test_db_role_separation() {
    log_test "7. Database role separation"

    if ! command -v psql &>/dev/null; then
        log_warn "psql not found -- skipping database tests"
        return
    fi

    if ! sudo -u postgres pg_isready -q 2>/dev/null; then
        log_warn "PostgreSQL is not running -- skipping database tests"
        return
    fi

    # Check syncer_role cannot DROP tables
    RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
        SELECT has_table_privilege('syncer_role', 'messages', 'DELETE');
    " 2>/dev/null || echo "error")

    if [[ "${RESULT}" == "f" ]]; then
        log_pass "syncer_role cannot DELETE from messages"
    elif [[ "${RESULT}" == "t" ]]; then
        log_fail "syncer_role CAN DELETE from messages (should be denied)"
    else
        log_warn "Could not verify syncer_role DELETE permission: ${RESULT}"
    fi

    # Check syncer_role can INSERT
    RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
        SELECT has_table_privilege('syncer_role', 'messages', 'INSERT');
    " 2>/dev/null || echo "error")

    if [[ "${RESULT}" == "t" ]]; then
        log_pass "syncer_role can INSERT into messages"
    else
        log_fail "syncer_role cannot INSERT into messages (should be allowed)"
    fi

    # Check syncer_role can update embedding only
    RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
        SELECT has_column_privilege('syncer_role', 'messages', 'embedding', 'UPDATE');
    " 2>/dev/null || echo "error")
    if [[ "${RESULT}" == "t" ]]; then
        log_pass "syncer_role can UPDATE messages.embedding"
    else
        log_fail "syncer_role cannot UPDATE messages.embedding (should be allowed)"
    fi

    RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
        SELECT has_column_privilege('syncer_role', 'messages', 'text', 'UPDATE');
    " 2>/dev/null || echo "error")
    if [[ "${RESULT}" == "f" ]]; then
        log_pass "syncer_role cannot UPDATE messages.text"
    elif [[ "${RESULT}" == "t" ]]; then
        log_fail "syncer_role CAN UPDATE messages.text (should be denied)"
    else
        log_warn "Could not verify syncer_role UPDATE(text) permission: ${RESULT}"
    fi

    # Check querybot_role cannot INSERT into messages
    RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
        SELECT has_table_privilege('querybot_role', 'messages', 'INSERT');
    " 2>/dev/null || echo "error")

    if [[ "${RESULT}" == "f" ]]; then
        log_pass "querybot_role cannot INSERT into messages"
    elif [[ "${RESULT}" == "t" ]]; then
        log_fail "querybot_role CAN INSERT into messages (should be denied)"
    else
        log_warn "Could not verify querybot_role INSERT permission: ${RESULT}"
    fi

    # Check querybot_role can SELECT
    RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
        SELECT has_table_privilege('querybot_role', 'messages', 'SELECT');
    " 2>/dev/null || echo "error")

    if [[ "${RESULT}" == "t" ]]; then
        log_pass "querybot_role can SELECT from messages"
    else
        log_fail "querybot_role cannot SELECT from messages (should be allowed)"
    fi

    # Check neither role can DROP (CREATE privilege on schema)
    for ROLE in syncer_role querybot_role; do
        RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
            SELECT has_schema_privilege('${ROLE}', 'public', 'CREATE');
        " 2>/dev/null || echo "error")

        if [[ "${RESULT}" == "f" ]]; then
            log_pass "${ROLE} cannot CREATE in public schema (no DDL)"
        elif [[ "${RESULT}" == "t" ]]; then
            log_fail "${ROLE} CAN CREATE in public schema (should be denied)"
        else
            log_warn "Could not verify ${ROLE} CREATE permission: ${RESULT}"
        fi
    done

    # Check pgvector extension
    RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
        SELECT extname FROM pg_extension WHERE extname = 'vector';
    " 2>/dev/null || echo "")

    if [[ "${RESULT}" == "vector" ]]; then
        log_pass "pgvector extension is installed"
    else
        log_fail "pgvector extension is not installed"
    fi
}

# =============================================================================
# Test 8: Audit logging is enabled
# =============================================================================
test_audit_logging() {
    log_test "8. Audit logging configuration"

    # Check audit_log table exists in the database
    if command -v psql &>/dev/null && sudo -u postgres pg_isready -q 2>/dev/null; then
        RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'audit_log'
            );
        " 2>/dev/null || echo "error")

        if [[ "${RESULT}" == "t" ]]; then
            log_pass "audit_log table exists in database"
        else
            log_fail "audit_log table not found in database"
        fi

        # Both roles should be able to INSERT into audit_log
        for ROLE in syncer_role querybot_role; do
            RESULT=$(sudo -u postgres psql -d "${DB_NAME}" -tAc "
                SELECT has_table_privilege('${ROLE}', 'audit_log', 'INSERT');
            " 2>/dev/null || echo "error")

            if [[ "${RESULT}" == "t" ]]; then
                log_pass "${ROLE} can INSERT into audit_log"
            else
                log_fail "${ROLE} cannot INSERT into audit_log"
            fi
        done
    else
        log_warn "Cannot check database -- PostgreSQL not available"
    fi

    # Check config file for audit settings
    if [[ -f "${CONFIG_FILE}" ]]; then
        if grep -q 'enable_audit_log.*=.*true' "${CONFIG_FILE}" 2>/dev/null; then
            log_pass "Audit logging is enabled in config"
        else
            log_warn "Audit logging may not be enabled in config"
        fi
    fi
}

# =============================================================================
# Test 9: Log directory permissions
# =============================================================================
test_log_directory() {
    log_test "9. Log directory permissions"

    if [[ ! -d "${LOG_DIR}" ]]; then
        log_fail "Log directory does not exist: ${LOG_DIR}"
        return
    fi

    # Main log directory
    PERMS=$(stat -c %a "${LOG_DIR}")
    if [[ "${PERMS}" == "775" || "${PERMS}" == "770" || "${PERMS}" == "755" || "${PERMS}" == "750" || "${PERMS}" == "700" ]]; then
        log_pass "Log directory has secure permissions (${PERMS})"
    else
        log_fail "Log directory has permissions ${PERMS} (expected 775/770/755/750/700)"
    fi

    # Syncer log subdirectory
    if [[ -d "${LOG_DIR}/syncer" ]]; then
        OWNER=$(stat -c '%U' "${LOG_DIR}/syncer")
        PERMS=$(stat -c %a "${LOG_DIR}/syncer")
        if [[ "${OWNER}" == "${SYNCER_USER}" && ("${PERMS}" == "750" || "${PERMS}" == "700") ]]; then
            log_pass "Syncer log dir: ${OWNER}, ${PERMS}"
        else
            log_fail "Syncer log dir: owner=${OWNER} perms=${PERMS} (expected ${SYNCER_USER}, 750)"
        fi
    else
        log_warn "Syncer log directory not found: ${LOG_DIR}/syncer"
    fi

    # Querybot log subdirectory
    if [[ -d "${LOG_DIR}/querybot" ]]; then
        OWNER=$(stat -c '%U' "${LOG_DIR}/querybot")
        PERMS=$(stat -c %a "${LOG_DIR}/querybot")
        if [[ "${OWNER}" == "${QUERYBOT_USER}" && ("${PERMS}" == "750" || "${PERMS}" == "700") ]]; then
            log_pass "Querybot log dir: ${OWNER}, ${PERMS}"
        else
            log_fail "Querybot log dir: owner=${OWNER} perms=${PERMS} (expected ${QUERYBOT_USER}, 750)"
        fi
    else
        log_warn "Querybot log directory not found: ${LOG_DIR}/querybot"
    fi
}

# =============================================================================
# Test 10: No plaintext credentials in config or environment
# =============================================================================
test_no_plaintext_credentials() {
    log_test "10. No plaintext credentials in config or environment"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Config file not found -- skipping credential check"
        return
    fi

    # Check for common credential patterns in settings.toml
    CREDENTIAL_PATTERNS=(
        'bot_token\s*=\s*"[0-9]+:'           # Bot tokens look like 123456:ABC-DEF...
        'api_key\s*=\s*"sk-'                   # Anthropic keys start with sk-
        'password\s*=\s*"[^"]{8,}'            # Passwords longer than 8 chars
        'session_key\s*=\s*"[A-Za-z0-9+/=]'  # Base64 encoded keys
    )

    FOUND_CREDS=false
    for PATTERN in "${CREDENTIAL_PATTERNS[@]}"; do
        if grep -qP "${PATTERN}" "${CONFIG_FILE}" 2>/dev/null; then
            log_fail "Possible plaintext credential found matching: ${PATTERN}"
            FOUND_CREDS=true
        fi
    done

    if [[ "${FOUND_CREDS}" == false ]]; then
        log_pass "No plaintext credentials detected in ${CONFIG_FILE}"
    fi

    # Verify API ID/hash are placeholders (stored in encrypted credstore instead)
    if grep -q 'api_id = "YOUR_API_ID"' "${CONFIG_FILE}" 2>/dev/null && \
       grep -q 'api_hash = "YOUR_API_HASH"' "${CONFIG_FILE}" 2>/dev/null; then
        log_pass "API ID/hash are placeholders (stored in credstore)"
    else
        log_warn "API ID/hash appear set in config; should be placeholders"
    fi

    # Check for .env files with credentials
    for DIR in "${CONFIG_DIR}" "${SYNCER_HOME}" "${QUERYBOT_HOME}" "/opt/tg-assistant"; do
        if [[ -f "${DIR}/.env" ]]; then
            log_warn ".env file found at ${DIR}/.env -- verify it does not contain secrets"
            PERMS=$(stat -c %a "${DIR}/.env" 2>/dev/null || echo "???")
            if [[ "${PERMS}" != "600" ]]; then
                log_fail "${DIR}/.env has permissions ${PERMS} (expected 600)"
            fi
        fi
    done

    # Check systemd service files for hardcoded credentials
    for SVC in tg-syncer tg-querybot; do
        SERVICE_FILE="/etc/systemd/system/${SVC}.service"
        if [[ -f "${SERVICE_FILE}" ]]; then
            if grep -qP '(BOT_TOKEN|API_KEY|PASSWORD|SECRET)=\S+' "${SERVICE_FILE}" 2>/dev/null; then
                log_fail "Possible hardcoded credential in ${SERVICE_FILE}"
            else
                log_pass "No hardcoded credentials in ${SVC}.service"
            fi
        fi
    done

    # Check encrypted credstore entries exist
    if [[ -d /etc/credstore.encrypted ]]; then
        for CRED in tg-assistant-bot-token tg-assistant-claude-api-key tg-assistant-api-id tg-assistant-api-hash session_encryption_key; do
            if [[ -f "/etc/credstore.encrypted/${CRED}" ]]; then
                log_pass "Credstore entry present: ${CRED}"
            else
                log_warn "Credstore entry missing: ${CRED}"
            fi
        done
    else
        log_warn "Credstore directory not found: /etc/credstore.encrypted"
    fi

    # Check environment of running processes
    for SVC_USER in "${SYNCER_USER}" "${QUERYBOT_USER}"; do
        PIDS=$(pgrep -u "${SVC_USER}" 2>/dev/null || echo "")
        if [[ -n "${PIDS}" ]]; then
            for PID in ${PIDS}; do
                if cat "/proc/${PID}/environ" 2>/dev/null | tr '\0' '\n' | grep -qiP '(token|key|password|secret)=\S+'; then
                    log_warn "Process ${PID} (${SVC_USER}) has credential-like environment variables"
                    log_info "Verify these are injected via systemd LoadCredential, not plain env vars"
                fi
            done
        fi
    done
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    echo ""
    echo "=============================================="
    echo "  Test Summary"
    echo "=============================================="
    echo ""
    echo -e "  ${GREEN}Passed:${NC}   ${PASSED}"
    echo -e "  ${RED}Failed:${NC}   ${FAILED}"
    echo -e "  ${YELLOW}Warnings:${NC} ${WARNINGS}"
    echo ""

    TOTAL=$((PASSED + FAILED + WARNINGS))
    echo "  Total checks: ${TOTAL}"
    echo ""

    if [[ ${FAILED} -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}RESULT: Some security tests FAILED.${NC}"
        echo -e "  ${RED}Review and fix the failures above before running in production.${NC}"
        echo ""
        exit 1
    elif [[ ${WARNINGS} -gt 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}RESULT: All tests passed, but warnings detected.${NC}"
        echo -e "  ${YELLOW}Review the warnings above. They may indicate incomplete setup.${NC}"
        echo ""
        exit 0
    else
        echo -e "  ${GREEN}${BOLD}RESULT: All security tests passed.${NC}"
        echo ""
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    test_config_permissions
    test_system_users
    test_session_permissions
    test_session_encrypted
    test_nftables
    test_systemd_hardening
    test_db_role_separation
    test_audit_logging
    test_log_directory
    test_no_plaintext_credentials
    print_summary
}

main "$@"
