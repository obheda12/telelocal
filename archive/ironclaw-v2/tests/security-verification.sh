#!/bin/bash
#
# IronClaw Security Verification Tests
#
# Run these tests after deployment to verify security controls are working.
# Some tests require IronClaw to be running.
#
# Usage: ./security-verification.sh
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

log_test() { echo -e "${BLUE}[TEST]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
log_info() { echo -e "       $1"; }

echo "=============================================="
echo "  IronClaw Security Verification Tests"
echo "=============================================="
echo ""

# =============================================================================
# Test 1: Configuration File Security
# =============================================================================
test_config_permissions() {
    log_test "Checking configuration file permissions..."

    CONFIG_FILE="${HOME}/.ironclaw/settings.toml"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Configuration file not found: ${CONFIG_FILE}"
        return
    fi

    PERMS=$(stat -c %a "${CONFIG_FILE}")

    if [[ "${PERMS}" == "600" ]]; then
        log_pass "settings.toml has correct permissions (600)"
    else
        log_fail "settings.toml has insecure permissions: ${PERMS} (should be 600)"
    fi
}

# =============================================================================
# Test 2: HTTP Allowlist Configuration
# =============================================================================
test_http_allowlist() {
    log_test "Checking HTTP allowlist configuration..."

    CONFIG_FILE="${HOME}/.ironclaw/settings.toml"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Configuration file not found"
        return
    fi

    # Check that http_allowlist exists and is restricted
    if grep -q 'http_allowlist.*\[\]' "${CONFIG_FILE}"; then
        log_pass "HTTP allowlist is empty (maximum security - Option C)"
    elif grep -q 'http_allowlist.*api\.telegram\.org' "${CONFIG_FILE}"; then
        log_pass "HTTP allowlist restricted to api.telegram.org (Option A)"
    else
        log_fail "HTTP allowlist may not be properly configured"
        log_info "Check: grep http_allowlist ${CONFIG_FILE}"
    fi
}

# =============================================================================
# Test 3: Telegram Method Blocking
# =============================================================================
test_telegram_method_blocking() {
    log_test "Checking Telegram write methods are blocked..."

    CONFIG_FILE="${HOME}/.ironclaw/settings.toml"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Configuration file not found"
        return
    fi

    # Check for blocked_methods containing sendMessage
    if grep -q 'sendMessage' "${CONFIG_FILE}"; then
        log_pass "sendMessage is in blocked methods list"
    else
        log_fail "sendMessage not found in blocked_methods"
    fi

    # Check allowed_methods doesn't include write operations
    if grep -A 20 'allowed_methods' "${CONFIG_FILE}" | grep -q 'sendMessage'; then
        log_fail "sendMessage found in allowed_methods!"
    else
        log_pass "sendMessage not in allowed_methods"
    fi
}

# =============================================================================
# Test 4: Log Directory Security
# =============================================================================
test_log_directory() {
    log_test "Checking log directory configuration..."

    LOG_DIR="/var/log/ironclaw"

    if [[ ! -d "${LOG_DIR}" ]]; then
        log_warn "Log directory does not exist: ${LOG_DIR}"
        return
    fi

    # Check ownership
    OWNER=$(stat -c %U "${LOG_DIR}")
    if [[ "${OWNER}" == "pi" || "${OWNER}" == "${USER}" ]]; then
        log_pass "Log directory owned by correct user: ${OWNER}"
    else
        log_warn "Log directory owned by: ${OWNER}"
    fi

    # Check permissions
    PERMS=$(stat -c %a "${LOG_DIR}")
    if [[ "${PERMS}" == "750" || "${PERMS}" == "700" ]]; then
        log_pass "Log directory has secure permissions: ${PERMS}"
    else
        log_warn "Log directory permissions: ${PERMS} (recommend 750 or 700)"
    fi
}

# =============================================================================
# Test 5: PostgreSQL Connection
# =============================================================================
test_postgresql() {
    log_test "Checking PostgreSQL configuration..."

    if ! command -v psql &> /dev/null; then
        log_warn "psql not found - skipping database tests"
        return
    fi

    # Check if we can connect (without exposing password)
    if psql -h localhost -U ironclaw -d ironclaw -c "SELECT 1;" &> /dev/null; then
        log_pass "Can connect to PostgreSQL database"

        # Check pgvector extension
        if psql -h localhost -U ironclaw -d ironclaw -c "SELECT extname FROM pg_extension WHERE extname='vector';" | grep -q vector; then
            log_pass "pgvector extension is installed"
        else
            log_fail "pgvector extension not found"
        fi
    else
        log_warn "Cannot connect to PostgreSQL - may need PGPASSWORD"
    fi
}

# =============================================================================
# Test 6: Network Connectivity (should be restricted)
# =============================================================================
test_network_restrictions() {
    log_test "Checking network restrictions..."

    # This test should be run FROM the IronClaw process context
    # Here we just verify the config intention

    log_info "To verify network isolation, run these commands while IronClaw is active:"
    log_info "  sudo tcpdump -i any -n 'host not api.telegram.org and not localhost'"
    log_info "Expected: No traffic to non-Telegram hosts"

    # Check if systemd service has network restrictions
    SERVICE_FILE="/etc/systemd/system/ironclaw.service"
    if [[ -f "${SERVICE_FILE}" ]]; then
        if grep -q "RestrictAddressFamilies" "${SERVICE_FILE}"; then
            log_pass "Systemd service has network restrictions configured"
        else
            log_warn "Systemd service may not have network restrictions"
        fi
    else
        log_info "Systemd service not installed - skipping service checks"
    fi
}

# =============================================================================
# Test 7: Audit Logging Enabled
# =============================================================================
test_audit_logging() {
    log_test "Checking audit logging configuration..."

    CONFIG_FILE="${HOME}/.ironclaw/settings.toml"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Configuration file not found"
        return
    fi

    if grep -q 'log_all_queries.*=.*true' "${CONFIG_FILE}"; then
        log_pass "Query logging is enabled"
    else
        log_fail "Query logging may not be enabled"
    fi

    if grep -q 'log_tool_executions.*=.*true' "${CONFIG_FILE}"; then
        log_pass "Tool execution logging is enabled"
    else
        log_fail "Tool execution logging may not be enabled"
    fi
}

# =============================================================================
# Test 8: Prompt Injection Defense
# =============================================================================
test_prompt_injection_defense() {
    log_test "Checking prompt injection defense configuration..."

    CONFIG_FILE="${HOME}/.ironclaw/settings.toml"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Configuration file not found"
        return
    fi

    if grep -q 'prompt_injection_severity.*=.*"block"' "${CONFIG_FILE}"; then
        log_pass "Prompt injection severity set to 'block'"
    elif grep -q 'prompt_injection_severity.*=.*"warn"' "${CONFIG_FILE}"; then
        log_warn "Prompt injection severity set to 'warn' (recommend 'block')"
    else
        log_fail "Prompt injection defense may not be configured"
    fi
}

# =============================================================================
# Test 9: WASM Sandbox Configuration
# =============================================================================
test_wasm_sandbox() {
    log_test "Checking WASM sandbox configuration..."

    CONFIG_FILE="${HOME}/.ironclaw/settings.toml"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_warn "Configuration file not found"
        return
    fi

    if grep -q 'allow_filesystem.*=.*false' "${CONFIG_FILE}"; then
        log_pass "WASM filesystem access disabled"
    else
        log_warn "WASM filesystem access may be enabled"
    fi

    if grep -q 'allow_network.*=.*false' "${CONFIG_FILE}"; then
        log_pass "WASM network access disabled"
    else
        log_warn "WASM network access may be enabled"
    fi
}

# =============================================================================
# Test 10: Secret Storage
# =============================================================================
test_secret_storage() {
    log_test "Checking secret storage..."

    # Verify secrets are not in plaintext config
    CONFIG_FILE="${HOME}/.ironclaw/settings.toml"

    if [[ -f "${CONFIG_FILE}" ]]; then
        if grep -qi "telegram.*token.*=" "${CONFIG_FILE}" | grep -v "Secret:"; then
            log_fail "Possible plaintext token in config file!"
        else
            log_pass "No plaintext tokens found in config"
        fi
    fi

    # Check for .env files with secrets
    if [[ -f "${HOME}/.ironclaw/.env" ]]; then
        log_warn ".env file found - ensure it has proper permissions"
        PERMS=$(stat -c %a "${HOME}/.ironclaw/.env")
        if [[ "${PERMS}" != "600" ]]; then
            log_fail ".env file has insecure permissions: ${PERMS}"
        fi
    fi

    log_info "Secrets should be stored via: ironclaw secrets add TELEGRAM_BOT_TOKEN"
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

    if [[ ${FAILED} -gt 0 ]]; then
        echo -e "${RED}Some security tests failed. Please review and fix before production use.${NC}"
        exit 1
    elif [[ ${WARNINGS} -gt 0 ]]; then
        echo -e "${YELLOW}Some warnings detected. Review recommended but not blocking.${NC}"
        exit 0
    else
        echo -e "${GREEN}All security tests passed!${NC}"
        exit 0
    fi
}

# Run all tests
main() {
    test_config_permissions
    test_http_allowlist
    test_telegram_method_blocking
    test_log_directory
    test_postgresql
    test_network_restrictions
    test_audit_logging
    test_prompt_injection_defense
    test_wasm_sandbox
    test_secret_storage
    print_summary
}

main "$@"
