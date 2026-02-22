#!/bin/bash
#
# Refresh nftables IP sets for querybot API egress allowlists.
#
# Resolves api.telegram.org and api.anthropic.com, then updates:
#   - querybot_api_ipv4
#   - querybot_api_ipv6
# in table: inet tg_assistant_isolation

set -euo pipefail

TABLE_FAMILY="inet"
TABLE_NAME="tg_assistant_isolation"
DNS_SET_IPV4="dns_resolver_ipv4"
DNS_SET_IPV6="dns_resolver_ipv6"
SET_IPV4="querybot_api_ipv4"
SET_IPV6="querybot_api_ipv6"
API_HOSTS=("api.telegram.org" "api.anthropic.com")

log() {
    printf '[refresh-api-ipsets] %s\n' "$1"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "Missing required command: $1"
        exit 1
    fi
}

resolve_ipv4() {
    local host="$1"
    getent ahostsv4 "$host" \
        | awk '{print $1}' \
        | sort -u
}

resolve_ipv6() {
    local host="$1"
    getent ahostsv6 "$host" \
        | awk '{print $1}' \
        | sed 's/%.*$//' \
        | sort -u
}

sync_set() {
    local set_name="$1"
    shift
    local values=("$@")

    nft flush set "$TABLE_FAMILY" "$TABLE_NAME" "$set_name"
    if [[ ${#values[@]} -eq 0 ]]; then
        return
    fi

    local csv
    csv="$(printf '%s, ' "${values[@]}")"
    csv="${csv%, }"
    nft add element "$TABLE_FAMILY" "$TABLE_NAME" "$set_name" "{ ${csv} }"
}

main() {
    require_cmd nft
    require_cmd getent

    if [[ $EUID -ne 0 ]]; then
        log "Run as root."
        exit 1
    fi

    nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null
    nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$DNS_SET_IPV4" >/dev/null
    nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$DNS_SET_IPV6" >/dev/null
    nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_IPV4" >/dev/null
    nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_IPV6" >/dev/null

    declare -A dns_seen_v4=()
    declare -A dns_seen_v6=()
    declare -A seen_v4=()
    declare -A seen_v6=()

    while IFS= read -r resolver; do
        [[ -n "$resolver" ]] || continue
        resolver="${resolver%%#*}"
        resolver="${resolver// /}"
        [[ -n "$resolver" ]] || continue
        resolver="${resolver#\[}"
        resolver="${resolver%\]}"
        resolver="${resolver%%%*}"
        if [[ "$resolver" == *:* ]]; then
            dns_seen_v6["$resolver"]=1
        elif [[ "$resolver" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            dns_seen_v4["$resolver"]=1
        fi
    done < <(awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null)

    for host in "${API_HOSTS[@]}"; do
        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue
            seen_v4["$ip"]=1
        done < <(resolve_ipv4 "$host" || true)

        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue
            seen_v6["$ip"]=1
        done < <(resolve_ipv6 "$host" || true)
    done

    mapfile -t ipv4_list < <(printf '%s\n' "${!seen_v4[@]}" | sort -u)
    mapfile -t ipv6_list < <(printf '%s\n' "${!seen_v6[@]}" | sort -u)
    mapfile -t dns_ipv4_list < <(printf '%s\n' "${!dns_seen_v4[@]}" | sort -u)
    mapfile -t dns_ipv6_list < <(printf '%s\n' "${!dns_seen_v6[@]}" | sort -u)

    if [[ ${#dns_ipv4_list[@]} -eq 0 && ${#dns_ipv6_list[@]} -eq 0 ]]; then
        log "No DNS resolvers found in /etc/resolv.conf; refusing to flush DNS sets."
        exit 1
    fi

    if [[ ${#ipv4_list[@]} -eq 0 && ${#ipv6_list[@]} -eq 0 ]]; then
        log "DNS resolution returned no IPs; refusing to flush allowlists."
        exit 1
    fi

    sync_set "$DNS_SET_IPV4" "${dns_ipv4_list[@]}"
    sync_set "$DNS_SET_IPV6" "${dns_ipv6_list[@]}"
    sync_set "$SET_IPV4" "${ipv4_list[@]}"
    sync_set "$SET_IPV6" "${ipv6_list[@]}"

    log "Updated $DNS_SET_IPV4 with ${#dns_ipv4_list[@]} entries"
    log "Updated $DNS_SET_IPV6 with ${#dns_ipv6_list[@]} entries"
    log "Updated $SET_IPV4 with ${#ipv4_list[@]} entries"
    log "Updated $SET_IPV6 with ${#ipv6_list[@]} entries"
}

main "$@"
