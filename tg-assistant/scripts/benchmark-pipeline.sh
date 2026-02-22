#!/bin/bash
#
# benchmark-pipeline.sh — ingestion + query latency benchmark
#
# Usage:
#   ./scripts/benchmark-pipeline.sh
#   ./scripts/benchmark-pipeline.sh --query-count 20 --runs-per-query 6
#   ./scripts/benchmark-pipeline.sh --queries-file ./queries.txt
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

CONFIG_PATH="/etc/tg-assistant/settings.toml"
if [[ ! -f "${CONFIG_PATH}" ]]; then
    CONFIG_PATH="${SCRIPT_DIR}/../config/settings.toml"
fi

PYTHONPATH="${SCRIPT_DIR}/../src" \
exec python3 "${SCRIPT_DIR}/benchmark_pipeline.py" \
    --config "${CONFIG_PATH}" \
    "$@"
