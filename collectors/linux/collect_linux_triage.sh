#!/usr/bin/env bash
# ==============================================================================
# ForensicOps AI - Headless Linux Endpoint Triage & Artifact Collector v4.0
# Standards: RFC 3227 (Order of Volatility), NIST SP 800-86, ISO/IEC 27037
# ==============================================================================

set -u

CASE_ID="CASE-$(date -u +%Y%m%d-%H%M%S)"
OUTPUT_ROOT="/tmp/ForensicOps_Capsule"
MODULES="Volatile,SystemInfo,Logs,Persistence,UsersAndSSH,Containers"
INCLUDE_MEMORY_DUMP=0
TOOLS_BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case-id) CASE_ID="$2"; shift 2 ;;
        --output-root) OUTPUT_ROOT="$2"; shift 2 ;;
        --modules) MODULES="$2"; shift 2 ;;
        --include-memory-dump) INCLUDE_MEMORY_DUMP=1; shift 1 ;;
        --tools-bin-dir) TOOLS_BIN_DIR="$2"; shift 2 ;;
        *) echo "[FATAL] Unknown parameter: $1" >&2; exit 1 ;;
    esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[FATAL] Root privileges (UID 0) are required for forensic acquisition." >&2
    exit 1
fi

START_TIME_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CAPSULE_DIR="${OUTPUT_ROOT}/${CASE_ID}"
ARTIFACTS_DIR="${CAPSULE_DIR}/artifacts"
mkdir -p "${ARTIFACTS_DIR}"
chmod 700 "${CAPSULE_DIR}"

LOG_FILE="${CAPSULE_DIR}/collector_execution.log"
echo "[${START_TIME_UTC}] [INFO] Starting ForensicOps AI Linux Triage Collection for Case: ${CASE_ID}" > "${LOG_FILE}"
