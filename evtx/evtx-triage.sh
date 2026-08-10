#!/usr/bin/env bash
# evtx-triage.sh — EVTX triage wrapper: Hayabusa (dfir-timeline x2) + Takajo
#                  (automagic) + Chainsaw (Sigma hunt) over a directory of
#                  Windows Event Log (.evtx) files.
#
# Usage:   evtx-triage.sh -i <evtx_dir> [-o <output_base>]
#          evtx-triage.sh [-h|--help]
#
# Tested on: REMnux (v2026.26.13, Ubuntu 24.04.3 LTS) — full run against
#            the Yamato-Security/hayabusa-sample-evtx corpus (599 EVTX
#            files) verified end to end (2026-08-06; see CHANGELOG for
#            acceptance details). Syntax also validated in a Debian 12 dev
#            container. Requires evtx/get-tools.sh to have been run first.
# Version:   0.1.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Date:      2026-08-06
# Platforms: Linux (bash 4+)

set -euo pipefail

### CONSTANTS
SCRIPT_NAME="evtx-triage.sh"
SCRIPT_VERSION="0.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

### SHARED UTILITIES
# evtx/ is a sibling of triage/, not a child — path goes up one level.
if [[ ! -f "${SCRIPT_DIR}/../triage/common/utils.sh" ]]; then
    echo "[ERROR] Required file not found: ${SCRIPT_DIR}/../triage/common/utils.sh" >&2
    exit 2
fi
# shellcheck source=../triage/common/utils.sh
source "${SCRIPT_DIR}/../triage/common/utils.sh"

### TOOL PATHS (stable names — versions live only in get-tools.sh)
DIR_BIN_HAYABUSA="${SCRIPT_DIR}/bin/hayabusa"
DIR_BIN_TAKAJO="${SCRIPT_DIR}/bin/takajo"
DIR_BIN_CHAINSAW="${SCRIPT_DIR}/bin/chainsaw"
DIR_BIN_LIB="${SCRIPT_DIR}/bin/lib"
DIR_RULES_SIGMA_WINDOWS="${SCRIPT_DIR}/rules/sigma/rules/windows"
CHAINSAW_MAPPING="${DIR_BIN_CHAINSAW}/mappings/sigma-event-logs-all.yml"

BIN_HAYABUSA="${DIR_BIN_HAYABUSA}/hayabusa"
BIN_TAKAJO="${DIR_BIN_TAKAJO}/takajo"
BIN_CHAINSAW="${DIR_BIN_CHAINSAW}/chainsaw"
LIB_DUCKDB="${DIR_BIN_LIB}/libduckdb.so"

# Generous run_polled caps (long-running scans over large EVTX corpora).
HAYABUSA_MAX_SECS=3600
HAYABUSA_POLL_INTERVAL=30
TAKAJO_MAX_SECS=1800
TAKAJO_POLL_INTERVAL=20
CHAINSAW_MAX_SECS=1800
CHAINSAW_POLL_INTERVAL=20

FAILURES=0

### FUNCTIONS

script_usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} -i <evtx_dir> [-o <output_base>]
       ${SCRIPT_NAME} [-h|--help]

Runs the EVTX triage toolchain (Hayabusa dfir-timeline x2, Takajo automagic,
Chainsaw Sigma hunt) over a directory of Windows Event Log (.evtx) files and
writes numbered outputs into one timestamped run directory.

Options:
  -i, --input-dir PATH     Directory containing .evtx files (required)
  -o, --output-base PATH   Parent directory for the run directory
                            (default: .)
  -h, --help                Show this help and exit

Requires evtx/get-tools.sh to have been run first (installs Hayabusa,
Takajo, Chainsaw, libduckdb, SigmaHQ rules into evtx/bin and evtx/rules).

Output (under <output_base>/output_<evtx_dir_name>_<timestamp>/):
  001-hayabusa-timeline.csv    Hayabusa dfir-timeline, CSV, standard profile
                                 (input for the timeline notebook)
  001-hayabusa-timeline.log     run_polled log for the above
  002-hayabusa-timeline.jsonl   Hayabusa dfir-timeline, JSONL, super-verbose
                                 (input for Takajo)
  002-hayabusa-timeline.log     run_polled log for the above
  003-takajo-automagic/         Takajo automagic output directory
  003-takajo-automagic.log      run_polled log for the above
  004-chainsaw-hunt/             Chainsaw Sigma hunt CSV output directory
  004-chainsaw-hunt.log          run_polled log for the above

Exit codes:
  0  success (all four steps produced non-empty output)
  1  argument error / input dir not found
  2  missing required tool — run evtx/get-tools.sh first
  3  one or more triage steps failed or produced empty output (see logs);
     any successfully produced outputs are still left in the run directory
EOF
}

# Reports a run_polled return code (see triage/common/utils.sh) for a given
# step, without aborting the script (best-effort triage: a failing tool
# should not prevent the remaining tools from running).
report_step_rc() {
    local label="$1"
    local rc="$2"
    local artifact="$3"
    local logfile="$4"
    case "${rc}" in
        0)
            # run_polled rc=0 znamená len "nástroj skončil 0 a LOG je neprázdny"
            # (utils.sh r. 98) — o artefakte nevypovedá nič. Overiť ho treba tu.
            if [[ -d "${artifact}" ]]; then
                if [[ -z "$(ls -A "${artifact}" 2>/dev/null)" ]]; then
                    log_warn "${label}: tool reported success but output directory is empty: ${artifact}"
                    FAILURES=$((FAILURES + 1))
                    return
                fi
            elif [[ ! -s "${artifact}" ]]; then
                log_warn "${label}: tool reported success but artifact is missing or empty: ${artifact}"
                FAILURES=$((FAILURES + 1))
                return
            fi
            log_info "${label}: OK — artifact: ${artifact} (log: ${logfile})"
            ;;
        1) log_warn "${label}: tool exited non-zero — see log: ${logfile}"; FAILURES=$((FAILURES + 1)) ;;
        2) log_warn "${label}: exceeded time cap — terminated — see log: ${logfile}"; FAILURES=$((FAILURES + 1)) ;;
        3) log_warn "${label}: produced no log output — see log: ${logfile}"; FAILURES=$((FAILURES + 1)) ;;
        *) log_warn "${label}: unexpected run_polled status rc=${rc} — see log: ${logfile}"; FAILURES=$((FAILURES + 1)) ;;
    esac
}

check_tools() {
    local missing=0

    if [[ ! -x "${BIN_HAYABUSA}" ]]; then
        log_error "Hayabusa binary not found or not executable: ${BIN_HAYABUSA}"
        missing=$((missing + 1))
    fi
    if [[ ! -x "${BIN_TAKAJO}" ]]; then
        log_error "Takajo binary not found or not executable: ${BIN_TAKAJO}"
        missing=$((missing + 1))
    fi
    if [[ ! -x "${BIN_CHAINSAW}" ]]; then
        log_error "Chainsaw binary not found or not executable: ${BIN_CHAINSAW}"
        missing=$((missing + 1))
    fi
    if [[ ! -f "${LIB_DUCKDB}" ]]; then
        log_error "libduckdb.so not found: ${LIB_DUCKDB}"
        missing=$((missing + 1))
    fi
    if [[ ! -f "${CHAINSAW_MAPPING}" ]]; then
        log_error "Chainsaw mapping file not found: ${CHAINSAW_MAPPING}"
        missing=$((missing + 1))
    fi
    if [[ ! -d "${DIR_RULES_SIGMA_WINDOWS}" ]]; then
        log_error "SigmaHQ windows rules directory not found: ${DIR_RULES_SIGMA_WINDOWS}"
        missing=$((missing + 1))
    fi

    if [[ "${missing}" -gt 0 ]]; then
        log_error "Missing ${missing} required tool(s)/asset(s). Run evtx/get-tools.sh first."
        exit 2
    fi
}

### ARGUMENT PARSER
INPUT_DIR_ARG=""
OUTPUT_BASE_ARG=""

if [[ "$#" -eq 0 ]]; then
    script_usage
    exit 1
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -i|--input-dir)
            if [[ -z "${2:-}" ]]; then
                log_error "Option $1 requires an argument."
                script_usage
                exit 1
            fi
            INPUT_DIR_ARG="$2"
            shift 2
            ;;
        -o|--output-base)
            if [[ -z "${2:-}" ]]; then
                log_error "Option $1 requires an argument."
                script_usage
                exit 1
            fi
            OUTPUT_BASE_ARG="$2"
            shift 2
            ;;
        -h|--help)
            script_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            script_usage
            exit 1
            ;;
    esac
done

### INPUT VALIDATION
if [[ -z "${INPUT_DIR_ARG}" ]]; then
    log_error "Option -i / --input-dir is required."
    script_usage
    exit 1
fi

if [[ ! -d "${INPUT_DIR_ARG}" || ! -r "${INPUT_DIR_ARG}" ]]; then
    log_error "Directory not found or not readable: ${INPUT_DIR_ARG}"
    exit 1
fi

INPUT_DIR="$(cd "${INPUT_DIR_ARG}" && pwd)"
INPUT_BASENAME="$(basename "${INPUT_DIR}")"

if [[ -z "$(find "${INPUT_DIR}" -maxdepth 5 -iname '*.evtx' -print -quit 2>/dev/null)" ]]; then
    log_warn "No .evtx files found under: ${INPUT_DIR} (Hayabusa will likely report zero events)."
fi

### TOOL PRE-FLIGHT
check_tools

### OUTPUT DIRECTORY SETUP
OUTPUT_BASE="${OUTPUT_BASE_ARG:-.}"
mkdir -p "${OUTPUT_BASE}"
OUTPUT_BASE="$(cd "${OUTPUT_BASE}" && pwd)"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${OUTPUT_BASE}/output_${INPUT_BASENAME}_${TIMESTAMP}"
ensure_dir "${RUN_DIR}"

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
log_info "Input EVTX directory: ${INPUT_DIR}"
log_info "Run directory:        ${RUN_DIR}"
echo ""

### 001 — Hayabusa dfir-timeline: CSV, standard profile (notebook input)
log_info "Step 001: Hayabusa dfir-timeline (CSV, standard profile)..."
HAYABUSA_CSV="${RUN_DIR}/001-hayabusa-timeline.csv"
HAYABUSA_CSV_LOG="${RUN_DIR}/001-hayabusa-timeline.log"
rc=0
(
    cd "${DIR_BIN_HAYABUSA}"
    run_polled "hayabusa-csv-timeline" "${HAYABUSA_MAX_SECS}" "${HAYABUSA_POLL_INTERVAL}" "${HAYABUSA_CSV_LOG}" \
        ./hayabusa dfir-timeline -d "${INPUT_DIR}" -o "${HAYABUSA_CSV}" -w -C
) || rc=$?
report_step_rc "Hayabusa CSV timeline (001)" "${rc}" "${HAYABUSA_CSV}" "${HAYABUSA_CSV_LOG}"
echo ""

### 002 — Hayabusa dfir-timeline: JSONL, super-verbose profile (Takajo input)
log_info "Step 002: Hayabusa dfir-timeline (JSONL, super-verbose profile)..."
HAYABUSA_JSONL="${RUN_DIR}/002-hayabusa-timeline.jsonl"
HAYABUSA_JSONL_LOG="${RUN_DIR}/002-hayabusa-timeline.log"
rc=0
(
    cd "${DIR_BIN_HAYABUSA}"
    run_polled "hayabusa-jsonl-timeline" "${HAYABUSA_MAX_SECS}" "${HAYABUSA_POLL_INTERVAL}" "${HAYABUSA_JSONL_LOG}" \
        ./hayabusa dfir-timeline -d "${INPUT_DIR}" -t jsonl -p super-verbose -o "${HAYABUSA_JSONL}" -w -C
) || rc=$?
report_step_rc "Hayabusa JSONL timeline (002)" "${rc}" "${HAYABUSA_JSONL}" "${HAYABUSA_JSONL_LOG}"
echo ""

### 003 — Takajo automagic
log_info "Step 003: Takajo automagic..."
TAKAJO_OUT_DIR="${RUN_DIR}/003-takajo-automagic"
TAKAJO_LOG="${RUN_DIR}/003-takajo-automagic.log"
rc=0
(
    cd "${DIR_BIN_TAKAJO}"
    export LD_LIBRARY_PATH="${DIR_BIN_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    run_polled "takajo-automagic" "${TAKAJO_MAX_SECS}" "${TAKAJO_POLL_INTERVAL}" "${TAKAJO_LOG}" \
        ./takajo automagic -t "${HAYABUSA_JSONL}" -o "${TAKAJO_OUT_DIR}" -q
) || rc=$?
report_step_rc "Takajo automagic (003)" "${rc}" "${TAKAJO_OUT_DIR}" "${TAKAJO_LOG}"
echo ""

### 004 — Chainsaw hunt with SigmaHQ rules + shipped mapping
log_info "Step 004: Chainsaw hunt (SigmaHQ Sigma rules)..."
CHAINSAW_OUT_DIR="${RUN_DIR}/004-chainsaw-hunt"
CHAINSAW_LOG="${RUN_DIR}/004-chainsaw-hunt.log"
rc=0
run_polled "chainsaw-hunt" "${CHAINSAW_MAX_SECS}" "${CHAINSAW_POLL_INTERVAL}" "${CHAINSAW_LOG}" \
    "${BIN_CHAINSAW}" hunt "${INPUT_DIR}" \
        -s "${DIR_RULES_SIGMA_WINDOWS}" \
        --mapping "${CHAINSAW_MAPPING}" \
        --skip-errors --csv --output "${CHAINSAW_OUT_DIR}" || rc=$?
report_step_rc "Chainsaw hunt (004)" "${rc}" "${CHAINSAW_OUT_DIR}" "${CHAINSAW_LOG}"
echo ""

### SUMMARY
log_info "=== Summary ==="
log_info "Run directory: ${RUN_DIR}"
log_info "Steps with issues: ${FAILURES}/4 (see logs above for detail)"

if [[ "${FAILURES}" -gt 0 ]]; then
    log_warn "One or more steps had issues — review the .log files in ${RUN_DIR} before trusting the results."
    exit 3
fi

log_info "EVTX triage complete."
exit 0
