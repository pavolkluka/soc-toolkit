#!/usr/bin/env bash
# sigma-to-aql.sh — Convert Sigma detection rule(s) to IBM QRadar AQL using
#                    sigma-cli + pysigma-backend-qradar-aql.
#
# Usage:   sigma-to-aql.sh <rule-file-or-dir> [--fields] [-o|--output-dir DIR]
#          sigma-to-aql.sh [-h|--help]
#
# Tested on: REMnux (Ubuntu 24.04.3 LTS, Python 3.12.3) and Debian 12
#            (Python 3.11.2) — generated AQL verified byte-identical on both.
# Version:   0.1.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Date:      2026-08-06
# Platforms: Linux (bash 4+)

set -euo pipefail

### CONSTANTS
SCRIPT_NAME="sigma-to-aql.sh"
SCRIPT_VERSION="0.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

### SHARED UTILITIES
# detection/ is a sibling of triage/, not a child — path goes up one level.
if [[ ! -f "${SCRIPT_DIR}/../triage/common/utils.sh" ]]; then
    echo "[ERROR] Required file not found: ${SCRIPT_DIR}/../triage/common/utils.sh" >&2
    exit 2
fi
# shellcheck source=../triage/common/utils.sh
source "${SCRIPT_DIR}/../triage/common/utils.sh"

### LOGGING — redirect to stderr (local to this script only)
# utils.sh's log_info/log_warn/log_error write to stdout, which is correct
# for triage/file-triage.sh and evtx/evtx-triage.sh (already committed,
# depended upon — utils.sh itself is NOT changed here). But this script's
# stdout is a machine-consumable artifact (the generated AQL, meant for
# copy-paste into the QRadar console, same principle as lookup/soc-lookup.py
# sending rich tables to stderr so `| jq` gets clean JSON on stdout). Thin
# local wrappers below rename the originals and re-point their output to
# stderr, without touching utils.sh or its behaviour for other scripts.
eval "$(declare -f log_info | sed '1s/^log_info/_base_log_info/')"
eval "$(declare -f log_warn | sed '1s/^log_warn/_base_log_warn/')"
eval "$(declare -f log_error | sed '1s/^log_error/_base_log_error/')"
log_info() { _base_log_info "$@" >&2; }
log_warn() { _base_log_warn "$@" >&2; }
log_error() { _base_log_error "$@" >&2; }

### PYTHON VENV (sigma-cli + pysigma-backend-qradar-aql)
VENV_DIR="${SCRIPT_DIR}/../venv-setup/venv"

### SIGMA CONVERSION SETTINGS
SIGMA_TARGET="q_radar_aql"
PIPELINE_DEFAULT="qradar-aql-payload"
PIPELINE_FIELDS="qradar-aql-fields"

### DEFAULTS
OUTPUT_DIR_DEFAULT="${SCRIPT_DIR}/output"

### FUNCTIONS

script_usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <rule-file-or-dir> [--fields] [-o|--output-dir DIR]
       ${SCRIPT_NAME} [-h|--help]

Converts one Sigma rule file, or every *.yml/*.yaml rule in a directory
(non-recursive), to IBM QRadar AQL using sigma-cli's q_radar_aql target.

Arguments:
  <rule-file-or-dir>       Sigma rule file, or directory of rule files
                            (required)

Options:
  --fields                  Use the qradar-aql-fields pipeline instead of
                             the default qradar-aql-payload pipeline
  -o, --output-dir DIR      Directory to write .aql output files into
                             (default: ${OUTPUT_DIR_DEFAULT})
  -h, --help                 Show this help and exit

Requires venv-setup/setup.sh to have been run first (installs sigma-cli
and pysigma-backend-qradar-aql into venv-setup/venv).

Single-file mode writes <output-dir>/<rule-basename>.aql and also echoes
the generated AQL to stdout for copy-paste into the QRadar console.

Directory mode converts every rule file found, writes one .aql file per
rule, echoes each successfully converted rule's AQL to stdout (so stdout
carries the concatenated AQL of the batch), does not abort on individual
failures, and prints a summary line (to stderr, alongside all other log
output — stdout is reserved for AQL only in both modes).

Each echoed block is introduced by a "-- rule: <name>" line naming the rule
it came from, so a multi-rule batch stays attributable. That prefix is an
AQL comment, so the whole stdout stream remains valid for copy-paste.

Exit codes:
  0  success (all conversions succeeded)
  1  one or more conversions failed (batch mode), or bad arguments
  2  missing venv / missing tool / input path not found / rule directory
     contains no *.yml or *.yaml files
EOF
} >&2

# Derives the output basename for a rule file by stripping a trailing
# .yml or .yaml extension (order-independent: only one of the two can
# ever match a given filename).
rule_basename() {
    local base
    base="$(basename "$1")"
    base="${base%.yaml}"
    base="${base%.yml}"
    printf '%s' "${base}"
}

# Converts a single Sigma rule file to AQL, writing the result under
# OUTPUT_DIR. Never aborts the caller on failure — returns 1 instead, so
# batch (directory) mode can keep going after one bad rule.
#
# Usage:   convert_one <rule-file> <echo-to-stdout: true|false>
convert_one() {
    local rule_file="$1"
    local echo_stdout="$2"
    local base outfile aql stderr_file rc

    base="$(rule_basename "${rule_file}")"
    outfile="${OUTPUT_DIR}/${base}.aql"

    # sigma-cli writes its "Parsing Sigma rules" progress banner to stderr
    # and the actual AQL to stdout — keep them separate so the .aql file
    # (and the copy-paste-to-QRadar stdout echo) only ever contains AQL.
    stderr_file="$(mktemp)"
    rc=0
    aql="$(sigma convert -t "${SIGMA_TARGET}" -p "${PIPELINE}" "${rule_file}" 2>"${stderr_file}")" || rc=$?

    if [[ "${rc}" -eq 0 ]]; then
        printf '%s\n' "${aql}" > "${outfile}"
        log_info "Converted: ${rule_file} -> ${outfile} (pipeline: ${PIPELINE})"
        if [[ "${echo_stdout}" == "true" ]]; then
            printf -- '-- rule: %s\n' "${base}"
            printf '%s\n' "${aql}"
            printf '\n'
        fi
        rm -f "${stderr_file}"
        return 0
    fi

    log_warn "Conversion failed for ${rule_file}: $(cat "${stderr_file}")"
    rm -f "${stderr_file}"
    return 1
}

### ARGUMENT PARSER
INPUT_ARG=""
PIPELINE="${PIPELINE_DEFAULT}"
OUTPUT_DIR="${OUTPUT_DIR_DEFAULT}"

if [[ "$#" -eq 0 ]]; then
    script_usage
    exit 1
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --fields)
            PIPELINE="${PIPELINE_FIELDS}"
            shift
            ;;
        -o|--output-dir)
            if [[ -z "${2:-}" ]]; then
                log_error "Option $1 requires an argument."
                script_usage
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            script_usage
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            script_usage
            exit 1
            ;;
        *)
            if [[ -n "${INPUT_ARG}" ]]; then
                log_error "Unexpected extra argument: $1"
                script_usage
                exit 1
            fi
            INPUT_ARG="$1"
            shift
            ;;
    esac
done

if [[ -z "${INPUT_ARG}" ]]; then
    log_error "Missing required argument: <rule-file-or-dir>"
    script_usage
    exit 1
fi

### INPUT VALIDATION
if [[ -f "${INPUT_ARG}" ]]; then
    INPUT_MODE="file"
elif [[ -d "${INPUT_ARG}" ]]; then
    INPUT_MODE="dir"
else
    log_error "Input not found (not a file or directory): ${INPUT_ARG}"
    script_usage
    exit 2
fi

### VENV ACTIVATION
if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
    log_error "Python venv not found at ${VENV_DIR} (missing bin/activate)."
    log_error "Run venv-setup/setup.sh first."
    exit 2
fi
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

if ! command -v sigma &>/dev/null; then
    log_error "'sigma' command not found on PATH after venv activation."
    log_error "Run venv-setup/setup.sh first."
    exit 2
fi

### OUTPUT DIRECTORY SETUP
ensure_dir "${OUTPUT_DIR}"

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
log_info "Target:   ${SIGMA_TARGET}"
log_info "Pipeline: ${PIPELINE}"
log_info "Output:   ${OUTPUT_DIR}"
echo "" >&2

### CONVERSION
if [[ "${INPUT_MODE}" == "file" ]]; then
    if convert_one "${INPUT_ARG}" true; then
        exit 0
    else
        exit 1
    fi
fi

# Directory mode: convert every *.yml/*.yaml in INPUT_ARG (non-recursive).
# A failing rule does not abort the batch.
shopt -s nullglob
RULE_FILES=("${INPUT_ARG}"/*.yml "${INPUT_ARG}"/*.yaml)
shopt -u nullglob

if [[ "${#RULE_FILES[@]}" -eq 0 ]]; then
    log_error "No *.yml/*.yaml rule files found in: ${INPUT_ARG}"
    exit 2
fi

TOTAL=0
FAILURES=0
for rule in "${RULE_FILES[@]}"; do
    TOTAL=$((TOTAL + 1))
    if ! convert_one "${rule}" true; then
        FAILURES=$((FAILURES + 1))
    fi
done

echo "" >&2
log_info "=== Summary ==="
log_info "Converted: $((TOTAL - FAILURES))/${TOTAL} succeeded, ${FAILURES} failed."

if [[ "${FAILURES}" -gt 0 ]]; then
    exit 1
fi

exit 0
