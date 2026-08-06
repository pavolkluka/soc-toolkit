#!/usr/bin/env bash
# setup.sh — Create/update Python venv and install dependencies for
#             soc-toolkit (F6 toolkit layer).
#
# Usage:   setup.sh [--check-only] [-h|--help]
#
# Tested on: Debian 12 (Python 3.11.2)
# Note:      REMnux 7 (Ubuntu 20.04.6, Python 3.8.10) is NOT supported —
#            requirements.txt needs Python >= 3.10. See docs/remnux-notes.md.
# Version:   0.1.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Date:      2026-08-06
# Platforms: Linux (bash 4+)
#
# Standalone script: does NOT source triage/common/utils.sh and has no
# dependency on the triage/ tree. venv-setup/ must work on its own.
set -euo pipefail

### CONSTANTS
SCRIPT_NAME="setup.sh"
SCRIPT_VERSION="0.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
REQUIREMENTS="${SCRIPT_DIR}/requirements.txt"

# Packages whose versions --check-only reports (pinned in requirements.txt,
# plus pysigma which is a transitive dependency resolved by pip from the
# sigma-cli / pysigma-backend-qradar-aql pins — not listed explicitly).
CHECK_PACKAGES=(msticpy jupyterlab sigma-cli pysigma-backend-qradar-aql pysigma)

### SELF-CONTAINED LOGGING HELPERS
# (No sourcing of triage/common/utils.sh — venv-setup is standalone.)

log_info() {
    echo "[INFO] $*"
}

log_warn() {
    echo "[WARN] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

### USAGE

script_usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [--check-only] [-h|--help]

Creates (or updates in place) a Python virtual environment at
${VENV_DIR} and installs soc-toolkit's Python dependencies from
${REQUIREMENTS}.

Standalone script — does not depend on triage/common/utils.sh.

Options:
  --check-only   Report venv status only. Does NOT create, modify or
                 install anything. Prints the venv path, the Python
                 version inside the venv, and the installed versions of:
                 ${CHECK_PACKAGES[*]}.
                 Exits non-zero if no venv exists yet.
  -h, --help     Show this help and exit.

Exit codes:
  0  setup completed successfully / --check-only found a valid venv
  1  Python version guard failed, or --check-only found no venv
  2  script error (unknown argument)
EOF
}

### PYTHON VERSION GUARD (must run before any venv action)

check_python_version() {
    if ! command -v python3 > /dev/null 2>&1; then
        log_error "python3 not found in PATH."
        log_error "soc-toolkit requires Python 3.10+. See docs/remnux-notes.md."
        exit 1
    fi

    local py_version py_ok
    py_version="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
    py_ok="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)')"

    if [[ "${py_ok}" != "1" ]]; then
        log_error "Detected python3 ${py_version} — soc-toolkit requires Python 3.10+."
        log_error "REMnux 7 ships only Python 3.8.10, and no python3.10 package is"
        log_error "available for its Ubuntu 20.04 base (verified 2026-08-06, host"
        log_error "03-remnux-7-202510, Python 3.8.10)."
        log_error "See docs/remnux-notes.md for workaround options."
        exit 1
    fi

    log_info "python3 ${py_version} detected (>= 3.10 required) — OK."
}

### VENV CREATION (idempotent — never deletes an existing venv)

create_or_update_venv() {
    if [[ -d "${VENV_DIR}" && -f "${VENV_DIR}/pyvenv.cfg" ]]; then
        log_info "Existing virtual environment found at ${VENV_DIR} — updating in place."
    else
        log_info "Creating Python virtual environment at ${VENV_DIR}"
        python3 -m venv "${VENV_DIR}"
    fi
}

### DEPENDENCY INSTALLATION

install_dependencies() {
    log_info "Upgrading pip in ${VENV_DIR}"
    "${VENV_DIR}/bin/pip" install --upgrade pip

    log_info "Installing dependencies from ${REQUIREMENTS}"
    "${VENV_DIR}/bin/pip" install -r "${REQUIREMENTS}"
}

### CHECK-ONLY REPORT (read-only — no creation, modification or install)

check_only_report() {
    if [[ ! -d "${VENV_DIR}" || ! -f "${VENV_DIR}/pyvenv.cfg" ]]; then
        log_error "No virtual environment found at ${VENV_DIR}."
        log_error "Run '${SCRIPT_NAME}' (without --check-only) to create it."
        exit 1
    fi

    log_info "Virtual environment: ${VENV_DIR}"

    if [[ -x "${VENV_DIR}/bin/python3" ]]; then
        local venv_py_version
        venv_py_version="$("${VENV_DIR}/bin/python3" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2> /dev/null || echo "unknown")"
        log_info "Python version (venv): ${venv_py_version}"
    else
        log_warn "Python version (venv): interpreter not found at ${VENV_DIR}/bin/python3"
    fi

    if [[ ! -x "${VENV_DIR}/bin/pip" ]]; then
        log_warn "pip not found at ${VENV_DIR}/bin/pip — cannot report package versions."
        return
    fi

    local pkg ver
    for pkg in "${CHECK_PACKAGES[@]}"; do
        ver="$("${VENV_DIR}/bin/pip" show "${pkg}" 2> /dev/null | awk -F': ' '/^Version:/ {print $2}')" || true
        if [[ -z "${ver}" ]]; then
            log_warn "  ${pkg}: not installed"
        else
            log_info "  ${pkg}: ${ver}"
        fi
    done
}

### ARGUMENT PARSER

CHECK_ONLY=0

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --check-only)
            CHECK_ONLY=1
            shift
            ;;
        -h | --help)
            script_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            script_usage
            exit 2
            ;;
    esac
done

### MAIN

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
echo ""

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    check_only_report
    exit 0
fi

check_python_version
echo ""

create_or_update_venv
echo ""

install_dependencies
echo ""

log_info "Setup complete."
log_info "To activate: source ${VENV_DIR}/bin/activate"
