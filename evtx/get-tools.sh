#!/usr/bin/env bash
# get-tools.sh — Download the pinned EVTX forensic toolchain (Hayabusa, Takajo,
#                Chainsaw, DuckDB runtime lib, SigmaHQ rules) into evtx/bin and
#                evtx/rules for use by evtx-triage.sh.
#
# Usage:   get-tools.sh [--check-only] [-h|--help]
#
# Tested on: REMnux (v2026.26.13, Ubuntu 24.04.3 LTS) — full download run,
#            --check-only, and idempotent re-run verified end to end
#            (2026-08-06; see CHANGELOG for acceptance details). Syntax +
#            --help/--check-only also validated in a Debian 12 dev container.
# Version:   0.1.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Date:      2026-08-06
# Platforms: Linux (bash 4+, curl, unzip, tar, git)

set -euo pipefail

### CONSTANTS
SCRIPT_NAME="get-tools.sh"
SCRIPT_VERSION="0.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

### VERSION PINS — the single place to bump
HAYABUSA_VERSION="4.0.0"     # v4 merged csv-timeline/json-timeline into dfir-timeline
TAKAJO_VERSION="2.16.1"
CHAINSAW_VERSION="2.16.3"
DUCKDB_VERSION="1.4.4"       # libduckdb.so — runtime dependency of Takajo
SIGMA_REF="r2026-07-01"      # SigmaHQ/sigma release tag consumed by chainsaw hunt

### SHARED UTILITIES
# evtx/ is a sibling of triage/, not a child — path goes up one level.
if [[ ! -f "${SCRIPT_DIR}/../triage/common/utils.sh" ]]; then
    echo "[ERROR] Required file not found: ${SCRIPT_DIR}/../triage/common/utils.sh" >&2
    exit 2
fi
# shellcheck source=../triage/common/utils.sh
source "${SCRIPT_DIR}/../triage/common/utils.sh"

### PATHS
DIR_BIN="${SCRIPT_DIR}/bin"
DIR_BIN_HAYABUSA="${DIR_BIN}/hayabusa"
DIR_BIN_TAKAJO="${DIR_BIN}/takajo"
DIR_BIN_CHAINSAW="${DIR_BIN}/chainsaw"
DIR_BIN_LIB="${DIR_BIN}/lib"
DIR_RULES="${SCRIPT_DIR}/rules"
DIR_RULES_SIGMA="${DIR_RULES}/sigma"

# Version marker files, written after a successful install. Used instead of
# parsing each tool's --version output: --version output shape was verified
# for Takajo only in Step 0 of this task (real binary run: prints bare
# "2.16.1", exit 0). Hayabusa's and Chainsaw's --version text formats were
# not run in this session, so this script does not assume/parse them —
# doing so would risk a silent false "OK" or "MISMATCH" on a format that
# was never actually observed. Markers are deterministic and avoid that.
MARKER_HAYABUSA="${DIR_BIN_HAYABUSA}/.installed_version"
MARKER_TAKAJO="${DIR_BIN_TAKAJO}/.installed_version"
MARKER_CHAINSAW="${DIR_BIN_CHAINSAW}/.installed_version"
MARKER_DUCKDB="${DIR_BIN_LIB}/.installed_version"
MARKER_SIGMA="${DIR_RULES}/.sigma_version"

### ASSET URLS / NAMES
HAYABUSA_ASSET="hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip"
HAYABUSA_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${HAYABUSA_ASSET}"
HAYABUSA_BIN_VERSIONED="hayabusa-${HAYABUSA_VERSION}-lin-x64-musl"

TAKAJO_ASSET="takajo-${TAKAJO_VERSION}-lin-x64-gnu.zip"
TAKAJO_URL="https://github.com/Yamato-Security/takajo/releases/download/v${TAKAJO_VERSION}/${TAKAJO_ASSET}"
TAKAJO_BIN_VERSIONED="takajo-${TAKAJO_VERSION}-lin-x64-gnu"

CHAINSAW_ASSET="chainsaw_x86_64-unknown-linux-gnu.tar.gz"
CHAINSAW_URL="https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/${CHAINSAW_ASSET}"

DUCKDB_ASSET="libduckdb-linux-amd64.zip"
DUCKDB_URL="https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/${DUCKDB_ASSET}"

SIGMA_REPO_URL="https://github.com/SigmaHQ/sigma"

### FUNCTIONS

script_usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [--check-only] [-h|--help]

Downloads the pinned EVTX forensic toolchain into evtx/bin/ and clones
SigmaHQ/sigma into evtx/rules/sigma/ (both gitignored). Pinned versions:

  Hayabusa: ${HAYABUSA_VERSION}   Takajo: ${TAKAJO_VERSION}   Chainsaw: ${CHAINSAW_VERSION}
  DuckDB:   ${DUCKDB_VERSION}   SigmaHQ ref: ${SIGMA_REF}

Options:
  --check-only   Report installed vs pinned versions per tool and exit
                 non-zero on any mismatch/missing tool. Performs NO
                 network calls.
  -h, --help     Show this help and exit.

Behaviour:
  Idempotent — a tool already at the pinned version is skipped, not
  re-downloaded or re-cloned. Every downloaded archive's sha256sum is
  logged. Binaries are made executable and stable symlinks (e.g.
  bin/hayabusa/hayabusa) are created so evtx-triage.sh never encodes a
  version number.

Exit codes:
  0  success (or, with --check-only, everything matches the pins)
  1  --check-only found a mismatch or missing tool
  2  script error (missing utils.sh, bad args, missing host tool)
EOF
}

# Reads a version marker file; echoes its content or "" if absent/unreadable.
read_marker() {
    local marker="$1"
    if [[ -f "${marker}" ]]; then
        cat "${marker}"
    else
        echo ""
    fi
}

require_host_tools() {
    # Only needed for the real download flow — --check-only never calls this.
    local tool missing=0
    for tool in curl unzip tar git sha256sum chmod; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            log_error "Missing required host tool: ${tool}"
            missing=$((missing + 1))
        fi
    done
    if [[ "${missing}" -gt 0 ]]; then
        log_error "Install missing host tools and retry."
        exit 2
    fi
}

log_sha256() {
    local file="$1"
    local sum
    sum="$(sha256sum "${file}" | awk '{print $1}')"
    log_info "  sha256sum: ${sum}  (${file##*/})"
}

### --check-only MODE (no network calls)
run_check_only() {
    local overall_rc=0
    local installed status

    log_info "=== ${SCRIPT_NAME} v${SCRIPT_VERSION} --check-only ==="
    echo ""
    printf "  %-10s %-12s %-12s %s\n" "TOOL" "PINNED" "INSTALLED" "STATUS"

    installed="$(read_marker "${MARKER_HAYABUSA}")"
    if [[ -z "${installed}" ]]; then
        status="MISSING"; overall_rc=1
    elif [[ "${installed}" != "${HAYABUSA_VERSION}" ]]; then
        status="MISMATCH"; overall_rc=1
    elif [[ ! -x "${DIR_BIN_HAYABUSA}/hayabusa" ]]; then
        status="BROKEN (marker OK, binary missing)"; overall_rc=1
    else
        status="OK"
    fi
    printf "  %-10s %-12s %-12s %s\n" "hayabusa" "${HAYABUSA_VERSION}" "${installed:--}" "${status}"

    installed="$(read_marker "${MARKER_TAKAJO}")"
    if [[ -z "${installed}" ]]; then
        status="MISSING"; overall_rc=1
    elif [[ "${installed}" != "${TAKAJO_VERSION}" ]]; then
        status="MISMATCH"; overall_rc=1
    elif [[ ! -x "${DIR_BIN_TAKAJO}/takajo" ]]; then
        status="BROKEN (marker OK, binary missing)"; overall_rc=1
    else
        status="OK"
    fi
    printf "  %-10s %-12s %-12s %s\n" "takajo" "${TAKAJO_VERSION}" "${installed:--}" "${status}"

    installed="$(read_marker "${MARKER_CHAINSAW}")"
    if [[ -z "${installed}" ]]; then
        status="MISSING"; overall_rc=1
    elif [[ "${installed}" != "${CHAINSAW_VERSION}" ]]; then
        status="MISMATCH"; overall_rc=1
    elif [[ ! -x "${DIR_BIN_CHAINSAW}/chainsaw" ]]; then
        status="BROKEN (marker OK, binary missing)"; overall_rc=1
    else
        status="OK"
    fi
    printf "  %-10s %-12s %-12s %s\n" "chainsaw" "${CHAINSAW_VERSION}" "${installed:--}" "${status}"

    installed="$(read_marker "${MARKER_DUCKDB}")"
    if [[ -z "${installed}" ]]; then
        status="MISSING"; overall_rc=1
    elif [[ "${installed}" != "${DUCKDB_VERSION}" ]]; then
        status="MISMATCH"; overall_rc=1
    elif [[ ! -f "${DIR_BIN_LIB}/libduckdb.so" ]]; then
        status="BROKEN (marker OK, library missing)"; overall_rc=1
    else
        status="OK"
    fi
    printf "  %-10s %-12s %-12s %s\n" "duckdb" "${DUCKDB_VERSION}" "${installed:--}" "${status}"

    installed="$(read_marker "${MARKER_SIGMA}")"
    if [[ -z "${installed}" ]]; then
        status="MISSING"; overall_rc=1
    elif [[ "${installed}" != "${SIGMA_REF}" ]]; then
        status="MISMATCH"; overall_rc=1
    elif [[ ! -d "${DIR_RULES_SIGMA}/rules" ]]; then
        status="BROKEN (marker OK, rules/ missing)"; overall_rc=1
    else
        status="OK"
    fi
    printf "  %-10s %-12s %-12s %s\n" "sigma" "${SIGMA_REF}" "${installed:--}" "${status}"

    echo ""
    if [[ "${overall_rc}" -ne 0 ]]; then
        log_warn "Missing or mismatched tools — run '${SCRIPT_NAME}' (without --check-only) to install."
    else
        log_info "All tools match pinned versions."
    fi
    return "${overall_rc}"
}

### INSTALL FUNCTIONS (each idempotent via its marker file)

install_hayabusa() {
    local installed
    installed="$(read_marker "${MARKER_HAYABUSA}")"
    if [[ "${installed}" == "${HAYABUSA_VERSION}" && -x "${DIR_BIN_HAYABUSA}/hayabusa" ]]; then
        log_info "Hayabusa ${HAYABUSA_VERSION} already installed — skipping."
        return 0
    fi

    log_info "Hayabusa: downloading ${HAYABUSA_ASSET}..."
    local tmpzip="${TMP_DIR}/${HAYABUSA_ASSET}"
    curl -fSL -o "${tmpzip}" "${HAYABUSA_URL}"
    log_sha256 "${tmpzip}"

    rm -rf "${DIR_BIN_HAYABUSA}"
    ensure_dir "${DIR_BIN_HAYABUSA}"
    # Flat zip layout: binary + rules/ + config/ land directly under -d.
    unzip -q -o "${tmpzip}" -d "${DIR_BIN_HAYABUSA}"
    chmod +x "${DIR_BIN_HAYABUSA}/${HAYABUSA_BIN_VERSIONED}"
    ( cd "${DIR_BIN_HAYABUSA}" && ln -sf "${HAYABUSA_BIN_VERSIONED}" "hayabusa" )
    echo "${HAYABUSA_VERSION}" > "${MARKER_HAYABUSA}"
    log_info "Hayabusa ${HAYABUSA_VERSION} installed: ${DIR_BIN_HAYABUSA}/hayabusa -> ${HAYABUSA_BIN_VERSIONED}"
}

install_takajo() {
    local installed
    installed="$(read_marker "${MARKER_TAKAJO}")"
    if [[ "${installed}" == "${TAKAJO_VERSION}" && -x "${DIR_BIN_TAKAJO}/takajo" ]]; then
        log_info "Takajo ${TAKAJO_VERSION} already installed — skipping."
        return 0
    fi

    log_info "Takajo: downloading ${TAKAJO_ASSET}..."
    local tmpzip="${TMP_DIR}/${TAKAJO_ASSET}"
    curl -fSL -o "${tmpzip}" "${TAKAJO_URL}"
    log_sha256 "${tmpzip}"

    rm -rf "${DIR_BIN_TAKAJO}"
    ensure_dir "${DIR_BIN_TAKAJO}"
    # Flat zip layout: binary + conf/ + templates/ + mitre-attack.json land
    # directly under -d (verified in this session's Step 0).
    unzip -q -o "${tmpzip}" -d "${DIR_BIN_TAKAJO}"
    chmod +x "${DIR_BIN_TAKAJO}/${TAKAJO_BIN_VERSIONED}"
    ( cd "${DIR_BIN_TAKAJO}" && ln -sf "${TAKAJO_BIN_VERSIONED}" "takajo" )
    echo "${TAKAJO_VERSION}" > "${MARKER_TAKAJO}"
    log_info "Takajo ${TAKAJO_VERSION} installed: ${DIR_BIN_TAKAJO}/takajo -> ${TAKAJO_BIN_VERSIONED}"
}

install_duckdb() {
    local installed
    installed="$(read_marker "${MARKER_DUCKDB}")"
    if [[ "${installed}" == "${DUCKDB_VERSION}" && -f "${DIR_BIN_LIB}/libduckdb.so" ]]; then
        log_info "DuckDB ${DUCKDB_VERSION} already installed — skipping."
        return 0
    fi

    log_info "DuckDB: downloading ${DUCKDB_ASSET}..."
    local tmpzip="${TMP_DIR}/${DUCKDB_ASSET}"
    curl -fSL -o "${tmpzip}" "${DUCKDB_URL}"
    log_sha256 "${tmpzip}"

    ensure_dir "${DIR_BIN_LIB}"
    # Flat zip: duckdb.h, duckdb.hpp, libduckdb.so, libduckdb_static.a land
    # directly under -d (verified in this session's Step 0). The soname
    # Takajo's NEEDED entry requests is exactly "libduckdb.so" (confirmed
    # via readelf -d), which matches this filename exactly — no symlink
    # needed for LD_LIBRARY_PATH to resolve it.
    unzip -q -o "${tmpzip}" -d "${DIR_BIN_LIB}"
    echo "${DUCKDB_VERSION}" > "${MARKER_DUCKDB}"
    log_info "DuckDB ${DUCKDB_VERSION} installed: ${DIR_BIN_LIB}/libduckdb.so"
}

install_chainsaw() {
    local installed
    installed="$(read_marker "${MARKER_CHAINSAW}")"
    if [[ "${installed}" == "${CHAINSAW_VERSION}" && -x "${DIR_BIN_CHAINSAW}/chainsaw" ]]; then
        log_info "Chainsaw ${CHAINSAW_VERSION} already installed — skipping."
        return 0
    fi

    log_info "Chainsaw: downloading ${CHAINSAW_ASSET}..."
    local tmptar="${TMP_DIR}/${CHAINSAW_ASSET}"
    curl -fSL -o "${tmptar}" "${CHAINSAW_URL}"
    log_sha256 "${tmptar}"

    rm -rf "${DIR_BIN_CHAINSAW}"
    ensure_dir "${DIR_BIN_CHAINSAW}"
    # Tarball has a wrapping chainsaw/ top directory — strip it.
    tar -xzf "${tmptar}" --strip-components=1 -C "${DIR_BIN_CHAINSAW}"
    chmod +x "${DIR_BIN_CHAINSAW}/chainsaw"
    echo "${CHAINSAW_VERSION}" > "${MARKER_CHAINSAW}"
    log_info "Chainsaw ${CHAINSAW_VERSION} installed: ${DIR_BIN_CHAINSAW}/chainsaw"
}

clone_sigma() {
    local installed
    installed="$(read_marker "${MARKER_SIGMA}")"
    if [[ "${installed}" == "${SIGMA_REF}" && -d "${DIR_RULES_SIGMA}/.git" ]]; then
        log_info "SigmaHQ/sigma ${SIGMA_REF} already cloned — skipping."
        return 0
    fi

    log_info "SigmaHQ/sigma: cloning ${SIGMA_REF} (depth 1)..."
    rm -rf "${DIR_RULES_SIGMA}"
    ensure_dir "${DIR_RULES}"
    git clone --depth 1 --branch "${SIGMA_REF}" "${SIGMA_REPO_URL}" "${DIR_RULES_SIGMA}"
    echo "${SIGMA_REF}" > "${MARKER_SIGMA}"
    log_info "SigmaHQ/sigma ${SIGMA_REF} cloned: ${DIR_RULES_SIGMA}"
}

### ARGUMENT PARSER
CHECK_ONLY=0

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --check-only)
            CHECK_ONLY=1
            shift
            ;;
        -h|--help)
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
if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    run_check_only
    exit $?
fi

require_host_tools

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} — installing pinned EVTX toolchain"
echo ""

install_hayabusa
echo ""
install_takajo
echo ""
install_duckdb
echo ""
install_chainsaw
echo ""
clone_sigma
echo ""

log_info "=== Summary ==="
log_info "  Hayabusa: ${HAYABUSA_VERSION}  -> ${DIR_BIN_HAYABUSA}/hayabusa"
log_info "  Takajo:   ${TAKAJO_VERSION}  -> ${DIR_BIN_TAKAJO}/takajo"
log_info "  Chainsaw: ${CHAINSAW_VERSION}  -> ${DIR_BIN_CHAINSAW}/chainsaw"
log_info "  DuckDB:   ${DUCKDB_VERSION}  -> ${DIR_BIN_LIB}/libduckdb.so"
log_info "  SigmaHQ:  ${SIGMA_REF}  -> ${DIR_RULES_SIGMA}"
log_info "Run 'evtx-triage.sh -i <evtx_dir>' to triage a directory of EVTX files."

exit 0
