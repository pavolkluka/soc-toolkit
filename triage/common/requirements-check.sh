#!/usr/bin/env bash
# requirements-check.sh — Dependency checker for soc-toolkit triage scripts.
#
# Usage:   requirements-check.sh [--install-deps] [--check-only] [-h|--help]
#
# Tested on: REMnux (Ubuntu 24.04.3 LTS, primary), Ubuntu 22.04 LTS
# Version:   0.1.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Date:      2026-04-17
# Platforms: Linux (bash 4+, apt-based distros)

set -euo pipefail

### CONSTANTS
SCRIPT_NAME="requirements-check.sh"
SCRIPT_VERSION="0.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure pipx default bin dir is on PATH so command -v probes work in
# non-interactive shells (e.g. SSH exec) where ~/.local/bin is often missing.
if [[ ":${PATH}:" != *":${HOME}/.local/bin:"* ]]; then
    export PATH="${HOME}/.local/bin:${PATH}"
fi

### SHARED UTILITIES
if [[ ! -f "${SCRIPT_DIR}/utils.sh" ]]; then
    echo "[ERROR] Required file not found: ${SCRIPT_DIR}/utils.sh" >&2
    exit 2
fi
# shellcheck source=utils.sh
source "${SCRIPT_DIR}/utils.sh"

### TOOL METADATA
# Tier 1: apt-installable system tools ("<cmd>|<apt_pkg>")
TIER1_APT=(
    "file|file"
    "exiftool|libimage-exiftool-perl"
    "strings|binutils"
    "readelf|binutils"
    "nm|binutils"
    "md5sum|coreutils"
    "sha1sum|coreutils"
    "sha256sum|coreutils"
    "unzip|unzip"
    "7z|p7zip-full"
    "unrar|unrar"
)

# Tier 2: pipx-installable Python CLI tools ("<cmd>|<pipx_pkg>")
# Note: oletools provides both rtfobj and oleobj — package installed once, shims both.
TIER2_PIPX=(
    "malwoverview|malwoverview"
    "rtfobj|oletools"
    "oleobj|oletools"
    "lnkparse|LnkParse3"
    "peepdf|peepdf3"
    "floss|flare-floss"
    "capa|flare-capa"
)

# Tier 3: external downloads (no auto-install) — "<cmd>|<URL>|<hint>"
TIER3_EXTERNAL=(
    "diec|https://github.com/horsicq/Detect-It-Easy|Download from releases or build from source (requires Qt)."
    "trid|https://mark0.net/soft-trid-e.html|Download TrID binary (Linux x86-64 ZIP) + TrIDDefs.TRD definitions."
    "portex|https://github.com/struppigel/PortEx|Download PortexAnalyzer.jar (requires java runtime)."
    "oledump.py|https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py|wget URL -O /usr/local/bin/oledump.py && chmod +x /usr/local/bin/oledump.py"
    "pdfid.py|https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py|wget URL -O /usr/local/bin/pdfid.py && chmod +x /usr/local/bin/pdfid.py"
)

# malwoverview API keys used by file-triage.sh
MALWAPI_KEYS=(VTAPI TRIAGEAPI ALIENAPI BAZAARAPI)
MALWAPI_CONF="${HOME}/.malwapi.conf"
MALWAPI_DOCS_URL="https://github.com/alexandreborges/malwoverview?tab=readme-ov-file#required-apis"

### FUNCTIONS

script_usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [--install-deps | --check-only] [-h|--help]

Checks soc-toolkit triage dependencies across three tiers:
  Tier 1: apt-installable (file, exiftool, binutils, unzip, p7zip, unrar, coreutils)
  Tier 2: pipx-installable (malwoverview, oletools, LnkParse3, peepdf3, flare-floss, flare-capa)
  Tier 3: manual downloads (diec, trid, portex, oledump.py, pdfid.py)

Also validates ~/.malwapi.conf and counts configured API keys
(VTAPI, TRIAGEAPI, ALIENAPI, BAZAARAPI).

Options:
  --install-deps   Auto-install missing Tier 1 + Tier 2 tools without prompts.
                   Tier 3 tools are never auto-installed; URL + hint is printed.
                   Requires sudo for apt; pipx uses user scope (no sudo).
  --check-only     Detection only; exit 1 if anything is missing or any API
                   key is unconfigured. Suitable for CI.
  -h, --help       Show this help and exit.

Behaviour without flags:
  Detect everything, then interactively prompt [y/N] to install missing
  Tier 1 + Tier 2 tools. Tier 3 is always hint-only.

Exit codes:
  0  all dependencies present and API keys configured
  1  something missing (tool or API key)
  2  script error (missing utils.sh, bad args)
EOF
}

parse_entry() {
    # Split "field1|field2|..." into a global array ENTRY_FIELDS
    local IFS='|'
    read -ra ENTRY_FIELDS <<< "$1"
}

check_cmd() {
    # Usage: check_cmd <command_name>
    # Returns 0 if in PATH, 1 otherwise.
    command -v "$1" > /dev/null 2>&1
}

### TIER 1 — APT
check_tier1() {
    TIER1_MISSING=()
    TIER1_PKGS_TO_INSTALL=()
    local entry cmd pkg
    log_info "=== Tier 1: apt-installable system tools ==="
    for entry in "${TIER1_APT[@]}"; do
        parse_entry "${entry}"
        cmd="${ENTRY_FIELDS[0]}"
        pkg="${ENTRY_FIELDS[1]}"
        if check_cmd "${cmd}"; then
            printf "  [OK]      %-12s (apt: %s)\n" "${cmd}" "${pkg}"
        else
            printf "  [MISSING] %-12s (apt: %s)\n" "${cmd}" "${pkg}"
            TIER1_MISSING+=("${cmd}")
            # Deduplicate package list (binutils + coreutils repeat)
            if [[ ! " ${TIER1_PKGS_TO_INSTALL[*]:-} " == *" ${pkg} "* ]]; then
                TIER1_PKGS_TO_INSTALL+=("${pkg}")
            fi
        fi
    done
}

### TIER 2 — PIPX
check_tier2() {
    TIER2_MISSING=()
    TIER2_PKGS_TO_INSTALL=()
    local entry cmd pkg
    log_info "=== Tier 2: pipx-installable Python CLI tools ==="
    for entry in "${TIER2_PIPX[@]}"; do
        parse_entry "${entry}"
        cmd="${ENTRY_FIELDS[0]}"
        pkg="${ENTRY_FIELDS[1]}"
        if check_cmd "${cmd}"; then
            printf "  [OK]      %-12s (pipx: %s)\n" "${cmd}" "${pkg}"
        else
            printf "  [MISSING] %-12s (pipx: %s)\n" "${cmd}" "${pkg}"
            TIER2_MISSING+=("${cmd}")
            if [[ ! " ${TIER2_PKGS_TO_INSTALL[*]:-} " == *" ${pkg} "* ]]; then
                TIER2_PKGS_TO_INSTALL+=("${pkg}")
            fi
        fi
    done
}

### TIER 3 — external downloads
check_tier3() {
    TIER3_MISSING=()
    local entry cmd url hint
    log_info "=== Tier 3: external tools (manual download) ==="
    for entry in "${TIER3_EXTERNAL[@]}"; do
        parse_entry "${entry}"
        cmd="${ENTRY_FIELDS[0]}"
        url="${ENTRY_FIELDS[1]}"
        hint="${ENTRY_FIELDS[2]:-}"
        if check_cmd "${cmd}"; then
            printf "  [OK]      %-12s\n" "${cmd}"
        else
            printf "  [MISSING] %-12s\n" "${cmd}"
            printf "            URL:  %s\n" "${url}"
            printf "            Hint: %s\n" "${hint}"
            TIER3_MISSING+=("${cmd}")
        fi
    done
}

### .malwapi.conf
check_malwapi_conf() {
    MALWAPI_MISSING_FILE=0
    MALWAPI_CONFIGURED_COUNT=0
    log_info "=== malwoverview API configuration ==="
    if [[ ! -f "${MALWAPI_CONF}" ]]; then
        log_warn ".malwapi.conf NOT FOUND at: ${MALWAPI_CONF}"
        MALWAPI_MISSING_FILE=1
        cat <<EOF

  To configure, create ${MALWAPI_CONF} with (fill in keys you have):

    [VIRUSTOTAL]
    VTAPI =

    [TRIAGE]
    TRIAGEAPI =

    [ALIENVAULT]
    ALIENAPI =

    [MALWAREBAZAAR]
    BAZAARAPI =

  Full documentation:
    ${MALWAPI_DOCS_URL}

EOF
        return
    fi

    printf "  [OK] File present: %s\n" "${MALWAPI_CONF}"
    local key configured=0
    for key in "${MALWAPI_KEYS[@]}"; do
        # Match "<KEY> = <value>" where value is non-empty (at least one non-whitespace char)
        if grep -qE "^${key}[[:space:]]*=[[:space:]]*[^[:space:]].*$" "${MALWAPI_CONF}"; then
            printf "  [OK]      %-12s configured\n" "${key}"
            configured=$((configured + 1))
        else
            printf "  [MISSING] %-12s empty or not set\n" "${key}"
        fi
    done
    MALWAPI_CONFIGURED_COUNT="${configured}"
    log_info "API keys configured: ${configured}/${#MALWAPI_KEYS[@]}"
    if [[ "${configured}" -lt "${#MALWAPI_KEYS[@]}" ]]; then
        printf "  See: %s\n" "${MALWAPI_DOCS_URL}"
    fi
}

### INSTALLATION
bootstrap_pipx() {
    # Ensure pipx is available; on apt systems prefer apt pkg, else fallback to pip --user.
    if check_cmd pipx; then
        return 0
    fi
    log_info "pipx not found — bootstrapping..."
    if check_cmd apt; then
        sudo apt update
        sudo apt install -y pipx
    fi
    if ! check_cmd pipx; then
        # Fallback: pip --user (PEP 668 may require --break-system-packages on modern Ubuntu)
        if check_cmd pip3; then
            pip3 install --user pipx || pip3 install --user --break-system-packages pipx
        else
            log_error "pip3 not available — cannot bootstrap pipx."
            return 1
        fi
    fi
    # Ensure ~/.local/bin is on PATH for current shell
    export PATH="${HOME}/.local/bin:${PATH}"
    if ! check_cmd pipx; then
        log_error "pipx bootstrap failed."
        return 1
    fi
    pipx ensurepath > /dev/null 2>&1 || true
    log_info "pipx bootstrapped."
}

install_tier1() {
    if [[ "${#TIER1_PKGS_TO_INSTALL[@]}" -eq 0 ]]; then
        log_info "Tier 1: nothing to install."
        return 0
    fi
    log_info "Tier 1: installing via apt: ${TIER1_PKGS_TO_INSTALL[*]}"
    sudo apt update
    sudo apt install -y "${TIER1_PKGS_TO_INSTALL[@]}"
}

install_tier2() {
    if [[ "${#TIER2_PKGS_TO_INSTALL[@]}" -eq 0 ]]; then
        log_info "Tier 2: nothing to install."
        return 0
    fi
    bootstrap_pipx
    local pkg
    for pkg in "${TIER2_PKGS_TO_INSTALL[@]}"; do
        log_info "Tier 2: pipx install ${pkg}"
        pipx install "${pkg}" || log_warn "pipx install ${pkg} failed — continuing."
    done
    # Reminder: extend PATH
    if [[ ":${PATH}:" != *":${HOME}/.local/bin:"* ]]; then
        log_warn "~/.local/bin is NOT on your PATH. Add:"
        log_warn "    export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    fi
}

### INTERACTIVE PROMPT
prompt_install() {
    local have_apt="${#TIER1_PKGS_TO_INSTALL[@]}"
    local have_pip="${#TIER2_PKGS_TO_INSTALL[@]}"
    if [[ "${have_apt}" -eq 0 && "${have_pip}" -eq 0 ]]; then
        return 1  # nothing to install
    fi
    echo ""
    log_info "Missing tools can be auto-installed:"
    if [[ "${have_apt}" -gt 0 ]]; then
        echo "  apt: ${TIER1_PKGS_TO_INSTALL[*]}"
    fi
    if [[ "${have_pip}" -gt 0 ]]; then
        echo "  pipx: ${TIER2_PKGS_TO_INSTALL[*]}"
    fi
    local reply
    read -r -p "Install now? [y/N] " reply
    case "${reply}" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

### ARGUMENT PARSER
INSTALL_DEPS=0
CHECK_ONLY=0

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --install-deps)
            INSTALL_DEPS=1
            shift
            ;;
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
            exit 1
            ;;
    esac
done

if [[ "${INSTALL_DEPS}" -eq 1 && "${CHECK_ONLY}" -eq 1 ]]; then
    log_error "--install-deps and --check-only are mutually exclusive."
    exit 1
fi

### MAIN
log_info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
echo ""

check_tier1
echo ""
check_tier2
echo ""
check_tier3
echo ""
check_malwapi_conf
echo ""

# Totals
TOTAL_MISSING=$(( ${#TIER1_MISSING[@]} + ${#TIER2_MISSING[@]} + ${#TIER3_MISSING[@]} ))
API_MISSING=$(( ${#MALWAPI_KEYS[@]} - MALWAPI_CONFIGURED_COUNT ))
if [[ "${MALWAPI_MISSING_FILE}" -eq 1 ]]; then
    API_MISSING="${#MALWAPI_KEYS[@]}"
fi

log_info "=== Summary ==="
log_info "  Tier 1 missing:   ${#TIER1_MISSING[@]}"
log_info "  Tier 2 missing:   ${#TIER2_MISSING[@]}"
log_info "  Tier 3 missing:   ${#TIER3_MISSING[@]}"
log_info "  API keys set:     ${MALWAPI_CONFIGURED_COUNT}/${#MALWAPI_KEYS[@]}"
echo ""

# --check-only: no install, exit 1 if anything missing
if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    if [[ "${TOTAL_MISSING}" -gt 0 || "${API_MISSING}" -gt 0 ]]; then
        log_warn "Missing dependencies or API keys — exit 1 (check-only mode)."
        exit 1
    fi
    log_info "All dependencies and API keys present."
    exit 0
fi

# Install flow (auto or interactive)
SHOULD_INSTALL=0
if [[ "${INSTALL_DEPS}" -eq 1 ]]; then
    SHOULD_INSTALL=1
    log_info "--install-deps: installing Tier 1 + Tier 2 automatically."
elif [[ "${#TIER1_PKGS_TO_INSTALL[@]}" -gt 0 || "${#TIER2_PKGS_TO_INSTALL[@]}" -gt 0 ]]; then
    if prompt_install; then
        SHOULD_INSTALL=1
    fi
fi

if [[ "${SHOULD_INSTALL}" -eq 1 ]]; then
    echo ""
    install_tier1
    echo ""
    install_tier2
    echo ""
    log_info "Installation attempted. Re-run to verify."
fi

# Tier 3 hints always when missing (never auto-install)
if [[ "${#TIER3_MISSING[@]}" -gt 0 ]]; then
    log_warn "Tier 3 tools still missing (manual download required — see URLs above):"
    log_warn "  ${TIER3_MISSING[*]}"
fi

# Final exit code
if [[ "${TOTAL_MISSING}" -gt 0 || "${API_MISSING}" -gt 0 ]]; then
    exit 1
fi
exit 0
