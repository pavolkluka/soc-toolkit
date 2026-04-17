#!/usr/bin/env bash
# utils.sh — shared utility functions for soc-toolkit triage scripts.
#
# This file is intended to be sourced, not executed:
#     source "${SCRIPT_DIR}/common/utils.sh"
#
# Version:   0.1.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Platforms: Linux (bash 4+)

# Guard against double-sourcing
if [[ -n "${__SOC_TOOLKIT_UTILS_SH_LOADED:-}" ]]; then
    return 0
fi
__SOC_TOOLKIT_UTILS_SH_LOADED=1

### Logging primitives
# All log_* helpers write to stdout with a fixed prefix for easy grep/pipeline use.

log_info() {
    echo "[INFO] $*"
}

log_warn() {
    echo "[WARN] $*"
}

log_error() {
    echo "[ERROR] $*"
}

### Counter formatting
# Zero-pads an integer to 3 digits (e.g. 7 -> "007").

format_counter() {
    printf '%03d' "$1"
}

### ANSI escape stripping
# Reads from stdin, writes to stdout with ANSI escape sequences removed.
# Used to clean tool output that emits colours regardless of TTY.

strip_ansi() {
    sed -e 's/\x1B\[[0-9;]*[JKmsu]//g'
}

### Directory creation
# Idempotent: logs whether the directory was created or already existed.

ensure_dir() {
    local path="$1"
    if [[ -d "$path" ]]; then
        log_info "Directory exists: ${path}"
    else
        mkdir -p "$path"
        log_info "Directory created: ${path}"
    fi
}
