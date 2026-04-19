#!/usr/bin/env bash
# utils.sh — shared utility functions for soc-toolkit triage scripts.
#
# This file is intended to be sourced, not executed:
#     source "${SCRIPT_DIR}/common/utils.sh"
#
# Version:   0.2.0
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

### Polled process runner
# Runs a long-running command in the background, polls its PID with a
# progress log every <interval> seconds, and terminates it if runtime
# exceeds <max_secs>. Stdout+stderr are merged into <outfile>.
#
# Usage:   run_polled <label> <max_secs> <interval> <outfile> <cmd> [args...]
# Returns: 0 success (rc=0 and outfile non-empty)
#          1 process exited with non-zero rc
#          2 process terminated due to timeout cap
#          3 outfile empty after successful exit

run_polled() {
    local label="$1"; shift
    local max_secs="$1"; shift
    local interval="$1"; shift
    local outfile="$1"; shift

    "$@" > "${outfile}" 2>&1 &
    local pid=$!
    local elapsed=0
    while kill -0 "${pid}" 2>/dev/null; do
        sleep "${interval}"
        elapsed=$((elapsed + interval))
        log_info "  ${label} still running (${elapsed}s elapsed, PID ${pid})..."
        if (( elapsed >= max_secs )); then
            log_warn "  ${label} exceeded ${max_secs}s cap — terminating PID ${pid}"
            kill -TERM "${pid}" 2>/dev/null || true
            sleep 5
            kill -KILL "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
            return 2
        fi
    done
    local rc=0
    wait "${pid}" || rc=$?
    if (( rc != 0 )); then
        return 1
    fi
    if [[ ! -s "${outfile}" ]]; then
        return 3
    fi
    return 0
}
