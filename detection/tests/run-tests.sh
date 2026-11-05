#!/usr/bin/env bash
# run-tests.sh — Golden-output tests for detection/sigma-to-aql.sh.
#
# Usage:   detection/tests/run-tests.sh [--update]
#
# Converts each fixture in tests/fixtures/ with the options listed in CASES
# and compares the generated AQL with tests/expected/<name>.aql byte for
# byte. --update rewrites the expected files from the current output (use
# only after reviewing the diff). Two negative cases assert that the stock
# backend behaviour still fails where documented.
#
# Version:   0.1.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Date:      2026-11-05
# Platforms: Linux (bash 4+)
#
# Exit codes: 0 all cases pass, 1 at least one case failed, 2 setup problem.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTION_DIR="$(cd "${TESTS_DIR}/.." && pwd)"
SCRIPT="${DETECTION_DIR}/sigma-to-aql.sh"
MAPPING="${DETECTION_DIR}/pipelines/qradar-lab.yml"
FIXTURES="${TESTS_DIR}/fixtures"
EXPECTED="${TESTS_DIR}/expected"
UPDATE="false"
[[ "${1:-}" == "--update" ]] && UPDATE="true"

# name|fixture|options  (options are passed to sigma-to-aql.sh verbatim)
CASES=(
    "not_filter.payload|not_filter.yml|"
    "not_filter.fields|not_filter.yml|--fields"
    "cidr_destination.payload|cidr_destination.yml|"
    "dns_queryname.payload.nomap|dns_queryname.yml|"
    "dns_queryname.fields.lab|dns_queryname.yml|--fields -m ${MAPPING}"
    "failed_logon_source.fields.lab|failed_logon_source.yml|--fields -m ${MAPPING}"
)
# name|fixture|options|expected exit code — must NOT convert
NEGATIVE=(
    "cidr_destination.stock|cidr_destination.yml|--no-cidr-workaround|1"
    "dns_queryname.fields.nomap|dns_queryname.yml|--fields|1"
    "failed_logon_source.fields.nomap|failed_logon_source.yml|--fields|1"
)

[[ -x "${SCRIPT}" ]] || { echo "[ERROR] not executable: ${SCRIPT}" >&2; exit 2; }
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${EXPECTED}"

pass=0; fail=0
for case in "${CASES[@]}"; do
    IFS='|' read -r name fixture opts <<< "${case}"
    out="${WORK}/${name}"
    mkdir -p "${out}"
    # shellcheck disable=SC2086 — opts is a deliberately word-split option list
    if ! "${SCRIPT}" "${FIXTURES}/${fixture}" ${opts} -o "${out}" >/dev/null 2>"${out}/stderr"; then
        echo "FAIL ${name}: conversion failed" >&2
        sed 's/^/      /' "${out}/stderr" >&2
        fail=$((fail + 1)); continue
    fi
    got="${out}/${fixture%.yml}.aql"
    want="${EXPECTED}/${name}.aql"
    if [[ "${UPDATE}" == "true" ]]; then
        cp "${got}" "${want}"; echo "UPDATED ${name}"; continue
    fi
    if [[ ! -f "${want}" ]]; then
        echo "FAIL ${name}: no expected file ${want} (run with --update)" >&2
        fail=$((fail + 1)); continue
    fi
    if cmp -s "${got}" "${want}"; then
        echo "ok   ${name}"; pass=$((pass + 1))
    else
        echo "FAIL ${name}: output differs from ${want}" >&2
        diff -u "${want}" "${got}" >&2 || true
        fail=$((fail + 1))
    fi
done

for case in "${NEGATIVE[@]}"; do
    IFS='|' read -r name fixture opts want_rc <<< "${case}"
    out="${WORK}/${name}"
    mkdir -p "${out}"
    rc=0
    # shellcheck disable=SC2086
    "${SCRIPT}" "${FIXTURES}/${fixture}" ${opts} -o "${out}" >/dev/null 2>&1 || rc=$?
    if [[ "${rc}" -eq "${want_rc}" ]]; then
        echo "ok   ${name} (expected failure, exit ${rc})"; pass=$((pass + 1))
    else
        echo "FAIL ${name}: exit ${rc}, expected ${want_rc}" >&2
        fail=$((fail + 1))
    fi
done

echo "=== ${pass} passed, ${fail} failed ==="
[[ "${fail}" -eq 0 ]]
