#!/usr/bin/env bash
# file-triage.sh — Static file triage: hashing, metadata, strings, threat intel, format-specific analysis
#
# Usage:   file-triage.sh -i <input_file> [-o <output_dir>]
#          file-triage.sh [-h|--help]
#
# Tested on: REMnux (Ubuntu 24.04.3 LTS, primary), Ubuntu 22.04 LTS
# Version:   0.3.0
# Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
# Date:      2026-04-17
# Platforms: Linux

set -euo pipefail

### CONSTANTS
SCRIPT_NAME="file-triage.sh"
SCRIPT_VERSION="0.3.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATE_SHORT="$(date +"%Y-%m-%d")"
DATE_LONG="$(date +"%Y-%m-%d %H:%M")"

### SHARED UTILITIES
# shellcheck source=common/utils.sh
if [[ ! -f "${SCRIPT_DIR}/common/utils.sh" ]]; then
    echo "[ERROR] Required file not found: ${SCRIPT_DIR}/common/utils.sh" >&2
    exit 2
fi
source "${SCRIPT_DIR}/common/utils.sh"

### GLOBALS (set later)
MD5=""
SHA1=""
SHA256=""
TMPFILE=""
COUNTER=1
COUNTER_INITIAL=1

### FUNCTIONS

script_usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} -i <input_file> [-o <output_dir>]
       ${SCRIPT_NAME} [-h|--help]

File triage: hashing, metadata, strings, threat intel, format-specific analysis.
Primary environment: REMnux. Also works on Debian/Ubuntu-based Linux.

Options:
  -i, --input-file PATH    File to analyze (required)
  -o, --output-dir PATH    Output directory (default: ./output)
  -h, --help               Show this help and exit

Output files (numbered, format: NNN-<filename>-<stage>.txt):
  001 hashes (MD5, SHA1, SHA256)
  002 Detect-It-Easy (file type / packer)
  003 TrID
  004 ExifTool (metadata)
  005 strings
  006+ Malwoverview: VirusTotal, Tria.ge (+ per-ID reports), AlienVault OTX, Malware Bazaar
  NNN+ Format-specific:
    PE:    PortEx Analyzer
    ELF:   readelf -a, nm -D
    PDF:   pdfid.py, peepdf
    RTF:   rtfobj, oleobj
    OLE:   oledump.py, oleobj
    OOXML: oledump.py, oleobj
    LNK:   lnkparse (LnkParse3)
    ZIP/RAR/7z: archive content listing (no recursion)
    Scripts (.vbs/.js/.ps1/.bat/etc.): strings only (no language-specific tool)

Exit codes:
  0  success
  1  argument error / file not found
  2  missing required dependency

Examples:
  ${SCRIPT_NAME} -i /path/to/sample.exe
  ${SCRIPT_NAME} -i sample.docx -o /tmp/triage-run-01
EOF
}

compute_hashes() {
    local file="$1"
    MD5="$(md5sum "$file" | awk '{print $1}')"
    SHA1="$(sha1sum "$file" | awk '{print $1}')"
    SHA256="$(sha256sum "$file" | awk '{print $1}')"
}

detect_file_type() {
    local file="$1"
    local mime
    mime="$(file --mime-type -b "$file")"

    case "$mime" in
        application/x-dosexec|application/x-msdownload|application/vnd.microsoft.portable-executable)
            echo "pe" ;;
        application/x-executable|application/x-sharedlib|application/x-pie-executable|application/x-object)
            echo "elf" ;;
        application/pdf)
            echo "pdf" ;;
        text/rtf|application/rtf)
            echo "rtf" ;;
        application/x-ole-storage|application/msword|application/vnd.ms-excel|application/vnd.ms-powerpoint|application/CDFV2)
            echo "ole" ;;
        application/vnd.openxmlformats-*)
            echo "ooxml" ;;
        application/zip|application/x-zip-compressed)
            # OOXML files are ZIP containers — check extension as tie-break
            local ext="${file##*.}"
            case "${ext,,}" in
                docx|xlsx|pptx|dotx|xlsm|pptm)
                    echo "ooxml" ;;
                *)
                    echo "archive" ;;
            esac
            ;;
        application/x-rar|application/x-rar-compressed|application/vnd.rar|application/x-7z-compressed)
            echo "archive" ;;
        application/x-ms-shortcut|application/x-mslnk|application/vnd.microsoft.linkfile)
            echo "lnk" ;;
        text/x-python|application/x-shellscript|text/x-perl|application/javascript|text/javascript|application/x-vbscript|text/vbscript)
            echo "script" ;;
        *)
            # Fallback: check extension (file's MIME detection misclassifies some scripts/RTFs)
            local ext="${file##*.}"
            case "${ext,,}" in
                exe|dll|sys|drv|ocx|efi|cpl|scr)
                    echo "pe" ;;
                elf|so|o|ko)
                    echo "elf" ;;
                pdf)
                    echo "pdf" ;;
                rtf)
                    echo "rtf" ;;
                doc|xls|ppt|msi)
                    echo "ole" ;;
                docx|xlsx|pptx|dotx|xlsm|pptm)
                    echo "ooxml" ;;
                zip|rar|7z|tar|gz|bz2|xz)
                    echo "archive" ;;
                lnk)
                    echo "lnk" ;;
                vbs|vbe|js|jse|ps1|bat|cmd|sh|py|pl)
                    echo "script" ;;
                *)
                    echo "unknown" ;;
            esac
            ;;
    esac
}

run_malwoverview() {
    local label="$1"; shift
    local outfile="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-malw-${label}.txt"
    if malwoverview "$@" 2>&1 | strip_ansi > "${outfile}"; then
        log_info "Malwoverview (${label}) saved to: ${outfile}"
    else
        log_warn "Malwoverview (${label}) exited non-zero — output may be partial: ${outfile}"
    fi
    COUNTER=$((COUNTER + 1))
}

cleanup() {
    if [[ -n "${TMPFILE}" && -f "${TMPFILE}" ]]; then
        rm -f "${TMPFILE}"
    fi
}

### DEPENDENCY CHECK (critical tools only)
check_deps() {
    local missing=0
    local tool
    for tool in diec trid file exiftool malwoverview strings md5sum sha1sum sha256sum; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            log_error "Missing required tool: ${tool}"
            missing=$((missing + 1))
        fi
    done
    if [[ "${missing}" -gt 0 ]]; then
        log_error "Install missing tools and retry."
        exit 2
    fi
}

### ARGUMENT PARSER
DIR_OUTPUT_ARG=""
SCRIPT_ARG=""

if [[ "$#" -eq 0 ]]; then
    script_usage
    exit 1
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -i|--input-file)
            if [[ -z "${2:-}" ]]; then
                log_error "Option $1 requires an argument."
                script_usage
                exit 1
            fi
            SCRIPT_ARG="$2"
            shift 2
            ;;
        -o|--output-dir)
            if [[ -z "${2:-}" ]]; then
                log_error "Option $1 requires an argument."
                script_usage
                exit 1
            fi
            DIR_OUTPUT_ARG="$2"
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
if [[ -z "${SCRIPT_ARG}" ]]; then
    log_error "Option -i / --input-file is required."
    script_usage
    exit 1
fi

if [[ ! -f "${SCRIPT_ARG}" || ! -r "${SCRIPT_ARG}" ]]; then
    log_error "File not found or not readable: ${SCRIPT_ARG}"
    exit 1
fi

### SETUP
check_deps

PATH_FILE="$(readlink -f "${SCRIPT_ARG}")"
SCRIPT_ARG_FILE="$(basename "${PATH_FILE}")"
DIR_OUTPUT="${DIR_OUTPUT_ARG:-./output}"

ensure_dir "${DIR_OUTPUT}"

# Artifacts directory: sibling of output dir, auto-derived with -artifacts suffix.
# Created lazily (only when a tool that extracts payloads is dispatched).
DIR_ARTIFACTS="${DIR_OUTPUT}-artifacts"
DIR_ARTIFACTS_CREATED=0

ensure_artifacts_dir() {
    if [[ "${DIR_ARTIFACTS_CREATED}" -eq 0 ]]; then
        if mkdir -p "${DIR_ARTIFACTS}" 2>/dev/null; then
            DIR_ARTIFACTS_CREATED=1
            log_info "Artifacts directory created: ${DIR_ARTIFACTS}"
        else
            log_error "Cannot create artifacts directory: ${DIR_ARTIFACTS}"
            return 1
        fi
    fi
    return 0
}

trap cleanup EXIT

# Determine starting counter from existing output files
if [[ -z "$(ls "${DIR_OUTPUT}" 2>/dev/null)" ]]; then
    log_info "Counter for output files starts at 1."
    COUNTER=1
else
    TEMP_COUNTER="$(ls "${DIR_OUTPUT}" | sort | tail -1 | grep -oP '^[0-9]{3}' | sed 's/^0*//' || echo '0')"
    if [[ -z "${TEMP_COUNTER}" ]]; then
        TEMP_COUNTER=0
    fi
    COUNTER=$((TEMP_COUNTER + 1))
    log_info "Counter for output files continues at ${COUNTER}."
fi
COUNTER_INITIAL="${COUNTER}"

### 001 HASHES
echo ""
log_info "Computing hashes..."
compute_hashes "${PATH_FILE}"
HASH_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-hashes.txt"
diec --special Hash "${PATH_FILE}" > "${HASH_OUTFILE}"
log_info "Hashes saved to: ${HASH_OUTFILE}"
COUNTER=$((COUNTER + 1))

### 002 DETECT-IT-EASY
echo ""
log_info "Detect-It-Easy (deepscan + heuristicscan)..."
DIE_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-die.txt"
if diec --deepscan --heuristicscan "${PATH_FILE}" > "${DIE_OUTFILE}"; then
    log_info "Detect-It-Easy output saved to: ${DIE_OUTFILE}"
else
    log_warn "Detect-It-Easy exited non-zero — output may be partial: ${DIE_OUTFILE}"
fi
COUNTER=$((COUNTER + 1))

### 003 TRID
echo ""
log_info "TrID..."
TRID_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-trid.txt"
if trid "${PATH_FILE}" > "${TRID_OUTFILE}"; then
    log_info "TrID output saved to: ${TRID_OUTFILE}"
else
    log_warn "TrID exited non-zero — output may be partial: ${TRID_OUTFILE}"
fi
COUNTER=$((COUNTER + 1))

### 004 EXIFTOOL
echo ""
log_info "ExifTool..."
EXIF_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-exiftool.txt"
if exiftool "${PATH_FILE}" > "${EXIF_OUTFILE}"; then
    log_info "ExifTool output saved to: ${EXIF_OUTFILE}"
else
    log_warn "ExifTool exited non-zero — output may be partial: ${EXIF_OUTFILE}"
fi
COUNTER=$((COUNTER + 1))

### 005 STRINGS
echo ""
log_info "strings..."
STRINGS_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-strings.txt"
if strings "${PATH_FILE}" > "${STRINGS_OUTFILE}"; then
    log_info "strings output saved to: ${STRINGS_OUTFILE}"
else
    log_warn "strings exited non-zero — output may be partial: ${STRINGS_OUTFILE}"
fi
COUNTER=$((COUNTER + 1))

### 006+ MALWOVERVIEW — VIRUSTOTAL
echo ""
log_info "Malwoverview: VirusTotal..."
run_malwoverview "virustotal" -v 8 -V "${SHA256}"

### MALWOVERVIEW — TRIA.GE
echo ""
log_info "Malwoverview: Tria.ge search..."
TRIAGE_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-malw-triage.txt"
if malwoverview -x 1 -X "${SHA256}" 2>&1 | strip_ansi > "${TRIAGE_OUTFILE}"; then
    log_info "Malwoverview (triage) saved to: ${TRIAGE_OUTFILE}"
else
    log_warn "Malwoverview (triage) exited non-zero — output may be partial: ${TRIAGE_OUTFILE}"
fi
COUNTER=$((COUNTER + 1))

TRIAGE_IDS="$(grep -oP 'id:\s+\K[0-9a-zA-Z-]+' "${TRIAGE_OUTFILE}" || true)"
if [[ -n "${TRIAGE_IDS}" ]]; then
    while IFS= read -r ID; do
        echo ""
        log_info "Malwoverview: Tria.ge report for ID: ${ID}..."
        TRIAGE_ID_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-malw-triage-${ID}.txt"
        if malwoverview -x 2 -X "${ID}" 2>&1 | strip_ansi > "${TRIAGE_ID_OUTFILE}"; then
            log_info "Malwoverview (triage ID: ${ID}) saved to: ${TRIAGE_ID_OUTFILE}"
        else
            log_warn "Malwoverview (triage ID: ${ID}) exited non-zero — output may be partial: ${TRIAGE_ID_OUTFILE}"
        fi
        COUNTER=$((COUNTER + 1))

        TRIAGE_DYN_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-malw-triage-${ID}-dynamic.txt"
        if malwoverview -x 7 -X "${ID}" 2>&1 | strip_ansi > "${TRIAGE_DYN_OUTFILE}"; then
            log_info "Malwoverview (triage dynamic ID: ${ID}) saved to: ${TRIAGE_DYN_OUTFILE}"
        else
            DYN_RC=$?
            log_warn "Malwoverview (triage dynamic ID: ${ID}) exited non-zero (rc=${DYN_RC}): ${TRIAGE_DYN_OUTFILE}"
            # Replace noisy Python traceback with a short sanitized note (upstream bug
            # in malwoverview triage_dynamic when Tria.ge response has no 'tags' field).
            cat > "${TRIAGE_DYN_OUTFILE}" <<EOF
malwoverview -x 7 -X ${ID} failed with exit code ${DYN_RC}.
If the traceback showed "TypeError: 'NoneType' object is not iterable" in
malwoverview/modules/triage.py triage_dynamic, it is a known upstream bug
that occurs when the Tria.ge response has no 'tags' field.
EOF
        fi
        COUNTER=$((COUNTER + 1))
    done <<< "${TRIAGE_IDS}"
else
    log_info "No Tria.ge report IDs found for: ${SCRIPT_ARG_FILE}"
fi

### MALWOVERVIEW — ALIENVAULT OTX
echo ""
log_info "Malwoverview: AlienVault OTX..."
run_malwoverview "alienvault" -n 4 -N "${SHA256}" -o 0

### MALWOVERVIEW — MALWARE BAZAAR
echo ""
log_info "Malwoverview: Malware Bazaar..."
run_malwoverview "alienvault-bazaar" -b 1 -B "${SHA256}"

### FORMAT-SPECIFIC DISPATCH
echo ""
FILE_TYPE="$(detect_file_type "${PATH_FILE}")"
log_info "Detected file type category: ${FILE_TYPE}"

case "${FILE_TYPE}" in
    pe)
        echo ""
        log_info "PE: PortEx Analyzer..."
        PORTEX_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-portex.txt"
        if command -v portex > /dev/null 2>&1; then
            if portex -o "${PORTEX_OUTFILE}" "${PATH_FILE}"; then
                log_info "PortEx output saved to: ${PORTEX_OUTFILE}"
            else
                log_warn "PortEx exited non-zero — output may be partial: ${PORTEX_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "portex not found — skipping PE-specific analysis."
        fi
        ;;
    elf)
        echo ""
        log_info "ELF: readelf..."
        if command -v readelf > /dev/null 2>&1; then
            READELF_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-readelf.txt"
            if readelf -a "${PATH_FILE}" > "${READELF_OUTFILE}" 2>&1; then
                log_info "readelf output saved to: ${READELF_OUTFILE}"
            else
                log_warn "readelf exited non-zero — output may be partial: ${READELF_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "readelf not found — skipping."
        fi

        echo ""
        log_info "ELF: nm..."
        if command -v nm > /dev/null 2>&1; then
            NM_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-nm.txt"
            if nm -D "${PATH_FILE}" > "${NM_OUTFILE}" 2>&1; then
                log_info "nm output saved to: ${NM_OUTFILE}"
            else
                log_warn "nm exited non-zero — output may be partial: ${NM_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "nm not found — skipping."
        fi
        ;;
    pdf)
        echo ""
        log_info "PDF: pdfid.py..."
        if command -v pdfid.py > /dev/null 2>&1; then
            PDFID_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-pdfid.txt"
            if pdfid.py "${PATH_FILE}" > "${PDFID_OUTFILE}"; then
                log_info "pdfid.py output saved to: ${PDFID_OUTFILE}"
            else
                log_warn "pdfid.py exited non-zero — output may be partial: ${PDFID_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "pdfid.py not found — skipping."
        fi

        echo ""
        log_info "PDF: peepdf..."
        if command -v peepdf > /dev/null 2>&1; then
            PEEPDF_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-peepdf.txt"
            if echo exit | peepdf -i "${PATH_FILE}" 2>&1 | strip_ansi > "${PEEPDF_OUTFILE}"; then
                log_info "peepdf output saved to: ${PEEPDF_OUTFILE}"
            else
                log_warn "peepdf exited non-zero — output may be partial: ${PEEPDF_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "peepdf not found — skipping."
        fi
        ;;
    rtf)
        echo ""
        log_info "RTF: rtfobj..."
        if command -v rtfobj > /dev/null 2>&1; then
            ensure_artifacts_dir || true
            RTFOBJ_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-rtfobj.txt"
            if rtfobj -d "${DIR_ARTIFACTS}" "${PATH_FILE}" > "${RTFOBJ_OUTFILE}" 2>&1; then
                log_info "rtfobj output saved to: ${RTFOBJ_OUTFILE}"
            else
                log_warn "rtfobj exited non-zero — output may be partial: ${RTFOBJ_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "rtfobj not found — skipping (install: pip install oletools)."
        fi

        echo ""
        log_info "RTF: oleobj..."
        if command -v oleobj > /dev/null 2>&1; then
            ensure_artifacts_dir || true
            OLEOBJ_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-oleobj.txt"
            if oleobj -d "${DIR_ARTIFACTS}" "${PATH_FILE}" > "${OLEOBJ_OUTFILE}" 2>&1; then
                log_info "oleobj output saved to: ${OLEOBJ_OUTFILE}"
            else
                log_warn "oleobj exited non-zero — output may be partial: ${OLEOBJ_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "oleobj not found — skipping."
        fi
        ;;
    ole)
        echo ""
        log_info "OLE: oledump.py..."
        if command -v oledump.py > /dev/null 2>&1; then
            OLEDUMP_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-oledump.txt"
            if oledump.py "${PATH_FILE}" > "${OLEDUMP_OUTFILE}"; then
                log_info "oledump.py output saved to: ${OLEDUMP_OUTFILE}"
            else
                log_warn "oledump.py exited non-zero — output may be partial: ${OLEDUMP_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "oledump.py not found — skipping."
        fi

        echo ""
        log_info "OLE: oleobj..."
        if command -v oleobj > /dev/null 2>&1; then
            ensure_artifacts_dir || true
            OLEOBJ_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-oleobj.txt"
            if oleobj -d "${DIR_ARTIFACTS}" "${PATH_FILE}" > "${OLEOBJ_OUTFILE}" 2>&1; then
                log_info "oleobj output saved to: ${OLEOBJ_OUTFILE}"
            else
                log_warn "oleobj exited non-zero — output may be partial: ${OLEOBJ_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "oleobj not found — skipping."
        fi
        ;;
    ooxml)
        echo ""
        log_info "OOXML: oledump.py (ZIP container)..."
        if command -v oledump.py > /dev/null 2>&1; then
            OLEDUMP_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-oledump.txt"
            if oledump.py "${PATH_FILE}" > "${OLEDUMP_OUTFILE}"; then
                log_info "oledump.py output saved to: ${OLEDUMP_OUTFILE}"
            else
                log_warn "oledump.py exited non-zero — output may be partial: ${OLEDUMP_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "oledump.py not found — skipping."
        fi

        echo ""
        log_info "OOXML: oleobj..."
        if command -v oleobj > /dev/null 2>&1; then
            ensure_artifacts_dir || true
            OLEOBJ_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-oleobj.txt"
            if oleobj -d "${DIR_ARTIFACTS}" "${PATH_FILE}" > "${OLEOBJ_OUTFILE}" 2>&1; then
                log_info "oleobj output saved to: ${OLEOBJ_OUTFILE}"
            else
                log_warn "oleobj exited non-zero — output may be partial: ${OLEOBJ_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "oleobj not found — skipping."
        fi
        ;;
    lnk)
        echo ""
        log_info "LNK: lnkparse (LnkParse3)..."
        if command -v lnkparse > /dev/null 2>&1; then
            LNK_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-lnkparse.txt"
            if lnkparse -a "${PATH_FILE}" > "${LNK_OUTFILE}" 2>&1; then
                log_info "lnkparse output saved to: ${LNK_OUTFILE}"
            else
                log_warn "lnkparse exited non-zero — output may be partial: ${LNK_OUTFILE}"
            fi
            COUNTER=$((COUNTER + 1))
        else
            log_warn "lnkparse not found — skipping (install: pip install LnkParse3)."
        fi
        ;;
    archive)
        echo ""
        log_info "Archive: listing contents..."
        local_ext="${PATH_FILE##*.}"
        ARCHIVE_OUTFILE="${DIR_OUTPUT}/$(format_counter "${COUNTER}")-${SCRIPT_ARG_FILE}-archive-list.txt"
        case "${local_ext,,}" in
            zip)
                if command -v unzip > /dev/null 2>&1; then
                    if unzip -l "${PATH_FILE}" > "${ARCHIVE_OUTFILE}"; then
                        log_info "Archive listing saved to: ${ARCHIVE_OUTFILE}"
                    else
                        log_warn "unzip exited non-zero — output may be partial: ${ARCHIVE_OUTFILE}"
                    fi
                else
                    log_warn "unzip not found — trying 7z..."
                    if command -v 7z > /dev/null 2>&1; then
                        if 7z l "${PATH_FILE}" > "${ARCHIVE_OUTFILE}"; then
                            log_info "Archive listing (7z) saved to: ${ARCHIVE_OUTFILE}"
                        else
                            log_warn "7z exited non-zero — output may be partial: ${ARCHIVE_OUTFILE}"
                        fi
                    else
                        log_warn "Neither unzip nor 7z found — cannot list archive."
                    fi
                fi
                ;;
            rar)
                if command -v unrar > /dev/null 2>&1; then
                    if unrar l "${PATH_FILE}" > "${ARCHIVE_OUTFILE}"; then
                        log_info "Archive listing (unrar) saved to: ${ARCHIVE_OUTFILE}"
                    else
                        log_warn "unrar exited non-zero — output may be partial: ${ARCHIVE_OUTFILE}"
                    fi
                elif command -v 7z > /dev/null 2>&1; then
                    if 7z l "${PATH_FILE}" > "${ARCHIVE_OUTFILE}"; then
                        log_info "Archive listing (7z) saved to: ${ARCHIVE_OUTFILE}"
                    else
                        log_warn "7z exited non-zero — output may be partial: ${ARCHIVE_OUTFILE}"
                    fi
                else
                    log_warn "Neither unrar nor 7z found — cannot list RAR archive."
                fi
                ;;
            7z|tar|gz|bz2|xz)
                if command -v 7z > /dev/null 2>&1; then
                    if 7z l "${PATH_FILE}" > "${ARCHIVE_OUTFILE}"; then
                        log_info "Archive listing (7z) saved to: ${ARCHIVE_OUTFILE}"
                    else
                        log_warn "7z exited non-zero — output may be partial: ${ARCHIVE_OUTFILE}"
                    fi
                else
                    log_warn "7z not found — cannot list archive."
                fi
                ;;
            *)
                log_info "Archive type by extension unknown — trying 7z..."
                if command -v 7z > /dev/null 2>&1; then
                    if 7z l "${PATH_FILE}" > "${ARCHIVE_OUTFILE}"; then
                        log_info "Archive listing (7z) saved to: ${ARCHIVE_OUTFILE}"
                    else
                        log_warn "7z exited non-zero — output may be partial: ${ARCHIVE_OUTFILE}"
                    fi
                else
                    log_warn "7z not found — cannot list archive."
                fi
                ;;
        esac
        COUNTER=$((COUNTER + 1))
        ;;
    script|unknown)
        log_info "No format-specific tools for type: ${FILE_TYPE}"
        ;;
    *)
        log_info "No format-specific tools for type: ${FILE_TYPE}"
        ;;
esac

### SUMMARY
FILES_GENERATED=$((COUNTER - COUNTER_INITIAL))
echo ""
log_info "Triage complete for: ${SCRIPT_ARG_FILE}"
log_info "Output directory:    ${DIR_OUTPUT}"
if [[ "${DIR_ARTIFACTS_CREATED}" -eq 1 ]]; then
    log_info "Artifacts directory: ${DIR_ARTIFACTS}"
fi
log_info "Files generated:     ${FILES_GENERATED}"

exit 0
