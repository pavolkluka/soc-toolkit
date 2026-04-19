# Changelog

All notable changes to this project are documented here. Format roughly
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **README.md**: Support section replaced with Hydranode Lightning donation
  button (`images/hydranode_donation_button_black.png`) wrapped in an HTML
  `<a target="_blank" rel="noopener noreferrer">` anchor so clicks open in a
  new tab (GitHub markdown does not honor `target` on `[text](url)` syntax).
  Accompanying text changed to "If you want to support me, you can do so in
  satoshi. Use the Lightning Network."

### Fixed

- **file-triage.sh v0.4.1**: triage-dynamic output no longer overwrites the
  partial malwoverview report with a bare error note on upstream crash. The
  report header and `analysis:` block (id, target, hashes, platform, resource,
  `time_net`, `time_krn`) are now preserved; the Python traceback is trimmed
  with `awk` and followed by a `---` separator and a sanitized note explaining
  the known upstream bug (`'NoneType' object is not iterable` when the Tria.ge
  response has no `tags` field).
- **file-triage.sh v0.4.1**: FLARE floss invocation now uses
  `--disable-progress --quiet` to eliminate tqdm progress bars and
  "analyzing program" status spam that previously dominated the output file
  (observed reduction: 164 KB → ~1 KB on the same Rust sample).
- **file-triage.sh v0.4.1**: FLARE capa `-vv` is now skipped when default capa
  already reports "does not appear to target a supported OS" (typically
  stripped or custom ELFs). This avoids a redundant ~30 s poll cycle that
  would produce an identical error output.

## [0.4.0] - 2026-04-19

### Added

- **file-triage.sh v0.4.0**: FLARE floss and FLARE capa integration in the
  format-specific dispatch. floss runs only for PE (FLOSS upstream does not
  support ELF for string decoding); capa runs for both PE and ELF in default
  and `-vv` modes.
- **common/utils.sh v0.2.0**: `run_polled()` helper — runs a long-running
  command in the background, logs progress every N seconds, enforces a hard
  timeout cap, captures stdout+stderr to an outfile. Return codes: 0 success,
  1 non-zero rc, 2 timeout, 3 empty output.
- **common/requirements-check.sh**: `flare-floss` and `flare-capa` added to
  the Tier 2 pipx dependency list.

### Changed

- **common/requirements-check.sh**: PATH now augmented with `~/.local/bin` at
  script entry so `command -v` probes succeed in non-interactive SSH shells
  where the default PATH does not include the user-local pipx bin directory.

### Fixed

- **file-triage.sh**: Detect-It-Easy now runs with `--deepscan --heuristicscan`
  so heuristic signature matching is included in the report.
- **file-triage.sh**: malwoverview `-x 7` (Tria.ge dynamic report) non-zero
  exit is now handled — the noisy Python traceback is replaced in the output
  file with a short explanatory note and the actual exit code is surfaced in
  the `[WARN]` log line.
- **README.md**: `requirements-check.sh` usage example corrected to use
  `--check-only` (the previous example used a non-existent positional
  argument).

## [0.3.0] - 2026-04-17

### Added

- **triage/file-triage.sh v0.3.0**: static file triage script covering
  hashing (MD5/SHA1/SHA256), metadata extraction (DIE, TrID, exiftool),
  strings, malwoverview threat intel (VirusTotal, Tria.ge static + dynamic,
  AlienVault OTX, Malware Bazaar), and format-specific dispatch (PE →
  PortEx Analyzer; ELF → readelf + nm; Office / PDF handlers;
  LNK → LnkParse3). Refactored from the legacy `get_general_info.bash`.
- **triage/common/utils.sh v0.1.0**: logging primitives (`log_info`,
  `log_warn`, `log_error`), counter formatting, ANSI strip, idempotent
  `ensure_dir`, shared across triage scripts.
- **triage/common/requirements-check.sh**: tiered dependency checker
  (Tier 1: apt system tools; Tier 2: pipx Python tools). Supports
  `--check-only`, `--list`, and `--install-deps` with interactive prompt.

## [0.2.0] - 2026-04-16

### Added

- **docs/methodology.md**: triage methodology reference.
- **docs/tool-deps.md**: per-tool dependency matrix.
- **docs/remnux-notes.md**: REMnux-specific setup notes and known issues.

## [0.1.0] - 2026-04-16

### Added

- Initial repository structure (`triage/`, `triage/common/`, `venv-setup/`,
  `docs/`, `secrets/`).
- **README.md**: main project overview, tool descriptions, setup
  instructions.
- `.gitignore` covering `secrets/.malwapi.conf`, `CLAUDE.md`, `output/`,
  Python `venv/`, and local scratch directories.
