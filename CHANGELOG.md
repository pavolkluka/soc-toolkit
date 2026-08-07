# Changelog

All notable changes to this project are documented here. Format roughly
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **venv-setup/setup.sh**: Python venv bootstrap for the F6 toolkit layer.
  Idempotent (a second run updates an existing venv in place rather than
  recreating it); enforces a Python >= 3.10 guard before proceeding;
  `--check-only` mode reports install status, including which individual
  packages are missing, without mutating the venv.
- **venv-setup/requirements.txt**: pinned dependency set for the F6 toolkit
  layer (msticpy, jupyterlab, sigma-cli, pySigma-backend-QRadar-AQL, pandas,
  matplotlib). Pins `msticpy==3.0.0`, not the `3.0.2` specified in
  `handoff-f6-toolkit.md` §2 (deviation approved after QA caught it):
  `msticpy>=3.0.1` requires `packaging>=26.2`, which conflicts with pySigma
  0.11.x (required by `pySigma-backend-QRadar-AQL==0.3.2`, which pins
  `pySigma<0.12`) requiring `packaging<25.0,>=24.1` — pip returns
  `ResolutionImpossible` on 3.0.2. `msticpy==3.0.0` requires
  `packaging>=24.0` and resolves cleanly; `msticpy.vis.timeline.display_timeline`
  (needed by the TASK-12 timeline notebook) was confirmed still present and
  importable in the built venv.
- **docs/remnux-notes.md**: documented the Python >= 3.10 requirement for
  `venv-setup/setup.sh` — the primary REMnux 2026 target
  (`03-remnux-noble-202602`, Ubuntu 24.04.3, Python 3.12.3) satisfies it and
  passes the full TASK-08 QA gate; the older REMnux 7 target
  (`03-remnux-7-202510`, Python 3.8.10) does not — see "Python version
  requirement (F6 toolkit / venv-setup)".
- **.gitignore**: now also excludes `.claude/` (local Claude Code tooling and
  agent scratch state, not project content), placed directly beneath the
  existing `CLAUDE.md` rule for the same reason.
- **lookup/soc-lookup.py** / **lookup/soc-lookup**: combined IntelOwl + Yeti
  IOC lookup CLI (`soc-lookup <observable>`). Autodetects
  `ip|domain|hash|url` (falls back to `generic`; `--type` overrides), queries
  both sources in parallel (`ThreadPoolExecutor(max_workers=2)`) and
  aggregates results with a `source_ref` per source
  (`yeti:observable/<id>`, `yeti:entity/<id>`, `intelowl:job/<id>`). Config
  via `SOC_YETI_URL`/`SOC_YETI_APIKEY`/`SOC_INTELOWL_URL`/
  `SOC_INTELOWL_TOKEN` or `secrets/soc-lookup.env` (gitignored), validated
  only for the branch(es) actually requested. Exit codes: `0` OK (including
  a legitimate "not found"), `1` API/auth error, `2` IntelOwl job-poll
  timeout, `3` bad args/config. `--json` writes the aggregate to stdout
  only; rich tables and summary always render on stderr, so `| jq` works.
  Yeti output shows observable tags/context plus related nodes (via a
  follow-up `POST /api/v2/graph/search` call — the search response itself
  has no `entities` key, which is what produces `yeti:entity/<id>`);
  IntelOwl output shows the per-analyzer breakdown and job warnings.
  `already_exists` is surfaced so a cached result is distinguishable from a
  fresh one.

  Two deviations from `handoff-f6-toolkit.md` §3, both confirmed against
  live IntelOwl v6.7.0 and Yeti 2.5.1 on 2026-08-06 (handoff §8B
  criterion 1):
  - `--playbook` default is `WB_Lookup`, not the handoff's `WB-Lookup` —
    IntelOwl restricts playbook names to `[A-Za-z0-9_]` and rejects hyphens.
  - `--force` sends `"scan_mode": 1`, not the handoff's
    `"check_analysis_availability"` — that field is silently ignored by
    IntelOwl, so `--force` would have appeared to work while still
    returning cached results.

  Full live-verification evidence (per-item confirmation status) lives in
  `handoff-f6-findings.md`, outside this repo.
- **detection/sigma-to-aql.sh**: converts one Sigma rule or a whole
  directory to QRadar AQL. Writes `detection/output/<rule>.aql` and echoes
  the AQL to stdout for copy-paste into the QRadar console; all logging
  goes to stderr so stdout carries only AQL and can be piped. Default
  pipeline `qradar-aql-payload`; `--fields` switches to `qradar-aql-fields`;
  `-o` overrides the output directory. Directory mode does not abort on a
  bad rule — it counts failures, converts the rest, and exits non-zero.
- **detection/rules/encoded-powershell-command.yml**: one sample Sigma
  rule, written from scratch (not derived from SigmaHQ), detecting encoded
  PowerShell execution. Matches the full valid parameter-prefix range from
  `-e` to `-encodedcommand`, since PowerShell accepts any unambiguous
  prefix and a rule matching only the long spellings is trivially bypassed.
- Deviation from `handoff-f6-toolkit.md` §5: the conversion target is
  `q_radar_aql`, not the handoff's `ibm-qradar-aql`, which sigma-cli
  rejects outright — verifiable via `sigma list targets`.
- Verified on REMnux (Ubuntu 24.04.3, Python 3.12.3) and Debian 12 (Python
  3.11.2), with the generated AQL byte-identical on both.
- **evtx/get-tools.sh**: downloads pinned forensic binaries into `evtx/bin/`
  and clones SigmaHQ rules into `evtx/rules/`. Versions are header variables:
  Hayabusa 4.0.0 (musl), Takajo 2.16.1, Chainsaw 2.16.3, DuckDB 1.4.4,
  SigmaHQ/sigma tag `r2026-07-01`. Idempotent, `--check-only` reports
  installed vs pinned without touching the network, sha256 of every archive
  logged.
- **evtx/evtx-triage.sh**: `-i <evtx_dir> [-o <output_base>]`, produces a
  timestamped run directory with numbered outputs (`001-hayabusa-timeline.csv`,
  `002-hayabusa-timeline.jsonl` for Takajo, `003-takajo-automagic/`,
  `004-chainsaw-hunt/`) plus per-step logs. Confirms Takajo 2.16.1 ↔ Hayabusa
  4.0.0 JSONL compatibility, listed as unconfirmed upstream in
  `handoff-f6-toolkit.md` §9 — no Hayabusa 3.x downgrade fallback needed.
  Acceptance run on 03-remnux-noble-202602 (Ubuntu 24.04.3, 2026-08-06) over
  the full `Yamato-Security/hayabusa-sample-evtx` corpus (599 EVTX files):
  exit 0 in ~100s, 32,377 timeline rows, 781 Takajo output files, 14,047
  non-informational Hayabusa detections, 10,802 Chainsaw detections.
- **.gitignore**: `evtx/bin/` and `evtx/rules/` excluded — downloaded
  binaries and Sigma rules are never committed.
- **notebooks/timeline-template.ipynb**: Jupyter template for
  `001-hayabusa-timeline.csv` (output of `evtx/evtx-triage.sh`). Six cell
  groups: load (path from `SOC_TIMELINE_CSV` env var, no hardcoded path),
  overview (Level/Channel/Computer counts, time range), parametric filters
  (level, time window, computer, keyword), visualisation (msticpy
  `display_timeline` plus a matplotlib fallback), IOC extraction
  (IPv4/domain/hash regex, dedup'd for `lookup/soc-lookup`), and an exported
  markdown summary, auto-numbered after the triage run's `001`-`004`
  outputs. Committed with cleared outputs (real event data, public repo).
  Hayabusa `Level`/`Channel` are abbreviated (`crit`/`high`/`med`/`low`/
  `info`, `Sec`/`Sys`/`Sysmon`) — filtering uses an explicit ordinal map, not
  a string match. `Timestamp` carries the source host's local offset, not
  UTC — parsed with `utc=True`. Uses `display_timeline` directly, not the
  `mp_plot.timeline()` accessor from `handoff-f6-toolkit.md` §6 (needs
  `init_notebook()`, warns on missing config); no msticpy config required,
  so the nbconvert risk in handoff §9 doesn't apply. The §6.5 domain regex
  matched Windows filenames; a denylist filters most, some .NET identifiers
  still slip through (known limitation). Verified on REMnux (Ubuntu
  24.04.3) against the 32,377-row full-corpus CSV — 7.2s, 3,689 IOCs; also
  run on Debian 12 on a smaller sample.
- **.gitignore**: `notebooks/.ipynb_checkpoints/`.
- **docs/atomic-validation.md**: new document — Atomic Red Team validation
  workflow (install Invoke-AtomicRedTeam on a lab victim VM, map a
  `detection/rules/` Sigma rule's ATT&CK tag to atomic tests, run + confirm
  the detection fired via `evtx/evtx-triage.sh` Chainsaw output or the AQL
  from `detection/sigma-to-aql.sh`, then clean up). Opens with an explicit
  provenance note: none of the commands in this document have been executed
  or verified in this project — no Windows or pwsh victim VM was available —
  they are transcribed from `handoff-f6-toolkit.md` §7 and upstream
  Invoke-AtomicRedTeam documentation, unlike the rest of this repo's docs,
  which record measured facts. States up front that atomics are never run
  on the workbench host, lab victim VM only.
- **docs/methodology.md**: added "EVTX Triage Workflow" (`get-tools.sh` once
  → `evtx-triage.sh` → numbered run directory → timeline notebook, which
  appends its markdown summary as the next numbered output) and "IOC Lookup
  Workflow" (observable → `soc-lookup` → Yeti + IntelOwl results with a
  `source_ref` per source, prerequisite: the `WB_Lookup` playbook)
  sections. The existing PCAP and Windows-events placeholder sections
  (reserved for TASK-06/TASK-07) are unchanged.
- **docs/tool-deps.md**: added "soc-lookup" (Python deps, env vars, the
  IntelOwl/Yeti API contract as implemented, and a "Prerequisite: the
  WB_Lookup playbook" subsection with a working `curl` example for
  recreating it), "EVTX toolchain" (pinned versions, operational facts,
  confirms Takajo 2.16.1 reads Hayabusa 4.0.0 super-verbose JSONL correctly
  — no Hayabusa 3.x downgrade fallback needed — and a Hayabusa CSV quirks
  list), and "notebooks" (jupyterlab/pandas/matplotlib/msticpy deps, why
  msticpy is pinned at 3.0.0 not 3.0.2, why no msticpy config is required,
  the input contract, and the IOC-regex known limitation) sections, placed
  in repo directory order alongside the existing file-triage.sh and
  sigma-to-aql.sh sections.

### Changed

- **README.md**: Support section replaced with Hydranode Lightning donation
  button (`images/hydranode_donation_button_black.png`) wrapped in an HTML
  `<a target="_blank" rel="noopener noreferrer">` anchor so clicks open in a
  new tab (GitHub markdown does not honor `target` on `[text](url)` syntax).
  Accompanying text changed to "If you want to support me, you can do so in
  satoshi. Use the Lightning Network."
- **README.md**: added sections for `soc-lookup`, `evtx-triage.sh` (naming
  `get-tools.sh` as the required first step), `sigma-to-aql.sh`, and
  `notebooks/timeline-template.ipynb`, in the style of the existing
  entries, placed before the `pcap-triage.py` / `windows-events-triage.py`
  "coming soon" entries. Added `docs/atomic-validation.md` to the
  Documentation list. The `venv-setup/setup.sh` reference was checked
  against the repo and is already correct — `venv-setup/setup.sh` exists
  (TASK-08); no correction was needed.

### Fixed

- **lookup/soc-lookup.py**: corrected stale documentation in the module
  docstring and comment block, which still stated the script had never been
  run against a live IntelOwl or Yeti instance. The live acceptance run
  (handoff §8B criterion 1) passed on 2026-08-06 against IntelOwl v6.7.0 and
  Yeti 2.5.1. The isolation block is renamed from "UNVERIFIED AGAINST LIVE
  API" to "API-SHAPE-DEPENDENT VALUES", since its contents are now verified
  and its remaining purpose is to keep any future API-shape change to a
  single-block edit. Comments only; no logic change.
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
- **README.md**: `windows-events-triage.py` *(coming soon)* blurb clarified —
  previously read as duplicating the now-shipped `evtx/evtx-triage.sh`. Now
  distinguishes the two (native Python parser for specific event categories
  vs. evtx-triage.sh's external-binary-based broad detection) and points
  readers wanting EVTX analysis today at `evtx/evtx-triage.sh`.
- **README.md**: Setup section now includes `evtx/get-tools.sh` as a
  one-time step (~270 MB, gitignored), previously documented only inside
  the `evtx-triage.sh` tool section.

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
