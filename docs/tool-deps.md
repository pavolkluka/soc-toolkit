# Tool Dependencies

## file-triage.sh

### System tools (apt)

| Tool | Package | REMnux | Purpose |
|------|---------|--------|---------|
| md5sum, sha1sum, sha256sum | coreutils | pre-installed | File hashing |
| strings | binutils | pre-installed | Extract printable strings |
| file | file | pre-installed | File type identification |
| curl | curl | pre-installed | HTTP requests |
| jq | jq | pre-installed | JSON parsing |
| exiftool | libimage-exiftool-perl | pre-installed | Metadata extraction |

### Python tools (pip)

| Tool | pip install | REMnux | Purpose |
|------|-------------|--------|---------|
| malwoverview | malwoverview | pre-installed | Threat intel lookups: VirusTotal, Tria.ge, AlienVault OTX, Malware Bazaar |
| oledump.py | oledump | pre-installed | OLE stream analysis |
| pdfid.py | pdfid | pre-installed | PDF structure analysis |
| peepdf | peepdf-3 | pre-installed | PDF deep analysis |
| oleobj | oletools | pre-installed | OLE embedded object extraction |

### External tools (manual install)

| Tool | Source | REMnux | Purpose |
|------|--------|--------|---------|
| diec | [github.com/horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | pre-installed | File type / packer detection |
| trid | [mark0.net/soft-trid-e.html](https://mark0.net/soft-trid-e.html) | pre-installed | File type identification |
| portex | [github.com/struppigel/PortEx](https://github.com/struppigel/PortEx) | pre-installed | PE file analysis |

### Configuration

| File | Purpose |
|------|---------|
| ~/.malwapi.conf | API keys for malwoverview (VirusTotal, Tria.ge, AlienVault OTX, Malware Bazaar) |

## soc-lookup

### Python tools (pip, via venv-setup/requirements.txt)

| Tool | pip install | Purpose |
|------|-------------|---------|
| click | click | CLI argument parsing |
| rich | rich | Terminal table output (always written to stderr, so `--json \| jq` stays clean) |
| requests | requests | HTTP client for the Yeti and IntelOwl REST APIs |

### Configuration

| Variable | Purpose |
|----------|---------|
| SOC_YETI_URL | Yeti base URL, e.g. `http://127.0.0.1:8089` |
| SOC_YETI_APIKEY | Yeti API key (Yeti UI profile -> API key) |
| SOC_INTELOWL_URL | IntelOwl base URL, e.g. `http://127.0.0.1:8082` |
| SOC_INTELOWL_TOKEN | IntelOwl API token (IntelOwl UI "API Access") |

Only the variable(s) for the branch(es) actually requested are validated
(`--yeti-only` / `--intelowl-only` narrow this); a missing variable is a
hard error naming exactly which one is missing. Any of the above can
instead be set in `secrets/soc-lookup.env` (gitignored, `KEY=VALUE` lines)
as a fallback — a real process environment variable always takes
precedence over the file.

### API contract (as implemented)

**IntelOwl:**

1. `POST /api/playbook/analyze_multiple_observables`, header
   `Authorization: Token <token>`, body
   `{"observables": [[<type>, <value>]], "playbook_requested": "WB_Lookup", "tlp": "CLEAR"}`
2. Poll `GET /api/jobs/<id>` until `status` is `reported_without_fails` or
   `reported_with_fails`, or the `--timeout` deadline is reached
3. `--force` adds `"scan_mode": 1` to the submit body — this forces a
   fresh analysis. `scan_mode: 2` (the playbook's own default) reuses a
   previous analysis within its configured `scan_check_time` instead. An
   earlier draft of this contract used a `check_analysis_availability`
   field for this purpose; that field is silently ignored by IntelOwl,
   which is worse than being rejected outright — `--force` would have
   appeared to work while still quietly returning cached results.

**Yeti:**

1. Auth exchange: `POST /api/v2/auth/api-token`, header
   `x-yeti-apikey: <key>`, returning a Bearer token
2. `POST /api/v2/observables/search` with the Bearer token — the response
   has no `entities` key; it does not carry related nodes
3. A **second** call, `POST /api/v2/graph/search`, retrieves related nodes
   for each matched observable. `source` must be collection-prefixed (e.g.
   `"observables/62307"`) — a bare id is rejected.

### Prerequisite: the WB_Lookup playbook

soc-lookup's IntelOwl branch depends on a playbook named `WB_Lookup`
existing on the IntelOwl side. It does not ship with IntelOwl and nothing
in this repo creates it — anyone who loses their IntelOwl data will need
to recreate it manually before `soc-lookup` can return IntelOwl results.

- **Analyzers:** Cymru_Hash_Registry_Get_Observable, Feodo_Tracker,
  MalwareBazaar_Get_Observable, TalosReputation, ThreatFox, URLhaus,
  YARAify_Generics
- **Observable types:** ip, url, domain, generic, hash
- **tlp:** CLEAR
- **scan_mode:** 2
- **weight:** 10

Playbook names are restricted to `[A-Za-z0-9_]` — hyphens are rejected at
validation. A playbook named `WB-Lookup` could therefore never have existed
on a real instance; the name used throughout this repo and by
`soc-lookup --playbook` is `WB_Lookup`.

Creating a playbook via `POST /api/playbook` requires `scan_check_time` in
Django `DurationField` **input** format (`"1 00:00:00"`), even though the
API returns that same value back as `"1:00:00:00"` on a subsequent read.
Submitting the value as read back from a `GET` is rejected — the two
formats are not interchangeable.

```bash
curl -X POST http://127.0.0.1:8082/api/playbook \
  -H "Authorization: Token <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "WB_Lookup",
    "type": ["ip", "url", "domain", "generic", "hash"],
    "analyzers": [
      "Cymru_Hash_Registry_Get_Observable",
      "Feodo_Tracker",
      "MalwareBazaar_Get_Observable",
      "TalosReputation",
      "ThreatFox",
      "URLhaus",
      "YARAify_Generics"
    ],
    "tlp": "CLEAR",
    "scan_mode": 2,
    "scan_check_time": "1 00:00:00",
    "weight": 10
  }'
```

## EVTX toolchain

### Pinned versions (evtx/get-tools.sh)

| Tool | Version | Asset | Purpose |
|------|---------|-------|---------|
| Hayabusa | 4.0.0 | `hayabusa-4.0.0-lin-x64-musl.zip` | EVTX timeline generation (musl build — the gnu build needs glibc >= 2.39, newer than what Ubuntu 22.04 ships) |
| Takajo | 2.16.1 | `takajo-2.16.1-lin-x64-gnu.zip` | Post-processing of Hayabusa JSONL output |
| Chainsaw | 2.16.3 | `chainsaw_x86_64-unknown-linux-gnu.tar.gz` | Sigma-rule hunting over EVTX |
| DuckDB | 1.4.4 | `libduckdb-linux-amd64.zip` | `libduckdb.so`, Takajo's runtime dependency (resolved via `LD_LIBRARY_PATH`, no sudo required) |
| SigmaHQ/sigma | r2026-07-01 | `git clone --depth 1` | Sigma rules consumed by Chainsaw hunt |

Versions live in `evtx/get-tools.sh`'s header as the single place to bump.

### Operational facts

- Hayabusa and Takajo each refuse to run unless their own extraction
  directory is the current working directory — `evtx-triage.sh` `cd`s into
  each tool's `bin/<tool>/` directory before invoking it.
- The Chainsaw tarball has a wrapping directory; `get-tools.sh` strips it
  on extract.
- Hayabusa's and Takajo's binaries are versioned inside their release
  archives (e.g. `hayabusa-4.0.0-lin-x64-musl`); `get-tools.sh` creates
  stable symlinks (`hayabusa`, `takajo`) so `evtx-triage.sh` never encodes
  a version number.
- Footprint after `get-tools.sh` is roughly 268 MB, all under `evtx/bin/`
  and `evtx/rules/` (both gitignored).

### Takajo / Hayabusa 4.x compatibility — confirmed

Takajo 2.16.1 reading Hayabusa 4.0.0 super-verbose JSONL is **confirmed
working**. This was listed as unconfirmed upstream in the original F6
handoff, with a Hayabusa 3.x downgrade held as a fallback plan — the
fallback is not needed. Evidence: the full-corpus acceptance run against
`Yamato-Security/hayabusa-sample-evtx` (599 EVTX files) produced 781
Takajo output files from the Hayabusa 4.0.0 JSONL input, with no
compatibility errors.

### Hayabusa CSV quirks

Anything consuming `001-hayabusa-timeline.csv` will hit these:

- `Level` values are abbreviated: `crit`/`high`/`med`/`low`/`info`
- `Channel` values are abbreviated: `Sec`/`Sys`/`Sysmon`
- `Timestamp` carries the local timezone offset of the machine that ran
  Hayabusa, not UTC
- `Details` / `ExtraFieldInfo` use a broken bar (U+00A6, `¦`) as their
  internal field separator, not a pipe character

See the header cell of `notebooks/timeline-template.ipynb` for the fuller
explanation and the exact parsing approach used for each — not duplicated
here.

## sigma-to-aql.sh

### Python tools (pip, via venv-setup/requirements.txt)

| Tool | pip install | Version | Purpose |
|------|-------------|---------|---------|
| sigma-cli | sigma-cli | 1.0.6 | Sigma rule conversion CLI |
| pysigma-backend-qradar-aql | pysigma-backend-qradar-aql | 0.3.2 | IBM QRadar AQL backend for sigma-cli (resolves pySigma to 0.11.23) |

Pinned in `venv-setup/requirements.txt` (TASK-08) — this section documents
those pins, it does not set them. Do not install the backend with
`sigma plugin install`: the backend comes from the venv, and a
plugin-manager install would pull an incompatible pySigma version and break
reproducibility.

### Conversion target

`sigma-to-aql.sh` calls `sigma convert -t q_radar_aql ...`. This corrects
`handoff-f6-toolkit.md` §5, which gives the target identifier as
`ibm-qradar-aql` — sigma-cli rejects that value outright:

```
Invalid value for '--target' / '-t': 'ibm-qradar-aql' is not 'q_radar_aql'.
```

`ibm-qradar-aql` is the PyPI package name, not the backend id sigma-cli
registers. `sigma list targets` returns exactly one identifier: `q_radar_aql`.

### Pipelines

| Pipeline | Flag | Behavior |
|----------|------|----------|
| qradar-aql-payload | default | Uses named QRadar fields where a mapping exists, and falls back to a raw payload search (`LOWER(UTF8(payload)) LIKE ...`) for anything unmapped |
| qradar-aql-fields | `--fields` | Uses named QRadar fields only; hard-errors on any Sigma field with no mapping |

For a rule whose fields are all mapped the two pipelines emit **identical**
AQL — `Image` and `CommandLine`, for instance, map the same way in both, so
the sample rule converts byte-identically either way. The difference only
appears on an unmapped field: a rule using `Description` converts cleanly
under `qradar-aql-payload` (as a payload search) but fails under
`qradar-aql-fields` with `field 'Description' is not supported`. Payload is
the default because of that failure mode.

### Known limitations

- The pinned sigma-cli 1.0.6 / pySigma 0.11.x toolchain predates newer Sigma
  specification features: no correlation rules, no newer field modifiers.
  Rules under `detection/rules/` must stay in classic single-rule form.
- The IBM QRadar AQL backend is effectively unmaintained — 0.3.2 (2024) is
  the latest release, and it pins `pysigma<0.12`, which is why sigma-cli
  cannot be upgraded past 1.0.6. If it breaks, a community fork is the
  likely replacement path.

### Output

`detection/output/` is not committed — it is already covered by the repo's
generic `output/` gitignore rule; no new entry was needed.

## notebooks

### Python tools (pip, via venv-setup/requirements.txt)

| Tool | pip install | Version | Purpose |
|------|-------------|---------|---------|
| jupyterlab | jupyterlab | 4.6.2 | Notebook runtime |
| pandas | pandas | unpinned | Timeline dataframe loading/filtering |
| matplotlib | matplotlib | unpinned | Fallback histogram visualisation |
| msticpy | msticpy | 3.0.0 | `display_timeline` interactive visualisation |

### msticpy pinned at 3.0.0, not 3.0.2

`msticpy>=3.0.1` requires `packaging>=26.2`, which is mutually exclusive
with pySigma 0.11.x (`packaging<25.0,>=24.1`) — itself required by
`pysigma-backend-qradar-aql==0.3.2`, the pinned QRadar AQL backend (see
[sigma-to-aql.sh](#sigma-to-aqlsh) above). Pinning `msticpy==3.0.2` makes
`venv-setup/requirements.txt` unresolvable — `pip` returns
`ResolutionImpossible`. `msticpy==3.0.0` requires only `packaging>=24.0`
and resolves cleanly alongside the QRadar AQL toolchain. This reasoning
currently lives only as a comment in `venv-setup/requirements.txt`.

### No msticpy config required

The notebook calls `msticpy.vis.timeline.display_timeline` directly rather
than the `df.mp_plot.timeline()` pandas accessor. The accessor needs
`init_notebook()`, which warns about a missing `msticpyconfig.yaml` on
every run. Calling `display_timeline` directly needs no msticpy config at
all.

### Input contract

`notebooks/timeline-template.ipynb` reads `001-hayabusa-timeline.csv` (the
first output of `evtx/evtx-triage.sh`), path overridable via the
`SOC_TIMELINE_CSV` environment variable.

### Known limitation

The notebook's IOC-extraction regex over-matches Windows filenames
(`powershell.exe`, `RPCRT4.dll`) and .NET dotted identifiers
(`System.Diagnostics.Process`) as domains. A denylist of common
executable/library/temp-file extensions filters most of these, but it is a
noise reducer, not a TLD validator — some false positives still slip
through. Review the extracted IOC table before piping it into
`lookup/soc-lookup`.

## pcap-triage.py (planned)

| Library | pip install | Purpose |
|---------|-------------|---------|
| pyshark | pyshark | PCAP parsing via TShark |
| scapy | scapy | Packet manipulation |
| dpkt | dpkt | Fast PCAP parsing |

## windows-events-triage.py (planned)

| Library | pip install | Purpose |
|---------|-------------|---------|
| python-evtx | python-evtx | Parse Windows .evtx files |
| lxml | lxml | XML processing |
