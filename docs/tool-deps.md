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
