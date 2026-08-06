# SOC Triage Methodology

## File Triage Workflow

1. **Identify** — determine file type using multiple methods (diec, trid, file command)
2. **Hash** — compute MD5, SHA1, SHA256 for identification and threat intel lookups
3. **Metadata** — extract with ExifTool (author, timestamps, embedded objects)
4. **Strings** — extract printable strings for IOC identification
5. **Threat Intel** — lookup hashes via malwoverview:
   - VirusTotal (detection ratio, AV labels)
   - Tria.ge (sandbox reports, dynamic analysis)
   - AlienVault OTX (threat context, related indicators)
   - Malware Bazaar (sample metadata, tags)
6. **PE Analysis** — PortEx analyzer for PE files (sections, imports, anomalies)
7. **Deep Analysis** — format-specific analysis:
   - PDF: pdfid.py, peepdf (suspicious elements, JavaScript, embedded objects)
   - Office/OLE: oledump.py, oleobj (macros, embedded objects, streams)
8. **Output** — all results organized in numbered files under `output/`

## Output Directory Structure

```
output/
├── 001-hashes.txt
├── 002-file-type.txt
├── 003-exiftool.txt
├── 004-strings.txt
├── 005-malw-virustotal.txt
├── 006-malw-triage.txt
├── 007-malw-triage-<id>.txt          # per-sample Tria.ge reports
├── 008-malw-triage-<id>-dynamic.txt  # dynamic analysis reports
├── 009-malw-alienvault.txt
├── 010-malw-alienvault-bazaar.txt
├── 011-portex.txt
└── [format-specific]
    ├── 012-oledump.txt         # Office files
    ├── 013-oleobj.txt          # Office embedded objects
    ├── 014-pdf-pdfid.txt       # PDF files
    └── 015-pdf-peepdf.txt      # PDF files
```

## EVTX Triage Workflow

1. **Install toolchain** — run `evtx/get-tools.sh` once. Downloads the
   pinned Hayabusa, Takajo, Chainsaw, and DuckDB binaries and clones the
   SigmaHQ/sigma rules (see [Tool Dependencies](tool-deps.md))
2. **Triage** — `evtx/evtx-triage.sh -i <evtx_dir>` runs Hayabusa (CSV +
   JSONL timelines), Takajo (`automagic`), and Chainsaw (Sigma hunt) over a
   directory of `.evtx` files, writing one timestamped run directory
3. **Timeline** — load `001-hayabusa-timeline.csv` into
   `notebooks/timeline-template.ipynb` for interactive review; the notebook
   writes its markdown summary back into the same run directory, continuing
   the run's numbering as the next output

### Output Directory Structure

```
output_<evtx_dir_name>_<timestamp>/
├── 001-hayabusa-timeline.csv        # Hayabusa dfir-timeline, CSV — input for the notebook
├── 001-hayabusa-timeline.log
├── 002-hayabusa-timeline.jsonl      # Hayabusa dfir-timeline, JSONL super-verbose — input for Takajo
├── 002-hayabusa-timeline.log
├── 003-takajo-automagic/            # Takajo automagic output
├── 003-takajo-automagic.log
├── 004-chainsaw-hunt/               # Chainsaw Sigma hunt, per-group CSV
├── 004-chainsaw-hunt.log
└── 005-timeline-summary.md          # written by the notebook, continuing the run's numbering
```

## IOC Lookup Workflow

1. **Identify an observable** — from EVTX triage output (Hayabusa/Chainsaw
   findings) or from the notebook's IOC-extraction cell
2. **Look it up** — `lookup/soc-lookup <observable>` queries Yeti and
   IntelOwl in parallel
3. **Read the result** — Yeti context (tags, related nodes found via a
   graph search) and IntelOwl per-analyzer verdicts, each carrying a
   `source_ref` (`yeti:observable/<id>`, `yeti:entity/<id>`,
   `intelowl:job/<id>`)
4. **Write to IRIS** — the `source_ref` attached to each finding is what
   makes it traceable back to its source once it's written into IRIS

Prerequisite: the `WB_Lookup` playbook must exist on the IntelOwl side
before `soc-lookup` can return IntelOwl results — see
[Tool Dependencies: soc-lookup](tool-deps.md#soc-lookup).

## PCAP Triage Workflow (planned)

[placeholder - to be defined before TASK-06]

## Windows Events Triage Workflow (planned)

[placeholder - to be defined before TASK-07]
