# soc-toolkit

A collection of triage and analysis scripts for SOC analysts and DFIR practitioners.

**Primary environment:** REMnux | **Also works on:** Debian/Ubuntu-based Linux

---

## Tools

### file-triage.sh

Automated file triage: hashing, metadata extraction, threat intelligence lookups
(via malwoverview), and format-specific analysis (Office documents, PDFs).
Results are saved to a structured `output/` directory.

**Requirements:** REMnux (all deps pre-installed) or see [docs/tool-deps.md](docs/tool-deps.md)

```bash
./triage/file-triage.sh -i suspicious_file.docx
```

### soc-lookup

Combined IntelOwl + Yeti IOC lookup in one command. Autodetects the
observable type (ip/domain/hash/url, falling back to generic), queries both
sources in parallel, and aggregates the result with a `source_ref` per
source (`yeti:observable/<id>`, `yeti:entity/<id>`, `intelowl:job/<id>`) for
traceability into IRIS.

**Requirements:** `venv-setup/setup.sh` run first; IntelOwl and Yeti
reachable and configured — see
[docs/tool-deps.md](docs/tool-deps.md#soc-lookup)

```bash
./lookup/soc-lookup 8.8.8.8
./lookup/soc-lookup <sha256_hash> --json | jq
```

### evtx-triage.sh

Hayabusa + Takajo + Chainsaw EVTX triage in one command: a Hayabusa
`dfir-timeline` CSV timeline (for the timeline notebook), a Hayabusa
super-verbose JSONL timeline (for Takajo), a Takajo `automagic` run, and a
Chainsaw Sigma hunt — all written into one timestamped run directory.

**Requirements:** run `evtx/get-tools.sh` once first, to download the
pinned binaries and Sigma rules — see [docs/tool-deps.md](docs/tool-deps.md)

```bash
./evtx/get-tools.sh
./evtx/evtx-triage.sh -i /path/to/evtx_dir
```

### sigma-to-aql.sh

Converts one Sigma rule, or every rule in a directory, to IBM QRadar AQL for
copy-paste into the QRadar console.

**Requirements:** `venv-setup/setup.sh` run first (installs sigma-cli +
pysigma-backend-qradar-aql) — see
[docs/tool-deps.md](docs/tool-deps.md#sigma-to-aqlsh)

```bash
./detection/sigma-to-aql.sh detection/rules/encoded-powershell-command.yml
```

### timeline-template.ipynb

Jupyter notebook for interactive review of a Hayabusa `dfir-timeline` CSV —
overview counts, parametric filters, msticpy/matplotlib visualisation, IOC
extraction, and a markdown summary export. A lightweight Timesketch
replacement for the common case.

**Requirements:** `venv-setup/setup.sh` run first; input is
`001-hayabusa-timeline.csv` from `evtx/evtx-triage.sh`

```bash
source venv-setup/venv/bin/activate
jupyter lab notebooks/timeline-template.ipynb
```

### pcap-triage.py *(coming soon)*

PCAP analysis: protocol dissection, IOC extraction, C2 communication detection,
DNS/HTTP/TLS summary. Pairs with my network traffic analysis articles on Medium.

### windows-events-triage.py *(coming soon)*

Windows Event Log (`.evtx`) analysis: suspicious logon events, process creation,
privilege escalation indicators, lateral movement artifacts. A native Python
parser (`python-evtx`) focused on those specific event categories, distinct
from [`evtx/evtx-triage.sh`](#evtx-triagesh)'s external-binary-based broad
detection coverage — for EVTX analysis today, use `evtx/evtx-triage.sh`.

---

## Setup

```bash
git clone https://github.com/pavolkluka/soc-toolkit
cd soc-toolkit

# Check dependencies (bash scripts)
./triage/common/requirements-check.sh --check-only

# Setup Python venv (for Python tools)
./venv-setup/setup.sh

# Download EVTX toolchain binaries + Sigma rules (one-time, ~270 MB into
# gitignored directories — only needed for evtx-triage.sh)
./evtx/get-tools.sh
```

---

## Documentation

- [Triage Methodology](docs/methodology.md)
- [Tool Dependencies](docs/tool-deps.md)
- [REMnux Notes](docs/remnux-notes.md)
- [Atomic Validation Workflow](docs/atomic-validation.md)

---

## Related

- [medium-articles-code](https://github.com/pavolkluka/medium-articles-code) — sample-specific scripts from my Medium articles
- [Medium articles](https://medium.com/@pavol.kluka) — analysis walkthroughs

---

## Support

If you want to support me, you can do so in satoshi. Use the Lightning Network.

<a href="https://hydranode.org/btcpay/apps/3eaaJ6N3NvEDSvkhWfLGR3Zxf1GN/pos" target="_blank" rel="noopener noreferrer">
  <img src="images/hydranode_donation_button_black.png" alt="Pay with Hydranode">
</a>
