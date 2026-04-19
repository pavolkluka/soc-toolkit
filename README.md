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

### pcap-triage.py *(coming soon)*

PCAP analysis: protocol dissection, IOC extraction, C2 communication detection,
DNS/HTTP/TLS summary. Pairs with my network traffic analysis articles on Medium.

### windows-events-triage.py *(coming soon)*

Windows Event Log (`.evtx`) analysis: suspicious logon events, process creation,
privilege escalation indicators, lateral movement artifacts.

---

## Setup

```bash
git clone https://github.com/pavolkluka/soc-toolkit
cd soc-toolkit

# Check dependencies (bash scripts)
./triage/common/requirements-check.sh --check-only

# Setup Python venv (for Python tools)
./venv-setup/setup.sh
```

---

## Documentation

- [Triage Methodology](docs/methodology.md)
- [Tool Dependencies](docs/tool-deps.md)
- [REMnux Notes](docs/remnux-notes.md)

---

## Related

- [medium-articles-code](https://github.com/pavolkluka/medium-articles-code) — sample-specific scripts from my Medium articles
- [Medium articles](https://medium.com/@pavol.kluka) — analysis walkthroughs

---

## Support

If my work helped you: [Lightning tip via Hydranode](https://hydranode.org/btcpay/apps/3eaaJ6N3NvEDSvkhWfLGR3Zxf1GN/pos)
