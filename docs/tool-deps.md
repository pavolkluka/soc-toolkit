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
