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

## PCAP Triage Workflow (planned)

[placeholder - to be defined before TASK-06]

## Windows Events Triage Workflow (planned)

[placeholder - to be defined before TASK-07]
