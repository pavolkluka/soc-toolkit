# Sigma → QRadar AQL: what converts, what does not (lab measurements)

Measured 2026-11-05 with the pinned toolchain (sigma-cli 1.0.6, pySigma
0.11.23, pySigma-backend-QRadar-AQL 0.3.2, pyparsing 3.3.0) over SigmaHQ
`rules/windows` at commit `b510129`, and against QRadar CE lab exports
(72 offense exports of the `soc-agent-evals` dataset). §4 is the run of the
converted queries on the lab QRadar (2026-11-07). Tooling:
[tool-deps.md](tool-deps.md#sigma-to-aqlsh).

## 1. Conversion rate by rule directory

| directory | rules | payload pipeline | fields pipeline | why the rest fails |
|---|---|---|---|---|
| process_creation | 1193 | 1187 | 1088 | fields: unmapped field (105); payload: `null` value on an unmapped field (6) |
| network_connection | 51 | 27 → **50 with CIDR workaround** | 26 | `|cidr` crash in the backend (23); boolean `Initiated` on payload (1) |
| dns_query | 23 | 23 | 3 | `QueryName` unmapped (20) → payload search |
| builtin/security | 146 | 135 | 60 | unmapped `IpAddress`, `SubStatus`, `SubjectUserName`, … (86); CIDR (3); `null` (3) |

With pyparsing 3.3.3 — what a fresh `pip install` picked before the pin —
the payload numbers were 888 / 17 / 17 / 96: every rule with `not` in its
condition failed inside pySigma ([tool-deps.md](tool-deps.md#pyparsing-upper-bound-added-2026-11-05)).

## 2. Backend limits that remain after the fixes

- **Unmapped Sigma fields.** The backend knows 104 Sigma field names. Anything
  else is refused by the fields pipeline and degraded to
  `LOWER(UTF8(payload)) LIKE '%value%'` by the payload pipeline: a full
  payload scan that matches the value anywhere in the event. Relevant gaps for
  Windows telemetry: `IpAddress` (4624/4625 source), `SubStatus` (4625
  reason), `SubjectUserName`, `QueryName` (Sysmon EID 22), `Protocol`,
  `Channel`, `Provider_Name`. Serve them with a mapping file
  (`detection/pipelines/qradar-lab.yml`) where the target QRadar has a
  property.
- **CIDR values** crash backend 0.3.2; the engine works around it and emits
  `INCIDR('10.0.0.0/8', destinationip)`. The AQL is valid; `INCIDR` on `sourceip`
  was confirmed in the lab run (§4, rule 6).
- **No correlation rules, no aggregation.** pySigma 0.11 predates Sigma
  correlation rules. "N failed logons from one source in M minutes" (brute
  force), beaconing and volume-based exfiltration cannot be expressed; the
  Sigma rule can only select the per-event condition (4625 + reason), the
  threshold lives in the QRadar CRE rule. Rules under `detection/rules/` stay
  single-rule form.
- **Every query starts with `devicetype=12`** (`WindowsAuthServer`, the
  Microsoft Windows Security Event Log DSM). Sysmon collected through
  WinCollect arrives under the same log source type, so the filter holds for
  Sysmon and Security channels alike. Linux auditd rules are outside this
  backend's reach (product `linux` has no device type in its table).
- **Numeric values on unmapped fields** become `field%value` payload
  patterns with a warning — partial matches are possible.
- **`Initiated='true'`** (Sysmon EID 3) is emitted as a named property; the
  lab exports do not show it as a parsed property, so it may be empty on
  QRadar [VERIFY in lab].
- **`LOWER(sourceip) LIKE '%-%'`** appears when a rule compares `IpAddress`
  with a string pattern; whether AQL accepts `LOWER()` on an IP-typed column
  is accepted by the lab QRadar (§4, rule 6).

## 3. What the lab QRadar actually populates (from exports)

The backend targets QRadar's normalized Windows properties. Counted over
`customProps` of the dataset exports (values `N/A` and `-` excluded):

| event (QID) | n | populated | missing |
|---|---|---|---|
| Sysmon EID 1 process create (5001828) | 138 | Command, Process Path, Process Name, Parent Command, Parent Process Path/Name (135), Event ID | — |
| Sysmon EID 3 network connection (5001840) | 445 | Process Path, Process Name, Event ID; `destinationip`/`destinationport` native | Destination Hostname, Command |
| Sysmon EID 22 DNS query (5002343) | 121 | Event ID | QueryName — only in the custom property `SysmonQueryName` |
| Security 4688 process creation (5000862) | 73 | Command, Process Path/Name, Parent Process Path/Name, Event ID; Target Username (30) | — |
| Security 4625 failed logon (5000475) | 380 | Event ID, Logon Type, Target Username, Account Name; `sourceip` native | IpAddress not mapped by the backend; SubStatus only in payload |
| Security 4624 logon (5000830) | 41 | Event ID, Logon Type, Target Username, Process Name (35) | — |

Consequence: **process_creation rules (Sysmon EID 1 and 4688) should match
in the lab without any mapping** — the properties the backend emits are the
ones the DSM fills. DNS and failed-logon rules need `qradar-lab.yml`.

## 4. Lab run (2026-11-07)

The first attempt ran the queries over August 2026; the lab QRadar no longer
holds events from that period (an unfiltered `COUNT(*)` for 2026-08-25 returned
nothing), so every query came back empty. The second run produced one positive
case per rule on `DESKTOP-CRDRE9S` between 21:07 and 21:13 UTC on 2026-11-07
and ran each query with `LAST 2 HOURS`.

| # | rule | pipeline | lab case | rows | matched events |
|---|---|---|---|---|---|
| 1 | `detection/rules/encoded-powershell-command.yml` | payload = fields | `powershell.exe -NoProfile -EncodedCommand …` | 2 | Sysmon EID 1 + Security 4688 of the same process |
| 2 | SigmaHQ `proc_creation_win_powershell_invoke_webrequest_download.yml` | payload = fields | `Invoke-WebRequest -Uri … -OutFile '%TEMP%\…'` | 2 | Sysmon EID 1 + 4688 |
| 3 | SigmaHQ `win_security_user_creation.yml` (4720) | payload = fields | `New-LocalUser lab-s4-test` | 1 | 4720 |
| 4 | SigmaHQ `win_security_susp_failed_logon_reasons.yml` | payload | logon to a disabled local account, 2× | 4 | 2× 4625 (Sub Status `0xC0000072`) + 2× 4776 (Error Code `0xC0000072`) |
| 5 | SigmaHQ `dns_query_win_common_malware_hosting_services.yml` (EID 22) | fields + `qradar-lab.yml` | `Resolve-DnsName tinyurl.com` | 1 | Sysmon EID 22 via `SysmonQueryName` |
| 6 | SigmaHQ `win_security_susp_failed_logon_source.yml` (4625, non-private source) | fields + `qradar-lab.yml` (`IpAddress → sourceip`, CIDR workaround) | none possible, the lab has no public source | 0 | control query without the `NOT` returned both 4625 events |

All six queries ran without an AQL error, including `INCIDR(...)` and
`LOWER(sourceip) LIKE '%-%'` on `sourceip`, which §2 had left open.

What the run showed:

- **Every process rule matches twice.** `devicetype=12` covers Sysmon and the
  Security channel, and the DSM fills `Command` / `Process Path` for both
  Sysmon EID 1 and 4688. One process start gives two rows, and a CRE rule built
  on the same test fires twice. Restrict by QID (5001828 or 5000862) if one source
  is enough.
- **Properties the backend emits but the lab does not have do not fail the
  query.** `Status` (rule 4) and `Filename` (rule 2) are not among the lab's
  custom properties; the queries ran anyway and returned the same rows as
  variants without those conditions. The matches came from the payload branch
  (rule 4) and from `Process Path` (rule 2). A missing property is therefore
  silent: the condition never matches, and nothing in the result says so.
- **`Status` is in the lab under the name `Error Code`.** For 4776 it holds the
  failure reason (`0xC0000072`). For 4625 it holds the Status (`0xC000006E`)
  and the Sub Status is only in the payload. A `Status → Error Code` mapping
  would help 4776, not 4625.
- **WinCollect writes SIDs as names** (`Security ID: \NULL SID`, not
  `S-1-0-0`). Rule 4's exclusion `SubjectUserSid: S-1-0-0` becomes
  `NOT payload LIKE '%s-1-0-0%'` and never excludes anything in this lab.
- **`Process Name` is the bare file name** (`powershell.exe`). The backend's
  `LIKE '%\powershell.exe'` branch on it can never match. `Process Path` carries
  the match.
- **`sourceip` of a local 4625 is the host's address, not `IpAddress`.** The
  payload says `Source Network Address: ::1`, `sourceip` is `172.16.56.100`.
  For local logons the `IpAddress → sourceip` mapping is not the same field.
  For network logons [VERIFY in lab].
- **Sigma `%VAR%` patterns become LIKE wildcards.** `'%temp%'` in rule 2 is
  emitted as `LIKE '%%temp%%'`, which matches any command line containing
  `temp`. The lab case matched through this branch (the command line held the
  literal `%TEMP%`), not through `\temp\`.
- **The generated AQL has no time clause.** A query run by hand needs
  `LAST …` or `START … STOP …`; the default window without one was not
  measured [VERIFY].

## 5. Reading the numbers

- A conversion success says the backend produced AQL, not that the AQL is
  right for a given QRadar: property names come from the DSM in use, custom
  event properties are per-deployment. Section 3 is the lab's truth, a
  customer QRadar needs its own table.
- Sigma rules written for Sysmon field names convert fine, but the lab's
  Sysmon config is an allowlist (mostly PowerShell); a rule that converts and
  returns nothing may be blind by collection policy, not wrong.
