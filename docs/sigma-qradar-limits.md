# Sigma → QRadar AQL: what converts, what does not (lab measurements)

Measured 2026-11-05 with the pinned toolchain (sigma-cli 1.0.6, pySigma
0.11.23, pySigma-backend-QRadar-AQL 0.3.2, pyparsing 3.3.0) over SigmaHQ
`rules/windows` at commit `b510129`, and against QRadar CE lab exports
(72 offense exports of the `soc-agent-evals` dataset). Nothing here has run
on the lab QRadar yet; the AQL run is the next step. Tooling:
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
  `INCIDR('10.0.0.0/8', destinationip)`. The AQL is valid, the lab run has to
  confirm `INCIDR` on `sourceip`/`destinationip` behaves as expected.
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
  is untested [VERIFY in lab].

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

## 4. Five rules prepared for the lab run

| # | rule | pipeline | expected lab hit | conversion |
|---|---|---|---|---|
| 1 | `detection/rules/encoded-powershell-command.yml` | payload = fields | encoded PowerShell samples (EID 1 + 4688) | OK |
| 2 | SigmaHQ `proc_creation_win_powershell_invoke_webrequest_download.yml` (T1105) | payload = fields | ingress tool transfer run, if it happened | OK |
| 3 | SigmaHQ `win_security_user_creation.yml` (4720, T1136.001) | payload = fields | new local account sample | OK |
| 4 | SigmaHQ `win_security_susp_failed_logon_reasons.yml` (4625/4776 + Status) | payload | brute-force sample (non-existent accounts) | OK (needs pyparsing < 3.3.3) |
| 5 | SigmaHQ `dns_query_win_common_malware_hosting_services.yml` (EID 22) | fields + `qradar-lab.yml` | none expected (negative test) | OK → `SysmonQueryName` |

Run each in Log Activity (AQL) over the August 2026 lab window, record the
row count and whether the positive samples are among the rows. A syntax
error is a finding and goes into this file.

## 5. Reading the numbers

- A conversion success says the backend produced AQL, not that the AQL is
  right for a given QRadar: property names come from the DSM in use, custom
  event properties are per-deployment. Section 3 is the lab's truth, a
  customer QRadar needs its own table.
- Sigma rules written for Sysmon field names convert fine, but the lab's
  Sysmon config is an allowlist (mostly PowerShell); a rule that converts and
  returns nothing may be blind by collection policy, not wrong.
