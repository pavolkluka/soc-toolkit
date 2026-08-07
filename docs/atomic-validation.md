# Atomic Red Team Validation Workflow

## Provenance note — read this before anything else

**This workflow has been run end to end, once, against a real lab victim
VM.** Verified on 2026-08-07 against:

- Windows 10 Pro, build 19045 (22H2), hostname `DESKTOP-CRDRE9S`
- Windows PowerShell 5.1
- Reached from the workbench over SSH (OpenSSH for Windows)

The chain that was confirmed working: the shipped Sigma rule
`detection/rules/encoded-powershell-command.yml` (`attack.t1059.001`) →
atomic test `T1059.001-15` → a Sysmon process-creation event → the rule
matching that event. The full worked example is below.

**What this run did *not* cover — do not assume these are equally solid:**

- **No Linux/pwsh victim.** Every path and command below is Windows-only.
  The pwsh/Linux side of Invoke-AtomicRedTeam is untouched and untested in
  this project.
- **The QRadar-AQL branch of the detection-confirmation step was not
  exercised.** No live QRadar instance was available for this run. Only the
  EVTX/Sysmon branch (via `evtx/evtx-triage.sh` and direct Sysmon log
  inspection) was actually confirmed.

This is consistent with the rest of this repo's `docs/` — `methodology.md`,
`tool-deps.md`, and `remnux-notes.md` record facts observed from real runs,
not transcriptions. This document now belongs in that category, but only
for the environment and branch actually exercised. Treat anything outside
that scope (Linux victims, the AQL branch) as still unverified.

## Hard rule

Atomics are **never** run on the workbench host. Lab victim VM only.

## Installing Invoke-AtomicRedTeam on a victim

Windows victim: PowerShell 5+ (verified on 5.1). Linux victim: requires
pwsh (PowerShell Core) — not tested in this project.

### Connectivity precondition

The install needs more than GitHub reachability. Confirm the victim can
reach:

- `github.com` / `raw.githubusercontent.com` (atomics + install script)
- `www.powershellgallery.com` (PowerShell Gallery, for `powershell-yaml`)
- `go.microsoft.com` (NuGet provider bootstrap, needed the first time
  `Install-Module` runs on a fresh box)

On a restricted victim the Gallery/NuGet endpoints can be blocked while
GitHub still works, so `Install-Module` can fail even though the atomics
download fine. On the test VM this was reachable once a NAT interface was
enabled — it is not always blocked, but don't assume it's open just because
GitHub is.

If the Gallery is blocked, `powershell-yaml` can be installed without it:
download the module from its GitHub release
(`github.com/cloudbase/powershell-yaml`) and copy the module folder into a
module path on the victim. Its `lib/net47` directory ships prebuilt DLLs
that Windows PowerShell 5.1 loads directly — no compilation step needed.

### Step 1 — install `powershell-yaml` first

`powershell-yaml` is a required module of Invoke-AtomicRedTeam. The
installer path below (`IEX ... ` + `Install-AtomicRedTeam -getAtomics`)
does **not** install it. Skipping this step fails later with:

```
The required module 'powershell-yaml' is not loaded.
```

```powershell
Install-Module powershell-yaml -Scope CurrentUser -Force
```

### Step 2 — install Invoke-AtomicRedTeam and pull the atomics

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Atomics land in **`C:\AtomicRedTeam`**, not `~/AtomicRedTeam`:

- Atomics: `C:\AtomicRedTeam\atomics`
- Module: `C:\AtomicRedTeam\invoke-atomicredteam`

### Re-running the installer

If `C:\AtomicRedTeam` already exists, `Install-AtomicRedTeam -getAtomics`
prints `Atomic Redteam already exists ... No changes were made` and does
nothing — this matters because a failed first attempt still leaves the
directory behind, and a naive retry looks like it succeeded while changing
nothing. Force a real reinstall with:

```powershell
Install-AtomicRedTeam -getAtomics -Force
```

## Workflow

1. Pick a rule from `detection/rules/` and read its ATT&CK tag. The shipped
   `encoded-powershell-command.yml` carries `attack.t1059.001`.
2. List the atomic test(s) for that technique on the victim — do not assume
   a specific test index number in advance:
   ```powershell
   Invoke-AtomicTest T1059.001 -ShowDetailsBrief
   ```
   Pick the test(s) whose behavior matches what the rule actually detects.
3. `Invoke-AtomicTest <T#> -TestNumbers <N> -ShowDetails`
4. `Invoke-AtomicTest <T#> -TestNumbers <N> -GetPrereqs` — per-test, and
   sometimes mandatory (not every test needs it). Installs whatever the
   test's own prerequisites declare, e.g. a helper PowerShell module.
5. `Invoke-AtomicTest <T#> -TestNumbers <N> -CheckPrereqs` — confirms
   whether step 4 is actually needed for this test; run it before assuming
   prerequisites are met.
6. `Invoke-AtomicTest <T#> -TestNumbers <N>` — run it, on the lab victim VM.
7. Confirm the detection fired.

   Precondition: process-creation `CommandLine` only appears in the log if
   command-line auditing is on (`ProcessCreationIncludeCmdLine_Enabled = 1`
   in Windows audit policy) or Sysmon is capturing it independently.

   Verify Sysmon is actually present by the **event log**, not by service
   name — a Sysmon install can run under a renamed service (a common
   hardening/evasion choice; the test VM used `WinHealthMon`). Check for
   the presence and growth of `Microsoft-Windows-Sysmon/Operational`
   instead of searching for a service literally named `Sysmon`.

   Then either:
   - **(verified branch)** collect the victim's EVTX and run
     `evtx/evtx-triage.sh` against it, then check the `004-chainsaw-hunt/`
     output for the matching Sigma rule — or read the relevant Sysmon
     EventID 1 record directly, or
   - **(not verified in this project)** run the AQL produced by
     `detection/sigma-to-aql.sh` for the same rule against QRadar directly.
     No live QRadar instance was available for the 2026-08-07 run; this
     branch is still a transcription, not a measured result.
8. `Invoke-AtomicTest <T#> -TestNumbers <N> -Cleanup` — **only if the test
   defines a `cleanup_command`.** Not all of them do. Test 15 below has
   none and leaves no persistent artifact (it just spawns short-lived
   processes), so there is nothing to clean up.

## Worked example: T1059.001 / encoded-powershell-command.yml (2026-08-07)

1. Rule: `detection/rules/encoded-powershell-command.yml`, tag
   `attack.t1059.001`.
2. Listed the technique's tests on the victim:
   ```powershell
   Invoke-AtomicTest T1059.001 -ShowDetailsBrief
   ```
   22 tests returned. Test 15, "ATHPowerShellCommandLineParameter
   -EncodedCommand parameter variations," is the one that exercises what
   the rule actually looks for — encoded-command parameter spelling
   variants, not just the canonical `-EncodedCommand` form.
3. Prerequisites:
   ```powershell
   Invoke-AtomicTest T1059.001 -TestNumbers 15 -GetPrereqs
   ```
   Installed the `AtomicTestHarnesses` module (required by tests 15 and
   16).
   ```powershell
   Invoke-AtomicTest T1059.001 -TestNumbers 15 -CheckPrereqs
   ```
   → `Prerequisites met`.
4. Run:
   ```powershell
   Invoke-AtomicTest T1059.001 -TestNumbers 15
   ```
   → `TestSuccess: True`.
5. Detection confirmation (EVTX/Sysmon branch): Sysmon EventID 1 captured
   the resulting process:
   ```
   powershell.exe -NoProfile -E <base64>
   ```
   The rule's `CommandLine|contains` list spans the full valid
   parameter-prefix range (` -e ` through `-encodedcommand`), matching this
   `-E` single-letter form directly — Sigma string matching is
   case-insensitive. This is a real confirmation of the rule's design
   intent: a rule matching only `-enc`/`-EncodedCommand` would have missed
   this atomic entirely, since PowerShell accepts any unambiguous prefix
   and the test used the shortest one.
6. Cleanup: test 15 defines no `cleanup_command` — nothing to run, no
   persistent artifact left behind.

## What's still unverified, and how to extend this

This document is now a tested procedure for one environment and one branch
of the detection-confirmation step — not a fully proven workflow. Known
gaps, restated from the provenance note: no Linux/pwsh victim has been
tried, and the QRadar-AQL branch of step 7 has not been run against a live
QRadar instance.

If you extend this into either of those areas, or if any command above
doesn't behave as documented — a flag that doesn't exist, a path that
differs, an extra prerequisite that's needed — record the deviation in this
document with what was actually observed. Do not silently patch around it
and leave the doc looking more verified than it is. This rewrite exists
because the previous version of this document was itself an unverified
transcription; treat the same discipline as ongoing, not a one-time
cleanup.
