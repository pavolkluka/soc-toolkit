# Atomic Red Team Validation Workflow

## Provenance note — read this before anything else

**Nothing in this document has been executed or verified in this project.**
No Windows or pwsh victim VM was available during F6. Every command below is
transcribed from `handoff-f6-toolkit.md` §7 and upstream Invoke-AtomicRedTeam
documentation, not measured against a running system.

This is different from the rest of this repo's `docs/` — `methodology.md`,
`tool-deps.md`, and `remnux-notes.md` record facts observed from real runs
(acceptance tests, live API calls, actual `--help` output). This document
does not carry that same authority. Treat every command here as unverified
until someone actually runs it against a lab victim VM.

## Hard rule

Atomics are **never** run on the workbench host. Lab victim VM only.

## Installing Invoke-AtomicRedTeam on a victim

Windows victim: PowerShell 5+. Linux victim: requires pwsh (PowerShell Core).

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Atomics land in `~/AtomicRedTeam` by default. Per-test prerequisites are
fetched separately, per technique:

```powershell
Invoke-AtomicTest <T#> -GetPrereqs
```

## Workflow

1. Pick a rule from `detection/rules/` and read its ATT&CK tag. The shipped
   `encoded-powershell-command.yml` carries `attack.t1059.001`.
2. Find the atomic test(s) for that technique under the victim's
   `~/AtomicRedTeam/atomics/<T#>/` directory. Do not assume a specific test
   index number in advance — list what's actually available for the
   technique on the victim and choose from there.
3. `Invoke-AtomicTest <T#> -ShowDetails`
4. `Invoke-AtomicTest <T#> -CheckPrereqs`
5. `Invoke-AtomicTest <T#>` — run it, on the lab victim VM.
6. Confirm the detection fired. Either:
   - collect the victim's EVTX and run `evtx/evtx-triage.sh` against it,
     then check the `004-chainsaw-hunt/` output for the matching Sigma
     rule, or
   - run the AQL produced by `detection/sigma-to-aql.sh` for the same rule
     against QRadar directly.
7. `Invoke-AtomicTest <T#> -Cleanup`

## Before treating this as a checklist

The first real use of this workflow should treat every command above as a
draft to verify, not a tested procedure. If a command doesn't behave as
described here — a flag that doesn't exist, a path that differs, an extra
prerequisite that's needed — record the deviation in this document. Do not
silently patch around it and leave the doc looking more confirmed than it
is.
