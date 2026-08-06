# REMnux Notes

## Pre-installed tools used by soc-toolkit

REMnux includes all tools required by file-triage.sh out of the box.
No additional installation needed beyond venv-setup/setup.sh for Python tools.

## malwoverview configuration

malwoverview is pre-installed on REMnux. API keys must be configured in `~/.malwapi.conf`.

See the malwoverview documentation for config format:
[github.com/alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview)

## Python version requirement (F6 toolkit / venv-setup)

`venv-setup/requirements.txt` requires Python >= 3.10 (both `msticpy` and
`jupyterlab` declare `requires_python >=3.10`). `venv-setup/setup.sh`
enforces this with a version guard before proceeding. The deciding factor
is the Python version available on the host, not REMnux as such — REMnux
releases differ in which Python they ship, as the two cases below show.

### Primary REMnux (2026) — supported

Verified 2026-08-06 on `03-remnux-noble-202602` (REMnux v2026.26.13, Ubuntu
24.04.3 LTS), reached over SSH:

- system Python is 3.12.3; `venv` and `ensurepip` are present, and
  `python3-venv` is installed
- a PEP 668 `EXTERNALLY-MANAGED` marker exists on this system's Python, but
  it caused no problems for venv-based installs (explicitly checked: no
  `externally-managed-environment` error anywhere in the logs)
- PyPI and GitHub are reachable from the VM

Full TASK-08 QA gate re-run on this VM — **PASS**:

- fresh venv + `pip install -r requirements.txt` completes, exit 0
- `pip check` reports "No broken requirements found."
- resolved package versions are identical to the Debian 12 / Python 3.11.2
  baseline: `msticpy==3.0.0`, `jupyterlab==4.6.2`, `sigma-cli==1.0.6`,
  `pySigma==0.11.23`, `pySigma-backend-QRadar-AQL==0.3.2`, `packaging==24.2`
- `from msticpy.vis.timeline import display_timeline` imports OK (the
  TASK-12 dependency)
- `--check-only` exits 0, reports correctly, and does not mutate the venv
  (verified with a canary file and `pyvenv.cfg` mtime)
- missing-package regression case behaves correctly (warns, continues,
  exits 0)
- idempotent: a second run updates the venv in place rather than recreating
  it
- resulting venv size: 762M

The scratch directory used for this QA run was removed afterwards; the VM
was left exactly as found.

### Older REMnux 7 — not supported

Verified 2026-08-06 on `03-remnux-7-202510` (REMnux 7, Ubuntu 20.04.6 LTS),
reached over SSH from the build container:

- system `python3` is 3.8.10; `python3.9` is also present
- no `python3.10`, `python3.11`, or `python3.12` interpreter is available
- no pyenv, no conda, no deadsnakes PPA configured
- Ubuntu 20.04's own repositories do not carry a `python3.10` package
- internet access from the VM works fine (PyPI and GitHub both reachable)

Consequence: `venv-setup/setup.sh` cannot complete on this REMnux VM. Its
Python version guard rejects the run by design, with an actionable error
message, rather than failing partway through the install. The VM was
deliberately **not** modified to work around this (no pyenv/deadsnakes
install, no compiling Python from source).

### Guard verified in both directions

`setup.sh`'s `Python >= 3.10` guard has now been live-tested on both ends:
it correctly refuses to run on REMnux 7 (Python 3.8.10, no venv created),
and correctly proceeds on the primary REMnux 2026 target (Python 3.12.3,
full QA gate pass above).

This requirement affects only the Python-based F6 tooling under
`venv-setup/`. It does not affect `triage/file-triage.sh` or any other
bash-based tooling in `triage/`, which runs fine regardless of which Python
REMnux ships.

`venv-setup/setup.sh` and `venv-setup/requirements.txt` were originally
developed and QA'd on the secondary target platform per `CLAUDE.md` §8
(Debian 12, Python 3.11.2). The QA gate has since been re-run and passed on
the primary REMnux target (Ubuntu 24.04.3, Python 3.12.3) as documented
above.

## Recommended REMnux configuration

[placeholder - to be updated during real-world usage]

## Tool locations on REMnux

[placeholder]
