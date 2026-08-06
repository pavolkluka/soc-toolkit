# REMnux Notes

## Pre-installed tools used by soc-toolkit

REMnux includes all tools required by file-triage.sh out of the box.
No additional installation needed beyond venv-setup/setup.sh for Python tools.

## malwoverview configuration

malwoverview is pre-installed on REMnux. API keys must be configured in `~/.malwapi.conf`.

See the malwoverview documentation for config format:
[github.com/alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview)

## Python version limitation (F6 toolkit / venv-setup)

Verified 2026-08-06 on `03-remnux-7-202510` (REMnux 7, Ubuntu 20.04.6 LTS),
reached over SSH from the build container:

- system `python3` is 3.8.10; `python3.9` is also present
- no `python3.10`, `python3.11`, or `python3.12` interpreter is available
- no pyenv, no conda, no deadsnakes PPA configured
- Ubuntu 20.04's own repositories do not carry a `python3.10` package
- internet access from the VM works fine (PyPI and GitHub both reachable)

Consequence: `venv-setup/requirements.txt` requires Python >= 3.10 (both
`msticpy` and `jupyterlab` declare `requires_python >=3.10`), so
`venv-setup/setup.sh` cannot complete on this REMnux VM. Its Python version
guard rejects the run by design, with an actionable error message, rather
than failing partway through the install.

The VM was deliberately **not** modified to work around this (no
pyenv/deadsnakes install, no compiling Python from source).

This limitation affects only the Python-based F6 tooling under
`venv-setup/`. It does not affect `triage/file-triage.sh` or any other
bash-based tooling in `triage/`, which run fine on the pre-installed REMnux
Python 3.8/3.9.

`venv-setup/setup.sh` and `venv-setup/requirements.txt` were therefore
developed and QA'd on the secondary target platform per `CLAUDE.md` §8:
Debian 12, Python 3.11.2.

## Recommended REMnux configuration

[placeholder - to be updated during real-world usage]

## Tool locations on REMnux

[placeholder]
