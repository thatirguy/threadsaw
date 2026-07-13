# Contributing to Threadsaw

Thank you for helping improve Threadsaw. Contributions must preserve its offline, static-analysis posture.

## Development setup

1. Create a Python 3.11+ virtual environment.
2. Install `python -m pip install -e '.[msg,dev]'`.
3. Run `PYTHONPATH=src pytest -q`.
4. Run `python -m build` before submitting packaging changes.

## Security invariants

Contributions must not follow URLs, resolve or contact hosts, execute attachments, or invoke arbitrary subprocesses. `readpst` is the only allowlisted child process. New parsing must be bounded and deterministic.

## Pull requests

Keep changes focused, add tests, update documentation and the changelog, and describe compatibility or schema implications. Do not include real client evidence, credentials, malicious binaries, or private mailbox data.
