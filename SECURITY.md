# Security Policy

## Supported versions

Security fixes are provided for the latest published minor release.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability involving evidence exposure, path traversal, command execution, network access, parser denial of service, or container escape. Use GitHub's private vulnerability reporting feature when enabled, or contact the repository owner privately.

Include the affected version, reproduction steps using synthetic evidence, impact, and suggested remediation. Do not attach real emails or malicious payloads.

## Security model

Threadsaw is designed for static, offline analysis. Docker/Podman isolation is the primary boundary; Python runtime guardrails are defense in depth. See `docs/SECURITY_AND_FORENSICS.md`.
