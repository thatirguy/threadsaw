# Threadsaw 1.3.0 Release Notes

## Large-case readiness

- Core message and attachment CSV reports are generated from bounded iterators rather than full-case lists.
- `--large-case` writes JSON Lines and avoids monolithic JSON arrays.
- Phish Hunt writes score and detail records incrementally while committing database results in checkpoints.
- PST-derived EML parse failures are isolated and recorded without stopping the remaining indexing pass.
- PST disk-space preflight defaults to a conservative five-times-file-size estimate.
- Incomplete `readpst` output is preserved; partial EMLs are indexed after a failed extraction before the failure is reported.

## Evaluate Phishing Email

Every run now includes `evaluation_hits.txt`, a human-readable report listing factors that returned YES, score contribution, explanation, evidence, source, and unavailable factors.

## Publication readiness

Added cross-platform Getting Started guides, GitHub issue/PR templates, CI and CodeQL workflows, contribution/security/support policies, release checklist, citation metadata, direct dependency pins, third-party licensing guidance, and a CycloneDX SBOM.

The `v1.3.0` tag publishes an attested multi-architecture default image to `ghcr.io/thatirguy/threadsaw` and attaches the wheel, source distribution, source SBOM, and SHA-256 checksums to the GitHub Release. PyPI publication is intentionally deferred; the GitHub wheel is provided for advanced native CLI installations.

## Correctness and documentation follow-up

- Fixed Windows CI portability while preserving the Windows, macOS, and Linux test matrix.
- Updated OpenCV and pypdfium2 pins and synchronized the source SBOM.
- Tightened Microsoft Safe Links recognition to the exact hostname or a dot-delimited subdomain, preventing deceptive suffix hosts from being misclassified.
- Added six practical investigation recipes with matching GUI modules and CLI commands.
- Configured security-first Dependabot grouping with monthly routine updates.

## Validation

The final suite contains 75 tests. Hosted CI passes on Windows, macOS, and Linux for Python 3.11 and 3.13, the container smoke test passes, and CodeQL reports no open finding for the corrected URL-wrapper match.

## Licensing note

Optional MSG support uses GPL-licensed `extract-msg`. The default container build excludes that optional dependency; build with `THREADSAW_INSTALL_MSG=1` only after reviewing distribution obligations.
