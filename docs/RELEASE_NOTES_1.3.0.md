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

## Licensing note

Optional MSG support uses GPL-licensed `extract-msg`. The default container build excludes that optional dependency; build with `THREADSAW_INSTALL_MSG=1` only after reviewing distribution obligations.
