# Threadsaw 1.3.0 testing and validation

## Automated suite

Run from the project root:

```bash
PYTHONPATH=src pytest -q
```

The 1.3.0 suite covers:

- Runtime denial of sockets, DNS, URL retrieval, browser/OS launch, and unapproved subprocesses.
- Explicit-path and allowlisted invocation of `readpst`.
- EML, PST, optional MSG, nested MIME, and terminal `message/rfc822` handling.
- Child-message linkage and correct body/attachment attribution.
- Source hashing, attachment persistence, inline-image counting, safe filenames, and report/export behavior.
- SQLite initialization, Version 1.0 migration, URL duplicate cleanup, indexes, rollback journaling, and health checks.
- URL extraction, bare `www` capture, Proofpoint/Mimecast decoding, offline PSL handling, SharePoint relationship, and auto-indexing before scoring.
- Conservative PST-derived trusted context with a 20-message minimum, exact-host/domain-suffix Received fallback, and automatic removal of unavailable factors.
- Hash/CSV/range/scope/all/report-threshold selection and UTC whole-second date behavior.
- Completion-timestamped output isolation and collision avoidance.
- QR decoding from stored images/PDF pages through pypdfium2 and bounded ZIP central-directory inventory, including encrypted-member scoring.
- String Search across SQLite, exported review text, and reports.
- Evaluate Phishing Email for case, matching external, standalone, and history-override modes.
- Direction classification with analyst-declared organization domains, subject-drift thread-hijack matching, Version 1.1/1.2 factors, lookalike guards, score coverage, all 72 visible evaluator mappings, and starter presets.
- GUI module navigation, two-row controls, help/load behavior, command construction, and ambiguous mount-path validation.

## What passing tests establishes

Passing tests establishes only that covered paths behaved as expected in the test environment. It does not establish complete compatibility with every PST/MSG producer, complete resistance to adversarial MIME, malware-detection capability, legal admissibility, preset accuracy, independent security assurance, or enterprise-scale performance.

## Recommended acceptance testing

Before operational use, validate against representative organizational evidence:

1. Known-good and known-bad EML fixtures with expected headers, body attribution, URLs, QR images, and attachments.
2. PSTs from every expected Outlook/Exchange export workflow, with and without deleted-item extraction.
3. Attached-email and nested MIME samples where wrapper/child attribution is manually verified.
4. MSG files from expected Outlook versions when MSG is in scope.
5. PST corpora with expected authentication-service and Received-boundary consensus, plus corpora where inference must fail safely.
6. URL-rewriting environments for decoder and displayed-target calibration.
7. SharePoint tenants and organization domains for heuristic relationship review.
8. ZIP files with encrypted flags, suspicious member names, large member counts, and malformed central directories.
9. QR codes in common image formats and on early/late PDF pages, including unreadable controls.
10. Representative 50,000–200,000-message performance and disk-capacity tests.
11. Repeated-run isolation, forced interruption, schema migration on a copied case, and recovery behavior.
12. Independent parser or manual comparison for a statistically meaningful sample.

## Reproducibility records

Retain the Threadsaw version and artifact hash, container image digest when used, source hashes, pre-migration case backup, `case.json`, SQLite, run manifests, requested/effective Phish Hunt configurations and hashes, report/export manifests, and any organizational validation records.
