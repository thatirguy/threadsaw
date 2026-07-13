# Threadsaw 1.3.0 validation plan

## 1. Controlled corpus

Build a non-sensitive corpus with expected results for:

- Text, HTML, multipart/alternative, nested MIME, and attached `message/rfc822` wrappers.
- Duplicate/missing Message-ID, malformed dates, fractional input ranges, and DST boundaries.
- PST-derived repeated and inconsistent Authentication-Results/Received infrastructure.
- Forged or conflicting authentication headers.
- Unicode, bidirectional controls, invisible format controls, newlines, path-like names, and spreadsheet-formula prefixes.
- Inline signature images, duplicate attachment names, zero-byte files, executable signatures, HTML/SVG, modern-loader, macro-enabled, archive, and attached-email formats.
- ZIP central directories with normal, suspicious, encrypted, malformed, and over-limit member metadata.
- QR images and QR-bearing PDFs at multiple sizes, rotations, contrast levels, and page positions.
- Plain, displayed-text, bare `www`, Proofpoint v2/v3, Mimecast, nested, percent-encoded, Base64-like, IP, and SharePoint URL forms.
- Valid, damaged, Unicode-folder, deleted-item, and large PST fixtures.
- Ordinary, signed, embedded-message, and malformed MSG fixtures.

## 2. Correctness comparisons

For each source set:

1. Record count, size, SHA-256, export method, and tool versions.
2. Compare `readpst` output and deleted-item behavior with an independent viewer or controlled reference.
3. Verify wrapper/child message linkage and confirm no inner body or payload is attributed to the wrapper.
4. Compare Threadsaw message hashes, recipients, dates, direction, counts, URL rows, and artifacts with manually verified expectations.
5. Confirm URL duplicates are collapsed and URL count equals stored unique occurrence rows.
6. Confirm inline artifacts remain stored but are excluded from message attachment counts/history.
7. Confirm every parse/processing failure is visible in structured error output.
8. Confirm source files remain unchanged.

## 3. Platform matrix

- Windows 11 with Docker Desktop.
- Windows 11 with WSL2.
- Current macOS on Apple Silicon.
- Intel macOS while support remains required.
- Supported Linux LTS with Docker Engine.

Test path quoting, long/Unicode paths, unexpected colons, bind-mount permissions, host ownership, Docker Desktop filesystem performance, CSV behavior, and manual host-side EML review. Confirm Threadsaw itself never launches a review application.

## 4. Scale and resilience

Benchmark copied representative cases at 50k, 100k, and 200k messages. Measure ingestion, URL indexing, each Heavy history family, complete preset hunts, QR/PDF work, ZIP inventory, peak memory, SQLite size, temporary disk, and Docker Desktop overhead. Capture query plans for indexed historical evaluators and fail acceptance on full-body/full-table per-factor scans.

Also test forced termination, low disk, malformed single-message isolation, output staging cleanup, repeated-run naming, database backup/restore, and Version 1.0 migration on a disposable copy.

## 5. Security review

- Fuzz MIME, URL strings/wrappers, archive metadata, QR images, and filenames.
- Verify traversal and Unicode visual-spoof controls in generated names.
- Verify CSV formula neutralization in expected host spreadsheet tools.
- Verify sockets, DNS, URL retrieval, browser launch, OS launch, and general subprocess APIs are denied.
- Verify only the selected absolute/local `readpst` executable can run, with no shell and stripped proxy/network environment.
- Confirm normal workflows with Docker `network_mode: none` and read-only root.
- Verify QR values, URLs, IPs, and archive names remain inert strings.
- Verify ZIP inventory never calls member read/extract functions and respects all bounds.
- Verify attachments are never executed, mounted, rendered by host applications, or associated with OS handlers.
- Review dependency licenses, vulnerabilities, and container packages.

## 6. Phish Hunt validation

- Exercise all 72 visible factors independently through YES, NO, UNKNOWN, NOT_APPLICABLE, and ERROR where meaningful.
- Verify hidden legacy factors remain compatibility-only and absent from the GUI.
- Reconcile each score with detail-row points and verify uncapped positive/negative integers.
- Reconcile `max_possible_points_evaluated`, `unknown_positive_points`, and `positive_score_percent_evaluated` against factor results.
- Confirm selected unindexed messages are URL-indexed before evaluation.
- Confirm unavailable trusted context removes dependent factors from the effective config and manifest without prompting.
- Confirm context inference uses PST-derived messages only and fails conservatively on weak/inconsistent evidence.
- Validate indexed history query plans and runtime at scale.
- Confirm configuration hashes and evaluator versions reproduce the same result on the same case and selection.
- Confirm start-inclusive/end-exclusive range behavior, required range/scope, and long-range warnings.
- Confirm report-threshold downstream selection rejects mixed/mismatched cases, runs, hashes, and scores.
- Calibrate External, Internal, and General presets against labeled data before making effectiveness claims.

## 7. New feature validation

- Confirm `readpst -D` is opt-in and uses a distinct cache.
- Confirm QR scanning is limited to stored supported images and bounded PDF pages and never contacts values.
- Confirm SharePoint relationship values are reproducible and clearly heuristic.
- Confirm standalone email evaluation installs guardrails and does not modify the real case.
- Confirm re-ingestion is documented and tested for retroactive attached-email and inline-count correction.
