## 1.2.0 - PDFium migration, robust case context, and encrypted ZIP scoring

- Replaced PyMuPDF with `pypdfium2`/PDFium for bounded offline PDF rendering in Evaluate QRs.
- Added a hard minimum of 20 PST-derived messages before trusted authserver or Received-boundary inference is permitted.
- Added a second-tier Received-boundary fallback that selects the most specific stable domain suffix meeting the same 40% corpus-consensus threshold when exact frontend hosts rotate.
- Added analyst-declared organization domains for EML/MSG-only and PST cases through `--organization-domain`, `threadsaw case-config`, and the GUI.
- Relaxed the changed-thread-infrastructure evaluator to require exact Message-ID reference plus participant overlap without requiring identical normalized subjects.
- Added `attachment_encrypted_zip`, backed by bounded ZIP central-directory encryption flags, with External/General weight 25 and Internal weight 20.
- Added automatic ZIP-family inventory for enabled archive-dependent Phish Hunt factors and standalone email evaluation.
- Added `archive_inspections` status records so incomplete, truncated, or failed archive inventories cannot silently produce a benign result.
- Documented the one-mailbox/one-coherent-environment-per-case assumption for PST-derived trusted context.
- Expanded automated validation to 72 tests and 72 visible operational evaluators.

## 1.1.0 - Correctness, context inference, QR, and scale

- Corrected `message/rfc822` traversal so attached messages are stored, linked, and recursively indexed without leaking child bodies or attachments into the wrapper.
- Deduplicated URL rows with empty displayed text, added bare `www.` capture, expanded Proofpoint v2/v3 and Mimecast decoding, and vendored an offline Public Suffix List snapshot.
- Phish Hunt now auto-indexes URLs for selected unindexed messages.
- Replaced manually configured trusted auth/Received server identifiers with conservative inference from PST-derived messages; unavailable dependent factors are removed from the effective run configuration.
- Reworked historical evaluators to use normalized indexed fields and SQL existence/aggregate queries.
- Added offline QR evaluation for stored images and bounded PDF pages.
- Added optional bounded ZIP central-directory inventory with no extraction.
- Added `readpst -D` opt-in, message direction, whole-second timestamp normalization, and explicit `THREADSAW_READPST` path support.
- Added score coverage fields: `max_possible_points_evaluated`, `unknown_positive_points`, and `positive_score_percent_evaluated`.
- Split HTML script and event-handler checks and added thread-infrastructure-change, payment/urgency, HTML/SVG attachment, and modern-loader/macro-extension evaluators.
- Recalibrated default presets, including stronger DKIM than SPF weighting and lower weights for plain HTTP, free-email providers, and sender/URL-domain differences.
- Stripped bidirectional/invisible Unicode format controls from exported filesystem names.
- Added `case-context` CLI status/recompute command and large-selection SQLite batching.

## 1.0.0 - Official Version 1 release

- Promoted the approved 0.6.1 implementation to the official Version 1 baseline.
- Updated package and GUI version branding to 1.0.0.
- Added comprehensive user, installation, module, CLI, configuration, database/output, evaluator, file, testing, troubleshooting, and release-status documentation.
- No database schema or evaluator-scoring changes from 0.6.1.

## 0.6.1 - Completed visible evaluator catalog and starter presets

- Removed three visible factors whose prerequisites are not collected by ingestion.
- Replaced encrypted/password-protected archive status with a metadata-only common-archive evaluator.
- Implemented all 66 visible Phish Hunt evaluators.
- Added conservative External, Internal, and General phishing starter configurations with explicit enabled states, weights, and effect directions.
- Added CLI export of bundled starter configurations and JSON examples.
- Added migration of the old `encrypted_archive` factor ID to `attachment_archive`.

## 0.6.0 - Phish Hunt evaluator batch and report normalization

- Implemented 65 visible Phish Hunt evaluators.
- Left four prerequisite-dependent factors pending with explicit UNKNOWN outcomes.
- Removed the unique URL destination-domain count factor from the visible catalog while retaining legacy config compatibility.
- Added `url_count` and `url_indexed` to SQLite and message rollup reports.
- Simplified URL SharePoint output to `contains_sharepoint_reference` yes/no and removed internal/external classification from the URL report.
- Updated the Phish Hunt GUI scoring explanation and evaluator availability status.
- Added regression coverage for counts, SharePoint output, evaluator mappings, and all-factor execution.

## 0.5.0 - String Search and Evaluate Phishing Email

- Added case-insensitive literal String Search across SQLite fields, exported review TXT files, and reports.
- Added optional SQLite-only date filtering and unique timestamped search reports.
- Added Evaluate Phishing Email for one case message or standalone EML/MSG, with explicit standalone versus case-history behavior.
- Added matched-factor config.json generation for reuse in Phish Hunt.
- Added filename-extension filtering to attachment reports and exports.
- Renamed GUI Phish Hunt configuration actions to Import/Export config.json and retained CLI `--config` execution.
- Added two new Step 2 workflow actions and GUI tabs.
- Preserved the existing offline, no-URL-following, no-IP-connection, and no-attachment-execution guardrails.

## 0.4.0 - Phish Hunt factor catalog and explainable GUI

- Added the reviewed Inherently Risky and Situational factor catalog with collapsible subcategories.
- Added factor search, state/load filters, expand/collapse controls, enabled counts, load badges, and availability indicators.
- Added hover help that always says “Click for more information.” and a full scrollable factor-detail dialog with examples, cautions, prerequisites, and load explanations.
- Added generic factor-specific parameter controls and saved them in versioned scoring configurations.
- Added explicit UNKNOWN/zero-point behavior for cataloged evaluators that are not yet implemented.
- Retained backward compatibility with 0.3.x cross-domain demonstration configurations.

## 0.3.3 - Scrollable module pages and clearer attachment actions

- Added vertical scrollbars and cross-platform mouse-wheel support to every GUI module page.
- Increased notebook-tab font size, weight, and padding so module tabs are visually distinct from ordinary text.
- Replaced the attachment-copy checkbox with separate report-only and report-plus-file-export buttons.
- Updated command-preview behavior to reflect the selected attachment action before execution.

## 0.3.2 - Guided workflow and simplified case creation

- Added a Workflow page with prominent, ordered Step 1 and Step 2 action groups.
- Grouped Full Pipeline, Ingest Data, and Generate Reports under Data Initialization.
- Grouped Set Scope, Phish Hunt, Get URLs, Export Attachments, and Export Messages under Deeper Analysis and Exports.
- Moved Diagnostics to the upper-right application banner.
- Removed the public Initialize Case GUI action and CLI subcommand; Ingest Data and Full Pipeline continue to create or update cases internally.
- Added clearer Phish Hunt guidance explaining zero-centered scoring, report inclusion, and preset-first configuration.
- Increased visual emphasis on executable action buttons while preserving the live CLI command preview.

## 0.3.1 - Collision-safe completed outputs

- URL CSVs receive a UTC execution-completion timestamp before the `.csv` extension.
- Core reports, full-pipeline reports, attachment reports, copied attachment packages, and message exports finalize into completion-timestamped folders.
- Phish Hunt folders now use a completion timestamp while retaining immutable run IDs and manifests.
- Same-second completions receive deterministic `__2`, `__3`, and later suffixes instead of overwriting.
- Multi-file reports and artifact packages use hidden staging paths and are renamed only after successful finalization.
- GUI labels now identify output values as base names and explain that a completion timestamp is appended.

# Changelog

## 0.3.0 - Phish Hunt scoring prototype

- Added an explainable, user-configurable `phish_hunt` scoring framework with uncapped additive integer scores centered at zero.
- Added one low-weight prototype factor, sender/recipient domain difference, to exercise scored and unchanged messages.
- Required every hunt to use a UTC date range or named scope and warned on ranges longer than seven days.
- Created a unique timestamped/UUID-suffixed report folder for every execution and preserved configuration and run manifests.
- Added SQLite tables for hunt runs, message scores, and per-factor outcomes.
- Added GUI factor toggles, integer weights, effect modes, placeholder presets, configuration save/load, and a dedicated Phish Hunt tab.
- Added URL/attachment selection from an existing Phish Hunt CSV and uncapped integer threshold, with an editable report dropdown and Browse support.
- Added regression tests for scoring, negative uncapped values, run isolation, report selection, GUI discovery, and CLI parsing.

## 0.2.5 - Date export, progress heartbeat, and recipient context

- Fixed `export-messages` so `--start` and `--end` work as a standalone selector in both the CLI and GUI.
- Added explicit GUI start notices for every operation and a 90-second stage-aware heartbeat while work is still running.
- Added recipient-address context alongside sender-address context in message, URL, attachment, and export-summary CSVs and in exported message review text.
- Added `recipient_addresses` as a semicolon-delimited analyst field while retaining separate To/Cc/Bcc columns in message reports.
- Removed default Compose bind mounts so Docker Compose does not create surprise `evidence` or `case` folders; the user-selected folders are mounted explicitly.
- Added regression tests for date-range export argument parsing, recipient context, progress messages, and Compose folder behavior.

## 0.2.4 - Command preview and sender-IP context

- Added a live, non-executing Docker/CLI command preview to the GUI.
- Moved the motto to CLI startup and the GUI banner; removed it from message review exports.
- Added trusted-boundary, SPF-client, claimed-originating, topmost-Received, and bottommost-Received IP columns to message, URL, attachment, and export-summary CSVs.
- Added sender-IP classifications and SPF/DKIM/DMARC/ARC outcomes to companion message review text.
- Removed the aggregate sender-IPs field from analyst-facing message CSVs.
- Added regression coverage for IP classification, security-result export, branding placement, and command preview.

## 0.2.3 - Bind-mount-safe database access

- Replaced SQLite WAL mode with `DELETE` rollback-journal mode, `synchronous=FULL`, and a 30-second busy timeout.
- Added one-time automatic recovery for legacy WAL cases after a bind-mount disk I/O failure. Recovery copies the database and sidecars to local temporary storage, checkpoints them, verifies integrity, converts journal mode, and preserves a timestamped backup before replacement.
- Removed all direct host-GUI SQLite access. Named scopes are now loaded through `threadsaw scope list` inside the hardened container.
- Added database journal/integrity status to `threadsaw doctor`.
- Added clearer busy/database error handling and prevented selecting the same folder as both input evidence and writable case output.
- Retained all 0.2.2 MSG, canonical-source, subject-folder, calendar, scope, report-path, and security improvements.

## 0.2.2 - Portable cases and human-friendly exports

### Added and changed

- Loose EML and MSG inputs are copied byte-for-byte into canonical case storage during ingestion, so later exports do not require the original input mount.
- MSG conversion now preserves available transport headers through `extract-msg`'s email conversion path, including Date, Message-ID, Return-Path, Received, and Authentication-Results.
- Empty plain-text MSG parts now fall back to readable text derived from HTML, and embedded null characters are removed from interpreted header fields.
- Message and copied-attachment directories use sanitized, length-bounded subject lines; duplicate names receive numeric suffixes.
- Copied attachments retain sanitized original filenames and the attachment CSV records `exported_path`.
- The GUI calendar visibly highlights the selected date and shows a selected-date label.
- Named-scope selection uses a read-only drop-down populated from the selected case database, with refresh support.
- Full-pipeline and default report output moved to `/case/reports`; exports remain under `/case/exports`.
- Attachment reporting supports a separate `--copy-output` path for analyst-friendly copied bytes.

### Compatibility note

Cases ingested before 0.2.2 may not contain canonical loose-message copies. Re-ingest those loose EML/MSG sources to make the case self-contained.

## 0.2.1 - Complete GUI command surface

### Added

- GUI tabs for every current CLI operation: full pipeline, ingest, reports, URLs, attachments, message export, scopes, case initialization, and doctor.
- Full message-selector controls for all messages, date range, one SHA-256, SHA-256 CSV, and named scope.
- Editable/pasteable ISO-8601 date fields plus a dependency-free calendar and UTC time dropdowns.
- Per-module output controls restricted to the selected case/output folder.
- GUI controls for worker count, recursive discovery, quiet mode, and attachment-byte copying.
- Named Docker containers and cleaner GUI stop behavior.
- Dedicated GUI documentation in `docs/GUI.md`.

### Security invariants retained

- The GUI displays progress and outcomes only, not generated evidence data.
- No URL or IP address is followed, retrieved, resolved, or enriched.
- No attachment is opened, launched, rendered, detonated, or executed.


## 0.2.0 - V2 prototype

V2 builds on the frozen V1 CLI baseline (`0.1.1`).

### Added

- Optional desktop GUI launcher in `launcher/threadsaw_gui.py`.
  - Collects project, input, case/output, worker count, and optional UTC date range.
  - Streams CLI progress and final outcome text.
  - Does not display evidence or open messages, attachments, URLs, or IP addresses.
- Verbose stage and progress output for discovery, PST extraction, EML indexing, URL extraction, batched commits, and final outcomes.
- `--quiet` global option for automation workflows that only want final JSON.
- Sender email, selected message date/time, and subject columns in attachment and URL reports.
- Verified PST extraction completion marker.
- Automatic removal and re-extraction of incomplete PST output rather than silently reusing it.
- Batched URL commits to reduce long silent SQLite commits.

### Security invariants retained

- No URL or IP address is followed, retrieved, resolved, or enriched.
- No attachment is opened, launched, rendered, detonated, or executed.
- `readpst` remains the only allowed external process inside Threadsaw.

## 0.1.1 - V1 CLI release

- Frozen as the first CLI-only release.
- SQLite-first indexing, PST/EML/optional MSG ingestion, reporting, URL string extraction, attachment carving, scopes, and message export.
- Permanent offline and static-analysis security guardrails.

## 1.3.0 - 2026-07-13

- Added large-case streaming for core reports and Phish Hunt, including JSON Lines output.
- Added PST free-space preflight, preserved partial extraction output, and per-EML fault isolation.
- Added human-readable Evaluate Phishing Email hit report.
- Added GitHub publication files, platform Getting Started guides, dependency pins, licensing guidance, and CycloneDX SBOM.
- Default container build excludes optional GPL-licensed MSG support; enable explicitly with `THREADSAW_INSTALL_MSG=1`.
