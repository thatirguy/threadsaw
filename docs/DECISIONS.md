# Architecture decisions

## ADR-001: Parse once into SQLite

**Decision:** Normalize messages into SQLite during ingestion. Reports, searches, exports, and Phish Hunt evaluations query normalized records instead of reparsing every message.

**Consequence:** Attachment bytes are carved to a hash-addressed artifact store during ingestion. Later analysis remains deterministic and does not require reopening the original PST or MIME message unless a module explicitly performs a bounded static inspection of a carved artifact.

## ADR-002: Date narrowing is a query, not a copying module

**Decision:** Date narrowing is a universal query and optional named scope rather than a module that duplicates messages.

**Consequence:** Physical EML copies are created only by message export. File-based String Search results are not implicitly restricted by a SQLite date range.

## ADR-003: Use an explicit message SHA-256 identifier

**Decision:** `message_sha256` is the SHA-256 of the indexed EML bytes. Threadsaw does not invent a branded identifier.

**Consequence:** For MSG input, the message identifier describes the clearly labeled derived EML. The original MSG is separately hashed in the source table.

## ADR-004: Evidence is distinct from reports

**Decision:** SQLite, original source files, derived EMLs, and hash-addressed artifacts are authoritative case material. CSV, JSON, TXT, and selected-message directories are generated products.

**Consequence:** Editing a report does not modify the case database or evidence records.

## ADR-005: Dependency-light core with bounded static analyzers

**Decision:** Core EML processing uses the Python standard library. `readpst` is the PST adapter and `extract-msg` remains optional for MSG conversion. Additional libraries are permitted only for bounded, offline static analysis whose behavior is explicit and testable.

**Consequence:** Threadsaw 1.2 includes a vendored Public Suffix List snapshot, offline QR decoding with OpenCV, PDF page rendering with pypdfium2/PDFium, and bounded ZIP central-directory inspection. It still excludes active document rendering, macro execution, detonation, live reputation services, and unrestricted archive extraction.

## ADR-006: No network access under any mode

**Decision:** Threadsaw never resolves or connects to IP addresses and never retrieves, follows, previews, or opens URLs. This is fixed policy rather than a default that can be disabled.

**Consequence:** Wrapper decoders preserve wrapper and deterministically decoded target strings but cannot and must not confirm live redirect behavior. External reputation services remain outside the product boundary.

## ADR-007: Never launch or execute attachments

**Decision:** Threadsaw may decode, hash, copy, inventory, render selected PDF pages to pixels, and statically inspect bytes, but it never launches an attachment through the operating system or executes an attachment, script, macro, document behavior, or embedded object.

**Consequence:** Analyzers must remain bounded static parsers. Features requiring an office application, browser, shell, detonation environment, or general-purpose subprocess are excluded.

## ADR-008: External process allowlist

**Decision:** The sole permitted child process is the explicitly resolved `readpst` binary, invoked with list-form arguments, no shell, closed standard input, a proxy-stripped environment, and captured output. `THREADSAW_READPST` may provide an explicit binary path for native-host use.

**Consequence:** General `subprocess`, browser, and OS-launcher calls are denied by runtime guardrails and audited in tests. Docker remains the primary isolation boundary.

## ADR-009: Use rollback journaling on Docker host bind mounts

**Decision:** Use SQLite `DELETE` journal mode with `synchronous=FULL`; do not use WAL for case databases.

**Reason:** Threadsaw cases commonly live on Windows or macOS filesystems presented to a Linux Docker VM. Avoiding WAL removes cross-boundary shared-memory assumptions. The GUI obtains metadata through the container CLI rather than opening SQLite from the host.

## ADR-010: Preserve attached-message boundaries

**Decision:** A `message/rfc822` MIME part is recorded as an attachment and recursively indexed as its own linked message. The outer-message body and attachment collectors do not descend into the attached message.

**Consequence:** Inner body text and payloads are attributed to the attached message rather than the wrapper. Parent-child relationships are retained in `message_relationships`.

## ADR-011: Infer trusted mail infrastructure only from the PST corpus

**Decision:** Threadsaw does not prompt for trusted Authentication-Results servers or trusted Received boundary hosts. It derives conservative consensus values only from messages that are demonstrably PST-derived.

**Consequence:** Manual `trusted_authserv_ids` and `trusted_received_hosts` values are ignored and removed from case configuration. When no stable PST-derived consensus is available, dependent Phish Hunt factors are disabled in the effective run configuration and the manifest states why. Trust flags can be recomputed from the normalized corpus without reparsing MIME.

## ADR-012: Use a vendored Public Suffix List

**Decision:** Registrable-domain comparisons use an offline, versioned Public Suffix List snapshot distributed with Threadsaw.

**Consequence:** Domain comparisons support multi-label public suffixes without DNS or network access. Results reflect the bundled snapshot until the application is updated.

## ADR-013: Historical factors must use indexed SQL

**Decision:** Case-history factors use indexed `EXISTS`, aggregate, and narrowly projected SQL queries against normalized sender, domain, subject, URL, and relationship fields.

**Consequence:** Evaluators must not repeatedly load full historical message bodies and parse addresses in Python. This avoids the previous quadratic full-row scan pattern and makes large-case execution practical, subject to real-world benchmarking.

## ADR-014: Inline related media is not a normal attachment count

**Decision:** MIME parts marked inline or referenced by Content-ID are retained as artifacts but flagged with `is_inline=1` and excluded from `attachment_count`, `has_attachments`, and attachment-history factors unless an evaluator explicitly requests inline material.

**Consequence:** Signature logos and similar related content do not inflate ordinary attachment metrics.

## ADR-015: QR and ZIP analysis are bounded and opt-in

**Decision:** QR evaluation operates only on carved image attachments and a configured maximum number of rendered PDF pages. ZIP inspection reads bounded central-directory metadata and does not extract members.

**Consequence:** Results include limits and truncation status. Decoded QR URLs are stored as text only and are never contacted. Archive member names, sizes, encryption flags, and suspicious extensions can inform analysis without extraction.

## ADR-016: SharePoint relationship is explicitly heuristic

**Decision:** URL reporting records both whether a SharePoint reference exists and a probable relationship to inferred or configured organization domains.

**Consequence:** Values such as `probable_internal`, `probable_external`, `unknown`, and `not_sharepoint` are triage aids, not authoritative tenant ownership determinations. Exact legitimate-host comparison remains available as a configurable Phish Hunt factor.

## ADR-017: Phish Hunt scores are uncapped and zero-centered

**Decision:** Phish Hunt uses additive integers with no artificial minimum or maximum. Zero is neutral, positive values indicate greater correspondence with the configured phishing indicators, and negative values indicate less correspondence. Weights are non-negative; direction is represented by an explicit effect mode.

**Consequence:** Threadsaw does not present an uncalibrated score as a 0–100 probability. Main output also records evaluated maximum positive points, unknown/unavailable counts, and an evaluated-score percentage so missing evidence is visible.

## ADR-018: One isolated folder per analysis run

**Decision:** Every Phish Hunt, String Search, QR, report, and export execution creates a new timestamped output folder and corresponding run metadata where applicable.

**Consequence:** Existing reports are not silently overwritten, and multiple configurations or date windows can coexist.

## ADR-019: Phish Hunt configurations are complete JSON documents

**Decision:** GUI presets, CLI execution, imported configurations, and exported configurations share the same complete JSON schema and backend factor registry.

**Consequence:** Preset behavior cannot drift between interfaces. Evaluate Phishing Email may export a starter configuration containing factors that hit, but analysts must review its weights and direction before reuse.

## ADR-020: URL analysis is automatic when required by Phish Hunt

**Decision:** Before scoring, Phish Hunt deterministically indexes URLs for selected messages whose `url_indexed` flag is false.

**Consequence:** URL-dependent factors are not silently lost after an ingest-only workflow. The run manifest reports how many messages were auto-indexed.

## ADR-021: Literal String Search only

**Decision:** String Search uses Unicode case-folded literal substring matching. It does not support regular expressions, fuzzy matching, or executable search expressions.

**Consequence:** Search behavior is predictable. SQLite date filtering applies only to message-associated database rows; exported-text and report-file searches remain unscoped by that date range and are labeled accordingly.

## ADR-022: External single-message evaluation does not contaminate the case

**Decision:** Evaluate Phishing Email processes a new external EML or MSG in a temporary case. If its hash matches an existing case message, normal case-aware evaluation is used. Otherwise only standalone factors run by default; the analyst may explicitly allow case-history factors against a temporary database clone.

**Consequence:** The original case database is not modified, and case-history limitations are visible rather than silently interpreted as benign results.

## ADR-023: Use pypdfium2/PDFium for PDF QR rendering

**Decision:** Replace PyMuPDF with `pypdfium2`/PDFium for bounded PDF-page rendering in the QR module.

**Consequence:** PDF QR scanning remains available without making PyMuPDF a dependency. Threadsaw ships the applicable third-party notices, renders only a configured number of pages at bounded DPI, and never activates PDF actions or follows decoded targets.

## ADR-024: Separate analyst organization domains from inferred trusted infrastructure

**Decision:** Permit analysts to declare organization domains for any case, but never accept manual trusted authserv-id or Received-host identifiers.

**Consequence:** Loose EML/MSG cases can obtain direction and organization-aware comparisons without allowing user-entered values to establish authentication or transport trust.

## ADR-025: Require a substantive PST corpus for trust inference

**Decision:** Infer trusted mail infrastructure only from at least 20 PST-derived messages. Received inference uses exact-host consensus, then a PSL-bounded stable parent-domain suffix.

**Consequence:** Small corpora cannot establish trust, and rotating M365/Google-style frontend names can still produce a conservative stable boundary when the underlying suffix repeats.

## ADR-026: Encrypted ZIP detection is metadata-only

**Decision:** The encrypted-archive evaluator is limited to ZIP-family artifacts whose bounded central-directory inventory exposes a member encryption flag.

**Consequence:** A positive result means protected ZIP member metadata was observed. It does not decrypt content, test a password, or identify encryption in unsupported RAR/7Z containers. Missing or incomplete inventory returns UNKNOWN rather than NO.

## ADR-027: One coherent mailbox environment per case

**Decision:** Treat a case as one mailbox or one coherent mail environment.

**Consequence:** PST-derived trust and case-history context may be applied to all messages in the case, so unrelated custodians should be kept in separate cases.
