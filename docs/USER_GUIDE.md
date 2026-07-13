# Threadsaw 1.3.0 user guide

## 1. Purpose

Threadsaw turns PST, EML, and optional MSG sources into a repeatable offline case containing normalized message metadata, inert attachment artifacts, URL strings, QR results, reports, saved scopes, phishing scores, and review exports. It is designed for triage and pattern discovery in Business Email Compromise and phishing investigations.

Threadsaw does not decide whether an email is malicious. Its reports and scores are explainable evidence summaries that require analyst review.

## 2. Case and evidence model

A case is a writable directory containing `case.json`, `threadsaw.sqlite3`, canonical source copies or extraction products, hash-addressed artifacts, reports, exports, logs, and saved configurations. SQLite is authoritative; CSV, JSON, TXT, copied attachments, and exported EMLs are generated views.

`message_sha256` identifies the indexed EML representation. A loose EML is hashed from its exact bytes. A PST-derived message is hashed from the EML produced by `readpst`. MSG input retains its source hash separately from the derived EML hash.

An attached `message/rfc822` email is stored as an attachment and recursively indexed as a linked child message. Its body and attachments do not leak into the wrapper message’s evidence.

## 3. Recommended workflow

### Step 1 — Preserve evidence

Keep original evidence read-only and separate from the writable case directory. Record provenance and source hashes under the organization’s evidence-handling procedure.

### Step 2 — Ingest or run the Full Pipeline

**Full Pipeline** is the recommended first operation. It ingests messages, performs offline URL indexing, and writes core reports. **Ingest Data** can be used independently when the analyst wants to defer later processing.

PST ingestion can optionally include recoverable deleted items through `readpst -D`. Threadsaw keeps deleted-item and ordinary extraction caches separate.

### Step 3 — Review inferred case context

Threadsaw does not ask for trusted Authentication-Results or Received-server identifiers. After PST ingestion it attempts conservative consensus only when at least 20 PST-derived messages are available. Received boundaries use exact-host consensus first and a stable parent-domain-suffix fallback for rotating cloud frontends. Use:

```bash
threadsaw case-context --case ./case
```

When trust context cannot be inferred, dependent factors are removed from the effective hunt configuration rather than returning misleading zero-point results. Organization domains may be supplied at ingest/run with repeatable `--organization-domain`, in the GUI Organization domains field, or later with `threadsaw case-config`; they support direction, lookalike, embedded-domain, and SharePoint heuristics without establishing trusted servers.

### Step 4 — Review rollups

Start with `messages.csv`, then pivot into URL, attachment, QR, archive-member, or exported review-text outputs. Key message columns include direction, deduplicated URL count, and non-inline attachment count.

### Step 5 — Narrow the evidence

- **Set Scope** saves an immutable date-based message set.
- **String Search** locates literal case-insensitive strings across SQLite, exported review text, and reports.
- **Phish Hunt** scores a required date range or scope with a complete `config.json`.
- **Evaluate Phishing Email** explains one indexed or standalone message and exports a starter config containing matched factors.

### Step 6 — Export review material

Export selected messages or attachments into new completion-timestamped folders. Preserve the manifest, configuration hash, and summary files with the exported content.

## 4. Desktop launcher

The Tkinter GUI runs on the host and constructs network-disabled Docker commands. It does not open SQLite directly or render email, URL, QR, or attachment content.

### Step 1 modules

- Full Pipeline
- Ingest Data
- Generate Reports
- Set Scope

### Step 2 modules

- Phish Hunt
- Evaluate Phishing Email
- String Search
- Evaluate QRs
- Get URLs
- Attachment Report / Export
- Export Messages

Navigation can use two rows so every module remains visible.

### Phish Hunt controls

Factors are grouped under **Inherently Risky** and **Situational**, then into collapsible subcategories. Each factor row includes its toggle, weight, effect mode, computational load, prerequisites, and help control. Every hover tooltip ends with **Click for more information.** Clicking opens the complete description, examples, false-positive notes, result semantics, and load explanation.

The GUI includes External, Internal, and General starter configurations. They are adjustable heuristics, not calibrated probabilities.

## 5. Selectors and date behavior

Most analysis and export commands accept one selector: a message hash, hash CSV, named scope, UTC range, or all messages where supported. URL and attachment workflows can also consume a Phish Hunt CSV plus a minimum score.

Date ranges are start-inclusive and end-exclusive. Stored and user-supplied timestamps are normalized to UTC whole seconds.

Phish Hunt intentionally requires a complete date range or a named scope; it has no unrestricted `--all` mode.

## 6. Core outputs

### Messages

`messages.csv` and `messages.json` contain message identifiers, selected and header dates, Received context, sender/recipient fields, direction, preferred trusted authentication results when available, IP evidence, non-inline attachment count, deduplicated URL count, derivation status, and parser defects.

Direction is `inbound`, `outbound`, `internal`, or `unknown` relative to configured or conservatively inferred organization domains.

### URLs

`urls.csv` contains the original and normalized text, displayed target, statically decoded wrapper target, hostname, offline Public-Suffix-List registrable domain, mismatch status, SharePoint presence, and heuristic SharePoint relationship. Threadsaw never resolves or retrieves any target.

### Attachments and archives

`attachments.csv` records the original and safe names, MIME declaration, disposition, content ID, inline status, hashes, size, executable/script observation, artifact path, and optional copied path. Inline signature images remain evidence but do not inflate attachment counts or attachment-history factors.

Optional ZIP inventory records bounded central-directory member metadata only. It does not extract, decompress, recurse into nested archives, decrypt content, or test passwords. The `attachment_encrypted_zip` evaluator can report a ZIP-family archive when one or more inventoried members carry the standard encryption flag; incomplete inventory returns UNKNOWN unless a positive encrypted member was already observed.

### QR results

QR evaluation scans stored image attachments and a bounded number of PDF pages rendered locally through pypdfium2/PDFium. It records decoded text and URL-shaped values without contacting them.

### Phish Hunt

`phish_hunt.csv` contains one row per selected message. **The higher the score in the output CSV, the more likely the message is to match the configured phishing indicators.** Scores are uncapped additive integers and may be negative.

Coverage columns show how much positive scoring capacity was actually evaluable:

- `max_possible_points_evaluated`
- `unknown_positive_points`
- `positive_score_percent_evaluated`

These fields expose missing-data bias but do not turn the score into a probability.

`phish_hunt_details.csv` contains one row per enabled factor per message with answer, points, weight, effect mode, evidence, source, status, reason, and evaluator version.

## 7. Result semantics

- `YES` — the factor matched.
- `NO` — it was evaluated and did not match.
- `UNKNOWN` — required evidence was missing, untrusted, or inconclusive.
- `NOT_APPLICABLE` — the factor cannot meaningfully run in the selected mode, commonly a case-history factor on an unrelated standalone message.
- `ERROR` — evaluator failure; zero points and visible detail.

`risk_when_yes` adds the weight for `YES`. `trust_when_yes` subtracts it. Other answers add zero.

Scores from different configurations are not directly comparable. Preserve the requested and effective scoring configurations and their hashes.

## 8. Standalone email evaluation

An indexed case message receives all applicable message-local and case-history factors. A new EML/MSG is parsed in an isolated temporary case. When its derived hash matches the existing case, the indexed case record is used. Otherwise, only standalone factors run by default.

The case-history override is available, but it is meaningful only when the external message came from the same mailbox population as the case. The original case database is not modified.

## 9. Important Version 1.1/1.2 migration notes

Opening an older Version 1 case migrates its schema in place to schema version 8 and removes duplicate URL rows caused by NULL display text. Re-running URL indexing is recommended for bare-`www` capture, expanded wrapper decoding, and refreshed SharePoint relationship values.

Re-ingestion is required to fully correct historical wrapper/attached-email attribution and inline-attachment counts because those changes occur during MIME parsing. Preserve the old case before rebuilding when evidentiary continuity matters.

## 10. Forensic reminders

- Preserve original evidence separately and read-only.
- Retain source hashes, `case.json`, SQLite, run manifests, requested/effective configs, and config hashes.
- Validate important findings against the original message or mailbox source.
- Treat PST-generated and MSG-derived EMLs as derived representations.
- Treat inferred trust and SharePoint relationship as conservative heuristics, not authoritative infrastructure ownership.
- Keep one mailbox or one coherent mail environment per case; PST-derived trust applies to every message in that case.
- Do not treat a high or low score as a verdict without examining coverage and factor details.
