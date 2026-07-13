# Threadsaw 1.3.0 module reference

## Step 1 modules

### Full Pipeline

Runs ingestion, URL indexing, and core reports. Use it for a new case when the default end-to-end workflow is appropriate. It supports optional `readpst -D` deleted-item extraction.

### Ingest Data

Indexes PST, EML, and optional MSG evidence. Source hashes are recorded; loose source files are copied into the case. MIME bodies, recipients, Received fields, authentication results, attachments, and defects are normalized. Attached emails become linked child messages rather than leaking into wrapper evidence.

### Generate Reports

Reads SQLite and emits analyst-facing message, attachment, and error rollups. Message reports contain direction, URL count, and non-inline attachment count.

### Set Scope

Creates immutable named message selections from a date range. Later ingestion does not alter an existing scope.

## Step 2 modules

### Phish Hunt

Applies an imported or GUI-edited `config.json` across a date range or scope. Factors are grouped in collapsible Inherently Risky and Situational subcategories. Each row exposes enabled state, weight, effect mode, load, availability, and help. Every hover tooltip ends with “Click for more information.”

The module auto-indexes missing URL data, performs bounded ZIP inventory when archive-dependent factors are enabled, and removes trusted-dependent factors when conservative PST consensus is unavailable. Outputs include score coverage fields and both requested/effective configurations. The encrypted-ZIP factor consumes stored central-directory encryption flags without extraction or password attempts.

### Evaluate Phishing Email

Evaluates one indexed SHA-256 or an external EML/MSG. Standalone files run only message-local factors unless case history is explicitly allowed. A matched-factor config is generated for later hunts.

### String Search

Performs a case-insensitive literal substring search across selected SQLite fields/tables, exported review text, and reports. SQLite date filtering does not apply to filesystem text.

### Evaluate QRs

Decodes QR codes offline from stored image attachments and a bounded number of PDF pages rendered through pypdfium2/PDFium. It records decoded text and URL-shaped values but never retrieves them.

### Get URLs

Extracts URL/URI strings from text and HTML, including bare `www.` hostnames. It records displayed text, mismatch, wrapper/decoded target, effective domain, SharePoint presence, and heuristic relationship. It never resolves or follows a target.

### Attachment Report / Export

Reports attachment metadata and optionally copies bytes. An extension filter supports one or more user-specified filename extensions. Optional bounded ZIP listing records member metadata without extraction.

### Export Messages

Exports selected EMLs with review text, summaries, and a manifest. Filesystem names are sanitized, including removal of bidirectional/invisible format controls.

### Diagnostics

Reports dependency, container/runtime, case database, and security posture. It also identifies the actual `readpst` executable used.

## Non-GUI support module: Case Context

The CLI `case-context` command surveys PST-derived messages, recomputes conservative trusted auth/Received context, and shows whether dependent factors can run. It deliberately has no trusted-server input prompt.

## Non-GUI support module: Case Configuration

The CLI `case-config` command sets or clears analyst-declared organization domains and immediately recomputes direction and organization-aware context. This is intentionally separate from trusted mail-server inference; no trusted authserver or Received-host identifiers can be entered.
