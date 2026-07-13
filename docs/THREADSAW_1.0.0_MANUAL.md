# Threadsaw 1.0.0 Manual

**When you're looking for a needle in a haystack, you need a pitchfork.**

Official Version 1 documentation. Generated from the same source tree and factor metadata as the application.



---

# Documentation Index


## Begin here

- [`USER_GUIDE.md`](USER_GUIDE.md) — end-to-end operating guide for analysts.
- [`INSTALLATION_AND_DEPLOYMENT.md`](INSTALLATION_AND_DEPLOYMENT.md) — host, Docker, CLI, and optional MSG setup.
- [`MODULE_REFERENCE.md`](MODULE_REFERENCE.md) — purpose, inputs, processing, outputs, and limitations of every user-facing module.
- [`CLI_REFERENCE.md`](CLI_REFERENCE.md) — every command, selector, option, and exit code.

## Analysis and data reference

- [`EVALUATOR_REFERENCE.md`](EVALUATOR_REFERENCE.md) — all 66 Phish Hunt evaluators, examples, prerequisites, load, and default preset settings.
- [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md) — `case.json`, Phish Hunt `config.json`, presets, and score semantics.
- [`DATABASE_AND_OUTPUTS.md`](DATABASE_AND_OUTPUTS.md) — case layout, SQLite tables, report files, and column definitions.
- [`FILE_REFERENCE.md`](FILE_REFERENCE.md) — what every file in the source distribution does.

## Assurance, design, and support

- [`SECURITY_AND_FORENSICS.md`](SECURITY_AND_FORENSICS.md) — non-negotiable offline/static-analysis posture and forensic cautions.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — components, data flow, persistence, and isolation model.
- [`DECISIONS.md`](DECISIONS.md) — important architecture decisions and their rationale.
- [`TESTING_AND_VALIDATION.md`](TESTING_AND_VALIDATION.md) — automated coverage, validation boundaries, and recommended acceptance testing.
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — common host, Docker, database, parsing, and output issues.
- [`RELEASE_STATUS.md`](RELEASE_STATUS.md) — what Version 1 does and does not claim.
- [`RELEASE_NOTES_1.0.0.md`](RELEASE_NOTES_1.0.0.md) — official Version 1 release notes.
- [`CHANGELOG.md`](../CHANGELOG.md) — historical changes from the earliest prototype through Version 1.

## Historical and specialized references

The original module-specific documents and historical release notes are retained for traceability. The Version 1 documents above are authoritative when they differ from an older note.


---

# User Guide


## 1. Purpose

Threadsaw helps an analyst turn one or more mailbox sources into a repeatable case containing normalized message metadata, inert attachment artifacts, URL strings, reports, saved scopes, phishing scores, and review exports. It is designed for triage and pattern discovery, especially in Business Email Compromise investigations.

Threadsaw does not determine whether an email is malicious. Its outputs are evidence summaries and configurable indicators that require analyst interpretation.

## 2. Core concepts

### Case

A case is a writable directory containing `case.json`, `threadsaw.sqlite3`, canonical source copies, extracted EMLs, attachment artifacts, reports, exports, configurations, logs, and saved scopes. SQLite is authoritative; CSV, JSON, TXT, EML, and copied attachments are generated views or export products.

### Message identifier

`message_sha256` is the SHA-256 of the indexed EML representation. A loose EML is identified by its exact bytes. A PST-derived message is identified by the EML produced by `readpst`. An MSG has a separate source-file hash and an indexed, clearly labeled derived EML hash.

### Selection

Most analysis and export commands accept one of these selectors:

- One `message_sha256`.
- A CSV of message hashes.
- A named scope.
- A UTC date range, start inclusive and end exclusive.
- All messages, where the module allows it.
- A Phish Hunt report plus minimum score for URL and attachment operations.

Phish Hunt is intentionally stricter: it requires exactly one named scope or a complete start/end range.

### Completion-timestamped outputs

Every report or export operation creates a new finalized file or directory. Threadsaw stages work in a hidden in-progress path and renames it only after completion. It never overwrites a completed run. If two runs finish in the same second, suffixes such as `__2` are added.

## 3. Recommended case workflow

### Step 1 — Prepare evidence and case directories

Keep original evidence in a read-only directory. Create a separate writable case directory on a local or host filesystem with enough capacity for extracted EMLs and attachment bytes.

### Step 2 — Configure trust and organization context

Before ingestion, edit `case/case.json` after the case is created, or create the configuration through your normal case-preparation process. Useful values include trusted authentication-service IDs, trusted Received hosts, organization domains, and date-selection policy. Empty trust lists deliberately produce `UNKNOWN` classifications rather than guesses.

### Step 3 — Run Full Pipeline

For a new case, Full Pipeline is the simplest starting point. It ingests PST/EML/MSG inputs, indexes messages and attachments, performs offline URL indexing, and writes core reports.

### Step 4 — Review rollups

Open the generated CSV/JSON files with your chosen host tools. Threadsaw itself does not launch them. Start with `messages.csv`, then pivot into `urls.csv`, `attachments.csv`, or exported review-text packages.

### Step 5 — Narrow with scopes, search, or Phish Hunt

- Use **Set Scope** for reusable date windows.
- Use **String Search** for literal indicators such as addresses, invoice numbers, domains, or phrases.
- Use **Phish Hunt** to score a date window or scope with an explicit `config.json`.
- Use **Evaluate Phishing Email** to understand one message and produce a starter config containing factors that matched.

### Step 6 — Export review material

Export selected messages or attachments into timestamped packages. Preserve the manifest and summary files with the exported bytes.

## 4. Desktop launcher

The GUI is a host-side Tkinter launcher that builds Docker Compose commands and streams process output. It never opens the case SQLite database directly and never renders message, URL, or attachment content.

### Workflow page

The Workflow page presents two stages:

**Step 1: Data Initialization**

- Full Pipeline
- Ingest Data
- Generate Reports

**Step 2: Deeper Analysis and Exports**

- Set Scope
- Phish Hunt
- Evaluate Phishing Email
- String Search
- Get URLs
- Export Attachments
- Export Messages

The module navigation is displayed in two rows when needed so every module remains visible across supported desktop platforms.

### Common launcher controls

- Evidence/input directory.
- Case directory.
- Output base path.
- Worker count.
- Message selector and UTC date fields.
- Live command preview that is not executed until the analyst starts the operation.
- Progress log, start notices, and periodic heartbeat for long operations.
- Stop control for the active container process.

### Date controls

Date ranges use ISO 8601 timestamps with a UTC offset or `Z`. The launcher provides editable fields and a built-in UTC calendar/time picker. Start is inclusive; end is exclusive.

### Phish Hunt interface

The factor catalog is grouped into **Inherently Risky** and **Situational**, then into collapsible subcategories. Each row provides:

- Enabled/disabled toggle.
- Integer weight.
- Effect mode (`risk_when_yes` or `trust_when_yes`).
- Light, Moderate, Heavy, or Extreme computational-load badge.
- Question-mark help control.
- Factor-specific parameters where applicable.

Every hover tooltip ends with **Click for more information.** Clicking opens the full description, examples, false-positive cautions, prerequisites, and result semantics.

The GUI includes External, Internal, and General starter configurations. They are heuristics, not probabilities, and should be reviewed before use.

## 5. Reading the main outputs

### `messages.csv`

One row per selected message. It includes dates, sender and recipient context, authentication summaries, sender-IP evidence, attachment and URL counts, derivation status, and parse defects.

### `urls.csv`

One row per stored URL occurrence. It includes displayed text, actual and decoded targets, hostname and registrable-domain fields, wrapper type, mismatch status, and a yes/no SharePoint-reference flag. It does not classify SharePoint links as internal or external.

### `attachments.csv`

One row per attachment. It includes message context, original and safe filenames, MIME declaration, size, SHA-256, MD5, static executable-format observation, artifact path, exported path, and status.

### `phish_hunt.csv`

One row per selected message. **The higher the score in the output CSV, the more likely the message is to match the configured phishing indicators.** Scores are uncapped additive integers and may be negative.

### `phish_hunt_details.csv`

One row per factor per message, with answer, points, weight, effect mode, evidence, source, status, reason, and evaluator version.

### Exported message package

Each message receives a subject-derived folder containing the EML, `review.txt`, and, for standalone MSG inputs where available, the original MSG. The package root also contains `summary.csv` and `manifest.json`.

## 6. Interpreting Phish Hunt results

- `YES`: the factor matched.
- `NO`: the factor was evaluated and did not match.
- `UNKNOWN`: required evidence was absent, untrusted, or inconclusive.
- `NOT_APPLICABLE`: the factor was intentionally skipped, commonly because a standalone email has no valid case-history context.
- `ERROR`: evaluator failure; contributes zero and remains visible for review.

`risk_when_yes` adds the configured weight for `YES`. `trust_when_yes` subtracts the configured weight for `YES`. All other answers add zero.

Do not compare scores from different configurations as though they were on the same calibrated scale. Preserve `scoring_config.json` and the config hash with every run.

## 7. Handling standalone email evaluation

An existing case message uses all applicable standalone and case-history factors. A new EML/MSG is parsed in an isolated temporary case. When its derived message hash matches the existing case, Threadsaw uses the case record. Otherwise, historical factors are `NOT_APPLICABLE` by default.

The analyst may enable the case-history override, but results are only meaningful when the external message came from the same mailbox population as the case. The real case is not modified.

## 8. Forensic handling reminders

- Record source provenance before ingestion.
- Preserve original evidence separately and read-only.
- Retain `case.json`, SQLite, run manifests, and configuration hashes.
- Validate important findings against the original message or mailbox source.
- Treat MSG-derived EMLs and PST-generated EMLs as derived representations.
- Do not interpret missing or untrusted authentication results as passes or failures.
- Do not treat a high Phish Hunt score as a verdict.


---

# Installation and Deployment


## Supported execution models

Threadsaw 1.0.0 can run as:

1. A containerized CLI, launched directly or through the Tkinter GUI.
2. A native Python CLI in a virtual environment.

Containerized execution is recommended because it provides a consistent parser environment and adds `network_mode: none`, a read-only container filesystem, dropped capabilities, and `no-new-privileges`.

## Host requirements

- 64-bit Windows, macOS, or Linux capable of running Docker/Compose, or Python 3.11+ for native CLI use.
- Sufficient disk space for PST extraction, canonical source copies, attachment artifacts, reports, and exports.
- Tkinter for the desktop launcher.
- `readpst` for PST ingestion.
- Optional `extract-msg==0.55.0` for standalone MSG ingestion.

## Desktop launcher setup

1. Install and start Docker Desktop or a compatible Docker engine.
2. Install Python 3.11 or newer with Tkinter.
3. Extract the Threadsaw source package.
4. Open a terminal in the project directory.
5. Run:

```powershell
python .\launcher\threadsaw_gui.py
```

The launcher calls Docker Compose. It does not require the Threadsaw package to be installed into the host Python environment.

## Native Python setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

Windows PowerShell activation:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

Optional MSG support:

```bash
pip install -e '.[msg]'
```

Run diagnostics:

```bash
threadsaw doctor
threadsaw doctor --case ./case
```

## Docker build

```bash
docker build -t threadsaw:1.0.0 .
```

The Dockerfile installs `pst-utils`, which supplies `readpst`, and installs optional MSG support by default. To omit MSG support:

```bash
docker build --build-arg THREADSAW_INSTALL_MSG=0 -t threadsaw:1.0.0-no-msg .
```

## Secure container invocation

```bash
docker run --rm --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=2g \
  --mount type=bind,src="/absolute/evidence",dst=/input,readonly \
  --mount type=bind,src="/absolute/case",dst=/case \
  threadsaw:1.0.0 run --input /input --case /case
```

Evidence must be mounted read-only. The case directory must be writable. Do not mount the same directory as both evidence and case.

## Docker Compose

`compose.yaml` deliberately contains no default host volume paths. The GUI supplies explicit bind mounts for the selected evidence and case directories. This prevents Docker Compose from creating unexpected empty directories in the project folder.

## Windows path considerations

- Use absolute paths for Docker bind mounts.
- Ensure the drive is shared with Docker Desktop.
- Avoid storing an active case in cloud-synchronization folders while Threadsaw is running.
- Close spreadsheet applications that may lock report files before rerunning an export.

## SQLite filesystem policy

Threadsaw uses SQLite `DELETE` rollback-journal mode, `synchronous=FULL`, and a 30-second busy timeout. WAL is intentionally avoided on Windows/macOS host folders bind-mounted into a Linux container. A legacy WAL database can be recovered automatically on local temporary storage, with the original components backed up under `case/logs/database-backups/`.

## Updating from 0.6.1

Version 1.0.0 does not change the database schema or evaluator logic from 0.6.1. Existing 0.6.1 cases and Phish Hunt configurations remain compatible. Install the new wheel or extract the Version 1 source package into a new directory, rebuild the container, and continue using the existing case directory.


---

# Module Reference


This document describes every user-facing module in the desktop launcher and its corresponding CLI behavior.

## Full Pipeline

**Purpose:** Perform the normal first-pass workflow in one operation.

**Inputs:** Evidence path, case path, optional UTC date range for the reporting/URL stage, worker count.

**Processing:** Creates or loads the case, ingests supported sources, parses and stores messages and attachments, indexes URL strings for the selected set, then writes core reports and a URL report.

**Outputs:** A completion-timestamped pipeline report directory containing message, attachment, error, and URL rollups. Ingestion artifacts remain in the case tree and SQLite.

**Use when:** Starting a new case or adding a new evidence batch and immediately producing rollups.

## Ingest Data

**Purpose:** Parse evidence into the case without generating the complete analyst report set.

**Supported sources:** PST, EML, MSG, or directories containing them.

**Key behavior:**

- Hashes each source with SHA-256 and MD5.
- Uses `readpst -e -t e` for PST extraction.
- Stores loose EML/MSG source bytes in canonical case paths.
- Parses headers, recipients, dates, bodies, Received hops, Authentication-Results, attachments, and parser defects.
- Stores attachment bytes by hash.
- Does not follow URLs or execute content.

**Outputs:** Updated SQLite, source records, canonical source copies, PST-derived EMLs, attachment artifacts, logs, and error records.

## Generate Reports

**Purpose:** Produce analyst-facing rollups from the current SQLite index.

**Selection:** All messages or a supported message selector.

**Outputs:**

- `messages.csv`
- `messages.json`
- `attachments.csv`
- `errors.csv`

The message rollup records both `attachment_count` and `url_count`, plus `url_indexed` so an unprocessed message can be distinguished from one containing zero URLs.

## Set Scope

**Purpose:** Save a named logical date selection without copying messages.

**Inputs:** Scope name, start timestamp, end timestamp.

**Processing:** Resolves the range to message hashes and stores the criteria and membership in SQLite.

**Outputs:** A named scope available to reports, exports, and Phish Hunt.

**Important:** Scope membership is fixed at creation. Recreate the scope after ingesting additional messages that should belong to it.

## Phish Hunt

**Purpose:** Apply a configurable set of static indicators to a required scope or date range.

**Inputs:** Case, exact selection, optional run name, output root, and a complete `config.json`.

**Processing:** Evaluates enabled factors against stored message, recipient, authentication, URL, attachment, HTML, and case-history data. No URL or IP is contacted and no attachment is reopened or executed during scoring.

**Score:** Uncapped additive integer centered at zero. The higher the score in the output CSV, the more likely the message is to match the configured phishing indicators.

**Outputs:**

- `phish_hunt.csv`
- `phish_hunt_details.csv`
- `phish_hunt.json`
- `scoring_config.json`
- `run_manifest.json`
- SQLite run/result/detail records

**Starter configurations:** External, Internal, and General phishing. These are reviewable heuristics, not calibrated models.

## Evaluate Phishing Email

**Purpose:** Explain which Phish Hunt factors match one email and create a reusable starter configuration.

**Inputs:** Existing case `message_sha256` or new EML/MSG file; optional case-history override.

**Processing modes:**

- **Case message:** all relevant factors use the selected case.
- **External file matching a case hash:** uses the existing case message.
- **External file not in case:** standalone factors only by default.
- **Override enabled:** case-history factors compare with a temporary clone of the selected case.

**Outputs:**

- `evaluation.csv`
- `evaluation_details.csv`
- `evaluation.json`
- `matched_factors_config.json`
- `run_manifest.json`

The generated config enables only factors that returned `YES` and assigns a starter weight of 10. It must be reviewed before reuse.

## String Search

**Purpose:** Find a literal, case-insensitive string in selected local case content.

**Sources:**

- Every SQLite field.
- Exported message `review.txt` files under a selected directory.
- Text-based reports (`.csv`, `.json`, `.txt`, `.md`, `.log`).

**Date behavior:** The optional date range limits only message-associated SQLite rows. It does not limit exported text or report files.

**Outputs:** `string_search.csv`, `string_search.json`, and `run_manifest.json` in a unique run directory.

**Limitations:** No regex, fuzzy, stemming, semantic, OCR, binary search, or network lookup.

## Get URLs

**Purpose:** Extract URL-like strings from stored plain text and HTML and produce a normalized report.

**Processing:** Parses message bodies, records displayed text and actual href where available, performs bounded deterministic decoding of supported Safe Links/Proofpoint wrappers, normalizes URL components, and stores URL rows in SQLite.

**Outputs:** Completion-timestamped `urls.csv`; updated `url_count` and `url_indexed` in `messages`.

**SharePoint field:** `contains_sharepoint_reference` is yes/no only. Legitimate-host and internal/external analysis is performed by Phish Hunt factors.

## Export Attachments

**Purpose:** Report selected attachments and optionally copy their inert bytes to an analyst-friendly tree.

**Inputs:** Message selection, output base, optional copy destination, optional case-insensitive extension filter.

**Processing:** Reads only stored metadata and artifact bytes. It never opens, renders, mounts, extracts, decrypts, launches, or executes an attachment.

**Outputs:** `attachments.csv` and, when selected, copied files grouped by sanitized message subject. `exported_path` correlates copied bytes to report rows.

## Export Messages

**Purpose:** Create review packages containing selected EMLs and plain-text summaries.

**Inputs:** One required message selector and output base.

**Outputs:** Subject-derived per-message folders plus root `summary.csv` and `manifest.json`.

`review.txt` contains headers, recipients, dates, sender-IP evidence, authentication results, Received hops, body text, and attachment metadata. Threadsaw does not render HTML or launch the EML.

## Diagnostics

**Purpose:** Report runtime readiness and fixed security posture.

**Checks:** Python/runtime version, `readpst`, optional MSG parser, runtime-denial installation, case path writability, database journal mode, and SQLite integrity/health when a case is supplied.

Diagnostics do not alter evidence. Database recovery may occur only when opening a legacy WAL case that cannot be safely used in place; originals are backed up first.


---

# CLI Reference


## Global syntax

```text
threadsaw [--version] [--quiet] <command> [options]
```

`--quiet` suppresses progress messages written to stderr; final JSON remains on stdout.

## Commands

### `threadsaw ingest`

Hash, extract, parse, and index PST/EML/MSG sources.

**Syntax:** `--input PATH --case PATH [--no-recursive] [--workers N]`

- Input may be a PST, EML, MSG, file tree, or directory containing supported sources.
- PST is extracted with the allowlisted `readpst` executable. Loose EML/MSG files are copied into the case.
- `--workers` controls parsing workers; it does not enable network activity.

### `threadsaw report`

Write message, attachment, and error rollups.

**Syntax:** `--case PATH [--output PATH] [selector]`

- Without a selector, reports all indexed messages.
- Outputs `messages.csv`, `messages.json`, `attachments.csv`, and `errors.csv` in a new timestamped directory.

### `threadsaw urls`

Extract and report URL strings without retrieving them.

**Syntax:** `--case PATH [--output PATH] [selector | --phish-hunt-report CSV --min-score N]`

- Without a selector, processes all indexed messages.
- URL rows are stored in SQLite and `url_count`/`url_indexed` are updated.
- The report contains `contains_sharepoint_reference=yes|no`; internal/external SharePoint logic belongs to Phish Hunt.

### `threadsaw attachments`

Report attachments and optionally copy inert bytes.

**Syntax:** `--case PATH --output PATH [--copy-files] [--copy-output PATH] [--extension EXT] [selector | hunt threshold]`

- `--extension` is case-insensitive, repeatable, and accepts comma-separated values.
- `--copy-files` copies bytes but never opens or executes them.
- A hunt-threshold selector reads only message hashes and scores from the selected `phish_hunt.csv`.

### `threadsaw export-messages`

Export EML/review text packages.

**Syntax:** `--case PATH --output PATH selector`

- A selector is required.
- The output package includes EML, `review.txt`, `summary.csv`, and `manifest.json`.

### `threadsaw scope create`

Create a named immutable date selection.

**Syntax:** `--case PATH --name NAME --start ISO --end ISO`

- The range is start-inclusive and end-exclusive.
- The scope stores the resolved message-hash set, so later messages are not silently added.

### `threadsaw scope list`

List named scopes and counts.

**Syntax:** `--case PATH`

- Outputs JSON containing name, criteria, creation time, and message count.

### `threadsaw phish-hunt-preset`

Print or export a bundled preset config.

**Syntax:** `--name external|internal|general [--output FILE]`

- Writes a complete 66-factor `config.json` document.
- Organization-specific factors remain off until configured.

### `threadsaw phish-hunt`

Score a required date range or named scope.

**Syntax:** `--case PATH [--output-root PATH] [--config FILE] [--run-name NAME] (--scope NAME | --start ISO --end ISO)`

- Exactly one scope or full date range is required; `--all` is intentionally unavailable.
- Ranges longer than seven days generate a warning.
- The higher the score in `phish_hunt.csv`, the more likely the message is to match the configured indicators.

### `threadsaw phish-hunt-list`

List recorded Phish Hunt runs.

**Syntax:** `--case PATH`

- Reads run metadata stored in SQLite and returns JSON.

### `threadsaw string-search`

Literal case-insensitive search across selected local sources.

**Syntax:** `--case PATH --query TEXT [--database] [--exported-text-dir PATH] [--reports] [--start ISO --end ISO] [--output-root PATH]`

- At least one of database, exported text, or reports must be selected.
- The date range applies only to message-associated SQLite rows.
- Search is literal substring matching after case folding; no regex, fuzzy, semantic, or network lookup.

### `threadsaw evaluate-phishing-email`

Evaluate one indexed message or external EML/MSG.

**Syntax:** `--case PATH (--sha256 HASH | --email-file PATH) [--allow-case-history] [--output-root PATH]`

- Existing hashes use case context.
- External files are evaluated in an isolated temporary case.
- `--allow-case-history` is meaningful only when the file belongs to the same mailbox population.

### `threadsaw run`

Ingest, index URLs, and produce core reports.

**Syntax:** `--input PATH --case PATH [--start ISO --end ISO] [--workers N]`

- Combines ingestion, URL indexing, and core report generation.
- Optional start/end limits the URL/report selection after the entire source has been ingested.

### `threadsaw doctor`

Report dependencies, guardrails, and optional case health.

**Syntax:** `[--case PATH]`

- Checks Python, `readpst`, optional MSG support, runtime guardrail posture, and case/database readiness.

## Message selectors

- `--sha256 HASH` — one indexed EML SHA-256.
- `--sha256-csv FILE` — CSV with `message_sha256`, `sha256`, or exactly one column.
- `--scope NAME` — named scope.
- `--start ISO --end ISO` — UTC-aware range, start inclusive/end exclusive.
- `--all` — all indexed messages where supported.
- `--phish-hunt-report CSV --min-score N` — URL/attachment selection by score.

Normal selectors cannot be combined with a hunt-threshold selector.

## Output and progress behavior

Progress is written to stderr and final machine-readable JSON to stdout. Report and export paths are completion-timestamped and collision-safe. A user-supplied output path is a base/template, not a file that will be overwritten.

## Exit codes

- `0` — operation completed.
- `2` — invalid request, missing dependency, database error, or one or more ingestion errors.
- `3` — a valid message-export selector matched no messages.

## Examples

```bash
threadsaw run --input ./evidence --case ./case --workers 4
threadsaw scope create --case ./case --name july-week-one --start 2026-07-01T00:00:00Z --end 2026-07-08T00:00:00Z
threadsaw phish-hunt --case ./case --scope july-week-one --config ./general_phishing.json
threadsaw urls --case ./case --phish-hunt-report ./case/reports/phish_hunt/<run>/phish_hunt.csv --min-score 50
threadsaw attachments --case ./case --all --extension zip,iso --output ./case/reports/archive-attachments --copy-files
threadsaw string-search --case ./case --query "wire instructions" --database --reports
threadsaw evaluate-phishing-email --case ./case --email-file ./suspect.eml
```


---

# Configuration Reference


## `case.json`

`case.json` contains the case identity, creation metadata, Threadsaw configuration, and fixed security-policy information. A representative configuration section is:

```json
{
  "config": {
    "trusted_authserv_ids": ["mx.example.com"],
    "trusted_received_hosts": ["mx.example.com"],
    "organization_domains": ["example.com"],
    "default_date_policy": "best"
  }
}
```

### `trusted_authserv_ids`

Authentication-Results records are marked trusted only when the `authserv-id` matches configured values. SPF, DKIM, DMARC, and ARC failure evaluators use trusted stored results only.

### `trusted_received_hosts`

Used to identify a trusted Received boundary and its timestamp/IP evidence. Empty configuration yields unknown classifications rather than guessing.

### `organization_domains`

Provides organization context for reporting and analyst configuration. Phish Hunt lookalike factors use their own explicit parameters so a saved hunt remains self-contained.

### `default_date_policy`

Controls the best available message date selection. Threadsaw preserves raw and normalized alternatives so analysts can review the source used.

Security prohibitions are not configurable. No case setting can enable networking, URL retrieval, browser launch, or attachment execution.

## Phish Hunt `config.json`

A configuration is a data-only JSON document. It cannot contain Python, SQL, shell commands, or executable expressions.

```json
{
  "config_version": 1,
  "name": "General phishing email hunt",
  "preset": "general",
  "factors": [
    {
      "factor_id": "reply_to_domain_mismatch",
      "enabled": true,
      "weight": 25,
      "effect_mode": "risk_when_yes",
      "parameters": {}
    }
  ],
  "notes": "Review before use."
}
```

A complete exported configuration contains all 66 visible factor IDs. Disabled factors normally use weight 0. Unknown factor IDs are rejected except for the hidden removed legacy factor retained for backward compatibility.

## Effect modes

- `risk_when_yes` — YES contributes `+weight`.
- `trust_when_yes` — YES contributes `-weight`.

Weights are non-negative integers with no arbitrary upper cap. UNKNOWN, NOT_APPLICABLE, ERROR, and NO contribute zero.

## Score interpretation

The score is not a probability. It is the sum of enabled factor contributions under one exact configuration. **The higher the score in the output CSV, the more likely the message is to match the configured phishing indicators.** Negative scores indicate that enabled trust-oriented factors outweighed risk-oriented factors.

Preserve the configuration hash and `scoring_config.json` before comparing or reproducing a run.

## Parameters

Only factors requiring analyst input include parameters. Current parameter types include text, multiline lists, integer thresholds, and fixed choices. Examples:

- Legitimate organization domains.
- Legitimate SharePoint host.
- Exact URL or attachment count.
- Date discrepancy threshold in hours.
- Minimum subdomain depth.
- Percent-encoding and Base64-like length thresholds.
- Attachment type match field/value.

Missing required parameters normally produce UNKNOWN rather than a guessed result.

## Bundled presets

### External phishing

Enabled factors: 58. Emphasizes external sender/domain novelty, deceptive URLs, active HTML, executable/shortcut attachments, and authentication failure. Same-domain sender/recipient context is modestly trust-reducing.

### Internal phishing

Enabled factors: 54. Emphasizes unusual behavior within an internal-looking message. Same-domain sender/recipient context is risk-increasing because compromised internal accounts are in scope.

### General phishing

Enabled factors: 57. Balanced starting point. Ambiguous same-domain context is disabled.

Factors requiring organization-specific domains, SharePoint hosts, exact counts, or campaign-specific attachment values remain off until configured.

## Import, export, and CLI use

The GUI imports and exports complete JSON documents. The CLI executes them directly:

```bash
threadsaw phish-hunt --case ./case --scope review-window --config ./general_phishing.json
```

Export a bundled preset:

```bash
threadsaw phish-hunt-preset --name general --output general_phishing.json
```

## Compatibility

A 0.6.0/earlier `encrypted_archive` setting is migrated to `attachment_archive`. The removed unique-URL-domain-count factor is accepted only as a hidden legacy entry and contributes zero/UNKNOWN. The three removed unsupported factors are not part of the Version 1 catalog and should be deleted from hand-edited configurations.


---

# Database and Outputs


## Case directory layout

```text
case/
  case.json
  threadsaw.sqlite3
  logs/
  extracted/
  sources/eml/
  sources/msg/
  artifacts/attachments/
  selections/
  configs/phish_hunt/
  reports/
    phish_hunt/
    string_search/
    evaluate_phishing_email/
  exports/
```

SQLite is authoritative. Generated reports and exports can be recreated unless the source representation or configuration has changed.

## SQLite connection policy

- `journal_mode=DELETE`
- `synchronous=FULL`
- foreign keys enabled
- 30-second busy timeout
- in-memory temporary store
- automatic schema migration for older compatible cases

## Tables

| Table | Function |
|---|---|
| `sources` | One row per observed or generated source file, including provenance hashes, canonical path, parser, status, and parent relationship. |
| `messages` | One row per unique indexed EML representation, containing normalized headers, dates, bodies, counts, derivation status, and parse defects. |
| `message_sources` | Many-to-many linkage between a message and the source files from which it was observed or derived. |
| `recipients` | Normalized To, Cc, and Bcc recipients with display name, address, and domain. |
| `received_hops` | Ordered Received-header values, parsed timestamps, observed sender IP strings, and trusted-boundary classification. |
| `authentication_results` | Stored Authentication-Results records and normalized SPF/DKIM/DMARC/ARC values, with trust classification. |
| `attachments` | Attachment metadata, hashes, content declaration, artifact path, static executable observation, and status. |
| `urls` | Offline-extracted URL occurrences, displayed/actual values, wrapper decoding, hostname/domain fields, and SharePoint-reference flag. |
| `scopes` | Named selection criteria. |
| `scope_messages` | Fixed message membership for named scopes. |
| `errors` | Non-fatal and fatal processing errors with stage and source/message correlation. |
| `phish_hunt_runs` | Run-level selection, normalized configuration, hash, status, paths, timestamps, and version. |
| `phish_hunt_results` | One score summary per message per run. |
| `phish_hunt_factor_results` | One detailed factor result per message per run. |

## Key message fields

- `message_sha256` — SHA-256 of the indexed EML bytes.
- `format` — EML or derived representation type.
- `derivation_status` — whether the indexed EML is original or derived.
- `selected_date_utc` and `selected_date_source` — date chosen for selection/reporting.
- `trusted_received_utc` — Received timestamp from a configured trusted boundary when available.
- `attachment_count` — attachments counted during ingestion.
- `url_count` — stored URL occurrences after URL indexing.
- `url_indexed` — 0 when URL indexing has not been established; 1 after processing.
- `defects_json` — parser defects preserved rather than silently discarded.

## Core report files

### `messages.csv / messages.json`

One row/object per message, with normalized context and counts.
```text
message_sha256, internet_message_id, selected_date_utc, selected_date_source, header_date_utc, top_received_utc, trusted_received_utc, date_discrepancy_seconds, from_address, recipient_addresses, from_domain, reply_to, reply_to_domain, return_path, return_path_domain, from_reply_to_mismatch, from_return_path_mismatch, to_addresses, cc_addresses, bcc_addresses, subject, trusted_boundary_ip, spf_client_ip, claimed_originating_ip, topmost_received_ip, bottommost_received_ip, spf_result, dkim_result, dmarc_result, arc_result, authserv_id, auth_trusted, attachment_count, url_count, url_indexed, has_attachments, body_text_source, format, derivation_status, eml_path, parse_defects
```

### `attachments.csv`

One row per attachment. `exported_path` is populated when bytes are copied.
```text
message_sha256, sender_email, recipient_addresses, message_date_utc, subject, trusted_boundary_ip, spf_client_ip, claimed_originating_ip, topmost_received_ip, bottommost_received_ip, part_index, original_filename, safe_filename, content_type_declared, size_bytes, sha256, md5, executable_format, artifact_path, exported_path, status
```

### `errors.csv`

One row per recorded processing error.
```text
error_id, source_path, message_sha256, stage, error_type, error_detail, recorded_utc
```

### `urls.csv`

One row per URL occurrence. SharePoint is represented only by `contains_sharepoint_reference`.
```text
message_sha256, sender_email, recipient_addresses, message_date_utc, subject, trusted_boundary_ip, spf_client_ip, claimed_originating_ip, topmost_received_ip, bottommost_received_ip, source_part, displayed_text, display_target_mismatch, raw_url, normalized_url, wrapper_type, decoded_target_url, hostname, registrable_domain, registrable_domain_method, contains_sharepoint_reference
```

### `string_search.csv`

One row per field or line match.
```text
source_kind, source_name, row_identifier, message_sha256, field_name, line_number, matched_value, context, date_filter_applied
```

### `evaluation.csv`

One summary row for the evaluated message.
```text
selected_date_utc, score, from_address, recipient_addresses, subject, message_sha256, internet_message_id, selected_date_source, header_date_utc, top_received_utc, trusted_received_utc, date_discrepancy_seconds, from_domain, reply_to, reply_to_domain, return_path, return_path_domain, from_reply_to_mismatch, from_return_path_mismatch, to_addresses, cc_addresses, bcc_addresses, trusted_boundary_ip, spf_client_ip, claimed_originating_ip, topmost_received_ip, bottommost_received_ip, spf_result, dkim_result, dmarc_result, arc_result, authserv_id, auth_trusted, attachment_count, url_count, url_indexed, has_attachments, body_text_source, format, derivation_status, eml_path, parse_defects, positive_points, negative_points, evaluated_factor_count, unknown_factor_count, evaluation_mode, case_history_enabled
```

### `evaluation_details.csv`

One row per factor.
```text
message_sha256, factor_id, factor_label, category, subcategory, computational_load, requires_case_history, answer, points, weight, effect_mode, evidence, source, status, reason, evaluator_version
```

### `phish_hunt.csv`

One row per selected message.
```text
selected_date_utc, score, from_address, recipient_addresses, subject, message_sha256, internet_message_id, selected_date_source, header_date_utc, top_received_utc, trusted_received_utc, date_discrepancy_seconds, from_domain, reply_to, reply_to_domain, return_path, return_path_domain, from_reply_to_mismatch, from_return_path_mismatch, to_addresses, cc_addresses, bcc_addresses, trusted_boundary_ip, spf_client_ip, claimed_originating_ip, topmost_received_ip, bottommost_received_ip, spf_result, dkim_result, dmarc_result, arc_result, authserv_id, auth_trusted, attachment_count, url_count, url_indexed, has_attachments, body_text_source, format, derivation_status, eml_path, parse_defects, positive_points, negative_points, evaluated_factor_count, unknown_factor_count, top_score_reasons, phish_hunt_run_id, config_name, config_hash, case_id
```

### `phish_hunt_details.csv`

One row per factor per message.
```text
phish_hunt_run_id, case_id, message_sha256, factor_id, factor_label, answer, points, weight, effect_mode, evidence, source, status, reason, evaluator_version
```

## Other generated files

| File | Purpose |
|---|---|
| `manifest.json` / `run_manifest.json` | Input selection, timestamps, output names, counts, version, and provenance for an export or analysis run. |
| `scoring_config.json` | Exact normalized Phish Hunt configuration used for a run. |
| `phish_hunt.json` | JSON form of the main score report. |
| `evaluation.json` | Single-email summary and factor details. |
| `matched_factors_config.json` | Starter configuration containing factors that returned YES. |
| `review.txt` | Plain-text message review representation inside an exported message folder. |
| `summary.csv` | Message-level summary for an exported-message package. |

## CSV safety

Values beginning with spreadsheet formula-control characters are prefixed for safer viewing in spreadsheet applications. Reports are written atomically. This reduces accidental formula execution but does not replace normal handling of untrusted data.

## Source and artifact preservation

Loose EML and MSG inputs are copied byte-for-byte into canonical hash-named paths. PST files are not duplicated because they can be very large; the EMLs generated by `readpst` are retained under the case extraction tree. Attachment bytes are stored by SHA-256 under `artifacts/attachments/`.


---

# Evaluator Reference


Threadsaw includes 66 visible, operational, static evaluators: 24 Inherently Risky and 42 Situational. Computational-load labels describe work performed during scoring, not work already completed during ingestion.

Load distribution: 24 Light, 29 Moderate, 13 Heavy, and 0 Extreme.

## Shared answer and scoring semantics

- **YES** — the condition matched; points are added or subtracted according to effect mode.
- **NO** — the evaluator had sufficient data and the condition did not match.
- **UNKNOWN** — evidence or a required parameter was missing, untrusted, or inconclusive.
- **NOT_APPLICABLE** — intentionally skipped, especially for external standalone emails without case history.
- **ERROR** — evaluator failure; zero points and full detail retained.

All evaluators are offline. URL evaluators inspect stored strings only; attachment evaluators use stored metadata/static classifications and do not launch or execute files.

## Load levels

- **Light:** simple message/header/authentication lookup or local string comparison.
- **Moderate:** related URL, attachment, recipient, or HTML rows for the current message.
- **Heavy:** historical correlation across earlier case messages. Runtime grows with total case size.
- **Extreme:** reserved for especially broad repeated correlation; no current visible evaluator is labeled Extreme.

## Preset matrix

| Factor | Category | Load | External | Internal | General |
|---|---|---:|---:|---:|---:|
| Reply-To domain differs from From domain | Inherently Risky | Light | +25 on YES | +25 on YES | +25 on YES |
| Display name contains an email address with a different domain | Inherently Risky | Light | +35 on YES | +30 on YES | +35 on YES |
| Sender domain resembles a configured legitimate organization domain | Inherently Risky | Moderate | Off | Off | Off |
| Sender domain resembles a recipient domain but does not match | Inherently Risky | Moderate | +35 on YES | +25 on YES | +30 on YES |
| Trusted DMARC check failed | Inherently Risky | Light | +30 on YES | +20 on YES | +30 on YES |
| Trusted DKIM check failed | Inherently Risky | Light | +15 on YES | +10 on YES | +15 on YES |
| Trusted SPF check failed | Inherently Risky | Light | +20 on YES | +15 on YES | +20 on YES |
| Displayed URL domain differs from actual domain | Inherently Risky | Moderate | +30 on YES | +30 on YES | +30 on YES |
| URL uses a literal IP address | Inherently Risky | Moderate | +30 on YES | +30 on YES | +30 on YES |
| URL contains misleading user-information before the hostname | Inherently Risky | Moderate | +40 on YES | +40 on YES | +40 on YES |
| URL uses a non-standard network port | Inherently Risky | Moderate | +15 on YES | +15 on YES | +15 on YES |
| URL uses a potentially dangerous URI scheme | Inherently Risky | Moderate | +40 on YES | +40 on YES | +40 on YES |
| URL hostname embeds a configured legitimate domain outside the true registrable domain | Inherently Risky | Moderate | Off | Off | Off |
| URL uses an obfuscated numeric IP-address representation | Inherently Risky | Moderate | +40 on YES | +40 on YES | +40 on YES |
| Attachment contains executable or script content | Inherently Risky | Light | +50 on YES | +50 on YES | +50 on YES |
| Attachment filename uses a double extension | Inherently Risky | Light | +35 on YES | +35 on YES | +35 on YES |
| Attachment filename contains Unicode direction-control or invisible characters | Inherently Risky | Light | +35 on YES | +35 on YES | +35 on YES |
| Executable or script attachment has no filename extension | Inherently Risky | Light | +45 on YES | +45 on YES | +45 on YES |
| Attachment is a shortcut or Internet shortcut file | Inherently Risky | Light | +45 on YES | +45 on YES | +45 on YES |
| Attachment is a disk-image or container format | Inherently Risky | Light | +30 on YES | +30 on YES | +30 on YES |
| HTML form is embedded in the message body | Inherently Risky | Moderate | +35 on YES | +35 on YES | +35 on YES |
| HTML body contains an automatic redirect | Inherently Risky | Moderate | +35 on YES | +35 on YES | +35 on YES |
| HTML body contains an embedded frame or active-object element | Inherently Risky | Moderate | +40 on YES | +40 on YES | +40 on YES |
| HTML body contains script code or JavaScript event handlers | Inherently Risky | Moderate | +45 on YES | +45 on YES | +45 on YES |
| Return-Path domain differs from From domain | Situational | Light | +10 on YES | +10 on YES | +10 on YES |
| Sender address is newly observed in the case | Situational | Heavy | +10 on YES | +5 on YES | +5 on YES |
| Sender domain is newly observed in the case | Situational | Heavy | +15 on YES | Off | +10 on YES |
| Sender infrastructure IP is newly observed for that sender | Situational | Heavy | Off | +10 on YES | Off |
| Reply-To address is newly observed for that sender | Situational | Heavy | +15 on YES | +20 on YES | +10 on YES |
| Return-Path domain is newly observed for that sender | Situational | Heavy | +5 on YES | +10 on YES | +5 on YES |
| Sender uses a common free-email provider | Situational | Light | +15 on YES | Off | +10 on YES |
| Sender email domain contains Punycode | Situational | Light | +20 on YES | +15 on YES | +15 on YES |
| Sender header address differs from visible From address | Situational | Moderate | +10 on YES | +10 on YES | +10 on YES |
| Corroborated reply to an existing thread | Situational | Heavy | -10 on YES | Off | -5 on YES |
| Prior sender-recipient relationship | Situational | Heavy | -10 on YES | Off | -5 on YES |
| Prior sender and normalized subject pair | Situational | Heavy | -5 on YES | Off | -5 on YES |
| Subject appears to be a reply, but no thread-reference headers are present | Situational | Moderate | +10 on YES | +10 on YES | +10 on YES |
| Thread-reference headers do not match any earlier message in the case | Situational | Heavy | +10 on YES | +10 on YES | +10 on YES |
| Trusted ARC check failed | Situational | Light | +5 on YES | +5 on YES | +5 on YES |
| Authentication results conflict across headers | Situational | Moderate | +15 on YES | +15 on YES | +15 on YES |
| Message date differs substantially from trusted Received time | Situational | Light | +10 on YES | +10 on YES | +10 on YES |
| Message-ID is missing or malformed | Situational | Light | +5 on YES | +5 on YES | +5 on YES |
| Message-ID domain differs from visible From domain | Situational | Light | +5 on YES | +5 on YES | +5 on YES |
| SharePoint link differs from configured legitimate SharePoint host | Situational | Moderate | Off | Off | Off |
| External SharePoint tenant is newly observed in the case | Situational | Heavy | Off | Off | Off |
| Exact number of URLs in message | Situational | Moderate | Off | Off | Off |
| URL uses a known shortening service | Situational | Moderate | +10 on YES | +10 on YES | +5 on YES |
| URL hostname contains Punycode | Situational | Moderate | +20 on YES | +20 on YES | +15 on YES |
| URL destination domain is newly observed in the case | Situational | Heavy | +10 on YES | +5 on YES | +5 on YES |
| URL destination domain is newly observed for that sender | Situational | Heavy | +10 on YES | +15 on YES | +10 on YES |
| URL hostname has unusually deep subdomain nesting | Situational | Moderate | +10 on YES | +10 on YES | +10 on YES |
| URL contains another full URL inside its query string or fragment | Situational | Moderate | +10 on YES | +10 on YES | +10 on YES |
| URL uses plain HTTP rather than HTTPS | Situational | Moderate | +10 on YES | +10 on YES | +5 on YES |
| URL contains unusually heavy percent-encoding | Situational | Moderate | +5 on YES | +5 on YES | +5 on YES |
| URL contains a large Base64-like encoded value | Situational | Moderate | +5 on YES | +5 on YES | +5 on YES |
| URL contains a recipient email address | Situational | Moderate | +10 on YES | +10 on YES | +5 on YES |
| URL destination domain differs from sender domain | Situational | Moderate | +5 on YES | +10 on YES | +5 on YES |
| Exact number of attachments in message | Situational | Light | Off | Off | Off |
| Attachment type matches a configured value | Situational | Moderate | Off | Off | Off |
| Attachment type is newly observed for that sender | Situational | Heavy | +10 on YES | +15 on YES | +10 on YES |
| Attachment is an archive | Situational | Light | +10 on YES | +10 on YES | +10 on YES |
| Message contains an attached email message | Situational | Light | +5 on YES | +5 on YES | +5 on YES |
| Sender and recipient share the same domain | Situational | Light | -15 on YES | +25 on YES | Off |
| Sender address mimics a recipient local part on another domain | Situational | Moderate | +20 on YES | +15 on YES | +20 on YES |
| Message contains no visible recipient address | Situational | Light | +5 on YES | +5 on YES | +5 on YES |
| Message contains recipients only in BCC | Situational | Light | +5 on YES | +5 on YES | +5 on YES |

## Inherently Risky

### Sender and Header Deception

#### Reply-To domain differs from From domain

- **Factor ID:** `reply_to_domain_mismatch`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1

Checks whether the registrable domain in Reply-To differs from the visible From domain.

**Matching or potentially suspicious example(s)**

- From: accounts@legitcompany.com; Reply-To: paymentdesk@external.test

**Nonmatching or potentially legitimate example(s)**

- From: alerts@company.com; Reply-To: support@company.com

**Interpretation caution:** Mailing platforms, ticketing systems, and outsourced support services can legitimately use another Reply-To domain.

**Default presets**

- External: +25 on YES
- Internal: +25 on YES
- General: +25 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Display name contains an email address with a different domain

- **Factor ID:** `display_name_embedded_email_domain_mismatch`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1

Extracts email-like text from the sender display name and compares its domain with the actual sender address domain.

**Matching or potentially suspicious example(s)**

- From: "janesmith@legitcompany.com" <janesmith@external.test>

**Nonmatching or potentially legitimate example(s)**

- From: "Jane Smith" <janesmith@legitcompany.com>

**Default presets**

- External: +35 on YES
- Internal: +30 on YES
- General: +35 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender domain resembles a configured legitimate organization domain

- **Factor ID:** `sender_domain_lookalike_configured`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1

Compares the sender domain with analyst-supplied legitimate domains using conservative local lookalike checks.

**Matching or potentially suspicious example(s)**

- legitcornpany.com resembles configured legitcompany.com

**Nonmatching or potentially legitimate example(s)**

- Exact match legitcompany.com is not flagged.

**Interpretation caution:** Similar names can belong to unrelated legitimate organizations. Configure only domains relevant to the investigation.

**Parameters**

- Legitimate organization domains; name `legitimate_domains`; type multiline

**Default presets**

- External: Off
- Internal: Off
- General: Off

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender domain resembles a recipient domain but does not match

- **Factor ID:** `sender_domain_lookalike_recipient`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** recipient data

Compares the sender domain with recipient domains and flags a conservative lookalike mismatch.

**Matching or potentially suspicious example(s)**

- From billing@legitcornpany.com to employee@legitcompany.com

**Nonmatching or potentially legitimate example(s)**

- Exact sender/recipient domain matches are not flagged.

**Default presets**

- External: +35 on YES
- Internal: +25 on YES
- General: +30 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Security Check Failures

#### Trusted DMARC check failed

- **Factor ID:** `trusted_dmarc_fail`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** trusted authentication-result classification

Uses only a trusted, stored Authentication-Results record that explicitly reports DMARC fail.

**Matching or potentially suspicious example(s)**

- dmarc=fail from a configured trusted authentication service

**Nonmatching or potentially legitimate example(s)**

- Missing, none, or untrusted results return UNKNOWN rather than YES.

**Default presets**

- External: +30 on YES
- Internal: +20 on YES
- General: +30 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Trusted DKIM check failed

- **Factor ID:** `trusted_dkim_fail`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** trusted authentication-result classification

Uses only a trusted, stored Authentication-Results record that explicitly reports DKIM fail.

**Matching or potentially suspicious example(s)**

- dkim=fail from a configured trusted authentication service

**Nonmatching or potentially legitimate example(s)**

- No DKIM signature is UNKNOWN, not a failure.

**Default presets**

- External: +15 on YES
- Internal: +10 on YES
- General: +15 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Trusted SPF check failed

- **Factor ID:** `trusted_spf_fail`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** trusted authentication-result classification

Uses stored trusted SPF results. FAIL, SOFTFAIL, and PERMERROR can match; TEMPERROR and missing results are UNKNOWN.

**Matching or potentially suspicious example(s)**

- spf=fail client-ip=203.0.113.5

**Nonmatching or potentially legitimate example(s)**

- spf=pass does not trigger; missing SPF is UNKNOWN.

**Default presets**

- External: +20 on YES
- Internal: +15 on YES
- General: +20 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### URL Deception and Obfuscation

#### Displayed URL domain differs from actual domain

- **Factor ID:** `displayed_url_domain_mismatch`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks links whose visible text itself looks like a URL/domain and compares it with the actual destination stored by Threadsaw.

**Matching or potentially suspicious example(s)**

- Visible text: https://login.company.com; actual href: https://attacker.test/login

**Nonmatching or potentially legitimate example(s)**

- A security gateway may rewrite the actual href while leaving the original URL visible.

**Interpretation caution:** This can produce false positives when the organization rewrites URLs. Disable this factor in URL-rewriting environments.

**Default presets**

- External: +30 on YES
- Internal: +30 on YES
- General: +30 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL uses a literal IP address

- **Factor ID:** `url_literal_ip`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks whether a stored URL directly uses an IPv4 or IPv6 address instead of a hostname.

**Matching or potentially suspicious example(s)**

- http://192.0.2.25/login
- https://[2001:db8::25]/document

**Nonmatching or potentially legitimate example(s)**

- Some internal appliances use IP-address URLs.

**Default presets**

- External: +30 on YES
- Internal: +30 on YES
- General: +30 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL contains misleading user-information before the hostname

- **Factor ID:** `url_userinfo_misdirection`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks URL userinfo before @, which can make the left side look like the destination while the true host follows @.

**Matching or potentially suspicious example(s)**

- https://login.legitcompany.com@malicious.test/account

**Default presets**

- External: +40 on YES
- Internal: +40 on YES
- General: +40 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL uses a non-standard network port

- **Factor ID:** `url_nonstandard_port`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks explicit web ports other than HTTP 80 or HTTPS 443 without connecting to the host.

**Matching or potentially suspicious example(s)**

- https://example.test:8443/login

**Nonmatching or potentially legitimate example(s)**

- Some legitimate internal or development applications use non-standard ports.

**Default presets**

- External: +15 on YES
- Internal: +15 on YES
- General: +15 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL uses a potentially dangerous URI scheme

- **Factor ID:** `url_dangerous_scheme`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks a bundled conservative list of schemes that may invoke scripts, local resources, applications, or unusual protocol handlers.

**Matching or potentially suspicious example(s)**

- file://
- smb://
- javascript:
- data:
- ms-msdt:
- search-ms:

**Nonmatching or potentially legitimate example(s)**

- mailto: and tel: are not included by default.

**Default presets**

- External: +40 on YES
- Internal: +40 on YES
- General: +40 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL hostname embeds a configured legitimate domain outside the true registrable domain

- **Factor ID:** `url_embeds_legitimate_domain`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks for an analyst-supplied legitimate domain placed misleadingly in subdomain labels while another registrable domain controls the host.

**Matching or potentially suspicious example(s)**

- microsoft.com.login.attacker.test (actual registrable domain attacker.test)

**Nonmatching or potentially legitimate example(s)**

- login.microsoft.com is a genuine subdomain and is not flagged.

**Parameters**

- Legitimate domains; name `legitimate_domains`; type multiline

**Default presets**

- External: Off
- Internal: Off
- General: Off

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL uses an obfuscated numeric IP-address representation

- **Factor ID:** `url_obfuscated_numeric_ip`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Recognizes local-only numeric IPv4 forms such as integer, hexadecimal, octal, or mixed-radix host text.

**Matching or potentially suspicious example(s)**

- http://2130706433/
- http://0x7f000001/

**Default presets**

- External: +40 on YES
- Internal: +40 on YES
- General: +40 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Attachment Deception and Executable Content

#### Attachment contains executable or script content

- **Factor ID:** `attachment_executable_or_script`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored executable/script classification

Reads the executable/script classification already stored during ingestion or attachment reporting. It never rescans the file during Phish Hunt.

**Matching or potentially suspicious example(s)**

- PE executable, PowerShell, JavaScript, VBScript, batch, or shell script classification

**Nonmatching or potentially legitimate example(s)**

- UNKNOWN means the earlier check was not run or was inconclusive.

**Default presets**

- External: +50 on YES
- Internal: +50 on YES
- General: +50 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Attachment filename uses a double extension

- **Factor ID:** `attachment_double_extension`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Checks filenames that may disguise the final extension while excluding common compound formats such as tar.gz.

**Matching or potentially suspicious example(s)**

- invoice.pdf.exe
- payment.docx.lnk

**Nonmatching or potentially legitimate example(s)**

- archive.tar.gz is not flagged by itself.

**Default presets**

- External: +35 on YES
- Internal: +35 on YES
- General: +35 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Attachment filename contains Unicode direction-control or invisible characters

- **Factor ID:** `attachment_unicode_controls`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Inspects stored filename code points for bidirectional overrides, zero-width characters, and related invisible formatting controls.

**Matching or potentially suspicious example(s)**

- A filename visually appearing as invoice.pdf while hidden characters reorder its true suffix.

**Nonmatching or potentially legitimate example(s)**

- International text may legitimately contain some formatting controls, though they are unusual in filenames.

**Default presets**

- External: +35 on YES
- Internal: +35 on YES
- General: +35 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Executable or script attachment has no filename extension

- **Factor ID:** `executable_without_extension`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored executable/script classification

Combines the existing executable/script classification with the stored filename and does not rescan bytes.

**Matching or potentially suspicious example(s)**

- Filename Invoice; stored class Windows PE executable

**Default presets**

- External: +45 on YES
- Internal: +45 on YES
- General: +45 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Attachment is a shortcut or Internet shortcut file

- **Factor ID:** `attachment_shortcut`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Checks stored extensions/types for shortcut and launcher formats without resolving or launching them.

**Matching or potentially suspicious example(s)**

- Document.lnk
- Secure Portal.url
- Payment.website

**Default presets**

- External: +45 on YES
- Internal: +45 on YES
- General: +45 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Attachment is a disk-image or container format

- **Factor ID:** `attachment_disk_image`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Checks stored attachment metadata for ISO, IMG, VHD, VHDX, DMG, and similar mountable container formats.

**Matching or potentially suspicious example(s)**

- payload.iso
- documents.vhdx

**Default presets**

- External: +30 on YES
- Internal: +30 on YES
- General: +30 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Active HTML Content

#### HTML form is embedded in the message body

- **Factor ID:** `html_form`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored HTML body

Statically parses the stored HTML body for form and input elements. It never renders or submits the form.

**Matching or potentially suspicious example(s)**

- <form><input type=password><button type=submit>

**Default presets**

- External: +35 on YES
- Internal: +35 on YES
- General: +35 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### HTML body contains an automatic redirect

- **Factor ID:** `html_auto_redirect`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored HTML body

Statically checks the stored HTML for automatic redirect mechanisms such as meta refresh. Destinations remain inert text.

**Matching or potentially suspicious example(s)**

- <meta http-equiv="refresh" content="0;url=https://example.test/login">

**Default presets**

- External: +35 on YES
- Internal: +35 on YES
- General: +35 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### HTML body contains an embedded frame or active-object element

- **Factor ID:** `html_embedded_active_object`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored HTML body

Checks for iframe, frame, object, embed, and applet elements without rendering or retrieving referenced content.

**Matching or potentially suspicious example(s)**

- <iframe src=...>
- <object data=...>

**Default presets**

- External: +40 on YES
- Internal: +40 on YES
- General: +40 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### HTML body contains script code or JavaScript event handlers

- **Factor ID:** `html_script_or_event_handlers`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored HTML body

Checks stored HTML for script elements and inline on* event attributes. No script is executed.

**Matching or potentially suspicious example(s)**

- <script>...</script>
- <img onerror=...>

**Default presets**

- External: +45 on YES
- Internal: +45 on YES
- General: +45 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

## Situational

### Sender, Domain, and Infrastructure History

#### Return-Path domain differs from From domain

- **Factor ID:** `return_path_domain_mismatch`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1

Compares the registrable Return-Path and From domains.

**Matching or potentially suspicious example(s)**

- From billing@company.com; Return-Path bounce@unrelated.test

**Nonmatching or potentially legitimate example(s)**

- Legitimate mailing platforms commonly use a separate bounce domain.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender address is newly observed in the case

- **Factor ID:** `sender_address_new`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1

Searches all earlier dated messages in the case for the same normalized sender address.

**Matching or potentially suspicious example(s)**

- First appearance of a purported vendor address during the campaign window.

**Nonmatching or potentially legitimate example(s)**

- Every legitimate correspondent is new once.

**Default presets**

- External: +10 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender domain is newly observed in the case

- **Factor ID:** `sender_domain_new`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1

Searches all earlier dated messages for any sender using the same registrable domain.

**Matching or potentially suspicious example(s)**

- A new lookalike vendor domain first appears during the hunt.

**Nonmatching or potentially legitimate example(s)**

- A new legitimate vendor also introduces a new domain.

**Default presets**

- External: +15 on YES
- Internal: Off
- General: +10 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender infrastructure IP is newly observed for that sender

- **Factor ID:** `sender_ip_new_for_sender`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** trusted boundary IP classification

Compares the current trusted-boundary IP with earlier IPs for the same sender. No lookup or geolocation occurs.

**Matching or potentially suspicious example(s)**

- Established sender suddenly arrives through an unseen trusted-boundary IP.

**Nonmatching or potentially legitimate example(s)**

- Cloud mail providers routinely rotate outbound IP addresses.

**Default presets**

- External: Off
- Internal: +10 on YES
- General: Off

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Reply-To address is newly observed for that sender

- **Factor ID:** `reply_to_new_for_sender`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1

Compares the current Reply-To address/domain with earlier messages from the same sender.

**Matching or potentially suspicious example(s)**

- A known vendor suddenly directs replies to an external mailbox.

**Nonmatching or potentially legitimate example(s)**

- A sender may legitimately change help-desk or billing addresses.

**Default presets**

- External: +15 on YES
- Internal: +20 on YES
- General: +10 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Return-Path domain is newly observed for that sender

- **Factor ID:** `return_path_new_for_sender`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1

Compares the current Return-Path domain with earlier messages from the same sender.

**Matching or potentially suspicious example(s)**

- A known sender suddenly uses unfamiliar delivery infrastructure.

**Nonmatching or potentially legitimate example(s)**

- Legitimate senders switch email-service providers.

**Default presets**

- External: +5 on YES
- Internal: +10 on YES
- General: +5 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender uses a common free-email provider

- **Factor ID:** `sender_free_email_provider`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** bundled provider list

Compares the sender domain with a bundled, versioned static list of common consumer email providers. No live lookup occurs.

**Matching or potentially suspicious example(s)**

- A purported corporate executive writes from a consumer mailbox.

**Nonmatching or potentially legitimate example(s)**

- Individuals and small organizations legitimately use consumer providers.

**Default presets**

- External: +15 on YES
- Internal: Off
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender email domain contains Punycode

- **Factor ID:** `sender_domain_punycode`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1

Checks the sender domain for xn-- labels and decodes them locally for review.

**Matching or potentially suspicious example(s)**

- billing@xn--legitcompny-...

**Nonmatching or potentially legitimate example(s)**

- Internationalized domains legitimately use Punycode.

**Default presets**

- External: +20 on YES
- Internal: +15 on YES
- General: +15 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender header address differs from visible From address

- **Factor ID:** `sender_header_mismatch`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored raw headers

Parses the stored raw Sender header and compares it with the visible From address.

**Matching or potentially suspicious example(s)**

- From payments@company.com; Sender delivery@external.test

**Nonmatching or potentially legitimate example(s)**

- Delegated sending and mailing platforms legitimately use Sender.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Thread and Relationship History

#### Corroborated reply to an existing thread

- **Factor ID:** `corroborated_thread_reply`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** stored Message-ID and thread-reference headers

Requires a thread-reference match to an earlier case message, plausible normalized subject continuity, and participant overlap.

**Matching or potentially suspicious example(s)**

- Can be weighted upward when a campaign is known to hijack real threads.

**Nonmatching or potentially legitimate example(s)**

- A well-corroborated earlier thread can be weighted downward, but compromised mailboxes can still reply in genuine threads.

**Default presets**

- External: -10 on YES
- Internal: Off
- General: -5 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Prior sender-recipient relationship

- **Factor ID:** `prior_sender_recipient`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** recipient data

Searches earlier messages for the same sender and at least one matching recipient address.

**Matching or potentially suspicious example(s)**

- Can be positive for a campaign targeting established relationships.

**Nonmatching or potentially legitimate example(s)**

- Can be negative when prior correspondence is reassuring.

**Default presets**

- External: -10 on YES
- Internal: Off
- General: -5 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Prior sender and normalized subject pair

- **Factor ID:** `prior_sender_subject`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1

Searches earlier messages for the same sender and subject after removing common reply/forward prefixes and normalizing whitespace.

**Matching or potentially suspicious example(s)**

- A known campaign repeatedly reuses a sender-subject signature.

**Nonmatching or potentially legitimate example(s)**

- Recurring legitimate notifications commonly reuse subjects.

**Default presets**

- External: -5 on YES
- Internal: Off
- General: -5 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Subject appears to be a reply, but no thread-reference headers are present

- **Factor ID:** `reply_subject_without_references`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** stored raw headers

Checks for a reply-style subject prefix while In-Reply-To and References are absent.

**Matching or potentially suspicious example(s)**

- Re: Updated payment instructions with no thread headers.

**Nonmatching or potentially legitimate example(s)**

- Exports and some mail clients may omit threading headers.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Thread-reference headers do not match any earlier message in the case

- **Factor ID:** `unmatched_thread_references`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** stored Message-ID and thread-reference headers

Checks whether present In-Reply-To/References values fail to match any earlier case Message-ID.

**Matching or potentially suspicious example(s)**

- Fabricated thread references may not match collected history.

**Nonmatching or potentially legitimate example(s)**

- The referenced message may simply be outside the collected mailbox data.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Authentication and Routing Context

#### Trusted ARC check failed

- **Factor ID:** `trusted_arc_fail`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** trusted authentication-result classification

Uses only a stored trusted ARC result that explicitly reports failure.

**Matching or potentially suspicious example(s)**

- arc=fail from a configured trusted authentication service

**Nonmatching or potentially legitimate example(s)**

- Forwarding and intermediary modification can produce legitimate ARC problems.

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Authentication results conflict across headers

- **Factor ID:** `authentication_conflict`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** multiple authentication-result records

Compares multiple stored Authentication-Results records for pass/fail contradictions and records trusted status.

**Matching or potentially suspicious example(s)**

- Untrusted header says DMARC pass while trusted gateway says fail.

**Nonmatching or potentially legitimate example(s)**

- Multiple legitimate gateways can observe different results after forwarding or modification.

**Default presets**

- External: +15 on YES
- Internal: +15 on YES
- General: +15 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Message date differs substantially from trusted Received time

- **Factor ID:** `date_received_discrepancy`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** trusted Received timestamp

Uses the existing stored date discrepancy and a user-configured absolute threshold.

**Matching or potentially suspicious example(s)**

- Header Date differs from trusted Received time by 53 hours.

**Nonmatching or potentially legitimate example(s)**

- Queue delays, migrations, and bad clocks can also create discrepancies.

**Parameters**

- Difference threshold (hours); name `threshold_hours`; type integer; default `24`; minimum `0`

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Message-ID is missing or malformed

- **Factor ID:** `message_id_missing_or_malformed`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1

Uses the stored Message-ID and conservative local syntax validation. No domain lookup is performed.

**Matching or potentially suspicious example(s)**

- No Message-ID or Message-ID: invoice-12345

**Nonmatching or potentially legitimate example(s)**

- Drafts, locally created MSG files, and unusual systems may omit it.

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Message-ID domain differs from visible From domain

- **Factor ID:** `message_id_domain_mismatch`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1

Compares registrable domains in the stored Message-ID and From address.

**Matching or potentially suspicious example(s)**

- From billing@company.com; Message-ID <id@unrelated.test>

**Nonmatching or potentially legitimate example(s)**

- Marketing, ticketing, and delegated platforms often generate their own Message-ID domain.

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### URL Characteristics

#### SharePoint link differs from configured legitimate SharePoint host

- **Factor ID:** `sharepoint_host_mismatch`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Runs only when the analyst supplies a legitimate SharePoint hostname. Any stored URL containing SharePoint keywords but not matching that host can trigger.

**Matching or potentially suspicious example(s)**

- Configured company.sharepoint.com; message links to unfamiliar.sharepoint.com

**Nonmatching or potentially legitimate example(s)**

- External collaboration commonly uses another organization's SharePoint tenant.

**Parameters**

- Legitimate SharePoint host; name `legitimate_sharepoint_host`; type text

**Default presets**

- External: Off
- Internal: Off
- General: Off

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### External SharePoint tenant is newly observed in the case

- **Factor ID:** `external_sharepoint_tenant_new`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Requires a configured legitimate host, identifies a mismatched SharePoint tenant, and checks whether it appeared in earlier case messages.

**Matching or potentially suspicious example(s)**

- A newly introduced external tenant appears during a credential-phishing campaign.

**Nonmatching or potentially legitimate example(s)**

- A new collaboration partner also introduces a new tenant.

**Parameters**

- Legitimate SharePoint host; name `legitimate_sharepoint_host`; type text

**Default presets**

- External: Off
- Internal: Off
- General: Off

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL uses a known shortening service

- **Factor ID:** `url_shortener`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing, bundled shortener list

Compares stored URL hosts with a bundled, versioned local list of common shortening services. No redirect is followed.

**Matching or potentially suspicious example(s)**

- bit.ly or tinyurl.com link conceals the destination.

**Nonmatching or potentially legitimate example(s)**

- Shorteners are common in legitimate notifications and social media.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL hostname contains Punycode

- **Factor ID:** `url_punycode`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks stored URL hostnames for xn-- labels and decodes locally for analyst review.

**Matching or potentially suspicious example(s)**

- A lookalike hostname encoded with Punycode.

**Nonmatching or potentially legitimate example(s)**

- Internationalized domains legitimately use Punycode.

**Default presets**

- External: +20 on YES
- Internal: +20 on YES
- General: +15 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL destination domain is newly observed in the case

- **Factor ID:** `url_domain_new_case`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks whether any destination registrable domain was absent from all earlier case messages.

**Matching or potentially suspicious example(s)**

- New credential-harvesting infrastructure appears in the hunt window.

**Nonmatching or potentially legitimate example(s)**

- Legitimate correspondence regularly introduces new domains.

**Default presets**

- External: +10 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL destination domain is newly observed for that sender

- **Factor ID:** `url_domain_new_sender`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks whether an established sender links to a destination domain never seen in that sender's earlier messages.

**Matching or potentially suspicious example(s)**

- A known vendor suddenly links to an unfamiliar host.

**Nonmatching or potentially legitimate example(s)**

- Vendors adopt new platforms and services.

**Default presets**

- External: +10 on YES
- Internal: +15 on YES
- General: +10 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL hostname has unusually deep subdomain nesting

- **Factor ID:** `url_deep_subdomains`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Counts labels before the registrable domain and compares with an analyst-supplied minimum depth.

**Matching or potentially suspicious example(s)**

- secure.login.account.company.attacker.test

**Nonmatching or potentially legitimate example(s)**

- Cloud and enterprise services can use deeply nested legitimate hostnames.

**Parameters**

- Minimum subdomain depth; name `minimum_depth`; type integer; default `4`; minimum `1`

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL contains another full URL inside its query string or fragment

- **Factor ID:** `url_nested_url`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Locally decodes bounded query/fragment values and checks for an embedded complete HTTP(S) URL without following either URL.

**Matching or potentially suspicious example(s)**

- https://redirector.test/?target=https%3A%2F%2Fattacker.test

**Nonmatching or potentially legitimate example(s)**

- Marketing, authentication, and security rewriting commonly embed destination URLs.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL uses plain HTTP rather than HTTPS

- **Factor ID:** `url_plain_http`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks stored web URLs for the http scheme and never connects to them.

**Matching or potentially suspicious example(s)**

- http://example.test/login

**Nonmatching or potentially legitimate example(s)**

- Legacy and internal systems may legitimately use HTTP.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL contains unusually heavy percent-encoding

- **Factor ID:** `url_heavy_percent_encoding`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Counts %xx sequences in stored URL text and compares with an analyst-supplied threshold using a bounded local decoder.

**Matching or potentially suspicious example(s)**

- A path or query with many encoded characters obscures its visible content.

**Nonmatching or potentially legitimate example(s)**

- Tracking and authentication links frequently use heavy encoding.

**Parameters**

- Minimum percent-encoded sequences; name `minimum_sequences`; type integer; default `8`; minimum `1`

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL contains a large Base64-like encoded value

- **Factor ID:** `url_base64_like`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Checks URL path/query/fragment values for long Base64 or URL-safe Base64 patterns; decoding is local, bounded, and never executed.

**Matching or potentially suspicious example(s)**

- A long encoded query value conceals recipient or destination data.

**Nonmatching or potentially legitimate example(s)**

- Authentication and tracking links often contain long tokens.

**Parameters**

- Minimum encoded-value length; name `minimum_length`; type integer; default `40`; minimum `8`

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL contains a recipient email address

- **Factor ID:** `url_contains_recipient_email`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing, recipient data

Checks literal and locally decoded URL text for a complete recorded recipient email address.

**Matching or potentially suspicious example(s)**

- Credential link includes employee%40company.com as a parameter.

**Nonmatching or potentially legitimate example(s)**

- Unsubscribe and account-management links often contain recipient identifiers.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### URL destination domain differs from sender domain

- **Factor ID:** `url_domain_differs_sender`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Compares every stored destination registrable domain with the sender domain. No URLs are omitted.

**Matching or potentially suspicious example(s)**

- A purported vendor links to unrelated credential infrastructure.

**Nonmatching or potentially legitimate example(s)**

- Organizations routinely link to Microsoft, Google, payment processors, and other third parties.

**Default presets**

- External: +5 on YES
- Internal: +10 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Campaign Signatures

#### Exact number of URLs in message

- **Factor ID:** `exact_url_count`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** URL indexing

Matches the exact complete URL count recorded by Threadsaw. No URL types or duplicates are omitted from the stored count.

**Matching or potentially suspicious example(s)**

- Known campaign samples consistently contain exactly 2 URLs.

**Nonmatching or potentially legitimate example(s)**

- This is a campaign signature, not a universal risk signal.

**Parameters**

- Expected URL count; name `expected_count`; type integer; default `0`; minimum `0`

**Default presets**

- External: Off
- Internal: Off
- General: Off

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Exact number of attachments in message

- **Factor ID:** `exact_attachment_count`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Matches the exact complete attachment count stored by Threadsaw. No attachment types are omitted.

**Matching or potentially suspicious example(s)**

- Known samples consistently contain exactly one attachment.

**Nonmatching or potentially legitimate example(s)**

- This is a campaign signature rather than an inherent risk indicator.

**Parameters**

- Expected attachment count; name `expected_count`; type integer; default `0`; minimum `0`

**Default presets**

- External: Off
- Internal: Off
- General: Off

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Attachment Characteristics

#### Attachment type matches a configured value

- **Factor ID:** `attachment_type_match`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Matches either a stored filename extension or stored detected type using a case-insensitive exact comparison.

**Matching or potentially suspicious example(s)**

- Known campaign consistently delivers HTML attachments.

**Nonmatching or potentially legitimate example(s)**

- The same type may be routine in another environment.

**Parameters**

- Match field; name `match_field`; type choice; default `Filename extension`; choices: Filename extension, Detected file type
- Value; name `match_value`; type text

**Default presets**

- External: Off
- Internal: Off
- General: Off

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Attachment type is newly observed for that sender

- **Factor ID:** `attachment_type_new_sender`
- **Computational load:** Heavy
- **Requires case history:** Yes
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Compares current attachment types with earlier messages from the same sender using existing metadata only.

**Matching or potentially suspicious example(s)**

- A sender that historically sends PDF/XLSX suddenly sends HTML.

**Nonmatching or potentially legitimate example(s)**

- Legitimate senders begin using new file formats.

**Default presets**

- External: +10 on YES
- Internal: +15 on YES
- General: +10 on YES

**Standalone-email behavior**

Returns NOT_APPLICABLE for a new standalone email unless the message matches the case or case-history override is enabled.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Attachment is an archive

- **Factor ID:** `attachment_archive`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Checks stored attachment filename extensions and declared MIME types for common archive formats. It does not open, extract, or inspect archive contents during scoring.

**Matching or potentially suspicious example(s)**

- A campaign consistently delivers ZIP, 7Z, RAR, TAR, GZ, BZ2, XZ, CAB, or similar archives.

**Nonmatching or potentially legitimate example(s)**

- Archives are commonly used for legitimate file transfer and software distribution.

**Interpretation caution:** This factor identifies archive packaging only; it does not determine whether the archive is encrypted, malicious, or safe.

**Default presets**

- External: +10 on YES
- Internal: +10 on YES
- General: +10 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Message contains an attached email message

- **Factor ID:** `attached_email`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** attachment metadata

Checks stored MIME type/extension metadata for EML, MSG, or message/rfc822 without recursively parsing it during scoring.

**Matching or potentially suspicious example(s)**

- An attached message conceals or reproduces campaign content.

**Nonmatching or potentially legitimate example(s)**

- Forwarding and abuse reporting commonly attach original emails.

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

### Recipient and Message Direction

#### Sender and recipient share the same domain

- **Factor ID:** `sender_recipient_same_domain`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** recipient data

Checks whether the sender registrable domain matches at least one To, CC, or preserved BCC recipient domain.

**Matching or potentially suspicious example(s)**

- Can be weighted upward during an internal-account-compromise hunt.

**Nonmatching or potentially legitimate example(s)**

- Can be weighted downward during an external-phishing hunt, but internal spoofing/compromise remains possible.

**Default presets**

- External: -15 on YES
- Internal: +25 on YES
- General: Off

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Sender address mimics a recipient local part on another domain

- **Factor ID:** `sender_mimics_recipient_localpart`
- **Computational load:** Moderate
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** recipient data

Checks whether sender and recipient share the same mailbox name before @ while their registrable domains differ.

**Matching or potentially suspicious example(s)**

- From janesmith@external.test to janesmith@company.com

**Nonmatching or potentially legitimate example(s)**

- Generic local parts such as info, billing, or support can legitimately recur across organizations.

**Default presets**

- External: +20 on YES
- Internal: +15 on YES
- General: +20 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Message contains no visible recipient address

- **Factor ID:** `no_visible_recipient`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** recipient data

Checks whether no usable To or CC address is present. It does not infer BCC use.

**Matching or potentially suspicious example(s)**

- Bulk campaign hides all visible recipients.

**Nonmatching or potentially legitimate example(s)**

- Mailing lists and privacy-preserving notifications often omit visible recipients.

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.

#### Message contains recipients only in BCC

- **Factor ID:** `bcc_only_recipients`
- **Computational load:** Light
- **Requires case history:** No
- **Evaluator version:** 1
- **Prerequisites:** preserved BCC data

Requires affirmative preserved BCC recipients plus no usable To or CC recipients. Missing BCC data returns UNKNOWN.

**Matching or potentially suspicious example(s)**

- Concealed-recipient campaign sent only through BCC.

**Nonmatching or potentially legitimate example(s)**

- Newsletters and privacy-sensitive communications can use BCC.

**Default presets**

- External: +5 on YES
- Internal: +5 on YES
- General: +5 on YES

**Standalone-email behavior**

Available without case history.

**Result handling**

YES/NO reflect the condition above. Missing or unusable prerequisite data produces UNKNOWN. The message remains in the detailed output for every answer.


---

# File Reference


This inventory describes every file shipped in the Version 1 source distribution. Generated wheels, case data, reports, exports, caches, and build directories are not source-distribution files.

## Root, launcher, and examples

| File | Function |
|---|---|
| `.dockerignore` | Excludes development/runtime clutter from the Docker build context. |
| `.gitignore` | Excludes virtual environments, caches, build products, and local case/evidence data from Git. |
| `CHANGELOG.md` | Chronological feature and behavior history through Version 1. |
| `Dockerfile` | Builds the network-isolated Threadsaw runtime with Python, `readpst`, optional MSG support, and a non-root user. |
| `LICENSE` | MIT license for the Threadsaw source. |
| `Makefile` | Convenience targets for install, tests, Docker build, and diagnostics. |
| `README.md` | Concise Version 1 overview, security boundary, quick start, and documentation entry point. |
| `compose.yaml` | Hardened Compose service definition without default evidence/case volume paths. |
| `examples/make_sample_eml.py` | Creates a small synthetic EML for smoke testing. |
| `examples/phish_hunt_presets/external_phishing.json` | Complete External phishing starter configuration. |
| `examples/phish_hunt_presets/general_phishing.json` | Complete General phishing starter configuration. |
| `examples/phish_hunt_presets/internal_phishing.json` | Complete Internal phishing starter configuration. |
| `examples/phish_hunt_prototype.json` | Historical minimal scoring configuration retained as an example/compatibility artifact. |
| `launcher/threadsaw_gui.py` | Complete Tkinter desktop launcher: workflow pages, two-row navigation, selectors, factor catalog UI, help, command preview, Docker execution, logs, and stop behavior. |
| `pyproject.toml` | Python build metadata, package version, dependencies, optional extras, and `threadsaw` console entry point. |

## Python package files

| File | Function | Key public entry points |
|---|---|---|
| `src/threadsaw/__init__.py` | Defines package version, project name, and motto. | Package metadata/import side effects only. |
| `src/threadsaw/__main__.py` | Allows `python -m threadsaw` to invoke the CLI. | Package metadata/import side effects only. |
| `src/threadsaw/attachments.py` | Queries attachment records, filters by original filename extension, writes reports, and copies inert artifact bytes into timestamped export trees. | `attachment_rows`, `export_attachment_report`, `export_attachment_run` |
| `src/threadsaw/case.py` | Creates, loads, and atomically updates `case.json` and the standard case directory structure. | `initialize_case`, `load_case`, `update_case` |
| `src/threadsaw/cli.py` | Defines the argparse command surface, selector validation, command dispatch, progress handling, and exit codes. | `build_parser`, `main` |
| `src/threadsaw/db.py` | Defines the SQLite schema, connection safety policy, compatible migrations, legacy WAL recovery, health checks, and error recording. | `connect_db`, `initialize_schema`, `database_health`, `record_error` |
| `src/threadsaw/doctor.py` | Checks runtime dependencies, filesystem readiness, database health, and the fixed security posture. | `run_doctor`, `os_access_writable` |
| `src/threadsaw/evaluate_email.py` | Evaluates one case or external EML/MSG against the Phish Hunt registry and writes summary, detail, manifest, and matching-factor config files. | `evaluate_phishing_email` |
| `src/threadsaw/exporter.py` | Builds timestamped message review packages containing EMLs, review text, summary CSV, and manifest JSON. | `export_messages` |
| `src/threadsaw/factor_catalog.py` | Holds the authoritative metadata for all visible Phish Hunt factors, help text, parameters, prerequisites, categories, and computational loads. | `factor_catalog_document` |
| `src/threadsaw/factor_evaluators.py` | Implements the 66 static factor evaluators and reusable header, URL, attachment, authentication, HTML, and history helpers. | `EVALUATORS registry`, `eval_* factor functions` |
| `src/threadsaw/ingest.py` | Orchestrates source discovery, hashing, PST extraction, EML/MSG parsing, database inserts, canonical copies, attachment artifacts, and errors. | `ingest_path` |
| `src/threadsaw/ip_fields.py` | Extracts IP-address strings from stored headers and separates trusted boundary, SPF client, claimed originating, topmost, and bottommost evidence. | `extract_ips`, `received_sender_ips`, `sender_ip_fields`, `enrich_sender_ip_rows` |
| `src/threadsaw/message_context.py` | Builds deduplicated recipient context for message, URL, attachment, and export rows. | `recipient_fields`, `enrich_recipient_rows` |
| `src/threadsaw/output_naming.py` | Creates staging paths and completion-timestamped, collision-safe final files/directories. | `completion_timestamp`, `timestamped_file`, `timestamped_directory`, `staging_file`, `staging_directory`, `finalize_file`, `finalize_directory`, `cleanup_staging` |
| `src/threadsaw/parsers/__init__.py` | Marks the parser package. | Package metadata/import side effects only. |
| `src/threadsaw/parsers/eml.py` | Parses EML/MIME data into normalized message and attachment dataclasses, dates, recipients, bodies, headers, and shallow executable-format observations. | `ParsedAttachment`, `ParsedMessage`, `parse_eml` |
| `src/threadsaw/parsers/msg.py` | Uses optional `extract-msg` to read MSG and produce a clearly labeled derived EmailMessage/EML representation. | `parse_msg` |
| `src/threadsaw/phish_hunt.py` | Validates configs, evaluates messages, calculates scores, stores run/result rows, writes reports, and reads score-threshold selections. | `FactorDefinition`, `prototype_default_config`, `all_factor_config`, `empty_preset_config`, `normalize_config`, `load_scoring_config`, `config_hash`, `evaluate_message`, `selection_span_days`, `run_phish_hunt`, `list_hunt_runs`, `read_hunt_report_selection` |
| `src/threadsaw/phish_hunt_presets.py` | Defines complete External, Internal, General, and Clear configurations and their weights/effect modes. | `preset_config`, `available_presets` |
| `src/threadsaw/progress.py` | Provides consistent stderr progress output and count-based progress updates. | `console_progress`, `ProgressCounter` |
| `src/threadsaw/reports.py` | Builds message/authentication/IP rollups and writes timestamped core CSV/JSON reports. | `auth_summary_for_message`, `message_rows`, `write_reports`, `write_timestamped_reports` |
| `src/threadsaw/security.py` | Installs runtime denials for networking, URL/browser launch, OS launch, and general subprocesses; exposes only allowlisted `readpst` execution. | `SecurityGuardrailError`, `install_runtime_guardrails`, `run_readpst`, `security_posture` |
| `src/threadsaw/selection.py` | Reads hash CSVs, resolves all supported selectors, and creates named scopes. | `read_message_hashes_csv`, `resolve_message_hashes`, `create_scope` |
| `src/threadsaw/string_search.py` | Performs literal case-insensitive searches across SQLite and selected text trees, then writes timestamped results and a manifest. | `search_sqlite`, `search_text_tree`, `run_string_search` |
| `src/threadsaw/urls.py` | Extracts URL strings from stored bodies, parses HTML links, decodes supported wrappers, normalizes components, stores URL rows, and writes reports. | `LinkParser`, `extract_urls`, `write_url_report`, `write_timestamped_url_report` |
| `src/threadsaw/util.py` | Shared time, hashing, filename, atomic-write, CSV-safety, path, and file-iteration utilities. | `utc_now`, `iso_utc`, `parse_iso8601`, `file_hashes`, `byte_hashes`, `safe_filename`, `human_folder_name`, `unique_path`, `excel_safe`, `atomic_write_text`, `atomic_write_json`, `atomic_write_csv`, `iter_files`, `relative_or_absolute` |

## Test files

| File | Function |
|---|---|
| `tests/test_attachment_extension_filter.py` | Verifies case-insensitive and comma-separated attachment filename-extension filtering. |
| `tests/test_cli.py` | Validates command parsing, selectors, removed init behavior, Phish Hunt ranges/scopes, and preset export. |
| `tests/test_counts_sharepoint_and_evaluators.py` | Checks URL/attachment counts, SharePoint yes/no report behavior, evaluator coverage, and representative evaluator outcomes. |
| `tests/test_database.py` | Exercises schema, compatibility columns, journal mode, and database health behavior. |
| `tests/test_evaluate_email.py` | Tests indexed and standalone email evaluation, case-history behavior, and generated matching configs. |
| `tests/test_launcher.py` | Tests GUI command construction, navigation, scrollability, factor help/load UI, selectors, and source-folder discovery. |
| `tests/test_phish_hunt.py` | Tests uncapped scoring, run isolation, presets, legacy factor handling, and archive-config migration. |
| `tests/test_security.py` | Asserts runtime denials, subprocess allowlisting, and source-level security invariants. |
| `tests/test_string_search.py` | Tests combined SQLite/exported-text/report search and date-filter labeling. |
| `tests/test_timestamped_outputs.py` | Confirms repeated reports and exports never overwrite completed outputs. |
| `tests/test_workflow.py` | End-to-end ingestion, reporting, export, recipient context, sender-IP fields, and error guidance tests. |

## Documentation files

| File | Function |
|---|---|
| `docs/ARCHITECTURE.md` | System components, data flow, security boundary, persistence, and analysis layers. |
| `docs/CLI_REFERENCE.md` | Complete command, option, selector, output, and exit-code reference. |
| `docs/CONFIGURATION_REFERENCE.md` | Case and Phish Hunt configuration fields, score semantics, parameters, presets, and compatibility. |
| `docs/DATABASE_AND_OUTPUTS.md` | Case layout, SQLite tables, report schemas, output files, and preservation behavior. |
| `docs/DECISIONS.md` | Architecture decision records and rationale. |
| `docs/DOCUMENTATION_INDEX.md` | Navigation hub for the complete Version 1 documentation set. |
| `docs/EVALUATE_PHISHING_EMAIL.md` | Specialized historical/reference note for the single-email module. |
| `docs/EVALUATOR_REFERENCE.md` | Authoritative detailed reference for all 66 evaluators and preset settings. |
| `docs/FILE_REFERENCE.md` | Inventory and purpose of every distributed source, test, example, infrastructure, and documentation file. |
| `docs/GUI.md` | Detailed launcher behavior and controls; retained as a specialized reference. |
| `docs/INSTALLATION_AND_DEPLOYMENT.md` | Docker, GUI, native CLI, dependencies, filesystem, and upgrade setup. |
| `docs/MODULE_REFERENCE.md` | Every user-facing module, its inputs, processing, outputs, and limitations. |
| `docs/PHISH_HUNT.md` | Specialized scoring-framework design and run behavior. |
| `docs/PHISH_HUNT_FACTOR_CATALOG.md` | Catalog alias synchronized with the Version 1 evaluator reference. |
| `docs/PROTOTYPE_STATUS.md` | Historical pre-Version-1 status record retained for traceability. |
| `docs/RELEASE_NOTES_0.2.2.md` | Historical release notes for Threadsaw 0.2.2. |
| `docs/RELEASE_NOTES_0.2.3.md` | Historical release notes for Threadsaw 0.2.3. |
| `docs/RELEASE_NOTES_0.2.4.md` | Historical release notes for Threadsaw 0.2.4. |
| `docs/RELEASE_NOTES_0.2.5.md` | Historical release notes for Threadsaw 0.2.5. |
| `docs/RELEASE_NOTES_0.3.0.md` | Historical release notes for Threadsaw 0.3.0. |
| `docs/RELEASE_NOTES_0.3.1.md` | Historical release notes for Threadsaw 0.3.1. |
| `docs/RELEASE_NOTES_0.3.2.md` | Historical release notes for Threadsaw 0.3.2. |
| `docs/RELEASE_NOTES_0.3.3.md` | Historical release notes for Threadsaw 0.3.3. |
| `docs/RELEASE_NOTES_0.4.0.md` | Historical release notes for Threadsaw 0.4.0. |
| `docs/RELEASE_NOTES_0.5.0.md` | Historical release notes for Threadsaw 0.5.0. |
| `docs/RELEASE_NOTES_0.6.0.md` | Historical release notes for Threadsaw 0.6.0. |
| `docs/RELEASE_NOTES_0.6.1.md` | Historical release notes for Threadsaw 0.6.1. |
| `docs/RELEASE_NOTES_1.0.0.md` | Official Version 1 changes and compatibility. |
| `docs/RELEASE_STATUS.md` | Current Version 1 capabilities, limitations, and claims. |
| `docs/ROADMAP.md` | Historical development roadmap and future candidates. |
| `docs/SECURITY_AND_FORENSICS.md` | Fixed offline/static-analysis guardrails and forensic-use cautions. |
| `docs/STRING_SEARCH.md` | Specialized historical/reference note for String Search. |
| `docs/TESTING_AND_VALIDATION.md` | Automated coverage, limits of testing, and recommended acceptance plan. |
| `docs/THREADSAW_1.0.0_MANUAL.md` | Consolidated Markdown source for the formatted Version 1 manual. |
| `docs/TROUBLESHOOTING.md` | Common installation, Docker, database, parsing, scoring, and output issues. |
| `docs/USER_GUIDE.md` | End-to-end analyst workflow and interpretation guide. |
| `docs/VALIDATION_PLAN.md` | Historical validation plan retained for traceability. |

## Generated distribution artifacts

- `Threadsaw_1.0.0.zip` — complete source distribution with documentation and examples.
- `threadsaw-1.0.0-py3-none-any.whl` — installable Python wheel.
- `Threadsaw_1.0.0_Manual.docx` — consolidated formatted manual.
- `Threadsaw_1.0.0_Documentation.zip` — standalone Markdown documentation plus the Word manual.

## Files created inside a case

Case files are described in `DATABASE_AND_OUTPUTS.md`. They are evidence derivatives and operational records, not part of the source distribution.


---

# Security and Forensic Posture


Threadsaw is a triage tool, not a malware sandbox, eDiscovery suite, or source of legal conclusions.

## Absolute prohibitions

Threadsaw must never:

- Resolve a hostname or IP address through DNS.
- Connect to an IP address or network service.
- Retrieve, follow, preview, open, or submit a URL.
- Follow redirects or verify a decoded wrapper target.
- Launch a browser or operating-system URL handler.
- Launch an attachment in an associated application.
- Execute an attachment, script, macro, document behavior, embedded object, or carved payload.
- Invoke a general-purpose shell or arbitrary child process.

These are fixed product rules, not configurable defaults.

## Permitted static operations

Threadsaw may:

- Read PST, EML, MSG, MIME-part, and attachment bytes.
- Decode MIME transfer encodings and parse headers/bodies.
- Extract IP-address and URL strings as inert text.
- Normalize and deterministically decode known URL-wrapper strings offline.
- Compute hashes and shallow file-signature observations.
- Copy original or derived bytes into review packages.
- Run the locally resolved `readpst` executable solely to convert PST records into EML representations.

A copied attachment remains potentially dangerous. Threadsaw does not mark it safe and never opens it.

## Enforcement layers

1. **Runtime denials:** The CLI blocks socket creation, DNS resolution, URL retrieval, browser launch, OS application launch, and general subprocess APIs.
2. **Process allowlist:** `readpst` is the sole child-process exception. It is resolved locally, invoked without a shell, receives closed standard input, runs with proxy variables removed, and has output captured.
3. **Container isolation:** Documented Docker commands use `--network none`, a read-only root filesystem, dropped capabilities, `no-new-privileges`, read-only evidence, and a dedicated writable case mount.
4. **Source audit tests:** Automated tests reject network-client imports and non-allowlisted subprocess imports.
5. **Roadmap constraint:** Network enrichment, document application launch, active rendering, and detonation are permanently excluded.

These controls reduce risk but are not a substitute for independent security review. Native libraries, the Python runtime, container runtime, and `readpst` remain part of the trusted computing base.

## Required forensic controls

- Evidence input should be mounted read-only.
- Original PST, EML, and MSG files are never rewritten.
- `message_sha256` is the SHA-256 of the indexed EML representation, not a branded identifier.
- An EML generated from MSG is labeled `derived-eml-from-msg`; the MSG remains the original source.
- Failed, unsupported, and malformed items are written to the `errors` table and report.
- CSV is an analyst view. SQLite and JSON preserve raw values; CSV cells are neutralized against spreadsheet-formula execution.
- Authentication results are recorded observations and are trusted only through explicit case configuration.
- URL reports record only whether a SharePoint reference is present. Internal/external ownership is not inferred in the URL module; configured Phish Hunt factors perform organization-specific host comparison.
- Static attachment indicators never produce a benign or malicious verdict.

## Honest handling of provenance

For loose EML and MSG, the original external path is recorded and a byte-for-byte canonical source copy is stored inside the case during ingestion. Later exports use that canonical copy. For PST, `readpst` constructs RFC 822/EML files from MAPI records; these are PST-derived EMLs, not byte-for-byte original messages from the PST. For MSG, Threadsaw creates a derived RFC 822 representation and retains the original MSG when exporting.

## Analyst responsibility

Threadsaw creates files that analysts may choose to inspect with other tools. That manual action occurs outside Threadsaw and outside its security guarantees. Exported attachments should be handled as hostile evidence in an appropriately isolated analyst environment.


Canonical source copying is a byte-copy operation only. Threadsaw does not open, render, follow, or execute copied message or attachment content.

## Sender-IP evidence fields

Sender-IP fields are derived only from message headers already present in the case. Threadsaw never resolves, geolocates, enriches, contacts, or connects to those addresses. `trusted_boundary_ip` depends on case configuration; `claimed_originating_ip` remains explicitly labeled as claimed. These values support filtering and review but do not establish the identity or location of a human sender.

## Phish Hunt security and interpretation

Phish Hunt does not add network behavior or active-content handling. Factors operate only on locally indexed metadata and static content. No factor may follow a URL, resolve or connect to an IP address, or open/execute an attachment. User configuration is data-only and cannot inject executable logic.

Scores are not probabilities, verdicts, or calibrated confidence levels. A score is meaningful only with the preserved configuration, evaluator versions, and selection manifest. Unknown or unavailable evidence contributes zero and remains visible in the factor-detail report.


## String Search and single-email evaluation

String Search performs literal local text comparison only. It does not invoke a shell, query a network service, or interpret matched strings as commands, URLs, or paths.

Evaluate Phishing Email may statically parse a supplied EML/MSG and run offline URL extraction in a temporary case. It never follows the extracted strings or launches attachment content. The optional case-history override copies the case database to local temporary storage and never inserts the external message into the actual case.


---

# Architecture


> **When you're looking for a needle in a haystack, you need a pitchfork.**

Threadsaw is a case-based, offline email triage pipeline. Source evidence is hashed and left unchanged. Messages are normalized into SQLite once; report, URL-string, scope, attachment, String Search, Evaluate Phishing Email, and export commands query that index.

## Invariant security boundary

The architecture treats the following as permanently out of scope:

- DNS lookups, IP connections, URL retrieval, redirects, previews, reputation calls, and live enrichment
- Browser or operating-system URL launch
- Launching an attachment in an associated application
- Executing an attachment, script, macro, embedded object, or extracted payload
- General-purpose child-process execution

Threadsaw may read and statically parse message and attachment bytes. The only child process permitted by the implementation is the locally resolved `readpst` executable for PST extraction. Runtime guards deny socket creation, DNS resolution, URL retrieval, browser launch, OS application launch, and general subprocess APIs. Docker adds `--network none` as defense in depth.

URL wrapper decoding is string transformation only. IP addresses are extracted as text only. Neither is followed, resolved, contacted, or submitted elsewhere.

## Version 1 boundaries

Implemented:

- Case initialization and SQLite schema
- Recursive EML ingestion
- PST extraction through `readpst -e -t e`, followed by EML ingestion
- Optional standalone MSG parsing through `extract-msg`, preserving available transport headers in a derived EML clearly labeled as derived
- SHA-256 of indexed EML bytes in the explicit `message_sha256` field, plus MD5 pivot hash
- UTC date normalization and start-inclusive/end-exclusive range selection
- Recipient, Received, Authentication-Results, body, attachment, and parser-defect indexing
- Byte-for-byte canonical case copies for loose EML/MSG sources and hash-addressed attachment storage
- Offline URL-string extraction from text and HTML; deterministic Safe Links and Proofpoint string decoding
- Named logical date scopes
- EML export by one SHA-256, SHA-256 CSV, date range, scope, or all messages
- Companion `review.txt`, `summary.csv`, and `manifest.json`
- Excel-oriented CSV safety and atomic report writes
- String Search across SQLite fields, exported review text, and reports
- Evaluate Phishing Email for one indexed message or isolated standalone EML/MSG, with matched-factor config generation
- Attachment report/export filename-extension filtering
- Docker packaging, dependency diagnostics, and security-posture diagnostics

Explicit Version 1 limitations:

- A complete Public Suffix List resolver is not bundled. Registrable domains are marked as heuristic.
- MSG conversion is a best-effort derived representation and requires the optional package.
- Trusted Received and Authentication-Results classifications require case configuration.
- PST delivery timestamps and original MAPI folder identifiers are not exposed by generated EMLs in a guaranteed way.
- No QR, static Office structure inspection, YARA, or archive-recursion functionality is included.
- Proofpoint decoding covers common query-string forms, not every historical rewrite version.
- Native MIME executable checks are shallow byte-signature/extension observations, not malware analysis.

## Data flow

```text
Read-only evidence
      |
Hash source files
      |
PST -> allowlisted readpst -> generated EML   Loose EML -> canonical case copy   Optional MSG -> canonical copy + derived EML
      |                                         |                         |
      +-----------------------------------------+-------------------------+
                                                |
                                       Parse and normalize
                                                |
                              SQLite + hash-addressed byte artifacts
                                                |
          +-------------------------------------+--------------------------------+
          |                                     |                                |
        reports                               scopes                           exports
          |                                     |                                |
     CSV / JSON                      fixed message SHA-256 set          EML + TXT + manifest

No network. No URL/IP following. No attachment launch or execution.
```

## Why NarrowDates was removed

Date narrowing is a query, not an extraction stage. The `scope` command preserves a named logical selection without copying messages. `export-messages` creates physical EML packages only when the analyst needs them.

## Message hash terminology

`message_sha256` is the SHA-256 of the indexed EML bytes. It is a transparent data field, not a Threadsaw- or Pitchfork-branded identifier. For a loose or PST-derived EML, it identifies that exact EML representation. For MSG, it identifies the clearly labeled derived EML while the original MSG has its own source SHA-256.

## Case portability

Loose EML and MSG source bytes are copied without transformation into hash-named files under `sources/eml` and `sources/msg`. The database retains both the original observed path and the canonical case path. This prevents later exports from depending on a host input mount that may have moved or been removed. PST inputs are not duplicated because they may be very large; their derived EMLs are already stored in the case extraction tree.

## Human-readable export folders

Export packages use sanitized, length-bounded subject lines for message directories. Copied attachments are grouped under the same subject-derived directory convention and retain sanitized original filenames. Hash values remain in reports and manifests for unambiguous correlation.


## SQLite host-filesystem policy

Case databases use `DELETE` rollback journaling, `synchronous=FULL`, and a bounded busy timeout. WAL is prohibited for normal operation because Docker Desktop cases commonly reside on host bind mounts. The desktop launcher never opens SQLite directly; it asks the containerized CLI for scope metadata.

## Phish Hunt scoring layer

`phish_hunt` is a database-backed analysis layer rather than a separate message parser. A run resolves a mandatory date range or named scope to `message_sha256` values, evaluates registered static factors against normalized SQLite rows, and stores run/result/detail records before writing analyst-facing CSV/JSON files.

Configurations contain only reviewed factor IDs and settings. Factor code remains part of Threadsaw; configuration files cannot execute Python, SQL, shell commands, or arbitrary expressions. Every execution receives a unique run ID and report folder, preserving prior runs and the exact normalized configuration.

Downstream URL and attachment threshold selection treats `phish_hunt.csv` only as a message-hash/score selection document. The selected case ID must match, and actual artifact/URL data is retrieved from SQLite.


## String Search layer

String Search reads selected local text sources only. SQLite rows are scanned as text values, exported message review TXT files are read recursively, and text-based report files can be included. Optional date filtering constrains message-associated SQLite tables but intentionally does not alter file-based search. Every execution finalizes to a unique timestamped report folder.

## Evaluate Phishing Email layer

Evaluate Phishing Email reuses the Phish Hunt factor registry. Existing message hashes evaluate against the selected case. External EML/MSG files are parsed in an isolated temporary case; historical factors are skipped unless the message matches an existing case record or the operator explicitly requests a temporary case-database clone. The real case is not modified by external-file evaluation.


---

# Testing and Validation


## Automated test suite

Run from the project root:

```bash
pytest -q
```

The Version 1 baseline contains tests for:

- Security guardrails that deny sockets, DNS, URL retrieval, browser launch, OS launch, and unapproved subprocess use.
- EML parsing, PST/MSG workflow boundaries, source hashing, attachment persistence, and report generation.
- Database initialization, migrations, rollback-journal posture, counts, and SharePoint report behavior.
- Message selection by hash, CSV, range, scope, all messages, and Phish Hunt threshold.
- Completion-timestamped outputs and collision avoidance.
- GUI command construction, module navigation, factor help/load controls, and no-default-volume Compose behavior.
- String Search across SQLite, exported review text, and reports.
- Evaluate Phishing Email for case messages and external files.
- Attachment extension filtering.
- Phish Hunt scoring, details, presets, legacy config migration, and all 66 evaluator mappings.

## What passing tests establishes

Passing tests demonstrates that the tested code paths behave as expected in the test environment. It does not establish:

- Complete compatibility with every PST or MSG producer.
- Complete MIME parsing across malformed or adversarial messages.
- Malware-detection capability.
- Legal admissibility or evidentiary completeness.
- Enterprise-scale performance.
- Independent security assurance.

## Recommended organizational acceptance testing

Before operational use, validate Threadsaw against representative data from the organization’s mail systems:

1. Small known-good EML set with expected headers, dates, recipients, URLs, and attachments.
2. PSTs from each expected Outlook/Exchange export process.
3. MSG files from expected Outlook versions if MSG is in scope.
4. Messages with trusted Authentication-Results and Received boundaries.
5. URL-rewriting environments to calibrate displayed-target mismatch behavior.
6. SharePoint tenants and configured legitimate domains.
7. Large-case runtime and disk-capacity tests.
8. Repeated-run output isolation and recovery after forced interruption.
9. Independent comparison with another parser or manual review for a sample.

## Reproducibility records

Retain:

- Threadsaw version and wheel/source hash.
- Container image digest when used.
- `case.json` and source hashes.
- SQLite database and database-recovery logs.
- Run manifests.
- Exact Phish Hunt `scoring_config.json` and config hash.
- Export manifests and report hashes generated by the organization’s normal evidence-handling process.


---

# Troubleshooting


## The GUI does not start

- Confirm Python 3.11+ is installed.
- Confirm Tkinter is present: `python -m tkinter` should open a small test window.
- Start Docker Desktop before launching Threadsaw.
- Run the launcher from the extracted project directory so `compose.yaml` is available.

## Docker cannot mount the evidence or case path

- Use an absolute path.
- On Windows/macOS, share the drive/folder with Docker Desktop.
- Avoid characters or shell quoting that alter the path.
- Ensure evidence is readable and the case directory is writable.

## `readpst` is missing

Run `threadsaw doctor`. In Docker, rebuild the supplied Dockerfile. In native mode, install the operating system’s `libpst`/`pst-utils` package and confirm `readpst` is on `PATH`.

## MSG files are rejected

Install optional MSG support with `pip install -e '.[msg]'`, or rebuild the default Docker image. MSG is a best-effort derived representation; inspect `errors.csv` for unsupported variants.

## The database is busy

Stop other Threadsaw containers or GUI operations using the same case. Close tools that directly opened `threadsaw.sqlite3`. Threadsaw waits up to 30 seconds, then reports a clear busy error.

## A legacy database reports disk I/O errors

Threadsaw may recover a former WAL database by copying it to local temporary storage, checkpointing, checking integrity, converting to DELETE mode, and replacing the case database. The original database and sidecars are preserved under `case/logs/database-backups/<timestamp>/`.

## URL count is zero but the message has links

Check `url_indexed`:

- `0` means URL indexing has not been established for that message.
- `1` with `url_count=0` means the URL module ran and stored no URL occurrences.

Rerun Get URLs or Full Pipeline for older cases.

## A trusted authentication factor returns UNKNOWN

Configure the correct `trusted_authserv_ids` in `case.json`. Threadsaw intentionally ignores untrusted Authentication-Results headers. Missing authentication is not treated as failure.

## A historical factor is NOT_APPLICABLE in Evaluate Phishing Email

The external EML/MSG does not match an existing case message and case-history override was not selected. This is expected. Enable override only when the message came from the same mailbox population as the case.

## A Phish Hunt factor appears noisy

Review its help dialog, false-positive notes, prerequisites, and weight. Common examples are URL rewriting, free-email senders, external conferencing links, plain HTTP, and sender-domain mismatch. Disable or reduce factors that are not meaningful in the environment.

## Phish Hunt is slow

Heavy factors search earlier records across the complete case. Use a well-indexed local case directory, avoid concurrent operations, and test on a representative scope. The selected range limits result messages, but historical comparison may still examine the broader case.

## A completed output was not written to the exact path entered

The path is a base name. Threadsaw adds a completion timestamp and, if necessary, collision suffix. Read the final JSON or GUI log for the actual path.

## Attachment files are not copied

Select the copy/export action or use `--copy-files`. Verify the extension filter. The report-only action intentionally writes metadata without copying bytes.

## String Search date range seems ignored for files

The range applies only to message-associated SQLite rows. Exported review text and report files have no reliable uniform message-date boundary, so they are searched without that filter and labeled accordingly.

## Reports display spreadsheet warnings or modified values

Threadsaw prefixes values that could be interpreted as spreadsheet formulas. This is deliberate CSV safety. Use JSON or SQLite when the exact raw leading character is required for analysis.


---

# Release Status


Version 1.0.0 is the first official release of the current Threadsaw GUI and CLI code line. It consolidates the features previously developed through 0.6.1 and adds complete operator, technical, file, database, and evaluator documentation.

## Included

- PST, EML, and optional MSG ingestion.
- Case-based SQLite normalization.
- Source and attachment hashing.
- Offline URL extraction and supported wrapper decoding.
- Core reports, message exports, attachment reports/exports, scopes, and String Search.
- Evaluate Phishing Email.
- Explainable Phish Hunt with 66 operational visible evaluators.
- External, Internal, and General starter configurations.
- Cross-platform Tkinter launcher and CLI.
- Fixed runtime security guardrails and network-disabled Docker configuration.
- Completion-timestamped, non-overwriting outputs.

## Important limitations

- Not independently security-audited.
- Not formally validated for legal admissibility.
- Not a malware scanner or sandbox.
- No live reputation, DNS, WHOIS, HTTP, redirect, or IP enrichment.
- No QR analysis, Office macro inspection, YARA, archive extraction/recursion, or attachment execution.
- Registrable-domain calculation is heuristic because a complete Public Suffix List is not bundled.
- MSG parsing and derived EML creation are best effort.
- Broad enterprise-scale performance has not been benchmarked.

## Version relationship

The analysis and database behavior in 1.0.0 is the approved 0.6.1 baseline, relabeled as the official Version 1 release. The version bump includes documentation and release-branding updates rather than a new scoring algorithm or schema migration.


---

# Release Notes 1.0.0


## Official Version 1 baseline

Threadsaw 1.0.0 promotes the approved 0.6.1 implementation to the first official release of the current GUI/CLI code line.

## Analysis capabilities

- 66 visible Phish Hunt factors with operational evaluators.
- External, Internal, and General starter configurations with reviewable weights and effect modes.
- Metadata-only archive identification; no archive opening or extraction.
- String Search, Evaluate Phishing Email, URL reporting, attachment extension filtering, message exports, scopes, and threshold-based downstream selection.
- URL and attachment counts in SQLite and message rollups.
- SharePoint URL reports limited to a yes/no reference field; ownership/tenant logic remains in Phish Hunt.

## Documentation

Added authoritative Version 1 references for:

- Installation and deployment.
- Analyst workflows and every GUI module.
- Complete CLI command/options reference.
- SQLite tables, case layout, report schemas, and outputs.
- `case.json` and Phish Hunt configuration.
- All 66 evaluator functions, examples, loads, prerequisites, and preset settings.
- Every file in the source distribution.
- Testing, validation boundaries, troubleshooting, and release status.

## Compatibility

- Existing 0.6.1 cases require no re-ingestion.
- Existing 0.6.1 configurations remain compatible.
- Package and GUI version changed to 1.0.0.
- No new database schema migration or factor-scoring change is introduced by the Version 1 promotion.
