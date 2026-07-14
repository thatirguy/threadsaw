# Threadsaw 1.3.0 Manual

This is the current operator manual for Threadsaw 1.3.0. The `THREADSAW_1.0.0_MANUAL.md` filename is retained so existing bookmarks and external links continue to work; the contents no longer describe only the 1.0.0 baseline.

Threadsaw is an offline, case-based email triage and phishing-risk analysis tool for PST, EML, and optionally MSG evidence. It helps analysts find and explain suspicious messages in Business Email Compromise and phishing investigations. Its desktop GUI displays the underlying CLI command for repeatable and scriptable workflows.

Threadsaw is an analyst-assistance tool. It does not determine that a message is malicious, replace evidence-handling procedures, or provide malware detonation or reputation services.

## Contents

1. [Security boundary](#1-security-boundary)
2. [Choose how to start Threadsaw](#2-choose-how-to-start-threadsaw)
3. [Evidence and case model](#3-evidence-and-case-model)
4. [Recommended investigation workflow](#4-recommended-investigation-workflow)
5. [Desktop GUI](#5-desktop-gui)
6. [Module reference](#6-module-reference)
7. [Practical investigation recipes](#7-practical-investigation-recipes)
8. [Selectors and date behavior](#8-selectors-and-date-behavior)
9. [CLI reference](#9-cli-reference)
10. [Case and hunt configuration](#10-case-and-hunt-configuration)
11. [Phish Hunt scoring and interpretation](#11-phish-hunt-scoring-and-interpretation)
12. [URL, attachment, archive, and QR analysis](#12-url-attachment-archive-and-qr-analysis)
13. [Database, reports, and exports](#13-database-reports-and-exports)
14. [Upgrading an older Version 1 case](#14-upgrading-an-older-version-1-case)
15. [Troubleshooting](#15-troubleshooting)
16. [Validation, limitations, and forensic use](#16-validation-limitations-and-forensic-use)
17. [Detailed references](#17-detailed-references)

## 1. Security boundary

Threadsaw treats URLs, hostnames, IP addresses, QR values, message content, and attachments as evidence, never as instructions.

It does not:

- resolve DNS names or make IP connections;
- retrieve, preview, follow, or submit URLs;
- open URLs in a browser or operating-system handler;
- launch attachments or execute scripts, macros, embedded objects, or archive members;
- mount disk images, decrypt archives, or test passwords;
- use remote reputation, WHOIS, sandbox, or enrichment services.

The only permitted child process is `readpst`, used to extract PST content into EML files. Arguments are passed without a shell. Native installations can set `THREADSAW_READPST` to a trusted absolute path whose basename is `readpst` or `readpst.exe`.

The supplied container posture adds the primary runtime isolation controls:

- networking disabled;
- read-only root filesystem;
- non-root user;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- process limit and bounded temporary filesystem;
- read-only evidence mount and writable case mount.

Python socket, subprocess, and browser guards are defense in depth, not a replacement for the container boundary.

Exported URL text and attachment bytes remain untrusted evidence. Review them only with controls appropriate to the investigation.

## 2. Choose how to start Threadsaw

Use the methods below from easiest to most complex.

### 2.1 Published container with the GUI

This is recommended for most PST and EML investigations. The published image is `ghcr.io/thatirguy/threadsaw:1.3.0` for `linux/amd64` and `linux/arm64`. It contains `readpst`, OpenCV, and pypdfium2/PDFium. It does not contain optional MSG support.

From the extracted Threadsaw source directory:

```powershell
docker compose pull
python .\launcher\threadsaw_gui.py
```

On macOS or Linux:

```bash
docker compose pull
python3 launcher/threadsaw_gui.py
```

The launcher runs on the host, but parsing and analysis run in the network-disabled container. Python 3.11 or newer with Tkinter is required on the host for the GUI.

### 2.2 Published container from the command line

Use Docker Compose directly for automation or headless work. The first `threadsaw` below is the Compose service; `run` is the Threadsaw command executed inside it.

```bash
docker compose run --rm --no-deps -T \
  -v "/absolute/path/evidence:/input:ro" \
  -v "/absolute/path/case:/case" \
  threadsaw run --input /input --case /case
```

Use absolute host paths. Keep `/input` read-only and `/case` writable.

### 2.3 Locally built container

Build locally to audit or customize the image:

```bash
docker compose build
```

MSG parsing is optional because it adds the GPL-licensed `extract-msg` dependency. Enable it only after reviewing the licensing implications:

```bash
docker compose build --build-arg THREADSAW_INSTALL_MSG=1
```

### 2.4 Native wheel on macOS or Linux

Native installation has a larger host dependency and trust surface. Download `threadsaw-1.3.0-py3-none-any.whl` and `SHA256SUMS.txt` from the [Threadsaw 1.3.0 release](https://github.com/thatirguy/threadsaw/releases/tag/v1.3.0), verify the hash, and install the wheel in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./threadsaw-1.3.0-py3-none-any.whl
threadsaw doctor
```

PST ingestion also requires a trusted `libpst/readpst` installation from the operating-system package manager. Optional native MSG support requires the wheel's `msg` extra and its additional license.

Native wheel installation is not a documented Windows method because a compatible and controlled `readpst` dependency is problematic there. Use Docker Desktop with WSL 2 on Windows.

### 2.5 Platform instructions

- [Windows](getting-started/WINDOWS.md)
- [macOS](getting-started/MACOS.md)
- [Linux](getting-started/LINUX.md)
- [Large cases](LARGE_CASES.md)
- [Dependencies, SBOM, and licensing](DEPENDENCIES_AND_LICENSING.md)

## 3. Evidence and case model

### 3.1 Evidence types

- **PST** - extracted by `readpst`; the generated EML files are derived representations.
- **EML** - parsed directly; the indexed message hash is calculated from the exact input bytes.
- **MSG** - optional, best-effort conversion through `extract-msg`; the source hash and derived EML hash are recorded separately.

An attached `message/rfc822` email is stored as an attachment and recursively indexed as a linked child message. Its body and attachments do not leak into the wrapper message's evidence.

### 3.2 Case contents

A case is a writable directory containing the authoritative SQLite index and all durable configuration, artifacts, reports, and exports:

```text
case/
  case.json
  threadsaw.sqlite3
  sources/
  extracted/
  artifacts/
    attachments/
    embedded-messages/
  reports/
  exports/
  logs/
```

SQLite is authoritative. CSV, JSON, TXT, copied attachments, and exported EML files are generated views.

### 3.3 Message identity

`message_sha256` identifies the indexed EML representation. A loose EML uses its exact byte hash. A PST-derived message uses the hash of the EML generated by `readpst`. MSG retains a separate source hash because its EML is derived.

### 3.4 Case boundary

Use one mailbox or one coherent mail environment per case. Trusted context inferred from PST-derived messages and case-history comparisons applies to every message in the case, including loose EML or MSG files added later. Mixing unrelated custodians can make direction, routing, and novelty comparisons misleading.

### 3.5 Evidence handling

- Preserve original evidence separately and read-only.
- Use a separate writable case directory.
- Record acquisition provenance and original hashes under the organization's procedure.
- Keep case storage on a local filesystem with enough space for PST extraction, attachment artifacts, SQLite, reports, and exports.
- Avoid live cloud-synchronization conflicts while the database is open.

## 4. Recommended investigation workflow

### Step 1: Preserve and stage evidence

Place the source evidence in a read-only folder. Create or select a different writable case folder. For large PSTs, perform capacity and performance planning before ingestion.

### Step 2: Run Full Pipeline

**Full Pipeline** is the normal first operation. It ingests the selected evidence, indexes URLs offline, and writes core reports. Use **Ingest Data** alone only when later processing should be deferred.

PST ingestion can optionally pass `readpst -D` to include recoverable deleted items. Ordinary and deleted-item extraction caches remain separate.

### Step 3: Review case context

Threadsaw does not ask the analyst to identify trusted Authentication-Results service IDs or Received boundary hosts. For a corpus of at least 20 PST-derived messages, it attempts conservative consensus automatically.

```bash
threadsaw case-context --case ./case
```

Analyst-declared organization domains are separate from server trust. Supply them at ingest/run, in the GUI, or with `case-config` to enable direction and organization-aware factors.

### Step 4: Review the core reports

Start with `messages.csv`, then examine `urls.csv`, `attachments.csv`, `errors.csv`, QR outputs, archive inventory, or message exports as needed. Validate consequential findings against the original message or mailbox source.

### Step 5: Narrow the evidence

- **Set Scope** saves an immutable date-based selection.
- **String Search** finds case-insensitive literal strings.
- **Phish Hunt** scores a required date range or named scope.
- **Evaluate Phishing Email** explains one indexed or standalone message and creates a matched-factor starter config.

### Step 6: Export review material

Export selected messages, URLs, or attachments into new completion-timestamped folders. Preserve the selection, manifest, requested/effective scoring configurations, configuration hashes, and summary files with the exported content.

## 5. Desktop GUI

The Tkinter launcher constructs network-disabled Docker Compose commands. It does not parse evidence, open SQLite directly, render messages, or preview URL and attachment content on the host.

The GUI shows the underlying CLI command before execution and streams progress and completion output. This makes a successful GUI workflow straightforward to reproduce as a script.

### 5.1 Navigation

Step 1 contains ingestion, reporting, and scope setup. Step 2 contains Phish Hunt, single-message evaluation, string search, QR analysis, URL analysis, attachment reporting/export, message export, and diagnostics.

### 5.2 Phish Hunt controls

The 72 visible factors are grouped under **Inherently Risky** and **Situational**, then into collapsible subcategories. Each row exposes:

- enabled state;
- weight and effect mode;
- computational load;
- prerequisite availability;
- factor-specific parameters;
- detailed help, examples, and false-positive guidance.

The External, Internal, and General presets are adjustable starting points, not calibrated probabilities.

### 5.3 Mount behavior

The launcher mounts evidence read-only and the case directory writable. Windows drive-letter colons are accepted, while ambiguous extra colons are rejected to avoid incorrect Docker bind-mount parsing.

## 6. Module reference

| GUI module | CLI command | Purpose |
|---|---|---|
| Full Pipeline | `threadsaw run` | Ingest evidence, index URLs, and write core reports. |
| Ingest Data | `threadsaw ingest` | Hash, extract, parse, and normalize PST, EML, and optional MSG evidence. |
| Generate Reports | `threadsaw report` | Write message, attachment, error, and JSON rollups from SQLite. |
| Set Scope | `threadsaw scope create` | Save an immutable date-based message selection. |
| Phish Hunt | `threadsaw phish-hunt` | Score a required date range or named scope with a complete configuration. |
| Evaluate Phishing Email | `threadsaw evaluate-phishing-email` | Explain one indexed or standalone message and create a matched-factor config. |
| String Search | `threadsaw string-search` | Search literal text across selected SQLite fields, review text, and reports. |
| Evaluate QRs | `threadsaw qr` | Decode QR values locally from stored images and bounded PDF pages. |
| Get URLs | `threadsaw urls` | Extract, normalize, and statically decode URL strings without following them. |
| Attachment Report / Export | `threadsaw attachments` | Report or copy inert attachments, filter by extension, and optionally inventory ZIP metadata. |
| Export Messages | `threadsaw export-messages` | Export EML, review text, summary, and manifest files. |
| Diagnostics | `threadsaw doctor` | Check dependencies, runtime guardrails, storage, and case database health. |

CLI-only support commands include `case-context`, which recomputes PST-derived trust context, and `case-config`, which sets analyst-declared organization domains.

## 7. Practical investigation recipes

The [Practical Investigation Workflows](USE_CASE_GUIDE.md) guide provides complete GUI and CLI instructions. The following is the operational map.

### 7.1 Analyze an EML or MSG file

1. Put the message in a dedicated evidence folder.
2. For MSG, build a local container with `THREADSAW_INSTALL_MSG=1`.
3. Run **Full Pipeline** to create and populate the case.
4. Review the message, URL, attachment, and error reports.
5. Run **Evaluate Phishing Email** for a factor-by-factor assessment.

An unrelated standalone file uses message-local factors by default. Use case history only when the file belongs to the same mailbox population.

### 7.2 Break a PST into EML files and summarize it

1. Run **Full Pipeline** on the PST.
2. Enable recoverable deleted items only when they are in scope.
3. Review `messages.csv` and the other core reports.
4. Run **Export Messages** with **All messages** to create normalized EML files, review TXT files, a summary, and a manifest.

PST-generated EML files are normalized derived representations, not byte-identical originals from the PST.

### 7.3 Export URLs or attachments from a date range

1. Ingest the evidence.
2. Run **Get URLs** with the start and end timestamps.
3. Run **Attachment Report / Export** with the same selector.
4. Enable attachment copying only when the bytes are needed. Filter by extension or request bounded ZIP metadata when useful.

### 7.4 Score all emails in a date range by risk and export artifacts

1. Ingest the evidence.
2. Run **Phish Hunt** with a date range or saved scope and a reviewed preset/custom configuration.
3. Review both `phish_hunt.csv` and `phish_hunt_details.csv`.
4. Pass that exact hunt CSV and a chosen minimum score to **Get URLs** or **Attachment Report / Export**.

Choose the threshold after reviewing the configuration and score distribution. Scores are not probabilities or verdicts.

### 7.5 Fingerprint a known phishing email and hunt for similar messages

1. Run **Evaluate Phishing Email** on the known message.
2. Review its detail and hit outputs.
3. Edit the generated `matched_factors_config.json` to remove incidental characteristics and tune weights.
4. Ingest the target PST into a coherent case.
5. Run **Phish Hunt** with the reviewed fingerprint config.

The generated config starts matched factors at a uniform weight of 10. It is a hypothesis-building aid, not proof of campaign relationship.

### 7.6 Search for a string across case content

Use **String Search** for a case-insensitive literal substring across SQLite fields, exported review text, reports, or any combination. Export messages first if normalized review TXT files should be included. Date filtering applies only to message-associated SQLite rows, not filesystem text.

## 8. Selectors and date behavior

Commands that support message selection accept exactly one of:

- `--sha256 <64-hex-message-hash>`;
- `--sha256-csv <file.csv>`;
- `--scope <name>`;
- `--start <ISO-8601> --end <ISO-8601>`;
- `--all`, where supported.

URL and attachment workflows can alternatively select messages from a Phish Hunt report:

```text
--phish-hunt-report <phish_hunt.csv> --min-score <integer>
```

All stored and user-supplied timestamps are normalized to UTC whole seconds. A range is start-inclusive and end-exclusive. For example, `2026-06-01T00:00:00Z` through `2026-07-01T00:00:00Z` selects June in UTC.

Phish Hunt deliberately requires either a complete date range or a named scope. It has no unrestricted `--all` mode.

A named scope stores the resolved message hashes at creation time. Later ingestion does not change the scope.

## 9. CLI reference

Global syntax:

```text
threadsaw [--quiet] [--version] <command>
```

`--quiet` suppresses progress messages but preserves final JSON output.

### 9.1 Core commands

```bash
threadsaw ingest --input ./evidence --case ./case [--workers 4] [--include-deleted]
threadsaw run --input ./evidence --case ./case [--workers 4] [--include-deleted]
threadsaw report --case ./case [--output ./case/reports/core] [selector]
threadsaw urls --case ./case [--output ./case/reports/urls.csv] [selector]
threadsaw attachments --case ./case --output ./case/reports/attachments [selector]
threadsaw qr --case ./case --output-root ./case/reports/qr [selector]
threadsaw export-messages --case ./case --output ./case/exports/messages [selector]
```

Repeat `--organization-domain` on `ingest` or `run` to replace the analyst-declared organization-domain list:

```bash
threadsaw run --input ./evidence --case ./case \
  --organization-domain example.com \
  --organization-domain subsidiary.example
```

Attachment reporting can copy files, filter extensions, and inventory bounded ZIP metadata:

```bash
threadsaw attachments --case ./case --output ./case/reports/attachments \
  --copy-files --copy-output ./case/exports/attachments \
  --extension pdf --extension docx,zip \
  --list-zip-contents --all
```

### 9.2 Scope, scoring, evaluation, and search

```bash
threadsaw scope create --case ./case --name week-1 --start ... --end ...
threadsaw scope list --case ./case

threadsaw phish-hunt-preset --name general --output general.json
threadsaw phish-hunt --case ./case --start ... --end ... --config general.json
threadsaw phish-hunt-list --case ./case

threadsaw evaluate-phishing-email --case ./case --sha256 MESSAGE_SHA256
threadsaw evaluate-phishing-email --case ./case --email-file ./message.eml

threadsaw string-search --case ./case --query "literal text" --database --reports
```

### 9.3 Case administration and diagnostics

```bash
threadsaw case-context --case ./case

threadsaw case-config --case ./case \
  --organization-domain example.com

threadsaw case-config --case ./case --clear-organization-domains
threadsaw doctor [--case ./case]
```

### 9.4 Exit status

- `0` - command completed.
- `2` - ingestion completed with one or more recorded source errors, or CLI argument/validation failure.
- Other nonzero values - unexpected execution failure.

See the [CLI Reference](CLI_REFERENCE.md) for every option and selection rule.

## 10. Case and hunt configuration

### 10.1 `case.json`

Threadsaw creates and atomically updates `case.json`. It records case identity, durable analyst configuration, and inferred context.

Analyst-configurable organization domains support:

- inbound, outbound, internal, and unknown direction;
- organization-domain lookalike checks;
- embedded-domain checks;
- SharePoint relationship heuristics.

They represent analyst knowledge and do not establish trusted mail-server infrastructure.

### 10.2 Trusted context

Manual trusted Authentication-Results IDs and Received hosts are not accepted. Threadsaw infers them only from repeated PST-derived evidence when at least 20 PST-derived messages are present.

- Authentication service IDs require at least 40% corpus consensus.
- Received inference first tries the exact hop-0 `by` hostname.
- If cloud frontends rotate, it tries the most specific stable parent-domain suffix meeting the same threshold, bounded by the offline Public Suffix List.
- Loose EML and MSG evidence does not establish trusted server context.

When stable context is unavailable, dependent factors are removed from the effective hunt configuration rather than treated as reassuring zero-point results.

### 10.3 Phish Hunt `config.json`

A complete hunt configuration has a version, name, preset label, and factor list:

```json
{
  "config_version": 1,
  "name": "Custom hunt",
  "preset": "custom",
  "factors": [
    {
      "factor_id": "reply_to_domain_mismatch",
      "enabled": true,
      "weight": 25,
      "effect_mode": "risk_when_yes",
      "parameters": {}
    }
  ]
}
```

Unknown factor IDs are rejected. Weights are non-negative integers. Preserve both the requested and effective configurations because availability checks can remove context-dependent factors from a run.

Starter presets are:

- `external` - messages entering an organization;
- `internal` - apparent same-organization or compromised-account messages;
- `general` - balanced starting point when direction is uncertain.

Review preset factors and weights against the local environment and false-positive tolerance.

## 11. Phish Hunt scoring and interpretation

Phish Hunt applies an analyst-reviewable configuration to a required date range or named scope. Before scoring it:

1. recomputes PST-derived trusted context;
2. removes trusted-dependent factors when context is unavailable;
3. URL-indexes selected messages whose URL state is incomplete;
4. performs bounded ZIP inventory when an enabled factor requires it;
5. stores requested and effective configurations and their hashes.

### 11.1 Answers

- `YES` - the factor matched.
- `NO` - sufficient evidence was present and it did not match.
- `UNKNOWN` - required evidence was missing, untrusted, or inconclusive.
- `NOT_APPLICABLE` - the factor cannot meaningfully run in this evaluation mode.
- `ERROR` - the isolated evaluator failed; the remaining hunt continues.

`UNKNOWN`, `NOT_APPLICABLE`, and `ERROR` contribute zero points.

### 11.2 Effect modes

- `risk_when_yes`: YES adds the weight; NO adds zero.
- `trust_when_yes`: YES subtracts the weight; NO adds zero.
- `bidirectional_risk`: YES adds the weight; NO subtracts it.
- `bidirectional_trust`: YES subtracts the weight; NO adds it.

Scores are uncapped additive integers centered at zero. Higher scores mean the message matches more of the configured phishing indicators. Scores from different configurations are not directly comparable and are never probabilities.

### 11.3 Evidence coverage

The main report includes:

- `max_possible_points_evaluated` - positive-risk ceiling among factors returning YES or NO;
- `unknown_positive_points` - positive-risk ceiling attached to factors that could not be evaluated;
- `positive_score_percent_evaluated` - positive points divided by the evaluable positive-risk ceiling when nonzero.

Use these fields to detect missing-data bias. A low raw score with substantial unknown positive points is not necessarily reassuring.

### 11.4 Factor catalog

Version 1.3.0 exposes 72 factors covering sender and header deception, authentication failures, routing context, URL obfuscation, attachment characteristics, active HTML, message and sender history, thread continuity, campaign patterns, archives, recipient context, and trust evidence.

See the [Phish Hunt Factor Catalog](PHISH_HUNT_FACTOR_CATALOG.md) for behavior, prerequisites, examples, false-positive notes, parameters, computational load, and starter weights for every factor.

## 12. URL, attachment, archive, and QR analysis

### 12.1 URLs

Threadsaw extracts URL and URI strings from text and HTML, including bare `www.` hostnames. It records original and normalized text, displayed target, statically decoded wrapper target, hostname, offline Public-Suffix-List registrable domain, mismatch, SharePoint presence, and heuristic SharePoint relationship.

Wrapper decoding is a text transformation. Threadsaw never resolves or retrieves the target. The vendored Public Suffix List is static and is not refreshed at runtime.

### 12.2 Attachments

Attachment bytes are hash-addressed. Reports record original and sanitized filenames, declared MIME type, disposition, content ID, inline status, hashes, size, executable/script observation, and artifact path.

Inline signature images remain evidence but do not inflate normal attachment counts or attachment-history factors. Exported names remove path separators, platform-reserved names, excessive length, and Unicode format controls such as bidirectional overrides.

### 12.3 ZIP inventory

Optional ZIP inspection reads bounded central-directory metadata only. It does not extract or decompress members, recurse into nested archives, decrypt content, or test passwords.

The encrypted-ZIP evaluator uses stored per-member encryption flags. Incomplete inventory returns `UNKNOWN` unless a positive encrypted member was already observed.

### 12.4 QR codes

QR evaluation scans stored image attachments and a bounded number of PDF pages rendered locally with pypdfium2/PDFium. It records decoded text and URL-shaped values without contacting them. Remote images and arbitrary document formats are not fetched or rendered.

## 13. Database, reports, and exports

### 13.1 Important SQLite tables

- `sources` - source path, hash, parser, status, and parentage.
- `messages` - normalized headers, bodies, dates, direction, counts, and EML hash.
- `message_sources` and `message_relationships` - source attribution and wrapper/child links.
- `recipients`, `received_hops`, and `authentication_results` - address, routing, and authentication evidence.
- `attachments`, `archive_members`, and `archive_inspections` - artifact and bounded archive metadata.
- `urls` and `qr_results` - offline extracted and decoded text.
- `scopes` and `scope_messages` - immutable selections.
- `phish_hunt_runs`, `phish_hunt_results`, and `phish_hunt_factor_results` - run, score, coverage, and factor evidence.
- `errors` - stage-specific processing errors.

### 13.2 Core outputs

`messages.csv` and `messages.json` include identifiers, selected/header/Received dates, direction, sender and recipient fields, IP evidence, trusted authentication results when available, non-inline attachment count, deduplicated URL count, parser status, and EML path.

`urls.csv` contains the offline URL analysis. `attachments.csv` contains attachment metadata and optional copy paths. `errors.csv` exposes recorded source and stage failures.

QR runs write `qr_codes.csv`, `qr_codes.json`, and `run_manifest.json`.

### 13.3 Phish Hunt outputs

Each completed run has a timestamped directory containing:

- `phish_hunt.csv` - one score row per selected message;
- `phish_hunt_details.csv` - one row per enabled factor per message;
- `phish_hunt.json`;
- `scoring_config.json` - effective configuration executed;
- `requested_scoring_config.json` - original requested configuration;
- `run_manifest.json`.

The manifest records selection, context, URL auto-indexing, archive preparation, removed factors, score semantics, hashes, and timestamps.

### 13.4 Standalone evaluation outputs

Single-message evaluation writes summary and detail CSV/JSON, a readable hits file, a manifest, and `matched_factors_config.json` for later fingerprint hunts.

### 13.5 Timestamped outputs and CSV safety

Threadsaw treats a supplied output path as a base and creates a completion-timestamped folder or file. Collision suffixes prevent earlier results from being overwritten.

CSV values beginning with spreadsheet formula prefixes are escaped. Use JSON or SQLite when exact raw leading characters are required.

## 14. Upgrading an older Version 1 case

1. Preserve a copy of the original case.
2. Stop existing Threadsaw containers and database viewers.
3. Install or extract Threadsaw 1.3.0, or pull the versioned container image.
4. Open the copied case. Schema migration runs automatically to schema version 8.
5. Run `threadsaw case-context --case <case>` for PST-derived cases.
6. Re-run URL indexing to gain bare-`www` capture, updated wrapper decoding, Public-Suffix-based domains, and refreshed SharePoint relationship values.

Migration collapses older duplicate URL rows caused by NULL displayed text and adds current tables, columns, and indexes.

Re-ingestion is required only when an older case must retroactively correct parse-time attached-message attribution or inline-attachment counts. Preserve the old case when evidentiary continuity matters.

## 15. Troubleshooting

### GUI does not start

Confirm Python 3.11 or newer, Tkinter, and Docker are installed. `python -m tkinter` should open a test window. Start the launcher from the Threadsaw directory so `compose.yaml` is present.

### Docker cannot mount a path

Use absolute paths and grant Docker access to the evidence and case locations. Evidence must be readable; the case must be writable. On Windows, ambiguous extra colons in paths are rejected because Docker may parse them as mount separators.

### `readpst` is missing or unexpected

Run `threadsaw doctor`. The published image includes `readpst`. For native macOS/Linux operation, install `libpst/readpst` and optionally set `THREADSAW_READPST` to the trusted absolute executable path.

### MSG files are rejected

The published image intentionally excludes MSG support. Build locally with `docker compose build --build-arg THREADSAW_INSTALL_MSG=1`, or install the native package with its `msg` extra after reviewing licensing.

### Database is busy or reports disk I/O errors

Stop concurrent Threadsaw operations and close other tools that opened `threadsaw.sqlite3`. Keep active cases on a local filesystem rather than a live synchronized or unreliable network mount.

### URL count is zero

`url_indexed=0` means indexing has not been established. `url_indexed=1` with `url_count=0` means indexing completed and stored no URL. Re-run Get URLs for older cases. Phish Hunt automatically indexes selected messages when needed.

### Trusted factors are absent

Run `threadsaw case-context --case ./case`. Trusted context requires at least 20 PST-derived messages and stable consensus. When it cannot be inferred, dependent factors are removed from the effective config and listed in the manifest.

### Score is low but many factors are unknown

Review `max_possible_points_evaluated`, `unknown_positive_points`, `positive_score_percent_evaluated`, and `phish_hunt_details.csv`. Missing evidence can suppress the raw score.

### QR or ZIP results are empty

QR analysis covers stored image attachments and bounded rendered PDF pages. ZIP inventory covers recognized ZIP-compatible central directories and is opt-in outside Phish Hunt prerequisites. Inspect the run manifest and diagnostics for dependency, limit, corruption, and per-artifact errors.

### Output is not at the exact supplied path

The supplied path is a base. Read the final JSON or GUI log for the completion-timestamped path.

See [Troubleshooting](TROUBLESHOOTING.md) for additional operational cases.

## 16. Validation, limitations, and forensic use

The 1.3.0 release was validated with 75 passing automated tests, clean-wheel installation, CLI smoke tests, the bundled Public Suffix List, complete preset/evaluator registry checks, and a local ingest/report/Phish Hunt workflow. Hosted CI covers Windows, macOS, and Linux under Python 3.11 and 3.13.

Passing tests do not establish:

- compatibility with every PST, MSG, MIME, or mailbox producer;
- resistance to every adversarial input;
- malware detection or sender attribution;
- legal admissibility;
- calibrated preset accuracy;
- independent security assurance;
- enterprise-scale performance in a particular environment.

Important current limits:

- MSG conversion is a best-effort derived representation.
- QR analysis is limited to stored images and bounded PDF pages.
- ZIP analysis is central-directory metadata only and cannot inspect encrypted content or non-ZIP archive internals.
- SharePoint relationship, organization context, and trusted infrastructure inference are heuristics.
- Large cases require representative storage, capacity, and performance testing.

Before production use, validate representative organizational PST exports, damaged and nested MIME, known-good and known-bad messages, expected routing/authentication consensus, rewritten URLs, SharePoint tenants, archives, QR samples, interrupted runs, migration on a copied case, and 50,000- to 200,000-message performance where applicable.

Retain the Threadsaw version and artifact hash, container image digest, source hashes, original/pre-migration case, `case.json`, SQLite database, manifests, requested/effective configs and hashes, and organizational validation records.

## 17. Detailed references

- [Documentation index](DOCUMENTATION_INDEX.md)
- [Practical investigation workflows](USE_CASE_GUIDE.md)
- [User guide](USER_GUIDE.md)
- [Installation and deployment](INSTALLATION_AND_DEPLOYMENT.md)
- [GUI reference](GUI.md)
- [Module reference](MODULE_REFERENCE.md)
- [CLI reference](CLI_REFERENCE.md)
- [Configuration reference](CONFIGURATION_REFERENCE.md)
- [Phish Hunt](PHISH_HUNT.md)
- [All 72 Phish Hunt factors](PHISH_HUNT_FACTOR_CATALOG.md)
- [Database and outputs](DATABASE_AND_OUTPUTS.md)
- [Security and forensic posture](SECURITY_AND_FORENSICS.md)
- [Architecture](ARCHITECTURE.md)
- [Testing and validation](TESTING_AND_VALIDATION.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Release status](RELEASE_STATUS.md)
- [Release notes 1.3.0](RELEASE_NOTES_1.3.0.md)
- [Dependencies, SBOM, and licensing](DEPENDENCIES_AND_LICENSING.md)
