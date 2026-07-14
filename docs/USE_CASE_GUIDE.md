# Practical investigation workflows

This guide maps common investigation goals to the Threadsaw GUI modules and their equivalent CLI commands. The GUI shows the underlying Docker CLI command before execution and prints it in the progress view, so a workflow can be repeated or adapted as a script.

Threadsaw performs static, offline analysis. It does not follow URLs, contact hosts, or execute attachments. Exported URLs and files are still untrusted evidence and should be reviewed with appropriate isolation and evidence-handling procedures.

## Before you begin

Docker is the recommended way to run Threadsaw. On Windows, install WSL 2 and Docker Desktop first; see the [Windows setup guide](getting-started/WINDOWS.md). Setup instructions are also available for [macOS](getting-started/MACOS.md) and [Linux](getting-started/LINUX.md).

Pull the published default image, which supports PST and EML evidence:

```bash
docker compose pull
```

You can instead build the default image locally for auditing or customization:

```bash
docker compose build
```

MSG support is optional because it adds a GPL-3.0-or-later parser to the runtime image. Enable it in a local build when required:

```bash
docker compose build --build-arg THREADSAW_INSTALL_MSG=1
```

Launch the GUI from Bash or macOS:

```bash
python3 launcher/threadsaw_gui.py
```

Or from PowerShell:

```powershell
python .\launcher\threadsaw_gui.py
```

The CLI examples below show the `threadsaw` portion of each command. They can be run in a native installation, or placed after this Docker wrapper:

```bash
docker compose run --rm --no-deps -T \
  -v "/absolute/path/to/evidence:/input:ro" \
  -v "/absolute/path/to/case:/case" \
  threadsaw <command> <options>
```

In these examples, `/input` is the read-only evidence mount and `/case` is the writable case directory. Use container paths in Docker commands, not host paths.

## Module chooser

| Goal | GUI module | CLI command |
|---|---|---|
| Ingest evidence and create core reports | Full Pipeline | `threadsaw run` |
| Export normalized messages and readable summaries | Export Messages | `threadsaw export-messages` |
| Extract URL strings | Get URLs | `threadsaw urls` |
| Inventory or copy attachments | Export Attachments | `threadsaw attachments` |
| Score messages for phishing risk | Phish Hunt | `threadsaw phish-hunt` |
| Evaluate one known message | Evaluate Phishing Email | `threadsaw evaluate-phishing-email` |
| Search case data and text outputs | String Search | `threadsaw string-search` |

Dates must be ISO 8601 values with an offset or `Z`. The start is inclusive and the end is exclusive. For example, `--start 2026-06-01T00:00:00Z --end 2026-07-01T00:00:00Z` selects all of June in UTC.

## Use case 1: Analyze an EML or MSG file

Use **Full Pipeline** to ingest the message, extract its metadata, index URL strings and attachments, and create the core case reports. Use **Evaluate Phishing Email** afterward when you want the complete Phish Hunt factor-by-factor assessment for that message.

### GUI

1. Put the EML or MSG in its own evidence folder. MSG requires the optional image build described above.
2. Open **Full Pipeline**, choose the evidence folder and a new or existing case folder, and add the organization's trusted domains when known.
3. Run the pipeline and review the message, URL, attachment, and error reports it creates.
4. Open **Evaluate Phishing Email** and select either the standalone file or the indexed message SHA-256 for a detailed factor assessment.

### CLI

```bash
threadsaw run \
  --input /input \
  --case /case \
  --organization-domain example.com
```

Evaluate the standalone file directly:

```bash
threadsaw evaluate-phishing-email \
  --case /case \
  --email-file /input/message.eml
```

Or evaluate a message already indexed in the case:

```bash
threadsaw evaluate-phishing-email \
  --case /case \
  --sha256 MESSAGE_SHA256
```

The pipeline writes timestamped core reports under `case/reports/`. Evaluation writes `evaluation.csv`, `evaluation_details.csv`, `evaluation.json`, `evaluation_hits.txt`, and `matched_factors_config.json` in a timestamped evaluation directory.

By default, a standalone message that is not already indexed is evaluated without case-history factors. Add `--allow-case-history` only when comparing it with the selected case's history is analytically appropriate.

## Use case 2: Break a PST into EML files and summarize the contents

Use **Full Pipeline** to extract the PST with `readpst`, normalize its messages, and generate case-level summaries. Then use **Export Messages** to create an analyst-facing EML and companion review-text export for every indexed message.

### GUI

1. Open **Full Pipeline** and select the folder containing the PST and the destination case folder.
2. Set worker count and trusted organization domains as appropriate. Enable deleted-item recovery only when it is in scope for the investigation.
3. Run the pipeline.
4. Open **Export Messages**, select **All messages**, choose an export directory under the case, and run the export.

For large PSTs, review the [large-case guidance](LARGE_CASES.md) before starting.

### CLI

```bash
threadsaw run \
  --input /input \
  --case /case \
  --workers 4

threadsaw export-messages \
  --case /case \
  --output /case/exports/messages \
  --all
```

Add `--include-deleted` to `run` only when recoverable deleted PST items are in scope; it passes `-D` to `readpst`. The export contains normalized EML files, readable companion TXT files, a CSV summary, and a manifest. EML created from a PST is a normalized representation, not a claim of byte-for-byte identity with the source PST item.

## Use case 3: Export URLs or attachments from a date range

Ingest the evidence first, then use **Get URLs** and **Export Attachments** with the same date selector. You can run either module independently when only one artifact type is needed.

### GUI

1. Run **Full Pipeline** or **Ingest Data** for the evidence.
2. Open **Get URLs**, select a start and end date, and choose the CSV output.
3. Open **Export Attachments**, use the same dates, and choose an output directory.
4. Enable attachment copying only when you need the bytes for deeper review. Optionally filter by extension or list bounded ZIP metadata.

### CLI

```bash
threadsaw urls \
  --case /case \
  --start 2026-06-01T00:00:00Z \
  --end 2026-07-01T00:00:00Z \
  --output /case/reports/june_urls.csv

threadsaw attachments \
  --case /case \
  --start 2026-06-01T00:00:00Z \
  --end 2026-07-01T00:00:00Z \
  --output /case/reports/june_attachments \
  --copy-files \
  --copy-output /case/exports/june_attachments
```

For a narrower attachment hunt, repeat `--extension` or provide comma-separated values, such as `--extension pdf --extension docx,xlsm`. Add `--list-zip-contents` to inventory bounded ZIP central-directory metadata without extracting members.

The URL report contains strings only; Threadsaw does not retrieve them. Copied attachments are never launched or executed, but the exported bytes remain potentially malicious.

## Use case 4: Score all emails in a date range by risk and export artifacts

Use **Phish Hunt** to score every message in a required date range or saved scope. Start with the `general`, `external`, or `internal` preset, or supply a reviewed custom factor configuration. Then pass the resulting `phish_hunt.csv` to **Get URLs** and **Export Attachments** with a minimum score.

### GUI

1. Ingest the evidence with **Full Pipeline** or **Ingest Data**.
2. Open **Phish Hunt** and choose a start/end range or a named scope.
3. Select a bundled preset or import a custom JSON configuration. Review enabled factors and weights before running it.
4. Run the hunt and review `phish_hunt.csv` alongside `phish_hunt_details.csv` to understand what produced each score.
5. Open **Get URLs** or **Export Attachments**, select the hunt report, and set the minimum score. Copy attachments only when needed.

### CLI

Export a preset, then use it as an editable starting point:

```bash
threadsaw phish-hunt-preset \
  --name general \
  --output /case/general-hunt.json

threadsaw phish-hunt \
  --case /case \
  --start 2026-06-01T00:00:00Z \
  --end 2026-07-01T00:00:00Z \
  --config /case/general-hunt.json \
  --run-name june-review
```

Use the exact `phish_hunt.csv` path returned by the hunt:

```bash
threadsaw urls \
  --case /case \
  --phish-hunt-report /case/reports/phish_hunt/RUN_DIRECTORY/phish_hunt.csv \
  --min-score 20 \
  --output /case/reports/high_risk_urls.csv

threadsaw attachments \
  --case /case \
  --phish-hunt-report /case/reports/phish_hunt/RUN_DIRECTORY/phish_hunt.csv \
  --min-score 20 \
  --output /case/reports/high_risk_attachments \
  --copy-files \
  --copy-output /case/exports/high_risk_attachments
```

Phish Hunt scores are uncapped integers, not probabilities or verdicts. Choose the threshold after reviewing the selected configuration, its weights, and the score distribution in that case. The detail report is the basis for validating why a message crossed the threshold.

## Use case 5: Fingerprint a known phishing email and hunt for similar messages

Use **Evaluate Phishing Email** on the known phish. Threadsaw records every matched factor and exports `matched_factors_config.json`, a starter configuration representing the message's matched behavioral and structural characteristics beyond simple IOC matching. Review and tune that configuration before applying it to a PST with **Phish Hunt**.

### GUI

1. Open **Evaluate Phishing Email** and select the known EML/MSG file or an indexed message SHA-256.
2. Review `evaluation_details.csv` and `evaluation_hits.txt` to verify which factors are meaningful characteristics of the phish.
3. Open the exported `matched_factors_config.json`. Disable generic or incidental matches and adjust weights to emphasize the characteristics relevant to your investigation.
4. Ingest the target PST into a case.
5. Open **Phish Hunt**, import the reviewed fingerprint configuration, choose the target date range or scope, and run the hunt.
6. Review the detail report before treating high-scoring messages as related.

### CLI

```bash
threadsaw evaluate-phishing-email \
  --case /case \
  --email-file /input/known-phish.eml
```

After reviewing and copying the generated configuration to `/case/known-phish-fingerprint.json`, run it against the target case:

```bash
threadsaw phish-hunt \
  --case /case \
  --start 2026-01-01T00:00:00Z \
  --end 2026-07-01T00:00:00Z \
  --config /case/known-phish-fingerprint.json \
  --run-name known-phish-fingerprint
```

The generated configuration enables matched factors with a uniform starter weight of 10. It is intentionally a starting point, not an assertion that every match is distinctive or that every similar email is malicious. Data-only or case-history factors may need special review before reuse in another case.

## Use case 6: Search for a string across case content

Use **String Search** for a case-insensitive literal search across SQLite fields, exported message review text, and text-based reports. Search all three locations for the broadest coverage.

### GUI

1. Ingest the evidence. To include normalized message review TXT files as a separate search source, run **Export Messages** first.
2. Open **String Search** and enter the exact string to find.
3. Select the database, an exported-text directory, reports, or any combination of those sources.
4. Optionally apply a date range to database results and run the search.
5. Review the timestamped result CSV, summary, and manifest.

### CLI

Search the database and reports:

```bash
threadsaw string-search \
  --case /case \
  --query "wire instructions" \
  --database \
  --reports
```

Search every supported text source:

```bash
threadsaw string-search \
  --case /case \
  --query "vendor@example.com" \
  --database \
  --exported-text-dir /case/exports/messages \
  --reports \
  --output-root /case/reports/string_search
```

`--start` and `--end` restrict only message-associated SQLite results; they do not filter exported TXT files or report files. The query is a literal, case-insensitive string. String Search does not perform regular-expression, fuzzy, semantic, OCR, or arbitrary binary-content searching.

## Related references

- [GUI guide](GUI.md)
- [CLI reference](CLI_REFERENCE.md)
- [Module reference](MODULE_REFERENCE.md)
- [Phish Hunt scoring and configuration](PHISH_HUNT.md)
- [Evaluate Phishing Email](EVALUATE_PHISHING_EMAIL.md)
- [String Search](STRING_SEARCH.md)
- [Database and output schemas](DATABASE_AND_OUTPUTS.md)
- [Security and forensic boundaries](SECURITY_AND_FORENSICS.md)
