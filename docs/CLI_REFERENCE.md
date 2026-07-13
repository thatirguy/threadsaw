# Threadsaw 1.3.0 CLI reference

All commands install runtime guardrails. Docker deployments also run with networking disabled. Paths below are examples; use host/container paths appropriate to the execution method.

## Global options

```text
threadsaw [--quiet] [--version] <command>
```

`--quiet` suppresses progress messages but retains final JSON output.

## Message selectors

Commands supporting message selection accept exactly one of:

- `--sha256 <64-hex-message-hash>`
- `--sha256-csv <file.csv>`
- `--scope <name>`
- `--start <ISO-8601> --end <ISO-8601>`
- `--all`

Date ranges are start-inclusive/end-exclusive and normalized to UTC whole seconds.

URL and attachment commands can alternatively use:

```text
--phish-hunt-report <phish_hunt.csv> --min-score <integer>
```

## `ingest`

```bash
threadsaw ingest --input ./evidence --case ./case [--no-recursive] [--workers 4] [--include-deleted] \
  [--organization-domain example.com ...]
```

Hashes and indexes PST, EML, and optional MSG sources. `--include-deleted` passes `readpst -D` and uses a separate extraction cache. Attached `message/rfc822` messages are linked and indexed independently. Repeatable `--organization-domain` values replace the analyst-declared organization-domain list and make direction and organization-aware evaluators available for loose EML/MSG cases.

## `run`

```bash
threadsaw run --input ./evidence --case ./case [--start ... --end ...] [--workers 4] [--include-deleted] \
  [--organization-domain example.com ...]
```

Ingests, URL-indexes the selected messages, and writes core reports into a completion-timestamped pipeline folder.

## `report`

```bash
threadsaw report --case ./case [--output ./case/reports/core] [selector]
```

Writes message, attachment, error CSVs and message JSON. When no selector is supplied, all messages are selected.

## `urls`

```bash
threadsaw urls --case ./case [--output ./case/reports/urls.csv] [selector]
```

Extracts and normalizes URL strings, captures bare `www.` forms, decodes supported wrappers as text, computes offline PSL domains, updates URL counts, and writes a timestamped report. Nothing is followed.

## `attachments`

```bash
threadsaw attachments --case ./case --output ./case/reports/attachments \
  [--copy-files] [--copy-output ./case/exports/attachments] \
  [--extension pdf --extension docx,zip] \
  [--list-zip-contents --zip-max-members 1000 --zip-max-total-members 10000] \
  [selector]
```

Reports metadata and optionally copies inert bytes. ZIP listing reads only bounded central-directory metadata and never extracts members.

## `qr`

```bash
threadsaw qr --case ./case --output-root ./case/reports/qr \
  [--max-pdf-pages 100] [--render-dpi 144] [selector]
```

Decodes QR codes locally from stored image attachments and bounded PDF pages rendered through `pypdfium2`/PDFium. `render-dpi` must be between 72 and 600. Decoded URLs remain text.

## `export-messages`

```bash
threadsaw export-messages --case ./case --output ./case/exports/messages [selector]
```

Writes EML, `review.txt`, summary CSV, and manifest outputs in a completion-timestamped folder.

## `scope`

```bash
threadsaw scope create --case ./case --name week-1 --start ... --end ...
threadsaw scope list --case ./case
```

A scope stores a fixed set of message SHA-256 values resolved at creation time.

## `phish-hunt-preset`

```bash
threadsaw phish-hunt-preset --name external --output external.json
threadsaw phish-hunt-preset --name internal --output internal.json
threadsaw phish-hunt-preset --name general --output general.json
```

Prints or exports a complete starter `config.json`.

## `phish-hunt`

```bash
threadsaw phish-hunt --case ./case \
  (--scope <name> | --start <time> --end <time>) \
  [--config hunt.json] [--run-name "Vendor BEC"] [--output-root ./case/reports/phish_hunt]
```

Requires a date range or named scope. It recomputes PST-derived trusted context, disables unavailable dependent factors, automatically URL-indexes selected messages that have not been indexed, and performs bounded ZIP-family inventory when an enabled archive-dependent factor needs it.

## `phish-hunt-list`

```bash
threadsaw phish-hunt-list --case ./case
```

Lists recorded runs, status, configuration hash, output path, and timestamps.

## `evaluate-phishing-email`

```bash
threadsaw evaluate-phishing-email --case ./case --sha256 <message-hash>
threadsaw evaluate-phishing-email --case ./case --email-file ./message.eml [--allow-case-history]
```

An existing case message is evaluated with case context. An external EML/MSG whose SHA-256 does not match the case uses standalone factors by default. `--allow-case-history` is an explicit override and may be meaningless when the email came from another mailbox. The run exports a matched-factor configuration.

## `string-search`

```bash
threadsaw string-search --case ./case --query "literal text" \
  [--database] [--exported-text-dir ./case/exports/messages] [--reports] \
  [--start ... --end ...] [--output-root ./case/reports/string_search]
```

Searches for a case-insensitive literal substring. The date range applies only to message-associated SQLite rows, not exported text or report files.

## `case-context`

```bash
threadsaw case-context --case ./case
```

Recomputes and displays trusted authserv-id, Received boundary, and likely organization-domain context inferred from PST-derived messages. It does not prompt for or accept trusted server IDs. It reports which dependent factor families are available.

Trusted authserver and Received-boundary inference requires at least 20 PST-derived messages. Received inference uses exact-host consensus first, then a stable parent-domain-suffix fallback for rotating cloud frontends.

## `case-config`

```bash
threadsaw case-config --case ./case \
  --organization-domain example.com \
  --organization-domain subsidiary.example

threadsaw case-config --case ./case --clear-organization-domains
```

Replaces or clears analyst-declared organization domains and immediately recomputes message direction and organization-aware context. It never configures trusted authserver or Received-host identifiers. In a PST case, clearing the list may allow conservative recipient-domain inference to repopulate it.

## `doctor`

```bash
threadsaw doctor [--case ./case]
```

Reports Python/platform details, dependency availability, selected `readpst` path/version, guardrails, free space, database integrity, and journal mode.

## Exit status

- `0` — command completed.
- `2` — ingestion completed with one or more recorded source errors, or argument/validation failure through the CLI boundary.
- Other nonzero values — unexpected execution failure.
