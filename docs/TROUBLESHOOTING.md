# Threadsaw 1.3.0 troubleshooting

## The GUI does not start

Confirm Python 3.11 or newer, Tkinter, and Docker are available. `python -m tkinter` should open a test window. Run the launcher from the extracted project directory so `compose.yaml` is present.

## Docker cannot mount an evidence or case path

Use absolute paths and share the location with Docker Desktop. The launcher rejects unexpected colons because Docker may misparse them as bind-mount separators; move the folder to a path without an additional colon. Evidence must be readable and the case directory writable.

## `readpst` is missing or the wrong executable is selected

Run `threadsaw doctor`. The supplied container installs `pst-utils`. For native operation, install `libpst/readpst`. To avoid PATH ambiguity, set `THREADSAW_READPST` to an absolute path whose basename is `readpst` or `readpst.exe`.

## Deleted PST items are not present

Deleted-item recovery is opt-in. Select **Include recoverable deleted PST items** or pass `--include-deleted`. Threadsaw uses a separate extraction cache for standard and `-D` runs.

## MSG files are rejected

Install optional support with `pip install -e '.[msg]'`, or use the default container build. MSG conversion is a best-effort derived EML representation; review `errors.csv` for unsupported variants.

## The database is busy or reports disk I/O errors

Stop other Threadsaw operations and close tools that directly opened `threadsaw.sqlite3`. Threadsaw waits up to 30 seconds. A legacy WAL case may be copied to local temporary storage, checkpointed, integrity-checked, converted to DELETE journal mode, and restored; originals are retained under `logs/database-backups/`.

## URL count is zero although a message has links

`url_indexed=0` means URL indexing has not been established. `url_indexed=1` with `url_count=0` means indexing completed and stored no URL. Phish Hunt automatically indexes selected unindexed messages. Re-run Get URLs for older cases to capture bare `www.` forms, refreshed wrapper decoding, and Public-Suffix-based domains.

## A trusted authentication or Received-boundary factor is absent

Threadsaw does not accept manually entered trusted server identifiers in Version 1.2. Run:

```bash
threadsaw case-context --case ./case
```

Trusted context is inferred only from at least 20 PST-derived messages. Authentication service IDs require 40% consensus; Received boundaries use exact-host consensus first and a stable parent-domain-suffix fallback. When no stable consensus is available, dependent factors are disabled in the effective `scoring_config.json` and listed under `context_dependent_factors_removed` in the manifest. Loose EML/MSG-only cases normally cannot supply this context.

## A historical factor is NOT_APPLICABLE in Evaluate Phishing Email

The external file does not match an existing case message and case-history override was not selected. Override is meaningful only when the message belongs to the same mailbox population as the case.

## A Phish Hunt score is low but many factors are UNKNOWN

Review `max_possible_points_evaluated`, `unknown_positive_points`, and `positive_score_percent_evaluated`, then inspect `phish_hunt_details.csv`. A low raw score may reflect limited evidence rather than reassuring evidence.

## Phish Hunt is slow

Heavy factors query earlier case records. Version 1.2 uses indexed SQL and avoids loading full bodies for history comparisons, but very large cases still require representative benchmarking. Keep the case on a performant local filesystem, avoid concurrent operations, and use an investigative scope.

## QR evaluation finds nothing

Only stored image attachments and rendered PDF pages are evaluated. Remote images and arbitrary document formats are not fetched or rendered. Confirm OpenCV and pypdfium2 are available with `threadsaw doctor`, increase the PDF page limit only when justified, and inspect the run manifest for per-attachment errors.

## ZIP inventory is empty

Attachment-report ZIP inventory is opt-in; Phish Hunt automatically performs bounded inventory when an enabled archive-dependent factor needs it. Only ZIP-compatible containers recognized by stored extension or MIME metadata are supported. The encrypted-ZIP evaluator reads member encryption flags from central-directory metadata; it cannot identify encrypted RAR/7Z content and does not prove that a usable password exists. Corrupt, truncated, unsupported, or missing artifacts produce UNKNOWN/error details; nested archives are not recursively inspected.

## Attachment counts differ from the number of attachment rows

Inline MIME images remain in `attachments` for evidence preservation, but `attachment_count` and `has_attachments` exclude signature-like inline images. Use the `is_inline` column to reconcile the rows.

## A completed output is not at the exact path entered

The supplied path is a base. Threadsaw adds a completion timestamp and collision suffix rather than overwriting prior output. Read the final JSON or GUI log for the actual path.

## Copied attachments have changed-looking filenames

Threadsaw sanitizes path separators, Windows-reserved names, and Unicode format-control characters before writing filesystem names. The original filename remains in SQLite and CSV reports.

## String Search date range seems ignored for files

The range applies only to message-associated SQLite rows. Exported review text and report files do not have a uniform message-date boundary and are searched without that filter.

## Reports display spreadsheet warnings or prefixed values

Threadsaw prefixes strings that spreadsheet software could interpret as formulas. Use JSON or SQLite when the exact leading character is needed.

## EML/MSG-only messages have unknown direction

Declare the client or organization domains during `ingest`/`run` with repeatable `--organization-domain`, use the GUI Organization domains field, or update an existing case with `threadsaw case-config`. This supplies direction and organization-aware factors without configuring trusted mail servers.

## Trust or direction looks wrong after mixing evidence

Threadsaw assumes one mailbox or one coherent mail environment per case. Move unrelated custodians to separate cases; PST-derived trust context applies to every message in its case.
