# Threadsaw V2 prototype 0.5.0 release notes

Version 0.5.0 adds two analysis modules and extends attachment and Phish Hunt configuration workflows.

## String Search

- Searches every SQLite field, exported message review TXT files, and case reports in any selected combination.
- Uses case-insensitive literal matching only.
- Supports an optional SQLite-only UTC date range.
- Pre-populates the newest completed message-export folder in the GUI when available.
- Writes a new completion-timestamped report folder for every execution.

## Evaluate Phishing Email

- Accepts an existing case message SHA-256 or a new EML/MSG.
- Uses full case context for existing messages and matching external files.
- Uses standalone factors for unmatched external files by default.
- Offers an explicit case-history override with a warning.
- Exports a starter `matched_factors_config.json` containing factors that returned YES.
- Does not modify the real case when evaluating a new external file.

## Attachment filtering

- Attachment report/export accepts one or more filename-extension filters.
- Filtering is case-insensitive and uses the stored original filename.
- No attachment is reopened or reclassified to apply the filter.

## Phish Hunt configurations

- GUI controls are labeled **Import config.json** and **Export config.json**.
- The same JSON document is accepted by `threadsaw phish-hunt --config`.
- GUI executions continue to write a complete active configuration into the selected case before invoking the CLI.

## Validation

The source test suite includes String Search, existing-case and standalone email evaluation, attachment-extension filtering, GUI discovery/default behavior, and all earlier security and workflow tests.
