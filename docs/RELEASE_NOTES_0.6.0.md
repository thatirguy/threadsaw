# Threadsaw V2 prototype 0.6.0 release notes

Version 0.6.0 is the first broad Phish Hunt evaluator build.

## Phish Hunt evaluators

- Implements 65 visible factor evaluators using only normalized SQLite data and stored message/header/body content.
- Removes **Exact number of unique URL destination domains** from the visible catalog.
- Retains that removed factor as a hidden, unavailable legacy entry so older `config.json` files can still be imported and explained.
- Leaves four factors pending because ingestion does not yet collect the required data:
  - attachment extension versus general detected file type;
  - declared MIME type versus general detected file type;
  - encrypted/password-protected archive status;
  - calendar invitation external-URL fields.
- Pending factors return `UNKNOWN` and zero points with an explicit prerequisite reason.
- Keeps all factor processing offline and static. No URL, hostname, or IP address is contacted, and no attachment is opened or executed.

## Counts and reports

- Adds `url_count` and `url_indexed` to the SQLite `messages` table.
- Keeps `attachment_count` as the ingestion-time attachment total.
- Adds `url_count` and `url_indexed` to the message/PST/EML rollup CSV and JSON reports.
- Recalculates URL rows and the stored count when URL indexing is rerun.

## SharePoint reporting

- Removes internal/external SharePoint classification from URL extraction and URL CSV output.
- Adds `contains_sharepoint_reference` with `yes` or `no` to the URL report.
- Leaves legitimate-host mismatch and newly observed external-tenant decisions in configurable Phish Hunt factors.

## GUI and configuration

- Updates the Phish Hunt explanation to state that the higher the score **in the output CSV**, the more likely the message is to match the configured phishing indicators.
- Shows 65 factors as available and four as evaluator pending.
- Preserves hover help, click-for-more-information dialogs, computational-load labels, import/export of `config.json`, and completion-timestamped run folders.

## Compatibility

Existing cases are migrated in place by adding `url_count` and `url_indexed` with safe defaults. Rerun offline URL indexing to populate accurate counts for older cases.
