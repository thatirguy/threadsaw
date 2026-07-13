# Threadsaw V2 prototype 0.3.1 release notes

Version 0.3.1 prevents report and artifact executions from overwriting earlier completed output.

## Output finalization rules

The path supplied to a report or export command is a base name. Threadsaw builds the output in a hidden staging path and appends a compact UTC completion timestamp during finalization.

Examples:

```text
reports/urls.csv                    -> reports/urls_20260712T151500Z.csv
reports/core                        -> reports/core_20260712T151500Z/
reports/attachments                 -> reports/attachments_20260712T151500Z/
exports/attachments                 -> exports/attachments_20260712T151500Z/
exports/message-export              -> exports/message-export_20260712T151500Z/
reports/pipeline                    -> reports/pipeline_20260712T151500Z/
```

If an output with the same completion timestamp already exists, Threadsaw appends `__2`, `__3`, and later suffixes. Existing completed output is never replaced.

Phish Hunt executions remain isolated and now finalize their run folder with the completion timestamp. Run IDs, start times, completion times, configurations, and manifests remain preserved.

## GUI behavior

Output controls now describe their values as base paths. The command preview continues to show the base path, while the process log and final JSON show the actual timestamped destination after completion.

## Validation

The automated suite verifies repeated URL reports, core reports, message exports, attachment reports, and copied-attachment exports without sleeping between runs. Same-second executions create distinct outputs and preserve both results.
