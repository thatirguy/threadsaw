# Threadsaw V2 prototype 0.2.5 release notes

Version 0.2.5 fixes the date-range message-export selector and improves long-running operation visibility and multi-mailbox review context.

## Fixed

- `threadsaw export-messages --start ... --end ...` now works without combining the date range with `--all` or another selector.
- The GUI emits the same standalone date selector in its command preview and executed command.

## Progress and operator feedback

- Every GUI operation begins with a plain-language start notice.
- Full pipeline and ingest explicitly warn that extraction and indexing can take a long time for large PST files.
- The GUI writes a stage-aware heartbeat every 90 seconds while an operation remains active.
- CLI commands emit clearer start and completion stage messages unless `--quiet` is used.

## Recipient context

- Added `recipient_addresses` beside `sender_email` in URL and attachment CSVs.
- Added `recipient_addresses` to message and message-export summary CSVs.
- Message CSVs retain separate `to_addresses`, `cc_addresses`, and `bcc_addresses` columns.
- Exported `review.txt` files show an aggregate Recipients line near the sender and retain the detailed recipient section.

## Folder behavior

- `compose.yaml` contains no default input/case volume mappings. User-selected host folders are mounted explicitly, avoiding surprise empty project-level evidence folders.

## Security invariants

The release does not add network access or active content handling. Threadsaw still never follows or retrieves URLs, resolves or connects to IP addresses, or opens/executes attachments.
