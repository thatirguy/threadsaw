# Large-Case Operations

Threadsaw 1.3.0 adds bounded-memory reporting and Phish Hunt output for large mailboxes.

## Large case mode

Use `--large-case` with `report`, `phish-hunt`, or `run`. CSV output is streamed, Phish Hunt detail rows are written as each message is scored, and JSON arrays are replaced by JSON Lines (`.jsonl`). This avoids retaining the complete result set in memory.

## PST disk preflight

Before invoking `readpst`, Threadsaw compares free space on the case filesystem with a default estimate of five times the PST size. The estimate covers EML expansion, attachment artifacts, SQLite, and reports. Change it with `--disk-multiplier`; override a failed check only with `--allow-low-disk`.

## Fault isolation and recovery

Each PST-derived EML is parsed inside its own exception boundary. A malformed message is recorded in `errors.csv` and indexing continues. Completed PST extraction folders are reused. Incomplete extraction output is preserved rather than deleted before a clean retry. If `readpst` returns partial EMLs and fails, Threadsaw indexes those files and records the extraction as partial; `readpst` itself does not provide a reliable cross-platform resume mechanism.

## Operational guidance

Use local SSD storage, avoid synchronized/network folders, keep one mailbox or coherent mail environment per case, and run date-bounded hunts when practical. Large-case mode reduces memory pressure but cannot remove the I/O cost of creating and hashing hundreds of thousands of EML files.
