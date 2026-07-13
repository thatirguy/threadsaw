# String Search

String Search performs case-insensitive literal substring matching across any selected combination of:

- Every field in the case SQLite database.
- Exported message review-text files.
- Text-based case reports (`.csv`, `.json`, `.txt`, `.md`, `.log`).

It does not use regular expressions, fuzzy matching, stemming, semantic search, OCR, binary inspection, or network access.

An optional UTC date range applies only to message-associated SQLite rows. File-based sources are searched without the range and are labeled accordingly.

Each run creates a unique completion-timestamped directory containing `string_search.csv`, `string_search.json`, and `run_manifest.json`.
