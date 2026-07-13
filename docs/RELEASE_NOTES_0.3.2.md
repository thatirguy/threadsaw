# Threadsaw V2 prototype 0.3.2 release notes

Version 0.3.2 reorganizes the desktop launcher around the normal investigative workflow.

## Changed

- Added a first-page workflow dashboard with **Step 1: Data Initialization** and **Step 2: Deeper Analysis and Exports**.
- Added prominent navigation buttons for Full Pipeline, Ingest Data, Generate Reports, Set Scope, Phish Hunt, Get URLs, Export Attachments, and Export Messages.
- Moved Diagnostics to the upper-right banner.
- Removed the standalone Initialize Case GUI button and `threadsaw init` command. Case initialization remains an internal prerequisite performed automatically by `ingest` and `run`.
- Other operations now provide a clear error when the selected folder is not an existing Threadsaw case.
- Added a plain-language Phish Hunt explanation describing score direction, inclusion of all selected messages, and preset-first configuration.
- Applied more visible styling to action and workflow buttons.

## Compatibility

Existing cases remain compatible. No re-ingestion or database migration is required. Scripts that called `threadsaw init` should remove that command and begin with `threadsaw ingest` or `threadsaw run`.
