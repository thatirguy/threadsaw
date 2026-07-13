# Threadsaw 1.3.0 validation summary

- 74 automated tests passed under Python 3.13 in the release workspace.
- The wheel was built and installed into a clean virtual environment without dependencies; `threadsaw --version` returned 1.3.0.
- New tests cover large-case JSON Lines core reporting and the human-readable Evaluate Phishing Email hit report.
- Existing tests cover parsing, database migration, security guardrails, timestamped outputs, factor evaluation, QR processing, archive inventory, URL handling, GUI command construction, and CLI behavior.

Publication CI repeats tests on Windows, macOS, and Linux for Python 3.11 and 3.13 and builds the OCI image on Linux. Those hosted CI runs remain pending until the repository is published.
