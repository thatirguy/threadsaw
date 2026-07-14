# Threadsaw 1.3.0 validation summary

- 75 automated tests passed under Python 3.13 in the release workspace.
- The wheel was built and installed into an isolated virtual environment; `threadsaw --version` returned 1.3.0 and the vendored Public Suffix List was present.
- New tests cover large-case JSON Lines core reporting, the human-readable Evaluate Phishing Email hit report, and strict DNS-label boundaries for Microsoft Safe Links wrapper detection.
- Existing tests cover parsing, database migration, security guardrails, timestamped outputs, factor evaluation, QR processing, archive inventory, URL handling, GUI command construction, and CLI behavior.

Publication CI passes on Windows, macOS, and Linux for Python 3.11 and 3.13 and builds the OCI image on Linux. The tag-triggered release workflow additionally validates the installed wheel and publishes an attested `linux/amd64` and `linux/arm64` image.
