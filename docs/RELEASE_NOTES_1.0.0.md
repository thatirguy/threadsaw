# Threadsaw 1.0.0 release notes

## Official Version 1 baseline

Threadsaw 1.0.0 promotes the approved 0.6.1 implementation to the first official release of the current GUI/CLI code line.

## Analysis capabilities

- 66 visible Phish Hunt factors with operational evaluators.
- External, Internal, and General starter configurations with reviewable weights and effect modes.
- Metadata-only archive identification; no archive opening or extraction.
- String Search, Evaluate Phishing Email, URL reporting, attachment extension filtering, message exports, scopes, and threshold-based downstream selection.
- URL and attachment counts in SQLite and message rollups.
- SharePoint URL reports limited to a yes/no reference field; ownership/tenant logic remains in Phish Hunt.

## Documentation

Added authoritative Version 1 references for:

- Installation and deployment.
- Analyst workflows and every GUI module.
- Complete CLI command/options reference.
- SQLite tables, case layout, report schemas, and outputs.
- `case.json` and Phish Hunt configuration.
- All 66 evaluator functions, examples, loads, prerequisites, and preset settings.
- Every file in the source distribution.
- Testing, validation boundaries, troubleshooting, and release status.

## Compatibility

- Existing 0.6.1 cases require no re-ingestion.
- Existing 0.6.1 configurations remain compatible.
- Package and GUI version changed to 1.0.0.
- No new database schema migration or factor-scoring change is introduced by the Version 1 promotion.
