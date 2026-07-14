# Threadsaw 1.3.0 file reference

This inventory describes every file shipped in the source distribution. Runtime cases, generated reports, caches, wheels, and build directories are not source files.

## Project root

| File | Function |
|---|---|
| `.dockerignore` | Excludes caches, local cases, and development clutter from the container build context. |
| `.gitignore` | Excludes virtual environments, build products, caches, and local evidence/case data. |
| `README.md` | Current overview, fixed security boundary, workflows, quick start, and documentation entry point. |
| `CHANGELOG.md` | Chronological behavior and release history. |
| `LICENSE` | MIT license for Threadsaw code. Third-party components retain their own licenses. |
| `pyproject.toml` | Python package metadata, dependencies, optional MSG support, console entry point, and package-data inclusion. |
| `Dockerfile` | Builds the non-root runtime with `readpst`, QR/PDF dependencies, and hardened defaults. |
| `compose.yaml` | Network-disabled, read-only-root Compose service used by the launcher. |
| `Makefile` | Convenience commands for installation, tests, Docker build, and diagnostics. |
| `CITATION.cff` | Citation metadata for the current release. |
| `SBOM.cdx.json` | CycloneDX source/wheel dependency inventory; the published image carries its own complete SBOM attestation. |

## GitHub automation

| File | Function |
|---|---|
| `.github/workflows/ci.yml` | Tests Python 3.11 and 3.13 on Windows, macOS, and Linux and performs a container smoke build. |
| `.github/workflows/release.yml` | On a version tag, validates release metadata, builds and attests Python artifacts, publishes the multi-architecture GHCR image, and creates the GitHub Release. |
| `.github/dependabot.yml` | Prioritizes security updates and groups periodic routine Python and GitHub Actions updates. |

## Desktop launcher and examples

| File | Function |
|---|---|
| `launcher/threadsaw_gui.py` | Host-side Tkinter launcher; renders modules, factor help/load controls, builds Docker commands, validates mounts, and streams output. |
| `examples/make_sample_eml.py` | Produces a small synthetic EML for smoke testing. |
| `examples/phish_hunt_presets/external_phishing.json` | Complete External phishing starter configuration. |
| `examples/phish_hunt_presets/internal_phishing.json` | Complete Internal phishing starter configuration. |
| `examples/phish_hunt_presets/general_phishing.json` | Complete General phishing starter configuration. |
| `examples/phish_hunt_prototype.json` | Historical minimal configuration retained for compatibility demonstrations; not a recommended 1.1 preset. |

## Package entry points and common infrastructure

| File | Function | Main public interface |
|---|---|---|
| `src/threadsaw/__init__.py` | Package version and identity. | `__version__` |
| `src/threadsaw/__main__.py` | Supports `python -m threadsaw`. | delegates to CLI `main` |
| `src/threadsaw/cli.py` | Defines commands, options, validation, progress, and command dispatch. | `build_parser`, `main` |
| `src/threadsaw/case.py` | Creates, reads, and atomically updates case metadata. | `initialize_case`, `load_case`, `update_case` |
| `src/threadsaw/db.py` | Opens SQLite, applies migrations/indexes, reports health, and records errors. | `connect_db`, `initialize_schema`, `database_health`, `record_error` |
| `src/threadsaw/util.py` | UTC normalization, hashing, safe names, atomic output, file iteration, chunking, and path helpers. | utility functions listed in source |
| `src/threadsaw/output_naming.py` | Creates non-overwriting completion-timestamped files/folders and staging paths. | timestamp/staging/finalize helpers |
| `src/threadsaw/progress.py` | Console progress callbacks and counters. | `console_progress`, `ProgressCounter` |

## Ingestion and parsing

| File | Function | Main public interface |
|---|---|---|
| `src/threadsaw/ingest.py` | Discovers evidence, hashes sources, runs PST extraction, parses EML/MSG, stores messages and artifacts, links attached emails, and recomputes context. | `ingest_path` |
| `src/threadsaw/parsers/eml.py` | Parses MIME headers/bodies/attachments, treats `message/rfc822` as a terminal wrapper attachment, and returns recursively parsed child messages. | `ParsedAttachment`, `ParsedEmbeddedMessage`, `ParsedMessage`, `parse_eml` |
| `src/threadsaw/parsers/msg.py` | Converts optional MSG input to a labeled derived EML representation and invokes the EML parser. | `parse_msg` |
| `src/threadsaw/ip_fields.py` | Extracts and categorizes sender-IP evidence from stored headers/hops. | `extract_ips`, `received_sender_ips`, `sender_ip_fields`, `enrich_sender_ip_rows` |
| `src/threadsaw/message_context.py` | Normalizes recipient context and enriches report rows in bounded batches. | `recipient_fields`, `enrich_recipient_rows` |
| `src/threadsaw/case_context.py` | Infers conservative PST-corpus trusted auth/Received and organization context, recomputes derived flags, and disables unavailable dependent factors. | `recompute_case_context`, `filter_config_for_available_context` |

## Domain, URL, attachment, archive, and QR analysis

| File | Function | Main public interface |
|---|---|---|
| `src/threadsaw/domains.py` | Offline hostname normalization and Public-Suffix-List suffix/registrable-domain resolution. | `normalize_hostname`, `public_suffix`, `registrable_domain` |
| `src/threadsaw/data/public_suffix_list.dat` | Vendored static Public Suffix List snapshot used without network access. |
| `src/threadsaw/urls.py` | Extracts text/HTML URLs and bare `www` forms, deduplicates candidates, statically decodes supported wrappers, stores domain/SharePoint fields, and writes reports. | `LinkParser`, `extract_urls`, URL report writers |
| `src/threadsaw/attachments.py` | Queries attachment metadata, applies extension filters, writes reports, and copies sanitized inert artifacts. | `attachment_rows`, `export_attachment_report`, `export_attachment_run` |
| `src/threadsaw/archive_inspection.py` | Performs opt-in bounded ZIP central-directory inventory without extraction or member reads. | `inspect_zip_attachments`, `archive_member_rows`, `write_archive_member_report` |
| `src/threadsaw/qr.py` | Decodes QR codes locally from stored images and bounded rendered PDF pages; never contacts decoded targets. | `evaluate_qrs` |

## Reports, selection, search, and export

| File | Function | Main public interface |
|---|---|---|
| `src/threadsaw/reports.py` | Builds message/authentication rollups and writes timestamped core CSV/JSON reports. | `auth_summary_for_message`, `message_rows`, report writers |
| `src/threadsaw/selection.py` | Resolves hash, CSV, scope, date, all-message, and report-threshold selectors and creates immutable scopes. | `read_message_hashes_csv`, `resolve_message_hashes`, `create_scope` |
| `src/threadsaw/string_search.py` | Performs literal Unicode case-folded search across SQLite and selected filesystem text trees. | `search_sqlite`, `search_text_tree`, `run_string_search` |
| `src/threadsaw/exporter.py` | Writes selected EMLs, review text, summaries, manifests, and original MSG where retained. | `export_messages` |

## Phish Hunt and single-message evaluation

| File | Function | Main public interface |
|---|---|---|
| `src/threadsaw/factor_catalog.py` | Defines the visible and legacy factor registry, categories, descriptions, examples, prerequisites, parameters, and load labels. | factor definitions and `factor_catalog_document` |
| `src/threadsaw/factor_evaluators.py` | Implements the message-local and indexed case-history evaluator functions. | `eval_*` functions |
| `src/threadsaw/phish_hunt_presets.py` | Defines the External, Internal, and General default toggles, weights, modes, and parameters. | `preset_config`, `available_presets` |
| `src/threadsaw/phish_hunt.py` | Normalizes JSON configs, evaluates messages, calculates scores/coverage, auto-indexes URLs, records runs, writes requested/effective configs and reports, and validates report-threshold selection. | `FactorDefinition`, config helpers, `evaluate_message`, `run_phish_hunt`, run/report helpers |
| `src/threadsaw/evaluate_email.py` | Evaluates an indexed SHA-256 or isolated external EML/MSG, applies standalone/history rules, and exports a matched-factor starter config. | `evaluate_phishing_email` |

## Security and diagnostics

| File | Function | Main public interface |
|---|---|---|
| `src/threadsaw/security.py` | Installs socket/DNS/URL-launch/subprocess guardrails and invokes only approved `readpst` with list-form arguments and a stripped environment. | `SecurityGuardrailError`, `install_runtime_guardrails`, `run_readpst`, `security_posture` |
| `src/threadsaw/doctor.py` | Reports dependency availability, selected `readpst`, platform, disk, database integrity, and security posture. | `run_doctor`, `os_access_writable` |

## Tests

| File | Primary coverage |
|---|---|
| `tests/test_1_1_features.py` | Attached-email attribution, URL dedupe/wrappers/bare-www, context inference/removal, inline counts, PSL, migration, ZIP, QR, direction, and new factors. |
| `tests/test_1_2_features.py` | pypdfium2 PDF QR rendering, 20-message trust minimum, rotating-host domain fallback, analyst organization domains, subject-drift thread continuity, and encrypted-ZIP scoring. |
| `tests/test_attachment_extension_filter.py` | Attachment extension parsing/filtering and reporting. |
| `tests/test_cli.py` | CLI parsing, version, commands, selectors, and validation. |
| `tests/test_counts_sharepoint_and_evaluators.py` | Persistent counts, SharePoint fields, and evaluator behavior. |
| `tests/test_database.py` | Schema initialization, migration, journaling, and health. |
| `tests/test_evaluate_email.py` | Existing-message and standalone evaluation modes and outputs. |
| `tests/test_launcher.py` | GUI construction, commands, navigation, factor help/load controls, and mount validation. |
| `tests/test_phish_hunt.py` | Config normalization, scoring, presets, details, coverage, reports, and compatibility. |
| `tests/test_security.py` | Network, launcher, subprocess, filename, and `readpst` guardrails. |
| `tests/test_string_search.py` | SQLite/filesystem literal search and date-scope rules. |
| `tests/test_timestamped_outputs.py` | Staging, finalization, collision avoidance, and non-overwrite behavior. |
| `tests/test_workflow.py` | End-to-end ingestion, reports, URL/attachment/export workflows, and source handling. |

## Documentation

| File | Function |
|---|---|
| `docs/DOCUMENTATION_INDEX.md` | Navigation for the current documentation set. |
| `docs/USER_GUIDE.md` | End-to-end operator guidance. |
| `docs/INSTALLATION_AND_DEPLOYMENT.md` | Installation, Docker, launcher, and upgrade instructions. |
| `docs/GUI.md` | Desktop launcher behavior. |
| `docs/CLI_REFERENCE.md` | Command and option reference. |
| `docs/MODULE_REFERENCE.md` | User-facing module descriptions. |
| `docs/PHISH_HUNT.md` | Scoring and configuration model. |
| `docs/PHISH_HUNT_FACTOR_CATALOG.md` | Full 72-factor catalog. |
| `docs/EVALUATOR_REFERENCE.md` | Evaluator-focused copy of the catalog. |
| `docs/EVALUATE_PHISHING_EMAIL.md` | Single-message evaluation reference. |
| `docs/STRING_SEARCH.md` | String Search reference. |
| `docs/CONFIGURATION_REFERENCE.md` | Case and hunt configuration reference. |
| `docs/ARCHITECTURE.md` | Component and data-flow design. |
| `docs/DATABASE_AND_OUTPUTS.md` | Case layout, tables, fields, and output formats. |
| `docs/SECURITY_AND_FORENSICS.md` / `docs/SECURITY.md` | Security boundary and forensic cautions. |
| `docs/TROUBLESHOOTING.md` | Operational recovery guidance. |
| `docs/DECISIONS.md` | Architecture decision record. |
| `docs/TESTING_AND_VALIDATION.md` | Automated and organizational validation guidance. |
| `docs/VALIDATION_PLAN.md` | Expanded acceptance plan. |
| `docs/RELEASE_STATUS.md` | Current maturity and limitations. |
| `docs/RELEASE_NOTES_1.3.0.md` | Current release changes. |
| `docs/RELEASE_NOTES_1.1.0.md` | Historical Version 1.1 changes. |
| `docs/RELEASE_NOTES_*.md` | Historical release notes. |
| `docs/ROADMAP.md` | Future validation and bounded-feature priorities. |
| `docs/PROTOTYPE_STATUS.md` | Historical development lineage. |
| `docs/THREADSAW_1.0.0_MANUAL.md` | Historical 1.0 manual; not authoritative for the current 1.3.0 release. |
