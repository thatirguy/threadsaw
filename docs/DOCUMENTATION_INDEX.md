# Threadsaw 1.3.0 documentation index

## Start here

- [`README.md`](../README.md) — purpose, security boundary, primary workflows, quick start, and major 1.3.0 changes.
- [`USER_GUIDE.md`](USER_GUIDE.md) — operator workflow from case creation through reporting, scoring, QR review, and exports.
- [`INSTALLATION_AND_DEPLOYMENT.md`](INSTALLATION_AND_DEPLOYMENT.md) — native, Docker, and desktop-launcher installation and upgrade guidance.
- [`GUI.md`](GUI.md) — desktop launcher layout and control behavior.
- [`CLI_REFERENCE.md`](CLI_REFERENCE.md) — command syntax, selectors, and exit behavior.

## Analysis and scoring

- [`MODULE_REFERENCE.md`](MODULE_REFERENCE.md) — purpose and behavior of every user-facing module.
- [`PHISH_HUNT.md`](PHISH_HUNT.md) — scoring model, configuration lifecycle, context inference, output interpretation, and presets.
- [`PHISH_HUNT_FACTOR_CATALOG.md`](PHISH_HUNT_FACTOR_CATALOG.md) — complete catalog of all 72 visible factors.
- [`EVALUATOR_REFERENCE.md`](EVALUATOR_REFERENCE.md) — evaluator-oriented copy of the complete factor catalog.
- [`EVALUATE_PHISHING_EMAIL.md`](EVALUATE_PHISHING_EMAIL.md) — single-message and standalone-message evaluation behavior.
- [`STRING_SEARCH.md`](STRING_SEARCH.md) — exact case-insensitive string-search scope and outputs.
- [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md) — `case.json`, inferred context, Phish Hunt JSON, presets, and environment variables.

## Technical and forensic references

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component model, evidence flow, database-first design, and trust boundaries.
- [`DATABASE_AND_OUTPUTS.md`](DATABASE_AND_OUTPUTS.md) — case layout, SQLite tables, migrations, and report schemas.
- [`FILE_REFERENCE.md`](FILE_REFERENCE.md) — function of every shipped source, launcher, test, example, and documentation file.
- [`SECURITY_AND_FORENSICS.md`](SECURITY_AND_FORENSICS.md) — fixed offline policy, attachment and URL handling, runtime protections, and forensic caveats.
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — common operational problems and safe recovery steps.
- [`DECISIONS.md`](DECISIONS.md) — major architecture decisions and their consequences.

## Validation and release history

- [`TESTING_AND_VALIDATION.md`](TESTING_AND_VALIDATION.md) — automated coverage and organizational acceptance guidance.
- [`VALIDATION_PLAN.md`](VALIDATION_PLAN.md) — broader platform, scale, security, parser, and scoring validation plan.
- [`RELEASE_STATUS.md`](RELEASE_STATUS.md) — current release maturity and known limits.
- [`RELEASE_NOTES_1.3.0.md`](RELEASE_NOTES_1.3.0.md) — changes in the current release.
- [`RELEASE_NOTES_1.1.0.md`](RELEASE_NOTES_1.1.0.md) — historical Version 1.1 changes.
- [`CHANGELOG.md`](../CHANGELOG.md) — chronological project history.
- [`ROADMAP.md`](ROADMAP.md) — post-1.2 priorities.
- [`PROTOTYPE_STATUS.md`](PROTOTYPE_STATUS.md) — historical prototype lineage and transition to official releases.

## Historical manual

- [`THREADSAW_1.0.0_MANUAL.md`](THREADSAW_1.0.0_MANUAL.md) documents the 1.0 baseline only. It is retained for release history and must not be used as the authoritative reference for 1.1 or 1.2 behavior.

- [`LARGE_CASES.md`](LARGE_CASES.md) — large PST preflight, streaming outputs, recovery, and operational guidance.
- [`DEPENDENCIES_AND_LICENSING.md`](DEPENDENCIES_AND_LICENSING.md) — pinned dependencies, optional GPL MSG support, and SBOM guidance.
- [`getting-started/WINDOWS.md`](getting-started/WINDOWS.md), [`MACOS.md`](getting-started/MACOS.md), and [`LINUX.md`](getting-started/LINUX.md) — platform-specific setup.
- [`GITHUB_RELEASE_CHECKLIST.md`](GITHUB_RELEASE_CHECKLIST.md) — publication checklist.
