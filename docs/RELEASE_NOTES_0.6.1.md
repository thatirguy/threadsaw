# Threadsaw V2 prototype 0.6.1 release notes

Version 0.6.1 completes the visible Phish Hunt evaluator catalog and adds usable starter configurations.

## Factor catalog changes

Removed three factors whose prerequisite data is not collected by the current ingestion pipeline:

- Attachment filename extension differs from detected file type
- Attachment-declared MIME type differs from detected file type
- Calendar invitation contains an external URL

Replaced **Attachment is an encrypted or password-protected archive** with **Attachment is an archive**. The new evaluator checks only stored filename extensions and declared MIME types for common archive formats. It never opens, extracts, decrypts, or otherwise inspects archive contents.

All 66 visible factors now have operational evaluators. The hidden removed unique-URL-domain-count factor remains accepted for older configs and returns UNKNOWN/zero.

## Starter configurations

Added backend-defined starter presets for:

- External phishing email hunt
- Internal phishing email hunt
- General phishing email hunt

The presets set explicit enabled states, weights, effect directions, and default parameters. They are conservative heuristics, not calibrated probabilities. Organization-specific factors and campaign-signature factors requiring analyst input remain disabled.

The same definitions are used by the GUI buttons, are included as JSON examples, and can be exported from the CLI with `threadsaw phish-hunt-preset`.

## Compatibility

Older configs containing `encrypted_archive` are automatically upgraded to `attachment_archive` while preserving enabled state, weight, and effect mode. Configs containing the three removed prerequisite-incomplete factors must be revised.

## Validation

- Full automated test suite
- Archive detection by stored extension and MIME metadata
- Preset distinction and effect-direction checks
- Legacy encrypted-archive config migration
- CLI preset JSON export
- Clean wheel installation and smoke testing
