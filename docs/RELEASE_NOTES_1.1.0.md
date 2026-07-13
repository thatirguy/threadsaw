# Threadsaw 1.1.0 release notes

## Summary

Version 1.1.0 addresses MIME attribution, URL completeness, trusted-mail context, historical-query scale, filesystem safety, and missing-data visibility. It also adds offline QR analysis, bounded ZIP inventory, deleted-item PST extraction, direction classification, four new Phish Hunt evaluations, and recalibrated starter presets.

## Correctness fixes

- Attached `message/rfc822` messages are recorded as wrapper attachments, recursively indexed as linked child message rows, and excluded from the wrapper body/attachment traversal.
- URL candidates are deduplicated before insertion and empty display text is stored consistently, preventing SQLite NULL uniqueness behavior from inflating `url_count`.
- Phish Hunt automatically performs deterministic offline URL indexing for selected messages whose `url_indexed` flag is false.
- Inline image attachments remain available as evidence but no longer inflate `attachment_count`, `has_attachments`, or attachment-history factors.
- Domain comparisons use a vendored static Public Suffix List rather than a short handcrafted suffix list.
- Text bodies now capture bare `www.example.com` forms.
- Proofpoint v2/v3 and Mimecast wrapper decoding is broader but remains string-only.

## Trusted-mail context

Threadsaw does not ask analysts to enter trusted Authentication-Results or Received server identifiers. It surveys only PST-derived messages and enables trusted-dependent factors only when a conservative repeated consensus can be inferred. When consensus is unavailable, the dependent factors are disabled in the effective `scoring_config.json`, listed in the run manifest, and do not masquerade as evaluated zeroes.

`threadsaw case-context --case <case>` recomputes and displays the inferred context and affected-factor availability.

## New analysis features

- **Evaluate QRs:** OpenCV decodes QR codes from stored image attachments; PyMuPDF renders a bounded number of PDF pages for local QR decoding. Decoded values are never contacted.
- **Bounded ZIP inventory:** optional central-directory listing stores member names, sizes, encryption flags, and suspicious extensions without extraction or decompression.
- **Deleted PST items:** `--include-deleted` passes `readpst -D` and uses a distinct extraction cache.
- **Message direction:** reports classify messages as inbound, outbound, internal, or unknown relative to configured or inferred organization domains.
- **SharePoint relationship:** URL reports include `probable_internal`, `probable_external`, `unknown`, or `not_sharepoint` as a heuristic tenant relationship.

## New or split Phish Hunt factors

- Thread continuation uses changed sender infrastructure.
- Payment-change or urgency language is present.
- Attachment is an HTML or SVG document.
- Attachment uses a modern loader, launcher, or macro-enabled Office extension.
- HTML script presence and inline event-handler attributes are now separate evaluations.

There are 71 visible evaluators in Version 1.1.0.

## Scoring and presets

Main reports now include:

- `max_possible_points_evaluated`
- `unknown_positive_points`
- `positive_score_percent_evaluated`

These expose when a low score is based on limited evidence. They do not convert the heuristic score into a probability.

Default preset changes include DKIM failure at 25, SPF failure at 15, plain HTTP at 5, sender/URL-domain difference at 5, HTML script at 45, event handlers at 25, and free-email-provider use at 8 where enabled.

## Security changes

- Unicode category `Cf` characters are stripped from generated filesystem names.
- `readpst` can be pinned with the absolute `THREADSAW_READPST` environment variable.
- standalone-email evaluation installs runtime guardrails directly.
- GUI Docker mount validation rejects ambiguous host paths containing unexpected colons.

## Compatibility

Existing Version 1.0 cases are migrated in place when opened. New columns, indexes, and tables are added without re-ingesting source messages. URL rows are deduplicated during migration. Re-running URL indexing is recommended when analysts need bare-`www` capture, expanded wrapper decoding, or refreshed SharePoint relationship values.

## Boundaries

- QR evaluation scans stored image attachments and a bounded number of rendered PDF pages only. It does not inspect remote images or contact decoded targets.
- ZIP inventory does not recurse into nested archives, extract members, or inspect encrypted contents.
- SharePoint internal/external labels are heuristic.
- Performance-sensitive history queries are now indexed SQL, but representative 50,000–200,000-message acceptance benchmarking is still recommended before operational deployment.

## Release validation

The packaged 1.1.0 release completed 68 automated tests, Python bytecode compilation, clean-wheel installation, CLI version/help smoke tests, Public Suffix List package-data verification, preset-registry validation, and an installed-wheel ingest/report/Phish Hunt smoke workflow.
