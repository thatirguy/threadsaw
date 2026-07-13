# Threadsaw 1.3.0 database and outputs

## Case layout

```text
case/
  case.json
  threadsaw.sqlite3
  sources/
  extracted/
  artifacts/
    attachments/
    embedded-messages/
  reports/
  exports/
  logs/
```

Source evidence is hashed. Loose EML/MSG bytes are copied into the case; PST-derived EMLs remain in the extraction tree. Attachment bytes are hash-addressed.

## Important SQLite tables

- `sources` — source paths, hashes, parser, status, and PST/EML parentage.
- `messages` — normalized headers, bodies, dates, direction, counts, and indexed EML SHA-256.
- `message_sources` — message-to-source links.
- `message_relationships` — wrapper/child links for attached `message/rfc822` messages.
- `recipients` — To, CC, and BCC addresses.
- `received_hops` — parsed Received fields and inferred trust flag.
- `authentication_results` — stored SPF/DKIM/DMARC/ARC results and inferred trust flag.
- `attachments` — attachment metadata, artifact path, executable observation, disposition, content ID, and `is_inline`.
- `archive_members` — bounded ZIP central-directory member metadata; no extracted bytes.
- `archive_inspections` — per-attachment inventory status, member totals, encrypted-member count, truncation, errors, and completion time.
- `qr_results` — locally decoded QR text and normalized URL text, when applicable.
- `urls` — original, normalized, displayed, wrapper, decoded target, effective domain, SharePoint presence, and heuristic relationship.
- `scopes` / `scope_messages` — immutable logical selections.
- `phish_hunt_runs`, `phish_hunt_results`, `phish_hunt_factor_results` — run metadata, scores, coverage, and factor evidence.
- `errors` — stage-specific parsing or processing errors.

## Key `messages` fields added or emphasized in Version 1

- `normalized_subject`
- `from_address_normalized`
- `from_domain_registrable`
- `direction`
- `attachment_count` — excludes inline attachments.
- `url_count` — deduplicated stored URL rows.
- `url_indexed`

Dates are normalized to UTC whole seconds. Date selections are start-inclusive and end-exclusive.

## Core message report

`messages.csv` and `messages.json` include message identifiers, selected/header/Received dates, direction, sender/recipient fields, sender IP categories, preferred authentication results, attachment and URL counts, parser status, and EML path.

Direction values:

- `inbound`
- `outbound`
- `internal`
- `unknown`

## URL report

`urls.csv` includes:

- original and normalized URL text;
- displayed-text mismatch flag;
- wrapper type and decoded target;
- hostname and Public-Suffix-List registrable domain;
- `contains_sharepoint_reference` (`yes`/`no`);
- `sharepoint_relationship` (`probable_internal`, `probable_external`, `unknown`, or `not_sharepoint`).

The relationship is a heuristic based on tenant text, organization domains, and recipient domains. It is not an authoritative tenant ownership determination.

## Attachment report

`attachments.csv` includes filename, declared MIME type, disposition, content ID, `is_inline`, hashes, size, executable/script observation, artifact path, and optional copied path. Filename-extension filters apply to report and copy operations.

When ZIP listing is enabled, `archive_members.csv` contains member names, compressed/uncompressed sizes, encryption flag, and suspicious-extension flag. `archive_inspections` records whether each inventory was complete, truncated, unavailable, or failed. Members are never extracted, decrypted, or password-tested.

## QR outputs

A timestamped QR run contains:

- `qr_codes.csv`
- `qr_codes.json`
- `run_manifest.json`

Rows identify the message, attachment, attachment hash, source kind, PDF page where applicable, decoded text, URL flag, and normalized URL text. No target is retrieved.

## Phish Hunt main report

In addition to message context and raw score, `phish_hunt.csv` includes:

- `positive_points`
- `negative_points`
- `evaluated_factor_count`
- `unknown_factor_count`
- `max_possible_points_evaluated`
- `unknown_positive_points`
- `positive_score_percent_evaluated`
- `top_score_reasons`
- run/config/case identifiers

`phish_hunt_details.csv` contains one row per enabled evaluated factor with answer, points, weight, effect mode, evidence, source, status, reason, and evaluator version.

## Migration

Opening an older Version 1 case migrates it in place to schema version 8, adding Version 1.3.0 columns, indexes, and tables. Existing URL duplicates caused by NULL displayed text are collapsed. Re-running URL indexing is recommended to gain new capture and decoder behavior. Re-ingestion is required only when an older case must retroactively correct parse-time attached-message attribution or inline-attachment counts.
