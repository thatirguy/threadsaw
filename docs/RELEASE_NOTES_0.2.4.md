# Threadsaw V2 prototype 0.2.4 release notes

Version 0.2.4 improves operator learning and sender-infrastructure review while preserving the permanent offline and non-execution security invariants.

## GUI command preview

The launcher now displays the Docker Compose command that would be run for the currently selected module and options. The preview updates as paths, selectors, dates, output locations, worker count, and attachment-copy settings change. Hovering or focusing an action button selects that operation for preview on tabs with more than one action.

The command preview is display-only. Threadsaw continues to execute Docker through an argument list and never invokes a shell.

## Branding placement

The project motto now appears in the GUI banner and at the start of non-quiet CLI runs. It has been removed from per-message `review.txt` exports.

## Sender-IP classifications

Analyst-facing message, URL, attachment, and message-export summary CSVs now include separate columns for:

- `trusted_boundary_ip`: sending-side IP literal from the first `Received` field matched to a configured trusted recipient host.
- `spf_client_ip`: `client-ip` recorded in the preferred Authentication-Results or Received-SPF evidence.
- `claimed_originating_ip`: IP literal recorded in recognized originating/client-IP headers.
- `topmost_received_ip`: sending-side IP literal from the topmost Received field.
- `bottommost_received_ip`: sending-side IP literal from the bottommost Received field.

Unavailable values remain blank. The former aggregate `sender_ips` column is intentionally omitted from analyst-facing CSVs. These fields are parsed offline and are evidence labels, not attribution conclusions.

## Message review exports

Companion `review.txt` files now include the five sender-IP classifications plus the preferred recorded SPF, DKIM, DMARC, and ARC results, authentication service identifier, and whether that result row was configured as trusted. Full raw Authentication-Results and Received fields remain in the review document.

## Validation

- 20 automated tests pass.
- Tests cover sender-IP classification across message, URL, attachment, and export-summary reports.
- Tests confirm the motto is absent from message review exports.
- Tests confirm the GUI command preview is generated without executing a command.

Live GUI validation on Windows, macOS, and Linux remains required before the optional launcher is considered fully cross-platform validated.
