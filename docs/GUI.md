# Threadsaw 1.3.0 desktop launcher

The Tkinter launcher builds command lines for the network-disabled Docker CLI. It does not reimplement parsing or scoring on the host.

## Navigation

The workflow uses two rows of tabs where necessary. Step 1 contains ingestion, reporting, and scope setup. Step 2 contains Phish Hunt, Evaluate Phishing Email, String Search, Evaluate QRs, URL analysis, attachment report/export, message export, and diagnostics.

## Phish Hunt factor controls

Factors are grouped under **Inherently Risky** and **Situational**, then under collapsible subcategories. Each row includes:

- enabled toggle;
- weight;
- effect mode;
- computational-load badge;
- evaluator availability;
- question-mark help control;
- factor-specific parameters.

Hover tooltips end with **“Click for more information.”** Clicking opens a scrollable explanation with behavior, prerequisites, suspicious and legitimate examples, false-positive notes, load rationale, and implementation status.

Search, enabled/disabled/unavailable filters, load filters, expand/collapse actions, preset import/export, and overall load summaries support review of the 72-factor catalog.

## Current Version 1.3.0 controls

- Ingest and Full Pipeline: **Include recoverable deleted PST items** (`readpst -D`) and an optional comma-separated **Organization domains** field for PST, EML, or MSG cases.
- Attachment Report/Export: filename extension filter, bounded ZIP listing toggle, member limits, and stored encryption-flag reporting.
- Evaluate QRs: selector, output folder, maximum PDF pages, and render DPI.
- Diagnostics/CLI visibility: inferred case context is available through `threadsaw case-context`; analyst-declared organization domains can also be updated with `threadsaw case-config`.

## Mount validation

The launcher validates host paths before creating Docker `-v` arguments. Windows drive-letter colons are accepted; other ambiguous colons are rejected with an explanatory message. Evidence mounts are read-only.

## Long-running operations

PST extraction, URL indexing, QR rendering, ZIP inventory, and large Phish Hunts may take time. The GUI streams CLI progress and completion output. Closing the launcher does not convert partial staging folders into completed outputs.
