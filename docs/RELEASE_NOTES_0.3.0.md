# Threadsaw V2 prototype 0.3.0 release notes

Version 0.3.0 introduces the first `phish_hunt` scoring prototype.

## Added

- Explainable, uncapped integer scoring centered at zero.
- Mandatory date-range or named-scope selection.
- One prototype factor: sender and recipient domains differ.
- User-configurable toggle, weight, and effect mode.
- Three placeholder presets plus Clear, all Off / 0.
- Save/load configuration controls in the GUI.
- Unique report folder for every hunt execution.
- Main, detail, JSON, configuration, and manifest outputs.
- SQLite run, score, and factor-result tables.
- URL and attachment selection from a Phish Hunt report and integer threshold.
- Editable GUI dropdown of existing hunt reports plus Browse.
- Seven-day long-range warnings.

## Security invariants

- No URL or IP address is followed, resolved, enriched, or contacted.
- No attachment is opened, launched, rendered, or executed.
- The score report is used only for message hash and score selection; actual URL and attachment data comes from SQLite.
- User configurations contain settings only and cannot execute arbitrary code.

## Prototype caveats

- The demonstration factor is intentionally weak and uncalibrated.
- The presets do not yet contain analyst-approved values.
- Cross-platform live GUI testing is still incomplete.

## Prototype validation performed

- 28 automated tests passed.
- Clean wheel installation and CLI smoke test passed.
- Two consecutive hunts created distinct report folders and SQLite run records.
- Positive and negative scores of 1,000,000 were preserved without clipping.
- Score-threshold URL and attachment selection was exercised end to end.
- A headless Tkinter smoke test loaded all nine GUI tabs and produced the Phish Hunt command preview.

Live Docker Desktop execution on Windows, macOS, and Linux remains operator validation work.
