# Threadsaw V2 prototype 0.4.0 release notes

Version 0.4.0 introduces the reviewed Phish Hunt factor-catalog user interface and shared metadata framework.

## Factor-catalog interface

- Added the approved factor catalog under two top-level groups: **Inherently Risky** and **Situational**.
- Grouped factors into collapsible subcategories such as Sender and Header Deception, Security Check Failures, URL Characteristics, Attachment Characteristics, Thread and Relationship History, and Campaign Signatures.
- Added factor search plus Enabled, Disabled, Unavailable, and computational-load filters.
- Added Expand All and Collapse All controls and enabled/shown counts on each subcategory.
- Added Light, Moderate, Heavy, and Extreme load badges. Load reflects work performed during Phish Hunt, not work already completed during ingestion.
- Added prerequisite/availability labels. Pending evaluators are never treated as a negative answer: they return `UNKNOWN`, contribute zero points, and are recorded in the details report.

## Factor help

- Every factor has a hoverable and clickable question-mark control.
- Every hover tooltip ends with **Click for more information.** so users know the short tooltip is not the complete documentation.
- Clicking opens a scrollable explanation with purpose, suspicious and legitimate examples, false-positive cautions, prerequisites, parameters, load explanation, implementation status, result semantics, and security posture.
- Load and availability badges also provide the same hover/click path to detailed help.

## Configuration

- Saved configurations now preserve all visible factor settings and factor-specific parameters.
- Existing 0.3.x configuration files containing the legacy `cross_domain_message` demonstration factor remain accepted by the CLI scoring engine.
- Preset buttons still intentionally set every visible factor to Off / 0 until final preset weights are approved.
- Scores remain uncapped additive integers centered at zero.

## Prototype boundary

The complete approved catalog is documented and configurable, but evaluator implementation is intentionally staged. Version 0.4.0 implements the visible **Sender and recipient share the same domain** demonstration evaluator and retains the hidden legacy cross-domain evaluator for compatibility. All other catalog factors explicitly report `UNKNOWN` until their reviewed evaluators and required ingestion fields are implemented. This prevents the UI from implying an analytic capability that the engine does not yet possess.
