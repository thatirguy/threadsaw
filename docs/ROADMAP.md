# Threadsaw roadmap after 1.3.0

The current release contains the complete intended 1.1 feature set. Future work should prioritize validation and evidence quality over adding more heuristic factors.

## Highest priority

1. Benchmark indexed history evaluators on representative 50,000–200,000-message PST cases, including Docker Desktop filesystems.
2. Independently compare PST, MSG, embedded-message, attachment, and URL attribution against controlled reference corpora.
3. Calibrate the three Phish Hunt presets against labeled organizational data and publish precision/recall only when defensible.
4. Fuzz malformed MIME, URL wrappers, archive metadata, QR images, and Unicode filenames.
5. Add explicit database backup/clone tooling before schema migration for regulated deployments.

## Candidate enhancements

- Additional bounded static archive parsers for formats other than ZIP, without extraction.
- More QR image preprocessing and supported static barcode families.
- Optional static document-structure inspection where dependencies and forensic limits can be clearly documented.
- Case-level performance telemetry and query-plan diagnostics.
- Signed release artifacts and reproducible container-build documentation.

## Permanently outside the product boundary

- Live URL, DNS, WHOIS, IP, or reputation enrichment.
- Browser launch, URL preview, or redirect following.
- Attachment execution, detonation, macro execution, mounting, or active document rendering.
- Automatic declarations that a message is malicious or benign.
