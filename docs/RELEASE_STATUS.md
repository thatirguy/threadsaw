# Threadsaw 1.3.0 release status

Version 1.3.0 is the current official release. It builds on the 1.0 baseline with correctness repairs, indexed historical queries, conservative PST-derived trust inference with rotating-host fallback, offline QR decoding through pypdfium2, bounded ZIP metadata inspection and encrypted-member scoring, deleted-item PST extraction, direction classification, score-coverage fields, and 72 visible Phish Hunt evaluators.

## Implemented and tested

- PST, EML, and optional MSG ingestion with source hashing and normalized SQLite storage.
- Correct terminal handling and child-message linkage for attached `message/rfc822` content.
- Offline URL extraction, deduplication, bare-`www` capture, wrapper decoding, and vendored Public Suffix List matching.
- Message, URL, attachment, archive-member, QR, error, search, score, and export outputs.
- Inline-attachment distinction and safe filesystem naming with Unicode format-control removal.
- 72 visible evaluators and External, Internal, and General starter configurations.
- Automatic URL indexing before Phish Hunt.
- PST-derived trust-context inference with a 20-message minimum, exact-host/domain-suffix Received fallback, and automatic removal of unavailable dependent factors.
- Indexed SQL history evaluators and database migration from Version 1.0.
- Network-disabled Docker posture and runtime denial of sockets, DNS, URL retrieval, launchers, and non-`readpst` subprocesses.

## Important limitations

- Not independently security-audited or formally validated for legal admissibility.
- Not a malware sandbox, antivirus product, or reputation service.
- QR analysis is limited to stored images and bounded rendered PDF pages; it does not inspect remote images or other barcode families.
- ZIP inventory is ZIP-compatible central-directory metadata only; no extraction, recursion, decryption, or password testing. The encrypted-ZIP factor can see only the standard per-member encryption flag.
- SharePoint relationship and inferred trusted infrastructure are heuristics.
- MSG conversion is best effort and depends on optional `extract-msg` support.
- Large-case query design has been improved, but representative 50,000–200,000-message operational benchmarks remain an acceptance requirement.
- Existing Version 1.0 cases require re-ingestion to retroactively correct attached-email attribution and inline-attachment counts.

## Release relationship

Version 1.0.0 was the first official release of the approved 0.6.1 implementation. Version 1.3.0 is a substantive schema, parser, evaluator, and functionality update. Existing cases are migrated in place when opened; the original case should be preserved before any operational upgrade.

## Packaged-release validation

The release artifact was validated with 68 passing automated tests, clean-wheel installation, CLI smoke tests, bundled Public Suffix List verification, complete preset/evaluator registry checks, and a local ingest/report/Phish Hunt smoke workflow. These checks do not replace representative PST and large-case acceptance testing.

## Case-boundary requirement

Operational use should keep one mailbox or one coherent mail environment per case. PST-derived trust context applies to every message in the case; unrelated custodians should be separated.
