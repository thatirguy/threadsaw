# Threadsaw V2 prototype 0.2.2 release notes

## Implemented

- Canonical byte-for-byte case copies for loose EML and MSG sources.
- MSG-derived EMLs preserve available transport headers through extract-msg's email conversion path.
- Whitespace-only text parts fall back to HTML-derived text; interpreted header values are stripped of embedded nulls.
- Subject-derived message and attachment export directories with collision-safe numeric suffixes.
- Copied attachments retain sanitized original filenames and report their case-relative exported path.
- Visible calendar-date highlighting and a selected-date label.
- Named-scope dropdowns populated from the current case database.
- Full-pipeline and default report output under `/case/reports`.
- Separate attachment report and copied-byte output paths.

## Compatibility

Cases ingested before 0.2.2 may not contain canonical copies for loose EML/MSG sources. Re-ingest those sources to make the case self-contained. The database migration adds `sources.canonical_path`, but metadata alone cannot recreate unavailable source bytes.

## Validation performed

- 16 automated tests passed.
- Full-pipeline EML smoke test wrote all core outputs under `/case/reports`.
- Loose EML export succeeded after the external input file was deleted.
- Attachment export produced a subject-derived directory and original filename.
- Headless GUI smoke test loaded all eight tabs, confirmed report/export defaults, and confirmed the selected calendar day was highlighted.
- A clean wheel installation with optional MSG dependencies ingested and exported the supplied real-world `Test.msg`, preserving Message-ID, Date, Return-Path, Received, Authentication-Results, HTML, and derived body text.

These checks do not establish compatibility with every PST/MSG variant, forensic completeness, legal admissibility, or independent security assurance.
