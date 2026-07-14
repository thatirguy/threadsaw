# Threadsaw 1.3.0

> When you're looking for a needle in a haystack, you need a pitchfork.

Threadsaw is an offline, case-based email triage and phishing-risk analysis tool for PST, EML, and optionally MSG evidence. Finding the initial phishing email while hunting for the root cause of a Business Email Compromise (BEC) case can be difficult, so I built Threadsaw to make that work easier. Its robust GUI displays the underlying CLI command for each operation, making workflows easy to understand, repeat, and script. Threadsaw never follows URLs, contacts hosts, or executes attachments. It is best used with Docker; on Windows, the recommended Docker workflow requires WSL 2.

## Investigation how-to guides

**Start here: [Practical investigation workflows](docs/USE_CASE_GUIDE.md)**

- [Analyze an EML or MSG file](docs/USE_CASE_GUIDE.md#use-case-1-analyze-an-eml-or-msg-file)
- [Break a PST into EML files and summarize its contents](docs/USE_CASE_GUIDE.md#use-case-2-break-a-pst-into-eml-files-and-summarize-the-contents)
- [Export URLs or attachments from a date range](docs/USE_CASE_GUIDE.md#use-case-3-export-urls-or-attachments-from-a-date-range)
- [Score all emails in a date range by risk and export artifacts](docs/USE_CASE_GUIDE.md#use-case-4-score-all-emails-in-a-date-range-by-risk-and-export-artifacts)
- [Fingerprint a known phishing email and hunt for similar messages](docs/USE_CASE_GUIDE.md#use-case-5-fingerprint-a-known-phishing-email-and-hunt-for-similar-messages)
- [Search for a string across case content](docs/USE_CASE_GUIDE.md#use-case-6-search-for-a-string-across-case-content)

## Getting started

- [Windows](docs/getting-started/WINDOWS.md)
- [macOS](docs/getting-started/MACOS.md)
- [Linux](docs/getting-started/LINUX.md)
- [Large cases](docs/LARGE_CASES.md)
- [Dependencies and licensing](docs/DEPENDENCIES_AND_LICENSING.md)
- [Complete documentation index](docs/DOCUMENTATION_INDEX.md)

Version **1.3.0** is a licensing, context-inference, archive-analysis, and workflow-maintenance release. It remains an analyst-assistance tool rather than a malware sandbox, reputation service, or substitute for evidence-handling procedures.

## Security boundary

Threadsaw performs static, offline analysis only:

- No DNS resolution, IP connections, URL retrieval, redirects, previews, or reputation lookups.
- No browser or operating-system URL launch.
- No attachment, script, macro, embedded-object, archive-member, or decoded-QR execution.
- ZIP inventory reads bounded central-directory metadata only and never extracts members or attempts passwords.
- QR decoding processes stored images and bounded rendered PDF pages only; decoded targets are never contacted.
- The only permitted child process is `readpst`, used for PST extraction. `THREADSAW_READPST` may identify an explicit absolute executable path.

Docker runs with networking disabled, a read-only root filesystem, dropped capabilities, and a non-root user as defense in depth.

## Primary workflows

1. **Full Pipeline** — ingest evidence, index URLs, and write core reports.
2. **Ingest Data** — hash, extract, parse, and store PST/EML/MSG evidence; optionally pass `readpst -D` for recoverable deleted PST items.
3. **Generate Reports** — message, attachment, URL, archive-member, and error rollups.
4. **Evaluate QRs** — offline QR decoding from stored image and PDF attachments. PDF rendering uses `pypdfium2`/PDFium rather than PyMuPDF.
5. **Set Scope** — save reusable date-based message selections.
6. **Phish Hunt** — score a required date range or named scope using a `config.json` file. Missing URL and enabled ZIP-inventory prerequisites are completed automatically.
7. **Evaluate Phishing Email** — evaluate one indexed or standalone EML/MSG and export a matching-factor config.
8. **String Search** — case-insensitive literal search across SQLite, exported review text, and reports.
9. **Get URLs** — extract, normalize, and statically decode supported rewritten URLs.
10. **Export Attachments** — report or copy inert attachment bytes, optionally filtered by extension and with bounded ZIP inventory.
11. **Export Messages** — export EMLs, review text, summaries, and manifests.
12. **Case Context** — recompute and display conservative trusted-mail context inferred from PST-derived messages, without prompting for server identifiers.
13. **Case Configuration** — declare organization domains for PST, EML, or MSG-only cases so direction and organization-aware evaluators are available.

## Notable 1.3.0 changes

- Replaced PyMuPDF with permissively licensed `pypdfium2`/PDFium for bounded PDF-page rendering in Evaluate QRs.
- Trusted Authentication-Results and Received-boundary inference now requires at least **20 PST-derived messages**.
- Received-boundary inference first tries an exact `by` host, then falls back to the most specific stable domain suffix that meets the same 40% consensus threshold. This supports rotating M365 and Google Workspace frontend hosts without asking the analyst to identify trusted servers.
- Added analyst-declared organization domains through repeatable `--organization-domain` ingest/run options, the GUI environment field, and `threadsaw case-config`.
- The thread-infrastructure-change evaluator now accepts an exact Message-ID reference plus participant overlap even when a hijacker changes the subject.
- Added **Attachment is an encrypted or password-protected ZIP-family archive**, backed by bounded ZIP central-directory metadata. It does not extract, decrypt, or attempt a password.
- Phish Hunt automatically inventories ZIP-family attachments when an enabled evaluator depends on that metadata.
- Added `archive_inspections` status records so truncated or failed inventories produce `UNKNOWN` rather than a misleading `NO`.

## Case-boundary assumption

A Threadsaw case should represent **one mailbox or one coherent mail environment**. Trusted context inferred from a PST is applied to all messages in that case, including loose EML/MSG files added later. Do not mix unrelated custodians or organizations in one case unless that inheritance is intentional and documented.

Organization domains are analyst knowledge, not trusted-server inference. They can be supplied for a loose-email case:

```bash
threadsaw ingest \
  --input ./evidence \
  --case ./case \
  --organization-domain client.example \
  --organization-domain subsidiary.example
```

They can also be replaced after ingestion, with message direction recomputed immediately:

```bash
threadsaw case-config \
  --case ./case \
  --organization-domain client.example \
  --organization-domain subsidiary.example
```

Threadsaw never prompts for trusted Authentication-Results or Received host identifiers. When a sufficiently large PST corpus cannot support conservative inference, dependent evaluations are disabled in the effective hunt configuration and documented in the run manifest.

## Documentation

Start with the current [`Threadsaw 1.3.0 manual`](docs/THREADSAW_1.0.0_MANUAL.md) or the [`complete documentation index`](docs/DOCUMENTATION_INDEX.md). Version 1.3.0 documentation includes release notes, module/CLI references, database and output descriptions, security guidance, and all 72 evaluators.

## Tests

```bash
pytest -q
```

## License

Threadsaw is released under the MIT License. `libpst/readpst`, OpenCV, `pypdfium2`/PDFium, the Public Suffix List, and optional `extract-msg` have their own licenses or terms that should be reviewed for redistribution. The installed `pypdfium2` distribution carries PDFium third-party license notices that must be preserved when bundling dependencies.
