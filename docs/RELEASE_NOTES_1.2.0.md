# Threadsaw 1.2.0 release notes

## Overview

Version 1.2.0 replaces the AGPL-licensed PyMuPDF dependency, makes PST-derived trust inference safer and more reliable in rotating cloud-mail infrastructure, adds organization-domain configuration for loose-email cases, and introduces a bounded encrypted-ZIP evaluator.

## PDF QR rendering

Evaluate QRs now renders bounded PDF pages with `pypdfium2`/PDFium instead of PyMuPDF. QR decoding remains offline through OpenCV, and decoded values remain inert text. Threadsaw does not fetch remote images, contact decoded URLs, or render arbitrary non-PDF document formats.

`pyproject.toml` now requires:

```text
opencv-python-headless>=4.10,<5
pypdfium2>=5.8,<6
```

Redistributors should preserve the PDFium third-party license notices shipped with the installed `pypdfium2` distribution.

## Trusted PST context

Trusted Authentication-Results and Received-boundary inference now requires at least 20 PST-derived messages. Smaller corpora never infer trusted server context, even when two or more messages agree.

Received boundary selection now proceeds in two stages:

1. Exact hop-0 `by` hostname consensus across at least 40% of the PST-derived corpus.
2. When exact hosts rotate, the most specific stable parent-domain suffix meeting the same threshold.

For example, rotating hosts under `namprd14.prod.outlook.com` can establish that stable suffix without treating one individual frontend hostname as permanent. The Public Suffix List bounds the fallback so it never broadens above the registrable unit.

When no conservative consensus exists, dependent factors are disabled in the effective hunt configuration and recorded in the manifest. Threadsaw still does not prompt for or accept trusted authserver/Received-host identifiers.

## Organization domains

Organization domains are analyst knowledge rather than trusted-server inference. They may now be supplied for PST, EML, or MSG-only cases:

```bash
threadsaw ingest --input ./evidence --case ./case \
  --organization-domain client.example \
  --organization-domain subsidiary.example
```

The `run` command accepts the same repeatable option. The desktop launcher exposes a comma-separated Organization domains field.

An existing case can be updated with:

```bash
threadsaw case-config --case ./case \
  --organization-domain client.example \
  --organization-domain subsidiary.example
```

This replaces the declared list and immediately recomputes message direction and organization-aware case context. It does not change trusted-server inference.

## Thread-hijack evaluator

`thread_continuation_changed_infrastructure` now accepts an exact In-Reply-To/References Message-ID match plus participant overlap without requiring an identical normalized subject. Subject continuity is recorded as evidence, but a hijacker appending urgency or payment language no longer evades this factor solely by changing the subject.

The stricter `corroborated_thread_reply` factor still requires subject continuity and remains a weak trust signal in the starter presets.

## Encrypted ZIP evaluator

The new visible factor is:

```text
attachment_encrypted_zip
Attachment is an encrypted or password-protected ZIP-family archive
```

It uses the ZIP central-directory encryption bit already collected by bounded archive inventory. Threadsaw does not extract, decrypt, brute-force, or attempt a password. The factor is Situational because legitimate organizations also use protected ZIP files.

Starter weights:

| Preset | Enabled | Weight |
|---|---:|---:|
| External phishing | Yes | 25 |
| Internal phishing | Yes | 20 |
| General phishing | Yes | 25 |

Phish Hunt and Evaluate Phishing Email automatically perform bounded ZIP-family inventory when an enabled evaluator depends on that metadata. The new `archive_inspections` table records complete, truncated, and failed inventories. A truncated or failed inventory with no observed encryption returns `UNKNOWN`, never a misleading `NO`.

## Case-boundary assumption

A case should represent one mailbox or one coherent mail environment. PST-derived trusted context is applied to every message in the case, including loose EML/MSG files added later. Mixing unrelated custodians can therefore produce misleading trust and direction classifications and is explicitly discouraged.

## Compatibility

- Existing Version 1 cases migrate in place to schema version 8.
- Existing `archive_members` rows remain valid.
- Old `encrypted_archive` factor IDs now migrate to `attachment_encrypted_zip` rather than the generic archive factor.
- Existing `attachment_archive` settings are unchanged.
- Re-ingestion is not required for the new context logic, organization-domain configuration, or ZIP factor. Stored ZIP bytes must be available for automatic inventory.

## Validation

Version 1.2.0 completed 72 automated tests, including:

- pypdfium2 PDF rendering and QR decoding
- exact-host and rotating-host domain-suffix trust inference
- hard minimum PST corpus size
- EML-only organization-domain direction classification
- subject-drift thread-hijack detection
- bounded encrypted-ZIP inventory and scoring
- schema migration and preset validation
