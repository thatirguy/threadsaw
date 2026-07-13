# Threadsaw 1.3.0 architecture

Threadsaw is a case-based, offline email triage pipeline. Source evidence is hashed and left unchanged. Parsed evidence is normalized into SQLite once; reports and evaluators query that index.

## Fixed security boundary

Out of scope:

- DNS, HTTP, WHOIS, reputation services, redirects, previews, and IP connections;
- browser or OS URL launch;
- attachment, script, macro, archive-member, embedded-object, or QR-target execution;
- general-purpose child processes.

The only allowed child process is `readpst` for PST extraction. Docker is network-disabled, read-only except for explicit mounts/tmpfs, capability-dropped, and non-root. Python guardrails are defense in depth rather than a sandbox boundary.

## Data flow

```text
Read-only evidence
  |-- PST -> readpst -> EML tree
  |-- EML -> canonical case copy
  `-- MSG -> canonical copy + clearly labeled derived EML
                         |
                 parse and normalize
                         |
       SQLite + hash-addressed attachment artifacts
                         |
  reports | scopes | URL index | QR | ZIP inventory | Phish Hunt | exports
```

No step contacts an observed URL, hostname, or IP address.

## MIME attribution

`message/rfc822` parts are terminal attachment containers for the wrapper traversal. Their serialized bytes are stored as an attachment and recursively parsed as a separate message linked through `message_relationships`. Child bodies and payloads are never attributed to the wrapper.

## Context inference

Trusted Authentication-Results IDs and Received boundary hosts are not supplied by the user. Threadsaw derives them only from repeated values in a corpus of at least 20 PST-derived messages. Authentication service IDs require 40% consensus. Received boundary inference first tries exact hop-0 `by` hostnames, then the most specific stable parent-domain suffix that reaches the same threshold, bounded by the offline Public Suffix List. If no stable consensus exists, dependent factors are disabled for that run. Inferred flags can be recomputed from normalized rows without re-parsing source messages. Analyst-declared organization domains are separate case knowledge and may be supplied for PST, EML, or MSG-only cases.

## URL model

URL extraction is deterministic and offline. Candidate deduplication happens in Python and is reinforced by an SQLite expression index treating NULL/empty displayed text identically. Supported wrapper decoding is a string transform. Registrable domains use a vendored PSL snapshot. Phish Hunt automatically indexes selected messages whose URL state is incomplete.

## Attachment model

All MIME parts identified as attachments are stored, including inline evidence and attached emails. Inline parts are marked `is_inline=1` and excluded from attachment counts/history noise. ZIP inventory reads central-directory metadata only. QR analysis reads image bytes or bounded rendered PDF pages.

## Scale model

Normalized sender address, sender registrable domain, normalized subject, URL effective domain, recipient address, and trusted-hop indexes support history evaluators through SQL `EXISTS`, counts, and distinct aggregates. Large message-ID selections are chunked to stay below portable SQLite variable limits.

## Known limits

- MSG parsing is best-effort derived representation.
- QR detection depends on local OpenCV/pypdfium2 decoding and bounded page/render settings.
- ZIP inventory covers ZIP-compatible central directories and does not recursively inspect nested archives. Encryption detection means at least one ZIP member has its encryption flag set; Threadsaw does not decrypt or test passwords.
- SharePoint relationship and organization-domain inference are heuristics.
- Broad enterprise-scale benchmarks remain an operational acceptance requirement.

## Case boundary

A case should contain one mailbox or one coherent mail environment. PST-derived trusted context is applied to all messages in that case, including later loose EML/MSG additions. Mixing unrelated custodians can distort trust, direction, and history-based evaluations.
