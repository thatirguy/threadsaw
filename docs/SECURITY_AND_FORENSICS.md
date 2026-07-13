# Threadsaw 1.3.0 security and forensic posture

## Offline/static invariant

Threadsaw treats URL, hostname, IP, QR, and attachment content as evidence, never as instructions. It does not resolve, retrieve, preview, launch, mount, extract, decrypt, or execute observed targets.

## Docker controls

The supplied Compose/container posture uses:

- `network_mode: none`
- read-only root filesystem
- non-root UID
- `cap_drop: ALL`
- `no-new-privileges`
- PID limit
- bounded tmpfs
- read-only evidence mount and writable case mount

These controls are the primary runtime boundary. Python socket/subprocess/browser guards are additional defense in depth and are not represented as an in-process sandbox.

## Child processes

Only `readpst` is allowlisted. Arguments are list-form with no shell. Proxy variables are stripped. In the container, the package-installed binary is used. Native deployments may set an explicit absolute path:

```bash
THREADSAW_READPST=/usr/bin/readpst
```

The basename must still be `readpst` or `readpst.exe`. Analysts should validate the binary provenance on native hosts.

## URL and QR handling

URL extraction and wrapper decoding are text transformations only. QR-decoded values are written as text. No result is resolved or submitted to a third party.

The vendored Public Suffix List is static and is never refreshed at runtime. Its source header and license notice remain in the distributed data file.

## Attachment handling

Attachment bytes are hash-addressed and never opened in an associated application. Exported filenames are sanitized for path separators, platform-reserved names, length, and Unicode format controls (`Cf`), including bidirectional overrides.

Optional ZIP inspection reads central-directory metadata through Python's ZIP parser and never calls `read`, `extract`, or `extractall` on members. Its encrypted-ZIP result is based only on member encryption flags and does not decrypt, brute-force, or test passwords. QR PDF processing renders bounded pages through pypdfium2/PDFium in the isolated runtime; it does not launch a viewer or activate embedded content.

## Evidence attribution

Attached emails are separate linked messages. This preserves wrapper/child attribution for bodies and payload hashes. Inline images are retained as evidence with `is_inline=1` but excluded from ordinary attachment counts.

## CSV safety

CSV values beginning with spreadsheet formula prefixes are escaped. SQLite and JSON remain available where exact raw leading characters are required.

## Trust inference

Trusted authserv-id and Received-boundary flags are derived only from repeated evidence in a corpus of at least 20 PST-derived messages. Received inference uses exact-host consensus first and a PSL-bounded parent-domain-suffix fallback for rotating cloud frontends. Manual trusted-server values are removed and ignored. When stable inference is unavailable, dependent Phish Hunt factors are disabled rather than treated as benign failures.

## Forensic cautions

Threadsaw does not claim legal admissibility, parser completeness, malware verdicts, sender attribution, or tenant ownership. Preserve original evidence separately, record tool version/configuration, retain manifests, and independently validate consequential findings.

## Case isolation assumption

A case is expected to represent one mailbox or one coherent mail environment. Mixing unrelated custodians allows one PST corpus's inferred trust context to be applied to unrelated loose messages and can invalidate direction and historical comparisons. Use separate cases unless the evidence belongs to the same environment.
