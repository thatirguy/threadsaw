# Threadsaw 1.3.0 configuration reference

## `case.json`

A case document identifies the case, stores durable analyst configuration, and records inferred context. Threadsaw creates and updates it atomically.

Representative structure:

```json
{
  "case_id": "...",
  "created_utc": "2026-07-13T12:00:00Z",
  "config": {
    "organization_domains": ["example.com"],
    "organization_domains_declared": true,
    "legitimate_sharepoint_host": "example.sharepoint.com"
  },
  "inferred_context": {
    "source": "pst-corpus-consensus",
    "pst_message_count": 25000,
    "minimum_trust_corpus_messages": 20,
    "trust_consensus_ratio": 0.4,
    "trusted_authserv_ids": ["mx.example.com"],
    "trusted_received_hosts": [],
    "trusted_received_domains": ["namprd14.prod.outlook.com"],
    "trusted_received_match_mode": "domain-suffix",
    "organization_domains": ["example.com"],
    "organization_domains_source": "analyst-declared",
    "computed_utc": "2026-07-13T12:15:00Z"
  }
}
```

### `organization_domains`

Optional analyst-supplied registrable domains used for message direction, organization-domain lookalike factors, embedded-legitimate-domain checks, and SharePoint relationship heuristics. They are permitted for PST, EML, and MSG-only cases because they represent analyst knowledge rather than trusted-server inference.

Declare them while ingesting:

```bash
threadsaw ingest --input ./evidence --case ./case \
  --organization-domain example.com \
  --organization-domain subsidiary.example
```

Or replace them later and recompute direction immediately:

```bash
threadsaw case-config --case ./case \
  --organization-domain example.com \
  --organization-domain subsidiary.example
```

The GUI provides the same setting as a comma-separated environment field. In a PST-derived case, Threadsaw may infer likely organization domains from repeated recipient-domain evidence only when no analyst-declared list is present.

### `legitimate_sharepoint_host`

Optional known tenant hostname used only by Phish Hunt factors that compare a URL to an expected SharePoint host.

### Trusted authserv-id and Received hosts

Do not enter these manually. Version 1.3.0 removes legacy manual values and derives conservative consensus from PST-derived messages only when the PST corpus contains at least 20 messages.

Authentication trust requires a repeated authserv-id across at least 40% of the PST-derived corpus. Received trust first attempts the exact hop-0 `by` hostname. When cloud frontends rotate, it falls back to the most specific stable parent-domain suffix that reaches the same threshold, bounded by the offline Public Suffix List. The derived values and match mode are recorded under `inferred_context`. When inference fails, dependent evaluations are removed from the effective hunt configuration.

Use:

```bash
threadsaw case-context --case ./case
```

This recomputes and reports the context without prompting or changing source evidence.

### Case-boundary assumption

Use one mailbox or one coherent mail environment per case. PST-derived trusted context applies to every message stored in the case, including loose EML/MSG files added later. Mixing unrelated custodians can make trusted-boundary, date, direction, and historical comparisons misleading.

## Phish Hunt `config.json`

```json
{
  "config_version": 1,
  "name": "Custom hunt",
  "preset": "custom",
  "factors": [
    {
      "factor_id": "payment_urgency_keywords",
      "enabled": true,
      "weight": 15,
      "effect_mode": "risk_when_yes",
      "parameters": {
        "keywords": "updated bank details\nwire\nurgent\ngift card",
        "include_financial_patterns": true
      }
    }
  ]
}
```

`factor_id` must be a known visible or supported legacy ID. `weight` is a non-negative integer. Effect modes are documented in [`PHISH_HUNT.md`](PHISH_HUNT.md).

Unknown factor IDs are rejected. Removed legacy `exact_unique_url_domains` configurations are accepted only for compatibility and contribute no score.

## Starter presets

- `external` — tuned for messages entering an organization.
- `internal` — tuned for apparent same-organization or compromised-account messages.
- `general` — balanced starting point where direction is uncertain.

Starter weights are heuristics and should be reviewed against local evidence and false-positive tolerance.

## Environment variables

### `THREADSAW_READPST`

Optional absolute path to the exact `readpst` executable. This is useful for native installations where relying on the first executable found on `PATH` is undesirable.

```bash
export THREADSAW_READPST=/usr/bin/readpst
```

The executable basename must still be `readpst` (or `readpst.exe` on Windows-like hosts).
