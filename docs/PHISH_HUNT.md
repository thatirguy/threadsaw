# Threadsaw 1.3.0 Phish Hunt

Phish Hunt applies an analyst-reviewable `config.json` to a required date range or named scope. It is an additive heuristic model, not a probability model.

> The higher the score in the output CSV, the more likely the message is to match the configured phishing indicators.

## Run preparation

Before scoring, Threadsaw:

1. recomputes PST-derived trusted-mail context;
2. disables trusted-dependent factors when stable context cannot be inferred;
3. identifies selected messages with `url_indexed=0`;
4. performs deterministic offline URL indexing for those messages;
5. performs bounded ZIP-family inventory when an enabled factor needs archive metadata;
6. stores both the requested and effective configurations in the run directory.

No URL is followed and no host is contacted.

## Factor answers

- `YES` — the factor condition matched.
- `NO` — the evaluator had sufficient evidence and the condition did not match.
- `UNKNOWN` — a message-specific prerequisite was missing or inconclusive.
- `NOT_APPLICABLE` — the factor does not apply in the current evaluation mode, such as a history factor on a standalone email.
- `ERROR` — the evaluator failed at its isolation boundary; the remaining hunt continues.

`UNKNOWN`, `NOT_APPLICABLE`, and `ERROR` contribute zero points.

## Effect modes

- `risk_when_yes`: YES `+weight`; NO `0`.
- `trust_when_yes`: YES `-weight`; NO `0`.
- `bidirectional_risk`: YES `+weight`; NO `-weight`.
- `bidirectional_trust`: YES `-weight`; NO `+weight`.

Scores are uncapped integers centered at zero.

## Evidence coverage fields

The main CSV includes:

- `max_possible_points_evaluated` — positive-risk ceiling among factors that returned YES or NO.
- `unknown_positive_points` — positive-risk ceiling attached to enabled factors that could not be evaluated.
- `positive_score_percent_evaluated` — `positive_points / max_possible_points_evaluated × 100`, when the denominator is nonzero.

These fields show when a low score may reflect incomplete evidence. They do not normalize trust deductions, replace the raw score, or represent a calibrated probability.

## Trusted Authentication-Results and Received context

Threadsaw does not ask the user to identify trusted authserv-ids or boundary hosts. It uses repeated consensus from PST-derived messages only, and only when at least 20 PST-derived messages are available. Authentication-service IDs require 40% corpus consensus. Received boundary inference tries exact hop-0 `by` hosts first, then the most specific stable parent-domain suffix meeting the same threshold. Loose EML/MSG evidence does not establish trusted-mail infrastructure.

When no stable consensus exists, the following enabled factors are disabled in the effective configuration and listed in the manifest:

- `trusted_spf_fail`
- `trusted_dkim_fail`
- `trusted_dmarc_fail`
- `trusted_arc_fail`
- `date_received_discrepancy`
- `sender_ip_new_for_sender`

Run `threadsaw case-context --case <case>` to recompute and inspect availability.

## Configuration files

A configuration has this shape:

```json
{
  "config_version": 1,
  "name": "General phishing email hunt",
  "preset": "general",
  "factors": [
    {
      "factor_id": "reply_to_domain_mismatch",
      "enabled": true,
      "weight": 25,
      "effect_mode": "risk_when_yes",
      "parameters": {}
    }
  ]
}
```

Export starter files with:

```bash
threadsaw phish-hunt-preset --name external --output external.json
threadsaw phish-hunt-preset --name internal --output internal.json
threadsaw phish-hunt-preset --name general --output general.json
```

The GUI can import, modify, and export the same JSON documents.

## Outputs

Every run receives a completion-timestamped folder containing:

- `phish_hunt.csv`
- `phish_hunt_details.csv`
- `phish_hunt.json`
- `scoring_config.json` — effective configuration actually executed
- `requested_scoring_config.json` — original requested configuration
- `run_manifest.json`

The manifest records URL auto-indexing, inferred context, factors removed because context was unavailable, score semantics, hashes, selection, and timestamps.

## History factors and scale

Version 1.3.0 stores normalized sender address, sender registrable domain, and normalized subject fields and evaluates history through indexed SQL existence or aggregate queries. It no longer loads every prior message body for every factor. Large cases still require sufficient storage I/O and should be benchmarked with representative evidence.

## Factor reference

See [`PHISH_HUNT_FACTOR_CATALOG.md`](PHISH_HUNT_FACTOR_CATALOG.md) or [`EVALUATOR_REFERENCE.md`](EVALUATOR_REFERENCE.md) for all 72 factors, examples, prerequisites, parameters, computational load, and starter weights.

## Case-boundary assumption

Use one mailbox or one coherent mail environment per case. PST-derived trusted context and case-history comparisons apply to every message in the case. Mixing unrelated custodians can make trust, direction, and historical novelty results misleading.
