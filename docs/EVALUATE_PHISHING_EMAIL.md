# Evaluate Phishing Email

This module evaluates one message against all relevant Version 1 Phish Hunt factors and produces a starter config containing the factors that returned YES.

## Inputs

- Existing case `message_sha256`, or
- Standalone `.eml`/`.msg` file.

## Modes

- Existing case message: standalone and historical factors use the case.
- External file whose derived message hash matches the case: the case record is used.
- External file not in the case: standalone factors run; historical factors are NOT_APPLICABLE.
- Case-history override: historical factors compare with a temporary clone of the case. Use only when the file belongs to the same mailbox population.

The real case is never modified by external-file evaluation.

## Outputs

- `evaluation.csv`
- `evaluation_details.csv`
- `evaluation.json`
- `matched_factors_config.json`
- `run_manifest.json`

The generated config enables YES factors with a starter weight of 10. Review effect modes, weights, and parameters before reuse.

## Security

The evaluator is static and offline. It never follows URLs, contacts IP addresses, or opens/executes attachments.
