#!/usr/bin/env sh
set -eu
IMAGE="${1:-threadsaw:latest}"
OUTPUT="${2:-threadsaw-container.sbom.cdx.json}"
if command -v syft >/dev/null 2>&1; then
  syft "$IMAGE" -o cyclonedx-json > "$OUTPUT"
else
  echo "Syft is required to generate a complete image SBOM: https://github.com/anchore/syft" >&2
  exit 1
fi
