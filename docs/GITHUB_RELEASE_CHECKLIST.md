# GitHub Release Checklist

- Update version in `pyproject.toml`, `src/threadsaw/__init__.py`, Docker labels, GUI branding, changelog, and release notes.
- Run `PYTHONPATH=src pytest -q` on supported platforms.
- Build with `python -m build` and install the wheel in a clean environment.
- Build the OCI image and run it with `--network none`.
- Generate/check `SBOM.cdx.json`; generate an image SBOM from the final image with Syft or Docker Scout when publishing a container.
- Verify licenses and `THIRD_PARTY_NOTICES.md`.
- Confirm no evidence, case databases, credentials, or generated reports are present.
- Confirm `CITATION.cff`, `SBOM.cdx.json`, validation counts, and dependency pins describe the release commit.
- Merge release preparation through a pull request and confirm required CI and CodeQL checks pass.
- Create and push the signed or annotated `vX.Y.Z` tag only from the verified `main` commit.
- Confirm the tag-triggered workflow publishes the GHCR image, provenance/SBOM attestations, wheel, source distribution, source SBOM, checksums, and GitHub Release.
- Make the GHCR package public and verify an unauthenticated pull by immutable digest.
- Do not publish to PyPI unless native installation prerequisites and ownership of the project name have been reviewed for that release.
