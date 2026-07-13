# GitHub Release Checklist

- Update version in `pyproject.toml`, `src/threadsaw/__init__.py`, Docker labels, GUI branding, changelog, and release notes.
- Run `PYTHONPATH=src pytest -q` on supported platforms.
- Build with `python -m build` and install the wheel in a clean environment.
- Build the OCI image and run it with `--network none`.
- Generate/check `SBOM.cdx.json`; generate an image SBOM from the final image with Syft or Docker Scout when publishing a container.
- Verify licenses and `THIRD_PARTY_NOTICES.md`.
- Confirm no evidence, case databases, credentials, or generated reports are present.
- Tag `vX.Y.Z`, create a GitHub Release, attach wheel/source/checksum files, and publish release notes.
