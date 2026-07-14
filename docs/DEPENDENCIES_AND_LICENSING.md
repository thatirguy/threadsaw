# Dependencies, SBOM, and Licensing

Threadsaw source code is MIT-licensed. Third-party software remains under its own terms. `SBOM.cdx.json` records direct application dependencies; a final container image has additional transitive and operating-system packages, so publishers should generate an image SBOM with `scripts/generate-container-sbom.sh` after the final build.

## Required runtime components

- `opencv-python-headless==5.0.0.93`: QR decoding. The Python packaging project is MIT, OpenCV is Apache-2.0, and bundled binaries have additional notices, including FFmpeg under LGPL terms.
- `pypdfium2==5.11.0`: PDF page rendering for offline QR analysis. It includes PDFium and third-party notices distributed with the wheel.
- `libpst/readpst`: PST extraction in the container. Debian resolves the exact package version when the image is built; the final image SBOM is authoritative for that build.
- Vendored Public Suffix List snapshot: MPL-2.0.

## Optional MSG support and GPL

`extract-msg==0.55.0` is GPL-licensed. It is an optional Python extra and the default published Docker build now excludes it. To build an image with MSG support:

```bash
docker build --build-arg THREADSAW_INSTALL_MSG=1 -t threadsaw:1.3.0-msg .
```

Anyone distributing that image must review and comply with the GPL and all transitive dependency licenses. This documentation is not legal advice.

## Reproducibility

Direct Python versions are pinned in `pyproject.toml` and `requirements.lock`. Platform-specific wheel hashes vary; use a package-locking tool appropriate to the target platform when producing a regulated deployment. Preserve license files from installed wheels and the Debian image.

The published default container is available from `ghcr.io/thatirguy/threadsaw`. Each version has a fixed manifest digest plus OCI provenance and SBOM attestations. Record that digest with the case when reproducibility matters; mutable convenience tags such as `latest` should not be used as evidentiary identifiers.
