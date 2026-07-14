# Threadsaw 1.3.0 installation and deployment

## Recommended: Docker plus host launcher

Requirements:

- Docker Desktop or compatible Docker/Compose runtime;
- Python 3.11+ with Tkinter on the host.

Pull the published default image, then launch the GUI:

```powershell
docker compose pull
python .\launcher\threadsaw_gui.py
```

The versioned image is published as `ghcr.io/thatirguy/threadsaw:1.3.0` for `linux/amd64` and `linux/arm64`. It includes `readpst`, OpenCV, and pypdfium2, excludes optional MSG support, and runs without networking. Set `THREADSAW_IMAGE` to select a different image reference.

## Build manually

```bash
docker build -t threadsaw:1.3.0 .
```

Enable optional MSG support only after reviewing its GPL licensing obligations:

```bash
docker build --build-arg THREADSAW_INSTALL_MSG=1 -t threadsaw:1.3.0-msg .
```

## Native Python installation

```bash
python -m venv .venv
. .venv/bin/activate
pip install .
```

For MSG:

```bash
pip install '.[msg]'
```

PST ingestion requires `readpst` from libpst. For stronger native-path control:

```bash
export THREADSAW_READPST=/usr/bin/readpst
```

Run `threadsaw doctor` to verify OpenCV, pypdfium2/PDFium, MSG support, readpst path/version, and guardrails. PyMuPDF is not used or installed by Threadsaw 1.3.0.

## Case storage

Use a local filesystem with sufficient free space. PST extraction may require space comparable to or larger than the PST, plus attachment artifacts and reports. Avoid live cloud-synchronization conflicts while a case database is open.

## Updating from Version 1.x

1. Stop existing Threadsaw containers.
2. Extract Version 1.3.0 into a new application directory or install the new wheel.
3. Run `docker compose pull`, or rebuild the image when using a customized local build.
4. Open the existing case. Schema migration runs automatically.
5. Run `threadsaw case-context --case <case>` for PST-derived cases.
6. Re-run URL indexing when new bare-`www`, wrapper, PSL, or SharePoint behavior is needed.

Source messages do not need to be re-ingested for schema migration. Re-ingestion may be warranted when attached-email attribution or inline-count corrections are important to an older case, because those changes affect parse-time evidence relationships/counts.

## Acceptance checks

```bash
threadsaw --version
threadsaw doctor --case ./case
pytest -q
```

Before production use, validate representative PSTs, damaged MIME, QR PDFs, large history hunts, and output handling on the intended host platform.
