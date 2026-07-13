# Getting Started on Windows

## Recommended: Docker Desktop

1. Install Docker Desktop and enable the WSL 2 backend. If you don't have WSL 2, install that first.
2. Extract or clone Threadsaw.
3. Open PowerShell in the repository root.
4. Build: `docker compose build`.
5. Start the GUI: `python .\\launcher\\threadsaw\_gui.py`.
6. Select a read-only evidence folder and a separate writable case folder.

For a very large PST, store evidence and the case on a fast local SSD, allocate at least 16 GB to Docker Desktop, and enable **Large case mode**. Threadsaw performs a disk preflight using a default five-times-PST estimate.

## CLI example

```powershell
docker compose run --rm --no-deps -T `
  -v "C:\\Evidence:/input:ro" `
  -v "D:\\Cases\\Matter01:/case" `
  threadsaw ingest --input /input --case /case --workers 4
```

Native wheel installations can analyze EML/MSG on Windows, but PST processing requires a compatible `readpst`; the container is therefore preferred.

