# Threadsaw V2 prototype 0.2.3 release notes

## Purpose

Version 0.2.3 is a stability build addressing SQLite `disk I/O error` failures observed when a case database on a Windows Docker Desktop bind mount remained in WAL mode.

## Changes

- Case databases now use `DELETE` rollback-journal mode, `synchronous=FULL`, and a 30-second busy timeout.
- Legacy WAL cases are converted in place when possible. If bind-mount access fails, Threadsaw copies the main database and sidecars to local container storage, checkpoints the WAL, verifies integrity, converts to rollback journaling, backs up the original files, and replaces the main database.
- The GUI no longer imports SQLite or reads `threadsaw.sqlite3` from Windows/macOS. Scope dropdowns are populated by the containerized `scope list` command.
- `doctor` reports database existence, journal mode, quick-check status, and readiness.
- Input and case folders cannot be the same folder for ingest operations.

## Upgrade

Stop old containers and rebuild without cache:

```powershell
docker compose down --remove-orphans
docker compose build --no-cache
```

Then run doctor against the existing case before exporting:

```powershell
docker compose run --rm threadsaw doctor --case /case
```

If automatic legacy-WAL recovery is required, the original files are preserved under `case/logs/database-backups/<timestamp>/`.
