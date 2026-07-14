# Getting Started on Linux

## Container deployment

```bash
docker compose pull
docker compose run --rm --no-deps -T \
  -v /evidence:/input:ro \
  -v /cases/matter01:/case \
  threadsaw ingest --input /input --case /case
```

Run `docker compose build` instead when auditing or customizing the image. Optional MSG parsing requires a local build with `THREADSAW_INSTALL_MSG=1`.

Podman may be substituted at the container/CLI level with `podman compose` when a Compose provider is installed. Rootless Podman on SELinux systems may require `:Z` or `:z` mount labeling.

## Native development installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[msg,dev]'
```

Install `pst-utils`/`readpst` through the distribution package manager for PST support. Pin `THREADSAW_READPST` to an absolute path in controlled native deployments.
