# Getting Started on Linux

Keep evidence read-only and separate from writable case storage. A fast local filesystem is recommended for large PST extractions and SQLite workloads.

## 1. Published container with the GUI (easiest)

This is the recommended path for most PST and EML investigations.

1. Install Docker Engine with the Compose plugin and Python 3.11 or newer with Tkinter.
2. Download and extract the [Threadsaw 1.3.0 source archive](https://github.com/thatirguy/threadsaw/releases/tag/v1.3.0), or clone the repository.
3. From the Threadsaw directory, pull the image and start the host launcher:

```bash
docker compose pull
python3 launcher/threadsaw_gui.py
```

The GUI displays the containerized CLI command before execution. The published `ghcr.io/thatirguy/threadsaw:1.3.0` image supports `linux/amd64` and `linux/arm64`, includes `readpst`, and does not include optional MSG parsing.

## 2. Published container from the shell

Use Docker Compose directly for automation or headless operation:

```bash
docker compose pull
docker compose run --rm --no-deps -T \
  -v /evidence:/input:ro \
  -v /cases/matter01:/case \
  threadsaw run --input /input --case /case
```

Podman may be substituted at the container/CLI level with `podman compose` when a Compose provider is installed. Rootless Podman on SELinux systems may require `:Z` or `:z` mount labeling.

## 3. Locally built container

Build locally when you need to audit or customize the image. Optional MSG support adds the GPL-licensed `extract-msg` dependency:

```bash
docker compose build
docker compose build --build-arg THREADSAW_INSTALL_MSG=1
python3 launcher/threadsaw_gui.py
```

## 4. Native wheel installation

Native operation has a larger host dependency and trust surface than the container. Download the wheel and `SHA256SUMS.txt` from the [1.3.0 release](https://github.com/thatirguy/threadsaw/releases/tag/v1.3.0), verify its SHA-256, and use an isolated environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./threadsaw-1.3.0-py3-none-any.whl
threadsaw doctor
```

Install `pst-utils`/`readpst` through the distribution package manager for PST support, and set `THREADSAW_READPST` to its absolute path in controlled deployments. Install the wheel with its `msg` extra only when native MSG parsing and the additional license are acceptable.

## 5. Editable source installation (most complex)

Use this only when changing Threadsaw or running its test suite:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
PYTHONPATH=src pytest -q
```

See [Large-Case Operations](../LARGE_CASES.md), [Dependencies, SBOM, and Licensing](../DEPENDENCIES_AND_LICENSING.md), and [Troubleshooting](../TROUBLESHOOTING.md) for operational details.
