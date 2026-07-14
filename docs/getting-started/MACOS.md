# Getting Started on macOS

Keep evidence in a read-only folder and use a separate writable case folder. Local APFS SSD storage is preferable to network or cloud-synchronized folders, particularly for PSTs that produce many EML files.

## 1. Published container with the GUI (easiest)

This is the recommended path for most PST and EML investigations.

1. Install Docker Desktop and Python 3.11 or newer with Tkinter.
2. Download and extract the [Threadsaw 1.3.0 source archive](https://github.com/thatirguy/threadsaw/releases/tag/v1.3.0), or clone the repository.
3. Open Terminal in the Threadsaw directory.
4. Pull the versioned image and start the launcher:

```bash
docker compose pull
python3 launcher/threadsaw_gui.py
```

Grant Docker access to the evidence and case folders when prompted. The GUI shows the containerized CLI command before it runs. The published `ghcr.io/thatirguy/threadsaw:1.3.0` image supports Apple silicon through `linux/arm64`, supports Intel hosts through `linux/amd64`, includes `readpst`, and does not include optional MSG parsing.

## 2. Published container from Terminal

Use Docker Compose directly for scripts and terminal workflows:

```bash
docker compose pull
docker compose run --rm --no-deps -T \
  -v "$HOME/Evidence:/input:ro" \
  -v "$HOME/Cases/Matter01:/case" \
  threadsaw run --input /input --case /case --large-case
```

## 3. Locally built container

Build locally when you need to audit or customize the image. Enable optional MSG support only after reviewing its GPL licensing implications:

```bash
docker compose build
docker compose build --build-arg THREADSAW_INSTALL_MSG=1
python3 launcher/threadsaw_gui.py
```

## 4. Native wheel installation (most complex)

Native operation has a larger host dependency and trust surface than the container. Download the wheel and `SHA256SUMS.txt` from the [1.3.0 release](https://github.com/thatirguy/threadsaw/releases/tag/v1.3.0), verify its SHA-256, then install it into an isolated environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./threadsaw-1.3.0-py3-none-any.whl
threadsaw doctor
```

PST ingestion also requires a trusted `libpst/readpst` installation from the operating-system package manager. Set `THREADSAW_READPST` to its absolute path in controlled deployments. Install the wheel with its `msg` extra only when native MSG parsing and the additional license are acceptable.

For large cases, see [Large-Case Operations](../LARGE_CASES.md). For dependency checks and path issues, see [Troubleshooting](../TROUBLESHOOTING.md).
