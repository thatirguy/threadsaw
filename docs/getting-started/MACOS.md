# Getting Started on macOS

1. Install Docker Desktop or Podman Desktop.
2. Clone or extract Threadsaw and open Terminal in the repository root.
3. Run `docker compose pull` to retrieve the versioned release image.
4. Start the GUI with `python3 launcher/threadsaw_gui.py`, or use the CLI.
5. Grant the container engine access to the evidence and case folders when prompted.

Run `docker compose build` instead when auditing or customizing the image. Optional MSG parsing requires a local build with `THREADSAW_INSTALL_MSG=1`.

Use local APFS SSD storage rather than network or cloud-synchronized folders. Docker Desktop bind mounts can be slow with hundreds of thousands of EML files; large-case mode reduces report memory usage but cannot eliminate filesystem overhead.

```bash
docker compose run --rm --no-deps -T \
  -v "$HOME/Evidence:/input:ro" \
  -v "$HOME/Cases/Matter01:/case" \
  threadsaw run --input /input --case /case --large-case
```
