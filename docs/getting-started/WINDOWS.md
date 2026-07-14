# Getting Started on Windows

Windows uses Docker Desktop with the WSL 2 backend. This keeps `readpst` and the analysis dependencies inside the supported Linux container and provides Threadsaw's strongest runtime isolation. Install Python 3.11 or newer with Tkinter only for the host-side GUI launcher.

Keep evidence in a read-only folder and use a different writable folder for the case. Prefer a local NTFS SSD rather than a network or cloud-synchronized location while Threadsaw is running.

## 1. Published container with the GUI (easiest)

This is the recommended path for most PST and EML investigations.

1. Install WSL 2 and Docker Desktop, then enable Docker Desktop's WSL 2 backend.
2. Download and extract the [Threadsaw 1.3.0 source archive](https://github.com/thatirguy/threadsaw/releases/tag/v1.3.0), or clone the repository.
3. Open PowerShell in the Threadsaw directory.
4. Pull the versioned image and start the launcher:

```powershell
docker compose pull
python .\launcher\threadsaw_gui.py
```

The GUI shows the underlying containerized CLI command before it runs. Choose a read-only evidence folder and a separate writable case folder. The published `ghcr.io/thatirguy/threadsaw:1.3.0` image supports `linux/amd64` and `linux/arm64`, includes `readpst`, and does not include optional MSG parsing.

## 2. Published container from PowerShell

Use the same image directly when scripting or when the GUI is not needed:

```powershell
docker compose pull
docker compose run --rm --no-deps -T `
  -v "C:\Evidence:/input:ro" `
  -v "D:\Cases\Matter01:/case" `
  threadsaw run --input /input --case /case --workers 4
```

Paths after the image command are container paths: `/input` is read-only evidence and `/case` is writable case storage.

## 3. Locally built container (most complex)

Build locally when you need to audit or customize the image. Optional MSG support requires this method because it adds the GPL-licensed `extract-msg` dependency:

```powershell
docker compose build
docker compose build --build-arg THREADSAW_INSTALL_MSG=1
python .\launcher\threadsaw_gui.py
```

Review [Dependencies, SBOM, and Licensing](../DEPENDENCIES_AND_LICENSING.md) before redistributing an MSG-enabled image.

## Large PSTs

Store evidence and the case on a fast local SSD, allocate at least 16 GB to Docker Desktop, and enable **Large case mode**. Threadsaw performs a disk preflight using a default five-times-PST estimate. See [Large-Case Operations](../LARGE_CASES.md).

## Verify the installation

```powershell
docker compose run --rm --no-deps -T threadsaw doctor
```

If Docker cannot mount a drive, enable file sharing for that location in Docker Desktop. See [Troubleshooting](../TROUBLESHOOTING.md) for path, Tkinter, and WSL-related checks.
