from __future__ import annotations

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .util import unique_path


def completion_timestamp() -> str:
    """Return a compact UTC timestamp suitable for a filename."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def timestamped_file(base_path: Path, timestamp: str) -> Path:
    """Return a collision-safe sibling file path with a completion timestamp."""
    base_path = Path(base_path)
    suffix = "".join(base_path.suffixes)
    name = base_path.name[: -len(suffix)] if suffix else base_path.name
    preferred = f"{name}_{timestamp}{suffix}"
    return unique_path(base_path.parent, preferred, is_directory=False)


def timestamped_directory(base_path: Path, timestamp: str) -> Path:
    """Return a collision-safe sibling directory path with a completion timestamp."""
    base_path = Path(base_path)
    return unique_path(base_path.parent, f"{base_path.name}_{timestamp}", is_directory=True)


def staging_file(base_path: Path) -> Path:
    """Return a hidden same-directory staging path for one output file."""
    base_path = Path(base_path)
    base_path.parent.mkdir(parents=True, exist_ok=True)
    suffix = "".join(base_path.suffixes)
    token = uuid.uuid4().hex[:12]
    return base_path.parent / f".{base_path.stem}.in-progress-{token}{suffix}"


def staging_directory(base_path: Path) -> Path:
    """Create and return a hidden sibling staging directory."""
    base_path = Path(base_path)
    base_path.parent.mkdir(parents=True, exist_ok=True)
    candidate = base_path.parent / f".{base_path.name}.in-progress-{uuid.uuid4().hex[:12]}"
    candidate.mkdir(parents=True, exist_ok=False)
    return candidate


def finalize_file(staging_path: Path, base_path: Path, timestamp: str | None = None) -> Path:
    """Atomically move a completed staging file to its timestamped final name."""
    stamp = timestamp or completion_timestamp()
    final_path = timestamped_file(Path(base_path), stamp)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging_path, final_path)
    return final_path


def finalize_directory(staging_path: Path, base_path: Path, timestamp: str | None = None) -> Path:
    """Move a completed staging directory to its timestamped final name."""
    stamp = timestamp or completion_timestamp()
    final_path = timestamped_directory(Path(base_path), stamp)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging_path, final_path)
    return final_path


def cleanup_staging(path: Path | None) -> None:
    """Best-effort removal of an incomplete generated-output staging path."""
    if path is None:
        return
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    except OSError:
        # A leftover .in-progress path is intentionally obvious and can be
        # inspected or removed by the user; do not mask the original error.
        pass
