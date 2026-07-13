from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso8601(value: str) -> datetime:
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a UTC offset or end in Z")
    return parsed.astimezone(timezone.utc)


def file_hashes(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            size += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest(), size


def byte_hashes(data: bytes) -> tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data, usedforsecurity=False).hexdigest()


def _strip_format_controls(value: str) -> str:
    """Remove invisible/bidirectional Unicode format controls from filesystem names."""
    return "".join(ch for ch in value if unicodedata.category(ch) != "Cf")


def safe_filename(value: str | None, fallback: str = "unnamed") -> str:
    value = _strip_format_controls((value or fallback).replace("\x00", ""))
    value = re.sub(r"[\\/:*?\"<>|\r\n]+", "_", value).strip(" .")
    fallback = _strip_format_controls(fallback) or "unnamed"
    return value[:180] or fallback


def human_folder_name(value: str | None, fallback: str = "No Subject", max_length: int = 96) -> str:
    """Return a readable, cross-platform folder name derived from message text."""
    cleaned = " ".join((value or fallback).replace("\x00", "").split())
    cleaned = safe_filename(cleaned, fallback)
    # Avoid Windows device names even when the case is created on another platform.
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{x}" for x in range(1, 10)), *(f"LPT{x}" for x in range(1, 10))}
    if cleaned.upper() in reserved:
        cleaned = "_" + cleaned
    return cleaned[:max_length].rstrip(" .") or fallback


def unique_path(parent: Path, preferred_name: str, *, is_directory: bool) -> Path:
    """Return a non-existing sibling path, adding __2, __3, etc. on collision."""
    candidate = parent / preferred_name
    if not candidate.exists():
        return candidate
    stem = candidate.name if is_directory else candidate.stem
    suffix = "" if is_directory else candidate.suffix
    counter = 2
    while True:
        candidate = parent / f"{stem}__{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def excel_safe(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    stripped = value.lstrip()
    if stripped.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def atomic_write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def atomic_write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore", quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: excel_safe(row.get(key, "")) for key in fieldnames})
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def iter_files(path: Path, recursive: bool = True) -> Iterator[Path]:
    if path.is_file():
        yield path
        return
    iterator = path.rglob("*") if recursive else path.glob("*")
    for item in iterator:
        if item.is_file():
            yield item



def chunked(values: Sequence[Any], size: int = 500) -> Iterator[list[Any]]:
    """Yield bounded lists suitable for SQLite IN clauses.

    SQLite builds may impose a comparatively low parameter limit.  Keeping
    batches at 500 makes large-case operations portable without changing
    result semantics.
    """
    if size < 1:
        raise ValueError("Chunk size must be at least 1")
    for offset in range(0, len(values), size):
        yield list(values[offset : offset + size])


def available_disk_bytes(path: Path) -> int:
    """Return free bytes for the filesystem containing path."""
    probe = path if path.exists() else path.parent
    probe.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(probe).free


def estimate_pst_case_bytes(pst_size: int, *, multiplier: float = 5.0) -> int:
    """Conservative planning estimate for extraction, artifacts, DB, and reports."""
    return int(max(pst_size, 0) * multiplier)


def atomic_write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def relative_or_absolute(path: Path, base: Path | None = None) -> str:
    if base:
        try:
            return str(path.resolve().relative_to(base.resolve()))
        except ValueError:
            pass
    return str(path.resolve())
