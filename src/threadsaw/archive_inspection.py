"""Bounded, metadata-only ZIP container inspection.

Threadsaw reads ZIP central-directory metadata only. It never extracts, opens,
or executes archive members. The output can expose filenames, sizes, encryption
flags, and risky member extensions for later reporting and Phish Hunt scoring.
"""
from __future__ import annotations

import csv
import zipfile
from pathlib import Path
from typing import Any, Callable

from .util import atomic_write_csv, chunked, utc_now

ZIP_CONTAINER_EXTENSIONS = {".zip", ".jar", ".apk", ".xpi", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
ZIP_CONTAINER_MIME_TYPES = {"application/zip", "application/java-archive", "application/vnd.android.package-archive"}
RISKY_MEMBER_EXTENSIONS = {
    ".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".scr", ".pif", ".cpl", ".chm", ".xll", ".one", ".iqy", ".slk", ".rdp",
    ".msi", ".msix", ".hta", ".lnk", ".url", ".webloc", ".website", ".docm", ".xlsm", ".pptm",
}
ARCHIVE_MEMBER_FIELDS = [
    "message_sha256", "attachment_id", "archive_filename", "archive_sha256", "member_index", "member_name",
    "compressed_size", "uncompressed_size", "encrypted", "suspicious_extension",
]


def is_zip_family_attachment(filename: str | None, content_type: str | None) -> bool:
    extension = Path(str(filename or "")).suffix.lower()
    mime = str(content_type or "").lower().split(";", 1)[0]
    return extension in ZIP_CONTAINER_EXTENSIONS or mime in ZIP_CONTAINER_MIME_TYPES


def _record_inspection(
    conn,
    *,
    attachment_id: int,
    status: str,
    member_count: int,
    total_member_count: int | None,
    encrypted_member_count: int,
    truncated: bool,
    error_detail: str | None = None,
) -> None:
    conn.execute(
        """INSERT INTO archive_inspections(
               attachment_id,status,member_count,total_member_count,encrypted_member_count,truncated,error_detail,inspected_utc
           ) VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(attachment_id) DO UPDATE SET
               status=excluded.status,
               member_count=excluded.member_count,
               total_member_count=excluded.total_member_count,
               encrypted_member_count=excluded.encrypted_member_count,
               truncated=excluded.truncated,
               error_detail=excluded.error_detail,
               inspected_utc=excluded.inspected_utc""",
        (
            attachment_id,
            status,
            member_count,
            total_member_count,
            encrypted_member_count,
            int(truncated),
            error_detail,
            utc_now(),
        ),
    )


def inspect_zip_attachments(
    conn,
    ids: list[str],
    *,
    max_members_per_archive: int = 1000,
    max_total_members: int = 10000,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if max_members_per_archive < 1 or max_total_members < 1:
        raise ValueError("ZIP member limits must be positive integers")
    if not ids:
        return {"archives_inspected": 0, "members_recorded": 0, "archives_truncated": 0, "errors": []}
    attachments = []
    for batch in chunked(ids):
        placeholders = ",".join("?" for _ in batch)
        attachments.extend(conn.execute(
            f"""SELECT attachment_id,message_sha256,original_filename,artifact_path,sha256,content_type_declared,part_index
                 FROM attachments WHERE message_sha256 IN ({placeholders})""",
            batch,
        ).fetchall())
    attachments.sort(key=lambda row: (str(row["message_sha256"]), int(row["part_index"])))
    inspected = 0
    recorded = 0
    truncated = 0
    errors: list[dict[str, str]] = []
    for row in attachments:
        if not is_zip_family_attachment(row["original_filename"], row["content_type_declared"]):
            continue
        artifact = Path(str(row["artifact_path"] or ""))
        conn.execute("DELETE FROM archive_members WHERE attachment_id=?", (row["attachment_id"],))
        if not artifact.is_file():
            error = "Artifact bytes are unavailable"
            errors.append({"attachment_id": str(row["attachment_id"]), "error": error})
            _record_inspection(
                conn,
                attachment_id=int(row["attachment_id"]),
                status="error",
                member_count=0,
                total_member_count=None,
                encrypted_member_count=0,
                truncated=False,
                error_detail=error,
            )
            continue
        try:
            with zipfile.ZipFile(artifact, "r") as archive:
                infos = archive.infolist()
                allowed = min(len(infos), max_members_per_archive, max_total_members - recorded)
                archive_truncated = allowed < len(infos)
                if archive_truncated:
                    truncated += 1
                encrypted_count = 0
                for index, info in enumerate(infos[:allowed]):
                    suffix = Path(info.filename).suffix.lower()
                    encrypted = int(bool(info.flag_bits & 0x1))
                    conn.execute(
                        """INSERT INTO archive_members(attachment_id,member_index,member_name,compressed_size,
                               uncompressed_size,encrypted,suspicious_extension) VALUES(?,?,?,?,?,?,?)""",
                        (
                            row["attachment_id"], index, info.filename, int(info.compress_size), int(info.file_size),
                            encrypted, int(suffix in RISKY_MEMBER_EXTENSIONS),
                        ),
                    )
                    encrypted_count += encrypted
                    recorded += 1
                _record_inspection(
                    conn,
                    attachment_id=int(row["attachment_id"]),
                    status="truncated" if archive_truncated else "complete",
                    member_count=allowed,
                    total_member_count=len(infos),
                    encrypted_member_count=encrypted_count,
                    truncated=archive_truncated,
                )
                inspected += 1
                if progress:
                    progress(f"[ARCHIVE] {row['original_filename'] or '[unnamed]'}: recorded {allowed:,} member(s)")
                if recorded >= max_total_members:
                    break
        except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            errors.append({"attachment_id": str(row["attachment_id"]), "error": error})
            _record_inspection(
                conn,
                attachment_id=int(row["attachment_id"]),
                status="error",
                member_count=0,
                total_member_count=None,
                encrypted_member_count=0,
                truncated=False,
                error_detail=error,
            )
    conn.commit()
    return {
        "archives_inspected": inspected,
        "members_recorded": recorded,
        "archives_truncated": truncated,
        "max_members_per_archive": max_members_per_archive,
        "max_total_members": max_total_members,
        "errors": errors,
    }


def archive_member_rows(conn, ids: list[str]) -> list[dict[str, Any]]:
    if not ids:
        return []
    output: list[dict[str, Any]] = []
    for batch in chunked(ids):
        placeholders = ",".join("?" for _ in batch)
        output.extend(dict(row) for row in conn.execute(
            f"""SELECT a.message_sha256,a.attachment_id,a.original_filename AS archive_filename,a.sha256 AS archive_sha256,
                        a.part_index,am.member_index,am.member_name,am.compressed_size,am.uncompressed_size,
                        CASE am.encrypted WHEN 1 THEN 'yes' ELSE 'no' END AS encrypted,
                        CASE am.suspicious_extension WHEN 1 THEN 'yes' ELSE 'no' END AS suspicious_extension
                 FROM archive_members am JOIN attachments a ON a.attachment_id=am.attachment_id
                 WHERE a.message_sha256 IN ({placeholders})""",
            batch,
        ))
    output.sort(key=lambda row: (str(row.get("message_sha256") or ""), int(row.pop("part_index", 0)), int(row.get("member_index") or 0)))
    return output


def write_archive_member_report(conn, path: Path, ids: list[str]) -> int:
    rows = archive_member_rows(conn, ids)
    atomic_write_csv(path, ARCHIVE_MEMBER_FIELDS, rows)
    return len(rows)
