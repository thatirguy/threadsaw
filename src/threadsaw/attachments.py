from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .reports import ATTACHMENT_FIELDS
from .archive_inspection import inspect_zip_attachments, write_archive_member_report
from .ip_fields import enrich_sender_ip_rows
from .message_context import enrich_recipient_rows
from .output_naming import (
    cleanup_staging,
    completion_timestamp,
    finalize_directory,
    staging_directory,
    timestamped_directory,
)
from .util import atomic_write_csv, chunked, human_folder_name, safe_filename, unique_path


def _normalize_extensions(values: list[str] | None) -> set[str]:
    output: set[str] = set()
    for raw in values or []:
        for item in str(raw).split(","):
            value = item.strip().lower()
            if not value:
                continue
            output.add(value if value.startswith(".") else "." + value)
    return output


def attachment_rows(conn, ids: list[str], *, extensions: list[str] | None = None) -> list[dict[str, Any]]:
    if not ids:
        return []
    rows: list[dict[str, Any]] = []
    for batch in chunked(ids):
        placeholders = ",".join("?" for _ in batch)
        rows.extend(dict(row) for row in conn.execute(
            f"""SELECT a.message_sha256,m.from_address AS sender_email,m.selected_date_utc AS message_date_utc,m.subject,
                a.part_index,a.original_filename,a.safe_filename,a.content_type_declared,
                a.size_bytes,a.sha256,a.md5,a.executable_format,a.artifact_path,a.content_disposition,a.content_id,a.is_inline,a.status
                FROM attachments a JOIN messages m ON m.message_sha256=a.message_sha256
                WHERE a.message_sha256 IN ({placeholders})
                ORDER BY m.selected_date_utc,a.message_sha256,a.part_index""", batch
        ))
    rows.sort(key=lambda row: (str(row.get("message_date_utc") or ""), str(row.get("message_sha256") or ""), int(row.get("part_index") or 0)))
    wanted_extensions = _normalize_extensions(extensions)
    if wanted_extensions:
        rows = [
            row for row in rows
            if Path(str(row.get("original_filename") or "")).suffix.lower() in wanted_extensions
        ]
    enrich_recipient_rows(conn, rows)
    return enrich_sender_ip_rows(conn, rows)


def _message_directories(rows: list[dict[str, Any]], copies_root: Path) -> dict[str, Path]:
    directories: dict[str, Path] = {}
    for row in rows:
        message_sha256 = row["message_sha256"]
        if message_sha256 in directories:
            continue
        name = human_folder_name(row.get("subject"), "No Subject")
        directory = unique_path(copies_root, name, is_directory=True)
        directory.mkdir(parents=True, exist_ok=False)
        directories[message_sha256] = directory
    return directories


def _case_dir_from_connection(conn) -> Path | None:
    database_path = conn.execute("PRAGMA database_list").fetchone()[2]
    return Path(database_path).resolve().parent if database_path else None


def _set_exported_paths(
    rows: list[dict[str, Any]],
    *,
    copies_root: Path | None,
    reported_root: Path | None,
    case_dir: Path | None,
) -> None:
    for row in rows:
        relative = row.get("_copy_relative")
        if relative is None or copies_root is None or reported_root is None:
            row["exported_path"] = ""
            continue
        destination = reported_root / Path(relative)
        try:
            path = destination.resolve().relative_to(case_dir) if case_dir else destination
        except ValueError:
            path = destination
        row["exported_path"] = path.as_posix()


def _copy_attachment_rows(
    rows: list[dict[str, Any]],
    *,
    copies_root: Path | None,
) -> int:
    if copies_root is None:
        for row in rows:
            row["_copy_relative"] = None
        return 0

    copies_root.mkdir(parents=True, exist_ok=True)
    message_dirs = _message_directories(rows, copies_root)
    copied = 0
    for row in rows:
        source = Path(row["artifact_path"])
        if not source.is_file():
            row["_copy_relative"] = None
            continue
        message_dir = message_dirs[row["message_sha256"]]
        preferred = safe_filename(row["original_filename"], f"attachment-{row['part_index']}.bin")
        destination = unique_path(message_dir, preferred, is_directory=False)
        shutil.copyfile(source, destination)
        row["_copy_relative"] = destination.relative_to(copies_root).as_posix()
        copied += 1
    return copied


def export_attachment_report(
    conn,
    output_dir: Path,
    ids: list[str],
    *,
    copy_files: bool = False,
    files_output_dir: Path | None = None,
    extensions: list[str] | None = None,
    list_zip_contents: bool = False,
    zip_max_members: int = 1000,
    zip_max_total_members: int = 10000,
) -> dict[str, Any]:
    """Write an exact-path attachment report.

    This low-level function is retained for library callers. The CLI uses
    :func:`export_attachment_run`, which creates collision-safe timestamped
    report and artifact folders.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_summary = None
    archive_report = None
    if list_zip_contents:
        archive_summary = inspect_zip_attachments(conn, ids, max_members_per_archive=zip_max_members, max_total_members=zip_max_total_members)
        archive_report = output_dir / "archive_members.csv"
        write_archive_member_report(conn, archive_report, ids)
    rows = attachment_rows(conn, ids, extensions=extensions)
    copies_root = (files_output_dir or (output_dir / "files")) if copy_files else None
    copied = _copy_attachment_rows(rows, copies_root=copies_root)
    _set_exported_paths(
        rows,
        copies_root=copies_root,
        reported_root=copies_root,
        case_dir=_case_dir_from_connection(conn),
    )
    report = output_dir / "attachments.csv"
    atomic_write_csv(report, ATTACHMENT_FIELDS, rows)
    return {
        "selected_messages": len(ids),
        "attachment_count": len(rows),
        "copied_files": copied,
        "report": str(report),
        "report_directory": str(output_dir),
        "files_output": str(copies_root) if copies_root else None,
        "extension_filter": sorted(_normalize_extensions(extensions)),
        "archive_listing": archive_summary,
        "archive_report": str(archive_report) if archive_report else None,
    }


def export_attachment_run(
    conn,
    output_base: Path,
    ids: list[str],
    *,
    copy_files: bool = False,
    files_output_base: Path | None = None,
    extensions: list[str] | None = None,
    list_zip_contents: bool = False,
    zip_max_members: int = 1000,
    zip_max_total_members: int = 10000,
) -> dict[str, Any]:
    """Create one timestamped attachment-report/export execution.

    The timestamp is assigned at finalization, after attachment bytes have been
    copied and report rows prepared. Hidden ``.in-progress`` directories keep
    incomplete runs distinct from completed exports.
    """
    output_base = Path(output_base)
    report_stage: Path | None = staging_directory(output_base)
    copy_stage: Path | None = None
    embedded_copy = bool(copy_files and files_output_base is None)
    try:
        if copy_files:
            if files_output_base is not None:
                copy_stage = staging_directory(Path(files_output_base))
                copies_root = copy_stage
            else:
                copies_root = report_stage / "files"
        else:
            copies_root = None

        archive_summary = None
        archive_report_name = None
        if list_zip_contents:
            archive_summary = inspect_zip_attachments(conn, ids, max_members_per_archive=zip_max_members, max_total_members=zip_max_total_members)
            archive_report_name = "archive_members.csv"
            write_archive_member_report(conn, report_stage / archive_report_name, ids)
        rows = attachment_rows(conn, ids, extensions=extensions)
        copied = _copy_attachment_rows(rows, copies_root=copies_root)

        # Shared finalization timestamp for this logical execution.
        stamp = completion_timestamp()
        final_files_dir: Path | None = None

        # A separately requested artifact tree can be finalized first. Its
        # returned path is authoritative even during concurrent same-second
        # executions and can therefore be recorded accurately in the CSV.
        if copy_stage is not None and files_output_base is not None:
            final_files_dir = finalize_directory(copy_stage, Path(files_output_base), stamp)
            copy_stage = None

        if not embedded_copy:
            _set_exported_paths(
                rows,
                copies_root=copies_root,
                reported_root=final_files_dir,
                case_dir=_case_dir_from_connection(conn),
            )

        atomic_write_csv(report_stage / "attachments.csv", ATTACHMENT_FIELDS, rows)
        final_report_dir = finalize_directory(report_stage, output_base, stamp)
        report_stage = None

        if embedded_copy:
            final_files_dir = final_report_dir / "files"
            _set_exported_paths(
                rows,
                copies_root=copies_root,
                reported_root=final_files_dir,
                case_dir=_case_dir_from_connection(conn),
            )
            # Rewrite only the completed report CSV so embedded artifact paths
            # reflect the actual collision-safe final report folder.
            atomic_write_csv(final_report_dir / "attachments.csv", ATTACHMENT_FIELDS, rows)

        report = final_report_dir / "attachments.csv"
        return {
            "selected_messages": len(ids),
            "attachment_count": len(rows),
            "copied_files": copied,
            "completion_timestamp": stamp,
            "report": str(report),
            "report_directory": str(final_report_dir),
            "files_output": str(final_files_dir) if final_files_dir else None,
            "extension_filter": sorted(_normalize_extensions(extensions)),
            "archive_listing": archive_summary,
            "archive_report": str(final_report_dir / archive_report_name) if archive_report_name else None,
        }
    finally:
        cleanup_staging(report_stage)
        cleanup_staging(copy_stage)
