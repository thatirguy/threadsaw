from __future__ import annotations

import csv
import re
from email.message import EmailMessage
from pathlib import Path

from threadsaw.attachments import export_attachment_run
from threadsaw.case import initialize_case
from threadsaw.db import connect_db
from threadsaw.exporter import export_messages
from threadsaw.ingest import ingest_path
from threadsaw.reports import write_timestamped_reports
from threadsaw.selection import resolve_message_hashes
from threadsaw.urls import extract_urls, write_timestamped_url_report

STAMP_RE = re.compile(r"_\d{8}T\d{6}Z(?:__\d+)?$")


def _write_message(path: Path) -> None:
    message = EmailMessage()
    message["From"] = "sender@outside.test"
    message["To"] = "recipient@example.com"
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Subject"] = "Timestamp test"
    message.set_content("Review https://example.test/path")
    message.add_attachment(b"sample", maintype="application", subtype="octet-stream", filename="sample.bin")
    path.write_bytes(message.as_bytes())


def _case(tmp_path: Path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    _write_message(evidence / "sample.eml")
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    ids = resolve_message_hashes(conn, all_messages=True)
    extract_urls(conn, case, ids, progress=lambda _message: None)
    return case, conn, ids


def test_repeated_url_reports_never_overwrite(tmp_path):
    case, conn, ids = _case(tmp_path)
    try:
        base = case / "reports" / "urls.csv"
        first = write_timestamped_url_report(conn, base, ids)
        second = write_timestamped_url_report(conn, base, ids)
        first_path = Path(first["output"])
        second_path = Path(second["output"])
        assert first_path != second_path
        assert first_path.is_file() and second_path.is_file()
        assert re.search(r"urls_\d{8}T\d{6}Z(?:__\d+)?\.csv$", first_path.name)
        assert re.search(r"urls_\d{8}T\d{6}Z(?:__\d+)?\.csv$", second_path.name)
    finally:
        conn.close()


def test_repeated_message_and_attachment_exports_never_overwrite(tmp_path):
    case, conn, ids = _case(tmp_path)
    try:
        message_base = case / "exports" / "message-export"
        first_messages = export_messages(conn, message_base, ids)
        second_messages = export_messages(conn, message_base, ids)
        first_message_dir = Path(first_messages["output_directory"])
        second_message_dir = Path(second_messages["output_directory"])
        assert first_message_dir != second_message_dir
        assert STAMP_RE.search(first_message_dir.name)
        assert STAMP_RE.search(second_message_dir.name)
        assert (first_message_dir / "summary.csv").is_file()
        assert (second_message_dir / "summary.csv").is_file()

        report_base = case / "reports" / "attachments"
        files_base = case / "exports" / "attachments"
        first_attachments = export_attachment_run(
            conn, report_base, ids, copy_files=True, files_output_base=files_base
        )
        second_attachments = export_attachment_run(
            conn, report_base, ids, copy_files=True, files_output_base=files_base
        )
        first_report_dir = Path(first_attachments["report_directory"])
        second_report_dir = Path(second_attachments["report_directory"])
        first_files_dir = Path(first_attachments["files_output"])
        second_files_dir = Path(second_attachments["files_output"])
        assert first_report_dir != second_report_dir
        assert first_files_dir != second_files_dir
        assert STAMP_RE.search(first_report_dir.name)
        assert STAMP_RE.search(first_files_dir.name)
        with Path(first_attachments["report"]).open(encoding="utf-8-sig", newline="") as handle:
            row = next(csv.DictReader(handle))
        assert str(first_files_dir.relative_to(case)) in row["exported_path"]
    finally:
        conn.close()


def test_core_reports_use_timestamped_execution_folder(tmp_path):
    case, conn, ids = _case(tmp_path)
    try:
        first = write_timestamped_reports(conn, case / "reports" / "core", ids)
        second = write_timestamped_reports(conn, case / "reports" / "core", ids)
        first_dir = Path(first["output_directory"])
        second_dir = Path(second["output_directory"])
        assert first_dir != second_dir
        assert STAMP_RE.search(first_dir.name)
        assert STAMP_RE.search(second_dir.name)
        assert Path(first["messages_csv"]).is_file()
        assert Path(second["messages_csv"]).is_file()
    finally:
        conn.close()
