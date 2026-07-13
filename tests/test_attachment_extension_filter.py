from __future__ import annotations

import csv
from email.message import EmailMessage
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.attachments import export_attachment_run
from threadsaw.case import initialize_case
from threadsaw.db import connect_db
from threadsaw.ingest import ingest_path


def test_attachment_export_filters_original_filename_extensions(tmp_path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    msg["Message-ID"] = "<filter@example.test>"
    msg["Subject"] = "Filter"
    msg.set_content("Body")
    msg.add_attachment(b"pdf", maintype="application", subtype="pdf", filename="Invoice.PDF")
    msg.add_attachment(b"text", maintype="text", subtype="plain", filename="notes.txt")
    (evidence / "one.eml").write_bytes(msg.as_bytes())
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        ids = [row[0] for row in conn.execute("SELECT message_sha256 FROM messages")]
        result = export_attachment_run(
            conn,
            case / "reports" / "attachments",
            ids,
            extensions=["pdf"],
        )
    finally:
        conn.close()
    with Path(result["report"]).open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["original_filename"] for row in rows] == ["Invoice.PDF"]
    assert result["extension_filter"] == [".pdf"]
