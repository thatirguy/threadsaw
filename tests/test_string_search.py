from __future__ import annotations

import csv
from email.message import EmailMessage
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.case import initialize_case
from threadsaw.db import connect_db
from threadsaw.ingest import ingest_path
from threadsaw.string_search import run_string_search


def _write(path: Path, sender: str, date_value: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "recipient@example.com"
    msg["Date"] = date_value
    msg["Message-ID"] = f"<{path.stem}@example.test>"
    msg["Subject"] = "Search sample"
    msg.set_content(body)
    path.write_bytes(msg.as_bytes())


def test_string_search_combines_sqlite_export_text_and_reports(tmp_path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    _write(evidence / "one.eml", "Needle@Example.com", "Sat, 11 Jul 2026 12:00:00 +0000", "ordinary")
    _write(evidence / "two.eml", "other@example.com", "Mon, 20 Jul 2026 12:00:00 +0000", "outside date")
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)

    exported = tmp_path / "exported"
    exported.mkdir()
    (exported / "review.txt").write_text("The NEEDLE appears in exported text.\n", encoding="utf-8")
    reports = case / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "prior.csv").write_text("value\nneedle\n", encoding="utf-8")

    conn = connect_db(case)
    try:
        result = run_string_search(
            conn,
            case,
            query="needle",
            search_database=True,
            exported_text_dir=exported,
            search_reports=True,
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
            output_root=case / "reports" / "string_search",
        )
    finally:
        conn.close()

    with Path(result["csv"]).open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    kinds = {row["source_kind"] for row in rows}
    assert {"sqlite", "exported-message-text", "report"} <= kinds
    sqlite_rows = [row for row in rows if row["source_kind"] == "sqlite"]
    assert any(row["field_name"] == "from_address" for row in sqlite_rows)
    assert all("other@example.com" not in row["matched_value"] for row in sqlite_rows)
    assert Path(result["run_directory"]).name.startswith("string-search_")
