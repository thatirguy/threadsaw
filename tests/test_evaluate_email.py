from __future__ import annotations

import csv
import json
from email.message import EmailMessage
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.case import initialize_case
from threadsaw.db import connect_db
from threadsaw.evaluate_email import evaluate_phishing_email
from threadsaw.ingest import ingest_path


def _write(path: Path, sender: str, recipient: str, subject: str = "Evaluation") -> None:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    msg["Message-ID"] = f"<{path.stem}@example.test>"
    msg["Subject"] = subject
    msg.set_content("Body")
    path.write_bytes(msg.as_bytes())


def test_evaluate_existing_message_exports_hit_config(tmp_path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    path = evidence / "internal.eml"
    _write(path, "sender@example.com", "recipient@example.com")
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        message_hash = conn.execute("SELECT message_sha256 FROM messages").fetchone()[0]
        result = evaluate_phishing_email(
            conn,
            case,
            message_sha256=message_hash,
            email_path=None,
            allow_case_history_override=False,
            output_root=case / "reports" / "evaluate_phishing_email",
        )
    finally:
        conn.close()

    assert result["evaluation_mode"] == "existing-case-message"
    config = json.loads(Path(result["matched_config"]).read_text(encoding="utf-8"))
    hit_ids = {item["factor_id"] for item in config["factors"]}
    assert "sender_recipient_same_domain" in hit_ids
    assert all(item["weight"] == 10 for item in config["factors"])


def test_evaluate_external_standalone_skips_history_factors(tmp_path):
    case = tmp_path / "case"
    initialize_case(case)
    external = tmp_path / "outside.eml"
    _write(external, "sender@example.com", "recipient@example.com", "Standalone")
    conn = connect_db(case)
    try:
        result = evaluate_phishing_email(
            conn,
            case,
            message_sha256=None,
            email_path=external,
            allow_case_history_override=False,
            output_root=case / "reports" / "evaluate_phishing_email",
        )
    finally:
        conn.close()

    assert result["evaluation_mode"] == "external-file-standalone"
    with Path(result["details_report"]).open(encoding="utf-8-sig", newline="") as handle:
        rows = {row["factor_id"]: row for row in csv.DictReader(handle)}
    assert rows["sender_address_new"]["answer"] == "NOT_APPLICABLE"
    assert rows["sender_address_new"]["status"] == "standalone-skip"
    assert rows["sender_recipient_same_domain"]["answer"] == "YES"
