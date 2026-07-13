from __future__ import annotations

import csv
import json
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.case import initialize_case, update_case
from threadsaw.db import connect_db
from threadsaw.factor_catalog import FACTOR_CATALOG, LEGACY_FACTORS
from threadsaw.factor_evaluators import EVALUATORS, PENDING_REASONS
from threadsaw.ingest import ingest_path
from threadsaw.phish_hunt import all_factor_config, evaluate_message, normalize_config
from threadsaw.reports import write_reports
from threadsaw.urls import extract_urls, write_url_report


def _write_message(path: Path) -> None:
    message = EmailMessage()
    message["From"] = '"victim@legitcompany.com" <attacker@gmail.com>'
    message["Reply-To"] = "reply@other.test"
    message["Return-Path"] = "<bounce@mailer.test>"
    message["To"] = "victim@legitcompany.com"
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Message-ID"] = "<sample@unrelated.test>"
    message["Subject"] = "Sample"
    message["Authentication-Results"] = "trusted.example; spf=fail smtp.mailfrom=mailer.test; dkim=fail; dmarc=fail; arc=fail"
    message.set_content("Plain body http://192.0.2.25/login and https://company.sharepoint.com/doc")
    message.add_alternative(
        '<html><body><form action="http://192.0.2.25/login"><input type="password"></form>'
        '<a href="https://attacker.test/login">https://legitcompany.com/login</a>'
        '<script>void(0)</script></body></html>',
        subtype="html",
    )
    message.add_attachment(b"echo test", maintype="text", subtype="plain", filename="invoice.pdf.exe")
    path.write_bytes(message.as_bytes())


def _case_with_message(tmp_path: Path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    _write_message(evidence / "sample.eml")
    case_data = initialize_case(case)
    case_data["config"]["trusted_authserv_ids"] = ["trusted.example"]
    update_case(case, case_data)
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    message_hash = conn.execute("SELECT message_sha256 FROM messages").fetchone()[0]
    return case, conn, message_hash


def test_url_and_attachment_counts_are_stored_and_reported(tmp_path):
    case, conn, message_hash = _case_with_message(tmp_path)
    try:
        row = conn.execute("SELECT attachment_count,url_count,url_indexed FROM messages").fetchone()
        assert row["attachment_count"] == 1
        assert row["url_count"] == 0
        assert row["url_indexed"] == 0

        extract_urls(conn, case, [message_hash], progress=lambda _message: None)
        row = conn.execute("SELECT attachment_count,url_count,url_indexed FROM messages").fetchone()
        assert row["attachment_count"] == 1
        assert row["url_indexed"] == 1
        assert row["url_count"] == conn.execute(
            "SELECT COUNT(*) FROM urls WHERE message_sha256=?", (message_hash,)
        ).fetchone()[0]
        assert row["url_count"] >= 3

        output = tmp_path / "reports"
        write_reports(conn, output, [message_hash])
        with (output / "messages.csv").open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            report_row = next(reader)
            assert "attachment_count" in reader.fieldnames
            assert "url_count" in reader.fieldnames
            assert int(report_row["attachment_count"]) == 1
            assert int(report_row["url_count"]) == row["url_count"]
    finally:
        conn.close()


def test_url_report_includes_sharepoint_presence_and_probable_relationship(tmp_path):
    case, conn, message_hash = _case_with_message(tmp_path)
    try:
        extract_urls(conn, case, [message_hash], progress=lambda _message: None)
        output = tmp_path / "urls.csv"
        write_url_report(conn, output, [message_hash])
        with output.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
        assert "contains_sharepoint_reference" in reader.fieldnames
        assert "sharepoint_relationship" in reader.fieldnames
        assert any(row["contains_sharepoint_reference"] == "yes" for row in rows)
        assert all(row["contains_sharepoint_reference"] in {"yes", "no"} for row in rows)
        assert all(row["sharepoint_relationship"] in {"not_sharepoint", "unknown", "probable_internal", "probable_external"} for row in rows)
    finally:
        conn.close()


def test_visible_catalog_has_no_pending_prerequisite_factors_and_maps_evaluators():
    visible_ids = {item["factor_id"] for item in FACTOR_CATALOG}
    assert "exact_unique_url_domains" not in visible_ids
    assert "exact_unique_url_domains" in {item["factor_id"] for item in LEGACY_FACTORS}
    for removed in (
        "attachment_extension_type_mismatch",
        "attachment_declared_mime_mismatch",
        "encrypted_archive",
        "calendar_external_url",
    ):
        assert removed not in visible_ids
    assert "attachment_archive" in visible_ids
    implemented_ids = {item["factor_id"] for item in FACTOR_CATALOG if item["implemented"]}
    assert implemented_ids.issubset(set(EVALUATORS))
    assert set(EVALUATORS) - implemented_ids == {"html_script_or_event_handlers"}
    assert {item["factor_id"] for item in FACTOR_CATALOG if not item["implemented"]} == set()
    assert set(PENDING_REASONS) == {"exact_unique_url_domains"}


def test_evaluator_batch_hits_expected_static_factors(tmp_path):
    case, conn, message_hash = _case_with_message(tmp_path)
    try:
        extract_urls(conn, case, [message_hash], progress=lambda _message: None)
        message = conn.execute("SELECT * FROM messages WHERE message_sha256=?", (message_hash,)).fetchone()
        config = normalize_config(all_factor_config(weight=1))
        summary, details = evaluate_message(conn, message, config)
        by_id = {row["factor_id"]: row for row in details}
        assert not [row for row in details if row["answer"] == "ERROR"]
        assert by_id["reply_to_domain_mismatch"]["answer"] == "YES"
        assert by_id["display_name_embedded_email_domain_mismatch"]["answer"] == "YES"
        # Loose EML evidence has no PST corpus from which a trusted verifier can be inferred.
        assert by_id["trusted_dmarc_fail"]["answer"] == "UNKNOWN"
        assert by_id["trusted_dkim_fail"]["answer"] == "UNKNOWN"
        assert by_id["trusted_spf_fail"]["answer"] == "UNKNOWN"
        assert by_id["url_literal_ip"]["answer"] == "YES"
        assert by_id["displayed_url_domain_mismatch"]["answer"] == "YES"
        assert by_id["html_form"]["answer"] == "YES"
        assert by_id["html_script"]["answer"] == "YES"
        assert by_id["html_event_handlers"]["answer"] == "NO"
        assert by_id["attachment_double_extension"]["answer"] == "YES"
        assert by_id["attachment_archive"]["answer"] == "NO"
        assert by_id["exact_attachment_count"]["answer"] == "NO"  # default expected_count=0
        for pending in PENDING_REASONS:
            if pending in by_id:
                assert by_id[pending]["answer"] == "UNKNOWN"
                assert by_id[pending]["points"] == 0
        assert summary["score"] > 0
    finally:
        conn.close()


def test_archive_evaluator_uses_stored_filename_and_mime_metadata(tmp_path):
    evidence = tmp_path / "evidence-archive"
    case = tmp_path / "case-archive"
    evidence.mkdir()
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Message-ID"] = "<archive@test.example>"
    message["Subject"] = "Archive"
    message.set_content("See attachment")
    message.add_attachment(b"not-opened-or-extracted", maintype="application", subtype="zip", filename="documents.zip")
    (evidence / "archive.eml").write_bytes(message.as_bytes())
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        row = conn.execute("SELECT * FROM messages").fetchone()
        config = normalize_config({
            "config_version": 1,
            "name": "Archive check",
            "preset": "custom",
            "factors": [{
                "factor_id": "attachment_archive",
                "enabled": True,
                "weight": 10,
                "effect_mode": "risk_when_yes",
                "parameters": {},
            }],
        })
        summary, details = evaluate_message(conn, row, config)
        detail = next(item for item in details if item["factor_id"] == "attachment_archive")
        assert detail["answer"] == "YES"
        assert detail["points"] == 10
        assert "documents.zip" in detail["evidence"]
        assert summary["score"] == 10
    finally:
        conn.close()
