from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest

import pytest
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.attachments import export_attachment_report
from threadsaw.case import initialize_case
from threadsaw.db import connect_db
from threadsaw.exporter import export_messages
from threadsaw.ingest import ingest_path
from threadsaw.reports import write_reports
from threadsaw.selection import create_scope, resolve_message_hashes
from threadsaw.urls import extract_urls, write_url_report


def write_message(path: Path, *, date: str, subject: str = "Test", plain: str | None = "Body",
                  html: str | None = None, attachment_name: str | None = None) -> None:
    message = EmailMessage()
    message["From"] = "Accounts Payable <ap@example-attacker.test>"
    message["To"] = "Analyst <analyst@example.com>"
    message["Reply-To"] = "redirect@reply.test"
    message["Return-Path"] = "<bounce@return.test>"
    message["Date"] = date
    message["Message-ID"] = f"<{path.stem}@example-attacker.test>"
    message["Subject"] = subject
    message["Received"] = "from sender.example (sender.example [203.0.113.10]) by mx.example.com; Fri, 10 Jul 2026 16:31:00 +0000"
    message["Authentication-Results"] = "mx.example.com; spf=fail dkim=none dmarc=fail"
    if plain is not None:
        message.set_content(plain)
        if html is not None:
            message.add_alternative(html, subtype="html")
    elif html is not None:
        message.set_content(html, subtype="html")
    if attachment_name:
        message.add_attachment(b"MZfake", maintype="application", subtype="octet-stream", filename=attachment_name)
    path.write_bytes(message.as_bytes())


class WorkflowTest(unittest.TestCase):
    def test_eml_ingest_report_url_export(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence"
            case = root / "case"
            evidence.mkdir()
            write_message(
                evidence / "sample.eml",
                date="Fri, 10 Jul 2026 12:30:00 -0400",
                subject="=Potential spreadsheet formula",
                plain="Review https://example-attacker.test/invoice",
                html='<p>Open <a href="https://evil.test/login">Microsoft 365</a></p>',
                attachment_name="../invoice.exe",
            )

            initialize_case(case)
            stats = ingest_path(evidence, case)
            self.assertEqual(stats["indexed_new"], 1)
            self.assertEqual(stats["errors"], 0)

            conn = connect_db(case)
            try:
                ids = [r["message_sha256"] for r in conn.execute("SELECT message_sha256 FROM messages")]
                self.assertEqual(len(ids), 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM attachments").fetchone()[0], 1)
                self.assertGreaterEqual(extract_urls(conn, case, ids), 2)
                report_dir = case / "exports" / "test"
                write_reports(conn, report_dir, ids)
                write_url_report(conn, report_dir / "urls.csv", ids)
                export_base = case / "exports" / "selected"
                export_manifest = export_messages(conn, export_base, ids)
                export_dir = Path(export_manifest["output_directory"])
                self.assertTrue((export_dir / "summary.csv").exists())
                self.assertTrue((export_dir / "manifest.json").exists())
                self.assertEqual(len(list(export_dir.glob("*/message.eml"))), 1)
                review = next(export_dir.glob("*/review.txt")).read_text(encoding="utf-8")
                self.assertIn("FULL HEADER BLOCK", review)
                self.assertIn("ATTACHMENTS", review)
                self.assertNotIn("../invoice.exe", next((case / "artifacts" / "attachments").rglob("*"), Path()).name)
                with (report_dir / "messages.csv").open("r", encoding="utf-8-sig", newline="") as handle:
                    row = next(csv.DictReader(handle))
                    self.assertTrue(row["subject"].startswith("'="))
                    self.assertEqual(row["from_reply_to_mismatch"], "True")
                    self.assertEqual(row["from_return_path_mismatch"], "True")
            finally:
                conn.close()

    def test_html_only_body_is_rendered_to_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence"
            case = root / "case"
            evidence.mkdir()
            write_message(
                evidence / "html-only.eml",
                date="Fri, 10 Jul 2026 12:30:00 -0400",
                plain=None,
                html="<html><body><h1>Payment</h1><p>Open the portal.</p></body></html>",
            )
            ingest_path(evidence, case)
            conn = connect_db(case)
            try:
                row = conn.execute("SELECT body_text,body_text_source FROM messages").fetchone()
                self.assertEqual(row["body_text_source"], "derived-from-html")
                self.assertIn("Payment", row["body_text"])
                self.assertIn("Open the portal", row["body_text"])
            finally:
                conn.close()

    def test_date_range_is_start_inclusive_end_exclusive_and_scope_is_stable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence"
            case = root / "case"
            evidence.mkdir()
            write_message(evidence / "start.eml", date="Fri, 10 Jul 2026 00:00:00 +0000")
            write_message(evidence / "inside.eml", date="Fri, 10 Jul 2026 12:00:00 +0000")
            write_message(evidence / "end.eml", date="Sat, 11 Jul 2026 00:00:00 +0000")
            ingest_path(evidence, case)
            conn = connect_db(case)
            try:
                ids = resolve_message_hashes(conn, start="2026-07-10T00:00:00Z", end="2026-07-11T00:00:00Z")
                self.assertEqual(len(ids), 2)
                self.assertEqual(create_scope(conn, name="window", start="2026-07-10T00:00:00Z", end="2026-07-11T00:00:00Z"), 2)
                # A later ingest does not mutate the already resolved scope.
                write_message(evidence / "late-add.eml", date="Fri, 10 Jul 2026 18:00:00 +0000")
                ingest_path(evidence / "late-add.eml", case)
                scoped = resolve_message_hashes(conn, scope="window")
                current_range = resolve_message_hashes(conn, start="2026-07-10T00:00:00Z", end="2026-07-11T00:00:00Z")
                self.assertEqual(len(scoped), 2)
                self.assertEqual(len(current_range), 3)
            finally:
                conn.close()

    def test_sha256_csv_selection_and_safe_links_decoding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence"
            case = root / "case"
            evidence.mkdir()
            target = "https://external.example/login?invoice=42"
            safe_link = "https://nam01.safelinks.protection.outlook.com/?url=" + quote(target, safe="")
            write_message(
                evidence / "wrapped.eml",
                date="Fri, 10 Jul 2026 12:30:00 -0400",
                plain=f"Open {safe_link}",
                html='<a href="https://evil.example/path">https://good.example/path</a>',
            )
            ingest_path(evidence, case)
            conn = connect_db(case)
            try:
                message_sha256 = conn.execute("SELECT message_sha256 FROM messages").fetchone()[0]
                sha256_csv = root / "ids.csv"
                sha256_csv.write_text("message_sha256\n" + message_sha256 + "\n", encoding="utf-8")
                self.assertEqual(resolve_message_hashes(conn, sha256_csv=sha256_csv), [message_sha256])
                extract_urls(conn, case, [message_sha256])
                safe = conn.execute("SELECT wrapper_type,decoded_target_url FROM urls WHERE wrapper_type IS NOT NULL").fetchone()
                self.assertEqual(safe["wrapper_type"], "microsoft-safelinks")
                self.assertEqual(safe["decoded_target_url"], target)
                mismatch = conn.execute("SELECT display_target_mismatch FROM urls WHERE displayed_text <> ''").fetchone()
                self.assertEqual(mismatch["display_target_mismatch"], 1)
            finally:
                conn.close()

    def test_loose_eml_is_copied_into_case_and_exports_without_original_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence"
            case = root / "case"
            evidence.mkdir()
            source = evidence / "portable.eml"
            write_message(
                source,
                date="Sat, 11 Jul 2026 12:00:00 +0000",
                subject="Portable: Invoice / Review?",
                attachment_name="invoice.pdf",
            )
            ingest_path(evidence, case, progress=lambda _m: None)
            source.unlink()
            conn = connect_db(case)
            try:
                source_row = conn.execute("SELECT canonical_path FROM sources WHERE source_type='EML'").fetchone()
                self.assertTrue(Path(source_row["canonical_path"]).is_file())
                ids = resolve_message_hashes(conn, all_messages=True)
                manifest = export_messages(conn, case / "exports" / "messages", ids)
                self.assertEqual(manifest["message_count"], 1)
                self.assertEqual(manifest["messages"][0]["directory"], "Portable_ Invoice _ Review_")
                export_dir = Path(manifest["output_directory"])
                self.assertTrue((export_dir / "Portable_ Invoice _ Review_" / "message.eml").is_file())
            finally:
                conn.close()

    def test_attachment_copy_uses_subject_folder_and_original_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence"
            case = root / "case"
            evidence.mkdir()
            write_message(
                evidence / "attachment.eml",
                date="Sat, 11 Jul 2026 12:00:00 +0000",
                subject="Invoice: July / Review?",
                attachment_name="invoice.pdf",
            )
            ingest_path(evidence, case, progress=lambda _m: None)
            conn = connect_db(case)
            try:
                ids = resolve_message_hashes(conn, all_messages=True)
                result = export_attachment_report(
                    conn,
                    case / "reports" / "attachments",
                    ids,
                    copy_files=True,
                    files_output_dir=case / "exports" / "attachments",
                )
                self.assertEqual(result["copied_files"], 1)
                copied = case / "exports" / "attachments" / "Invoice_ July _ Review_" / "invoice.pdf"
                self.assertTrue(copied.is_file())
                with (case / "reports" / "attachments" / "attachments.csv").open(encoding="utf-8-sig", newline="") as handle:
                    row = next(csv.DictReader(handle))
                self.assertEqual(row["exported_path"], "exports/attachments/Invoice_ July _ Review_/invoice.pdf")
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()


def test_v2_reports_include_message_context(tmp_path):
    from email.message import EmailMessage
    from threadsaw.case import initialize_case
    from threadsaw.db import connect_db, initialize_schema
    from threadsaw.ingest import ingest_path
    from threadsaw.selection import resolve_message_hashes
    from threadsaw.urls import extract_urls, write_url_report
    import csv

    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.net"
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Subject"] = "Context test"
    message.set_content("Review https://example.com/path")
    message.add_attachment(b"test", maintype="application", subtype="octet-stream", filename="sample.bin")
    (evidence / "context.eml").write_bytes(message.as_bytes())

    ingest_path(evidence, case, progress=lambda _m: None)
    conn = connect_db(case)
    initialize_schema(conn)
    ids = resolve_message_hashes(conn, all_messages=True)
    extract_urls(conn, case, ids, progress=lambda _m: None)
    url_csv = case / "exports" / "urls.csv"
    write_url_report(conn, url_csv, ids)
    attach_dir = case / "exports" / "attachments"
    export_attachment_report(conn, attach_dir, ids)
    conn.close()

    with url_csv.open(encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["sender_email"] == "sender@example.com"
    assert row["recipient_addresses"] == "recipient@example.net"
    assert row["message_date_utc"] == "2026-07-11T12:00:00Z"
    assert row["subject"] == "Context test"

    with (attach_dir / "attachments.csv").open(encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["sender_email"] == "sender@example.com"
    assert row["recipient_addresses"] == "recipient@example.net"
    assert row["message_date_utc"] == "2026-07-11T12:00:00Z"
    assert row["subject"] == "Context test"


def test_sender_ip_types_and_security_results_are_exported(tmp_path):
    import csv
    import json
    from email.message import EmailMessage
    from threadsaw.case import initialize_case
    from threadsaw.db import connect_db
    from threadsaw.exporter import export_messages
    from threadsaw.ingest import ingest_path
    from threadsaw.reports import write_reports
    from threadsaw.selection import resolve_message_hashes
    from threadsaw.urls import extract_urls, write_url_report

    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    initialize_case(case)
    case_data = json.loads((case / "case.json").read_text(encoding="utf-8"))
    case_data["config"]["trusted_received_hosts"] = ["mx.recipient.example"]
    case_data["config"]["trusted_authserv_ids"] = ["mx.recipient.example"]
    (case / "case.json").write_text(json.dumps(case_data), encoding="utf-8")

    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.net"
    message["Subject"] = "Sender IP test"
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Received"] = (
        "from outbound.example (outbound.example [203.0.113.10]) "
        "by mx.recipient.example (mx.recipient.example [10.0.0.5]); "
        "Sat, 11 Jul 2026 12:00:01 +0000"
    )
    message["Received"] = (
        "from workstation (unknown [198.51.100.25]) by outbound.example; "
        "Sat, 11 Jul 2026 11:59:59 +0000"
    )
    message["Authentication-Results"] = (
        "mx.recipient.example; spf=pass smtp.mailfrom=example.com client-ip=203.0.113.10; "
        "dkim=pass header.d=example.com; dmarc=fail header.from=example.com"
    )
    message["X-Originating-IP"] = "[192.0.2.77]"
    message.set_content("Review https://example.com/path")
    message.add_attachment(b"content", maintype="application", subtype="octet-stream", filename="sample.bin")
    (evidence / "ip-test.eml").write_bytes(message.as_bytes())

    ingest_path(evidence, case, progress=lambda _m: None)
    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        extract_urls(conn, case, ids, progress=lambda _m: None)
        write_reports(conn, case / "reports", ids)
        write_url_report(conn, case / "reports" / "urls.csv", ids)
        export_manifest = export_messages(conn, case / "exports" / "messages", ids)
    finally:
        conn.close()

    with (case / "reports" / "messages.csv").open(encoding="utf-8-sig", newline="") as handle:
        message_row = next(csv.DictReader(handle))
    assert message_row["trusted_boundary_ip"] == ""
    assert message_row["spf_client_ip"] == "203.0.113.10"
    assert message_row["claimed_originating_ip"] == "192.0.2.77"
    assert message_row["topmost_received_ip"] == "203.0.113.10"
    assert message_row["bottommost_received_ip"] == "198.51.100.25"
    assert "sender_ips" not in message_row
    assert message_row["spf_result"] == "pass"
    assert message_row["dkim_result"] == "pass"
    assert message_row["dmarc_result"] == "fail"

    with (case / "reports" / "urls.csv").open(encoding="utf-8-sig", newline="") as handle:
        url_row = next(csv.DictReader(handle))
    with (case / "reports" / "attachments.csv").open(encoding="utf-8-sig", newline="") as handle:
        attachment_row = next(csv.DictReader(handle))
    for row in (url_row, attachment_row):
        assert row["recipient_addresses"] == "recipient@example.net"
        assert row["trusted_boundary_ip"] == ""
        assert row["spf_client_ip"] == "203.0.113.10"
        assert row["claimed_originating_ip"] == "192.0.2.77"
        assert row["topmost_received_ip"] == "203.0.113.10"
        assert row["bottommost_received_ip"] == "198.51.100.25"

    review = next(Path(export_manifest["output_directory"]).glob("*/review.txt")).read_text(encoding="utf-8")
    assert "Motto:" not in review
    assert "Recipients: recipient@example.net" in review
    assert "Trusted Boundary IP: " in review
    assert "SPF Client IP: 203.0.113.10" in review
    assert "Claimed Originating IP: 192.0.2.77" in review
    assert "SPF Result: PASS" in review
    assert "DKIM Result: PASS" in review
    assert "DMARC Result: FAIL" in review


def test_missing_case_message_points_to_ingest_or_run(tmp_path):
    from threadsaw.case import load_case

    with pytest.raises(FileNotFoundError) as excinfo:
        load_case(tmp_path / "not-a-case")
    message = str(excinfo.value)
    assert "threadsaw ingest" in message
    assert "threadsaw run" in message
    assert "threadsaw init" not in message
