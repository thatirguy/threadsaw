from __future__ import annotations

import io
from base64 import urlsafe_b64encode
import json
import sqlite3
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from threadsaw.archive_inspection import inspect_zip_attachments
from threadsaw.case import initialize_case, load_case, update_case
from threadsaw.case_context import recompute_case_context
from threadsaw.db import connect_db
from threadsaw.domains import registrable_domain
from threadsaw.factor_evaluators import EVALUATORS
from threadsaw.ingest import ingest_path
from threadsaw.phish_hunt import evaluate_message, normalize_config, run_phish_hunt
from threadsaw.qr import evaluate_qrs
from threadsaw.selection import resolve_message_hashes
from threadsaw.urls import _decode_wrapper, extract_urls
from threadsaw.util import human_folder_name, safe_filename


def _base_message(*, subject: str = "Test", body: str = "Body", sender: str = "sender@outside.test", recipient: str = "recipient@example.com") -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Message-ID"] = f"<{subject.lower().replace(' ', '-')}@outside.test>"
    message["Subject"] = subject
    message.set_content(body)
    return message


def _one_factor(factor_id: str, *, weight: int = 10, parameters: dict | None = None) -> dict:
    return normalize_config({
        "config_version": 1,
        "name": factor_id,
        "preset": "custom",
        "factors": [{
            "factor_id": factor_id,
            "enabled": True,
            "weight": weight,
            "effect_mode": "risk_when_yes",
            "parameters": parameters or {},
        }],
    })


def test_attached_rfc822_is_stored_and_linked_without_body_or_attachment_leakage(tmp_path: Path):
    inner = _base_message(subject="Inner", body="INNER BODY TEXT", sender="vendor@example.net")
    inner.add_attachment(b"INNER PAYLOAD", maintype="application", subtype="octet-stream", filename="payload.exe")

    outer = _base_message(subject="Outer", body="see attached")
    outer.add_attachment(inner)

    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "outer.eml").write_bytes(outer.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)

    conn = connect_db(case)
    try:
        outer_row = conn.execute("SELECT * FROM messages WHERE subject='Outer'").fetchone()
        inner_row = conn.execute("SELECT * FROM messages WHERE subject='Inner'").fetchone()
        assert outer_row and inner_row
        assert "INNER BODY TEXT" not in (outer_row["body_text"] or "")
        assert "see attached" in (outer_row["body_text"] or "")

        outer_attachments = conn.execute(
            "SELECT original_filename,content_type_declared FROM attachments WHERE message_sha256=?",
            (outer_row["message_sha256"],),
        ).fetchall()
        assert len(outer_attachments) == 1
        assert outer_attachments[0]["content_type_declared"] == "message/rfc822"

        inner_attachments = conn.execute(
            "SELECT original_filename FROM attachments WHERE message_sha256=?",
            (inner_row["message_sha256"],),
        ).fetchall()
        assert [row["original_filename"] for row in inner_attachments] == ["payload.exe"]
        assert conn.execute(
            "SELECT 1 FROM message_relationships WHERE parent_message_sha256=? AND child_message_sha256=? AND relationship_type='message/rfc822'",
            (outer_row["message_sha256"], inner_row["message_sha256"]),
        ).fetchone()

        summary, details = evaluate_message(conn, outer_row, _one_factor("attached_email"))
        assert details[0]["answer"] == "YES"
        assert summary["score"] == 10
    finally:
        conn.close()


def test_url_dedup_bare_www_and_wrapper_decoding(tmp_path: Path):
    message = _base_message(body="Visit https://example.com/a then https://example.com/a and www.example.co.za/path")
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "message.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        message_sha = conn.execute("SELECT message_sha256 FROM messages").fetchone()[0]
        extract_urls(conn, case, [message_sha], progress=lambda _message: None)
        rows = conn.execute("SELECT raw_url,normalized_url FROM urls ORDER BY url_id").fetchall()
        assert len([row for row in rows if row["raw_url"] == "https://example.com/a"]) == 1
        assert any(row["normalized_url"] == "https://www.example.co.za/path" for row in rows)
        assert conn.execute("SELECT url_count FROM messages").fetchone()[0] == 2
    finally:
        conn.close()

    assert _decode_wrapper("https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_a-3Fx-3D1&d=x") == (
        "proofpoint-v2", "https://example.com/a?x=1"
    )
    wrapper, target = _decode_wrapper("https://urldefense.com/v3/__https://example.com/a__;abc!token")
    assert wrapper == "proofpoint-v3"
    assert target == "https://example.com/a"
    replacement_stream = urlsafe_b64encode(b"12").decode("ascii").rstrip("=")
    wrapper, target = _decode_wrapper(
        f"https://urldefense.com/v3/__https%3A//example.com/a%3Fx%3D*%26y%3D*__;{replacement_stream}!token"
    )
    assert wrapper == "proofpoint-v3"
    assert target == "https://example.com/a?x=1&y=2"
    wrapper, target = _decode_wrapper("https://protect-us.mimecast.com/s/abc?domain=example.com")
    assert wrapper == "mimecast-protect-domain"
    assert target == "https://example.com"
    wrapper, target = _decode_wrapper("https://url.us.m.mimecastprotect.com/s/abc?domain=example.net")
    assert wrapper == "mimecast-protect-domain"
    assert target == "https://example.net"


def test_inline_signature_image_is_not_counted_as_attachment(tmp_path: Path):
    message = _base_message(subject="Inline")
    message.add_alternative('<html><body>Hello<img src="cid:logo"></body></html>', subtype="html")
    html_part = message.get_payload()[-1]
    html_part.add_related(b"not-a-real-image", maintype="image", subtype="png", cid="<logo>", filename="logo.png", disposition="inline")

    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "inline.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        row = conn.execute("SELECT attachment_count,has_attachments FROM messages").fetchone()
        assert dict(row) == {"attachment_count": 0, "has_attachments": 0}
        attachment = conn.execute("SELECT original_filename,is_inline FROM attachments").fetchone()
        assert attachment["original_filename"] == "logo.png"
        assert attachment["is_inline"] == 1
    finally:
        conn.close()


def test_filename_controls_and_public_suffix_snapshot():
    assert "\u202e" not in safe_filename("invoice\u202ecod.exe")
    assert "\u2066" not in human_folder_name("Quarterly\u2066 Report")
    assert registrable_domain("a.b.example.co.za") == "example.co.za"
    assert registrable_domain("mail.example.com.cn") == "example.com.cn"
    assert registrable_domain("x.example.co.in") == "example.co.in"
    assert registrable_domain("x.example.com.sg") == "example.com.sg"


def test_phish_hunt_auto_indexes_urls_and_exposes_coverage(tmp_path: Path):
    message = _base_message(body="Open http://192.0.2.25/login")
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "url.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        assert conn.execute("SELECT url_indexed FROM messages").fetchone()[0] == 0
        result = run_phish_hunt(
            conn, case, ids, config=_one_factor("url_literal_ip"),
            output_root=case / "reports" / "phish_hunt", run_name="auto-url",
            start="2026-07-11T00:00:00Z", end="2026-07-12T00:00:00Z", progress=lambda _message: None,
        )
        assert result["url_auto_indexed_messages"] == 1
        assert conn.execute("SELECT url_indexed FROM messages").fetchone()[0] == 1
        details = json.loads((Path(result["run_directory"]) / "phish_hunt.json").read_text(encoding="utf-8"))
        assert details[0]["score"] == 10
        assert details[0]["max_possible_points_evaluated"] == 10
        assert details[0]["positive_score_percent_evaluated"] == 100.0
    finally:
        conn.close()


def test_unavailable_trusted_context_disables_dependent_factor(tmp_path: Path):
    message = _base_message()
    message["Authentication-Results"] = "mx.example; dmarc=fail header.from=outside.test"
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "auth.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        result = run_phish_hunt(
            conn, case, ids, config=_one_factor("trusted_dmarc_fail"),
            output_root=case / "reports" / "phish_hunt", run_name="no-context",
            start="2026-07-11T00:00:00Z", end="2026-07-12T00:00:00Z", progress=lambda _message: None,
        )
        assert result["context_dependent_factors_removed"] == [{
            "factor_id": "trusted_dmarc_fail",
            "reason": "No stable trusted Authentication-Results authserv-id could be inferred from at least 20 PST-derived messages.",
        }]
        effective = json.loads((Path(result["run_directory"]) / "scoring_config.json").read_text(encoding="utf-8"))
        assert effective["factors"][0]["enabled"] is False
    finally:
        conn.close()



def test_manual_trusted_server_configuration_is_ignored_without_pst_consensus(tmp_path: Path):
    case = tmp_path / "case"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    case_data = initialize_case(case)
    case_data["config"]["trusted_authserv_ids"] = ["manual.mx.example"]
    case_data["config"]["trusted_received_hosts"] = ["manual.mx.example"]
    update_case(case, case_data)

    message = _base_message(subject="Manual trust ignored")
    message["Authentication-Results"] = "manual.mx.example; dmarc=fail"
    message["Received"] = "from sender.example by manual.mx.example; Sat, 11 Jul 2026 12:00:00 +0000"
    (evidence / "manual.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)

    stored = load_case(case)
    assert "trusted_authserv_ids" not in stored["config"]
    assert "trusted_received_hosts" not in stored["config"]
    assert stored["inferred_context"]["source"] == "unavailable-no-pst"
    conn = connect_db(case)
    try:
        assert conn.execute("SELECT trusted FROM authentication_results").fetchone()[0] == 0
        assert conn.execute("SELECT trusted FROM received_hops WHERE hop_order=0").fetchone()[0] == 0
    finally:
        conn.close()

def test_pst_corpus_consensus_recomputes_trusted_auth_and_received_context(tmp_path: Path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    for index in range(20):
        message = _base_message(subject=f"Auth {index}")
        message["Authentication-Results"] = "mx.recipient.example; spf=pass; dkim=pass; dmarc=fail"
        message["Received"] = (
            f"from sender.example (sender.example [203.0.113.10]) by CH{index:02d}PR14MB4222.namprd14.prod.outlook.com; "
            f"Sat, 11 Jul 2026 12:00:{index:02d} +0000"
        )
        (evidence / f"auth-{index}.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        # This row represents the PST parent source in a PST-derived case. The
        # child EMLs above provide the normalized corpus used for inference.
        cursor = conn.execute(
            """INSERT INTO sources(source_type,source_path,source_relative_path,canonical_path,sha256,md5,size_bytes,
                   parent_source_id,parser_name,parser_version,status,error,added_utc)
               VALUES('PST','/evidence/mailbox.pst',NULL,NULL,?,?,0,NULL,'readpst','test','indexed',NULL,'2026-07-11T00:00:00Z')""",
            ("a" * 64, "b" * 32),
        )
        conn.execute("UPDATE sources SET parent_source_id=? WHERE source_type='EML'", (cursor.lastrowid,))
        conn.commit()
        inferred = recompute_case_context(conn, case)
        assert inferred["trusted_authserv_ids"] == ["mx.recipient.example"]
        assert inferred["trusted_received_hosts"] == []
        assert inferred["trusted_received_domains"] == ["namprd14.prod.outlook.com"]
        assert inferred["trusted_received_match_mode"] == "domain-suffix"
        assert conn.execute("SELECT COUNT(*) FROM authentication_results WHERE trusted=1").fetchone()[0] == 20
        assert conn.execute("SELECT COUNT(*) FROM received_hops WHERE trusted=1").fetchone()[0] == 20
        message = conn.execute("SELECT * FROM messages ORDER BY subject LIMIT 1").fetchone()
        _summary, details = evaluate_message(conn, message, _one_factor("trusted_dmarc_fail"))
        assert details[0]["answer"] == "YES"
    finally:
        conn.close()


def test_bounded_zip_listing_surfaces_risky_member_for_factor(tmp_path: Path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("documents/readme.txt", "hello")
        archive.writestr("documents/invoice.exe", b"MZpayload")
    message = _base_message(subject="Archive")
    message.add_attachment(buffer.getvalue(), maintype="application", subtype="zip", filename="documents.zip")
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "archive.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        result = inspect_zip_attachments(conn, ids, max_members_per_archive=10, max_total_members=10)
        assert result["archives_inspected"] == 1
        assert result["members_recorded"] == 2
        assert conn.execute("SELECT suspicious_extension FROM archive_members WHERE member_name='documents/invoice.exe'").fetchone()[0] == 1
        message_row = conn.execute("SELECT * FROM messages").fetchone()
        _summary, details = evaluate_message(conn, message_row, _one_factor("attachment_executable_or_script"))
        assert details[0]["answer"] == "YES"
        assert "invoice.exe" in details[0]["evidence"]
    finally:
        conn.close()


def test_offline_qr_decode_from_image_attachment(tmp_path: Path):
    cv2 = pytest.importorskip("cv2")
    payload = "https://qr.example.test/login"
    image = cv2.QRCodeEncoder_create().encode(payload)
    ok, png = cv2.imencode(".png", image)
    assert ok
    message = _base_message(subject="QR")
    message.add_attachment(png.tobytes(), maintype="image", subtype="png", filename="qr.png")
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "qr.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        result = evaluate_qrs(conn, case, ids, output_root=case / "reports", max_pdf_pages=2, render_dpi=144)
        assert result["qr_results"] == 1
        row = conn.execute("SELECT decoded_text,is_url,normalized_url FROM qr_results").fetchone()
        assert row["decoded_text"] == payload
        assert row["is_url"] == 1
        assert row["normalized_url"] == payload
    finally:
        conn.close()


def test_direction_and_new_factor_evaluators(tmp_path: Path):
    case = tmp_path / "case"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    case_data = initialize_case(case)
    case_data["config"]["organization_domains"] = ["example.com"]
    update_case(case, case_data)

    message = _base_message(
        subject="Urgent updated bank details",
        body="Please send the wire today. IBAN DE89370400440532013000",
        sender="vendor@outside.test",
        recipient="finance@example.com",
    )
    message.add_attachment(b"<html>payload</html>", maintype="text", subtype="html", filename="invoice.html")
    message.add_attachment(b"macro", maintype="application", subtype="octet-stream", filename="payment.docm")
    (evidence / "factors.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)

    conn = connect_db(case)
    try:
        row = conn.execute("SELECT * FROM messages").fetchone()
        assert row["direction"] == "inbound"
        for factor_id in ("payment_urgency_keywords", "attachment_html_svg", "attachment_modern_loader_or_macro"):
            _summary, details = evaluate_message(conn, row, _one_factor(factor_id))
            assert details[0]["answer"] == "YES", factor_id
    finally:
        conn.close()


def test_thread_continuation_changed_reply_to_domain(tmp_path: Path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()

    first = _base_message(subject="Invoice", sender="vendor@vendor.example", recipient="buyer@example.com")
    first.replace_header("Message-ID", "<thread-1@vendor.example>")
    first["Reply-To"] = "billing@vendor.example"
    (evidence / "first.eml").write_bytes(first.as_bytes())

    reply = _base_message(subject="Re: Invoice — URGENT updated bank details", sender="vendor@vendor.example", recipient="buyer@example.com")
    reply.replace_header("Date", "Sat, 11 Jul 2026 13:00:00 +0000")
    reply.replace_header("Message-ID", "<thread-2@vendor.example>")
    reply["In-Reply-To"] = "<thread-1@vendor.example>"
    reply["References"] = "<thread-1@vendor.example>"
    reply["Reply-To"] = "payment@attacker.test"
    (evidence / "reply.eml").write_bytes(reply.as_bytes())

    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        current = conn.execute("SELECT * FROM messages WHERE internet_message_id='<thread-2@vendor.example>'").fetchone()
        assert current
        _summary, details = evaluate_message(conn, current, _one_factor("thread_continuation_changed_infrastructure"))
        assert details[0]["answer"] == "YES"
        assert "reply_to_domain=attacker.test" in details[0]["evidence"]
    finally:
        conn.close()


def test_context_inference_uses_pst_derived_messages_only(tmp_path: Path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    for index in range(20):
        message = _base_message(subject=f"PST {index}")
        message["Authentication-Results"] = "pst.mx.example; dmarc=pass"
        message["Received"] = f"from sender.example by pst.mx.example; Sat, 11 Jul 2026 12:00:{index:02d} +0000"
        (evidence / f"pst-{index}.eml").write_bytes(message.as_bytes())
    outsider = _base_message(subject="Loose")
    outsider["Authentication-Results"] = "loose.mx.example; dmarc=fail"
    outsider["Received"] = "from attacker.example by loose.mx.example; Sat, 11 Jul 2026 12:00:09 +0000"
    (evidence / "loose.eml").write_bytes(outsider.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)
    conn = connect_db(case)
    try:
        cursor = conn.execute(
            """INSERT INTO sources(source_type,source_path,source_relative_path,canonical_path,sha256,md5,size_bytes,
                   parent_source_id,parser_name,parser_version,status,error,added_utc)
               VALUES('PST','/evidence/mailbox.pst',NULL,NULL,?,?,0,NULL,'readpst','test','indexed',NULL,'2026-07-11T00:00:00Z')""",
            ("c" * 64, "d" * 32),
        )
        pst_source_id = cursor.lastrowid
        conn.execute("UPDATE sources SET parent_source_id=? WHERE source_path LIKE '%pst-%'", (pst_source_id,))
        conn.commit()
        inferred = recompute_case_context(conn, case)
        assert inferred["trusted_authserv_ids"] == ["pst.mx.example"]
        assert inferred["trusted_received_hosts"] == ["pst.mx.example"]
        assert "loose.mx.example" not in inferred["trusted_authserv_ids"]
    finally:
        conn.close()


def test_version_1_database_migrates_in_place(tmp_path: Path):
    database = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        PRAGMA foreign_keys=OFF;
        CREATE TABLE messages (
            message_sha256 TEXT PRIMARY KEY, format TEXT NOT NULL, derivation_status TEXT NOT NULL, eml_path TEXT,
            internet_message_id TEXT, subject TEXT, from_address TEXT, reply_to TEXT, return_path TEXT,
            header_date_raw TEXT, header_date_utc TEXT, top_received_utc TEXT, trusted_received_utc TEXT,
            selected_date_utc TEXT, selected_date_source TEXT, sender_ips_json TEXT NOT NULL DEFAULT '[]',
            raw_headers_text TEXT, body_text TEXT, body_text_source TEXT, body_html TEXT,
            date_discrepancy_seconds INTEGER, defects_json TEXT NOT NULL DEFAULT '[]', attachment_count INTEGER NOT NULL DEFAULT 0,
            url_count INTEGER NOT NULL DEFAULT 0, url_indexed INTEGER NOT NULL DEFAULT 0,
            has_attachments INTEGER NOT NULL DEFAULT 0, indexed_utc TEXT NOT NULL
        );
        CREATE TABLE attachments (
            attachment_id INTEGER PRIMARY KEY AUTOINCREMENT, message_sha256 TEXT NOT NULL, part_index INTEGER NOT NULL,
            original_filename TEXT, safe_filename TEXT, content_type_declared TEXT, size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL, md5 TEXT NOT NULL, artifact_path TEXT, content_disposition TEXT, content_id TEXT,
            executable_format TEXT, status TEXT NOT NULL, UNIQUE(message_sha256,part_index)
        );
        CREATE TABLE urls (
            url_id INTEGER PRIMARY KEY AUTOINCREMENT, message_sha256 TEXT NOT NULL, source_part TEXT NOT NULL,
            displayed_text TEXT, display_target_mismatch INTEGER, raw_url TEXT NOT NULL, normalized_url TEXT,
            wrapper_type TEXT, decoded_target_url TEXT, hostname TEXT, registrable_domain TEXT,
            registrable_domain_method TEXT, is_sharepoint INTEGER NOT NULL DEFAULT 0, sharepoint_relationship TEXT,
            UNIQUE(message_sha256,source_part,raw_url,displayed_text)
        );
        CREATE TABLE phish_hunt_runs (
            run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, run_name TEXT NOT NULL, config_name TEXT NOT NULL,
            config_hash TEXT NOT NULL, config_json TEXT NOT NULL, selection_json TEXT NOT NULL, output_path TEXT NOT NULL,
            status TEXT NOT NULL, started_utc TEXT NOT NULL, completed_utc TEXT, message_count INTEGER NOT NULL DEFAULT 0,
            threadsaw_version TEXT NOT NULL, error_detail TEXT
        );
        CREATE TABLE phish_hunt_results (
            run_id TEXT NOT NULL, message_sha256 TEXT NOT NULL, score INTEGER NOT NULL, positive_points INTEGER NOT NULL,
            negative_points INTEGER NOT NULL, evaluated_factor_count INTEGER NOT NULL, unknown_factor_count INTEGER NOT NULL,
            top_score_reasons TEXT, PRIMARY KEY(run_id,message_sha256)
        );
        """
    )
    sha = "1" * 64
    conn.execute(
        """INSERT INTO messages(message_sha256,format,derivation_status,subject,from_address,selected_date_utc,
               sender_ips_json,defects_json,attachment_count,url_count,url_indexed,has_attachments,indexed_utc)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (sha, "EML", "original-eml", "Re: Legacy", "Sender <User@Example.CO.ZA>", "2026-07-11T12:00:00Z", "[]", "[]", 1, 2, 1, 1, "2026-07-11T12:00:00Z"),
    )
    conn.execute(
        "INSERT INTO attachments(message_sha256,part_index,original_filename,size_bytes,sha256,md5,status) VALUES(?,?,?,?,?,?,?)",
        (sha, 0, "logo.png", 1, "2" * 64, "3" * 32, "stored"),
    )
    # Legacy UNIQUE permits duplicate rows when displayed_text is NULL.
    for _ in range(2):
        conn.execute(
            "INSERT INTO urls(message_sha256,source_part,displayed_text,raw_url,normalized_url,hostname,registrable_domain,registrable_domain_method) VALUES(?,?,?,?,?,?,?,?)",
            (sha, "text-body", None, "https://a.example.co.za", "https://a.example.co.za", "a.example.co.za", "example.co.za", "legacy"),
        )
    conn.execute(
        "INSERT INTO phish_hunt_runs(run_id,case_id,run_name,config_name,config_hash,config_json,selection_json,output_path,status,started_utc,threadsaw_version) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("run", "case", "run", "config", "hash", "{}", "{}", "/tmp", "complete", "2026-07-11T12:00:00Z", "1.0.0"),
    )
    conn.execute(
        "INSERT INTO phish_hunt_results(run_id,message_sha256,score,positive_points,negative_points,evaluated_factor_count,unknown_factor_count) VALUES(?,?,?,?,?,?,?)",
        ("run", sha, 10, 10, 0, 1, 0),
    )
    conn.commit()

    from threadsaw.db import initialize_schema
    initialize_schema(conn)
    try:
        message = conn.execute("SELECT * FROM messages").fetchone()
        assert message["from_address_normalized"] == "user@example.co.za"
        assert message["from_domain_registrable"] == "example.co.za"
        assert message["normalized_subject"] == "legacy"
        assert "direction" in message.keys()
        assert conn.execute("SELECT is_inline FROM attachments").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 1
        url = conn.execute("SELECT effective_registrable_domain FROM urls").fetchone()
        assert url[0] == "example.co.za"
        result = conn.execute("SELECT * FROM phish_hunt_results").fetchone()
        assert result["max_possible_points_evaluated"] == 0
        assert result["unknown_positive_points"] == 0
        assert "positive_score_percent_evaluated" in result.keys()
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='qr_results'").fetchone()
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()
