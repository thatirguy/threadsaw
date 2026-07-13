from __future__ import annotations

import io
import json
import zipfile
from email.message import EmailMessage
from pathlib import Path

import cv2
import pypdfium2 as pdfium

from threadsaw.case import load_case
from threadsaw.case_context import recompute_case_context, set_organization_domains
from threadsaw.db import connect_db
from threadsaw.ingest import ingest_path
from threadsaw.phish_hunt import normalize_config, run_phish_hunt
from threadsaw.qr import evaluate_qrs
from threadsaw.selection import resolve_message_hashes


def _message(*, subject: str, sender: str = "vendor@outside.test", recipient: str = "finance@example.com") -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Message-ID"] = f"<{subject.casefold().replace(' ', '-')}@outside.test>"
    message["Subject"] = subject
    message.set_content("Body")
    return message


def _one_factor(factor_id: str, weight: int = 10) -> dict:
    return normalize_config({
        "config_version": 1,
        "name": factor_id,
        "preset": "custom",
        "factors": [{
            "factor_id": factor_id,
            "enabled": True,
            "weight": weight,
            "effect_mode": "risk_when_yes",
            "parameters": {},
        }],
    })


def _set_zip_encryption_flags(data: bytes) -> bytes:
    output = bytearray(data)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        cursor = 0
        while True:
            cursor = output.find(signature, cursor)
            if cursor < 0:
                break
            flags = int.from_bytes(output[cursor + flag_offset:cursor + flag_offset + 2], "little") | 0x1
            output[cursor + flag_offset:cursor + flag_offset + 2] = flags.to_bytes(2, "little")
            cursor += len(signature)
    return bytes(output)


def test_password_protected_zip_factor_uses_bounded_inventory(tmp_path: Path):
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payment-details.txt", "secret")
    encrypted_zip = _set_zip_encryption_flags(archive_buffer.getvalue())

    message = _message(subject="Protected archive")
    message.add_attachment(encrypted_zip, maintype="application", subtype="zip", filename="documents.zip")
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "protected.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)

    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        result = run_phish_hunt(
            conn,
            case,
            ids,
            config=_one_factor("attachment_encrypted_zip", 25),
            output_root=case / "reports" / "phish_hunt",
            run_name="encrypted-zip",
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
            progress=lambda _message: None,
        )
        assert result["archive_inventory"]["archives_inspected"] == 1
        inspection = conn.execute(
            "SELECT status,encrypted_member_count FROM archive_inspections"
        ).fetchone()
        assert dict(inspection) == {"status": "complete", "encrypted_member_count": 1}
        details = json.loads(
            (Path(result["run_directory"]) / "phish_hunt.json").read_text(encoding="utf-8")
        )
        assert details[0]["score"] == 25
        factor = conn.execute(
            "SELECT answer,points FROM phish_hunt_factor_results WHERE factor_id='attachment_encrypted_zip'"
        ).fetchone()
        assert dict(factor) == {"answer": "YES", "points": 25}
    finally:
        conn.close()


def test_eml_only_case_accepts_declared_organization_domain(tmp_path: Path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "inbound.eml").write_bytes(_message(subject="Inbound").as_bytes())

    ingest_path(
        evidence,
        case,
        organization_domains=["Example.COM"],
        progress=lambda _message: None,
    )
    case_data = load_case(case)
    assert case_data["config"]["organization_domains"] == ["example.com"]
    assert case_data["config"]["organization_domains_declared"] is True

    conn = connect_db(case)
    try:
        assert conn.execute("SELECT direction FROM messages").fetchone()[0] == "inbound"
        set_organization_domains(case, ["other.example"])
        inferred = recompute_case_context(conn, case)
        assert inferred["organization_domains_source"] == "analyst-declared"
        assert conn.execute("SELECT direction FROM messages").fetchone()[0] == "unknown"
    finally:
        conn.close()


def test_trust_inference_requires_twenty_pst_messages(tmp_path: Path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    for index in range(5):
        message = _message(subject=f"Small {index}")
        message["Authentication-Results"] = "mx.example; dmarc=pass"
        message["Received"] = f"from sender.example by mx.example; Sat, 11 Jul 2026 12:00:0{index} +0000"
        (evidence / f"small-{index}.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)

    conn = connect_db(case)
    try:
        cursor = conn.execute(
            """INSERT INTO sources(source_type,source_path,source_relative_path,canonical_path,sha256,md5,size_bytes,
                   parent_source_id,parser_name,parser_version,status,error,added_utc)
               VALUES('PST','/evidence/small.pst',NULL,NULL,?,?,0,NULL,'readpst','test','indexed',NULL,'2026-07-11T00:00:00Z')""",
            ("9" * 64, "8" * 32),
        )
        conn.execute("UPDATE sources SET parent_source_id=? WHERE source_type='EML'", (cursor.lastrowid,))
        conn.commit()
        inferred = recompute_case_context(conn, case)
        assert inferred["pst_message_count"] == 5
        assert inferred["source"] == "pst-corpus-too-small-for-trust"
        assert inferred["trusted_authserv_ids"] == []
        assert inferred["trusted_received_hosts"] == []
        assert inferred["trusted_received_domains"] == []
    finally:
        conn.close()


def test_pdf_qr_rendering_uses_pypdfium2(tmp_path: Path):
    payload = "https://pdf-qr.example.test/"
    qr = cv2.QRCodeEncoder_create().encode(payload)
    qr = cv2.resize(qr, (300, 300), interpolation=cv2.INTER_NEAREST)
    jpeg = tmp_path / "qr.jpg"
    assert cv2.imwrite(str(jpeg), qr)

    pdf_path = tmp_path / "qr.pdf"
    document = pdfium.PdfDocument.new()
    page = document.new_page(400, 400)
    image = pdfium.PdfImage.new(document)
    try:
        image.load_jpeg(jpeg)
        image.set_matrix(pdfium.PdfMatrix(300, 0, 0, 300, 50, 50))
        page.insert_obj(image)
        page.gen_content()
        document.save(pdf_path)
    finally:
        image.close()
        page.close()
        document.close()

    message = _message(subject="PDF QR")
    message.add_attachment(pdf_path.read_bytes(), maintype="application", subtype="pdf", filename="qr.pdf")
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    (evidence / "pdf-qr.eml").write_bytes(message.as_bytes())
    ingest_path(evidence, case, progress=lambda _message: None)

    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        result = evaluate_qrs(
            conn,
            case,
            ids,
            output_root=case / "reports",
            max_pdf_pages=2,
            render_dpi=144,
        )
        assert result["qr_results"] == 1
        assert conn.execute("SELECT decoded_text FROM qr_results").fetchone()[0] == payload
    finally:
        conn.close()
