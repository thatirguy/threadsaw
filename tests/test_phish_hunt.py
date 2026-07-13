from __future__ import annotations

import csv
import json
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.attachments import export_attachment_report
from threadsaw.case import initialize_case, load_case
from threadsaw.db import connect_db
from threadsaw.ingest import ingest_path
from threadsaw.phish_hunt import (
    normalize_config,
    prototype_default_config,
    read_hunt_report_selection,
    run_phish_hunt,
)
from threadsaw.selection import resolve_message_hashes
from threadsaw.phish_hunt_presets import preset_config
from threadsaw.urls import extract_urls, write_url_report


def _write_message(path: Path, *, sender: str, recipient: str, subject: str, body: str, attachment: bool = False) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = "Sat, 11 Jul 2026 12:00:00 +0000"
    message["Message-ID"] = f"<{path.stem}@test.example>"
    message["Subject"] = subject
    message.set_content(body)
    if attachment:
        message.add_attachment(b"sample", maintype="application", subtype="octet-stream", filename="sample.bin")
    path.write_bytes(message.as_bytes())


def test_phish_hunt_scores_cross_domain_and_creates_unique_runs(tmp_path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    _write_message(
        evidence / "external.eml",
        sender="sender@outside.test",
        recipient="recipient@example.com",
        subject="External",
        body="Review https://outside.test/path",
        attachment=True,
    )
    _write_message(
        evidence / "internal.eml",
        sender="sender@example.com",
        recipient="recipient@example.com",
        subject="Internal",
        body="Internal update",
    )
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)

    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(
            conn,
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
        )
        config = normalize_config({
            "config_version": 1,
            "name": "Legacy cross-domain test",
            "preset": "custom",
            "factors": [{
                "factor_id": "cross_domain_message",
                "enabled": True,
                "weight": 10,
                "effect_mode": "risk_when_yes",
                "parameters": {},
            }],
        })
        first = run_phish_hunt(
            conn,
            case,
            ids,
            config=config,
            output_root=case / "reports" / "phish_hunt",
            run_name="Test Hunt",
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
            progress=lambda _message: None,
        )
        second = run_phish_hunt(
            conn,
            case,
            ids,
            config=config,
            output_root=case / "reports" / "phish_hunt",
            run_name="Test Hunt",
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
            progress=lambda _message: None,
        )
        assert first["run_directory"] != second["run_directory"]
        assert Path(first["run_directory"]).is_dir()
        assert Path(second["run_directory"]).is_dir()
        assert conn.execute("SELECT COUNT(*) FROM phish_hunt_runs").fetchone()[0] == 2

        with Path(first["main_report"]).open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            assert reader.fieldnames[:6] == [
                "selected_date_utc",
                "score",
                "from_address",
                "recipient_addresses",
                "subject",
                "message_sha256",
            ]
        scores = {row["subject"]: int(row["score"]) for row in rows}
        assert scores == {"External": 10, "Internal": 0}
        assert all(row["case_id"] == load_case(case)["case_id"] for row in rows)

        selected = read_hunt_report_selection(
            Path(first["main_report"]),
            min_score=10,
            case_id=load_case(case)["case_id"],
            conn=conn,
        )
        assert len(selected) == 1
        subject = conn.execute("SELECT subject FROM messages WHERE message_sha256=?", (selected[0],)).fetchone()[0]
        assert subject == "External"

        extract_urls(conn, case, selected, progress=lambda _message: None)
        url_csv = case / "reports" / "high-risk-urls.csv"
        write_url_report(conn, url_csv, selected)
        with url_csv.open(encoding="utf-8-sig", newline="") as handle:
            url_rows = list(csv.DictReader(handle))
        assert url_rows and {row["subject"] for row in url_rows} == {"External"}

        attachment_result = export_attachment_report(
            conn,
            case / "reports" / "high-risk-attachments",
            selected,
            copy_files=False,
        )
        assert attachment_result["attachment_count"] == 1
    finally:
        conn.close()


def test_phish_hunt_score_is_uncapped_in_negative_direction(tmp_path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    _write_message(
        evidence / "external.eml",
        sender="sender@outside.test",
        recipient="recipient@example.com",
        subject="External",
        body="Body",
    )
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)
    config = normalize_config(
        {
            "config_version": 1,
            "name": "Large negative",
            "preset": "custom",
            "factors": [
                {
                    "factor_id": "cross_domain_message",
                    "enabled": True,
                    "weight": 1_000_000,
                    "effect_mode": "trust_when_yes",
                }
            ],
        }
    )
    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        result = run_phish_hunt(
            conn,
            case,
            ids,
            config=config,
            output_root=case / "reports" / "phish_hunt",
            run_name="Uncapped",
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
            progress=lambda _message: None,
        )
        with Path(result["main_report"]).open(encoding="utf-8-sig", newline="") as handle:
            row = next(csv.DictReader(handle))
        assert int(row["score"]) == -1_000_000
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        assert manifest["score_model"].startswith("uncapped additive integer centered at zero; the higher the score in the output CSV")

        positive_config = normalize_config(
            {
                "config_version": 1,
                "name": "Large positive",
                "preset": "custom",
                "factors": [
                    {
                        "factor_id": "cross_domain_message",
                        "enabled": True,
                        "weight": 1_000_000,
                        "effect_mode": "risk_when_yes",
                    }
                ],
            }
        )
        positive = run_phish_hunt(
            conn,
            case,
            ids,
            config=positive_config,
            output_root=case / "reports" / "phish_hunt",
            run_name="Uncapped positive",
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
            progress=lambda _message: None,
        )
        with Path(positive["main_report"]).open(encoding="utf-8-sig", newline="") as handle:
            positive_row = next(csv.DictReader(handle))
        assert int(positive_row["score"]) == 1_000_000
    finally:
        conn.close()


def test_legacy_removed_factor_is_preserved_as_unknown(tmp_path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    evidence.mkdir()
    _write_message(
        evidence / "one.eml",
        sender="sender@example.com",
        recipient="recipient@example.com",
        subject="One",
        body="Body",
    )
    initialize_case(case)
    ingest_path(evidence, case, progress=lambda _message: None)
    config = normalize_config(
        {
            "config_version": 1,
            "name": "Pending factor",
            "preset": "custom",
            "factors": [
                {
                    "factor_id": "exact_unique_url_domains",
                    "enabled": True,
                    "weight": 50,
                    "effect_mode": "risk_when_yes",
                    "parameters": {},
                }
            ],
        }
    )
    conn = connect_db(case)
    try:
        ids = resolve_message_hashes(conn, all_messages=True)
        result = run_phish_hunt(
            conn,
            case,
            ids,
            config=config,
            output_root=case / "reports" / "phish_hunt",
            run_name="Pending",
            start="2026-07-11T00:00:00Z",
            end="2026-07-12T00:00:00Z",
            progress=lambda _message: None,
        )
        with Path(result["details_report"]).open(encoding="utf-8-sig", newline="") as handle:
            detail = next(csv.DictReader(handle))
        assert detail["answer"] == "UNKNOWN"
        assert int(detail["points"]) == 0
        assert "removed from the visible catalog" in detail["reason"]
    finally:
        conn.close()


def test_bundled_presets_have_reviewable_distinct_weights_and_effects():
    external = preset_config("external")
    internal = preset_config("internal")
    general = preset_config("general")
    for document in (external, internal, general):
        assert document["config_version"] == 1
        assert len(document["factors"]) >= 60
        assert any(item["enabled"] for item in document["factors"])
        assert max(item["weight"] for item in document["factors"]) == 50
        assert all(item["weight"] >= 0 for item in document["factors"])
    ext = {item["factor_id"]: item for item in external["factors"]}
    internal_by_id = {item["factor_id"]: item for item in internal["factors"]}
    general_by_id = {item["factor_id"]: item for item in general["factors"]}
    assert ext["sender_recipient_same_domain"]["enabled"] is True
    assert ext["sender_recipient_same_domain"]["effect_mode"] == "trust_when_yes"
    assert internal_by_id["sender_recipient_same_domain"]["enabled"] is True
    assert internal_by_id["sender_recipient_same_domain"]["effect_mode"] == "risk_when_yes"
    assert general_by_id["sender_recipient_same_domain"]["enabled"] is False
    assert ext["sender_domain_lookalike_configured"]["enabled"] is False
    assert ext["sharepoint_host_mismatch"]["enabled"] is False
    assert ext["exact_url_count"]["enabled"] is False
    assert ext["attachment_archive"]["enabled"] is True


def test_legacy_encrypted_archive_config_upgrades_to_encrypted_zip_factor():
    config = normalize_config({
        "config_version": 1,
        "name": "Old archive config",
        "preset": "custom",
        "factors": [{
            "factor_id": "encrypted_archive",
            "enabled": True,
            "weight": 17,
            "effect_mode": "risk_when_yes",
            "parameters": {},
        }],
    })
    archive = next(item for item in config["factors"] if item["factor_id"] == "attachment_encrypted_zip")
    assert archive["enabled"] is True
    assert archive["weight"] == 17
