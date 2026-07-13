from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from threadsaw.db import _recover_legacy_wal, connect_db, database_health, initialize_schema


def test_fresh_case_uses_delete_journal_and_full_integrity(tmp_path):
    case = tmp_path / "case"
    conn = connect_db(case)
    try:
        initialize_schema(conn)
        health = database_health(conn)
        assert health == {"journal_mode": "delete", "integrity": "ok", "ready": True}
    finally:
        conn.close()
    assert not (case / "threadsaw.sqlite3-wal").exists()
    assert not (case / "threadsaw.sqlite3-shm").exists()


def test_legacy_wal_recovery_preserves_committed_rows(tmp_path):
    source_dir = tmp_path / "source"
    case = tmp_path / "case"
    source_dir.mkdir()
    case.mkdir()
    source_db = source_dir / "threadsaw.sqlite3"

    # Keep the source connection open while copying so the committed row exists
    # in the WAL sidecar rather than relying on close-time checkpoint behavior.
    source_conn = sqlite3.connect(source_db)
    source_conn.execute("PRAGMA journal_mode=WAL")
    source_conn.execute("PRAGMA wal_autocheckpoint=0")
    source_conn.execute("CREATE TABLE sample(value TEXT)")
    source_conn.execute("INSERT INTO sample VALUES('preserved')")
    source_conn.commit()

    shutil.copy2(source_db, case / source_db.name)
    wal = Path(str(source_db) + "-wal")
    shm = Path(str(source_db) + "-shm")
    assert wal.exists()
    shutil.copy2(wal, case / wal.name)
    if shm.exists():
        shutil.copy2(shm, case / shm.name)
    source_conn.close()

    backup = _recover_legacy_wal(case / "threadsaw.sqlite3")
    assert (backup / "threadsaw.sqlite3").exists()
    assert (backup / "threadsaw.sqlite3-wal").exists()

    conn = connect_db(case)
    try:
        assert conn.execute("SELECT value FROM sample").fetchone()[0] == "preserved"
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
        assert conn.execute("PRAGMA integrity_check").fetchone()[0].lower() == "ok"
    finally:
        conn.close()
    assert not (case / "threadsaw.sqlite3-wal").exists()
    assert not (case / "threadsaw.sqlite3-shm").exists()


def test_schema_migration_adds_and_backfills_url_counts(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    db_path = case / "threadsaw.sqlite3"
    raw = sqlite3.connect(db_path)
    try:
        raw.executescript(
            """
            CREATE TABLE messages (
                message_sha256 TEXT PRIMARY KEY,
                format TEXT NOT NULL,
                derivation_status TEXT NOT NULL,
                eml_path TEXT,
                internet_message_id TEXT,
                subject TEXT,
                from_address TEXT,
                reply_to TEXT,
                return_path TEXT,
                header_date_raw TEXT,
                header_date_utc TEXT,
                top_received_utc TEXT,
                trusted_received_utc TEXT,
                selected_date_utc TEXT,
                selected_date_source TEXT,
                sender_ips_json TEXT NOT NULL DEFAULT '[]',
                raw_headers_text TEXT,
                body_text TEXT,
                body_text_source TEXT,
                body_html TEXT,
                date_discrepancy_seconds INTEGER,
                defects_json TEXT NOT NULL DEFAULT '[]',
                attachment_count INTEGER NOT NULL DEFAULT 0,
                has_attachments INTEGER NOT NULL DEFAULT 0,
                indexed_utc TEXT NOT NULL
            );
            CREATE TABLE urls (
                url_id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_sha256 TEXT NOT NULL,
                source_part TEXT NOT NULL,
                displayed_text TEXT,
                display_target_mismatch INTEGER,
                raw_url TEXT NOT NULL,
                normalized_url TEXT,
                wrapper_type TEXT,
                decoded_target_url TEXT,
                hostname TEXT,
                registrable_domain TEXT,
                registrable_domain_method TEXT,
                is_sharepoint INTEGER NOT NULL DEFAULT 0,
                sharepoint_relationship TEXT
            );
            INSERT INTO messages(message_sha256,format,derivation_status,indexed_utc)
            VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','EML','original','2026-01-01T00:00:00Z');
            INSERT INTO urls(message_sha256,source_part,raw_url,registrable_domain)
            VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','text-body','https://example.test','example.test');
            """
        )
        raw.commit()
    finally:
        raw.close()

    conn = connect_db(case)
    try:
        initialize_schema(conn)
        row = conn.execute("SELECT url_count,url_indexed FROM messages").fetchone()
        assert row["url_count"] == 1
        assert row["url_indexed"] == 1
    finally:
        conn.close()
