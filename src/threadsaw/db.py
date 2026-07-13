from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DB_FILENAME = "threadsaw.sqlite3"
BUSY_TIMEOUT_MS = 30_000

# Rollback-journal mode is deliberate. Threadsaw cases are commonly stored on
# Windows/macOS host folders bind-mounted into a Linux Docker VM. SQLite WAL
# relies on shared-memory/locking behavior that is not a safe portability
# assumption across that boundary.
SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    source_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source_path TEXT NOT NULL,
    source_relative_path TEXT,
    canonical_path TEXT,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    parent_source_id INTEGER REFERENCES sources(source_id),
    parser_name TEXT,
    parser_version TEXT,
    status TEXT NOT NULL,
    error TEXT,
    added_utc TEXT NOT NULL,
    UNIQUE(source_path, sha256)
);

CREATE TABLE IF NOT EXISTS messages (
    message_sha256 TEXT PRIMARY KEY,
    format TEXT NOT NULL,
    derivation_status TEXT NOT NULL,
    eml_path TEXT,
    internet_message_id TEXT,
    subject TEXT,
    normalized_subject TEXT,
    from_address TEXT,
    from_address_normalized TEXT,
    from_domain_registrable TEXT,
    direction TEXT,
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
    url_count INTEGER NOT NULL DEFAULT 0,
    url_indexed INTEGER NOT NULL DEFAULT 0,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    indexed_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS message_sources (
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
    PRIMARY KEY (message_sha256, source_id)
);

CREATE TABLE IF NOT EXISTS recipients (
    recipient_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    recipient_type TEXT NOT NULL,
    display_name TEXT,
    email_address TEXT,
    domain TEXT
);

CREATE TABLE IF NOT EXISTS received_hops (
    hop_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    hop_order INTEGER NOT NULL,
    raw_value TEXT NOT NULL,
    parsed_date_utc TEXT,
    sender_ips_json TEXT NOT NULL DEFAULT '[]',
    trusted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authentication_results (
    auth_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    authserv_id TEXT,
    spf_result TEXT,
    dkim_result TEXT,
    dmarc_result TEXT,
    arc_result TEXT,
    trusted INTEGER NOT NULL DEFAULT 0,
    raw_value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    attachment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    part_index INTEGER NOT NULL,
    original_filename TEXT,
    safe_filename TEXT,
    content_type_declared TEXT,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    artifact_path TEXT,
    content_disposition TEXT,
    content_id TEXT,
    executable_format TEXT,
    is_inline INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    UNIQUE(message_sha256, part_index)
);


CREATE TABLE IF NOT EXISTS message_relationships (
    parent_message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    child_message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    parent_part_index INTEGER NOT NULL,
    relationship_type TEXT NOT NULL,
    PRIMARY KEY(parent_message_sha256, child_message_sha256, parent_part_index)
);

CREATE TABLE IF NOT EXISTS archive_members (
    archive_member_id INTEGER PRIMARY KEY AUTOINCREMENT,
    attachment_id INTEGER NOT NULL REFERENCES attachments(attachment_id) ON DELETE CASCADE,
    member_index INTEGER NOT NULL,
    member_name TEXT NOT NULL,
    compressed_size INTEGER,
    uncompressed_size INTEGER,
    encrypted INTEGER NOT NULL DEFAULT 0,
    suspicious_extension INTEGER NOT NULL DEFAULT 0,
    UNIQUE(attachment_id, member_index)
);

CREATE TABLE IF NOT EXISTS archive_inspections (
    attachment_id INTEGER PRIMARY KEY REFERENCES attachments(attachment_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    member_count INTEGER NOT NULL DEFAULT 0,
    total_member_count INTEGER,
    encrypted_member_count INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    error_detail TEXT,
    inspected_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS qr_results (
    qr_result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    attachment_id INTEGER REFERENCES attachments(attachment_id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL,
    page_number INTEGER,
    decoded_text TEXT NOT NULL,
    is_url INTEGER NOT NULL DEFAULT 0,
    normalized_url TEXT,
    created_utc TEXT NOT NULL,
    UNIQUE(message_sha256, attachment_id, source_kind, page_number, decoded_text)
);

CREATE TABLE IF NOT EXISTS urls (
    url_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
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
    effective_registrable_domain TEXT,
    is_sharepoint INTEGER NOT NULL DEFAULT 0,
    sharepoint_relationship TEXT,
    UNIQUE(message_sha256, source_part, raw_url, displayed_text)
);

CREATE TABLE IF NOT EXISTS scopes (
    scope_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    criteria_json TEXT NOT NULL,
    created_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_messages (
    scope_id INTEGER NOT NULL REFERENCES scopes(scope_id) ON DELETE CASCADE,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    PRIMARY KEY(scope_id, message_sha256)
);

CREATE TABLE IF NOT EXISTS errors (
    error_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT,
    message_sha256 TEXT,
    stage TEXT NOT NULL,
    error_type TEXT NOT NULL,
    error_detail TEXT NOT NULL,
    recorded_utc TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS phish_hunt_runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    run_name TEXT NOT NULL,
    config_name TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    config_json TEXT NOT NULL,
    selection_json TEXT NOT NULL,
    output_path TEXT NOT NULL,
    status TEXT NOT NULL,
    started_utc TEXT NOT NULL,
    completed_utc TEXT,
    message_count INTEGER NOT NULL DEFAULT 0,
    threadsaw_version TEXT NOT NULL,
    error_detail TEXT
);

CREATE TABLE IF NOT EXISTS phish_hunt_results (
    run_id TEXT NOT NULL REFERENCES phish_hunt_runs(run_id) ON DELETE CASCADE,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    positive_points INTEGER NOT NULL,
    negative_points INTEGER NOT NULL,
    evaluated_factor_count INTEGER NOT NULL,
    unknown_factor_count INTEGER NOT NULL,
    max_possible_points_evaluated INTEGER NOT NULL DEFAULT 0,
    unknown_positive_points INTEGER NOT NULL DEFAULT 0,
    positive_score_percent_evaluated REAL,
    top_score_reasons TEXT,
    PRIMARY KEY(run_id, message_sha256)
);

CREATE TABLE IF NOT EXISTS phish_hunt_factor_results (
    run_id TEXT NOT NULL REFERENCES phish_hunt_runs(run_id) ON DELETE CASCADE,
    message_sha256 TEXT NOT NULL REFERENCES messages(message_sha256) ON DELETE CASCADE,
    factor_id TEXT NOT NULL,
    answer TEXT NOT NULL,
    points INTEGER NOT NULL,
    weight INTEGER NOT NULL,
    effect_mode TEXT NOT NULL,
    evidence TEXT,
    source TEXT,
    status TEXT NOT NULL,
    reason TEXT,
    evaluator_version TEXT NOT NULL,
    PRIMARY KEY(run_id, message_sha256, factor_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_selected_date ON messages(selected_date_utc);
CREATE INDEX IF NOT EXISTS idx_messages_from_date ON messages(from_address,selected_date_utc);
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(internet_message_id);
CREATE INDEX IF NOT EXISTS idx_recipients_message_email ON recipients(message_sha256,email_address);
CREATE INDEX IF NOT EXISTS idx_recipients_email_message ON recipients(email_address,message_sha256);
CREATE INDEX IF NOT EXISTS idx_received_hops_message ON received_hops(message_sha256,hop_order);
CREATE INDEX IF NOT EXISTS idx_authentication_results_message ON authentication_results(message_sha256,trusted);
CREATE INDEX IF NOT EXISTS idx_sources_sha256 ON sources(sha256);
CREATE INDEX IF NOT EXISTS idx_urls_message_sha256 ON urls(message_sha256);
CREATE INDEX IF NOT EXISTS idx_urls_domain_message ON urls(registrable_domain,message_sha256);
CREATE INDEX IF NOT EXISTS idx_attachments_message_sha256 ON attachments(message_sha256);
CREATE INDEX IF NOT EXISTS idx_message_relationships_parent ON message_relationships(parent_message_sha256);
CREATE INDEX IF NOT EXISTS idx_message_relationships_child ON message_relationships(child_message_sha256);
CREATE INDEX IF NOT EXISTS idx_archive_members_attachment ON archive_members(attachment_id);
CREATE INDEX IF NOT EXISTS idx_archive_inspections_status ON archive_inspections(status);
CREATE INDEX IF NOT EXISTS idx_qr_results_message ON qr_results(message_sha256);
CREATE INDEX IF NOT EXISTS idx_phish_hunt_results_score ON phish_hunt_results(run_id,score);
CREATE INDEX IF NOT EXISTS idx_phish_hunt_runs_started ON phish_hunt_runs(started_utc);
"""


def _configure_connection(conn: sqlite3.Connection) -> None:
    """Apply the case-safe SQLite posture before any schema/query work."""
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    row = conn.execute("PRAGMA journal_mode = DELETE").fetchone()
    mode = str(row[0] if row else "").lower()
    if mode != "delete":
        raise RuntimeError(f"Could not place case database in DELETE journal mode (reported {mode or 'unknown'})")
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA temp_store = MEMORY")


def _open_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    try:
        _configure_connection(conn)
        return conn
    except Exception:
        conn.close()
        raise


def _copy_with_fsync(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("wb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())


def _recover_legacy_wal(db_path: Path) -> Path:
    """Recover/checkpoint a legacy WAL database on local storage, then replace it.

    This is only attempted after normal in-place journal conversion fails. The
    original database and any WAL/SHM sidecars are copied to a timestamped
    backup directory before replacement.
    """
    if not db_path.is_file():
        raise RuntimeError("Case database does not exist and cannot be recovered")

    case_dir = db_path.parent
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = case_dir / "logs" / "database-backups" / timestamp
    backup_dir.mkdir(parents=True, exist_ok=False)

    components = [db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")]
    existing = [path for path in components if path.exists()]
    for source in existing:
        shutil.copy2(source, backup_dir / source.name)

    try:
        with tempfile.TemporaryDirectory(prefix="threadsaw-db-recovery-") as temp:
            temp_dir = Path(temp)
            local_db = temp_dir / db_path.name
            for source in existing:
                shutil.copy2(source, temp_dir / source.name)

            conn = sqlite3.connect(local_db, timeout=BUSY_TIMEOUT_MS / 1000)
            try:
                conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
                # Opening the copied database on a native local filesystem lets
                # SQLite safely replay/checkpoint any uncommitted WAL frames.
                checkpoint = conn.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
                if checkpoint and int(checkpoint[0]) != 0:
                    raise RuntimeError(f"Legacy WAL checkpoint remained busy: {tuple(checkpoint)}")
                mode_row = conn.execute("PRAGMA journal_mode = DELETE").fetchone()
                mode = str(mode_row[0] if mode_row else "").lower()
                if mode != "delete":
                    raise RuntimeError(f"Recovered database remained in {mode or 'unknown'} journal mode")
                integrity = conn.execute("PRAGMA integrity_check").fetchone()
                integrity_value = str(integrity[0] if integrity else "unknown")
                if integrity_value.lower() != "ok":
                    raise RuntimeError(f"Recovered database failed integrity_check: {integrity_value}")
                conn.commit()
            finally:
                conn.close()

            replacement = case_dir / f".{db_path.name}.recovered-{os.getpid()}"
            _copy_with_fsync(local_db, replacement)
            os.replace(replacement, db_path)
            for sidecar in (Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")):
                try:
                    sidecar.unlink()
                except FileNotFoundError:
                    pass

        log = backup_dir / "recovery.txt"
        log.write_text(
            "Threadsaw automatically recovered a legacy SQLite WAL database, "
            "verified integrity, and converted it to DELETE journal mode.\n",
            encoding="utf-8",
        )
        return backup_dir
    except Exception as exc:
        raise RuntimeError(
            f"Automatic legacy-WAL recovery failed. Original files were preserved in {backup_dir}: {exc}"
        ) from exc


def connect_db(case_dir: Path) -> sqlite3.Connection:
    case_dir = case_dir.resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    db_path = case_dir / DB_FILENAME
    try:
        return _open_connection(db_path)
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        if db_path.exists() and "disk i/o" in message:
            _recover_legacy_wal(db_path)
            return _open_connection(db_path)
        if "locked" in message or "busy" in message:
            raise RuntimeError(
                "The case database is busy. Stop other Threadsaw containers or GUI operations and try again."
            ) from exc
        raise RuntimeError(
            f"The case database could not be opened safely at {db_path}: {exc}"
        ) from exc


LEGACY_IDENTIFIER_TABLES = (
    "messages",
    "message_sources",
    "recipients",
    "received_hops",
    "authentication_results",
    "attachments",
    "urls",
    "scope_messages",
    "errors",
)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if not exists:
        return set()
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate_legacy_identifier_columns(conn: sqlite3.Connection) -> None:
    """Rename the pre-0.1.1 branded identifier column without changing values."""
    migrations = [
        table
        for table in LEGACY_IDENTIFIER_TABLES
        if "threadsaw_id" in _table_columns(conn, table)
        and "message_sha256" not in _table_columns(conn, table)
    ]
    if not migrations:
        return
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        for table in migrations:
            conn.execute(f"ALTER TABLE {table} RENAME COLUMN threadsaw_id TO message_sha256")
        conn.commit()
    finally:
        conn.execute("PRAGMA foreign_keys = ON")


def _ensure_schema_columns(conn: sqlite3.Connection) -> None:
    """Add columns and deterministic indexes introduced after earlier releases."""
    from email.utils import parseaddr
    from .domains import registrable_domain

    source_columns = _table_columns(conn, "sources")
    if source_columns and "canonical_path" not in source_columns:
        conn.execute("ALTER TABLE sources ADD COLUMN canonical_path TEXT")

    message_columns = _table_columns(conn, "messages")
    added_url_columns = False
    for name, declaration in (
        ("url_count", "INTEGER NOT NULL DEFAULT 0"),
        ("url_indexed", "INTEGER NOT NULL DEFAULT 0"),
        ("from_address_normalized", "TEXT"),
        ("from_domain_registrable", "TEXT"),
        ("direction", "TEXT"),
        ("normalized_subject", "TEXT"),
    ):
        if message_columns and name not in message_columns:
            conn.execute(f"ALTER TABLE messages ADD COLUMN {name} {declaration}")
            if name in {"url_count", "url_indexed"}:
                added_url_columns = True

    attachment_columns = _table_columns(conn, "attachments")
    if attachment_columns and "is_inline" not in attachment_columns:
        conn.execute("ALTER TABLE attachments ADD COLUMN is_inline INTEGER NOT NULL DEFAULT 0")

    result_columns = _table_columns(conn, "phish_hunt_results")
    for name, declaration in (
        ("max_possible_points_evaluated", "INTEGER NOT NULL DEFAULT 0"),
        ("unknown_positive_points", "INTEGER NOT NULL DEFAULT 0"),
        ("positive_score_percent_evaluated", "REAL"),
    ):
        if result_columns and name not in result_columns:
            conn.execute(f"ALTER TABLE phish_hunt_results ADD COLUMN {name} {declaration}")

    if added_url_columns and _table_columns(conn, "urls"):
        conn.execute(
            """UPDATE messages
               SET url_count=(SELECT COUNT(*) FROM urls WHERE urls.message_sha256=messages.message_sha256),
                   url_indexed=1
               WHERE EXISTS(SELECT 1 FROM urls WHERE urls.message_sha256=messages.message_sha256)"""
        )

    # Normalize sender fields once so historical evaluators can use indexed SQL.
    for row in conn.execute(
        "SELECT message_sha256,from_address FROM messages "
        "WHERE from_address_normalized IS NULL OR from_domain_registrable IS NULL"
    ).fetchall():
        address = parseaddr(row["from_address"] or "")[1].strip().lower()
        domain = registrable_domain(address.rsplit("@", 1)[1]) if "@" in address else None
        conn.execute(
            "UPDATE messages SET from_address_normalized=?,from_domain_registrable=? WHERE message_sha256=?",
            (address or None, domain, row["message_sha256"]),
        )
    for row in conn.execute("SELECT message_sha256,subject FROM messages WHERE normalized_subject IS NULL").fetchall():
        subject = str(row["subject"] or "")
        subject = __import__("re").sub(r"^\s*(?:(?:re|fw|fwd|aw|sv)\s*:\s*)+", "", subject, flags=__import__("re").I)
        normalized = " ".join(subject.split()).casefold()
        conn.execute("UPDATE messages SET normalized_subject=? WHERE message_sha256=?", (normalized, row["message_sha256"]))

    # SQLite treats NULL values as distinct in UNIQUE constraints. Collapse old
    # duplicate URL rows and normalize displayed_text before adding an
    # expression index that treats NULL and empty text identically.
    if _table_columns(conn, "urls"):
        url_columns = _table_columns(conn, "urls")
        if "effective_registrable_domain" not in url_columns:
            conn.execute("ALTER TABLE urls ADD COLUMN effective_registrable_domain TEXT")
        conn.execute("UPDATE urls SET effective_registrable_domain=registrable_domain WHERE effective_registrable_domain IS NULL")
        conn.execute(
            """DELETE FROM urls WHERE url_id NOT IN (
                   SELECT MIN(url_id) FROM urls
                   GROUP BY message_sha256,source_part,raw_url,COALESCE(displayed_text,'')
               )"""
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_urls_dedup_display "
            "ON urls(message_sha256,source_part,raw_url,COALESCE(displayed_text,''))"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_urls_effective_domain_message "
            "ON urls(effective_registrable_domain,message_sha256)"
        )
        conn.execute(
            """UPDATE messages SET url_count=(
                   SELECT COUNT(*) FROM urls WHERE urls.message_sha256=messages.message_sha256
               ) WHERE url_indexed=1"""
        )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_normalized_from_date ON messages(from_address_normalized,selected_date_utc)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_from_domain_date ON messages(from_domain_registrable,selected_date_utc)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_normalized_subject_date ON messages(normalized_subject,selected_date_utc)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_recipients_email_message ON recipients(email_address,message_sha256)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_received_hops_trusted_message ON received_hops(trusted,message_sha256,hop_order)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_authserv_message ON authentication_results(authserv_id,message_sha256)")
    conn.commit()


def initialize_schema(conn: sqlite3.Connection) -> None:
    _migrate_legacy_identifier_columns(conn)
    conn.executescript(SCHEMA)
    _ensure_schema_columns(conn)
    conn.commit()


def database_health(conn: sqlite3.Connection) -> dict[str, str | bool]:
    journal = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
    integrity = str(conn.execute("PRAGMA quick_check").fetchone()[0])
    return {
        "journal_mode": journal,
        "integrity": integrity,
        "ready": journal == "delete" and integrity.lower() == "ok",
    }


def record_error(conn: sqlite3.Connection, *, source_path: str | None, message_sha256: str | None,
                 stage: str, error_type: str, error_detail: str, recorded_utc: str) -> None:
    conn.execute(
        "INSERT INTO errors(source_path,message_sha256,stage,error_type,error_detail,recorded_utc) VALUES(?,?,?,?,?,?)",
        (source_path, message_sha256, stage, error_type, error_detail, recorded_utc),
    )
    conn.commit()
