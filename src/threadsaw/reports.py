from __future__ import annotations

import json
from pathlib import Path
from email.utils import parseaddr
from typing import Any

from .ip_fields import SENDER_IP_FIELD_NAMES, enrich_sender_ip_rows
from .message_context import enrich_recipient_rows
from .util import atomic_write_csv, atomic_write_json, atomic_write_jsonl, chunked

MESSAGE_FIELDS = [
    "message_sha256", "internet_message_id", "selected_date_utc", "selected_date_source", "direction",
    "header_date_utc", "top_received_utc", "trusted_received_utc", "date_discrepancy_seconds",
    "from_address", "recipient_addresses", "from_domain", "reply_to", "reply_to_domain", "return_path", "return_path_domain",
    "from_reply_to_mismatch", "from_return_path_mismatch", "to_addresses", "cc_addresses", "bcc_addresses", "subject",
    *SENDER_IP_FIELD_NAMES,
    "spf_result", "dkim_result", "dmarc_result", "arc_result", "authserv_id", "auth_trusted",
    "attachment_count", "url_count", "url_indexed", "has_attachments", "body_text_source", "format", "derivation_status", "eml_path", "parse_defects",
]

ATTACHMENT_FIELDS = [
    "message_sha256", "sender_email", "recipient_addresses", "message_date_utc", "subject", *SENDER_IP_FIELD_NAMES,
    "part_index", "original_filename", "safe_filename", "content_type_declared", "content_disposition", "content_id", "is_inline",
    "size_bytes", "sha256", "md5", "executable_format", "artifact_path", "exported_path", "status",
]

ERROR_FIELDS = ["error_id", "source_path", "message_sha256", "stage", "error_type", "error_detail", "recorded_utc"]


def _domain(value: str | None) -> str | None:
    address = parseaddr(value or "")[1]
    return address.rsplit("@", 1)[1].lower() if "@" in address else None


def auth_summary_for_message(conn, message_sha256: str) -> dict[str, Any]:
    """Return the preferred recorded authentication-result row.

    Trusted configured authserv-id rows are preferred. When no row is marked
    trusted, the first recorded row is returned and remains explicitly labeled
    untrusted in exports.
    """
    rows = conn.execute(
        """SELECT authserv_id,spf_result,dkim_result,dmarc_result,arc_result,trusted
           FROM authentication_results
           WHERE message_sha256=? ORDER BY trusted DESC, auth_id""", (message_sha256,)
    ).fetchall()
    return dict(rows[0]) if rows else {}


def message_rows(conn, ids: list[str] | None = None) -> list[dict[str, Any]]:
    if ids is not None and not ids:
        return []
    if ids is None:
        rows = conn.execute("SELECT * FROM messages ORDER BY selected_date_utc,message_sha256").fetchall()
    else:
        rows = []
        for batch in chunked(ids):
            placeholders = ",".join("?" for _ in batch)
            rows.extend(conn.execute(
                f"SELECT * FROM messages WHERE message_sha256 IN ({placeholders})", batch
            ).fetchall())
        rows.sort(key=lambda item: (str(item["selected_date_utc"] or ""), str(item["message_sha256"])))

    # Load preferred authentication rows once instead of issuing one query per message.
    auth_by_message: dict[str, dict[str, Any]] = {}
    message_ids = [str(row["message_sha256"]) for row in rows]
    for batch in chunked(message_ids):
        placeholders = ",".join("?" for _ in batch)
        auth_rows = conn.execute(
            f"""SELECT message_sha256,authserv_id,spf_result,dkim_result,dmarc_result,arc_result,trusted,auth_id
                 FROM authentication_results WHERE message_sha256 IN ({placeholders})
                 ORDER BY message_sha256,trusted DESC,auth_id""", batch
        ).fetchall()
        for auth in auth_rows:
            auth_by_message.setdefault(str(auth["message_sha256"]), dict(auth))

    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item.pop("sender_ips_json", None)  # Legacy aggregate intentionally omitted from analyst CSVs.
        item["parse_defects"] = "; ".join(json.loads(item.pop("defects_json") or "[]"))
        item.pop("body_text", None)
        item.pop("body_html", None)
        from_domain = _domain(item.get("from_address"))
        reply_domain = _domain(item.get("reply_to"))
        return_domain = _domain(item.get("return_path"))
        item.update({
            "from_domain": from_domain,
            "reply_to_domain": reply_domain,
            "return_path_domain": return_domain,
            "from_reply_to_mismatch": bool(from_domain and reply_domain and from_domain != reply_domain),
            "from_return_path_mismatch": bool(from_domain and return_domain and from_domain != return_domain),
        })
        auth = auth_by_message.get(str(row["message_sha256"]), {})
        item.update({
            "spf_result": auth.get("spf_result"),
            "dkim_result": auth.get("dkim_result"),
            "dmarc_result": auth.get("dmarc_result"),
            "arc_result": auth.get("arc_result"),
            "authserv_id": auth.get("authserv_id"),
            "auth_trusted": auth.get("trusted"),
        })
        output.append(item)
    enrich_recipient_rows(conn, output)
    enrich_sender_ip_rows(conn, output)
    for item in output:
        item.pop("raw_headers_text", None)
    return output


def iter_message_rows(conn, ids: list[str] | None = None, *, batch_size: int = 500):
    """Yield analyst-facing message rows in bounded batches.

    This prevents full-case bodies and HTML from being materialized at once.
    """
    if ids is None:
        cursor = conn.execute("SELECT message_sha256 FROM messages ORDER BY selected_date_utc,message_sha256")
        batch: list[str] = []
        for row in cursor:
            batch.append(str(row["message_sha256"]))
            if len(batch) >= batch_size:
                yield from message_rows(conn, batch)
                batch.clear()
        if batch:
            yield from message_rows(conn, batch)
        return
    for batch in chunked(ids, batch_size):
        yield from message_rows(conn, batch)


def iter_attachment_rows(conn, ids: list[str] | None = None, *, batch_size: int = 500):
    if ids is None:
        ids = [str(r["message_sha256"]) for r in conn.execute("SELECT message_sha256 FROM messages ORDER BY message_sha256")]
    for batch in chunked(ids, batch_size):
        if not batch:
            continue
        placeholders = ",".join("?" for _ in batch)
        rows = [dict(r) for r in conn.execute(
            f"""SELECT a.*, m.from_address AS sender_email, m.selected_date_utc AS message_date_utc, m.subject
                FROM attachments a JOIN messages m ON m.message_sha256=a.message_sha256
                WHERE a.message_sha256 IN ({placeholders})
                ORDER BY a.message_sha256,a.part_index""", batch)]
        enrich_recipient_rows(conn, rows)
        enrich_sender_ip_rows(conn, rows)
        yield from rows


def write_reports(
    conn,
    output_dir: Path,
    ids: list[str] | None = None,
    *,
    large_case: bool = False,
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    messages_csv = output_dir / "messages.csv"
    atomic_write_csv(messages_csv, MESSAGE_FIELDS, iter_message_rows(conn, ids))

    result: dict[str, Path] = {"messages_csv": messages_csv}
    if large_case:
        messages_jsonl = output_dir / "messages.jsonl"
        atomic_write_jsonl(messages_jsonl, iter_message_rows(conn, ids))
        result["messages_jsonl"] = messages_jsonl
    else:
        messages_json = output_dir / "messages.json"
        atomic_write_json(messages_json, list(iter_message_rows(conn, ids)))
        result["messages_json"] = messages_json

    attachment_csv = output_dir / "attachments.csv"
    atomic_write_csv(attachment_csv, ATTACHMENT_FIELDS, iter_attachment_rows(conn, ids))
    result["attachments_csv"] = attachment_csv

    errors_csv = output_dir / "errors.csv"
    if ids is None:
        error_rows = (dict(r) for r in conn.execute("SELECT * FROM errors ORDER BY error_id"))
    elif not ids:
        error_rows = iter(())
    else:
        def _errors():
            for batch in chunked(ids):
                placeholders = ",".join("?" for _ in batch)
                yield from (dict(r) for r in conn.execute(
                    f"SELECT * FROM errors WHERE message_sha256 IN ({placeholders}) ORDER BY error_id", batch))
        error_rows = _errors()
    atomic_write_csv(errors_csv, ERROR_FIELDS, error_rows)
    result["errors_csv"] = errors_csv
    return result


def write_timestamped_reports(
    conn, output_base: Path, ids: list[str] | None = None, *, large_case: bool = False
) -> dict[str, Path | str]:
    """Write a complete core-report set into a completion-timestamped folder."""
    from .output_naming import cleanup_staging, completion_timestamp, finalize_directory, staging_directory

    output_base = Path(output_base)
    stage: Path | None = staging_directory(output_base)
    try:
        paths = write_reports(conn, stage, ids, large_case=large_case)
        stamp = completion_timestamp()
        final_dir = finalize_directory(stage, output_base, stamp)
        stage = None
        remapped: dict[str, Path | str] = {
            key: final_dir / Path(path).name for key, path in paths.items()
        }
        remapped["output_directory"] = final_dir
        remapped["completion_timestamp"] = stamp
        return remapped
    finally:
        cleanup_staging(stage)
