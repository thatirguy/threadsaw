from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .reports import MESSAGE_FIELDS, auth_summary_for_message, message_rows
from .ip_fields import sender_ip_fields
from .message_context import recipient_fields
from .output_naming import cleanup_staging, completion_timestamp, finalize_directory, staging_directory
from .util import atomic_write_csv, atomic_write_json, atomic_write_text, human_folder_name, unique_path, utc_now


def _review_text(conn, message: Any) -> str:
    message_sha256 = message["message_sha256"]
    ip_fields = sender_ip_fields(conn, message_sha256, message["raw_headers_text"])
    auth_summary = auth_summary_for_message(conn, message_sha256)
    recipient_summary = recipient_fields(conn, message_sha256)

    def security_value(name: str) -> str:
        value = auth_summary.get(name)
        return str(value).upper() if value else "NOT RECORDED"
    recipients = conn.execute(
        "SELECT recipient_type,display_name,email_address FROM recipients WHERE message_sha256=? ORDER BY recipient_id",
        (message_sha256,),
    ).fetchall()
    attachments = conn.execute(
        """SELECT part_index,original_filename,content_type_declared,size_bytes,sha256,md5,content_disposition,
           content_id,executable_format,status FROM attachments WHERE message_sha256=? ORDER BY part_index""",
        (message_sha256,),
    ).fetchall()
    received = conn.execute(
        "SELECT hop_order,parsed_date_utc,trusted,raw_value FROM received_hops WHERE message_sha256=? ORDER BY hop_order",
        (message_sha256,),
    ).fetchall()
    auth = conn.execute(
        """SELECT authserv_id,spf_result,dkim_result,dmarc_result,arc_result,trusted,raw_value
           FROM authentication_results WHERE message_sha256=? ORDER BY auth_id""", (message_sha256,),
    ).fetchall()
    lines = [
        "THREADSAW MESSAGE REVIEW",
        "=" * 80,
        f"Message SHA-256: {message_sha256}",
        f"Format: {message['format']}",
        f"Derivation status: {message['derivation_status']}",
        f"RFC Message-ID: {message['internet_message_id'] or ''}",
        f"Subject: {message['subject'] or ''}",
        f"From: {message['from_address'] or ''}",
        f"Recipients: {recipient_summary['recipient_addresses']}",
        f"Reply-To: {message['reply_to'] or ''}",
        f"Return-Path: {message['return_path'] or ''}",
        f"Header Date (raw): {message['header_date_raw'] or ''}",
        f"Header Date (UTC): {message['header_date_utc'] or ''}",
        f"Top Received Date (UTC): {message['top_received_utc'] or ''}",
        f"Trusted Received Date (UTC): {message['trusted_received_utc'] or ''}",
        f"Selected Date (UTC): {message['selected_date_utc'] or ''}",
        f"Selected Date Source: {message['selected_date_source'] or ''}",
        f"Trusted Boundary IP: {ip_fields['trusted_boundary_ip']}",
        f"SPF Client IP: {ip_fields['spf_client_ip']}",
        f"Claimed Originating IP: {ip_fields['claimed_originating_ip']}",
        f"Topmost Received IP: {ip_fields['topmost_received_ip']}",
        f"Bottommost Received IP: {ip_fields['bottommost_received_ip']}",
        f"SPF Result: {security_value('spf_result')}",
        f"DKIM Result: {security_value('dkim_result')}",
        f"DMARC Result: {security_value('dmarc_result')}",
        f"ARC Result: {security_value('arc_result')}",
        f"Authentication Service: {auth_summary.get('authserv_id') or ''}",
        f"Authentication Result Trusted: {bool(auth_summary.get('trusted')) if auth_summary else ''}",
        "",
        "FULL HEADER BLOCK",
        "-" * 80,
        message["raw_headers_text"] or "[Header block unavailable]",
        "",
        "RECIPIENTS",
        "-" * 80,
    ]
    for item in recipients:
        display = f"{item['display_name']} <{item['email_address']}>" if item["display_name"] else item["email_address"]
        lines.append(f"{item['recipient_type'].upper()}: {display}")
    lines.extend(["", "AUTHENTICATION RESULTS", "-" * 80])
    if auth:
        for index, item in enumerate(auth, 1):
            lines.extend([
                f"[{index}] authserv-id={item['authserv_id'] or ''}; trusted={bool(item['trusted'])}",
                f"    SPF={item['spf_result'] or ''}; DKIM={item['dkim_result'] or ''}; DMARC={item['dmarc_result'] or ''}; ARC={item['arc_result'] or ''}",
                f"    Raw: {item['raw_value']}",
            ])
    else:
        lines.append("None recorded.")
    lines.extend(["", "RECEIVED HEADERS", "-" * 80])
    if received:
        for item in received:
            lines.extend([
                f"[{item['hop_order']}] date={item['parsed_date_utc'] or ''}; trusted={bool(item['trusted'])}",
                f"    {item['raw_value']}",
            ])
    else:
        lines.append("None recorded.")
    lines.extend(["", f"BODY TEXT (source: {message['body_text_source'] or 'unknown'})", "-" * 80, message["body_text"] or "[No body text extracted]"])
    if message["body_html"]:
        lines.extend(["", "HTML BODY (RAW)", "-" * 80, message["body_html"]])
    lines.extend(["", "ATTACHMENTS", "-" * 80])
    if attachments:
        for item in attachments:
            lines.extend([
                f"[{item['part_index']}] {item['original_filename'] or '[unnamed]'}",
                f"    MIME type: {item['content_type_declared'] or ''}",
                f"    Size: {item['size_bytes']} bytes",
                f"    SHA-256: {item['sha256']}",
                f"    MD5: {item['md5']}",
                f"    Disposition: {item['content_disposition'] or ''}",
                f"    Content-ID: {item['content_id'] or ''}",
                f"    Executable format: {item['executable_format'] or ''}",
                f"    Status: {item['status']}",
            ])
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def _existing_path(*values: str | None) -> Path | None:
    for value in values:
        if value:
            candidate = Path(value)
            if candidate.is_file():
                return candidate
    return None


def _message_eml_path(conn, message: Any) -> Path:
    direct = _existing_path(message["eml_path"])
    if direct:
        return direct
    rows = conn.execute(
        """SELECT s.source_type,s.source_path,s.canonical_path
           FROM sources s JOIN message_sources ms ON ms.source_id=s.source_id
           WHERE ms.message_sha256=? ORDER BY s.source_id""",
        (message["message_sha256"],),
    ).fetchall()
    for row in rows:
        if row["source_type"] == "EML":
            candidate = _existing_path(row["canonical_path"], row["source_path"])
            if candidate:
                return candidate
    raise FileNotFoundError(
        f"Indexed EML bytes are unavailable for {message['message_sha256']}. "
        "Re-ingest the source with Threadsaw 0.2.2 or later to create a self-contained case copy."
    )


def export_messages(conn, output_base: Path, ids: list[str]) -> dict[str, Any]:
    """Export one collision-safe, timestamped message package.

    ``output_base`` is a naming template such as ``exports/message-export``.
    The completed package is finalized as
    ``message-export_YYYYMMDDTHHMMSSZ``. Failed runs remain invisible as
    completed exports and their temporary staging directory is removed on a
    best-effort basis.
    """
    output_base = Path(output_base)
    output_stage: Path | None = staging_directory(output_base)
    started = utc_now()
    try:
        manifest: dict[str, Any] = {
            "created_utc": started,
            "selected_message_count": len(ids),
            "message_count": 0,
            "messages": [],
        }
        summary = message_rows(conn, ids)
        for message_sha256 in ids:
            message = conn.execute("SELECT * FROM messages WHERE message_sha256=?", (message_sha256,)).fetchone()
            if not message:
                continue
            base_name = human_folder_name(message["subject"], "No Subject")
            folder = unique_path(output_stage, base_name, is_directory=True)
            folder.mkdir(parents=True, exist_ok=False)
            src = _message_eml_path(conn, message)
            eml_name = "message.eml" if message["derivation_status"] != "derived-eml-from-msg" else "derived_message.eml"
            eml_dest = folder / eml_name
            shutil.copyfile(src, eml_dest)
            review_path = folder / "review.txt"
            atomic_write_text(review_path, _review_text(conn, message))
            source_rows = [dict(r) for r in conn.execute(
                """SELECT s.* FROM sources s JOIN message_sources ms ON ms.source_id=s.source_id
                   WHERE ms.message_sha256=? ORDER BY s.source_id""", (message_sha256,))]
            original_msg = None
            if message["format"] == "MSG":
                msg_source = next((r for r in source_rows if r["source_type"] == "MSG"), None)
                if msg_source:
                    msg_path = _existing_path(msg_source.get("canonical_path"), msg_source.get("source_path"))
                    if msg_path:
                        original_msg = folder / "original.msg"
                        shutil.copyfile(msg_path, original_msg)
            manifest["messages"].append({
                "message_sha256": message_sha256,
                "subject": message["subject"],
                "directory": folder.name,
                "eml_file": str(eml_dest.relative_to(output_stage)),
                "review_file": str(review_path.relative_to(output_stage)),
                "original_msg_file": str(original_msg.relative_to(output_stage)) if original_msg else None,
                "derivation_status": message["derivation_status"],
                "sources": source_rows,
            })
        manifest["message_count"] = len(manifest["messages"])
        atomic_write_csv(output_stage / "summary.csv", MESSAGE_FIELDS, summary)

        stamp = completion_timestamp()
        manifest["completed_utc"] = utc_now()
        manifest["completion_timestamp"] = stamp
        atomic_write_json(output_stage / "manifest.json", manifest)
        final_dir = finalize_directory(output_stage, output_base, stamp)
        output_stage = None
        manifest["output_directory"] = str(final_dir)
        manifest["summary_csv"] = str(final_dir / "summary.csv")
        manifest["manifest_json"] = str(final_dir / "manifest.json")
        return manifest
    finally:
        cleanup_staging(output_stage)

