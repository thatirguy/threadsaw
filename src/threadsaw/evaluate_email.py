from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .case import initialize_case, load_case, update_case
from .case_context import recompute_case_context, filter_config_for_available_context
from .db import connect_db, initialize_schema
from .factor_catalog import FACTOR_BY_ID, FACTOR_CATALOG
from .ingest import ingest_path
from .output_naming import cleanup_staging, completion_timestamp, finalize_directory, staging_directory
from .phish_hunt import all_factor_config, config_hash, evaluate_message, normalize_config
from .reports import MESSAGE_FIELDS, message_rows
from .util import atomic_write_csv, atomic_write_json, atomic_write_text, human_folder_name, utc_now
from .urls import extract_urls
from .security import install_runtime_guardrails
from .archive_inspection import inspect_zip_attachments

EVALUATION_PREFIX_FIELDS = [
    "selected_date_utc",
    "score",
    "from_address",
    "recipient_addresses",
    "subject",
    "message_sha256",
]
EVALUATION_FIELDS = EVALUATION_PREFIX_FIELDS + [
    field for field in MESSAGE_FIELDS if field not in EVALUATION_PREFIX_FIELDS
] + [
    "positive_points",
    "negative_points",
    "evaluated_factor_count",
    "unknown_factor_count",
    "max_possible_points_evaluated",
    "unknown_positive_points",
    "positive_score_percent_evaluated",
    "evaluation_mode",
    "case_history_enabled",
]
EVALUATION_DETAIL_FIELDS = [
    "message_sha256",
    "factor_id",
    "factor_label",
    "category",
    "subcategory",
    "computational_load",
    "requires_case_history",
    "answer",
    "points",
    "weight",
    "effect_mode",
    "evidence",
    "source",
    "status",
    "reason",
    "evaluator_version",
]


def _lookup_source_message_hash(conn, source_path: Path) -> str:
    row = conn.execute(
        """SELECT ms.message_sha256
           FROM sources s JOIN message_sources ms ON ms.source_id=s.source_id
           WHERE s.source_path=? ORDER BY s.source_id DESC LIMIT 1""",
        (str(source_path.resolve()),),
    ).fetchone()
    if not row:
        raise RuntimeError("The supplied email was parsed, but its indexed message identifier could not be located")
    return str(row["message_sha256"])


def _prepare_temp_case(source_case: Path, *, clone_database: bool) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    holder = tempfile.TemporaryDirectory(prefix="threadsaw-evaluate-")
    temp_case = Path(holder.name) / "case"
    source_data = load_case(source_case)
    temp_data = initialize_case(temp_case)
    temp_data["config"] = dict(source_data.get("config") or {})
    temp_data["evaluation_source_case_id"] = source_data.get("case_id")
    update_case(temp_case, temp_data)
    if clone_database:
        source_conn = connect_db(source_case)
        destination_conn = connect_db(temp_case)
        try:
            source_conn.backup(destination_conn)
            initialize_schema(destination_conn)
        finally:
            source_conn.close()
            destination_conn.close()
    return holder, temp_case


def _parse_external_in_temp(source_case: Path, email_path: Path, *, clone_database: bool) -> tuple[Any, Path, str]:
    holder, temp_case = _prepare_temp_case(source_case, clone_database=clone_database)
    # Keep the TemporaryDirectory object alive by attaching it to the returned
    # connection. sqlite3.Connection objects do not allow arbitrary attrs, so
    # the caller receives the holder separately via a module-level wrapper.
    ingest_path(email_path, temp_case, recursive=False, progress=lambda _message: None)
    conn = connect_db(temp_case)
    message_hash = _lookup_source_message_hash(conn, email_path)
    return (holder, conn), temp_case, message_hash


def _matched_config(details: list[dict[str, Any]], *, subject: str | None, message_sha256: str) -> dict[str, Any]:
    hit_ids = [row["factor_id"] for row in details if row.get("answer") == "YES"]
    return {
        "config_version": 1,
        "name": f"Evaluate Email hits - {human_folder_name(subject, message_sha256[:12], max_length=60)}",
        "preset": "evaluate-email-hits",
        "generated_from_message_sha256": message_sha256,
        "generated_utc": utc_now(),
        "weighting_note": (
            "Each matched factor is assigned a starter weight of 10 and risk_when_yes. "
            "Review every factor, weight, effect direction, and parameter before using this configuration as a hunt."
        ),
        "factors": [
            {
                "factor_id": factor_id,
                "enabled": True,
                "weight": 10,
                "effect_mode": "risk_when_yes",
                "parameters": {
                    p["name"]: p.get("default", "")
                    for p in FACTOR_BY_ID[factor_id].get("parameters", [])
                },
            }
            for factor_id in hit_ids
        ],
    }


def _friendly_hit_report(report_row: dict[str, Any], details: list[dict[str, Any]]) -> str:
    hits = [row for row in details if row.get("answer") == "YES"]
    hits.sort(key=lambda row: (abs(int(row.get("points") or 0)), str(row.get("factor_label") or "")), reverse=True)
    lines = [
        "THREADSAW — PHISHING EMAIL EVALUATION",
        "=" * 44,
        "",
        f"Message SHA-256: {report_row.get('message_sha256', '')}",
        f"Subject: {report_row.get('subject') or '(no subject)'}",
        f"From: {report_row.get('from_address') or '(unknown)'}",
        f"Selected date: {report_row.get('selected_date_utc') or '(unknown)'}",
        f"Evaluation mode: {report_row.get('evaluation_mode', '')}",
        f"Overall score: {report_row.get('score', 0)}",
        f"Factors that hit: {len(hits)}",
        "",
        "The higher the score, the more closely this message matches the configured phishing indicators.",
        "A hit is an investigative indicator, not a final determination that the message is malicious.",
        "",
        "FACTORS THAT HIT",
        "-" * 44,
    ]
    if not hits:
        lines.append("No enabled factor returned YES.")
    for index, row in enumerate(hits, start=1):
        lines.extend([
            "",
            f"{index}. {row.get('factor_label') or row.get('factor_id')}",
            f"   Factor ID: {row.get('factor_id', '')}",
            f"   Category: {row.get('category', '')} / {row.get('subcategory', '')}",
            f"   Score contribution: {int(row.get('points') or 0):+d}",
            f"   Why it hit: {row.get('reason') or 'The evaluator returned YES.'}",
            f"   Evidence: {row.get('evidence') or '(none recorded)'}",
            f"   Data source: {row.get('source') or '(not specified)'}",
        ])
    unknown = [row for row in details if row.get("answer") not in {"YES", "NO"}]
    if unknown:
        lines.extend(["", "UNAVAILABLE OR INCONCLUSIVE FACTORS", "-" * 44])
        for row in unknown:
            lines.append(f"- {row.get('factor_label')}: {row.get('answer')} — {row.get('reason') or row.get('status')}")
    lines.extend([
        "",
        "SECURITY NOTE",
        "-" * 44,
        "Threadsaw performed static local analysis only. It did not follow URLs, connect to hosts,",
        "or open or execute attachments.",
        "",
    ])
    return "\n".join(lines)


def evaluate_phishing_email(
    case_conn,
    case_dir: Path,
    *,
    message_sha256: str | None,
    email_path: Path | None,
    allow_case_history_override: bool,
    output_root: Path,
) -> dict[str, Any]:
    install_runtime_guardrails()
    if bool(message_sha256) == bool(email_path):
        raise ValueError("Choose exactly one input: an existing --sha256 or a new --email-file")

    case_data = load_case(case_dir)
    evaluation_conn = case_conn
    evaluation_case_dir = case_dir
    temp_holder: tempfile.TemporaryDirectory[str] | None = None
    temp_conn = None
    mode: str
    allow_case_history: bool

    try:
        if message_sha256:
            value = message_sha256.strip().lower()
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("--sha256 must be a 64-character hexadecimal message SHA-256")
            message = case_conn.execute("SELECT * FROM messages WHERE message_sha256=?", (value,)).fetchone()
            if not message:
                raise ValueError("The specified message SHA-256 is not present in the selected case")
            resolved_hash = value
            mode = "existing-case-message"
            allow_case_history = True
        else:
            assert email_path is not None
            email_path = email_path.resolve()
            if email_path.suffix.lower() not in {".eml", ".msg"}:
                raise ValueError("Evaluate Phishing Email accepts only EML or MSG files")
            if not email_path.is_file():
                raise FileNotFoundError(f"Email file does not exist: {email_path}")

            parsed_context, parsed_temp_case, parsed_hash = _parse_external_in_temp(case_dir, email_path, clone_database=False)
            temp_holder, temp_conn = parsed_context
            existing = case_conn.execute("SELECT * FROM messages WHERE message_sha256=?", (parsed_hash,)).fetchone()
            if existing:
                resolved_hash = parsed_hash
                message = existing
                mode = "external-file-matched-existing-case"
                allow_case_history = True
                temp_conn.close()
                temp_conn = None
                temp_holder.cleanup()
                temp_holder = None
            elif allow_case_history_override:
                temp_conn.close()
                temp_conn = None
                temp_holder.cleanup()
                temp_holder = None
                parsed_context, parsed_temp_case, parsed_hash = _parse_external_in_temp(case_dir, email_path, clone_database=True)
                temp_holder, temp_conn = parsed_context
                evaluation_conn = temp_conn
                evaluation_case_dir = parsed_temp_case
                resolved_hash = parsed_hash
                message = evaluation_conn.execute("SELECT * FROM messages WHERE message_sha256=?", (resolved_hash,)).fetchone()
                if not message:
                    raise RuntimeError("The external email could not be found in the temporary case-aware evaluation database")
                mode = "external-file-case-history-override"
                allow_case_history = True
            else:
                evaluation_conn = temp_conn
                evaluation_case_dir = parsed_temp_case
                resolved_hash = parsed_hash
                message = evaluation_conn.execute("SELECT * FROM messages WHERE message_sha256=?", (resolved_hash,)).fetchone()
                if not message:
                    raise RuntimeError("The external email could not be found in the temporary standalone evaluation database")
                mode = "external-file-standalone"
                allow_case_history = False

        # Ensure URL-dependent standalone factors have locally extracted URL
        # records. This is deterministic string parsing only and never follows
        # or retrieves any URL.
        extract_urls(evaluation_conn, evaluation_case_dir, [resolved_hash], progress=lambda _message: None)
        archive_inventory = inspect_zip_attachments(
            evaluation_conn,
            [resolved_hash],
            progress=lambda _message: None,
        )
        # URL indexing updates url_count/url_indexed in SQLite. Reload the row so
        # URL-dependent evaluators see the completed indexing state.
        message = evaluation_conn.execute(
            "SELECT * FROM messages WHERE message_sha256=?", (resolved_hash,)
        ).fetchone()
        if not message:
            raise RuntimeError("The evaluated message disappeared from the temporary or selected case")

        inferred_context = recompute_case_context(evaluation_conn, evaluation_case_dir)
        requested_config = normalize_config(all_factor_config())
        config, context_removed_factors = filter_config_for_available_context(requested_config, inferred_context)
        summary, details = evaluate_message(
            evaluation_conn,
            message,
            config,
            allow_case_history=allow_case_history,
        )
        for row in details:
            metadata = FACTOR_BY_ID[row["factor_id"]]
            row.update(
                {
                    "category": metadata.get("top_category", ""),
                    "subcategory": metadata.get("subcategory", ""),
                    "computational_load": metadata.get("load", ""),
                    "requires_case_history": "yes" if metadata.get("requires_case_history") else "no",
                }
            )

        base_rows = message_rows(evaluation_conn, [resolved_hash])
        if not base_rows:
            raise RuntimeError("The evaluated message could not be rendered into the summary report")
        report_row = {
            **base_rows[0],
            **summary,
            "evaluation_mode": mode,
            "case_history_enabled": "yes" if allow_case_history else "no",
        }
        hit_config = _matched_config(details, subject=message["subject"], message_sha256=resolved_hash)

        base = output_root / "evaluate-phishing-email"
        stage: Path | None = staging_directory(base)
        try:
            atomic_write_csv(stage / "evaluation.csv", EVALUATION_FIELDS, [report_row])
            atomic_write_csv(stage / "evaluation_details.csv", EVALUATION_DETAIL_FIELDS, details)
            atomic_write_json(stage / "evaluation.json", {"summary": report_row, "factors": details})
            atomic_write_json(stage / "matched_factors_config.json", hit_config)
            atomic_write_text(stage / "evaluation_hits.txt", _friendly_hit_report(report_row, details))
            stamp = completion_timestamp()
            manifest = {
                "project": "Threadsaw",
                "module": "evaluate_phishing_email",
                "threadsaw_version": __version__,
                "case_id": case_data.get("case_id"),
                "completed_utc": utc_now(),
                "completion_timestamp": stamp,
                "evaluation_mode": mode,
                "message_sha256": resolved_hash,
                "case_history_enabled": allow_case_history,
                "factor_count": len(details),
                "yes_factor_count": sum(row["answer"] == "YES" for row in details),
                "unknown_or_unavailable_count": sum(row["answer"] not in {"YES", "NO"} for row in details),
                "catalog_config_hash": config_hash(config),
                "inferred_case_context": inferred_context,
                "context_dependent_factors_removed": context_removed_factors,
                "archive_inventory": archive_inventory,
                "matched_config_note": hit_config["weighting_note"],
                "security": (
                    "Static local evaluation only. Threadsaw did not follow URLs, connect to IP addresses, "
                    "or open/execute attachments."
                ),
            }
            atomic_write_json(stage / "run_manifest.json", manifest)
            final_dir = finalize_directory(stage, base, stamp)
            stage = None
            return {
                "message_sha256": resolved_hash,
                "evaluation_mode": mode,
                "case_history_enabled": allow_case_history,
                "score": summary["score"],
                "yes_factors": manifest["yes_factor_count"],
                "run_directory": str(final_dir),
                "summary_report": str(final_dir / "evaluation.csv"),
                "details_report": str(final_dir / "evaluation_details.csv"),
                "matched_config": str(final_dir / "matched_factors_config.json"),
                "friendly_report": str(final_dir / "evaluation_hits.txt"),
                "manifest": str(final_dir / "run_manifest.json"),
            }
        finally:
            cleanup_staging(stage)
    finally:
        if temp_conn is not None:
            temp_conn.close()
        if temp_holder is not None:
            temp_holder.cleanup()
