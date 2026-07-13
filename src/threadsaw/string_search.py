from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .output_naming import cleanup_staging, completion_timestamp, finalize_directory, staging_directory
from .selection import resolve_message_hashes
from .util import atomic_write_csv, atomic_write_json, utc_now

SEARCH_FIELDS = [
    "source_kind",
    "source_name",
    "row_identifier",
    "message_sha256",
    "field_name",
    "line_number",
    "matched_value",
    "context",
    "date_filter_applied",
]

REPORT_SUFFIXES = {".csv", ".json", ".txt", ".md", ".log"}


def _literal_match(value: Any, needle: str) -> bool:
    if value is None:
        return False
    return needle in str(value).casefold()


def _short(value: Any, limit: int = 1000) -> str:
    text = str(value if value is not None else "")
    return text if len(text) <= limit else text[:limit] + "…"


def _table_names(conn) -> list[str]:
    return [
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def _table_info(conn, table: str) -> list[Any]:
    escaped = table.replace('"', '""')
    return list(conn.execute(f'PRAGMA table_info("{escaped}")'))


def _row_identifier(row: Any, pk_columns: list[str]) -> str:
    if pk_columns:
        return "; ".join(f"{name}={row[name]}" for name in pk_columns)
    if "message_sha256" in row.keys():
        return f"message_sha256={row['message_sha256']}"
    return ""


def search_sqlite(
    conn,
    query: str,
    *,
    start: str | None = None,
    end: str | None = None,
) -> list[dict[str, Any]]:
    """Search every SQLite field for a case-insensitive literal occurrence.

    A date range constrains message-associated tables through message_sha256.
    Tables that do not have a message relationship remain searchable and are
    explicitly labeled as not date-filtered in the output.
    """
    needle = query.casefold()
    if not needle:
        raise ValueError("Search string must not be blank")
    selected_ids: list[str] | None = None
    if start or end:
        selected_ids = resolve_message_hashes(conn, start=start, end=end)
    selected_set = set(selected_ids or [])

    results: list[dict[str, Any]] = []
    for table in _table_names(conn):
        info = _table_info(conn, table)
        columns = [str(row[1]) for row in info]
        if not columns:
            continue
        pk_columns = [str(row[1]) for row in sorted(info, key=lambda item: int(item[5])) if int(row[5]) > 0]
        escaped = table.replace('"', '""')
        parameters: list[Any] = []
        date_filter_applied = False
        if selected_ids is not None and "message_sha256" in columns:
            date_filter_applied = True
            if not selected_ids:
                continue
            placeholders = ",".join("?" for _ in selected_ids)
            sql = f'SELECT * FROM "{escaped}" WHERE message_sha256 IN ({placeholders})'
            parameters.extend(selected_ids)
        else:
            sql = f'SELECT * FROM "{escaped}"'
        cursor = conn.execute(sql, parameters)
        while True:
            rows = cursor.fetchmany(500)
            if not rows:
                break
            for row in rows:
                message_sha256 = str(row["message_sha256"] or "") if "message_sha256" in row.keys() else ""
                # Defensive check for views/tables that may expose message_sha256
                # after selection was computed but were not constrained above.
                if selected_ids is not None and message_sha256 and message_sha256 not in selected_set:
                    continue
                identifier = _row_identifier(row, pk_columns)
                for column in columns:
                    value = row[column]
                    if _literal_match(value, needle):
                        results.append(
                            {
                                "source_kind": "sqlite",
                                "source_name": table,
                                "row_identifier": identifier,
                                "message_sha256": message_sha256,
                                "field_name": column,
                                "line_number": "",
                                "matched_value": _short(value),
                                "context": "",
                                "date_filter_applied": "yes" if date_filter_applied else "no",
                            }
                        )
    return results


def _iter_text_files(root: Path, suffixes: set[str]) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in suffixes:
            yield root
        return
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in suffixes and ".in-progress-" not in path.name:
            yield path


def search_text_tree(root: Path, query: str, *, source_kind: str, suffixes: set[str]) -> list[dict[str, Any]]:
    needle = query.casefold()
    results: list[dict[str, Any]] = []
    for path in _iter_text_files(root, suffixes):
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            results.append(
                {
                    "source_kind": source_kind,
                    "source_name": str(path),
                    "row_identifier": "",
                    "message_sha256": "",
                    "field_name": "read_error",
                    "line_number": "",
                    "matched_value": "",
                    "context": f"{type(exc).__name__}: {exc}",
                    "date_filter_applied": "no",
                }
            )
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if needle in line.casefold():
                results.append(
                    {
                        "source_kind": source_kind,
                        "source_name": str(path),
                        "row_identifier": "",
                        "message_sha256": "",
                        "field_name": "text",
                        "line_number": number,
                        "matched_value": _short(line),
                        "context": "",
                        "date_filter_applied": "no",
                    }
                )
    return results


def run_string_search(
    conn,
    case_dir: Path,
    *,
    query: str,
    search_database: bool,
    exported_text_dir: Path | None,
    search_reports: bool,
    start: str | None,
    end: str | None,
    output_root: Path,
) -> dict[str, Any]:
    if not any((search_database, exported_text_dir is not None, search_reports)):
        raise ValueError("Select at least one search location")
    if bool(start) != bool(end):
        raise ValueError("SQLite date filtering requires both --start and --end")
    query = query.strip()
    if not query:
        raise ValueError("Search string must not be blank")

    rows: list[dict[str, Any]] = []
    if search_database:
        rows.extend(search_sqlite(conn, query, start=start, end=end))
    if exported_text_dir is not None:
        rows.extend(search_text_tree(exported_text_dir, query, source_kind="exported-message-text", suffixes={".txt"}))
    if search_reports:
        rows.extend(search_text_tree(case_dir / "reports", query, source_kind="report", suffixes=REPORT_SUFFIXES))

    base = output_root / "string-search"
    stage: Path | None = staging_directory(base)
    try:
        atomic_write_csv(stage / "string_search.csv", SEARCH_FIELDS, rows)
        atomic_write_json(stage / "string_search.json", rows)
        stamp = completion_timestamp()
        manifest = {
            "project": "Threadsaw",
            "module": "string_search",
            "completed_utc": utc_now(),
            "completion_timestamp": stamp,
            "match_semantics": "case-insensitive literal substring; no regex, stemming, fuzzy matching, or network lookup",
            "query": query,
            "locations": {
                "sqlite_all_fields": search_database,
                "exported_message_text": str(exported_text_dir) if exported_text_dir else None,
                "reports": search_reports,
            },
            "sqlite_date_range": {
                "start": start,
                "end": end,
                "applies_only_to_message-associated SQLite rows": True,
            },
            "match_count": len(rows),
        }
        atomic_write_json(stage / "run_manifest.json", manifest)
        final_dir = finalize_directory(stage, base, stamp)
        stage = None
        return {
            "query": query,
            "matches": len(rows),
            "run_directory": str(final_dir),
            "csv": str(final_dir / "string_search.csv"),
            "json": str(final_dir / "string_search.json"),
            "manifest": str(final_dir / "run_manifest.json"),
        }
    finally:
        cleanup_staging(stage)
