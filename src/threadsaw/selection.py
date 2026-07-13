from __future__ import annotations

import csv
import json
from pathlib import Path

from .util import chunked, parse_iso8601, utc_now, iso_utc


def read_message_hashes_csv(path: Path) -> list[str]:
    """Read message SHA-256 values from a named column or a one-column CSV."""
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return []
        normalized = {name.lower().strip(): name for name in reader.fieldnames}
        column = next((normalized[name] for name in ("message_sha256", "sha256") if name in normalized), None)
        if column is None:
            if len(reader.fieldnames) == 1:
                column = reader.fieldnames[0]
            else:
                raise ValueError("SHA-256 CSV must contain message_sha256 or sha256, or have exactly one column")
        values = [row[column].strip().lower() for row in reader if row.get(column, "").strip()]
    invalid = [value for value in values if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)]
    if invalid:
        raise ValueError(f"SHA-256 CSV contains {len(invalid)} invalid value(s)")
    return values


def resolve_message_hashes(
    conn,
    *,
    one_sha256: str | None = None,
    sha256_csv: Path | None = None,
    start: str | None = None,
    end: str | None = None,
    scope: str | None = None,
    all_messages: bool = False,
) -> list[str]:
    selectors = sum(bool(v) for v in (one_sha256, sha256_csv, scope, start or end, all_messages))
    if selectors != 1:
        raise ValueError("Choose exactly one selector: --sha256, --sha256-csv, --scope, --start/--end, or --all")
    if one_sha256:
        value = one_sha256.strip().lower()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError("--sha256 must be a 64-character hexadecimal SHA-256 value")
        rows = conn.execute("SELECT message_sha256 FROM messages WHERE message_sha256=?", (value,)).fetchall()
    elif sha256_csv:
        wanted = read_message_hashes_csv(sha256_csv)
        if not wanted:
            return []
        rows = []
        for batch in chunked(wanted):
            placeholders = ",".join("?" for _ in batch)
            rows.extend(conn.execute(
                f"SELECT message_sha256 FROM messages WHERE message_sha256 IN ({placeholders})", batch
            ).fetchall())
    elif scope:
        rows = conn.execute(
            """SELECT sm.message_sha256 FROM scope_messages sm JOIN scopes s ON s.scope_id=sm.scope_id
               WHERE s.name=? ORDER BY sm.message_sha256""",
            (scope,),
        ).fetchall()
    elif start or end:
        if not start or not end:
            raise ValueError("Date selection requires both --start and --end")
        start_utc = iso_utc(parse_iso8601(start))
        end_utc = iso_utc(parse_iso8601(end))
        if start_utc >= end_utc:
            raise ValueError("--start must be earlier than --end")
        rows = conn.execute(
            """SELECT message_sha256 FROM messages WHERE selected_date_utc >= ? AND selected_date_utc < ?
               ORDER BY selected_date_utc, message_sha256""",
            (start_utc, end_utc),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT message_sha256 FROM messages ORDER BY selected_date_utc, message_sha256"
        ).fetchall()
    return [row["message_sha256"] for row in rows]


def create_scope(conn, *, name: str, start: str, end: str) -> int:
    hashes = resolve_message_hashes(conn, start=start, end=end)
    criteria = {
        "type": "date-range",
        "start": start,
        "end": end,
        "semantics": "start-inclusive/end-exclusive",
    }
    cursor = conn.execute(
        "INSERT INTO scopes(name,criteria_json,created_utc) VALUES(?,?,?)",
        (name, json.dumps(criteria), utc_now()),
    )
    scope_id = int(cursor.lastrowid)
    conn.executemany(
        "INSERT INTO scope_messages(scope_id,message_sha256) VALUES(?,?)",
        ((scope_id, value) for value in hashes),
    )
    conn.commit()
    return len(hashes)
