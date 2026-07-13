from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .util import chunked


def _unique_addresses(rows: Iterable[Any]) -> list[str]:
    """Return recipient addresses once, preserving their recorded order."""
    seen: set[str] = set()
    values: list[str] = []
    for row in rows:
        value = str(row["email_address"] or "").strip()
        key = value.casefold()
        if not value or key in seen:
            continue
        seen.add(key)
        values.append(value)
    return values


def recipient_fields(conn, message_sha256: str) -> dict[str, str]:
    """Return analyst-friendly recipient fields for one indexed message."""
    rows = conn.execute(
        """SELECT recipient_type,email_address FROM recipients
           WHERE message_sha256=? ORDER BY recipient_id""",
        (message_sha256,),
    ).fetchall()
    by_type = {
        kind: _unique_addresses(row for row in rows if row["recipient_type"] == kind)
        for kind in ("to", "cc", "bcc")
    }
    all_values = _unique_addresses(rows)
    return {
        "recipient_addresses": "; ".join(all_values),
        "to_addresses": "; ".join(by_type["to"]),
        "cc_addresses": "; ".join(by_type["cc"]),
        "bcc_addresses": "; ".join(by_type["bcc"]),
    }


def enrich_recipient_rows(conn, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add recipient address fields to report rows without altering evidence."""
    if not rows:
        return rows
    message_ids = list(dict.fromkeys(str(row["message_sha256"]) for row in rows if row.get("message_sha256")))
    if not message_ids:
        return rows
    recipient_rows = []
    for batch in chunked(message_ids):
        placeholders = ",".join("?" for _ in batch)
        recipient_rows.extend(conn.execute(
            f"""SELECT message_sha256,recipient_type,email_address,recipient_id
                FROM recipients WHERE message_sha256 IN ({placeholders})
                ORDER BY message_sha256,recipient_id""",
            batch,
        ).fetchall())
    recipient_rows.sort(key=lambda item: (str(item["message_sha256"]), int(item["recipient_id"])))
    grouped: dict[str, list[Any]] = {message_id: [] for message_id in message_ids}
    for recipient in recipient_rows:
        grouped.setdefault(str(recipient["message_sha256"]), []).append(recipient)

    for row in rows:
        message_sha256 = str(row.get("message_sha256") or "")
        recipients = grouped.get(message_sha256, [])
        by_type = {
            kind: _unique_addresses(item for item in recipients if item["recipient_type"] == kind)
            for kind in ("to", "cc", "bcc")
        }
        row["recipient_addresses"] = "; ".join(_unique_addresses(recipients))
        row["to_addresses"] = "; ".join(by_type["to"])
        row["cc_addresses"] = "; ".join(by_type["cc"])
        row["bcc_addresses"] = "; ".join(by_type["bcc"])
    return rows
