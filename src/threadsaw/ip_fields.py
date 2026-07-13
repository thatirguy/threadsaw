"""Offline sender-IP classification helpers.

These helpers only parse header text already present in the case. They never
resolve, enrich, contact, or connect to any IP address, hostname, or URL.
"""
from __future__ import annotations

import ipaddress
import json
import re
from email import policy
from email.parser import Parser
from typing import Any, Iterable

IPV4_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")
CLIENT_IP_RE = re.compile(r"\bclient-ip\s*=\s*\[?([0-9A-Fa-f:.]+)\]?", re.I)
CLAIMED_ORIGIN_HEADERS = (
    "X-Originating-IP",
    "X-Original-Client-IP",
    "X-MS-Exchange-Organization-OriginalClientIPAddress",
    "X-MS-Exchange-Organization-OriginalClientIP",
    "X-MS-Exchange-Organization-ConnectingIP",
    "X-Client-IP",
    "X-Sender-IP",
)
SENDER_IP_FIELD_NAMES = (
    "trusted_boundary_ip",
    "spf_client_ip",
    "claimed_originating_ip",
    "topmost_received_ip",
    "bottommost_received_ip",
)


def _append_ip(output: list[str], candidate: str) -> None:
    value = candidate.strip().strip("[]()<>;,\"'")
    if value.lower().startswith("ipv6:"):
        value = value[5:]
    try:
        normalized = str(ipaddress.ip_address(value))
    except ValueError:
        return
    if normalized not in output:
        output.append(normalized)


def extract_ips(value: str | None) -> list[str]:
    """Extract unique literal IPv4/IPv6 addresses without network activity."""
    if not value:
        return []
    output: list[str] = []
    # Catch ordinary IPv4 even when punctuation is tightly attached.
    for match in IPV4_RE.findall(value):
        _append_ip(output, match)
    # Token parsing catches bracketed IPv6 and key=value forms.
    for token in re.split(r"[\s<>()\[\],;\"']+", value):
        candidate = token.rsplit("=", 1)[-1]
        _append_ip(output, candidate)
    return output


def received_sender_ips(raw_received: str | None) -> list[str]:
    """Return IP literals from the sending side of one Received field.

    A Received field normally describes ``from ... by ...``. Limiting parsing
    to the portion before the first ``by`` avoids treating the recipient-side
    server address as another sender address.
    """
    if not raw_received:
        return []
    sender_side = re.split(r"\s+by\s+", raw_received, maxsplit=1, flags=re.I)[0]
    return extract_ips(sender_side)


def _join(values: Iterable[str]) -> str:
    unique: list[str] = []
    for value in values:
        if value and value not in unique:
            unique.append(value)
    return "; ".join(unique)


def _parse_headers(raw_headers_text: str | None):
    if not raw_headers_text:
        return None
    try:
        return Parser(policy=policy.default).parsestr(raw_headers_text + "\n\n", headersonly=True)
    except Exception:
        return None


def _client_ips(raw_values: Iterable[str]) -> list[str]:
    output: list[str] = []
    for raw in raw_values:
        for match in CLIENT_IP_RE.findall(raw or ""):
            _append_ip(output, match)
    return output


def sender_ip_fields(conn, message_sha256: str, raw_headers_text: str | None = None) -> dict[str, str]:
    """Classify sender-IP values for one indexed message.

    Empty strings are returned when a type is unavailable. The values are
    evidence labels, not attribution conclusions.
    """
    hops = conn.execute(
        "SELECT hop_order,raw_value,sender_ips_json,trusted FROM received_hops "
        "WHERE message_sha256=? ORDER BY hop_order",
        (message_sha256,),
    ).fetchall()

    hop_ips: list[list[str]] = []
    trusted_boundary: list[str] = []
    for hop in hops:
        parsed = received_sender_ips(hop["raw_value"])
        if not parsed:
            try:
                parsed = [str(ipaddress.ip_address(item)) for item in json.loads(hop["sender_ips_json"] or "[]")]
            except (ValueError, TypeError, json.JSONDecodeError):
                parsed = []
        hop_ips.append(parsed)
        if bool(hop["trusted"]) and not trusted_boundary and parsed:
            trusted_boundary = parsed

    if raw_headers_text is None:
        row = conn.execute(
            "SELECT raw_headers_text FROM messages WHERE message_sha256=?",
            (message_sha256,),
        ).fetchone()
        raw_headers_text = row["raw_headers_text"] if row else None
    headers = _parse_headers(raw_headers_text)

    auth_rows = conn.execute(
        "SELECT raw_value,trusted FROM authentication_results WHERE message_sha256=? "
        "ORDER BY trusted DESC,auth_id",
        (message_sha256,),
    ).fetchall()
    trusted_auth_values = [row["raw_value"] for row in auth_rows if bool(row["trusted"])]
    all_auth_values = [row["raw_value"] for row in auth_rows]
    spf_ips = _client_ips(trusted_auth_values)
    if not spf_ips:
        spf_ips = _client_ips(all_auth_values)
    if not spf_ips and headers is not None:
        spf_ips = _client_ips(str(value) for value in headers.get_all("Received-SPF", []))

    claimed: list[str] = []
    if headers is not None:
        for header in CLAIMED_ORIGIN_HEADERS:
            for value in headers.get_all(header, []):
                for ip in extract_ips(str(value)):
                    if ip not in claimed:
                        claimed.append(ip)

    return {
        "trusted_boundary_ip": _join(trusted_boundary),
        "spf_client_ip": _join(spf_ips),
        "claimed_originating_ip": _join(claimed),
        "topmost_received_ip": _join(hop_ips[0] if hop_ips else []),
        "bottommost_received_ip": _join(hop_ips[-1] if hop_ips else []),
    }


def enrich_sender_ip_rows(conn, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add the classified sender-IP columns to report rows in place."""
    cache: dict[str, dict[str, str]] = {}
    for row in rows:
        message_sha256 = str(row.get("message_sha256") or "")
        if not message_sha256:
            for field in SENDER_IP_FIELD_NAMES:
                row[field] = ""
            continue
        if message_sha256 not in cache:
            cache[message_sha256] = sender_ip_fields(
                conn, message_sha256, row.get("raw_headers_text")
            )
        row.update(cache[message_sha256])
    return rows
