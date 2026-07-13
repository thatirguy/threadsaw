from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from base64 import urlsafe_b64decode
import string
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

from .util import atomic_write_csv, chunked
from .progress import ProgressCallback, ProgressCounter, console_progress
from .ip_fields import SENDER_IP_FIELD_NAMES, enrich_sender_ip_rows
from .message_context import enrich_recipient_rows
from .domains import registrable_domain, PSL_SNAPSHOT
from .case import load_case

URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s<>\"']+", re.I)
WWW_RE = re.compile(r"(?<![A-Za-z0-9@._/:=-])(www\.(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:/[^\s<>\"']*)?)", re.I)
URI_RE = re.compile(
    r"\b(?:https?|hxxps?|file|smb|ftp|javascript|data|ms-msdt|search-ms|ms-officecmd|ms-word|ms-excel|ms-powerpoint|shell|vbscript|ldap|ldaps|telnet|ssh):[^\s<>\"']+",
    re.I,
)
TRAILING = ".,;:!?)]}>'\""
URL_FIELDS = [
    "message_sha256", "sender_email", "recipient_addresses", "message_date_utc", "subject", *SENDER_IP_FIELD_NAMES,
    "source_part", "displayed_text", "display_target_mismatch", "raw_url", "normalized_url", "wrapper_type",
    "decoded_target_url", "hostname", "registrable_domain", "registrable_domain_method",
    "contains_sharepoint_reference", "sharepoint_relationship",
]


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str | None, str]] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        attrs_dict = dict(attrs)
        for attribute in ("href", "src", "action"):
            value = attrs_dict.get(attribute)
            if value and not (tag.lower() == "a" and attribute == "href"):
                self.items.append((value, None, f"html-{tag}-{attribute}"))
        if tag.lower() == "a":
            self._anchor_href = attrs_dict.get("href")
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if self._anchor_href is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._anchor_href is not None:
            text = " ".join("".join(self._anchor_text).split()) or None
            self.items.append((self._anchor_href, text, "html-anchor"))
            self._anchor_href = None
            self._anchor_text = []


def _clean(raw: str) -> str:
    raw = html.unescape(raw).strip().rstrip(TRAILING)
    raw = re.sub(r"^hxxps?://", lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://", raw, flags=re.I)
    return raw


def _decode_proofpoint_v2(value: str) -> str:
    # Proofpoint v2 uses -XX hex escapes and underscores for slashes. Decode
    # hex first so encoded underscores/hyphens remain literal.
    def repl(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)
    decoded = re.sub(r"-([0-9A-Fa-f]{2})", repl, value)
    return unquote(decoded.replace("_", "/"))


def _decode_proofpoint_v3(value: str) -> str:
    """Decode a Proofpoint v3 embedded URL entirely offline.

    V3 stores a URL template between ``__`` delimiters and a URL-safe
    Base64 replacement stream after ``__;``. A single ``*`` consumes one
    replacement character; ``**X`` consumes a run whose length is encoded by
    X. Some observed wrappers contain no replacement stream, so a conservative
    percent/hex fallback is retained.
    """
    match = re.search(r"^__(?P<template>.+?)__;( ?)(?P<encoded>.*?)!", value)
    if not match:
        # Accept a path fragment already stripped of leading delimiters.
        match = re.search(r"^(?P<template>.+?)__;( ?)(?P<encoded>.*?)!", value)
    if match:
        template = unquote(match.group("template"))
        # Repair the single slash form sometimes produced for scheme:/host.
        template = re.sub(r"^([a-z][a-z0-9+.-]+:/)([^/])", r"\1/\2", template, flags=re.I)
        encoded = match.group("encoded")
        try:
            padding = "=" * (-len(encoded) % 4)
            replacements = urlsafe_b64decode(encoded + padding).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            replacements = ""

        run_alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
        run_lengths = {character: index + 2 for index, character in enumerate(run_alphabet)}
        position = 0

        def token_replacement(token_match: re.Match[str]) -> str:
            nonlocal position
            token = token_match.group(0)
            length = 1 if token == "*" else run_lengths.get(token[-1], 0)
            if length < 1 or position + length > len(replacements):
                return token
            output = replacements[position : position + length]
            position += length
            return output

        return re.sub(r"\*(?:\*.)?", token_replacement, template)

    candidate = value[2:] if value.startswith("__") else value
    for marker in ("__;", "__!", "__$"):
        if marker in candidate:
            candidate = candidate.split(marker, 1)[0]
            break

    def hex_replacement(hex_match: re.Match[str]) -> str:
        try:
            return chr(int(hex_match.group(1), 16))
        except ValueError:
            return hex_match.group(0)

    return unquote(re.sub(r"\*([0-9A-Fa-f]{2})", hex_replacement, candidate))


def _decode_wrapper(url: str) -> tuple[str | None, str | None]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    query = parse_qs(parts.query)
    if host.endswith("safelinks.protection.outlook.com") and query.get("url"):
        return "microsoft-safelinks", unquote(query["url"][0])
    if host == "urldefense.proofpoint.com" or host.endswith(".urldefense.proofpoint.com") or host == "urldefense.com" or host.endswith(".urldefense.com"):
        if parts.path.startswith("/v3/"):
            encoded = parts.path[len("/v3/"):]
            return "proofpoint-v3", _decode_proofpoint_v3(encoded)
        if query.get("u"):
            return "proofpoint-v2", _decode_proofpoint_v2(query["u"][0])
        return "proofpoint", None
    if (
        (host.startswith("protect-") and host.endswith(".mimecast.com"))
        or host == "protect.mimecast.com"
        or host.endswith(".m.mimecastprotect.com")
        or host.endswith(".mimecastprotect.com")
    ):
        for key in ("url", "u"):
            if query.get(key):
                return "mimecast-protect", unquote(query[key][0])
        if query.get("domain"):
            domain = query["domain"][0].strip().strip(".")
            return "mimecast-protect-domain", f"https://{domain}" if domain else None
        return "mimecast-protect", None
    return None, None


def _normalize(url: str) -> tuple[str | None, str | None]:
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None, None
        host = parts.hostname.encode("idna").decode("ascii").lower()
        port = parts.port
        netloc = host
        if port and not ((parts.scheme.lower() == "http" and port == 80) or (parts.scheme.lower() == "https" and port == 443)):
            netloc += f":{port}"
        normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query, parts.fragment))
        return normalized, host
    except (ValueError, UnicodeError):
        return None, None


def _registrable(hostname: str | None) -> tuple[str | None, str]:
    value = registrable_domain(hostname)
    return value, f"public-suffix-list-{PSL_SNAPSHOT}" if value else "unavailable"


def extract_urls(conn, case_dir: Path, ids: list[str], *, progress: ProgressCallback = console_progress, batch_size: int = 250) -> int:
    inserted = 0
    counter = ProgressCounter("URLS", len(ids), progress, every=100)
    for index, message_sha256 in enumerate(ids, start=1):
        row = conn.execute("SELECT body_text,body_html FROM messages WHERE message_sha256=?", (message_sha256,)).fetchone()
        if not row:
            continue
        conn.execute("DELETE FROM urls WHERE message_sha256=?", (message_sha256,))
        candidates: list[tuple[str, str | None, str]] = []
        body_text = row["body_text"] or ""
        for raw in URI_RE.findall(body_text):
            candidates.append((raw, None, "text-body"))
        for raw in WWW_RE.findall(body_text):
            candidates.append((raw, None, "text-body-bare-www"))
        parser = LinkParser()
        try:
            parser.feed(row["body_html"] or "")
            candidates.extend(parser.items)
        except Exception:
            pass
        seen_candidates: set[tuple[str, str, str]] = set()
        for raw, display, source_part in candidates:
            display_value = display or ""
            candidate_key = (source_part, raw, display_value)
            if candidate_key in seen_candidates:
                continue
            seen_candidates.add(candidate_key)
            cleaned = _clean(raw)
            if "://" not in cleaned and cleaned.lower().startswith("www."):
                cleaned = "https://" + cleaned
            normalized, hostname = _normalize(cleaned)
            wrapper_type, decoded_target = _decode_wrapper(normalized or cleaned)
            if decoded_target:
                decoded_target, _ = _normalize(_clean(decoded_target))
            registrable, method = _registrable(hostname)
            effective_domain = registrable
            if decoded_target:
                _decoded_normalized, decoded_host = _normalize(decoded_target)
                effective_domain, _decoded_method = _registrable(decoded_host)
            display_mismatch = None
            if display_value:
                displayed_url_match = URL_RE.search(display_value)
                if displayed_url_match:
                    displayed_normalized, displayed_host = _normalize(_clean(displayed_url_match.group(0)))
                    actual_value = decoded_target or normalized
                    _actual_normalized, actual_host = _normalize(actual_value) if actual_value else (None, None)
                    displayed_domain, _display_method = _registrable(displayed_host)
                    actual_domain, _actual_method = _registrable(actual_host)
                    display_mismatch = bool(displayed_domain and actual_domain and displayed_domain != actual_domain)
            is_sharepoint = (
                "sharepoint" in cleaned.lower()
                or bool(hostname and "sharepoint" in hostname)
                or bool(decoded_target and "sharepoint" in decoded_target.lower())
            )
            cursor = conn.execute(
                """INSERT OR IGNORE INTO urls(message_sha256,source_part,displayed_text,display_target_mismatch,raw_url,normalized_url,
                   wrapper_type,decoded_target_url,hostname,registrable_domain,registrable_domain_method,effective_registrable_domain,
                   is_sharepoint) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (message_sha256, source_part, display, None if display_mismatch is None else int(display_mismatch), raw, normalized, wrapper_type, decoded_target, hostname,
                 registrable, method, effective_domain, int(is_sharepoint)),
            )
            inserted += cursor.rowcount
        for url_row in conn.execute(
            "SELECT url_id,message_sha256,hostname,is_sharepoint FROM urls WHERE message_sha256=?",
            (message_sha256,),
        ).fetchall():
            relationship = _sharepoint_relationship(conn, dict(url_row))
            conn.execute(
                "UPDATE urls SET sharepoint_relationship=? WHERE url_id=?",
                (relationship, url_row["url_id"]),
            )
        url_count = conn.execute("SELECT COUNT(*) FROM urls WHERE message_sha256=?", (message_sha256,)).fetchone()[0]
        conn.execute("UPDATE messages SET url_count=?, url_indexed=1 WHERE message_sha256=?", (url_count, message_sha256))
        if index % batch_size == 0:
            conn.commit()
            progress(f"[URLS] Committed through message {index:,}; new URL rows={inserted:,}")
        counter.update(index, force=index == len(ids))
    conn.commit()
    progress(f"[URLS] Complete: selected={len(ids):,} new_url_rows={inserted:,}")
    return inserted


def _sharepoint_relationship(conn, row: dict[str, object]) -> str:
    if not bool(row.get("is_sharepoint")):
        return "not_sharepoint"
    host = str(row.get("hostname") or "").lower()
    if not host.endswith(".sharepoint.com"):
        return "unknown"
    tenant = host[: -len(".sharepoint.com")].split(".")[-1]
    db_path = conn.execute("PRAGMA database_list").fetchone()[2]
    case_dir = Path(db_path).resolve().parent
    try:
        case_data = load_case(case_dir)
        domains = list((case_data.get("config") or {}).get("organization_domains") or [])
        domains += list((case_data.get("inferred_context") or {}).get("organization_domains") or [])
    except Exception:
        domains = []
    for recipient in conn.execute("SELECT domain FROM recipients WHERE message_sha256=?", (row.get("message_sha256"),)):
        if recipient["domain"]:
            domains.append(str(recipient["domain"]))
    tokens = {re.sub(r"[^a-z0-9]", "", (registrable_domain(value) or value).split(".")[0].lower()) for value in domains}
    tenant_token = re.sub(r"[^a-z0-9]", "", tenant)
    tokens.discard("")
    if not tokens:
        return "unknown"
    return "probable_internal" if any(token == tenant_token or (len(token) >= 5 and token in tenant_token) for token in tokens) else "probable_external"


def write_url_report(conn, output: Path, ids: list[str]) -> Path:
    if not ids:
        rows = []
    else:
        rows = []
        for batch in chunked(ids):
            placeholders = ",".join("?" for _ in batch)
            rows.extend(dict(r) for r in conn.execute(
                f"""SELECT u.message_sha256, u.url_id, u.source_part, u.displayed_text, u.display_target_mismatch,
                           u.raw_url, u.normalized_url, u.wrapper_type, u.decoded_target_url,
                           u.hostname, u.registrable_domain, u.registrable_domain_method, u.is_sharepoint,
                           u.sharepoint_relationship,
                           m.from_address AS sender_email, m.selected_date_utc AS message_date_utc, m.subject
                    FROM urls u JOIN messages m ON m.message_sha256=u.message_sha256
                    WHERE u.message_sha256 IN ({placeholders})""", batch))
        rows.sort(key=lambda row: (str(row.get("message_sha256") or ""), int(row.pop("url_id", 0))))
    enrich_recipient_rows(conn, rows)
    enrich_sender_ip_rows(conn, rows)
    for row in rows:
        row["contains_sharepoint_reference"] = "yes" if bool(row.get("is_sharepoint")) else "no"
        row["sharepoint_relationship"] = row.get("sharepoint_relationship") or _sharepoint_relationship(conn, row)
    atomic_write_csv(output, URL_FIELDS, rows)
    return output


def write_timestamped_url_report(conn, output_base: Path, ids: list[str]) -> dict[str, str]:
    """Write one completion-timestamped URL CSV without overwriting prior runs."""
    from .output_naming import cleanup_staging, completion_timestamp, finalize_file, staging_file

    output_base = Path(output_base)
    stage: Path | None = staging_file(output_base)
    try:
        write_url_report(conn, stage, ids)
        stamp = completion_timestamp()
        final_path = finalize_file(stage, output_base, stamp)
        stage = None
        return {
            "output": str(final_path),
            "completion_timestamp": stamp,
        }
    finally:
        cleanup_staging(stage)
