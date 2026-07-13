"""Offline evaluators for the Threadsaw Phish Hunt factor catalog.

Every evaluator works only with data already stored in the case SQLite database.
No evaluator follows URLs, resolves hosts, connects to IP addresses, opens an
attachment, executes content, or performs live enrichment.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import unicodedata
from datetime import datetime
from email import policy
from email.parser import Parser
from email.utils import getaddresses, parseaddr
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote, urlsplit

from .archive_inspection import is_zip_family_attachment
from .ip_fields import sender_ip_fields
from .domains import registrable_domain
from .util import chunked

Evaluator = Callable[[Any, Any, dict[str, Any]], dict[str, Any]]

SHORTENER_LIST_VERSION = "2026.07"
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
    "lnkd.in", "youtu.be", "trib.al", "amzn.to", "aka.ms", "1drv.ms",
    "forms.gle", "ift.tt", "s.id", "v.gd", "bl.ink", "soo.gd",
}
FREE_EMAIL_LIST_VERSION = "2026.07"
FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
    "mail.com", "zoho.com", "fastmail.com", "fastmail.fm", "tutanota.com",
    "tuta.com", "hey.com", "yandex.com", "yandex.ru", "qq.com", "163.com",
}
DANGEROUS_SCHEMES_VERSION = "2026.07"
DANGEROUS_SCHEMES = {
    "file", "smb", "ftp", "javascript", "data", "ms-msdt", "search-ms",
    "ms-officecmd", "ms-word", "ms-excel", "ms-powerpoint", "shell",
    "vbscript", "about", "jar", "ldap", "ldaps", "telnet", "ssh",
}
EMAIL_LIKE_RE = re.compile(r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
DISPLAY_DOMAIN_RE = re.compile(r"(?:https?://[^\s<>\"']+|(?<!@)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)", re.I)
MESSAGE_ID_RE = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
MESSAGE_ID_TOKEN_RE = re.compile(r"<[^<>\s]+>")
REPLY_PREFIX_RE = re.compile(r"^\s*(?:(?:re|aw|sv|答复|回复)\s*:\s*)+", re.I)
FORWARD_OR_REPLY_PREFIX_RE = re.compile(r"^\s*(?:(?:re|fw|fwd|aw|sv|答复|回复)\s*:\s*)+", re.I)
PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9_\-/+])([A-Za-z0-9_\-/+]{8,}={0,2})(?![A-Za-z0-9_\-/+=])")
UNICODE_CONTROL_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
    0x202D, 0x202E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066,
    0x2067, 0x2068, 0x2069, 0xFEFF,
}
SHORTCUT_EXTENSIONS = {".lnk", ".url", ".website", ".webloc", ".desktop", ".scf"}
HTML_SVG_EXTENSIONS = {".html", ".htm", ".shtml", ".xhtml", ".svg"}
HTML_SVG_CONTENT_TYPES = {"text/html", "application/xhtml+xml", "image/svg+xml"}
MODERN_LOADER_EXTENSIONS = {".wsf", ".wsh", ".scr", ".pif", ".cpl", ".chm", ".xll", ".one", ".iqy", ".slk", ".rdp", ".msix", ".docm", ".xlsm", ".pptm"}
FINANCIAL_PATTERNS = {
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.I),
    "routing_number": re.compile(r"\b(?:routing|aba)\s*(?:number|no\.?|#)?\s*[:=-]?\s*\d{9}\b", re.I),
    "account_number": re.compile(r"\baccount\s*(?:number|no\.?|#)\s*[:=-]?\s*\d{6,17}\b", re.I),
}
DISK_IMAGE_EXTENSIONS = {".iso", ".img", ".dmg", ".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2"}
ATTACHED_EMAIL_EXTENSIONS = {".eml", ".msg"}
ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".gz2", ".bz2", ".tbz", ".tbz2",
    ".xz", ".txz", ".z", ".cab", ".arj", ".lha", ".lzh", ".ace", ".jar", ".war",
    ".ear", ".cpio", ".rpm", ".deb", ".apk", ".xpi", ".crx",
}
ARCHIVE_CONTENT_TYPES = {
    "application/zip", "application/x-zip-compressed", "application/x-7z-compressed",
    "application/vnd.rar", "application/x-rar-compressed", "application/x-tar",
    "application/gzip", "application/x-gzip", "application/x-bzip2", "application/x-xz",
    "application/x-compress", "application/x-cpio", "application/vnd.ms-cab-compressed",
    "application/java-archive", "application/x-java-archive", "application/vnd.android.package-archive",
    "application/x-rpm", "application/vnd.debian.binary-package",
}
COMMON_COMPOUND_EXTENSIONS = {
    (".tar", ".gz"), (".tar", ".bz2"), (".tar", ".xz"), (".sql", ".zip"),
}


def _result(answer: str, reason: str, *, evidence: str = "", source: str = "SQLite case database", status: str = "evaluated") -> dict[str, Any]:
    return {"answer": answer, "status": status, "evidence": evidence, "source": source, "reason": reason}


def _yes(reason: str, *, evidence: str = "", source: str = "SQLite case database") -> dict[str, Any]:
    return _result("YES", reason, evidence=evidence, source=source)


def _no(reason: str, *, evidence: str = "", source: str = "SQLite case database") -> dict[str, Any]:
    return _result("NO", reason, evidence=evidence, source=source)


def _unknown(reason: str, *, evidence: str = "", source: str = "SQLite case database", status: str = "unknown") -> dict[str, Any]:
    return _result("UNKNOWN", reason, evidence=evidence, source=source, status=status)


def _message_value(message: Any, key: str, default: Any = None) -> Any:
    try:
        return message[key]
    except (KeyError, IndexError, TypeError):
        return default


def _address(value: str | None) -> str | None:
    address = parseaddr(value or "")[1].strip().lower()
    return address or None


def _address_domain(value: str | None) -> str | None:
    address = _address(value)
    if not address or "@" not in address:
        return None
    return _registrable(address.rsplit("@", 1)[1])


def _address_local(value: str | None) -> str | None:
    address = _address(value)
    return address.rsplit("@", 1)[0] if address and "@" in address else None


def _registrable(hostname: str | None) -> str | None:
    return registrable_domain(hostname)


def _parameter(factor_config: dict[str, Any], name: str, default: Any = None) -> Any:
    return (factor_config.get("parameters") or {}).get(name, default)


def _integer_parameter(factor_config: dict[str, Any], name: str, default: int) -> int | None:
    value = _parameter(factor_config, name, default)
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed


def _list_parameter(factor_config: dict[str, Any], name: str) -> list[str]:
    value = _parameter(factor_config, name, "")
    if isinstance(value, list):
        raw_values = [str(item) for item in value]
    else:
        raw_values = re.split(r"[\r\n,;]+", str(value or ""))
    output: list[str] = []
    for raw in raw_values:
        item = raw.strip().lower()
        if "://" in item:
            item = (urlsplit(item).hostname or item).lower()
        item = item.strip(". ")
        if item and item not in output:
            output.append(item)
    return output


@lru_cache(maxsize=4096)
def _parse_headers(raw_headers_text: str | None):
    if not raw_headers_text:
        return None
    try:
        return Parser(policy=policy.default).parsestr(raw_headers_text + "\n\n", headersonly=True)
    except Exception:
        return None


def _header(message: Any, name: str) -> str | None:
    headers = _parse_headers(_message_value(message, "raw_headers_text"))
    if headers is None:
        return None
    value = headers.get(name)
    return str(value).strip() if value is not None else None


def _headers(message: Any, name: str) -> list[str]:
    headers = _parse_headers(_message_value(message, "raw_headers_text"))
    if headers is None:
        return []
    return [str(value).strip() for value in headers.get_all(name, [])]


def _recipient_rows(conn, message_sha256: str) -> list[Any]:
    return conn.execute(
        "SELECT recipient_type,email_address,domain FROM recipients WHERE message_sha256=? ORDER BY recipient_id",
        (message_sha256,),
    ).fetchall()


def _recipient_addresses(conn, message_sha256: str, types: set[str] | None = None) -> list[str]:
    output: list[str] = []
    for row in _recipient_rows(conn, message_sha256):
        if types is not None and str(row["recipient_type"]).lower() not in types:
            continue
        address = _address(row["email_address"])
        if address and address not in output:
            output.append(address)
    return output


def _recipient_domains(conn, message_sha256: str, types: set[str] | None = None) -> list[str]:
    output: list[str] = []
    for row in _recipient_rows(conn, message_sha256):
        if types is not None and str(row["recipient_type"]).lower() not in types:
            continue
        domain = _registrable(row["domain"] or (_address(row["email_address"] or "") or "").rsplit("@", 1)[-1])
        if domain and domain not in output:
            output.append(domain)
    return output


def _url_rows(conn, message: Any) -> tuple[list[Any] | None, str | None]:
    indexed = int(_message_value(message, "url_indexed", 0) or 0)
    if not indexed:
        return None, "URL indexing has not been completed for this message."
    rows = conn.execute(
        "SELECT * FROM urls WHERE message_sha256=? ORDER BY url_id",
        (_message_value(message, "message_sha256"),),
    ).fetchall()
    return rows, None


def _url_variants(row: Any) -> list[tuple[str, str]]:
    output: list[tuple[str, str]] = []
    for label, value in (("original", row["normalized_url"] or row["raw_url"]), ("decoded", row["decoded_target_url"])):
        text = str(value or "").strip()
        if text and all(text != existing for _label, existing in output):
            output.append((label, text))
    return output


def _url_host(value: str) -> str | None:
    try:
        return (urlsplit(value).hostname or "").lower() or None
    except ValueError:
        return None


def _url_domain(value: str) -> str | None:
    return _registrable(_url_host(value))


def _attachment_rows(conn, message_sha256: str) -> list[Any]:
    return conn.execute(
        "SELECT * FROM attachments WHERE message_sha256=? ORDER BY part_index",
        (message_sha256,),
    ).fetchall()


def _selected_date(message: Any) -> str | None:
    value = _message_value(message, "selected_date_utc")
    return str(value) if value else None


def _normalize_subject(value: str | None) -> str:
    text = FORWARD_OR_REPLY_PREFIX_RE.sub("", str(value or ""))
    return " ".join(text.split()).casefold()


def _message_participants(conn, message: Any) -> set[str]:
    values = set(_recipient_addresses(conn, _message_value(message, "message_sha256")))
    sender = _address(_message_value(message, "from_address"))
    if sender:
        values.add(sender)
    return values


def _message_ids_from_headers(message: Any) -> list[str]:
    values: list[str] = []
    for header_name in ("In-Reply-To", "References"):
        for raw in _headers(message, header_name):
            for token in MESSAGE_ID_TOKEN_RE.findall(raw):
                normalized = token.strip().casefold()
                if normalized not in values:
                    values.append(normalized)
    return values


CONFUSABLE_MAP = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n",
    "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t", "υ": "y", "χ": "x",
})


def _confusable_skeleton(value: str) -> str:
    return unicodedata.normalize("NFKC", value).translate(CONFUSABLE_MAP).casefold()


def _domain_similarity_reason(left: str, right: str) -> str | None:
    left = left.lower().strip(".")
    right = right.lower().strip(".")
    if not left or not right or left == right:
        return None
    if _confusable_skeleton(left) == _confusable_skeleton(right):
        return "Unicode-confusable skeleton match"
    if left.replace("-", "") == right.replace("-", ""):
        return "hyphen-only variation"
    if left.replace("rn", "m") == right.replace("rn", "m"):
        return "rn/m visual substitution"
    if left.replace("0", "o").replace("1", "l") == right.replace("0", "o").replace("1", "l"):
        return "common digit/letter visual substitution"
    left_labels, right_labels = left.split("."), right.split(".")
    left_sld = left_labels[-2] if len(left_labels) >= 2 else left_labels[0]
    right_sld = right_labels[-2] if len(right_labels) >= 2 else right_labels[0]
    if min(len(left_sld), len(right_sld)) >= 5 and _edit_distance_at_most_one(left_sld, right_sld):
        return "single-character edit or adjacent transposition"
    if min(len(left_sld), len(right_sld)) >= 5 and left_sld == right_sld and left_labels[-1] != right_labels[-1]:
        return "top-level-domain variation"
    return None


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        mismatches = [index for index, (a, b) in enumerate(zip(left, right)) if a != b]
        if len(mismatches) <= 1:
            return True
        return len(mismatches) == 2 and mismatches[1] == mismatches[0] + 1 and left[mismatches[0]] == right[mismatches[1]] and left[mismatches[1]] == right[mismatches[0]]
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    i = j = edits = 0
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
            j += 1
        else:
            edits += 1
            j += 1
            if edits > 1:
                return False
    return True


def _auth_rows(conn, message_sha256: str, trusted_only: bool = False) -> list[Any]:
    sql = "SELECT * FROM authentication_results WHERE message_sha256=?"
    params: list[Any] = [message_sha256]
    if trusted_only:
        sql += " AND trusted=1"
    sql += " ORDER BY trusted DESC,auth_id"
    return conn.execute(sql, params).fetchall()


def _evaluate_auth_fail(check: str, fail_values: set[str]) -> Evaluator:
    def evaluator(conn, message: Any, _factor_config: dict[str, Any]) -> dict[str, Any]:
        rows = _auth_rows(conn, _message_value(message, "message_sha256"), trusted_only=True)
        if not rows:
            return _unknown("No trusted Authentication-Results record is available.", source="authentication_results")
        values = [str(row[f"{check}_result"] or "").lower() for row in rows if row[f"{check}_result"]]
        if not values:
            return _unknown(f"No trusted {check.upper()} result is available.", source="authentication_results")
        matches = [value for value in values if value in fail_values]
        evidence = f"{check}_results={';'.join(values)}"
        return _yes(f"A trusted {check.upper()} result reported {matches[0]}.", evidence=evidence, source="authentication_results") if matches else _no(f"No trusted {check.upper()} result reported a configured failure outcome.", evidence=evidence, source="authentication_results")
    return evaluator


def eval_reply_to_domain_mismatch(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    from_domain = _address_domain(_message_value(message, "from_address"))
    reply_domain = _address_domain(_message_value(message, "reply_to"))
    if not from_domain or not reply_domain:
        return _unknown("From or Reply-To did not contain a usable domain.")
    evidence = f"from_domain={from_domain}; reply_to_domain={reply_domain}"
    return _yes("Reply-To and From use different registrable domains.", evidence=evidence) if from_domain != reply_domain else _no("Reply-To and From use the same registrable domain.", evidence=evidence)


def eval_display_name_embedded_email_domain_mismatch(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    raw = str(_message_value(message, "from_address", "") or "")
    display_name, actual = parseaddr(raw)
    actual_domain = _address_domain(actual)
    if not actual_domain:
        return _unknown("The actual sender address did not contain a usable domain.")
    embedded = EMAIL_LIKE_RE.findall(display_name or "")
    if not embedded:
        return _no("The sender display name does not contain an email address.", evidence=f"display_name={display_name}")
    mismatches = [(item, _address_domain(item)) for item in embedded if _address_domain(item) and _address_domain(item) != actual_domain]
    evidence = f"display_name={display_name}; actual_sender={actual}; actual_domain={actual_domain}; embedded={';'.join(embedded)}"
    return _yes("An email address embedded in the display name uses a different domain from the actual sender.", evidence=evidence) if mismatches else _no("Embedded display-name email domains match the actual sender domain.", evidence=evidence)


def eval_sender_domain_lookalike_configured(_conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    sender = _address_domain(_message_value(message, "from_address"))
    configured = [_registrable(value) for value in _list_parameter(config, "legitimate_domains")]
    configured = [value for value in configured if value]
    if not configured:
        return _unknown("No legitimate organization domain was configured.", status="unavailable-config")
    if not sender:
        return _unknown("The sender domain is unavailable.")
    hits = [(domain, _domain_similarity_reason(sender, domain)) for domain in configured]
    hits = [(domain, reason) for domain, reason in hits if reason]
    evidence = f"sender_domain={sender}; configured_domains={';'.join(configured)}"
    return _yes(f"The sender domain resembles {hits[0][0]} ({hits[0][1]}).", evidence=evidence) if hits else _no("The sender domain does not conservatively resemble a configured legitimate domain.", evidence=evidence)


def eval_sender_domain_lookalike_recipient(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address_domain(_message_value(message, "from_address"))
    recipients = _recipient_domains(conn, _message_value(message, "message_sha256"))
    if not sender:
        return _unknown("The sender domain is unavailable.")
    if not recipients:
        return _unknown("No usable recipient domain is available.")
    hits = [(domain, _domain_similarity_reason(sender, domain)) for domain in recipients]
    hits = [(domain, reason) for domain, reason in hits if reason]
    evidence = f"sender_domain={sender}; recipient_domains={';'.join(recipients)}"
    return _yes(f"The sender domain resembles recipient domain {hits[0][0]} ({hits[0][1]}).", evidence=evidence) if hits else _no("The sender domain does not conservatively resemble a different recipient domain.", evidence=evidence)


def eval_displayed_url_domain_mismatch(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    evaluated = 0
    hits: list[str] = []
    for row in rows:
        display = str(row["displayed_text"] or "")
        match = DISPLAY_DOMAIN_RE.search(display)
        if not match:
            continue
        displayed_value = match.group(0)
        if "://" not in displayed_value:
            displayed_value = "https://" + displayed_value
        display_domain = _url_domain(displayed_value)
        actual = str(row["decoded_target_url"] or row["normalized_url"] or row["raw_url"] or "")
        actual_domain = _url_domain(actual)
        if not display_domain or not actual_domain:
            continue
        evaluated += 1
        if display_domain != actual_domain:
            hits.append(f"displayed={display_domain}; actual={actual_domain}; url={actual}")
    if not evaluated:
        return _unknown("No link had URL-like display text with two parseable domains.", source="urls")
    return _yes("At least one URL-like displayed domain differs from the actual stored destination domain.", evidence=" | ".join(hits), source="urls") if hits else _no("All evaluated URL-like display domains match their stored destination domains.", source="urls")


def _evaluate_url_predicate(predicate: Callable[[str], tuple[bool, str]], yes_reason: str) -> Evaluator:
    def evaluator(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
        rows, error = _url_rows(conn, message)
        if rows is None:
            return _unknown(error or "URL data unavailable.")
        hits: list[str] = []
        for row in rows:
            for variant, value in _url_variants(row):
                matched, detail = predicate(value)
                if matched:
                    hits.append(f"{variant}:{detail or value}")
        return _yes(yes_reason, evidence=" | ".join(hits), source="urls") if hits else _no("No stored URL matched this condition.", source="urls")
    return evaluator


def _literal_ip_predicate(value: str) -> tuple[bool, str]:
    host = _url_host(value)
    if not host:
        return False, ""
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return False, ""
    return True, f"host={parsed}; url={value}"


def _userinfo_predicate(value: str) -> tuple[bool, str]:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False, ""
    if parts.username is not None or parts.password is not None:
        return True, f"userinfo={parts.username or ''}; host={parts.hostname or ''}; url={value}"
    return False, ""


def _port_predicate(value: str) -> tuple[bool, str]:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return False, ""
    if port is None:
        return False, ""
    defaults = {"http": 80, "https": 443}
    expected = defaults.get(parts.scheme.lower())
    if expected is not None and port != expected:
        return True, f"scheme={parts.scheme}; port={port}; expected={expected}; url={value}"
    return False, ""


def _dangerous_scheme_predicate(value: str) -> tuple[bool, str]:
    scheme = value.split(":", 1)[0].lower() if ":" in value else ""
    return (scheme in DANGEROUS_SCHEMES, f"scheme={scheme}; list_version={DANGEROUS_SCHEMES_VERSION}; uri={value}")


def eval_url_embeds_legitimate_domain(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    configured = [_registrable(value) for value in _list_parameter(config, "legitimate_domains")]
    configured = [value for value in configured if value]
    if not configured:
        return _unknown("No legitimate domain was configured.", status="unavailable-config")
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits: list[str] = []
    for row in rows:
        for variant, value in _url_variants(row):
            host = _url_host(value)
            actual = _registrable(host)
            if not host or not actual:
                continue
            labels_joined = "." + host + "."
            for legitimate in configured:
                if actual == legitimate:
                    continue
                if f".{legitimate}." in labels_joined:
                    hits.append(f"configured={legitimate}; host={host}; actual_domain={actual}; {variant}_url={value}")
    return _yes("A legitimate domain is embedded in a hostname controlled by another registrable domain.", evidence=" | ".join(hits), source="urls") if hits else _no("No configured legitimate domain was misleadingly embedded in a stored URL hostname.", source="urls")


def _decode_obfuscated_ipv4(host: str) -> tuple[str, str] | None:
    text = host.lower()
    try:
        if re.fullmatch(r"\d+", text):
            number = int(text, 10)
            if 0 <= number <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(number)), "single-integer"
        if re.fullmatch(r"0x[0-9a-f]+", text):
            number = int(text, 16)
            if 0 <= number <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(number)), "hexadecimal-integer"
        parts = text.split(".")
        if 1 < len(parts) <= 4 and any(part.startswith("0x") or (len(part) > 1 and part.startswith("0")) for part in parts):
            values: list[int] = []
            for part in parts:
                base = 16 if part.startswith("0x") else (8 if len(part) > 1 and part.startswith("0") else 10)
                values.append(int(part, base))
            if len(values) == 4 and all(0 <= item <= 255 for item in values):
                return ".".join(str(item) for item in values), "mixed-radix-dotted"
    except (ValueError, ipaddress.AddressValueError):
        return None
    return None


def _obfuscated_ip_predicate(value: str) -> tuple[bool, str]:
    host = _url_host(value)
    if not host:
        return False, ""
    decoded = _decode_obfuscated_ipv4(host)
    return (True, f"host={host}; decoded_ip={decoded[0]}; representation={decoded[1]}; url={value}") if decoded else (False, "")


def eval_attachment_executable(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    message_sha256 = _message_value(message, "message_sha256")
    rows = _attachment_rows(conn, message_sha256)
    hits = [f"attachment={row['original_filename'] or '[unnamed]'}; classification={row['executable_format']}" for row in rows if row["executable_format"]]
    archived = conn.execute(
        """SELECT a.original_filename,am.member_name FROM archive_members am
           JOIN attachments a ON a.attachment_id=am.attachment_id
           WHERE a.message_sha256=? AND am.suspicious_extension=1 ORDER BY a.part_index,am.member_index""",
        (message_sha256,),
    ).fetchall()
    hits.extend(f"archive={row['original_filename'] or '[unnamed]'}; member={row['member_name']}" for row in archived)
    source = "attachments.executable_format and archive_members.suspicious_extension"
    return _yes("At least one attachment or listed ZIP member has an existing executable, script, loader, or macro classification.", evidence=" | ".join(hits), source=source) if hits else _no("No attachment or listed ZIP member has an executable, script, loader, or macro classification in SQLite.", source=source)


def eval_attachment_double_extension(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    hits: list[str] = []
    for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
        name = str(row["original_filename"] or "")
        suffixes = [item.lower() for item in Path(name).suffixes]
        if len(suffixes) >= 2 and tuple(suffixes[-2:]) not in COMMON_COMPOUND_EXTENSIONS:
            hits.append(name)
    return _yes("At least one attachment filename uses multiple potentially misleading extensions.", evidence="; ".join(hits), source="attachments.original_filename") if hits else _no("No potentially misleading double-extension attachment filename was found.", source="attachments.original_filename")


def eval_attachment_unicode_controls(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    hits: list[str] = []
    for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
        name = str(row["original_filename"] or "")
        codes = [f"U+{ord(char):04X}" for char in name if ord(char) in UNICODE_CONTROL_CODEPOINTS or unicodedata.category(char) == "Cf"]
        if codes:
            hits.append(f"filename={name!r}; controls={','.join(codes)}")
    return _yes("At least one attachment filename contains a Unicode formatting or invisible control character.", evidence=" | ".join(hits), source="attachments.original_filename") if hits else _no("No recognized Unicode direction-control or invisible characters were found in attachment filenames.", source="attachments.original_filename")


def eval_executable_without_extension(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    hits = []
    for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
        if row["executable_format"] and not Path(str(row["original_filename"] or "")).suffix:
            hits.append(f"{row['original_filename'] or '[unnamed]'}:{row['executable_format']}")
    return _yes("At least one executable or script attachment lacks a filename extension.", evidence="; ".join(hits), source="attachments") if hits else _no("No stored executable or script attachment lacks a filename extension.", source="attachments")


def _attachment_extension_factor(extensions: set[str], label: str) -> Evaluator:
    def evaluator(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
        hits = []
        for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
            extension = Path(str(row["original_filename"] or "")).suffix.lower()
            if extension in extensions:
                hits.append(str(row["original_filename"] or "[unnamed]"))
        return _yes(f"At least one attachment is classified by filename as {label}.", evidence="; ".join(hits), source="attachments.original_filename") if hits else _no(f"No attachment filename matched the {label} list.", source="attachments.original_filename")
    return evaluator


def _html_required(message: Any) -> tuple[str | None, dict[str, Any] | None]:
    html = str(_message_value(message, "body_html", "") or "")
    if not html.strip():
        return None, _unknown("No stored HTML body is available.", source="messages.body_html")
    return html, None


def eval_html_form(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    html, error = _html_required(message)
    if error:
        return error
    forms = len(re.findall(r"<\s*form\b", html or "", re.I))
    inputs = len(re.findall(r"<\s*(?:input|textarea|select|button)\b", html or "", re.I))
    passwords = len(re.findall(r"<\s*input\b[^>]*\btype\s*=\s*['\"]?password\b", html or "", re.I))
    evidence = f"form_count={forms}; input_control_count={inputs}; password_field_count={passwords}"
    return _yes("The stored HTML body contains an embedded form.", evidence=evidence, source="messages.body_html") if forms else _no("No form element was found in the stored HTML body.", evidence=evidence, source="messages.body_html")


def eval_html_auto_redirect(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    html, error = _html_required(message)
    if error:
        return error
    matches = re.findall(r"<\s*meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", html or "", re.I)
    return _yes("The stored HTML body contains a meta-refresh automatic redirect.", evidence=" | ".join(matches[:10]), source="messages.body_html") if matches else _no("No supported automatic redirect was found in the stored HTML body.", source="messages.body_html")


def eval_html_embedded_active_object(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    html, error = _html_required(message)
    if error:
        return error
    tags = re.findall(r"<\s*(iframe|frame|object|embed|applet)\b", html or "", re.I)
    return _yes("The stored HTML contains an embedded frame or active-object element.", evidence="elements=" + ";".join(tag.lower() for tag in tags), source="messages.body_html") if tags else _no("No embedded frame or active-object element was found.", source="messages.body_html")


def eval_html_script(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    html, error = _html_required(message)
    if error:
        return error
    scripts = len(re.findall(r"<\s*script\b", html or "", re.I))
    evidence = f"script_elements={scripts}"
    return _yes("The stored HTML contains one or more script elements.", evidence=evidence, source="messages.body_html") if scripts else _no("No script elements were found.", evidence=evidence, source="messages.body_html")


def eval_html_event_handlers(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    html, error = _html_required(message)
    if error:
        return error
    handlers = re.findall(r"\s(on[a-z0-9_-]+)\s*=", html or "", re.I)
    evidence = f"event_handlers={';'.join(sorted(set(item.lower() for item in handlers)))}"
    return _yes("The stored HTML contains inline JavaScript event-handler attributes.", evidence=evidence, source="messages.body_html") if handlers else _no("No inline event-handler attributes were found.", evidence=evidence, source="messages.body_html")


def eval_html_script_or_event_handlers(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    """Backward-compatible combined evaluator for imported 1.0.0 configs."""
    script = eval_html_script(conn, message, config)
    events = eval_html_event_handlers(conn, message, config)
    if script["answer"] == "YES" or events["answer"] == "YES":
        return _yes("The stored HTML contains script code or inline event handlers.", evidence=f"{script.get('evidence','')}; {events.get('evidence','')}", source="messages.body_html")
    if script["answer"] == "UNKNOWN" and events["answer"] == "UNKNOWN":
        return script
    return _no("No script elements or inline event-handler attributes were found.", evidence=f"{script.get('evidence','')}; {events.get('evidence','')}", source="messages.body_html")


def eval_return_path_domain_mismatch(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    from_domain = _address_domain(_message_value(message, "from_address"))
    return_domain = _address_domain(_message_value(message, "return_path"))
    if not from_domain or not return_domain:
        return _unknown("From or Return-Path did not contain a usable domain.")
    evidence = f"from_domain={from_domain}; return_path_domain={return_domain}"
    return _yes("Return-Path and From use different registrable domains.", evidence=evidence) if from_domain != return_domain else _no("Return-Path and From use the same registrable domain.", evidence=evidence)


def _history_date_and_sha(message: Any) -> tuple[str | None, str]:
    return _selected_date(message), str(_message_value(message, "message_sha256", "") or "")


def eval_sender_address_new(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address(_message_value(message, "from_address"))
    date, sha = _history_date_and_sha(message)
    if not sender:
        return _unknown("The sender address is unavailable.")
    if not date:
        return _unknown("The message lacks a usable date for historical comparison.")
    count = int(conn.execute(
        "SELECT COUNT(*) FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL "
        "AND selected_date_utc<? AND from_address_normalized=?",
        (sha, date, sender),
    ).fetchone()[0])
    evidence = f"sender={sender}; earlier_matches={count}"
    return _yes("No earlier distinct message from this sender address exists in the case.", evidence=evidence) if count == 0 else _no("This sender address appeared in an earlier case message.", evidence=evidence)


def eval_sender_domain_new(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    domain = _address_domain(_message_value(message, "from_address"))
    date, sha = _history_date_and_sha(message)
    if not domain:
        return _unknown("The sender domain is unavailable.")
    if not date:
        return _unknown("The message lacks a usable date for historical comparison.")
    count = int(conn.execute(
        "SELECT COUNT(*) FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL "
        "AND selected_date_utc<? AND from_domain_registrable=?",
        (sha, date, domain),
    ).fetchone()[0])
    evidence = f"sender_domain={domain}; earlier_matches={count}"
    return _yes("No earlier distinct message from this sender domain exists in the case.", evidence=evidence) if count == 0 else _no("This sender domain appeared in an earlier case message.", evidence=evidence)


def _trusted_boundary_ips(conn, message_sha256: str) -> set[str]:
    ips: set[str] = set()
    rows = conn.execute(
        "SELECT sender_ips_json FROM received_hops WHERE message_sha256=? AND trusted=1 ORDER BY hop_order LIMIT 1",
        (message_sha256,),
    ).fetchall()
    for row in rows:
        try:
            values = json.loads(row["sender_ips_json"] or "[]")
        except (TypeError, ValueError):
            values = []
        ips.update(str(item).strip() for item in values if str(item).strip())
    return ips


def _historical_trusted_boundary_ips(conn, *, sender: str, before_date: str, exclude_sha: str) -> set[str]:
    return {
        str(row[0]).strip()
        for row in conn.execute(
            """SELECT DISTINCT je.value
               FROM messages m
               JOIN received_hops rh ON rh.message_sha256=m.message_sha256
               JOIN json_each(rh.sender_ips_json) AS je
               WHERE m.message_sha256<>? AND m.selected_date_utc IS NOT NULL AND m.selected_date_utc<?
                 AND m.from_address_normalized=? AND rh.trusted=1
                 AND rh.hop_order=(
                     SELECT MIN(rh2.hop_order) FROM received_hops rh2
                     WHERE rh2.message_sha256=m.message_sha256 AND rh2.trusted=1
                 )""",
            (exclude_sha, before_date, sender),
        )
        if str(row[0]).strip()
    }


def eval_sender_ip_new_for_sender(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address(_message_value(message, "from_address"))
    date, sha = _history_date_and_sha(message)
    current = _trusted_boundary_ips(conn, sha)
    if not sender or not current:
        return _unknown("A sender address or inferred trusted-boundary IP is unavailable.")
    if not date:
        return _unknown("The message lacks a usable date for historical comparison.")
    prior_rows = conn.execute(
        "SELECT message_sha256 FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL "
        "AND selected_date_utc<? AND from_address_normalized=?",
        (sha, date, sender),
    ).fetchall()
    if not prior_rows:
        return _unknown("The sender has no earlier case history for an infrastructure comparison.")
    previous = _historical_trusted_boundary_ips(conn, sender=sender, before_date=date, exclude_sha=sha)
    if not previous:
        return _unknown("Earlier messages from this sender have no inferred trusted-boundary IP classification.")
    unseen = sorted(current - previous)
    evidence = f"sender={sender}; current_ips={';'.join(sorted(current))}; previous_ips={';'.join(sorted(previous))}; unseen_ips={';'.join(unseen)}"
    return _yes("The current trusted-boundary IP has not been observed previously for this sender.", evidence=evidence) if unseen else _no("The current trusted-boundary IP was previously observed for this sender.", evidence=evidence)


def _new_header_value_for_sender(field: str, compare_domain: bool = False) -> Evaluator:
    allowed = {"reply_to", "return_path"}
    if field not in allowed:
        raise ValueError(f"Unsupported historical header field: {field}")

    def evaluator(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
        sender = _address(_message_value(message, "from_address"))
        raw_current = _message_value(message, field)
        current = _address_domain(raw_current) if compare_domain else _address(raw_current)
        date, sha = _history_date_and_sha(message)
        if not sender or not current:
            return _unknown(f"A sender address or current {field.replace('_', ' ')} value is unavailable.")
        if not date:
            return _unknown("The message lacks a usable date for historical comparison.")
        rows = conn.execute(
            f"SELECT {field} FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL "
            "AND selected_date_utc<? AND from_address_normalized=?",
            (sha, date, sender),
        ).fetchall()
        if not rows:
            return _unknown("The sender has no earlier case history for comparison.")
        previous = set()
        for row in rows:
            value = _address_domain(row[field]) if compare_domain else _address(row[field])
            if value:
                previous.add(value)
        if not previous:
            return _unknown(f"Earlier messages from this sender have no usable {field.replace('_', ' ')} values.")
        evidence = f"sender={sender}; current={current}; previous={';'.join(sorted(previous))}"
        return _yes(f"The current {field.replace('_', ' ')} value is new for this sender.", evidence=evidence) if current not in previous else _no(f"The current {field.replace('_', ' ')} value was previously observed for this sender.", evidence=evidence)
    return evaluator


def eval_reply_to_new_for_sender(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address(_message_value(message, "from_address"))
    current = _address(_message_value(message, "reply_to"))
    if not sender or not current:
        return _unknown("A sender address or Reply-To address is unavailable.")
    if current == sender:
        return _no("The Reply-To address matches the visible sender address.", evidence=f"sender={sender}; reply_to={current}")
    return _new_header_value_for_sender("reply_to", compare_domain=False)(conn, message, _config)

def eval_sender_free_email_provider(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    domain = _address_domain(_message_value(message, "from_address"))
    if not domain:
        return _unknown("The sender domain is unavailable.")
    evidence = f"sender_domain={domain}; provider_list_version={FREE_EMAIL_LIST_VERSION}"
    return _yes("The sender uses a domain in Threadsaw's bundled common free-email provider list.", evidence=evidence) if domain in FREE_EMAIL_DOMAINS else _no("The sender domain is not in Threadsaw's bundled common free-email provider list.", evidence=evidence)


def eval_sender_domain_punycode(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    address = _address(_message_value(message, "from_address"))
    if not address or "@" not in address:
        return _unknown("The sender domain is unavailable.")
    domain = address.rsplit("@", 1)[1].lower()
    labels = [label for label in domain.split(".") if label.startswith("xn--")]
    decoded = ""
    if labels:
        try:
            decoded = domain.encode("ascii").decode("idna")
        except UnicodeError:
            decoded = "[decode failed]"
    evidence = f"sender_domain={domain}; punycode_labels={';'.join(labels)}; decoded={decoded}"
    return _yes("The sender domain contains one or more Punycode labels.", evidence=evidence) if labels else _no("The sender domain contains no Punycode labels.", evidence=evidence)


def eval_sender_header_mismatch(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender_header = _header(message, "Sender")
    if not sender_header:
        return _unknown("No Sender header is present.", source="messages.raw_headers_text")
    sender_address = _address(sender_header)
    from_address = _address(_message_value(message, "from_address"))
    if not sender_address or not from_address:
        return _unknown("Sender or From could not be parsed.", source="messages.raw_headers_text")
    evidence = f"from={from_address}; sender_header={sender_address}; from_domain={_address_domain(from_address)}; sender_domain={_address_domain(sender_address)}"
    return _yes("The Sender header address differs from the visible From address.", evidence=evidence, source="messages.raw_headers_text") if sender_address != from_address else _no("The Sender header address matches the visible From address.", evidence=evidence, source="messages.raw_headers_text")


def _corroborated_thread_match(
    conn,
    message: Any,
    *,
    require_subject: bool = True,
) -> tuple[Any | None, set[str], bool | None, str | None]:
    references = _message_ids_from_headers(message)
    if not references:
        return None, set(), None, "No usable In-Reply-To or References Message-ID is present."
    date, sha = _history_date_and_sha(message)
    if not date:
        return None, set(), None, "The candidate message lacks a usable date."
    placeholders = ",".join("?" for _ in references)
    rows = conn.execute(
        f"SELECT message_sha256,internet_message_id,subject,normalized_subject,from_address,from_address_normalized,reply_to,return_path,selected_date_utc "
        f"FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL AND selected_date_utc<? "
        f"AND LOWER(internet_message_id) IN ({placeholders}) ORDER BY selected_date_utc DESC",
        (sha, date, *references),
    ).fetchall()
    candidate_subject = str(_message_value(message, "normalized_subject", "") or _normalize_subject(_message_value(message, "subject")))
    candidate_participants = _message_participants(conn, message)
    for prior in rows:
        prior_subject = str(prior["normalized_subject"] or _normalize_subject(prior["subject"]))
        subject_ok = bool(candidate_subject and candidate_subject == prior_subject)
        overlap = candidate_participants & _message_participants(conn, prior)
        if overlap and (subject_ok or not require_subject):
            return prior, overlap, subject_ok, None
    requirement = "both subject continuity and participant overlap" if require_subject else "participant overlap"
    return None, set(), None, f"Thread-reference values did not produce an earlier-message match with {requirement}."


def eval_corroborated_thread_reply(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    prior, overlap, _subject_ok, reason = _corroborated_thread_match(conn, message)
    if prior:
        subject = str(_message_value(message, "normalized_subject", "") or _normalize_subject(_message_value(message, "subject")))
        evidence = f"matched_message={prior['message_sha256']}; matched_message_id={prior['internet_message_id']}; participant_overlap={';'.join(sorted(overlap))}; normalized_subject={subject}"
        return _yes("Thread references match an earlier message with plausible subject continuity and participant overlap.", evidence=evidence)
    if reason and reason.startswith("No usable"):
        return _unknown(reason, source="messages.raw_headers_text")
    if reason and "lacks a usable date" in reason:
        return _unknown(reason)
    return _no(reason or "No corroborated thread match was found.", evidence=f"references={';'.join(_message_ids_from_headers(message))}")


def eval_thread_continuation_changed_infrastructure(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    # For infrastructure-change detection, an exact Message-ID reference plus
    # participant overlap is the strong thread-continuation evidence. Subject
    # continuity is recorded but is not required because hijackers commonly
    # append urgency or payment language to a legitimate thread subject.
    prior, overlap, subject_ok, reason = _corroborated_thread_match(
        conn,
        message,
        require_subject=False,
    )
    if not prior:
        if reason and (reason.startswith("No usable") or "lacks a usable date" in reason):
            return _unknown(reason)
        return _no("The message is not a corroborated continuation of an earlier case thread.", evidence=reason or "")
    sender = _address(_message_value(message, "from_address"))
    date, sha = _history_date_and_sha(message)
    current_reply = _address_domain(_message_value(message, "reply_to"))
    current_return = _address_domain(_message_value(message, "return_path"))
    current_ips = _trusted_boundary_ips(conn, sha)
    counterparts = set(_recipient_addresses(conn, sha))
    history_rows = []
    if sender and date and counterparts:
        placeholders = ",".join("?" for _ in counterparts)
        history_rows = conn.execute(
            f"""SELECT DISTINCT m.message_sha256,m.reply_to,m.return_path
                 FROM messages m JOIN recipients r ON r.message_sha256=m.message_sha256
                 WHERE m.message_sha256<>? AND m.selected_date_utc IS NOT NULL AND m.selected_date_utc<?
                   AND m.from_address_normalized=? AND LOWER(r.email_address) IN ({placeholders})""",
            (sha, date, sender, *sorted(counterparts)),
        ).fetchall()
    previous_reply = {_address_domain(row["reply_to"]) for row in history_rows if _address_domain(row["reply_to"])}
    previous_return = {_address_domain(row["return_path"]) for row in history_rows if _address_domain(row["return_path"])}
    history_ids = [row["message_sha256"] for row in history_rows]
    previous_ips: set[str] = set()
    for history_batch in chunked(history_ids):
        placeholders = ",".join("?" for _ in history_batch)
        previous_ips.update(
            str(row[0]).strip()
            for row in conn.execute(
                f"""SELECT DISTINCT je.value FROM received_hops rh JOIN json_each(rh.sender_ips_json) AS je
                     WHERE rh.message_sha256 IN ({placeholders}) AND rh.trusted=1
                       AND rh.hop_order=(SELECT MIN(rh2.hop_order) FROM received_hops rh2
                                        WHERE rh2.message_sha256=rh.message_sha256 AND rh2.trusted=1)""",
                history_batch,
            )
            if str(row[0]).strip()
        )
    changed: list[str] = []
    if current_reply and previous_reply and current_reply not in previous_reply:
        changed.append(f"reply_to_domain={current_reply}")
    if current_return and previous_return and current_return not in previous_return:
        changed.append(f"return_path_domain={current_return}")
    unseen_ips = sorted(current_ips - previous_ips) if current_ips and previous_ips else []
    if unseen_ips:
        changed.append(f"new_trusted_boundary_ips={';'.join(unseen_ips)}")
    evidence = (
        f"matched_thread_message={prior['message_sha256']}; participant_overlap={';'.join(sorted(overlap))}; "
        f"subject_continuity={'yes' if subject_ok else 'no'}; counterparts={';'.join(sorted(counterparts))}; "
        f"current_reply_to_domain={current_reply or ''}; prior_reply_to_domains={';'.join(sorted(previous_reply))}; "
        f"current_return_path_domain={current_return or ''}; prior_return_path_domains={';'.join(sorted(previous_return))}; "
        f"current_trusted_boundary_ips={';'.join(sorted(current_ips))}; prior_trusted_boundary_ips={';'.join(sorted(previous_ips))}; "
        f"changes={' | '.join(changed)}"
    )
    if changed:
        return _yes("A corroborated thread continuation uses sender infrastructure not previously observed for that sender/counterpart context.", evidence=evidence, source="messages, recipients, and received_hops")
    if not any((current_reply and previous_reply, current_return and previous_return, current_ips and previous_ips)):
        return _unknown("The thread was corroborated, but no comparable historical Reply-To, Return-Path, or inferred trusted-boundary IP evidence is available.", evidence=evidence, source="messages, recipients, and received_hops")
    return _no("The corroborated thread continuation uses previously observed sender infrastructure.", evidence=evidence, source="messages, recipients, and received_hops")


def eval_prior_sender_recipient(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address(_message_value(message, "from_address"))
    recipients = set(_recipient_addresses(conn, _message_value(message, "message_sha256")))
    date, sha = _history_date_and_sha(message)
    if not sender or not recipients:
        return _unknown("A usable sender or recipient address is unavailable.")
    if not date:
        return _unknown("The message lacks a usable date for historical comparison.")
    placeholders = ",".join("?" for _ in recipients)
    count = int(conn.execute(
        f"SELECT COUNT(DISTINCT m.message_sha256) FROM messages m JOIN recipients r ON r.message_sha256=m.message_sha256 "
        f"WHERE m.message_sha256<>? AND m.selected_date_utc IS NOT NULL AND m.selected_date_utc<? "
        f"AND m.from_address_normalized=? AND LOWER(r.email_address) IN ({placeholders})",
        (sha, date, sender, *sorted(recipients)),
    ).fetchone()[0])
    evidence = f"sender={sender}; recipients={';'.join(sorted(recipients))}; earlier_relationship_messages={count}"
    return _yes("An earlier message contains the same sender and at least one matching recipient.", evidence=evidence) if count else _no("No earlier sender-recipient relationship was found.", evidence=evidence)


def eval_prior_sender_subject(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address(_message_value(message, "from_address"))
    subject = str(_message_value(message, "normalized_subject", "") or _normalize_subject(_message_value(message, "subject")))
    date, sha = _history_date_and_sha(message)
    if not sender or not subject:
        return _unknown("A usable sender or normalized subject is unavailable.")
    if not date:
        return _unknown("The message lacks a usable date for historical comparison.")
    count = int(conn.execute(
        "SELECT COUNT(*) FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL AND selected_date_utc<? "
        "AND from_address_normalized=? AND normalized_subject=?",
        (sha, date, sender, subject),
    ).fetchone()[0])
    evidence = f"sender={sender}; normalized_subject={subject}; earlier_matches={count}"
    return _yes("An earlier message has the same sender and normalized subject.", evidence=evidence) if count else _no("No earlier sender and normalized-subject pair was found.", evidence=evidence)


def eval_reply_subject_without_references(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    subject = str(_message_value(message, "subject", "") or "")
    reply_like = bool(REPLY_PREFIX_RE.match(subject))
    references = _message_ids_from_headers(message)
    evidence = f"subject={subject}; thread_references={';'.join(references)}"
    if not reply_like:
        return _no("The subject does not begin with a recognized reply prefix.", evidence=evidence, source="messages.subject and raw_headers_text")
    return _no("A reply-style subject has thread-reference metadata.", evidence=evidence, source="messages.subject and raw_headers_text") if references else _yes("The subject appears to be a reply but no In-Reply-To or References Message-ID is present.", evidence=evidence, source="messages.subject and raw_headers_text")


def eval_unmatched_thread_references(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    references = _message_ids_from_headers(message)
    if not references:
        return _unknown("No usable thread-reference Message-ID is present.", source="messages.raw_headers_text")
    date, sha = _history_date_and_sha(message)
    if not date:
        return _unknown("The candidate message lacks a usable date.")
    placeholders = ",".join("?" for _ in references)
    matches = [str(row[0]).casefold() for row in conn.execute(
        f"SELECT internet_message_id FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL "
        f"AND selected_date_utc<? AND LOWER(internet_message_id) IN ({placeholders})",
        (sha, date, *references),
    ).fetchall()]
    evidence = f"references={';'.join(references)}; matching_earlier_ids={';'.join(sorted(matches))}"
    return _no("At least one thread-reference Message-ID matches an earlier message in the case.", evidence=evidence) if matches else _yes("Thread-reference headers are present, but none match an earlier case message.", evidence=evidence)


def eval_authentication_conflict(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    rows = _auth_rows(conn, _message_value(message, "message_sha256"))
    if len(rows) < 2:
        return _unknown("Fewer than two Authentication-Results records are available.", source="authentication_results")
    conflicts: list[str] = []
    for check in ("spf", "dkim", "dmarc", "arc"):
        values = {str(row[f"{check}_result"] or "").lower() for row in rows if row[f"{check}_result"]}
        pass_present = "pass" in values
        fail_present = bool(values & {"fail", "softfail", "permerror", "temperror"})
        if pass_present and fail_present:
            conflicts.append(f"{check}={','.join(sorted(values))}")
    evidence = " | ".join(
        f"authserv={row['authserv_id'] or ''}; trusted={int(bool(row['trusted']))}; spf={row['spf_result'] or ''}; dkim={row['dkim_result'] or ''}; dmarc={row['dmarc_result'] or ''}; arc={row['arc_result'] or ''}"
        for row in rows
    )
    return _yes("Authentication-Results headers contain a material pass/failure contradiction.", evidence=f"conflicts={';'.join(conflicts)} | {evidence}", source="authentication_results") if conflicts else _no("No direct pass/failure contradiction was found across Authentication-Results records.", evidence=evidence, source="authentication_results")


def eval_date_received_discrepancy(_conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    threshold = _integer_parameter(config, "threshold_hours", 24)
    if threshold is None or threshold < 0:
        return _unknown("The configured threshold is not a valid non-negative integer.", status="invalid-config")
    discrepancy = _message_value(message, "date_discrepancy_seconds")
    trusted = _message_value(message, "trusted_received_utc")
    header = _message_value(message, "header_date_utc")
    if discrepancy is None or not trusted or not header:
        return _unknown("A trusted Received timestamp and parsed Date header are required.")
    absolute = abs(int(discrepancy))
    limit = threshold * 3600
    evidence = f"header_date_utc={header}; trusted_received_utc={trusted}; difference_seconds={absolute}; threshold_hours={threshold}"
    return _yes("The absolute Date/Received difference meets or exceeds the configured threshold.", evidence=evidence) if absolute >= limit else _no("The Date/Received difference is below the configured threshold.", evidence=evidence)


def eval_message_id_missing_or_malformed(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    value = str(_message_value(message, "internet_message_id", "") or "").strip()
    if not value:
        return _yes("The message has no stored RFC Message-ID.", evidence="message_id=[missing]", source="messages.internet_message_id")
    return _no("The stored Message-ID has a conservative valid structure.", evidence=f"message_id={value}", source="messages.internet_message_id") if MESSAGE_ID_RE.fullmatch(value) else _yes("The stored Message-ID is structurally malformed.", evidence=f"message_id={value}", source="messages.internet_message_id")


def _message_id_domain(value: str | None) -> str | None:
    text = str(value or "").strip().strip("<>")
    return _registrable(text.rsplit("@", 1)[1]) if "@" in text else None


def eval_message_id_domain_mismatch(_conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    from_domain = _address_domain(_message_value(message, "from_address"))
    message_id = _message_value(message, "internet_message_id")
    message_id_domain = _message_id_domain(message_id)
    if not from_domain or not message_id_domain:
        return _unknown("A usable From domain or Message-ID domain is unavailable.")
    evidence = f"from_domain={from_domain}; message_id_domain={message_id_domain}; message_id={message_id}"
    return _yes("The Message-ID domain differs from the visible From domain.", evidence=evidence) if from_domain != message_id_domain else _no("The Message-ID domain matches the visible From domain.", evidence=evidence)


def _normalize_host_parameter(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if "://" in text:
        text = urlsplit(text).hostname or ""
    return text.strip(". ") or None


def _sharepoint_rows(conn, message: Any) -> tuple[list[Any] | None, str | None]:
    rows, error = _url_rows(conn, message)
    if rows is None:
        return None, error
    return [row for row in rows if bool(row["is_sharepoint"]) or "sharepoint" in str(row["raw_url"] or "").lower()], None


def eval_sharepoint_host_mismatch(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    legitimate = _normalize_host_parameter(_parameter(config, "legitimate_sharepoint_host", ""))
    if not legitimate:
        return _unknown("No legitimate SharePoint host was configured.", status="unavailable-config")
    rows, error = _sharepoint_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    mismatches: list[str] = []
    for row in rows:
        for _variant, value in _url_variants(row):
            host = _url_host(value)
            if host and host != legitimate and not host.endswith("." + legitimate):
                mismatches.append(host)
    evidence = f"legitimate_host={legitimate}; mismatched_hosts={';'.join(sorted(set(mismatches)))}"
    return _yes("At least one SharePoint-referencing URL does not match the configured legitimate host.", evidence=evidence, source="urls") if mismatches else _no("No SharePoint-referencing URL mismatches the configured legitimate host.", evidence=evidence, source="urls")


def eval_external_sharepoint_tenant_new(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    legitimate = _normalize_host_parameter(_parameter(config, "legitimate_sharepoint_host", ""))
    if not legitimate:
        return _unknown("No legitimate SharePoint host was configured.", status="unavailable-config")
    rows, error = _sharepoint_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    current_hosts = {
        host for row in rows for _variant, value in _url_variants(row)
        if (host := _url_host(value)) and host != legitimate and not host.endswith("." + legitimate)
    }
    if not current_hosts:
        return _no("No mismatched SharePoint host is present in this message.", source="urls")
    date = _selected_date(message)
    if not date:
        return _unknown("The candidate message lacks a usable date for historical comparison.")
    previous = {
        str(row["hostname"] or "").lower()
        for row in conn.execute(
            """SELECT DISTINCT u.hostname FROM urls u JOIN messages m ON m.message_sha256=u.message_sha256
               WHERE m.message_sha256<>? AND m.selected_date_utc IS NOT NULL AND m.selected_date_utc<?
                 AND u.is_sharepoint=1 AND u.hostname IS NOT NULL""",
            (_message_value(message, "message_sha256"), date),
        )
    }
    new_hosts = sorted(current_hosts - previous)
    evidence = f"legitimate_host={legitimate}; current_external_hosts={';'.join(sorted(current_hosts))}; previous_sharepoint_hosts={';'.join(sorted(previous))}"
    return _yes("At least one mismatched SharePoint host is newly observed in the case.", evidence=evidence, source="urls and messages") if new_hosts else _no("All mismatched SharePoint hosts appeared in an earlier case message.", evidence=evidence, source="urls and messages")


def eval_exact_url_count(_conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    expected = _integer_parameter(config, "expected_count", 0)
    if expected is None or expected < 0:
        return _unknown("The expected URL count is not a valid non-negative integer.", status="invalid-config")
    if not int(_message_value(message, "url_indexed", 0) or 0):
        return _unknown("URL indexing has not been completed for this message.")
    observed = int(_message_value(message, "url_count", 0) or 0)
    evidence = f"expected_count={expected}; observed_count={observed}"
    return _yes("The complete stored URL count exactly matches the configured count.", evidence=evidence, source="messages.url_count") if observed == expected else _no("The complete stored URL count does not match the configured count.", evidence=evidence, source="messages.url_count")


def eval_url_shortener(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits = []
    for row in rows:
        for variant, value in _url_variants(row):
            host = _url_host(value)
            if host and (host in SHORTENER_HOSTS or any(host.endswith("." + item) for item in SHORTENER_HOSTS)):
                hits.append(f"host={host}; {variant}_url={value}")
    evidence = f"shortener_list_version={SHORTENER_LIST_VERSION}; matches={' | '.join(hits)}"
    return _yes("At least one URL uses a hostname in Threadsaw's bundled shortener list.", evidence=evidence, source="urls") if hits else _no("No stored URL uses a hostname in Threadsaw's bundled shortener list.", evidence=evidence, source="urls")


def eval_url_punycode(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits = []
    for row in rows:
        for variant, value in _url_variants(row):
            host = _url_host(value)
            if host and any(label.startswith("xn--") for label in host.split(".")):
                try:
                    decoded = host.encode("ascii").decode("idna")
                except UnicodeError:
                    decoded = "[decode failed]"
                hits.append(f"host={host}; decoded={decoded}; {variant}_url={value}")
    return _yes("At least one URL hostname contains a Punycode label.", evidence=" | ".join(hits), source="urls") if hits else _no("No stored URL hostname contains a Punycode label.", source="urls")


def _current_url_domains(conn, message: Any) -> tuple[set[str] | None, str | None]:
    rows, error = _url_rows(conn, message)
    if rows is None:
        return None, error
    domains = {str(row["effective_registrable_domain"] or "").strip().lower() for row in rows}
    domains.discard("")
    if not domains:
        domains = {_url_domain(value) for row in rows for _variant, value in _url_variants(row)}
        domains = {domain for domain in domains if domain}
    return domains, None


def eval_url_domain_new_case(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    current, error = _current_url_domains(conn, message)
    if current is None:
        return _unknown(error or "URL data unavailable.")
    if not current:
        return _no("The message contains no usable URL destination domain.", source="urls")
    date, sha = _history_date_and_sha(message)
    if not date:
        return _unknown("The candidate message lacks a usable date for historical comparison.")
    placeholders = ",".join("?" for _ in current)
    previous = {str(row[0]).lower() for row in conn.execute(
        f"SELECT DISTINCT u.effective_registrable_domain FROM urls u JOIN messages m ON m.message_sha256=u.message_sha256 "
        f"WHERE m.message_sha256<>? AND m.selected_date_utc IS NOT NULL AND m.selected_date_utc<? "
        f"AND u.effective_registrable_domain IN ({placeholders})",
        (sha, date, *sorted(current)),
    ).fetchall() if row[0]}
    new = sorted(current - previous)
    evidence = f"current_domains={';'.join(sorted(current))}; previously_observed={';'.join(sorted(previous))}; newly_observed={';'.join(new)}"
    return _yes("At least one URL destination domain is newly observed in the case.", evidence=evidence, source="urls and messages") if new else _no("All URL destination domains appeared in earlier case messages.", evidence=evidence, source="urls and messages")


def eval_url_domain_new_sender(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address(_message_value(message, "from_address"))
    current, error = _current_url_domains(conn, message)
    if current is None:
        return _unknown(error or "URL data unavailable.")
    if not current:
        return _no("The message contains no usable URL destination domain.", source="urls")
    if not sender:
        return _unknown("The sender address is unavailable.")
    date, sha = _history_date_and_sha(message)
    if not date:
        return _unknown("The candidate message lacks a usable date.")
    prior_count = int(conn.execute(
        "SELECT COUNT(*) FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL "
        "AND selected_date_utc<? AND from_address_normalized=?",
        (sha, date, sender),
    ).fetchone()[0])
    if not prior_count:
        return _unknown("The sender has no earlier case history.")
    placeholders = ",".join("?" for _ in current)
    previous = {str(row[0]).lower() for row in conn.execute(
        f"SELECT DISTINCT u.effective_registrable_domain FROM urls u JOIN messages m ON m.message_sha256=u.message_sha256 "
        f"WHERE m.message_sha256<>? AND m.selected_date_utc IS NOT NULL AND m.selected_date_utc<? "
        f"AND m.from_address_normalized=? AND u.effective_registrable_domain IN ({placeholders})",
        (sha, date, sender, *sorted(current)),
    ).fetchall() if row[0]}
    new = sorted(current - previous)
    evidence = f"sender={sender}; current_domains={';'.join(sorted(current))}; previously_observed={';'.join(sorted(previous))}; newly_observed={';'.join(new)}"
    return _yes("At least one URL destination domain is newly observed for this sender.", evidence=evidence, source="urls and messages") if new else _no("All URL destination domains appeared in earlier messages from this sender.", evidence=evidence, source="urls and messages")


def eval_url_deep_subdomains(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    minimum = _integer_parameter(config, "minimum_depth", 4)
    if minimum is None or minimum < 1:
        return _unknown("The minimum subdomain depth is invalid.", status="invalid-config")
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits = []
    for row in rows:
        for variant, value in _url_variants(row):
            host = _url_host(value)
            registrable = _registrable(host)
            if not host or not registrable:
                continue
            host_labels = host.split(".")
            reg_labels = registrable.split(".")
            depth = max(0, len(host_labels) - len(reg_labels))
            if host_labels and host_labels[0] == "www":
                depth = max(0, depth - 1)
            if depth >= minimum:
                hits.append(f"host={host}; registrable_domain={registrable}; depth={depth}; {variant}_url={value}")
    return _yes("At least one URL hostname meets or exceeds the configured subdomain depth.", evidence=" | ".join(hits), source="urls") if hits else _no("No stored URL hostname meets the configured subdomain depth.", source="urls")


def eval_url_nested_url(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits = []
    for row in rows:
        for variant, value in _url_variants(row):
            try:
                parts = urlsplit(value)
            except ValueError:
                continue
            values = [item for _key, item in parse_qsl(parts.query, keep_blank_values=True)] + [parts.fragment]
            for nested in values:
                current = nested
                for depth in range(3):
                    if re.search(r"https?://", current, re.I):
                        match = re.search(r"https?://[^\s<>'\"]+", current, re.I)
                        if match:
                            hits.append(f"outer={value}; nested={match.group(0)}; decode_depth={depth}; variant={variant}")
                            break
                    decoded = unquote(current)
                    if decoded == current:
                        break
                    current = decoded
    return _yes("At least one URL contains another complete HTTP(S) URL in its query string or fragment.", evidence=" | ".join(hits), source="urls") if hits else _no("No nested complete HTTP(S) URL was found in stored URL query strings or fragments.", source="urls")


def _plain_http_predicate(value: str) -> tuple[bool, str]:
    try:
        scheme = urlsplit(value).scheme.lower()
    except ValueError:
        return False, ""
    return (scheme == "http", f"url={value}")


def eval_url_heavy_percent_encoding(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    minimum = _integer_parameter(config, "minimum_sequences", 8)
    if minimum is None or minimum < 1:
        return _unknown("The minimum percent-encoding sequence count is invalid.", status="invalid-config")
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits = []
    for row in rows:
        for variant, value in _url_variants(row):
            count = len(PERCENT_RE.findall(value))
            if count >= minimum:
                hits.append(f"count={count}; threshold={minimum}; {variant}_url={value}")
    return _yes("At least one URL meets or exceeds the configured percent-encoding threshold.", evidence=" | ".join(hits), source="urls") if hits else _no("No stored URL meets the configured percent-encoding threshold.", source="urls")


def eval_url_base64_like(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    minimum = _integer_parameter(config, "minimum_length", 40)
    if minimum is None or minimum < 8:
        return _unknown("The minimum Base64-like value length is invalid.", status="invalid-config")
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits = []
    for row in rows:
        for variant, value in _url_variants(row):
            try:
                parts = urlsplit(value)
            except ValueError:
                continue
            haystacks = [parts.path, parts.query, parts.fragment]
            for location, text in zip(("path", "query", "fragment"), haystacks):
                for match in BASE64_RE.findall(text or ""):
                    if len(match) < minimum:
                        continue
                    preview = ""
                    candidate = match.replace("-", "+").replace("_", "/")
                    candidate += "=" * ((4 - len(candidate) % 4) % 4)
                    try:
                        decoded = base64.b64decode(candidate, validate=False)
                        preview = decoded[:48].decode("utf-8", errors="replace")
                    except (binascii.Error, ValueError):
                        pass
                    hits.append(f"location={location}; length={len(match)}; decoded_preview={preview!r}; {variant}_url={value}")
    return _yes("At least one URL contains a Base64-like value meeting the configured length.", evidence=" | ".join(hits), source="urls") if hits else _no("No stored URL contains a Base64-like value meeting the configured length.", source="urls")


def eval_url_contains_recipient_email(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    recipients = _recipient_addresses(conn, _message_value(message, "message_sha256"))
    if not recipients:
        return _unknown("No usable recipient address is available.")
    rows, error = _url_rows(conn, message)
    if rows is None:
        return _unknown(error or "URL data unavailable.")
    hits = []
    for row in rows:
        for variant, value in _url_variants(row):
            decoded_values = [value]
            for _ in range(2):
                decoded_values.append(unquote(decoded_values[-1]))
            combined = "\n".join(decoded_values).casefold()
            for recipient in recipients:
                if recipient.casefold() in combined:
                    hits.append(f"recipient={recipient}; {variant}_url={value}")
    return _yes("At least one stored URL contains a complete recipient email address.", evidence=" | ".join(hits), source="urls and recipients") if hits else _no("No stored URL contains a complete recorded recipient email address.", source="urls and recipients")


def eval_url_domain_differs_sender(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address_domain(_message_value(message, "from_address"))
    if not sender:
        return _unknown("The sender domain is unavailable.")
    domains, error = _current_url_domains(conn, message)
    if domains is None:
        return _unknown(error or "URL data unavailable.")
    if not domains:
        return _no("The message contains no usable URL destination domain.", source="urls")
    mismatches = sorted(domain for domain in domains if domain != sender)
    evidence = f"sender_domain={sender}; destination_domains={';'.join(sorted(domains))}; mismatches={';'.join(mismatches)}"
    return _yes("At least one URL destination domain differs from the sender domain.", evidence=evidence, source="urls") if mismatches else _no("All usable URL destination domains match the sender domain.", evidence=evidence, source="urls")


def eval_exact_attachment_count(_conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    expected = _integer_parameter(config, "expected_count", 0)
    if expected is None or expected < 0:
        return _unknown("The expected attachment count is invalid.", status="invalid-config")
    observed = int(_message_value(message, "attachment_count", 0) or 0)
    evidence = f"expected_count={expected}; observed_count={observed}"
    return _yes("The complete stored attachment count exactly matches the configured count.", evidence=evidence, source="messages.attachment_count") if observed == expected else _no("The complete stored attachment count does not match the configured count.", evidence=evidence, source="messages.attachment_count")


def eval_attachment_type_match(conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    field = str(_parameter(config, "match_field", "Filename extension") or "Filename extension")
    value = str(_parameter(config, "match_value", "") or "").strip().lower()
    if not value:
        return _unknown("No attachment type value was configured.", status="unavailable-config")
    rows = _attachment_rows(conn, _message_value(message, "message_sha256"))
    if field.casefold() == "detected file type".casefold():
        detected = [(row, str(row["executable_format"] or "").lower()) for row in rows if row["executable_format"]]
        if not detected:
            return _unknown("No general detected-file-type field exists; only executable/script classifications are currently stored.", status="unavailable-prerequisite")
        hits = [str(row["original_filename"] or "[unnamed]") for row, detected_value in detected if detected_value == value]
        evidence = f"match_field={field}; match_value={value}; available_detected_values={';'.join(sorted({item for _row,item in detected}))}"
    else:
        normalized = value if value.startswith(".") else "." + value
        hits = [str(row["original_filename"] or "[unnamed]") for row in rows if Path(str(row["original_filename"] or "")).suffix.lower() == normalized]
        evidence = f"match_field={field}; match_value={normalized}; matching_files={';'.join(hits)}"
    return _yes("At least one attachment matches the configured type value.", evidence=evidence, source="attachments") if hits else _no("No attachment matches the configured type value.", evidence=evidence, source="attachments")


def _attachment_classification(row: Any) -> tuple[str | None, str]:
    if row["executable_format"]:
        return str(row["executable_format"]).lower(), "executable_format"
    extension = Path(str(row["original_filename"] or "")).suffix.lower()
    if extension:
        return extension, "filename_extension"
    return None, "unavailable"


def eval_attachment_type_new_sender(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address(_message_value(message, "from_address"))
    date, sha = _history_date_and_sha(message)
    if not sender:
        return _unknown("The sender address is unavailable.")
    current_rows = conn.execute(
        "SELECT original_filename,executable_format FROM attachments WHERE message_sha256=? AND is_inline=0",
        (sha,),
    ).fetchall()
    current = {_attachment_classification(row)[0] for row in current_rows}
    current.discard(None)
    if not current:
        return _no("The message contains no non-inline attachment type classification to compare.", source="attachments")
    if not date:
        return _unknown("The candidate message lacks a usable date.")
    prior_count = int(conn.execute(
        "SELECT COUNT(*) FROM messages WHERE message_sha256<>? AND selected_date_utc IS NOT NULL "
        "AND selected_date_utc<? AND from_address_normalized=?",
        (sha, date, sender),
    ).fetchone()[0])
    if not prior_count:
        return _unknown("The sender has no earlier case history.")
    previous = set()
    for row in conn.execute(
        """SELECT a.original_filename,a.executable_format FROM attachments a
           JOIN messages m ON m.message_sha256=a.message_sha256
           WHERE m.message_sha256<>? AND m.selected_date_utc IS NOT NULL AND m.selected_date_utc<?
             AND m.from_address_normalized=? AND a.is_inline=0""",
        (sha, date, sender),
    ):
        classification, _source = _attachment_classification(row)
        if classification:
            previous.add(classification)
    new = sorted(current - previous)
    evidence = f"sender={sender}; current_types={';'.join(sorted(current))}; prior_types={';'.join(sorted(previous))}; new_types={';'.join(new)}"
    return _yes("At least one non-inline attachment type is newly observed for this sender.", evidence=evidence, source="attachments and messages") if new else _no("All non-inline attachment types appeared in earlier messages from this sender.", evidence=evidence, source="attachments and messages")


def eval_attachment_html_svg(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    hits: list[str] = []
    for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
        extension = Path(str(row["original_filename"] or "")).suffix.lower()
        content_type = str(row["content_type_declared"] or "").lower().split(";", 1)[0]
        if extension in HTML_SVG_EXTENSIONS or content_type in HTML_SVG_CONTENT_TYPES:
            hits.append(f"filename={row['original_filename'] or '[unnamed]'}; extension={extension}; content_type={content_type}")
    return _yes("At least one attachment is HTML, XHTML, SHTML, or SVG by stored metadata.", evidence=" | ".join(hits), source="attachments") if hits else _no("No HTML or SVG attachment was identified.", source="attachments")


def eval_attachment_modern_loader_or_macro(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    hits: list[str] = []
    for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
        extension = Path(str(row["original_filename"] or "")).suffix.lower()
        if extension in MODERN_LOADER_EXTENSIONS:
            hits.append(f"filename={row['original_filename'] or '[unnamed]'}; extension={extension}")
    return _yes("At least one attachment uses a modern loader, launcher, or macro-enabled Office extension.", evidence=" | ".join(hits), source="attachments.original_filename") if hits else _no("No modern loader, launcher, or macro-enabled Office extension was identified.", source="attachments.original_filename")


def eval_payment_urgency_keywords(_conn, message: Any, config: dict[str, Any]) -> dict[str, Any]:
    raw_keywords = _parameter(config, "keywords", "")
    keywords = [item.strip() for item in re.split(r"[\r\n,;]+", str(raw_keywords or "")) if item.strip()]
    text = "\n".join([str(_message_value(message, "subject", "") or ""), str(_message_value(message, "body_text", "") or "")])
    folded = text.casefold()
    hits = [keyword for keyword in keywords if keyword.casefold() in folded]
    pattern_hits: list[str] = []
    include_patterns = _parameter(config, "include_financial_patterns", True)
    if isinstance(include_patterns, str):
        include_patterns = include_patterns.strip().lower() not in {"", "0", "false", "no", "off"}
    if include_patterns:
        for name, pattern in FINANCIAL_PATTERNS.items():
            if pattern.search(text):
                pattern_hits.append(name)
    if not keywords and not include_patterns:
        return _unknown("No payment/urgency keywords or financial patterns were enabled.", status="invalid-config")
    evidence = f"keyword_hits={';'.join(hits)}; pattern_hits={';'.join(pattern_hits)}"
    return _yes("The subject or body contains configured payment-change, urgency, or financial-pattern language.", evidence=evidence, source="messages.subject and messages.body_text") if hits or pattern_hits else _no("No configured payment/urgency language or financial pattern was found.", evidence=evidence, source="messages.subject and messages.body_text")


def eval_attachment_archive(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    """Identify common archive formats using only stored metadata.

    This intentionally performs no content extraction or byte reinspection. A
    match can come from either the stored original filename extension or the
    MIME type declared by the message. The evidence states which metadata
    source produced the match.
    """
    hits: list[str] = []
    for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
        filename = str(row["original_filename"] or "")
        extension = Path(filename).suffix.lower()
        content_type = str(row["content_type_declared"] or "").strip().lower().split(";", 1)[0]
        reasons: list[str] = []
        if extension in ARCHIVE_EXTENSIONS:
            reasons.append(f"extension={extension}")
        if content_type in ARCHIVE_CONTENT_TYPES:
            reasons.append(f"declared_content_type={content_type}")
        if reasons:
            hits.append(f"filename={filename or '[unnamed]'}; " + "; ".join(reasons))
    if hits:
        return _yes(
            "At least one attachment is identified as a common archive format by stored filename or MIME metadata.",
            evidence=" | ".join(hits),
            source="attachments.original_filename and attachments.content_type_declared",
        )
    return _no(
        "No attachment matched Threadsaw's bundled archive extension or MIME-type lists.",
        source="attachments.original_filename and attachments.content_type_declared",
    )


def eval_attachment_encrypted_zip(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    """Identify ZIP-family containers with encrypted members from stored inventory metadata."""
    candidates = [
        row for row in _attachment_rows(conn, _message_value(message, "message_sha256"))
        if is_zip_family_attachment(row["original_filename"], row["content_type_declared"])
    ]
    if not candidates:
        return _no(
            "No ZIP-family attachment is present.",
            source="attachments and archive_inspections",
        )

    ids = [int(row["attachment_id"]) for row in candidates]
    placeholders = ",".join("?" for _ in ids)
    inspections = {
        int(row["attachment_id"]): row
        for row in conn.execute(
            f"SELECT * FROM archive_inspections WHERE attachment_id IN ({placeholders})",
            ids,
        ).fetchall()
    }
    encrypted_hits: list[str] = []
    incomplete: list[str] = []
    for attachment in candidates:
        attachment_id = int(attachment["attachment_id"])
        filename = str(attachment["original_filename"] or "[unnamed]")
        inspection = inspections.get(attachment_id)
        if not inspection:
            incomplete.append(f"{filename}: not inventoried")
            continue
        encrypted_count = int(inspection["encrypted_member_count"] or 0)
        if encrypted_count:
            encrypted_hits.append(
                f"filename={filename}; encrypted_members={encrypted_count}; "
                f"recorded_members={inspection['member_count']}; total_members={inspection['total_member_count'] or ''}; "
                f"status={inspection['status']}"
            )
        elif str(inspection["status"]) != "complete":
            detail = str(inspection["error_detail"] or inspection["status"])
            incomplete.append(f"{filename}: {detail}")

    if encrypted_hits:
        return _yes(
            "At least one ZIP-family attachment contains a member with the ZIP encryption flag set.",
            evidence=" | ".join(encrypted_hits),
            source="archive_inspections and archive_members",
        )
    if incomplete:
        return _unknown(
            "ZIP-family attachments are present, but the bounded inventory could not conclusively evaluate every archive.",
            evidence=" | ".join(incomplete),
            source="archive_inspections",
        )
    return _no(
        "All completely inventoried ZIP-family attachments contain no members with the ZIP encryption flag set.",
        evidence="; ".join(str(row["original_filename"] or "[unnamed]") for row in candidates),
        source="archive_inspections and archive_members",
    )


def eval_attached_email(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    hits = []
    for row in _attachment_rows(conn, _message_value(message, "message_sha256")):
        extension = Path(str(row["original_filename"] or "")).suffix.lower()
        content_type = str(row["content_type_declared"] or "").lower()
        if extension in ATTACHED_EMAIL_EXTENSIONS or content_type == "message/rfc822":
            hits.append(f"filename={row['original_filename'] or '[unnamed]'}; content_type={content_type}")
    return _yes("At least one attachment is identified as an attached email message.", evidence=" | ".join(hits), source="attachments") if hits else _no("No attachment is identified as an attached email message.", source="attachments")


def eval_sender_recipient_same_domain(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender = _address_domain(_message_value(message, "from_address"))
    recipients = _recipient_domains(conn, _message_value(message, "message_sha256"))
    if not sender:
        return _unknown("A usable sender domain is unavailable.")
    if not recipients:
        return _unknown("No usable recipient domain is available.")
    matches = [domain for domain in recipients if domain == sender]
    evidence = f"sender_domain={sender}; recipient_domains={';'.join(recipients)}"
    return _yes("At least one recipient domain matches the sender domain.", evidence=evidence) if matches else _no("No recipient domain matches the sender domain.", evidence=evidence)


def eval_sender_mimics_recipient_localpart(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    sender_address = _address(_message_value(message, "from_address"))
    sender_local = _address_local(sender_address)
    sender_domain = _address_domain(sender_address)
    if not sender_local or not sender_domain:
        return _unknown("The sender address is unavailable.")
    hits = []
    for recipient in _recipient_addresses(conn, _message_value(message, "message_sha256")):
        if _address_local(recipient) == sender_local and _address_domain(recipient) != sender_domain:
            hits.append(recipient)
    evidence = f"sender={sender_address}; matching_recipients={';'.join(hits)}"
    return _yes("The sender local part matches a recipient local part on a different domain.", evidence=evidence) if hits else _no("No recipient local part matches the sender local part on a different domain.", evidence=evidence)


def eval_no_visible_recipient(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    visible = _recipient_addresses(conn, _message_value(message, "message_sha256"), {"to", "cc"})
    evidence = f"visible_recipient_count={len(visible)}; visible_recipients={';'.join(visible)}"
    return _yes("No usable To or CC recipient address is stored.", evidence=evidence, source="recipients") if not visible else _no("At least one usable To or CC recipient address is stored.", evidence=evidence, source="recipients")


def eval_bcc_only_recipients(conn, message: Any, _config: dict[str, Any]) -> dict[str, Any]:
    visible = _recipient_addresses(conn, _message_value(message, "message_sha256"), {"to", "cc"})
    bcc = _recipient_addresses(conn, _message_value(message, "message_sha256"), {"bcc"})
    if not bcc:
        return _unknown("No preserved BCC recipient data is available.", source="recipients")
    evidence = f"visible_recipient_count={len(visible)}; bcc_recipient_count={len(bcc)}; bcc_recipients={';'.join(bcc)}"
    return _yes("Preserved recipients appear only in BCC; no usable To or CC recipient is stored.", evidence=evidence, source="recipients") if not visible else _no("At least one visible To or CC recipient is stored.", evidence=evidence, source="recipients")


# Evaluators built from reusable predicates.
eval_url_literal_ip = _evaluate_url_predicate(_literal_ip_predicate, "At least one stored URL uses a literal IPv4 or IPv6 address as its host.")
eval_url_userinfo_misdirection = _evaluate_url_predicate(_userinfo_predicate, "At least one stored URL contains user-information before the actual hostname.")
eval_url_nonstandard_port = _evaluate_url_predicate(_port_predicate, "At least one stored web URL explicitly uses a non-default network port.")
eval_url_dangerous_scheme = _evaluate_url_predicate(_dangerous_scheme_predicate, "At least one stored URI uses a scheme in Threadsaw's bundled dangerous-scheme list.")
eval_url_obfuscated_numeric_ip = _evaluate_url_predicate(_obfuscated_ip_predicate, "At least one stored URL uses an obfuscated numeric IPv4 representation.")
eval_url_plain_http = _evaluate_url_predicate(_plain_http_predicate, "At least one stored web URL uses plain HTTP rather than HTTPS.")
eval_attachment_shortcut = _attachment_extension_factor(SHORTCUT_EXTENSIONS, "a shortcut or launcher format")
eval_attachment_disk_image = _attachment_extension_factor(DISK_IMAGE_EXTENSIONS, "a disk-image or mountable container format")
eval_return_path_new_for_sender = _new_header_value_for_sender("return_path", compare_domain=True)
eval_trusted_dmarc_fail = _evaluate_auth_fail("dmarc", {"fail"})
eval_trusted_dkim_fail = _evaluate_auth_fail("dkim", {"fail"})
eval_trusted_spf_fail = _evaluate_auth_fail("spf", {"fail", "softfail", "permerror"})
eval_trusted_arc_fail = _evaluate_auth_fail("arc", {"fail"})


EVALUATORS: dict[str, Evaluator] = {
    "reply_to_domain_mismatch": eval_reply_to_domain_mismatch,
    "display_name_embedded_email_domain_mismatch": eval_display_name_embedded_email_domain_mismatch,
    "sender_domain_lookalike_configured": eval_sender_domain_lookalike_configured,
    "sender_domain_lookalike_recipient": eval_sender_domain_lookalike_recipient,
    "trusted_dmarc_fail": eval_trusted_dmarc_fail,
    "trusted_dkim_fail": eval_trusted_dkim_fail,
    "trusted_spf_fail": eval_trusted_spf_fail,
    "displayed_url_domain_mismatch": eval_displayed_url_domain_mismatch,
    "url_literal_ip": eval_url_literal_ip,
    "url_userinfo_misdirection": eval_url_userinfo_misdirection,
    "url_nonstandard_port": eval_url_nonstandard_port,
    "url_dangerous_scheme": eval_url_dangerous_scheme,
    "url_embeds_legitimate_domain": eval_url_embeds_legitimate_domain,
    "url_obfuscated_numeric_ip": eval_url_obfuscated_numeric_ip,
    "attachment_executable_or_script": eval_attachment_executable,
    "attachment_double_extension": eval_attachment_double_extension,
    "attachment_unicode_controls": eval_attachment_unicode_controls,
    "executable_without_extension": eval_executable_without_extension,
    "attachment_shortcut": eval_attachment_shortcut,
    "attachment_disk_image": eval_attachment_disk_image,
    "html_form": eval_html_form,
    "html_auto_redirect": eval_html_auto_redirect,
    "html_embedded_active_object": eval_html_embedded_active_object,
    "html_script": eval_html_script,
    "html_event_handlers": eval_html_event_handlers,
    "html_script_or_event_handlers": eval_html_script_or_event_handlers,
    "return_path_domain_mismatch": eval_return_path_domain_mismatch,
    "sender_address_new": eval_sender_address_new,
    "sender_domain_new": eval_sender_domain_new,
    "sender_ip_new_for_sender": eval_sender_ip_new_for_sender,
    "reply_to_new_for_sender": eval_reply_to_new_for_sender,
    "return_path_new_for_sender": eval_return_path_new_for_sender,
    "sender_free_email_provider": eval_sender_free_email_provider,
    "sender_domain_punycode": eval_sender_domain_punycode,
    "sender_header_mismatch": eval_sender_header_mismatch,
    "corroborated_thread_reply": eval_corroborated_thread_reply,
    "thread_continuation_changed_infrastructure": eval_thread_continuation_changed_infrastructure,
    "payment_urgency_keywords": eval_payment_urgency_keywords,
    "prior_sender_recipient": eval_prior_sender_recipient,
    "prior_sender_subject": eval_prior_sender_subject,
    "reply_subject_without_references": eval_reply_subject_without_references,
    "unmatched_thread_references": eval_unmatched_thread_references,
    "trusted_arc_fail": eval_trusted_arc_fail,
    "authentication_conflict": eval_authentication_conflict,
    "date_received_discrepancy": eval_date_received_discrepancy,
    "message_id_missing_or_malformed": eval_message_id_missing_or_malformed,
    "message_id_domain_mismatch": eval_message_id_domain_mismatch,
    "sharepoint_host_mismatch": eval_sharepoint_host_mismatch,
    "external_sharepoint_tenant_new": eval_external_sharepoint_tenant_new,
    "exact_url_count": eval_exact_url_count,
    "url_shortener": eval_url_shortener,
    "url_punycode": eval_url_punycode,
    "url_domain_new_case": eval_url_domain_new_case,
    "url_domain_new_sender": eval_url_domain_new_sender,
    "url_deep_subdomains": eval_url_deep_subdomains,
    "url_nested_url": eval_url_nested_url,
    "url_plain_http": eval_url_plain_http,
    "url_heavy_percent_encoding": eval_url_heavy_percent_encoding,
    "url_base64_like": eval_url_base64_like,
    "url_contains_recipient_email": eval_url_contains_recipient_email,
    "url_domain_differs_sender": eval_url_domain_differs_sender,
    "exact_attachment_count": eval_exact_attachment_count,
    "attachment_type_match": eval_attachment_type_match,
    "attachment_type_new_sender": eval_attachment_type_new_sender,
    "attachment_html_svg": eval_attachment_html_svg,
    "attachment_modern_loader_or_macro": eval_attachment_modern_loader_or_macro,
    "attachment_archive": eval_attachment_archive,
    "attachment_encrypted_zip": eval_attachment_encrypted_zip,
    "attached_email": eval_attached_email,
    "sender_recipient_same_domain": eval_sender_recipient_same_domain,
    "sender_mimics_recipient_localpart": eval_sender_mimics_recipient_localpart,
    "no_visible_recipient": eval_no_visible_recipient,
    "bcc_only_recipients": eval_bcc_only_recipients,
}

PENDING_REASONS = {
    "exact_unique_url_domains": "This factor was removed from the visible catalog in 0.6.0 and is accepted only for legacy configuration compatibility.",
}
