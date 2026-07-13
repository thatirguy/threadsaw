from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.headerregistry import Address
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from ..util import byte_hashes, iso_utc, safe_filename
from ..ip_fields import extract_ips, received_sender_ips

AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-zA-Z0-9_-]+)", re.I)


@dataclass
class ParsedAttachment:
    part_index: int
    original_filename: str | None
    safe_filename: str
    content_type: str
    data: bytes
    sha256: str
    md5: str
    content_disposition: str | None
    content_id: str | None
    executable_format: str | None
    is_inline: bool = False


@dataclass
class ParsedEmbeddedMessage:
    parent_part_index: int
    raw_bytes: bytes
    message_sha256: str


@dataclass
class ParsedMessage:
    message_sha256: str
    md5: str
    raw_bytes: bytes
    internet_message_id: str | None
    subject: str
    from_address: str
    reply_to: str
    return_path: str
    header_date_raw: str | None
    header_date_utc: str | None
    top_received_utc: str | None
    trusted_received_utc: str | None
    selected_date_utc: str | None
    selected_date_source: str | None
    sender_ips: list[str]
    raw_headers_text: str
    body_text: str
    body_text_source: str
    body_html: str
    date_discrepancy_seconds: int | None
    defects: list[str]
    recipients: list[dict[str, str | None]] = field(default_factory=list)
    received_hops: list[dict[str, Any]] = field(default_factory=list)
    auth_results: list[dict[str, Any]] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    embedded_messages: list[ParsedEmbeddedMessage] = field(default_factory=list)


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        cleaned = " ".join(data.split())
        if cleaned:
            self.parts.append(cleaned)

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self.parts.append("\n")

    def text(self) -> str:
        value = " ".join(self.parts)
        value = re.sub(r"[ \t]*\n[ \t]*", "\n", value)
        value = re.sub(r"[ \t]{2,}", " ", value)
        return value.strip()


def _html_to_text(value: str) -> str:
    parser = _HTMLTextExtractor()
    try:
        parser.feed(value)
        return parser.text()
    except Exception:
        return ""


def _raw_header_text(raw_bytes: bytes) -> str:
    if b"\r\n\r\n" in raw_bytes:
        header = raw_bytes.split(b"\r\n\r\n", 1)[0]
    else:
        header = raw_bytes.split(b"\n\n", 1)[0]
    return header.decode("utf-8", errors="replace")


def _decode_text_part(part: Any) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")


def _parse_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return iso_utc(parsed)
    except (TypeError, ValueError, OverflowError):
        return None


def _received_date(value: str) -> str | None:
    candidate = value.rsplit(";", 1)[-1].strip() if ";" in value else value.strip()
    return _parse_date(candidate)


def _addresses(message: Any, header: str, recipient_type: str) -> list[dict[str, str | None]]:
    values = message.get_all(header, [])
    output: list[dict[str, str | None]] = []
    for name, address in getaddresses([str(v) for v in values]):
        address = address.strip()
        if not address:
            continue
        domain = address.rsplit("@", 1)[1].lower() if "@" in address else None
        output.append({
            "recipient_type": recipient_type,
            "display_name": name or None,
            "email_address": address,
            "domain": domain,
        })
    return output


def _executable_format(data: bytes, filename: str | None, content_type: str) -> str | None:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return "Mach-O"
    suffix = Path(filename or "").suffix.lower()
    if suffix in {".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".sh", ".hta", ".wsf", ".wsh", ".scr", ".pif", ".cpl", ".chm", ".xll", ".one", ".iqy", ".slk", ".rdp", ".msix", ".docm", ".xlsm", ".pptm"}:
        return "script"
    if content_type in {"application/javascript", "text/javascript", "application/x-sh"}:
        return "script"
    return None


def _clean_header_value(value: object | None) -> str:
    return str(value or "").replace("\x00", "").strip()


def parse_eml(raw_bytes: bytes, config: dict[str, Any]) -> ParsedMessage:
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    sha256, md5 = byte_hashes(raw_bytes)

    header_date_raw = str(message.get("Date")) if message.get("Date") else None
    header_date_utc = _parse_date(header_date_raw)
    received_values = [str(v) for v in message.get_all("Received", [])]
    # Trusted mail-boundary classifications are deliberately not accepted from
    # case configuration at parse time. Version 1.1 derives them only from a
    # repeated PST-corpus consensus after ingestion, then recomputes the stored
    # flags and selected dates in case_context.recompute_case_context().
    received_hops: list[dict[str, Any]] = []
    trusted_received_utc = None
    sender_ips: list[str] = []
    for index, raw in enumerate(received_values):
        hop_ips = received_sender_ips(raw)
        for ip in hop_ips:
            if ip not in sender_ips:
                sender_ips.append(ip)
        trusted = False
        parsed_date = _received_date(raw)
        received_hops.append({
            "hop_order": index,
            "raw_value": raw,
            "parsed_date_utc": parsed_date,
            "sender_ips": hop_ips,
            "trusted": trusted,
        })
    top_received_utc = received_hops[0]["parsed_date_utc"] if received_hops else None

    if trusted_received_utc:
        selected_date_utc, selected_source = trusted_received_utc, "trusted-received"
    elif header_date_utc:
        selected_date_utc, selected_source = header_date_utc, "header"
    elif top_received_utc:
        selected_date_utc, selected_source = top_received_utc, "top-received-untrusted"
    else:
        selected_date_utc, selected_source = None, None

    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[ParsedAttachment] = []
    embedded_messages: list[ParsedEmbeddedMessage] = []
    part_index = 0

    def visit_part(part: Any) -> None:
        nonlocal part_index
        content_type = part.get_content_type().lower()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_id = part.get("Content-ID")

        # message/rfc822 is an attachment container, not part of the wrapper's
        # body tree.  Serialize the child message, record it as an attachment,
        # and stop traversal so its body and attachments are not attributed to
        # the outer message.
        if content_type == "message/rfc822":
            payload = part.get_payload()
            children = payload if isinstance(payload, list) else ([payload] if payload is not None else [])
            child_bytes: list[bytes] = []
            for child in children:
                if hasattr(child, "as_bytes"):
                    child_bytes.append(child.as_bytes(policy=policy.default))
            if not child_bytes:
                decoded = part.get_payload(decode=True)
                if decoded:
                    child_bytes.append(decoded)
            data = b"\r\n".join(child_bytes)
            part_sha256, part_md5 = byte_hashes(data)
            current_index = part_index
            attachments.append(ParsedAttachment(
                part_index=current_index,
                original_filename=filename,
                safe_filename=safe_filename(filename, f"attached-message-{current_index}.eml"),
                content_type=content_type,
                data=data,
                sha256=part_sha256,
                md5=part_md5,
                content_disposition=disposition or "attachment",
                content_id=content_id,
                executable_format=None,
                is_inline=False,
            ))
            part_index += 1
            for raw_child in child_bytes:
                child_sha256, _child_md5 = byte_hashes(raw_child)
                embedded_messages.append(ParsedEmbeddedMessage(current_index, raw_child, child_sha256))
            return

        if part.is_multipart():
            for child in part.iter_parts():
                visit_part(child)
            return

        is_attachment = disposition == "attachment" or filename is not None
        is_inline = bool(
            disposition == "inline"
            or (content_id and content_type.startswith("image/") and disposition != "attachment")
        )
        if is_attachment:
            data = part.get_payload(decode=True) or b""
            part_sha256, part_md5 = byte_hashes(data)
            attachments.append(ParsedAttachment(
                part_index=part_index,
                original_filename=filename,
                safe_filename=safe_filename(filename, f"attachment-{part_index}"),
                content_type=content_type,
                data=data,
                sha256=part_sha256,
                md5=part_md5,
                content_disposition=disposition,
                content_id=content_id,
                executable_format=_executable_format(data, filename, content_type),
                is_inline=is_inline,
            ))
            part_index += 1
        elif content_type == "text/plain":
            body_text_parts.append(_decode_text_part(part))
        elif content_type == "text/html":
            body_html_parts.append(_decode_text_part(part))

    visit_part(message)

    auth_results: list[dict[str, Any]] = []
    for raw_header in message.get_all("Authentication-Results", []):
        raw = str(raw_header)
        authserv_id = raw.split(";", 1)[0].strip() or None
        results = {key.lower(): value.lower() for key, value in AUTH_RESULT_RE.findall(raw)}
        auth_results.append({
            "authserv_id": authserv_id,
            "spf_result": results.get("spf"),
            "dkim_result": results.get("dkim"),
            "dmarc_result": results.get("dmarc"),
            "arc_result": results.get("arc"),
            "trusted": False,
            "raw_value": raw,
        })

    body_text = "\n\n".join(part.strip() for part in body_text_parts if part and part.strip()).strip()
    body_html = "\n\n".join(part for part in body_html_parts if part and part.strip()).strip()
    body_text_source = "text/plain"
    if not body_text and body_html:
        body_text = _html_to_text(body_html)
        body_text_source = "derived-from-html"
    elif not body_text:
        body_text_source = "unavailable"

    discrepancy = None
    comparison_received = trusted_received_utc or top_received_utc
    if header_date_utc and comparison_received:
        try:
            left = datetime.fromisoformat(header_date_utc.replace("Z", "+00:00"))
            right = datetime.fromisoformat(comparison_received.replace("Z", "+00:00"))
            discrepancy = int((left - right).total_seconds())
        except ValueError:
            discrepancy = None

    defects = [type(d).__name__ + (f": {d}" if str(d) else "") for d in message.defects]
    recipients = []
    recipients.extend(_addresses(message, "To", "to"))
    recipients.extend(_addresses(message, "Cc", "cc"))
    recipients.extend(_addresses(message, "Bcc", "bcc"))

    return ParsedMessage(
        message_sha256=sha256,
        md5=md5,
        raw_bytes=raw_bytes,
        internet_message_id=_clean_header_value(message.get("Message-ID")) or None,
        subject=_clean_header_value(message.get("Subject")),
        from_address=_clean_header_value(message.get("From")),
        reply_to=_clean_header_value(message.get("Reply-To")),
        return_path=_clean_header_value(message.get("Return-Path")),
        header_date_raw=header_date_raw,
        header_date_utc=header_date_utc,
        top_received_utc=top_received_utc,
        trusted_received_utc=trusted_received_utc,
        selected_date_utc=selected_date_utc,
        selected_date_source=selected_source,
        sender_ips=sender_ips,
        raw_headers_text=_raw_header_text(raw_bytes),
        body_text=body_text,
        body_text_source=body_text_source,
        body_html=body_html,
        date_discrepancy_seconds=discrepancy,
        defects=defects,
        recipients=recipients,
        received_hops=received_hops,
        auth_results=auth_results,
        attachments=attachments,
        embedded_messages=embedded_messages,
    )
