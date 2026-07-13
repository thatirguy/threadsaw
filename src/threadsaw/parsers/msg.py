from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import Parser
from email.utils import format_datetime
from pathlib import Path
from typing import Any

from .eml import ParsedMessage, parse_eml


def _clean_text(value: object | None) -> str:
    return str(value or "").replace("\x00", "").strip()


def _manual_email(msg: Any) -> EmailMessage:
    """Fallback MSG conversion that preserves available transport headers."""
    email = EmailMessage(policy=policy.default)
    header_text = _clean_text(getattr(msg, "headerText", None))
    if header_text:
        parsed_headers = Parser(policy=policy.default).parsestr(header_text, headersonly=True)
        excluded = {"content-type", "content-transfer-encoding", "mime-version"}
        for name, value in parsed_headers.raw_items():
            if name.lower() not in excluded and "\x00" not in name:
                try:
                    email[name] = _clean_text(value)
                except (ValueError, TypeError):
                    continue

    supplements = {
        "Subject": getattr(msg, "subject", None),
        "From": getattr(msg, "sender", None),
        "To": getattr(msg, "to", None),
        "Cc": getattr(msg, "cc", None),
        "Bcc": getattr(msg, "bcc", None),
        "Message-ID": getattr(msg, "messageId", None),
    }
    for name, value in supplements.items():
        cleaned = _clean_text(value)
        if cleaned and not email.get(name):
            email[name] = cleaned

    if not email.get("Date"):
        date_value = getattr(msg, "date", None) or getattr(msg, "receivedTime", None)
        if date_value:
            try:
                email["Date"] = format_datetime(date_value)
            except Exception:
                email["Date"] = _clean_text(date_value)

    body = _clean_text(getattr(msg, "body", None))
    html_body = getattr(msg, "htmlBody", None)
    if isinstance(html_body, bytes):
        html_body = html_body.decode("utf-8", errors="replace")
    html_text = str(html_body or "").replace("\x00", "")

    if body:
        email.set_content(body)
        if html_text.strip():
            email.add_alternative(html_text, subtype="html")
    elif html_text.strip():
        email.set_content(html_text, subtype="html")
    else:
        email.set_content("")

    for index, attachment in enumerate(getattr(msg, "attachments", []) or []):
        data = getattr(attachment, "data", None)
        if not isinstance(data, (bytes, bytearray)):
            continue
        filename = (
            getattr(attachment, "longFilename", None)
            or getattr(attachment, "shortFilename", None)
            or f"attachment-{index}"
        )
        email.add_attachment(
            bytes(data),
            maintype="application",
            subtype="octet-stream",
            filename=_clean_text(filename) or f"attachment-{index}",
        )
    return email


def parse_msg(path: Path, config: dict[str, Any]) -> tuple[ParsedMessage, bytes]:
    """Parse a standalone MSG and create a clearly labeled derived RFC 822 message.

    The original MSG remains the source evidence. The preferred extract-msg
    conversion path retains transport headers such as Received,
    Authentication-Results, Return-Path, Message-ID, and Date when present.
    """
    try:
        import extract_msg  # type: ignore
    except ImportError as exc:
        raise RuntimeError("MSG support requires `pip install threadsaw[msg]`") from exc

    msg = extract_msg.Message(str(path))
    try:
        try:
            email = msg.asEmailMessage()
        except Exception:
            email = _manual_email(msg)

        # Add provenance without replacing any original transport headers.
        if email.get("X-Threadsaw-Derived-From"):
            email.replace_header("X-Threadsaw-Derived-From", "Microsoft Outlook MSG")
        else:
            email["X-Threadsaw-Derived-From"] = "Microsoft Outlook MSG"

        derived = email.as_bytes(policy=policy.default)
        return parse_eml(derived, config), derived
    finally:
        close = getattr(msg, "close", None)
        if callable(close):
            close()
