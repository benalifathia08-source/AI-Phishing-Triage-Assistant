"""Turn a raw .eml file into plain Python data.

Every byte of the email is attacker-controlled. Parsing never executes, renders
or saves anything to disk, and hard limits stop oversized or deeply nested
messages before they use up memory.
"""
from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.errors import HeaderParseError
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

MAX_EMAIL_BYTES = 25 * 1024 * 1024  # above the 20-25 MB limit of common mail services
MAX_PARTS = 300
MAX_NESTING = 3  # an email attached to an email attached to an email

_BARE_ADDRESS = re.compile(r"<?([^\s<>@,;\"]+@[^\s<>,;\"]+)>?")


class EmailTooLarge(ValueError):
    pass


@dataclass
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].strip().strip(".").lower() if "@" in self.address else ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    inline: bool
    data: bytes = field(repr=False)


@dataclass
class ParsedEmail:
    raw: bytes = field(repr=False)
    sha256: str
    headers: list[tuple[str, str]]
    subject: str
    from_addresses: list[Address]  # From may legally hold several addresses
    reply_to: list[Address]
    return_path: str
    to: list[Address]
    cc: list[Address]
    date: datetime | None
    message_id: str
    text_body: str
    html_body: str
    attachments: list[Attachment]
    attached_emails: list[ParsedEmail]
    defects: list[str]
    # False when Python had to re-encode the bytes (an email attached as message/rfc822).
    # Re-encoding can change line folding, so a DKIM re-check would fail for the wrong reason.
    raw_exact: bool = True

    @property
    def sender(self) -> Address | None:
        return self.from_addresses[0] if self.from_addresses else None

    def header_all(self, name: str) -> list[str]:
        """All values of a header, top of the email first (the order servers added them, newest first)."""
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    def header(self, name: str) -> str:
        values = self.header_all(name)
        return values[0] if values else ""


def _raw_utf8(value: str) -> str:
    """Non-ASCII header bytes arrive as surrogate escapes. Read them as UTF-8, which RFC 6532 allows."""
    return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def decode_header_value(value) -> str:
    """Decode RFC 2047 encoded words (=?utf-8?B?...?=) and unfold the header onto one line."""
    if value is None:
        return ""
    if isinstance(value, str):
        value = _raw_utf8(value)
    try:
        text = str(make_header(decode_header(value)))
    except (HeaderParseError, LookupError, UnicodeError, ValueError):
        text = str(value)
    return " ".join(text.split())


def _clean_address(address: str) -> str:
    """Lenient parsing of a broken header can leave quotes or brackets in the address."""
    address = address.strip()
    if not any(char in address for char in ' <>"'):
        return address
    match = _BARE_ADDRESS.search(address.replace('"', " "))
    return match.group(1) if match else address


def parse_addresses(values: list) -> list[Address]:
    # Split the raw header first and decode display names afterwards: a decoded
    # name such as "Doe, John" would otherwise be split into two addresses.
    raw_values = [str(value) for value in values]
    addresses = [
        Address(decode_header_value(name), _clean_address(address))
        for name, address in getaddresses(raw_values)
        if address
    ]
    if addresses or not raw_values:
        return addresses
    # Strict parsing rejected the header. Malformed sender headers are common in
    # phishing, so still recover any address-looking text.
    return [Address("", match) for value in raw_values for match in _BARE_ADDRESS.findall(value)]


@dataclass
class _Collected:
    text: list[str] = field(default_factory=list)
    html: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    attached_emails: list[ParsedEmail] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)
    part_count: int = 0


def _decode_text(data: bytes, charset: str | None) -> str:
    try:
        return data.decode(charset or "utf-8", errors="replace")
    except LookupError:  # unknown or made-up charset name
        return data.decode("utf-8", errors="replace")


def _parse_attached_email(data: bytes, depth: int, out: _Collected, exact: bool = True) -> None:
    if depth + 1 > MAX_NESTING:
        out.defects.append(f"attached email nested deeper than {MAX_NESTING} levels was not parsed")
        return
    try:
        inner = parse_eml(data, _depth=depth + 1)
        inner.raw_exact = exact
        out.attached_emails.append(inner)
    except EmailTooLarge:
        out.defects.append("attached email too large to parse")


def _collect(part: Message, depth: int, out: _Collected) -> None:
    out.part_count += 1
    if out.part_count > MAX_PARTS:
        if out.part_count == MAX_PARTS + 1:
            out.defects.append(f"more than {MAX_PARTS} MIME parts, the rest were skipped")
        return
    out.defects.extend(type(defect).__name__ for defect in part.defects)

    content_type = part.get_content_type()
    payload = part.get_payload()
    if content_type == "message/rfc822" and isinstance(payload, list):
        for inner in payload[:1]:
            try:
                _parse_attached_email(inner.as_bytes(), depth, out, exact=False)
            except (LookupError, UnicodeError, ValueError, TypeError):
                out.defects.append("attached email could not be re-encoded for parsing")
        return
    if part.is_multipart():
        for sub_part in payload if isinstance(payload, list) else []:
            _collect(sub_part, depth, out)
        return

    data = part.get_payload(decode=True) or b""
    filename = decode_header_value(part.get_filename())
    disposition = part.get_content_disposition() or ""
    if content_type in ("text/plain", "text/html") and disposition != "attachment" and not filename:
        text = _decode_text(data, part.get_content_charset())
        (out.text if content_type == "text/plain" else out.html).append(text)
        return

    out.attachments.append(Attachment(
        filename=filename,
        content_type=content_type,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        inline=disposition != "attachment",
        data=data,
    ))
    if filename.lower().endswith(".eml"):
        _parse_attached_email(data, depth, out)


def parse_date(value: str) -> datetime | None:
    try:
        return parsedate_to_datetime(value) if value else None
    except (TypeError, ValueError, IndexError):
        return None


def parse_eml(raw: bytes, *, _depth: int = 0) -> ParsedEmail:
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailTooLarge(f"email is {len(raw)} bytes, the limit is {MAX_EMAIL_BYTES}")

    # compat32 keeps header values as raw text, so a malformed header can never
    # raise while we read it. We decode them ourselves.
    message = email.message_from_bytes(raw, policy=policy.compat32)
    collected = _Collected()
    _collect(message, _depth, collected)

    raw_headers = [(name, _raw_utf8(value)) for name, value in message.raw_items()]

    def raw_all(name: str) -> list[str]:
        return [value for key, value in raw_headers if key.lower() == name.lower()]

    def first(name: str) -> str:
        return decode_header_value((raw_all(name) or [""])[0])

    return ParsedEmail(
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        headers=[(name, decode_header_value(value)) for name, value in raw_headers],
        subject=first("Subject"),
        from_addresses=parse_addresses(raw_all("From")),
        reply_to=parse_addresses(raw_all("Reply-To")),
        return_path=first("Return-Path").strip("<> "),
        to=parse_addresses(raw_all("To")),
        cc=parse_addresses(raw_all("Cc")),
        date=parse_date(first("Date")),
        message_id=first("Message-ID"),
        text_body="\n".join(collected.text),
        html_body="\n".join(collected.html),
        attachments=collected.attachments,
        attached_emails=collected.attached_emails,
        defects=collected.defects,
    )
