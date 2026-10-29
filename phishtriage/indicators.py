"""Collect every indicator in an email: links, attachments, QR codes and phone numbers."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from phishtriage.attachments import AttachmentInfo, inspect_attachment
from phishtriage.links import Link, LinkCollection
from phishtriage.parser import ParsedEmail
from phishtriage.qr import inspect_pdf, qr_from_data_uri, qr_from_image

_PHONE = re.compile(r"(?<![\w+])(\+?\(?\d[\d\s().-]{8,20}\d)(?!\w)")
_PHONE_CONTEXT = re.compile(r"(?i)\b(call|phone|tel|telephone|contact|support|help ?desk|helpline|hotline|toll[- ]free|"
                            r"appel|appelez|t[ée]l[ée]phone|llame|anrufen|chiamare)\b")
_IMAGE_TYPES = {"png", "jpeg", "gif", "webp", "bmp"}


@dataclass
class QrCode:
    source: str  # the attachment or inline image it was found in
    text: str  # the decoded content, often a link


@dataclass
class IndicatorFacts:
    links: list[Link] = field(default_factory=list)  # every link found: web links and tel:, data:, javascript: and similar
    links_truncated: bool = False  # more than 300 links: the list was cut
    attachments: list[AttachmentInfo] = field(default_factory=list)  # every attachment, including inline pictures
    qr_codes: list[QrCode] = field(default_factory=list)  # QR codes decoded from pictures and PDF pages
    phone_numbers: list[str] = field(default_factory=list)  # numbers next to "call", "support"... (callback phishing)

    @property
    def web_links(self) -> list[Link]:
        """Links with http or https (images included; helpers.web_links leaves them out)."""
        return [link for link in self.links if link.scheme in ("http", "https")]

    @property
    def link_domains(self) -> list[str]:
        """Organizations the web links point to, in order of appearance."""
        return list(dict.fromkeys(link.org_domain for link in self.web_links if link.org_domain))


def phone_numbers(text: str) -> list[str]:
    found: dict[str, str] = {}  # digits -> number as written, so "+1 (866) 318 0095" and "+18663180095" count once
    for match in _PHONE.finditer(text):
        digits = re.sub(r"\D", "", match.group(1))
        if not 10 <= len(digits) <= 15:
            continue
        window = text[max(0, match.start() - 80): match.end() + 20]
        if _PHONE_CONTEXT.search(window):
            found.setdefault(digits[-10:], " ".join(match.group(1).split()))
    return list(found.values())[:10]


def collect_indicators(parsed: ParsedEmail) -> IndicatorFacts:
    links = LinkCollection()
    links.add_html(parsed.html_body)
    links.add_text(parsed.text_body)
    qr_codes: list[QrCode] = []

    def add_qr(source: str, texts: list[str]) -> None:
        for text in texts:
            qr_codes.append(QrCode(source=source, text=text[:2000]))
            links.add(text, source)

    attachments = []
    for attachment in parsed.attachments:
        info, html_text = inspect_attachment(attachment)
        label = attachment.filename or attachment.content_type
        if html_text:
            links.add_html(html_text, source=f"attachment:{label}")
        if info.detected_type == "pdf":
            pdf = inspect_pdf(attachment.data)
            info.pdf_pages, info.pdf_encrypted = pdf.pages, pdf.encrypted
            for url in pdf.links:
                links.add(url, f"attachment:{label}")
            add_qr(f"qr:{label}", pdf.qr_codes)
        elif info.detected_type in _IMAGE_TYPES:
            add_qr(f"qr:{label}", qr_from_image(attachment.data))
        attachments.append(info)

    for index, uri in enumerate(links.inline_images, start=1):
        add_qr(f"qr:inline-image-{index}", qr_from_data_uri(uri))

    body_text = parsed.text_body or re.sub(r"<[^>]+>", " ", parsed.html_body)
    return IndicatorFacts(
        links=links.links,
        links_truncated=links.truncated,
        attachments=attachments,
        qr_codes=qr_codes,
        phone_numbers=phone_numbers(body_text),
    )
