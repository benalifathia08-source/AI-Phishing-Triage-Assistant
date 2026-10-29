import base64
import hashlib

import pytest

from phishtriage import parser
from phishtriage.parser import EmailTooLarge, parse_eml
from tests.helpers import make_eml


def test_raw_utf8_header_is_read_as_utf8():
    # Seen in real phishing: bold "mathematical" letters written as raw UTF-8 bytes.
    parsed = parse_eml(make_eml(from_="Gift Team <team@gift-\U0001d41c\U0001d425\U0001d422.example>"))
    assert parsed.sender.domain == "gift-\U0001d41c\U0001d425\U0001d422.example"


def test_encoded_display_name_with_comma_is_one_address():
    name = base64.b64encode(b"Doe, John").decode()
    parsed = parse_eml(make_eml(from_=f"=?utf-8?B?{name}?= <john@example.com>"))
    assert [(a.display_name, a.address) for a in parsed.from_addresses] == [("Doe, John", "john@example.com")]


def test_malformed_from_still_yields_the_address():
    parsed = parse_eml(make_eml(from_='"Broken <<support@example.com'))
    assert parsed.sender is not None
    assert parsed.sender.address == "support@example.com"


def test_unknown_charset_does_not_crash():
    parsed = parse_eml(make_eml(body="caf\xe9", content_type="text/plain; charset=made-up-charset"))
    assert parsed.text_body.startswith("caf")


MULTIPART = """Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: multipart/alternative; boundary="b2"

--b2
Content-Type: text/plain; charset=utf-8

plain body
--b2
Content-Type: text/html; charset=utf-8

<p>html body</p>
--b2--
--b1
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

{pdf}
--b1
Content-Type: message/rfc822

From: Original <orig@example.net>
To: user@company.test
Subject: the original phish

inner body
--b1--
"""


def test_bodies_attachments_and_attached_email():
    pdf = b"%PDF-1.4 fake test content"
    raw = make_eml(extra_mime=MULTIPART.format(pdf=base64.b64encode(pdf).decode()))
    parsed = parse_eml(raw)
    assert parsed.text_body.strip() == "plain body"
    assert "<p>html body</p>" in parsed.html_body
    assert len(parsed.attachments) == 1
    attachment = parsed.attachments[0]
    assert (attachment.filename, attachment.content_type, attachment.inline) == ("invoice.pdf", "application/pdf", False)
    assert attachment.sha256 == hashlib.sha256(pdf).hexdigest()
    assert len(parsed.attached_emails) == 1
    assert parsed.attached_emails[0].subject == "the original phish"
    assert "inner body" not in parsed.text_body  # the attached email stays separate


def test_size_limit(monkeypatch):
    monkeypatch.setattr(parser, "MAX_EMAIL_BYTES", 100)
    with pytest.raises(EmailTooLarge):
        parse_eml(make_eml(body="x" * 200))


def test_part_limit(monkeypatch):
    monkeypatch.setattr(parser, "MAX_PARTS", 3)
    parts = "".join(f"--b\r\nContent-Type: text/plain\r\n\r\npart {n}\r\n" for n in range(10))
    parsed = parse_eml(make_eml(extra_mime=f'Content-Type: multipart/mixed; boundary="b"\r\n\r\n{parts}--b--\r\n'))
    assert any("MIME parts" in defect for defect in parsed.defects)
    assert parsed.text_body.count("part") == 2  # the container counts as the first part


def test_headers_keep_top_to_bottom_order():
    parsed = parse_eml(make_eml([("Received", "from b.example.net"), ("Received", "from a.example.org")]))
    assert parsed.header_all("Received") == ["from b.example.net", "from a.example.org"]
    assert parsed.header("received") == "from b.example.net"
