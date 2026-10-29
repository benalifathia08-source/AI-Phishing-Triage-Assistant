import base64
import io

import qrcode

from phishtriage.indicators import collect_indicators
from phishtriage.parser import parse_eml
from phishtriage.qr import inspect_pdf, qr_from_data_uri, qr_from_image
from tests.helpers import make_eml

TARGET = "https://mfa-reset.example.net/verify?id=42"


def qr_png(text: str = TARGET) -> bytes:
    buffer = io.BytesIO()
    qrcode.make(text).save(buffer, format="PNG")
    return buffer.getvalue()


def qr_pdf(text: str = TARGET) -> bytes:
    buffer = io.BytesIO()
    qrcode.make(text).get_image().convert("RGB").save(buffer, format="PDF")
    return buffer.getvalue()


LINK_PDF = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Annots [4 0 R]
  /Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >> endobj
4 0 obj << /Type /Annot /Subtype /Link /Rect [10 10 150 40] /A << /S /URI /URI (https://click.example.net/doc) >> >> endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
6 0 obj << /Length 60 >> stream
BT /F1 10 Tf 10 150 Td (Visit https://typed.example.net/a now) Tj ET
endstream endobj
trailer << /Root 1 0 R >>
%%EOF
"""


def test_qr_in_image():
    assert qr_from_image(qr_png()) == [TARGET]


def test_qr_in_inline_data_uri():
    assert qr_from_data_uri("data:image/png;base64," + base64.b64encode(qr_png()).decode()) == [TARGET]


def test_qr_in_pdf():
    facts = inspect_pdf(qr_pdf())
    assert facts.pages == 1
    assert facts.qr_codes == [TARGET]


def test_pdf_clickable_and_typed_links():
    facts = inspect_pdf(LINK_PDF)
    assert "https://click.example.net/doc" in facts.links
    assert "https://typed.example.net/a" in facts.links


def test_only_email_picture_formats_are_decoded():
    from PIL import Image

    def converted(fmt: str) -> bytes:
        out = io.BytesIO()
        Image.open(io.BytesIO(qr_png())).convert("RGB").save(out, format=fmt)
        return out.getvalue()

    assert qr_from_image(converted("JPEG")) == [TARGET]
    assert qr_from_image(converted("TIFF")) == []  # a rare decoder: never handed attacker bytes


def test_garbage_never_raises():
    assert qr_from_image(b"\x89PNG not really") == []
    assert inspect_pdf(b"%PDF-1.4 broken").unreadable or inspect_pdf(b"%PDF-1.4 broken").pages == 0


def test_qr_attachment_becomes_a_link():
    png = base64.b64encode(qr_png()).decode()
    mime = (
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain\r\n\r\nScan the code to keep your account.\r\n"
        "--b\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"code.png\"\r\n"
        f"Content-Transfer-Encoding: base64\r\n\r\n{png}\r\n--b--\r\n"
    )
    indicators = collect_indicators(parse_eml(make_eml(extra_mime=mime)))
    assert [(qr.source, qr.text) for qr in indicators.qr_codes] == [("qr:code.png", TARGET)]
    assert [link.source for link in indicators.web_links] == ["qr:code.png"]
