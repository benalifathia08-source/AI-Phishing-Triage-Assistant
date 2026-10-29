"""Facts about attachments, read from their bytes. Nothing is opened, extracted or run.

The declared file name and content type are written by the attacker, so the
real type comes from the first bytes of the file ("magic bytes").
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

from phishtriage.domains import suspicious_characters
from phishtriage.parser import Attachment

EXECUTABLE = {"exe", "scr", "com", "pif", "msi", "dll", "cpl", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
              "wsf", "wsh", "hta", "jar", "lnk", "reg", "appx", "msix", "msc", "url", "library-ms", "settingcontent-ms"}
DISK_IMAGE = {"iso", "img", "vhd", "vhdx"}
ARCHIVE = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "xz", "bz2", "z"}
HTML = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
MACRO_DOCUMENT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam"}
DOCUMENT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "one", "csv", "txt"}
IMAGE = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "ico"}

_HTML_TRICKS = {
    "decodes hidden text (atob)": re.compile(r"\batob\s*\("),
    "builds code at runtime (eval / Function)": re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
    "unescapes encoded text (unescape / decodeURIComponent)": re.compile(r"\bunescape\s*\(|decodeURIComponent\s*\("),
    "writes the page from script (document.write)": re.compile(r"document\.write\s*\("),
    "redirects the browser (location)": re.compile(r"(?:window|document|top|self)\.location\b|location\.(?:href|replace|assign)"),
    "builds strings from character codes": re.compile(r"String\.fromCharCode\s*\("),
    "creates a downloadable file in the browser (HTML smuggling)": re.compile(r"createObjectURL\s*\(|msSaveOrOpenBlob|new\s+Blob\s*\("),
    "sends data out (fetch / XMLHttpRequest)": re.compile(r"\bfetch\s*\(|XMLHttpRequest|\$\.(?:ajax|post)\s*\("),
}


@dataclass
class AttachmentInfo:
    filename: str  # file name as declared by the sender
    extension: str  # extension from the file name ('' when none)
    declared_type: str  # MIME type declared by the sender
    size: int  # size in bytes
    sha256: str  # SHA-256: what VirusTotal is asked about
    inline: bool  # shown inside the email (logos, pictures) rather than attached
    detected_type: str  # from magic bytes: pdf, zip, ooxml, ole, html, svg, pe, iso, lnk, rtf, onenote, png, ...
    category: str  # executable, config-profile, disk-image, archive, html, macro-document, document, image, other
    extension_mismatch: bool = False  # the name says one type, the bytes say another
    double_extension: bool = False  # invoice.pdf.html
    name_suspicious_characters: list[str] = field(default_factory=list)  # e.g. right-to-left override
    encrypted_archive: bool = False  # password-protected archives hide their content from scanners
    archive_members: list[str] = field(default_factory=list)  # file names inside a zip (listed, never extracted; first 50)
    archive_risky_members: list[str] = field(default_factory=list)  # risky files inside a zip: executables, scripts, HTML, disk images, macro documents
    has_macros: bool = False  # an Office document with VBA macros
    html_login_form: bool = False  # asks for a password inside the attachment itself
    html_script_tricks: list[str] = field(default_factory=list)  # script tricks in an HTML or SVG attachment: atob, eval, redirects, HTML smuggling...
    pdf_encrypted: bool = False  # a password-protected PDF
    pdf_pages: int = 0  # pages in a PDF (0 when not a PDF or unreadable)
    # What an Apple configuration profile would change, e.g. com.apple.vpn.managed,
    # com.apple.security.root (trusted root certificate), com.apple.mdm (device management)
    config_profile_payloads: list[str] = field(default_factory=list)


def detect_type(data: bytes) -> str:
    head = data[:16]
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"  # .doc, .xls, .ppt, .msg, .msi
    if head.startswith(b"MZ"):
        return "pe"  # Windows executable
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d"):
        return "onenote"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if head.startswith(b"\x89PNG"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"BM"):
        return "bmp"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if head.startswith(b"\x30\x82") and b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" in data[:40]:
        # PKCS#7 signed data. With a property list inside it is a signed Apple
        # configuration profile, which can install VPNs, proxies or root certificates.
        return "mobileconfig" if b"PayloadType" in data[:200_000] else "pkcs7"
    start = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if start.startswith(b"<svg") or (start.startswith(b"<?xml") and b"<svg" in start):
        return "svg"
    if any(marker in start for marker in (b"<html", b"<!doctype html", b"<head", b"<body", b"<script", b"<form", b"<meta")):
        return "html"
    if start.startswith(b"<?xml"):
        return "mobileconfig" if b"PayloadType" in data[:200_000] and b"<plist" in data[:4096] else "xml"
    return "unknown"


_TYPE_FOR_EXTENSION = {
    "pdf": {"pdf"}, "zip": {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "potm",
                             "ppam", "jar", "odt", "ods", "appx", "msix", "apk", "epub"},
    "ole": {"doc", "xls", "ppt", "msg", "msi", "dot", "xlt", "pot"}, "rtf": {"rtf", "doc"},
    "html": HTML, "svg": {"svg"}, "png": {"png"}, "jpeg": {"jpg", "jpeg", "jpe", "jfif"}, "gif": {"gif"},
    "webp": {"webp"}, "bmp": {"bmp"}, "iso": {"iso", "img"}, "lnk": {"lnk"}, "onenote": {"one"},
    "rar": {"rar"}, "7z": {"7z"}, "mobileconfig": {"mobileconfig", "plist", "xml"}, "gzip": {"gz", "tgz"}, "cab": {"cab"}, "pe": {"exe", "dll", "scr", "com", "cpl", "sys"},
}


def _category(extension: str, detected: str, has_macros: bool) -> str:
    if extension in EXECUTABLE or detected in ("pe", "elf", "lnk"):
        return "executable"
    if extension == "mobileconfig" or detected == "mobileconfig":
        return "config-profile"
    if extension in DISK_IMAGE or detected == "iso":
        return "disk-image"
    if extension in HTML or detected in ("html", "svg"):
        return "html"
    if extension in MACRO_DOCUMENT or has_macros:
        return "macro-document"
    if extension in ARCHIVE or (detected in ("zip", "rar", "7z", "gzip", "cab") and extension not in DOCUMENT):
        return "archive"
    if extension in DOCUMENT or detected in ("pdf", "ole", "rtf", "onenote"):
        return "document"
    if extension in IMAGE or detected in ("png", "jpeg", "gif", "webp", "bmp"):
        return "image"
    return "other"


def _inspect_zip(data: bytes, info: AttachmentInfo) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()[:500]  # listing only: nothing is decompressed
    except (zipfile.BadZipFile, ValueError, OSError, EOFError, NotImplementedError):
        return
    names = [entry.filename for entry in entries]
    if "[Content_Types].xml" in names:
        info.detected_type = "ooxml"  # Word / Excel / PowerPoint file
        info.has_macros = any(name.lower().endswith("vbaproject.bin") for name in names)
        return
    info.encrypted_archive = any(entry.flag_bits & 0x1 for entry in entries)
    info.archive_members = names[:50]
    for name in names:
        extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if extension in EXECUTABLE | DISK_IMAGE | HTML | MACRO_DOCUMENT | ARCHIVE:
            info.archive_risky_members.append(name)
    info.archive_risky_members = info.archive_risky_members[:20]


def _inspect_html(data: bytes, info: AttachmentInfo) -> str:
    text = data[:2_000_000].decode("utf-8", errors="replace")
    lowered = text.lower()
    info.html_login_form = "<form" in lowered and bool(re.search(r"type\s*=\s*['\"]?password", lowered))
    info.html_script_tricks = [label for label, pattern in _HTML_TRICKS.items() if pattern.search(text)]
    return text


def inspect_attachment(attachment: Attachment) -> tuple[AttachmentInfo, str]:
    """Facts about one attachment, plus its text when it is HTML/SVG (for link extraction)."""
    name = attachment.filename
    parts = name.lower().rsplit(".", 2)
    extension = parts[-1] if len(parts) > 1 else ""
    detected = detect_type(attachment.data)
    info = AttachmentInfo(
        filename=name,
        extension=extension,
        declared_type=attachment.content_type,
        size=attachment.size,
        sha256=attachment.sha256,
        inline=attachment.inline,
        detected_type=detected,
        category="other",
        double_extension=len(parts) == 3 and parts[1] in DOCUMENT | IMAGE | {"pdf"} and extension in EXECUTABLE | HTML | DISK_IMAGE | ARCHIVE,
        name_suspicious_characters=suspicious_characters(name),
    )
    html_text = ""
    if detected == "zip":
        _inspect_zip(attachment.data, info)
    elif detected == "ole":
        info.has_macros = b"_VBA_PROJECT" in attachment.data or b"V\x00B\x00A\x00" in attachment.data
    elif detected == "mobileconfig":
        payloads = re.findall(rb"<key>PayloadType</key>\s*<string>([^<]{1,100})</string>", attachment.data[:1_000_000])
        info.config_profile_payloads = list(dict.fromkeys(item.decode("ascii", "replace") for item in payloads))[:20]
    if detected in ("html", "svg") or (extension in HTML and detected in ("unknown", "xml")):
        html_text = _inspect_html(attachment.data, info)

    expected = _TYPE_FOR_EXTENSION.get(info.detected_type if info.detected_type != "ooxml" else "zip")
    info.extension_mismatch = bool(extension) and expected is not None and extension not in expected
    info.category = _category(extension, info.detected_type, info.has_macros)
    return info, html_text
