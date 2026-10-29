"""Read QR codes from images and PDF pages ("quishing": the link hides in a picture).

Image and PDF decoders parse attacker-supplied bytes, so inputs are capped in
size, pixels and pages, and every failure is swallowed: an unreadable picture
just yields no QR code.
"""
from __future__ import annotations

import base64
import ctypes
import io
import re
import warnings
from dataclasses import dataclass, field

import cv2
import numpy as np
import pypdfium2 as pdfium
import pypdfium2.raw as pdfium_c
from PIL import Image

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_PIXELS = 25_000_000  # about 5000 x 5000
MAX_PDF_BYTES = 20 * 1024 * 1024
MAX_PDF_PAGES = 3  # QR lures sit on the first page; rendering more costs time
MAX_PDF_LINKS = 100
# Only the picture formats email carries. Images come from the attacker, and most of Pillow's
# vulnerabilities sit in rarer decoders (TIFF, EPS, XBM, MIC...), which are never reached this way.
IMAGE_FORMATS = ("PNG", "JPEG", "GIF", "BMP", "WEBP")
_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"'`{}|\\^\[\]]+")

Image.MAX_IMAGE_PIXELS = MAX_PIXELS
try:  # OpenCV prints decoder warnings (e.g. "ECI is not supported") straight to the console
    cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_ERROR)
except AttributeError:
    pass


def _decode_array(gray: np.ndarray) -> list[str]:
    found: list[str] = []
    detectors = [cv2.QRCodeDetectorAruco(), cv2.QRCodeDetector()] if hasattr(cv2, "QRCodeDetectorAruco") else [cv2.QRCodeDetector()]
    candidates = [gray]
    if max(gray.shape[:2]) < 400:  # small codes decode better when enlarged
        candidates.append(cv2.resize(gray, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST))
    for image in candidates:
        for detector in detectors:
            try:
                ok, texts, _, _ = detector.detectAndDecodeMulti(image)
            except cv2.error:
                continue
            if ok:
                found.extend(text for text in texts if text)
        if found:
            break
    return list(dict.fromkeys(found))


def _to_gray(image: Image.Image) -> np.ndarray:
    if image.mode in ("RGBA", "LA", "P"):
        # Transparent backgrounds would turn black; put the picture on white.
        background = Image.new("RGB", image.size, "white")
        background.paste(image.convert("RGBA"), mask=image.convert("RGBA").split()[-1])
        image = background
    return np.array(image.convert("L"))


def qr_from_image(data: bytes) -> list[str]:
    if not data or len(data) > MAX_IMAGE_BYTES:
        return []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data), formats=IMAGE_FORMATS) as image:
                if image.width * image.height > MAX_PIXELS:
                    return []
                image.seek(0)  # first frame of an animated GIF
                return _decode_array(_to_gray(image))
    except Exception:  # noqa: BLE001 - corrupt or hostile images just yield nothing
        return []


def qr_from_data_uri(uri: str) -> list[str]:
    match = re.match(r"(?is)data:image/[\w.+-]+;base64,(.*)", uri)
    if not match:
        return []
    try:
        return qr_from_image(base64.b64decode(match.group(1)[: MAX_IMAGE_BYTES * 2], validate=False))
    except (ValueError, TypeError):
        return []


@dataclass
class PdfFacts:
    pages: int = 0
    encrypted: bool = False
    unreadable: bool = False
    links: list[str] = field(default_factory=list)  # clickable links and URLs written in the text
    qr_codes: list[str] = field(default_factory=list)


def _link_uris(document: pdfium.PdfDocument, page: pdfium.PdfPage) -> list[str]:
    uris = []
    position = ctypes.c_int(0)
    link = pdfium_c.FPDF_LINK()
    while len(uris) < MAX_PDF_LINKS and pdfium_c.FPDFLink_Enumerate(page.raw, ctypes.byref(position), ctypes.byref(link)):
        action = pdfium_c.FPDFLink_GetAction(link)
        if not action or pdfium_c.FPDFAction_GetType(action) != pdfium_c.PDFACTION_URI:
            continue
        size = pdfium_c.FPDFAction_GetURIPath(document.raw, action, None, 0)
        if 0 < size <= 8192:
            buffer = ctypes.create_string_buffer(size)
            pdfium_c.FPDFAction_GetURIPath(document.raw, action, buffer, size)
            uris.append(buffer.value.decode("latin-1"))
    return uris


def inspect_pdf(data: bytes) -> PdfFacts:
    facts = PdfFacts()
    if len(data) > MAX_PDF_BYTES:
        facts.unreadable = True
        return facts
    try:
        document = pdfium.PdfDocument(data)
    except pdfium.PdfiumError as error:
        facts.encrypted = "password" in str(error).lower()
        facts.unreadable = not facts.encrypted
        return facts
    try:
        facts.pages = len(document)
        for index in range(min(facts.pages, MAX_PDF_PAGES)):
            page = document[index]
            try:
                facts.links.extend(_link_uris(document, page))
                text = page.get_textpage().get_text_range()
                facts.links.extend(match.group(0).rstrip(".,;:!?)]}>'\"") for match in _URL.finditer(text))
                # A hostile PDF can declare a page several metres wide; cap the bitmap size.
                width, height = page.get_size()
                scale = min(2.0, (MAX_PIXELS / max(width * height, 1)) ** 0.5)
                rendered = page.render(scale=scale).to_pil()
                facts.qr_codes.extend(_decode_array(_to_gray(rendered)))
            finally:
                page.close()
    except Exception:  # noqa: BLE001
        facts.unreadable = True
    finally:
        document.close()
    facts.links = list(dict.fromkeys(facts.links))[:MAX_PDF_LINKS]
    facts.qr_codes = list(dict.fromkeys(facts.qr_codes))
    return facts
