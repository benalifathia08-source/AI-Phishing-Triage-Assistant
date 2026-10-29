"""Find every link in an email and record facts about each one.

Links come from the text body, the HTML body (anchors, forms, frames, meta
refresh, images), HTML and PDF attachments, and QR codes. Nothing is visited
here: this module only reads text.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote, urlsplit

from phishtriage.domains import (
    SHORTENER_DOMAINS, aligned, has_public_suffix, is_click_tracker, on_free_hosting, org_domain, suspicious_characters,
)

MAX_LINKS = 300
_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`{}|\\^\[\]]+")
_TRAILING = ".,;:!?)]}>'\""
_WEB_SCHEMES = ("http", "https")
# Non-web schemes worth reporting: callback phishing (tel), HTML smuggling (data),
# script links, and Windows protocol handlers abused to run code or open shares.
_SPECIAL_SCHEMES = ("tel", "data", "javascript", "vbscript", "file", "smb", "search-ms", "ms-msdt", "ms-officecmd")


@dataclass
class Link:
    url: str  # the link as found (cut at 2,000 characters)
    source: str  # text, html:a, html:form, html:iframe, html:meta-refresh, html:img, attachment:<name>, qr:<name>, embedded
    scheme: str = ""  # http, https, tel, data, javascript, file, ms-...
    host: str = ""  # the host the link really goes to
    org_domain: str = ""  # organization of the host
    link_text: str = ""  # the text shown for the link (cut at 200 characters)
    text_shows_other_domain: str = ""  # the link text names a different site than the real target
    host_is_ip: bool = False  # the host is a bare IP address
    is_shortener: bool = False  # a URL shortener (bit.ly, tinyurl.com...)
    on_free_hosting: bool = False  # free hosting, site builder or file sharing (web.app, sharepoint.com...)
    click_tracker: bool = False  # a mailing service's click-tracking domain (normal in newsletters)
    has_userinfo: bool = False  # http://trusted.example@evil.test/ really goes to evil.test
    nonstandard_port: bool = False  # an unusual port, such as :8443
    suspicious_characters: list[str] = field(default_factory=list)  # lookalike characters in the host
    embedded_urls: list[str] = field(default_factory=list)  # web addresses carried in the query (redirectors, Safe Links)


class _HtmlLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[tuple[str, str, str]] = []  # (url, source, link text)
        self.inline_images: list[str] = []  # data: image URLs, scanned for QR codes later
        self.outside_text: list[str] = []  # text outside links and <style>, searched for written-out URLs
        self._anchor: list | None = None
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "style":
            self._in_style = True
        elif tag == "a":
            self._close_anchor()
            if values.get("href"):
                self._anchor = [values["href"], []]
        elif tag == "area" and values.get("href"):
            self.found.append((values["href"], "html:a", ""))
        elif tag == "form" and values.get("action"):
            self.found.append((values["action"], "html:form", ""))
        elif tag in ("button", "input") and values.get("formaction"):
            self.found.append((values["formaction"], "html:form", ""))
        elif tag in ("iframe", "frame", "embed", "object") and (values.get("src") or values.get("data")):
            self.found.append((values.get("src") or values["data"], "html:iframe", ""))
        elif tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"(?i)url\s*=\s*['\"]?([^'\";]+)", values.get("content", ""))
            if match:
                self.found.append((match.group(1), "html:meta-refresh", ""))
        elif tag == "img" and values.get("src"):
            if values["src"].lower().startswith("data:image"):
                self.inline_images.append(values["src"])
            else:
                self.found.append((values["src"], "html:img", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._close_anchor()
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._anchor is not None:
            self._anchor[1].append(data)
        elif not self._in_style:
            self.outside_text.append(data)

    def _close_anchor(self) -> None:
        if self._anchor is not None:
            self.found.append((self._anchor[0], "html:a", " ".join(" ".join(self._anchor[1]).split())))
            self._anchor = None

    def close(self) -> None:
        super().close()
        self._close_anchor()


def parse_html(html_text: str) -> _HtmlLinks:
    collector = _HtmlLinks()
    try:
        collector.feed(html_text)
        collector.close()
    except Exception:  # noqa: BLE001 - broken markup must not stop the analysis
        collector._close_anchor()
    return collector


def urls_in_text(text: str) -> list[str]:
    return [match.group(0).rstrip(_TRAILING) for match in _URL_IN_TEXT.finditer(text)]


def _normalize(url: str) -> str:
    # Browsers ignore tabs and newlines inside URLs; attackers use them to break filters.
    url = re.sub(r"[\t\r\n]", "", url).strip()
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


# Security gateways rewrite links so clicks pass through them first. The real
# destination is inside the wrapper, and the wrapper's own domain says nothing.
LINK_WRAPPERS = ("safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com",
                 "mimecast.com", "linkprotect.cudasvc.com")
_PROOFPOINT_V3 = re.compile(r"/v3/__(.+?)__;")


def _is_wrapper(host: str) -> bool:
    return any(host == wrapper or host.endswith("." + wrapper) for wrapper in LINK_WRAPPERS)


def _proofpoint_v2(value: str) -> str:
    """u=https-3A__www.example.com_page -> https://www.example.com/page"""
    return re.sub(r"-([0-9A-Fa-f]{2})", lambda match: chr(int(match.group(1), 16)), value.replace("_", "/"))


def _embedded(parts) -> list[str]:
    found = []
    if (match := _PROOFPOINT_V3.search(parts.path)) and (parts.hostname or "").endswith("urldefense.com"):
        found.append(re.sub(r"^(https?):/(?!/)", r"\1://", match.group(1)))  # v3 writes "http:/host"
    for name, value in parse_qsl(parts.query, keep_blank_values=True) + [("", unquote(parts.fragment))]:
        value = value.strip()
        if name == "u" and value.lower().startswith(("http-3a", "https-3a")):
            value = _proofpoint_v2(value)
        if value.lower().startswith(("http://", "https://")):
            found.append(value)
    return found[:5]


def make_link(url: str, source: str, link_text: str = "") -> Link | None:
    url = _normalize(url)
    if not url or url.startswith("#"):
        return None
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme not in _WEB_SCHEMES:
        if scheme in _SPECIAL_SCHEMES or scheme.startswith("ms-"):
            # data: links can be megabytes long; keep only the start
            return Link(url=url[:200], source=source, scheme=scheme, link_text=link_text[:200])
        return None  # mailto:, cid: (inline images), relative paths
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").strip(".")
    except ValueError:
        return None
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        port = -1
    try:
        ipaddress.ip_address(host)
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    link = Link(
        url=url[:2000],
        source=source,
        scheme=scheme,
        host=host,
        org_domain=host if host_is_ip else org_domain(host),
        link_text=link_text[:200],
        host_is_ip=host_is_ip,
        is_shortener=org_domain(host) in SHORTENER_DOMAINS or host in SHORTENER_DOMAINS,
        on_free_hosting=on_free_hosting(host),
        click_tracker=is_click_tracker(host),
        has_userinfo="@" in parts.netloc,
        nonstandard_port=port not in (None, 80, 443),
        suspicious_characters=suspicious_characters(host),
        embedded_urls=_embedded(parts),
    )
    link.text_shows_other_domain = _text_mismatch(link)
    return link


def _shown_domains(text: str) -> list[str]:
    """Web addresses the reader sees in link text. Only URL-looking tokens count, or a
    link text that is a single domain, so a sentence like "your space.You can" is ignored."""
    tokens = text.split()
    shown = []
    for token in tokens:
        token = token.strip("()[]<>.,;:!?'\"").lower()
        if not (token.startswith(("http://", "https://", "www.")) or len(tokens) == 1):
            continue
        try:
            host = urlsplit(token if "://" in token else "http://" + token).hostname or ""
        except ValueError:
            continue
        if "." in host and has_public_suffix(host) and not _is_wrapper(host):
            shown.append(host)
    return shown


def _text_mismatch(link: Link) -> str:
    """The domain shown in the link text, when it is not where the link really goes."""
    shown = _shown_domains(link.link_text)
    if not shown:
        return ""
    targets = [link.host]
    for url in link.embedded_urls:
        try:
            targets.append(urlsplit(url).hostname or "")
        except ValueError:
            pass
    for domain in shown:
        if not any(aligned(domain, target) for target in targets if target):
            return domain
    return ""


@dataclass
class LinkCollection:
    links: list[Link] = field(default_factory=list)
    inline_images: list[str] = field(default_factory=list)
    truncated: bool = False
    _seen: set = field(default_factory=set, repr=False)

    def add(self, url: str, source: str, link_text: str = "") -> None:
        if len(self.links) >= MAX_LINKS:
            self.truncated = True
            return
        link = make_link(url, source, link_text)
        if link is None:
            return
        # Plain-text copies of a URL (text part, URL shown as link text) add nothing new.
        is_text = source == "text" or source.endswith("text")
        if (link.url in self._seen and is_text) or (link.url, source, link.link_text) in self._seen:
            return
        self._seen.update({link.url, (link.url, source, link.link_text)})
        self.links.append(link)
        for embedded in link.embedded_urls:
            if len(self.links) < MAX_LINKS and (inner := make_link(embedded, "embedded")):
                self.links.append(inner)

    def add_html(self, html_text: str, source: str = "") -> None:
        """Links in an HTML document. `source` labels them all (e.g. an attachment name)."""
        collector = parse_html(html_text)
        for url, tag_source, text in collector.found:
            self.add(url, source or tag_source, text)
        self.inline_images.extend(collector.inline_images[:20])
        # URLs written as plain text inside the HTML. Link texts are left out: what an
        # anchor displays is not where it goes, and it was recorded with the anchor.
        for url in urls_in_text(" ".join(collector.outside_text)):
            self.add(url, source or "html:text")

    def add_text(self, text: str, source: str = "text") -> None:
        for url in urls_in_text(text):
            self.add(url, source)
