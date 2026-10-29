"""The local web interface: `phishtriage web` (http://127.0.0.1:8765).

Every email shown here was written by an attacker, and the page runs in a browser that is logged in to
everything else, so:
  - it listens on 127.0.0.1 only, and rejects any other Host header (DNS rebinding: a website whose name
    suddenly points to 127.0.0.1 cannot read the pages);
  - it holds its port exclusively: on Windows, the usual SO_REUSEADDR lets any other program open the same
    port and receive the uploads (found 2026-10-22), so the port is opened with SO_EXCLUSIVEADDRUSE;
  - other programs and users on the same computer can reach 127.0.0.1 too, so each run prints a secret
    link: opening it sets a session cookie (HttpOnly, SameSite=Strict), and every page needs that cookie;
  - there is no JavaScript at all, and the Content-Security-Policy forbids every script, plugin and frame;
  - every value from the email is escaped, invisible characters are shown, links are defanged and never
    clickable, and the email's own HTML and pictures are never rendered;
  - POST requests need a token from this run and must come from this page (Origin, Sec-Fetch-Site), so
    another website cannot make the browser submit emails here (CSRF) and spend the lookup quotas;
  - reports stay in memory, behind unguessable IDs, and responses are never cached;
  - the analysis runs in a child process with a time limit (phishtriage.isolate).
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
from collections import OrderedDict
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from phishtriage import exports
from phishtriage.pipeline import Options, triage
from phishtriage.web import pages

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_FILE = pages.MAX_UPLOAD_MB * 1024 * 1024
MAX_BODY = MAX_FILE + 64 * 1024  # the file plus the form fields around it
MAX_REPORTS = 20  # the oldest is forgotten first
COOKIE = "phishtriage_session"
STATIC = Path(__file__).resolve().parent / "static"
_REPORT = re.compile(r"^/report/([A-Za-z0-9_-]{22})(?:/(report\.json|report\.md|iocs\.csv))?$")
_BOUNDARY = re.compile(r'boundary="?([0-9A-Za-z\'()+_,./:=? -]{1,70})"?(?:;|$)')
_DISPOSITION = re.compile(r'(?i)\bform-data\b(.*)$')
_PARAM = re.compile(r'(?i);\s*(name|filename)="((?:[^"\\]|\\.)*)"')

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


class FormError(ValueError):
    pass


def parse_form(body: bytes, content_type: str) -> dict[str, tuple[str | None, bytes]]:
    """A strict multipart/form-data parser that keeps file bytes exactly as sent.

    The standard library has none (cgi is gone), and parsing the form as an email would treat the .eml
    as an attached message and re-encode it, which breaks DKIM signatures. Returns {name: (filename, data)}."""
    match = _BOUNDARY.search(content_type or "")
    if not content_type.lower().startswith("multipart/form-data") or not match:
        raise FormError("expected a multipart/form-data upload")
    delimiter = b"--" + match.group(1).strip().encode("ascii")
    if not body.startswith(delimiter + b"\r\n"):
        raise FormError("the upload does not start with its boundary")
    fields: dict[str, tuple[str | None, bytes]] = {}
    for chunk in body[len(delimiter) + 2:].split(b"\r\n" + delimiter):
        if chunk.startswith(b"--"):
            break  # the closing delimiter
        if len(fields) >= 10:
            raise FormError("too many form fields")
        chunk = chunk[2:] if chunk.startswith(b"\r\n") else chunk
        head, separator, data = chunk.partition(b"\r\n\r\n")
        if not separator:
            raise FormError("a form field has no headers")
        disposition = next((line.split(b":", 1)[1].decode("utf-8", "replace") for line in head.split(b"\r\n")
                            if line.lower().startswith(b"content-disposition:")), "")
        found = _DISPOSITION.search(disposition)
        params = {key.lower(): value.replace('\\"', '"') for key, value in _PARAM.findall(found.group(1))} if found else {}
        if "name" not in params:
            raise FormError("a form field has no name")
        fields[params["name"]] = (params.get("filename"), data)
    else:
        raise FormError("the upload has no closing boundary")
    return fields


class App:
    """State of one server run: the token, the reports, and the single analysis process."""

    def __init__(self, settings, analyzer, enricher_factory=None, ai_client_factory=None, ai_available: bool = False,
                 notice: str = "") -> None:
        self.settings, self.analyzer = settings, analyzer
        self.enricher_factory, self.ai_client_factory = enricher_factory, ai_client_factory
        self.ai_available, self.notice = ai_available, notice
        self.token = secrets.token_urlsafe(32)  # in every form: proves a POST came from one of our pages
        self.launch_key = secrets.token_urlsafe(24)  # in the link printed at start: proves who opened the tool
        self.session = secrets.token_urlsafe(32)  # the cookie set by that link
        self._reports: OrderedDict[str, object] = OrderedDict()
        self._store_lock = threading.Lock()
        self.analysis_lock = threading.Lock()  # one analysis at a time: there is one child process
        self.stylesheet = (STATIC / "style.css").read_bytes()

    def add(self, report) -> str:
        report_id = secrets.token_urlsafe(16)  # 22 characters, 128 bits: not guessable
        with self._store_lock:
            self._reports[report_id] = report
            while len(self._reports) > MAX_REPORTS:
                self._reports.popitem(last=False)
        return report_id

    def get(self, report_id: str):
        with self._store_lock:
            return self._reports.get(report_id)

    def recent(self) -> list[tuple[str, object]]:
        with self._store_lock:
            return list(reversed(self._reports.items()))

    def forget(self) -> None:
        with self._store_lock:
            self._reports.clear()


class Handler(BaseHTTPRequestHandler):
    server_version = "phishtriage"
    sys_version = ""
    timeout = 60  # seconds to receive a request: a slow client cannot hold a thread forever
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> App:
        return self.server.app

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - the base class's name
        sys.stderr.write(f"{self.log_date_time_string()} {format % args}\n")  # paths hold report IDs, never email text

    # --- responses ---------------------------------------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str, headers: dict | None = None) -> None:
        self.send_response(status)
        for name, value in {**SECURITY_HEADERS, **(headers or {})}.items():
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _html(self, status: int, page: str) -> None:
        self._send(status, page.encode("utf-8"), "text/html; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self.close_connection = True
        self._html(status, pages.error_page(status, message))

    def _redirect(self, location: str) -> None:
        self._send(303, b"", "text/plain; charset=utf-8", {"Location": location})

    def _download(self, data: str, filename: str, content_type: str) -> None:
        self._send(200, data.encode("utf-8"), content_type,
                   {"Content-Disposition": f'attachment; filename="{filename}"'})

    # --- checks --------------------------------------------------------------------------------------------
    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _authorized(self) -> bool:
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
        except CookieError:
            return False
        return cookie is not None and hmac.compare_digest(cookie.value, self.app.session)

    def _same_origin(self) -> bool:
        """Did this POST come from one of our own pages? (The form token is checked as well.)

        Sec-Fetch-Site is set by the browser itself, never by a page's script, so it decides when present.
        Origin cannot decide alone: under a no-referrer policy the browser sends "Origin: null" even for our
        own form. The first version required a real Origin and refused every upload from a real browser
        (2026-10-22, found by Fathia's first-user test); a privacy extension can force that policy again."""
        origin = self.headers.get("Origin")
        own_or_hidden = origin is None or origin == "null" or origin in self.server.allowed_origins
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site in ("same-origin", "none") and own_or_hidden
        return origin is None or origin in self.server.allowed_origins  # older browsers: a sent Origin must be ours

    # --- GET -----------------------------------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - the base class's name
        if not self._host_ok():
            return self._error(421, "This server only answers at 127.0.0.1 or localhost.")
        path, _, query = self.path.partition("?")
        if path == "/static/style.css":  # public and harmless: lets the error pages keep their style
            return self._send(200, self.app.stylesheet, "text/css; charset=utf-8")
        key = parse_qs(query).get("key", [""])[0]
        if key:
            if not hmac.compare_digest(key, self.app.launch_key):
                if self._authorized():  # an old link from the history, but this browser is already in
                    return self._redirect("/")
                return self._error(403, "This link belongs to an earlier run, or was cut short. Use the link the "
                                        "terminal printed when you last started the server.")
            # The key leaves the address bar (and the history) at once; the session lives in a cookie
            return self._send(303, b"", "text/plain; charset=utf-8", {
                "Location": "/", "Set-Cookie": f"{COOKIE}={self.app.session}; HttpOnly; SameSite=Strict; Path=/"})
        if not self._authorized():
            return self._error(401, "Open the link printed in the terminal when the server started.")
        if path == "/":
            return self._html(200, pages.upload_page(self.app.token, self.app.recent(), self.app.ai_available,
                                                     self.app.notice))
        match = _REPORT.match(path)
        report = self.app.get(match.group(1)) if match else None
        if report is None:
            return self._error(404, "No such report. Reports are kept in memory and forgotten when the server stops.")
        kind, stem = match.group(2), f"phishtriage-{report.sha256[:12]}"
        if kind is None:
            return self._html(200, pages.report_page(match.group(1), report, self.app.token))
        if report.failed:
            return self._error(404, "A failed analysis has nothing to export.")
        if kind == "report.json":
            return self._download(json.dumps(exports.report_json(report), indent=2, ensure_ascii=False, default=str),
                                  f"{stem}.json", "application/json; charset=utf-8")
        if kind == "report.md":
            return self._download(exports.report_markdown(report), f"{stem}.md", "text/markdown; charset=utf-8")
        return self._download("\ufeff" + exports.iocs_csv(report), f"{stem}-iocs.csv", "text/csv; charset=utf-8")

    do_HEAD = do_GET  # noqa: N815

    # --- POST ----------------------------------------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._error(421, "This server only answers at 127.0.0.1 or localhost.")
        if not self._same_origin():
            return self._error(403, "This request did not come from this page.")
        if not self._authorized():
            return self._error(401, "Open the link printed in the terminal when the server started.")
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self._error(411, "Send the upload with a length.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._error(411, "Send the upload with a length.")
        if length < 0 or length > MAX_BODY:
            return self._error(413, f"The email is larger than {pages.MAX_UPLOAD_MB} MB.")
        body = self.rfile.read(length)
        if len(body) != length:
            return self._error(400, "The upload was cut short.")
        try:
            fields = parse_form(body, self.headers.get("Content-Type", ""))
        except FormError as error:
            return self._error(400, f"Unreadable form: {error}.")
        sent_token = fields.get("token", (None, b""))[1].decode("ascii", "replace")
        if not hmac.compare_digest(sent_token, self.app.token):
            return self._error(403, "The form has expired (the server was restarted). Reload the page.")
        path = self.path.split("?", 1)[0]
        if path == "/forget":
            self.app.forget()
            return self._redirect("/")
        if path != "/analyze":
            return self._error(404, "Nothing here.")
        filename, raw = fields.get("file", (None, b""))
        if not raw:
            return self._error(400, "Choose an .eml file first.")
        if len(raw) > MAX_FILE:
            return self._error(413, f"The email is larger than {pages.MAX_UPLOAD_MB} MB.")
        lookups = "lookups" in fields
        options = Options(lookups=lookups, scan=lookups and "scan" in fields,
                          ai="ai" in fields and self.app.ai_available)
        with self.app.analysis_lock:
            report = triage(raw, filename or "upload.eml", self.app.settings, self.app.analyzer, options,
                            self.app.enricher_factory, self.app.ai_client_factory)
        self._redirect(f"/report/{self.app.add(report)}")


class LocalServer(ThreadingHTTPServer):
    """A server that holds its port alone.

    Python's servers set SO_REUSEADDR. On Windows that option lets a second program open the same port while
    this one listens, and connections then go to either: any program on the computer could receive the
    emails uploaded here. It also let an old copy of this server keep answering after a new one started
    (Fathia's first-user test, 2026-10-22). SO_EXCLUSIVEADDRUSE refuses any other program the port."""
    daemon_threads = True
    allow_reuse_address = os.name != "nt"  # elsewhere SO_REUSEADDR only allows a quick restart

    def server_bind(self) -> None:
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_server(app: App, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    server = LocalServer((HOST, port), Handler)
    server.app = app
    port = server.server_address[1]  # the real one when port 0 was asked (tests)
    server.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    server.allowed_origins = {f"http://{host}" for host in server.allowed_hosts}
    return server


def ollama_reachable(settings) -> bool:
    from phishtriage.enrich.http import request_json

    try:
        return request_json("GET", f"{settings.ollama_host.rstrip('/')}/api/tags", timeout=2).status == 200
    except Exception:  # noqa: BLE001 - only decides whether the AI option is offered
        return False


def serve(settings, port: int = DEFAULT_PORT) -> int:
    from phishtriage.enrich.cache import purge_expired
    from phishtriage.isolate import IsolatedAnalyzer
    from phishtriage.pipeline import default_factories

    purged = purge_expired(settings)
    enricher_factory, ai_client_factory = default_factories(settings)
    notice = (f"Lookup results are kept {settings.cache_retention_days} days"
              + (f" ({purged} older ones were just removed)." if purged else "."))
    with IsolatedAnalyzer(settings) as analyzer:
        app = App(settings, analyzer, enricher_factory, ai_client_factory, ollama_reachable(settings), notice)
        try:
            server = make_server(app, port)
        except OSError:
            print(f"Port {port} is already in use: is phishtriage web already running in another window? "
                  f"Stop it (Ctrl+C there), or start this one with --port {port + 1}.", file=sys.stderr)
            return 1
        print(f"Phishing triage: http://127.0.0.1:{server.server_address[1]}/?key={app.launch_key}", flush=True)
        print("Open that link (it is valid until the server stops). Ctrl+C to stop; reports are not saved.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0
