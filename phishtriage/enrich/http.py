"""A small JSON-over-HTTPS helper. Error messages never include request headers (API keys)."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

import truststore

USER_AGENT = "phishtriage/0.1"
# Verify certificates with the operating system, like a browser does. Python's own
# check fails on servers that omit an intermediate certificate (seen with RDAP for .nl).
_TLS = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


@dataclass
class HttpResponse:
    status: int  # 0 when the request never got an answer
    data: dict | list | None
    error: str = ""


def request_json(method: str, url: str, headers: dict[str, str] | None = None,
                 body: dict | None = None, timeout: float = 20) -> HttpResponse:
    if urlsplit(url).scheme not in ("http", "https"):  # urllib would also open file: and ftp: URLs
        return HttpResponse(0, None, "refused: only http and https URLs are fetched")
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=payload, method=method, headers={  # noqa: S310 - scheme checked above
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        **({"Content-Type": "application/json"} if payload is not None else {}),
        **(headers or {}),
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_TLS) as response:  # noqa: S310 - scheme checked above
            return HttpResponse(response.status, _json(response.read()))
    except urllib.error.HTTPError as error:
        return HttpResponse(error.code, _json(error.read()), f"HTTP {error.code}")
    except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
        reason = getattr(error, "reason", error)
        return HttpResponse(0, None, f"network error: {reason}")


def _json(raw: bytes) -> dict | list | None:
    try:
        return json.loads(raw) if raw else None
    except (ValueError, UnicodeDecodeError):
        return None
