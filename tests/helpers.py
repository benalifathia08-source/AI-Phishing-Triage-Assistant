"""Build test emails in code. Only reserved names are used: example.com/.net/.org,
.test domains (RFC 2606) and documentation IP ranges (RFC 5737)."""
from __future__ import annotations

import hashlib


def make_eml(
    headers: list[tuple[str, str]] | None = None,
    body: str = "Hello,\r\nThis is a test message.\r\n",
    *,
    from_: str = "Example Sender <sender@example.com>",
    to: str = "analyst@company.test",
    subject: str = "Test message",
    date: str = "Wed, 07 Oct 2026 09:00:00 +0000",
    content_type: str = "text/plain; charset=utf-8",
    extra_mime: str | None = None,
) -> bytes:
    """Headers in `headers` come first (the top of the email, like a receiving server adds them)."""
    lines = [f"{name}: {value}" for name, value in (headers or [])]
    # A Message-ID unique to the content, like real mail (duplicate detection relies on it)
    message_id = hashlib.sha1(f"{headers}{from_}{to}{subject}{date}{body}{extra_mime}".encode(),
                              usedforsecurity=False).hexdigest()[:16]
    lines += [f"From: {from_}", f"To: {to}" if to else None, f"Subject: {subject}", f"Date: {date}",
              f"Message-ID: <{message_id}@example.com>", "MIME-Version: 1.0"]
    lines = [line for line in lines if line is not None]
    if extra_mime is not None:
        return ("\r\n".join(lines) + "\r\n" + extra_mime).encode("utf-8")
    lines.append(f"Content-Type: {content_type}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")
