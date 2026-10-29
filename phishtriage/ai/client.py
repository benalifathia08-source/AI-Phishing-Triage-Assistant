"""A minimal client for a local Ollama server.

Emails carry personal data, so by default only a server on this machine is accepted.
Answers are requested as JSON matching a schema, with temperature 0 and a fixed seed so
the same case gives the same summary (repeatable for tests and evaluation).
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from phishtriage.config import Settings
from phishtriage.enrich.http import request_json

_THINKING = re.compile(r"(?s)^.*?</think>\s*")  # some models still print their reasoning first
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass
class ChatResult:
    text: str  # the model's answer ('' on failure)
    error: str = ""
    seconds: float = 0.0


class OllamaClient:
    def __init__(self, settings: Settings | None = None, http=request_json) -> None:
        settings = settings or Settings.load()
        self.host = settings.ollama_host.rstrip("/")
        self.model = settings.ollama_model
        self.timeout = settings.ai_timeout
        self.http = http
        host = urlsplit(self.host).hostname or ""
        if host not in _LOCAL_HOSTS and not settings.ai_allow_remote:
            raise ValueError(f"refusing to send email content to {host}: set AI_ALLOW_REMOTE=yes to allow a remote AI")

    def chat(self, system: str, user: str, schema: dict | None = None, max_tokens: int | None = None) -> ChatResult:
        body = {
            "model": self.model, "stream": False, "think": False,
            "options": {"temperature": 0, "seed": 42, "num_ctx": 8192},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if max_tokens:  # a runaway answer ends here instead of at the timeout (llama3.2:3b: 7 of 52 ran to 180 s)
            body["options"]["num_predict"] = max_tokens
        if schema:
            body["format"] = schema
        start = time.monotonic()
        response = self.http("POST", f"{self.host}/api/chat", body=body, timeout=self.timeout)
        seconds = round(time.monotonic() - start, 1)
        if response.status != 200 or not isinstance(response.data, dict):
            return ChatResult("", response.error or f"HTTP {response.status}", seconds)
        text = (response.data.get("message") or {}).get("content", "")
        return ChatResult(_THINKING.sub("", text) if "</think>" in text else text, "", seconds)


def parse_json(text: str) -> dict | None:
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        match = re.search(r"\{.*\}", text or "", re.DOTALL)  # tolerate text around the JSON
        if not match:
            return None
        try:
            value = json.loads(match.group(0))
        except ValueError:
            return None
    return value if isinstance(value, dict) else None
