"""What every lookup returns, and the rate limiter that keeps us inside free quotas."""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from phishtriage.enrich.cache import Cache


@dataclass
class Reputation:
    service: str  # virustotal, urlscan, abuseipdb, rdap
    kind: str  # file, url, domain, ip
    target: str  # what was looked up: a hash, URL, domain or IP
    status: str  # ok, not_found, pending, refused, skipped, disabled, error
    detail: str = ""  # a short reason for anything other than ok
    malicious: int | None = None  # VirusTotal: engines calling it malicious
    suspicious: int | None = None  # VirusTotal: engines calling it suspicious
    engines: int | None = None  # VirusTotal: engines that gave any verdict
    score: int | None = None  # urlscan.io score, AbuseIPDB abuse confidence (0-100)
    verdict: str = ""  # urlscan.io: malicious / no classification
    labels: list[str] = field(default_factory=list)  # threat names, categories, impersonated brands
    link: str = ""  # page where the analyst can see the full report
    extra: dict = field(default_factory=dict)  # final URL, country, ISP, domain age...
    cached: bool = False  # from the 24-hour cache rather than a fresh lookup


class RateLimiter:
    """At most `per_minute` calls in any 60 seconds and `per_day` calls per calendar day."""

    def __init__(self, service: str, per_minute: int, per_day: int, cache: Cache) -> None:
        self.service, self.per_minute, self.per_day, self.cache = service, per_minute, per_day, cache
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self, max_wait: float) -> str:
        """'' when the call may go ahead, otherwise the reason it may not."""
        deadline = time.monotonic() + max_wait
        while True:
            with self._lock:
                if self.cache.used_today(self.service) >= self.per_day:
                    return f"daily free quota of {self.per_day} used up"
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= 60:
                    self._calls.popleft()
                if len(self._calls) < self.per_minute:
                    self._calls.append(now)
                    self.cache.count_use(self.service)
                    return ""
                wait = 60 - (now - self._calls[0]) + 0.5
            if time.monotonic() + wait > deadline:
                return f"per-minute limit of {self.per_minute} reached"
            time.sleep(wait)
