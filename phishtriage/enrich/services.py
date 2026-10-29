"""Clients for VirusTotal, urlscan.io, AbuseIPDB and RDAP. Each returns a Reputation.

Privacy rules, enforced here:
  - VirusTotal is only asked about things it may already know (GET lookups).
    Nothing is uploaded or submitted, so no attachment reaches VirusTotal's users.
  - urlscan.io scans are private or unlisted, never public, and the recipient's
    address is removed from the URL first.
  - AbuseIPDB and RDAP only receive an IP address or a domain name.
"""
from __future__ import annotations

import base64
import time
from dataclasses import asdict
from datetime import datetime, UTC
from urllib.parse import quote

from phishtriage.enrich.base import RateLimiter, Reputation
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.http import HttpResponse, request_json

DAY = 24 * 3600


class _Service:
    service = ""
    ttl = DAY

    def __init__(self, api_key: str, cache: Cache, limiter: RateLimiter, http=request_json, max_wait: float = 70) -> None:
        self.api_key, self.cache, self.limiter, self.http, self.max_wait = api_key, cache, limiter, http, max_wait

    def _cached(self, kind: str, target: str) -> Reputation | None:
        value = self.cache.get(self.service, f"{kind}:{target}", self.ttl)
        if value is None:
            return None
        reputation = Reputation(**value)
        reputation.cached = True
        return reputation

    def _remember(self, reputation: Reputation) -> Reputation:
        if reputation.status in ("ok", "not_found"):
            self.cache.put(self.service, f"{reputation.kind}:{reputation.target}", asdict(reputation))
        return reputation

    def _failure(self, kind: str, target: str, response: HttpResponse) -> Reputation:
        if response.status in (401, 403):
            return Reputation(self.service, kind, target, "error", "API key rejected")
        if response.status == 429:
            return Reputation(self.service, kind, target, "skipped", "quota exceeded at the service")
        return Reputation(self.service, kind, target, "error", response.error or f"HTTP {response.status}")


def _iso(epoch) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=UTC).date().isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


class VirusTotal(_Service):
    service = "virustotal"
    API = "https://www.virustotal.com/api/v3"
    GUI = "https://www.virustotal.com/gui"

    def lookup(self, kind: str, target: str) -> Reputation:
        if not self.api_key:
            return Reputation(self.service, kind, target, "disabled", "no VIRUSTOTAL_API_KEY in .env")
        if cached := self._cached(kind, target):
            return cached
        if reason := self.limiter.acquire(self.max_wait):
            return Reputation(self.service, kind, target, "skipped", reason)
        url_id = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        path, gui = {
            "file": (f"files/{target}", f"file/{target}"),
            "url": (f"urls/{url_id}", f"url/{url_id}"),
            "domain": (f"domains/{quote(target, safe='')}", f"domain/{quote(target, safe='')}"),
            "ip": (f"ip_addresses/{target}", f"ip-address/{target}"),
        }[kind]
        response = self.http("GET", f"{self.API}/{path}", headers={"x-apikey": self.api_key})
        if response.status == 404:
            return self._remember(Reputation(self.service, kind, target, "not_found", "never seen by VirusTotal"))
        if response.status != 200 or not isinstance(response.data, dict):
            return self._failure(kind, target, response)

        attributes = (response.data.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        labels: list[str] = []
        extra: dict = {}
        if kind == "file":
            threat = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")
            labels = [threat] if threat else []
            extra = {"name": attributes.get("meaningful_name", ""), "type": attributes.get("type_description", ""),
                     "first_seen": _iso(attributes.get("first_submission_date"))}
        else:
            labels = sorted(set((attributes.get("categories") or {}).values()))[:6]
            if kind == "url":
                extra = {"final_url": attributes.get("last_final_url", ""), "title": attributes.get("title", ""),
                         "first_seen": _iso(attributes.get("first_submission_date"))}
            elif kind == "domain":
                extra = {"created": _iso(attributes.get("creation_date")), "registrar": attributes.get("registrar", "")}
            else:
                extra = {"owner": attributes.get("as_owner", ""), "country": attributes.get("country", "")}
        return self._remember(Reputation(
            self.service, kind, target, "ok",
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            engines=sum(int(stats.get(key, 0)) for key in ("malicious", "suspicious", "undetected", "harmless")),
            labels=labels,
            link=f"{self.GUI}/{gui}",
            extra=extra,
        ))


class Urlscan(_Service):
    service = "urlscan"
    API = "https://urlscan.io/api/v1"

    def __init__(self, *args, visibility: str = "private", poll_timeout: float = 90, sleep=time.sleep, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Public scans are visible to everyone and can leak a victim's personal links.
        self.visibility = visibility if visibility in ("private", "unlisted") else "private"
        self.poll_timeout, self.sleep = poll_timeout, sleep

    def scan(self, url: str) -> Reputation:
        if not self.api_key:
            return Reputation(self.service, "url", url, "disabled", "no URLSCAN_API_KEY in .env")
        if cached := self._cached("url", url):
            return cached
        if reason := self.limiter.acquire(self.max_wait):
            return Reputation(self.service, "url", url, "skipped", reason)
        headers = {"API-Key": self.api_key}
        submitted = self.http("POST", f"{self.API}/scan/", headers=headers,
                              body={"url": url, "visibility": self.visibility, "tags": ["phishtriage"]})
        if submitted.status == 400:
            message = (submitted.data or {}).get("message", "") if isinstance(submitted.data, dict) else ""
            # e.g. the domain no longer resolves (taken down) or urlscan.io refuses to scan it
            return self._remember(Reputation(self.service, "url", url, "refused", message or "scan refused"))
        if submitted.status != 200 or not isinstance(submitted.data, dict) or not submitted.data.get("uuid"):
            return self._failure("url", url, submitted)

        uuid = submitted.data["uuid"]
        report = f"https://urlscan.io/result/{uuid}/"
        deadline = time.monotonic() + self.poll_timeout
        self.sleep(10)  # a scan takes 10-30 seconds; asking earlier only returns 404
        while True:
            result = self.http("GET", f"{self.API}/result/{uuid}/", headers=headers)
            if result.status == 200 and isinstance(result.data, dict):
                return self._remember(self._parse(url, result.data, report))
            if result.status not in (404, 0) or time.monotonic() >= deadline:
                return Reputation(self.service, "url", url, "pending", "scan not finished in time; open the link later", link=report)
            self.sleep(5)

    def _parse(self, url: str, data: dict, report: str) -> Reputation:
        overall = (data.get("verdicts") or {}).get("overall") or {}
        page = data.get("page") or {}
        task = data.get("task") or {}
        brands = [brand.get("name", "") if isinstance(brand, dict) else str(brand) for brand in overall.get("brands") or []]
        return Reputation(
            self.service, "url", url, "ok",
            score=overall.get("score"),
            verdict="malicious" if overall.get("malicious") else "no classification",
            labels=[str(item) for item in (overall.get("categories") or [])] + [f"impersonates {b}" for b in brands if b],
            link=task.get("reportURL") or report,
            extra={key: value for key, value in {
                "final_url": page.get("url", ""), "final_domain": page.get("domain", ""), "ip": page.get("ip", ""),
                "country": page.get("country", ""), "title": page.get("title", ""), "status": page.get("status", ""),
                "screenshot": task.get("screenshotURL", ""),
            }.items() if value},
        )


class AbuseIPDB(_Service):
    service = "abuseipdb"
    API = "https://api.abuseipdb.com/api/v2/check"

    def check(self, ip: str) -> Reputation:
        if not self.api_key:
            return Reputation(self.service, "ip", ip, "disabled", "no ABUSEIPDB_API_KEY in .env")
        if cached := self._cached("ip", ip):
            return cached
        if reason := self.limiter.acquire(self.max_wait):
            return Reputation(self.service, "ip", ip, "skipped", reason)
        response = self.http("GET", f"{self.API}?ipAddress={quote(ip)}&maxAgeInDays=90", headers={"Key": self.api_key})
        if response.status != 200 or not isinstance(response.data, dict):
            return self._failure("ip", ip, response)
        data = response.data.get("data") or {}
        labels = [data["usageType"]] if data.get("usageType") else []
        if data.get("isTor"):
            labels.append("Tor exit node")
        return self._remember(Reputation(
            self.service, "ip", ip, "ok",
            score=data.get("abuseConfidenceScore"),
            labels=labels,
            link=f"https://www.abuseipdb.com/check/{ip}",
            extra={"reports": data.get("totalReports", 0), "country": data.get("countryCode") or "",
                   "isp": data.get("isp") or "", "last_reported": (data.get("lastReportedAt") or "")[:10]},
        ))


class Rdap(_Service):
    """Domain registration date from the registry's RDAP service (the modern WHOIS). No account needed."""
    service = "rdap"
    ttl = 7 * DAY

    def domain(self, domain: str) -> Reputation:
        if cached := self._cached("domain", domain):
            return cached
        if reason := self.limiter.acquire(self.max_wait):
            return Reputation(self.service, "domain", domain, "skipped", reason)
        try:
            ascii_domain = domain.encode("idna").decode()
        except UnicodeError:
            return Reputation(self.service, "domain", domain, "error", "not a valid domain name")
        response = self.http("GET", f"https://rdap.org/domain/{ascii_domain}", timeout=15)
        if response.status == 404:
            return self._remember(Reputation(self.service, "domain", domain, "not_found",
                                             "no registration record (not registered, or its registry has no RDAP)"))
        if response.status != 200 or not isinstance(response.data, dict):
            return self._failure("domain", domain, response)
        events = {event.get("eventAction"): event.get("eventDate", "") for event in response.data.get("events") or []
                  if isinstance(event, dict)}
        registered = events.get("registration", "")[:10]
        age_days = None
        if registered:
            try:
                age_days = (datetime.now(UTC).date() - datetime.fromisoformat(registered).date()).days
            except ValueError:
                pass
        registrar = ""
        for entity in response.data.get("entities") or []:
            if isinstance(entity, dict) and "registrar" in (entity.get("roles") or []):
                for item in (entity.get("vcardArray") or [None, []])[1]:
                    if isinstance(item, list) and item[:1] == ["fn"]:
                        registrar = str(item[3])
        return self._remember(Reputation(
            self.service, "domain", domain, "ok",
            labels=[status for status in response.data.get("status") or [] if "hold" in status or "suspend" in status],
            extra={"registered": registered, "age_days": age_days, "registrar": registrar},
        ))
