"""Reputation lookups for an email's indicators, within free-tier budgets.

Free quotas are small (VirusTotal: 4 lookups a minute), so each email gets a
budget and the most telling indicators go first: attachments, then links
from QR codes and attachments, links whose text names another site, forms,
and finally ordinary links, one per organization.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import quote

from phishtriage.config import Settings
from phishtriage.domains import FREEMAIL_DOMAINS, WELL_KNOWN_DOMAINS, org_domain
from phishtriage.enrich.base import RateLimiter, Reputation
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.http import request_json
from phishtriage.enrich.services import AbuseIPDB, Rdap, Urlscan, VirusTotal
from phishtriage.links import LINK_WRAPPERS, Link

_RISKY_FIRST = ["executable", "config-profile", "disk-image", "html", "macro-document", "archive", "document", "other"]
_RESERVED_TLDS = ("test", "example", "invalid", "localhost")
REDACTED_ADDRESS = "redacted@example.com"


@dataclass
class EnrichmentFacts:
    results: list[Reputation] = field(default_factory=list)  # one entry per lookup
    notes: list[str] = field(default_factory=list)  # what was left out and why

    def for_target(self, target: str) -> list[Reputation]:
        return [result for result in self.results if result.target == target]


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _reserved(domain: str) -> bool:
    """Names that can never resolve on the internet (RFC 2606), so looking them up wastes quota."""
    return domain.lower().strip(".").rsplit(".", 1)[-1] in _RESERVED_TLDS


def _decoy(link: Link) -> bool:
    """A link to a famous site (footer icon, decoy), unless it is one of its abused hosting services."""
    return link.org_domain in WELL_KNOWN_DOMAINS and not link.on_free_hosting


def _priority(link: Link) -> int:
    if _decoy(link):
        return 5
    if link.source.startswith(("qr:", "attachment:")):
        return 0
    if link.text_shows_other_domain or link.has_userinfo:
        return 1
    if link.source == "html:form":
        return 2
    if link.source in ("html:a", "html:meta-refresh", "html:iframe", "embedded"):
        return 3
    return 4  # text copies, images


def pick_urls(links: list[Link]) -> list[str]:
    """One URL per organization, most telling first. Images and link wrappers are skipped."""
    chosen, seen = [], set()
    for link in sorted((candidate for candidate in links if candidate.scheme in ("http", "https")), key=_priority):
        if link.source == "html:img" or _reserved(link.host):
            continue
        if any(link.host == wrapper or link.host.endswith("." + wrapper) for wrapper in LINK_WRAPPERS):
            continue  # the real destination was extracted as an "embedded" link
        if link.org_domain in seen:
            continue
        seen.add(link.org_domain)
        chosen.append(link.url)
    return chosen


def redact_recipients(url: str, recipients: list[str]) -> str:
    """Remove the victim's address from a URL before a scanner visits it.

    Phishing links often carry the recipient's address (plain, URL-encoded or
    base64) so the attacker knows who clicked. A scan would confirm the victim.
    """
    for address in {variant for a in recipients if "@" in a for variant in (a, a.lower())}:
        url = re.sub(re.escape(address), REDACTED_ADDRESS, url, flags=re.IGNORECASE)
        url = re.sub(re.escape(quote(address, safe="")), quote(REDACTED_ADDRESS, safe=""), url, flags=re.IGNORECASE)
        for encode in (base64.b64encode, base64.urlsafe_b64encode):  # base64 is case-sensitive
            url = url.replace(encode(address.encode()).decode().rstrip("="),
                              encode(REDACTED_ADDRESS.encode()).decode().rstrip("="))
    return url


class Enricher:
    def __init__(self, settings: Settings, cache: Cache | None = None, http=request_json, scan_urls: bool = True,
                 sleep=None, domains_only: bool = False) -> None:
        """`domains_only` is for personal email (EVALUATION.md section 7): no VirusTotal URL or file lookups and no
        urlscan.io scans, so personal links and attachments never reach those services; domains and the sending
        server's IP only."""
        self.settings = settings
        self.domains_only = domains_only
        self.cache = cache or Cache(settings.cache_path)
        self.scan_urls = scan_urls and not domains_only
        limiter = lambda name, per_minute, per_day: RateLimiter(name, per_minute, per_day, self.cache)  # noqa: E731
        self.virustotal = VirusTotal(settings.virustotal_api_key, self.cache, limiter("virustotal", 4, 500), http)
        urlscan_kwargs = {"visibility": settings.urlscan_visibility}
        if sleep is not None:
            urlscan_kwargs["sleep"] = sleep
        self.urlscan = Urlscan(settings.urlscan_api_key, self.cache,
                               limiter("urlscan", 10, settings.urlscan_daily_scans), http, **urlscan_kwargs)
        self.abuseipdb = AbuseIPDB(settings.abuseipdb_api_key, self.cache, limiter("abuseipdb", 30, 1000), http)
        self.rdap = Rdap("", self.cache, limiter("rdap", 20, 2000), http)

    def enrich(self, facts, parsed=None, recipients: list[str] | None = None) -> EnrichmentFacts:
        """`recipients` (their addresses are removed from links before urlscan.io visits them) can be given
        instead of the parsed email, when the analysis ran in another process."""
        s = self.settings
        out = EnrichmentFacts()
        indicators = facts.indicators

        # VirusTotal budget: attachments first, then URLs, then link domains.
        attachments = sorted((a for a in indicators.attachments if a.category != "image" and a.size > 0),
                             key=lambda a: _RISKY_FIRST.index(a.category) if a.category in _RISKY_FIRST else 99)
        urls = pick_urls(indicators.links)
        vt_jobs = [("file", a.sha256) for a in attachments] + [("url", u) for u in urls]
        vt_jobs += [("domain", d) for d in indicators.link_domains
                    if not _reserved(d) and d not in FREEMAIL_DOMAINS and d not in WELL_KNOWN_DOMAINS]
        if self.domains_only:
            vt_jobs = [job for job in vt_jobs if job[0] == "domain"]
        vt_jobs = list(dict.fromkeys(vt_jobs))
        if len(vt_jobs) > s.virustotal_max_per_email:
            out.notes.append(f"VirusTotal: {len(vt_jobs) - s.virustotal_max_per_email} more indicator(s) not checked "
                             f"(budget {s.virustotal_max_per_email} per email)")
        vt_jobs = vt_jobs[: s.virustotal_max_per_email]

        if recipients is None:
            recipients = [a.address for a in parsed.to + parsed.cc] if parsed is not None else []
        scan_jobs = [redact_recipients(u, recipients) for u in urls[: s.urlscan_max_per_email]] if self.scan_urls else []
        if self.scan_urls and len(urls) > s.urlscan_max_per_email:
            out.notes.append(f"urlscan.io: scanned the {s.urlscan_max_per_email} most telling links of {len(urls)}")

        ips = [facts.auth.sender_ip] if _is_public_ip(facts.auth.sender_ip) else []
        if not self.domains_only:  # a link to a bare IP is a link: personal ones stay private
            ips += [link.host for link in indicators.web_links if link.host_is_ip and _is_public_ip(link.host)]
        ips = list(dict.fromkeys(ips))[: s.abuseipdb_max_per_email]

        domains = [facts.headers.sender.org_domain] + [org_domain(d) for d in facts.headers.reply_to_domains]
        domains += indicators.link_domains
        domains = [d for d in dict.fromkeys(domains) if d and "." in d and not _reserved(d) and not _is_public_ip(d)
                   and d not in FREEMAIL_DOMAINS and d not in WELL_KNOWN_DOMAINS]
        domains = domains[: s.rdap_max_per_email]

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self._run_virustotal, vt_jobs)]
            futures += [pool.submit(self.urlscan.scan, url) for url in scan_jobs]
            futures += [pool.submit(self.abuseipdb.check, ip) for ip in ips]
            futures += [pool.submit(self.rdap.domain, d) for d in domains]
            for future in futures:
                result = future.result()
                out.results.extend(result if isinstance(result, list) else [result])
        return out

    def _run_virustotal(self, jobs: list[tuple[str, str]]) -> list[Reputation]:
        # One at a time: the 4-per-minute limiter decides the pace.
        return [self.virustotal.lookup(kind, target) for kind, target in jobs]
