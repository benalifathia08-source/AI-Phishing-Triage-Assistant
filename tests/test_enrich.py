"""Reputation lookups against a fake network: no quota is spent and no request leaves the machine."""
import base64
from dataclasses import replace

from phishtriage.analyze import analyze
from phishtriage.config import Settings
from phishtriage.enrich import Enricher, pick_urls, redact_recipients
from phishtriage.enrich.base import RateLimiter
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.http import HttpResponse
from phishtriage.enrich.services import AbuseIPDB, Rdap, Urlscan, VirusTotal
from phishtriage.links import make_link
from tests.helpers import make_eml

KEY = "test-key-0123456789"


class FakeHttp:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, headers=None, body=None, timeout=20):
        self.calls.append((method, url, headers or {}, body))
        for prefix, responses in self.routes.items():
            if url.startswith(prefix):
                return responses.pop(0) if isinstance(responses, list) else responses
        return HttpResponse(404, None, "HTTP 404")


def limiter(name="svc", per_minute=100, per_day=1000, cache=None):
    return RateLimiter(name, per_minute, per_day, cache or Cache())


def test_virustotal_file_lookup_and_cache():
    cache = Cache()
    http = FakeHttp({"https://www.virustotal.com/api/v3/files/abc": HttpResponse(200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 12, "suspicious": 1, "undetected": 50, "harmless": 0, "timeout": 3},
        "popular_threat_classification": {"suggested_threat_label": "trojan.agent"},
        "meaningful_name": "invoice.html", "first_submission_date": 1790000000}}})})
    vt = VirusTotal(KEY, cache, limiter(cache=cache), http)
    result = vt.lookup("file", "abc")
    assert (result.status, result.malicious, result.suspicious, result.engines) == ("ok", 12, 1, 63)
    assert result.labels == ["trojan.agent"]
    assert result.link == "https://www.virustotal.com/gui/file/abc"
    assert http.calls[0][0] == "GET" and http.calls[0][2]["x-apikey"] == KEY
    assert vt.lookup("file", "abc").cached and len(http.calls) == 1  # second time from the cache


def test_virustotal_url_id_and_never_seen():
    http = FakeHttp({})
    result = VirusTotal(KEY, Cache(), limiter(), http).lookup("url", "https://example.net/a")
    url_id = base64.urlsafe_b64encode(b"https://example.net/a").decode().rstrip("=")
    assert http.calls[0][1].endswith(f"/urls/{url_id}")
    assert (result.status, result.detail) == ("not_found", "never seen by VirusTotal")


def test_virustotal_never_uploads_or_submits():
    http = FakeHttp({})
    vt = VirusTotal(KEY, Cache(), limiter(), http)
    for kind, target in [("file", "abc"), ("url", "https://example.net/"), ("domain", "example.net"), ("ip", "198.51.100.1")]:
        vt.lookup(kind, target)
    assert {method for method, *_ in http.calls} == {"GET"}


def test_missing_key_and_rejected_key():
    assert VirusTotal("", Cache(), limiter(), FakeHttp({})).lookup("file", "abc").status == "disabled"
    http = FakeHttp({"https://api.abuseipdb.com": HttpResponse(401, {"errors": []}, "HTTP 401")})
    result = AbuseIPDB(KEY, Cache(), limiter(), http).check("198.51.100.7")
    assert (result.status, result.detail) == ("error", "API key rejected")
    assert KEY not in repr(result)


def test_daily_quota_is_respected():
    cache = Cache()
    vt = VirusTotal(KEY, cache, limiter("virustotal", per_minute=100, per_day=2, cache=cache), FakeHttp({}))
    statuses = [vt.lookup("domain", f"d{n}.example.net").status for n in range(3)]
    assert statuses == ["not_found", "not_found", "skipped"]


def test_urlscan_private_scan_and_poll():
    http = FakeHttp({
        "https://urlscan.io/api/v1/scan/": HttpResponse(200, {"uuid": "u-1"}),
        "https://urlscan.io/api/v1/result/u-1/": [HttpResponse(404, None), HttpResponse(200, {
            "verdicts": {"overall": {"score": 100, "malicious": True, "categories": ["phishing"], "brands": [{"name": "Microsoft"}]}},
            "page": {"url": "https://final.example.net/login", "domain": "final.example.net", "ip": "203.0.113.9"},
            "task": {"reportURL": "https://urlscan.io/result/u-1/", "screenshotURL": "https://urlscan.io/screenshots/u-1.png"},
        })],
    })
    scanner = Urlscan(KEY, Cache(), limiter(), http, visibility="public", sleep=lambda seconds: None)
    result = scanner.scan("https://start.example.net/")
    assert http.calls[0][3]["visibility"] == "private"  # public is never used, even if configured
    assert (result.status, result.verdict, result.score) == ("ok", "malicious", 100)
    assert result.labels == ["phishing", "impersonates Microsoft"]
    assert result.extra["final_url"] == "https://final.example.net/login"


def test_urlscan_refused_scan():
    http = FakeHttp({"https://urlscan.io/api/v1/scan/": HttpResponse(400, {"message": "DNS Error - Could not resolve domain"})})
    result = Urlscan(KEY, Cache(), limiter(), http, sleep=lambda s: None).scan("https://gone.example.net/")
    assert (result.status, result.detail) == ("refused", "DNS Error - Could not resolve domain")


def test_abuseipdb_and_rdap_parsing():
    http = FakeHttp({
        "https://api.abuseipdb.com": HttpResponse(200, {"data": {"abuseConfidenceScore": 87, "totalReports": 120,
                                                                  "countryCode": "NL", "usageType": "Data Center/Web Hosting/Transit",
                                                                  "isTor": True, "isp": "Example Hosting"}}),
        "https://rdap.org/domain/new.example": HttpResponse(200, {
            "events": [{"eventAction": "registration", "eventDate": "2026-10-05T10:00:00Z"}],
            "status": ["client transfer prohibited", "server hold"],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]]}],
        }),
    })
    ip = AbuseIPDB(KEY, Cache(), limiter(), http).check("203.0.113.45")
    assert (ip.score, ip.extra["reports"], ip.labels) == (87, 120, ["Data Center/Web Hosting/Transit", "Tor exit node"])
    domain = Rdap("", Cache(), limiter(), http).domain("new.example")
    assert domain.extra["registered"] == "2026-10-05" and domain.extra["registrar"] == "Example Registrar"
    assert isinstance(domain.extra["age_days"], int)
    assert domain.labels == ["server hold"]


def test_recipient_address_is_removed_before_scanning():
    victim = "Jane.Doe@company.example"
    encoded = base64.b64encode(victim.lower().encode()).decode().rstrip("=")
    url = f"https://evil.example.net/a?email={victim}&e2=jane.doe%40company.example#{encoded}"
    redacted = redact_recipients(url, [victim])
    assert "jane.doe" not in redacted.lower()
    assert encoded not in redacted
    assert redacted.count("redacted") == 2


def test_most_telling_links_first_one_per_organization():
    links = [
        make_link("https://news.example.com/a", "html:a"),
        make_link("https://news.example.com/b", "html:a"),
        make_link("https://img.example.org/logo.png", "html:img"),
        make_link("https://login.example.net/x", "html:a", "www.paypal.com"),
        make_link("https://qr.example.info/z", "qr:code.png"),
        make_link("https://eur01.safelinks.protection.outlook.com/?url=x", "html:a"),
        make_link("https://www.facebook.com/brand", "html:a"),  # footer icon: last
        make_link("https://docs.google.com/forms/d/e/1/viewform", "html:a"),  # abused Google service: normal rank
    ]
    assert pick_urls(links) == ["https://qr.example.info/z", "https://login.example.net/x", "https://news.example.com/a",
                                "https://docs.google.com/forms/d/e/1/viewform", "https://www.facebook.com/brand"]


def test_enricher_budgets_and_notes():
    html = "".join(f'<a href="https://www.example.{tld}/p">link</a>' for tld in ("com", "net", "org", "info", "biz", "co"))
    raw = make_eml(
        [("Authentication-Results", "spf=fail (sender IP is 8.8.4.4) smtp.mailfrom=example.org;dmarc=fail action=none header.from=example.org")],
        body=html, content_type="text/html; charset=utf-8", from_="Sender <a@example.org>",
    )
    http = FakeHttp({"https://urlscan.io/api/v1/scan/": HttpResponse(400, {"message": "refused"})})
    settings = replace(Settings(), virustotal_api_key=KEY, urlscan_api_key=KEY, abuseipdb_api_key=KEY, dkim_recheck=False)
    enricher = Enricher(settings, cache=Cache(), http=http, sleep=lambda s: None)
    facts = analyze(raw, settings, enricher=enricher)
    by_service = {}
    for result in facts.enrichment.results:
        by_service.setdefault(result.service, []).append(result)
    assert len(by_service["virustotal"]) == 4
    assert len(by_service["urlscan"]) == 2
    assert [r.target for r in by_service["abuseipdb"]] == ["8.8.4.4"]  # a public IP; documentation ranges are skipped
    assert any("not checked" in note for note in facts.enrichment.notes)
    assert all(KEY not in url for _, url, _, _ in http.calls)  # keys travel only in headers



def test_only_http_and_https_urls_are_fetched():
    from phishtriage.enrich.http import request_json

    for url in ("file:///C:/Windows/win.ini", "ftp://files.example.test/x", "data:text/plain,hi"):
        response = request_json("GET", url)
        assert response.status == 0 and response.error.startswith("refused")
