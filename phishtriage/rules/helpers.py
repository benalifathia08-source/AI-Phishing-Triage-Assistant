"""Shortcuts for writing rules. Every function takes the facts `f` given to a rule.

Lookup helpers return None when nothing was looked up, so a rule can return UNKNOWN
instead of pretending the email is clean.
"""
from __future__ import annotations


def web_links(f) -> list:
    """Web links a reader can click (images excluded)."""
    return [link for link in f.indicators.web_links if link.source != "html:img"]


def attachments(f, *categories: str) -> list:
    """Attachments, optionally only some categories: executable, config-profile, disk-image, html,
    macro-document, archive, document, image, other."""
    return [item for item in f.indicators.attachments if not categories or item.category in categories]


def authenticated(f) -> bool:
    """DMARC passed, or SPF or DKIM passed for the From domain's organization."""
    return f.auth.dmarc == "pass" or f.auth.spf_aligned or f.auth.dkim_aligned


def headers_describe_sender(f) -> bool:
    """False when the headers say nothing about the real sender: an inline forward (they describe
    the person who forwarded it) or no authentication results at all. Header-based rules, positive
    and negative, should then return UNKNOWN instead of judging."""
    return not f.forwarding.inline_forward and f.auth.trust != "missing"


def external(f) -> bool:
    """Not sent from inside your own Microsoft 365 organization."""
    return not f.headers.internal


def lookalikes(f, *where: str, protected: bool | None = None) -> list:
    """Lookalike domains, optionally only where they appear (sender, reply-to, return-path, sender-name,
    forwarded-sender, link) and only for your own domains (protected=True) or only brands (False)."""
    found = f.brands.lookalikes
    if where:
        found = [item for item in found if item.where in where]
    if protected is not None:
        found = [item for item in found if (item.brand == "your organization") == protected]
    return found


def identity_tricks(f) -> list[str]:
    """Ways the email misleads the reader about WHO sent it. When any is present, a passing
    authentication only proves that the attacker's own domain sent it, so it is no evidence
    of legitimacy."""
    s = f.headers.sender
    tricks = []
    if f.brands.impersonated:
        tricks.append(f"claims to be {', '.join(f.brands.impersonated)}")
    if lookalikes(f, "sender", "reply-to", "return-path", "sender-name"):
        tricks.append("lookalike sender domain")
    if s.suspicious_characters:
        tricks.append("lookalike characters in the sender")
    if s.display_name_address_differs:
        tricks.append("sender name shows another address")
    if f.headers.reply_to_differs:
        tricks.append("replies go to another organization")
    if s.on_free_hosting:
        tricks.append("sender on a shared platform")
    if f.forwarding.reply_prefix_without_thread:
        tricks.append("fake reply")
    return tricks


def deceptive_links(f) -> list[str]:
    """Short reasons for every link trick in the email: what a credential-phishing link usually looks like."""
    reasons = []
    for link in web_links(f):
        if link.text_shows_other_domain and not link.click_tracker:
            reasons.append(f"text shows {link.text_shows_other_domain} but goes to {link.host}")
        if link.has_userinfo:
            reasons.append(f"real host hidden after @: {link.host}")
        if link.host_is_ip:
            reasons.append(f"bare IP address: {link.host}")
        if link.is_shortener:
            reasons.append(f"shortened link: {link.host}")
        if link.on_free_hosting and external(f):
            reasons.append(f"free hosting: {link.host}")
    reasons += [f"lookalike link domain: {item.domain}" for item in lookalikes(f, "link")]
    reasons += [f"QR code in {qr.source.removeprefix('qr:')}" for qr in f.indicators.qr_codes]
    return list(dict.fromkeys(reasons))


def text_signals(f) -> list[str]:
    """Names of the phrase families found in the subject and visible text."""
    names = ["credential_request", "urgency", "payment", "bank_details_change", "gift_cards", "secrecy", "prize",
             "delivery", "callback", "crypto", "qr_prompt", "open_attachment"]
    return [name for name in names if getattr(f.text, name)]


def lookups(f, service: str | None = None, kind: str | None = None) -> list:
    """Successful reputation results, optionally for one service (virustotal, urlscan, abuseipdb, rdap)."""
    if f.enrichment is None:
        return []
    return [r for r in f.enrichment.results
            if r.status == "ok" and (service is None or r.service == service) and (kind is None or r.kind == kind)]


def _checked(f, service: str) -> bool:
    return f.enrichment is not None and any(r.service == service and r.status in ("ok", "not_found")
                                            for r in f.enrichment.results)


def vt_detections(f, kind: str | None = None) -> int | None:
    """Most VirusTotal engines flagging any checked file, url, domain or ip. None: nothing was checked."""
    if not _checked(f, "virustotal"):
        return None
    return max((r.malicious or 0 for r in lookups(f, "virustotal", kind)), default=0)


def urlscan_malicious(f) -> bool | None:
    if not _checked(f, "urlscan"):
        return None
    return any(r.verdict == "malicious" for r in lookups(f, "urlscan"))


def abuse_score(f) -> int | None:
    """Highest AbuseIPDB confidence (0-100) among checked IPs. None: nothing was checked."""
    if not _checked(f, "abuseipdb"):
        return None
    return max((r.score or 0 for r in lookups(f, "abuseipdb")), default=0)


def newest_domain_age(f) -> int | None:
    """Age in days of the youngest domain whose registration date was found. None: unknown."""
    ages = [r.extra.get("age_days") for r in lookups(f, "rdap") if r.extra.get("age_days") is not None]
    return min(ages) if ages else None
