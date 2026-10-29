"""Run every check on one email and collect the facts the rules will score."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

from phishtriage.auth import AuthFacts, auth_facts
from phishtriage.brands import BrandFacts, brand_facts, load_brands
from phishtriage.config import Settings
from phishtriage.content import TextFacts, text_facts, visible_text
from phishtriage.dkim_check import DkimCheck, check_dkim
from phishtriage.forwarding import ForwardFacts, forward_facts, pick_target
from phishtriage.headers import HeaderFacts, header_facts
from phishtriage.indicators import IndicatorFacts, collect_indicators
from phishtriage.parser import ParsedEmail, parse_eml

MAX_LINK_HOSTS_FOR_BRANDS = 30


@dataclass
class EmailFacts:
    sha256: str  # SHA-256 of the whole .eml file
    size: int  # size of the .eml file in bytes
    subject: str  # the decoded subject line
    date: str  # the Date header in ISO format ('' when missing or unreadable)
    message_id: str  # the Message-ID header
    attached_emails: int = 0  # emails attached inside this one
    parse_defects: list[str] = field(default_factory=list)  # MIME structure problems noticed while parsing


@dataclass
class Facts:
    email: EmailFacts
    headers: HeaderFacts
    auth: AuthFacts
    dkim_recheck: list[DkimCheck]  # one result per DKIM signature re-checked by the tool (empty when not re-checked)
    dkim_recheck_enabled: bool  # False when the re-check was switched off or not possible
    indicators: IndicatorFacts
    text: TextFacts
    brands: BrandFacts
    forwarding: ForwardFacts
    notes: list[str] = field(default_factory=list)  # what the analyst should know about how this was analyzed
    enrichment: object | None = None  # EnrichmentFacts, filled in when lookups are enabled


def _email_facts(parsed: ParsedEmail) -> EmailFacts:
    return EmailFacts(
        sha256=parsed.sha256,
        size=len(parsed.raw),
        subject=parsed.subject,
        date=parsed.date.isoformat() if isinstance(parsed.date, datetime) else "",
        message_id=parsed.message_id,
        attached_emails=len(parsed.attached_emails),
        parse_defects=sorted(set(parsed.defects)),
    )


def _brand_hosts(headers: HeaderFacts, indicators: IndicatorFacts, forwarding: ForwardFacts) -> list[tuple[str, str]]:
    sender = headers.sender
    hosts = [(sender.domain, "sender")]
    if sender.display_name_address:
        hosts.append((sender.display_name_address.rpartition("@")[2], "sender-name"))
    hosts += [(domain, "reply-to") for domain in headers.reply_to_domains]
    hosts.append((headers.return_path_domain, "return-path"))
    if forwarding.quoted_sender_domain:
        hosts.append((forwarding.quoted_sender_domain, "forwarded-sender"))
    links = [link.host for link in indicators.web_links if link.source != "html:img"]
    hosts += [(host, "link") for host in dict.fromkeys(links)][:MAX_LINK_HOSTS_FOR_BRANDS]
    return [(host, where) for host, where in hosts if host]


def analyze(raw: bytes, settings: Settings | None = None, dnsfunc=None, enricher=None) -> Facts:
    """Facts about one email. `enricher` (see phishtriage.enrich) adds reputation lookups."""
    facts, target = analyze_offline(raw, settings, dnsfunc)
    if enricher is not None:
        facts.enrichment = enricher.enrich(facts, target)
    return facts


def analyze_offline(raw: bytes, settings: Settings | None = None, dnsfunc=None) -> tuple[Facts, ParsedEmail]:
    """Everything except reputation lookups, plus the email that was analyzed (the attached original of a
    report, or the email itself). The web interface runs this part in a child process with a time limit,
    because it feeds attacker-made PDFs and pictures to native parsers; the lookups run outside it."""
    settings = settings or Settings.load()
    parsed = parse_eml(raw)
    target, forwarding = pick_target(parsed)
    notes = []
    if forwarding.analyzed_attached_original:
        notes.append(f"Analyzed the original email attached to a report from {forwarding.reporter or 'an unknown sender'}.")

    shown, reader = visible_text(target.html_body, target.text_body)
    forwarding = forward_facts(target, shown, forwarding)
    if forwarding.inline_forward:
        notes.append("This email was forwarded inline, so its headers belong to the forwarder: authentication "
                     "results say nothing about the original sender. Ask for the original as an attachment.")

    headers = header_facts(target, settings.protected_domains)
    indicators = collect_indicators(target)
    dkim_recheck: list[DkimCheck] = []
    if settings.dkim_recheck and target.raw_exact:
        dkim_recheck = check_dkim(target.raw, dnsfunc=dnsfunc)
    elif settings.dkim_recheck:
        notes.append("DKIM was not re-checked: the attached original had to be re-encoded, which can break valid signatures.")

    facts = Facts(
        email=_email_facts(target),
        headers=headers,
        auth=auth_facts(target, set(settings.trusted_authserv_ids)),
        dkim_recheck=dkim_recheck,
        dkim_recheck_enabled=settings.dkim_recheck and target.raw_exact,
        indicators=indicators,
        text=text_facts(target.subject, shown=shown, reader=reader),
        brands=brand_facts(
            headers.sender.display_name, target.subject, headers.sender.address,
            _brand_hosts(headers, indicators, forwarding),
            load_brands(settings.brands_file), settings.protected_domains,
        ),
        forwarding=forwarding,
        notes=notes,
    )
    # Mail between two of your own Microsoft 365 organizations (e.g. a school and its university)
    # also arrives "from outside". It only counts as spoofing when nothing authenticates it.
    a = facts.auth
    authenticated = a.dmarc == "pass" or a.spf_aligned or a.dkim_aligned
    headers.own_domain_from_outside = headers.own_domain_from_outside and not authenticated
    return facts, target


def facts_to_dict(facts: Facts) -> dict:
    return asdict(facts)
