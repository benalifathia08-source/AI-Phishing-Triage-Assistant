"""Facts about the sender, reply path, routing and dates.

These are observations, not judgements: "Reply-To goes to another domain" is
a fact, and whether it is worth 10 points is decided later by the rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, UTC

from phishtriage.domains import (
    FREEMAIL_DOMAINS, aligned, is_valid_domain, on_free_hosting, org_domain, suspicious_characters,
)
from phishtriage.parser import ParsedEmail, parse_date

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


@dataclass
class SenderFacts:
    display_name: str = ""  # the name shown before the address, e.g. 'PayPal Service'
    address: str = ""  # the From address, lowercase
    domain: str = ""  # the From domain
    org_domain: str = ""  # organization part of the From domain: example.co.uk for mail.example.co.uk
    domain_is_valid: bool = False  # False when the domain has no real extension (muhbdrtdtbniig) or invalid characters
    is_freemail: bool = False  # the From domain is a free mail provider (gmail.com, outlook.fr...)
    on_free_hosting: bool = False  # sends from a shared platform anyone can sign up to, e.g. evil.onmicrosoft.com
    address_count: int = 0  # From normally holds exactly one address
    display_name_address: str = ""  # an email address written inside the display name
    display_name_address_differs: bool = False  # ...that belongs to another organization
    suspicious_characters: list[str] = field(default_factory=list)  # why the name or address looks deceptive: bold Unicode, mixed alphabets, invisible characters, punycode


@dataclass
class HeaderFacts:
    sender: SenderFacts
    reply_to_domains: list[str] = field(default_factory=list)  # domains of the Reply-To addresses
    reply_to_differs: bool = False  # replies go to another organization than From
    reply_to_is_freemail: bool = False  # a Reply-To address is at a free mail provider
    return_path_domain: str = ""  # envelope sender, where bounces go
    return_path_differs: bool = False  # the bounce address belongs to another organization than From (newsletters do this too)
    message_id_domain: str = ""  # domain of the Message-ID header
    message_id_differs: bool = False  # the Message-ID domain belongs to another organization than From (common in newsletters)
    received_hops: int = 0  # number of Received headers: servers the email passed through
    date_missing: bool = True  # no readable Date header
    date_skew_hours: float | None = None  # receive time minus the Date header; negative = dated in the future
    to_count: int = 0  # number of To addresses
    cc_count: int = 0  # number of Cc addresses
    recipients_hidden: bool = False  # no To or Cc: everyone was Bcc'd
    subject_suspicious_characters: list[str] = field(default_factory=list)  # lookalike or invisible characters in the subject
    # Microsoft 365 stamps how it authenticated the sender: Internal (inside your organization),
    # Anonymous (from the internet), Partner. Exchange strips this header from mail arriving
    # from outside, so an outsider cannot fake "Internal". Empty when not received by Microsoft.
    exchange_auth_as: str = ""
    internal: bool = False  # sent from inside your own Microsoft 365 organization
    sender_is_protected: bool = False  # the From domain is one of PROTECTED_DOMAINS
    # Claims your domain, arrived from the internet, and nothing (SPF, DKIM, DMARC) authenticates it:
    # spoofing, or one of your own systems sending without authorization (still worth fixing)
    own_domain_from_outside: bool = False


def _sender_facts(parsed: ParsedEmail) -> SenderFacts:
    sender = parsed.sender
    if sender is None:
        return SenderFacts()
    domain = sender.domain
    name_match = _EMAIL_IN_TEXT.search(sender.display_name)
    name_address = name_match.group(0).lower() if name_match else ""
    return SenderFacts(
        display_name=sender.display_name,
        address=sender.address.lower(),
        domain=domain,
        org_domain=org_domain(domain) if domain else "",
        domain_is_valid=is_valid_domain(domain),
        is_freemail=org_domain(domain) in FREEMAIL_DOMAINS if domain else False,
        on_free_hosting=on_free_hosting(domain) if domain else False,
        address_count=len(parsed.from_addresses),
        display_name_address=name_address,
        display_name_address_differs=bool(name_match) and not aligned(name_match.group(1), domain),
        suspicious_characters=suspicious_characters(f"{sender.display_name} {sender.address}"),
    )


def _received_time(parsed: ParsedEmail) -> datetime | None:
    """When the top-most server (the last hop, ours) received the email."""
    top = parsed.header("Received")
    return parse_date(top.rpartition(";")[2].strip()) if ";" in top else None


def _hours_between(later: datetime, earlier: datetime) -> float | None:
    try:
        if later.tzinfo is None:
            later = later.replace(tzinfo=UTC)
        if earlier.tzinfo is None:
            earlier = earlier.replace(tzinfo=UTC)
        return round((later - earlier).total_seconds() / 3600, 2)
    except (OverflowError, ValueError):
        return None


def header_facts(parsed: ParsedEmail, protected: frozenset[str] = frozenset()) -> HeaderFacts:
    sender = _sender_facts(parsed)
    auth_as = parsed.header("X-MS-Exchange-Organization-AuthAs").strip()
    sender_is_protected = bool(sender.domain) and any(aligned(sender.domain, domain) for domain in protected)
    reply_domains = sorted({address.domain for address in parsed.reply_to if address.domain})
    return_path_domain = parsed.return_path.rpartition("@")[2].lower() if "@" in parsed.return_path else ""
    message_id_domain = parsed.message_id.strip("<> ").rpartition("@")[2].lower() if "@" in parsed.message_id else ""

    received_at = _received_time(parsed)
    skew = _hours_between(received_at, parsed.date) if received_at and parsed.date else None

    return HeaderFacts(
        sender=sender,
        reply_to_domains=reply_domains,
        reply_to_differs=any(not aligned(domain, sender.domain) for domain in reply_domains),
        reply_to_is_freemail=any(org_domain(domain) in FREEMAIL_DOMAINS for domain in reply_domains),
        return_path_domain=return_path_domain,
        return_path_differs=bool(return_path_domain) and not aligned(return_path_domain, sender.domain),
        message_id_domain=message_id_domain,
        message_id_differs=bool(message_id_domain) and not aligned(message_id_domain, sender.domain),
        received_hops=len(parsed.header_all("Received")),
        date_missing=parsed.date is None,
        date_skew_hours=skew,
        to_count=len(parsed.to),
        cc_count=len(parsed.cc),
        recipients_hidden=not parsed.to and not parsed.cc,
        subject_suspicious_characters=suspicious_characters(parsed.subject),
        exchange_auth_as=auth_as,
        internal=auth_as.lower() == "internal",
        sender_is_protected=sender_is_protected,
        own_domain_from_outside=sender_is_protected and auth_as.lower() == "anonymous",
    )
