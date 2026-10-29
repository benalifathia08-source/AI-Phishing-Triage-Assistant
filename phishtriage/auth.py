"""Read SPF, DKIM and DMARC results from the Authentication-Results headers we can trust.

Anyone can write an Authentication-Results header into an email before sending
it. Only the header added by your own receiving mail server means anything. Mail
servers add headers at the top, so ours is the top-most one. If you set
TRUSTED_AUTHSERV_IDS, only headers carrying one of those server IDs are used.

Real-world formats handled here:
  RFC 8601   mx.google.com; spf=pass (...) smtp.mailfrom=example.com; dkim=pass header.d=...
  Microsoft  spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=...;dmarc=pass action=none ...
             (no server ID at all, or "mx.microsoft.com 1;" with a version number)
  Encoded    the whole header in =?utf-8?B?...?= when the From domain uses non-ASCII letters
  Split      one header per method from the same server (Proton Mail)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from phishtriage.domains import aligned
from phishtriage.parser import ParsedEmail

_METHOD = re.compile(r"^\s*([A-Za-z0-9_-]+)(?:/\d+)?\s*=\s*([A-Za-z0-9_-]+)")
_PROPERTY = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*(\"[^\"]*\"|[^\s;]+)")
_COMMENT = re.compile(r"\(([^()]*)\)")
_IP_IN_COMMENT = re.compile(r"sender IP is ([0-9A-Fa-f:.]+)")


@dataclass
class MethodResult:
    method: str  # spf, dkim, dmarc, compauth, arc, ...
    result: str  # pass, fail, softfail, none, neutral, temperror, permerror, ...
    properties: dict[str, str]  # smtp.mailfrom, header.d, header.from, action, reason, ...
    comment: str = ""


@dataclass
class AuthResultsHeader:
    authserv_id: str  # "" when the server left it out, as Microsoft 365 does
    results: list[MethodResult]
    position: int  # 0 is the top-most Authentication-Results header


@dataclass
class AuthFacts:
    trust: str  # configured, top-most-header, untrusted-only, missing
    authserv_id: str = ""  # server ID of the trusted header (receiver-specific: not for rules)
    spf: str = "missing"  # pass, fail, softfail, neutral, none, temperror, permerror, or missing
    spf_domain: str = ""  # envelope sender (smtp.mailfrom) or HELO name
    dkim: list[tuple[str, str]] = field(default_factory=list)  # (result, signing domain)
    dmarc: str = "missing"  # pass, fail, none (no DMARC policy), bestguesspass, permerror, temperror, or missing
    dmarc_from_domain: str = ""  # the From domain that DMARC checked
    dmarc_action: str = ""  # what the receiving server did because of DMARC: none, quarantine, reject...
    compauth: str = ""  # Microsoft composite authentication, when present
    compauth_reason: str = ""  # Microsoft's reason code (receiver-specific: not for rules)
    sender_ip: str = ""  # IP of the server that handed the email to your mail server
    # Aligned = the authenticated domain belongs to the same organization as the
    # From address the user sees. A pass without alignment proves nothing about From.
    spf_aligned: bool = False
    dkim_aligned: bool = False  # a passing DKIM signature belongs to the From domain's organization
    ignored_headers: int = 0  # Authentication-Results headers we did not trust
    ignored_authserv_ids: list[str] = field(default_factory=list)  # server IDs of the ignored headers (receiver-specific: not for rules)

    @property
    def dkim_pass_domains(self) -> list[str]:
        """Signing domains whose DKIM result was pass."""
        return [domain for result, domain in self.dkim if result == "pass"]


def _split_outside(text: str, separator: str = ";") -> list[str]:
    """Split on a separator, ignoring separators inside (comments) or "quotes"."""
    parts, current, depth, quoted = [], [], 0, False
    for char in text:
        if char == '"' and depth == 0:
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")" and depth:
            depth -= 1
        if char == separator and depth == 0 and not quoted:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def parse_authentication_results(value: str, position: int = 0) -> AuthResultsHeader:
    segments = [segment.strip() for segment in _split_outside(value)]
    authserv_id = ""
    if segments and "=" not in _COMMENT.sub("", segments[0]):
        # "mx.google.com" or "mx.microsoft.com 1" (the 1 is a version number)
        authserv_id = (segments[0].split() or [""])[0].lower()
        segments = segments[1:]

    results = []
    for segment in segments:
        match = _METHOD.match(segment)
        if not match:
            continue  # "none", empty segments, garbage
        rest = segment[match.end():]
        comments = _COMMENT.findall(rest)
        properties = {
            key.lower(): val.strip('"')
            for key, val in _PROPERTY.findall(_COMMENT.sub(" ", rest))
        }
        results.append(MethodResult(
            method=match.group(1).lower(),
            result=match.group(2).lower(),
            properties=properties,
            comment="; ".join(comment.strip() for comment in comments),
        ))
    return AuthResultsHeader(authserv_id=authserv_id, results=results, position=position)


def select_trusted(headers: list[AuthResultsHeader], trusted_ids: set[str]) -> tuple[list[AuthResultsHeader], str]:
    if not headers:
        return [], "missing"
    if trusted_ids:
        chosen = [header for header in headers if header.authserv_id in trusted_ids]
        return chosen, "configured" if chosen else "untrusted-only"
    # No configuration: trust the top-most header, plus any directly below it
    # from the same server (some servers write one header per method).
    top_id = headers[0].authserv_id
    chosen = []
    for header in headers:
        if header.authserv_id != top_id:
            break
        chosen.append(header)
    return chosen, "top-most-header"


def parse_received_spf(value: str) -> tuple[str, dict[str, str]]:
    """'Pass (comment) client-ip=192.0.2.1; helo=...' -> ('pass', {'client-ip': ...})"""
    result = (value.split() or ["missing"])[0].lower()
    properties = {key.lower(): val.strip('"') for key, val in _PROPERTY.findall(_COMMENT.sub(" ", value))}
    return result, properties


def auth_facts(parsed: ParsedEmail, trusted_ids: set[str] | None = None) -> AuthFacts:
    trusted_ids = {server_id.lower() for server_id in (trusted_ids or set())}
    headers = [
        parse_authentication_results(value, position)
        for position, value in enumerate(parsed.header_all("Authentication-Results"))
    ]
    trusted, trust = select_trusted(headers, trusted_ids)
    ignored = [header for header in headers if header not in trusted]
    facts = AuthFacts(
        trust=trust,
        authserv_id=trusted[0].authserv_id if trusted else "",
        ignored_headers=len(ignored),
        ignored_authserv_ids=sorted({header.authserv_id or "(no server ID)" for header in ignored}),
    )

    for result in (result for header in trusted for result in header.results):
        props = result.properties
        if result.method == "spf" and facts.spf == "missing":
            facts.spf = result.result
            facts.spf_domain = (props.get("smtp.mailfrom") or props.get("smtp.helo") or "").rpartition("@")[2].lower()
            if ip := _IP_IN_COMMENT.search(result.comment):
                facts.sender_ip = ip.group(1)
        elif result.method == "dkim":
            domain = props.get("header.d") or props.get("header.i", "").rpartition("@")[2]
            facts.dkim.append((result.result, "" if domain.lower() == "none" else domain.lower()))  # Microsoft: header.d=none
        elif result.method == "dmarc" and facts.dmarc == "missing":
            facts.dmarc = result.result
            facts.dmarc_from_domain = props.get("header.from", "").lower()
            facts.dmarc_action = props.get("action", "")
        elif result.method == "compauth" and not facts.compauth:
            facts.compauth = result.result
            facts.compauth_reason = props.get("reason", "")
        elif result.method == "arc" and not facts.sender_ip:
            facts.sender_ip = props.get("smtp.remote-ip", "")

    # Microsoft also writes Received-SPF with the connecting IP. Only use it
    # when we trusted the top-most header, because it carries no server ID.
    if not facts.sender_ip and trust == "top-most-header":
        _, props = parse_received_spf(parsed.header("Received-SPF"))
        facts.sender_ip = props.get("client-ip", "")

    from_domain = parsed.sender.domain if parsed.sender else ""
    facts.spf_aligned = facts.spf == "pass" and aligned(facts.spf_domain, from_domain)
    facts.dkim_aligned = any(aligned(domain, from_domain) for domain in facts.dkim_pass_domains)
    return facts
