"""Reported and forwarded emails.

A suspicious email often reaches the analyst second-hand:
  - Attached to a report ("Report phishing" buttons attach the original).
    The original keeps its headers, so it is the email to analyze.
  - Forwarded inline by a user. The original headers are gone: SPF, DKIM and
    DMARC now describe the user's forward, not the attacker. The tool must say
    so instead of reporting a reassuring "authentication passed".
Attackers also fake conversations with "RE:" subjects that answer nothing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from phishtriage.content import normalize
from phishtriage.parser import ParsedEmail

_REPORT_SUBJECT = re.compile(r"^\s*(fwd?|tr|wg|rv|enc)\s*:|\b(phish|phishing|hameçonnage|hameconnage|suspicious|suspect|spam|report|signal)",
                             re.IGNORECASE)
# "RE: ..." or a bare "RE" subject (seen in real lures); AW, SV, ANTW, RIF are other languages' "RE"
_REPLY_PREFIX = re.compile(r"^\s*(re|aw|sv|antw|rif|ref)\s*(:|$)", re.IGNORECASE)
_FORWARD_MARKERS = re.compile("|".join([
    r"-{2,}\s*forwarded message\s*-{2,}",  # Gmail
    r"-{2,}\s*original message\s*-{2,}",  # Outlook
    r"begin forwarded message\s*:",  # Apple Mail
    r"-{2,}\s*message transfere\s*-{2,}",  # Gmail and Thunderbird in French
    r"debut du message (reexpedie|transfere)",  # Apple Mail in French
    r"-{2,}\s*message d'?origine\s*-{2,}",  # Outlook in French
    r"(^|\n)\s*(from|de) ?:.{1,200}\n\s*(sent|envoye|date) ?:.{1,100}\n\s*(to|a) ?:",  # Outlook header block
]))
_QUOTED_FROM = re.compile(r"(?:^|\n)\s*(?:from|de) ?:\s*([^\n]{1,200})")
_ADDRESS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


@dataclass
class ForwardFacts:
    analyzed_attached_original: bool = False  # the email analyzed is the original attached to a report
    reporter: str = ""  # who reported or forwarded it
    report_subject: str = ""  # subject of the report that carried the original
    inline_forward: bool = False  # forwarded in the body: authentication results describe the forwarder
    quoted_sender: str = ""  # sender named in the forwarded text ("From: ...")
    quoted_sender_domain: str = ""  # domain of quoted_sender
    reply_prefix_without_thread: bool = False  # "RE:" but no In-Reply-To or References header: a fake reply


def _short_text(parsed: ParsedEmail) -> bool:
    text = parsed.text_body or re.sub(r"<[^>]+>", " ", parsed.html_body)
    return len(re.findall(r"\w+", text)) < 150


def pick_target(parsed: ParsedEmail) -> tuple[ParsedEmail, ForwardFacts]:
    """The email to analyze: the attached original when this looks like a user's report."""
    facts = ForwardFacts()
    if parsed.attached_emails and (_REPORT_SUBJECT.search(parsed.subject) or _short_text(parsed)):
        facts.analyzed_attached_original = True
        facts.reporter = parsed.sender.address if parsed.sender else ""
        facts.report_subject = parsed.subject
        return parsed.attached_emails[0], facts
    return parsed, facts


def forward_facts(target: ParsedEmail, shown_text: str, facts: ForwardFacts) -> ForwardFacts:
    if not facts.analyzed_attached_original:
        text = normalize(shown_text[:50_000])
        if marker := _FORWARD_MARKERS.search(text):
            facts.inline_forward = True
            if match := _QUOTED_FROM.search(text[marker.start():]):
                if address := _ADDRESS.search(match.group(1)):
                    facts.quoted_sender = address.group(0)
                    facts.quoted_sender_domain = address.group(0).rpartition("@")[2]
    has_thread = bool(target.header("In-Reply-To") or target.header("References"))
    facts.reply_prefix_without_thread = bool(_REPLY_PREFIX.match(target.subject)) and not has_thread
    return facts
