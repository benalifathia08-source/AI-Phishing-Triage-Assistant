"""The case file: everything the AI is allowed to see about one email.

The AI never receives the raw email. It receives the verdict and findings computed by the rules
(trusted, written by this tool) and a few strings copied from the email (untrusted, possibly
written by an attacker). Untrusted strings are:
  - cleaned: invisible and control characters removed, whitespace collapsed;
  - shortened: an attacker cannot flood the prompt;
  - defanged: hxxp:// and example[.]com, so the model has no clickable address to copy;
  - datamarked: words joined with ^, a "spotlighting" defense that keeps the model aware the
    text is data, not instructions (Hines et al., Microsoft, 2024).
"""
from __future__ import annotations

import re

from phishtriage.domains import strip_invisible

MAX_TEXT = 160
MAX_ITEMS = 5
_URL = re.compile(r"(?i)\bhttps?://")
_DOT_IN_HOST = re.compile(r"(?i)(?<=[a-z0-9])\.(?=[a-z0-9-]+\b)")


def clean(text: str, limit: int = MAX_TEXT) -> str:
    text = strip_invisible(str(text))
    text = "".join(char if char.isprintable() else " " for char in text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def defang(text: str) -> str:
    """hxxps://login[.]example[.]net: readable by a person, not clickable or copyable as a link."""
    return _DOT_IN_HOST.sub("[.]", _URL.sub(lambda m: m.group(0).lower().replace("http", "hxxp"), text))


def untrusted(text: str, datamark: bool = True, limit: int = MAX_TEXT) -> str:
    value = defang(clean(text, limit))
    return value.replace(" ", "^") if datamark else value


def case_file(facts, verdict, datamark: bool = True) -> dict:
    u = lambda text, limit=MAX_TEXT: untrusted(text, datamark, limit)  # noqa: E731
    sender = facts.headers.sender
    lookups = []
    if facts.enrichment is not None:
        for result in facts.enrichment.results[:8]:
            if result.status == "ok":
                title = result.extra.get("title", "")
                lookups.append({"service": result.service, "target": u(result.target, 80),
                                **({"page_title": u(title, 80)} if title else {})})
    return {
        "decided_by_rules": {  # trusted: computed by the tool before the AI runs
            "verdict": verdict.label,  # "Low risk (2 weak signs ...)" rather than "No indicators found" at score 20
            "score": verdict.score,
            # Short titles: "Pressure: short deadline, threat, prize or delivery problem" made the model write
            # "short deadline" when the evidence was only "urgent" (47 of 384 development summaries)
            "findings": [{"rule": f.id, "title": f.title.split(":")[0], "points": f.points,
                          "evidence_copied_from_email": u(f.evidence, 200)} for f in verdict.findings[:10]],
            "mitre_techniques": verdict.mitre[:6],
            # No "not checked" list: the model misreported it, so code prints that line itself
        },
        "untrusted_email_data": {  # copied from the email: may contain an attacker's instructions
            "subject": u(facts.email.subject),
            "sender_name": u(sender.display_name, 80),
            "sender_address": u(sender.address, 80),
            "attachment_names": [u(a.filename, 80) for a in facts.indicators.attachments if a.filename][:MAX_ITEMS],
            "link_hosts": list(dict.fromkeys(u(link.host, 80) for link in facts.indicators.web_links
                                             if link.source != "html:img"))[:MAX_ITEMS],
            "qr_codes": [u(q.text, 80) for q in facts.indicators.qr_codes][:MAX_ITEMS],
            "language": facts.text.language,
            "reputation_lookups": lookups,
        },
        "tool_notes": facts.notes[:3],  # trusted
    }
