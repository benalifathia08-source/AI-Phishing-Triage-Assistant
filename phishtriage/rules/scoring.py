"""Scoring rules (rule set v1, draft).

Written on 2026-10-19. Every rule, its points and the evidence
behind it are explained in docs/RULES.md; keep the two in step when changing a rule.

HOW A RULE WORKS
    @rule("SENDER-001", title="...", points=20, category="sender", mitre=["T1566"])
    def my_rule(f):
        return <something true when the rule should fire>

    - `f` holds every fact about the email (docs/FACTS.md). Shortcuts: phishtriage/rules/helpers.py (`h`).
    - Return True or an evidence sentence to fire; False/None to stay silent; UNKNOWN when the data
      needed is missing or cannot be trusted (for example the headers of an inline forward).
    - points: negative points are evidence the email is legitimate.
    - floor="Suspicious" / "Malicious": decisive evidence; the verdict is at least this.
    - needs="lookups": the rule uses reputation lookups and is "not checked" when they did not run.

POINT SCALE (chosen before tuning; see docs/RULES.md)
    40   decisive on its own, usually with a floor
    30-35 strong: one such sign makes the email Suspicious
    20-25 medium: needs a second sign
    10-15 weak: only counts together with others
    -15 / -20 evidence of legitimacy
    Suspicious from 30, Malicious from 70.

HOW TO CHANGE A RULE
    Edit it here, run `phishtriage rules report` (development sets only), update docs/RULES.md.
    The test sets are run once, at M7, on a frozen copy (git tag rules-v1). No changes after that.
"""
from phishtriage.rules import UNKNOWN, rule
from phishtriage.rules import helpers as h

SUSPICIOUS_AT = 30
MALICIOUS_AT = 70
# Correlated signs must not pile up: several authentication failures, several phrases or several
# link tricks usually describe one underlying fact about the email.
CATEGORY_CAPS = {"authentication": 40, "text": 30, "links": 45, "sender": 50, "reply-path": 30, "brand": 50}

_RISKY_SCHEMES = ("data", "javascript", "vbscript", "file", "smb", "search-ms", "ms-msdt", "ms-officecmd")


# ===== Authentication (cap 40) ====================================================================
@rule("AUTH-001", title="The From domain is not authenticated", points=20, category="authentication",
      mitre=["T1566"])
def from_domain_not_authenticated(f):
    if not h.headers_describe_sender(f):
        return UNKNOWN
    if h.external(f) and not h.authenticated(f):
        return (f"no DMARC pass and no SPF/DKIM aligned with {f.headers.sender.domain or 'the From domain'} "
                f"(SPF {f.auth.spf}, DMARC {f.auth.dmarc})")


@rule("AUTH-002", title="SPF fails: the sending server is not allowed to send for this domain", points=15,
      category="authentication", mitre=["T1566"])
def spf_fails(f):
    if not h.headers_describe_sender(f):
        return UNKNOWN
    if h.external(f) and f.auth.spf == "fail":
        return f"SPF fail for {f.auth.spf_domain or 'the envelope domain'} from {f.auth.sender_ip or 'an unknown IP'}"


@rule("AUTH-003", title="DMARC fails: the domain owner's own policy rejects this email", points=20,
      category="authentication", mitre=["T1566", "T1656"])
def dmarc_fails(f):
    if not h.headers_describe_sender(f):
        return UNKNOWN
    if f.auth.dmarc == "fail":
        return f"DMARC fail for {f.auth.dmarc_from_domain or f.headers.sender.domain}"


@rule("AUTH-004", title="The From domain publishes no DMARC policy", points=10, category="authentication",
      mitre=["T1566"])
def no_dmarc_policy(f):
    if not h.headers_describe_sender(f):
        return UNKNOWN
    if h.external(f) and f.auth.dmarc == "none":
        return f"{f.auth.dmarc_from_domain or f.headers.sender.domain} has no DMARC policy"


@rule("AUTH-005", title="Uses your own domain but arrived from the internet unauthenticated", points=25,
      category="authentication", mitre=["T1656", "T1566"], floor="Suspicious",
      actions=["Check whether one of your own systems sends this mail without SPF/DKIM; if not, it is spoofing."])
def own_domain_spoofed(f):
    if f.forwarding.inline_forward:
        return UNKNOWN
    if f.headers.own_domain_from_outside:
        return f"{f.headers.sender.domain} is your domain, but this email came from outside without authentication"


@rule("AUTH-006", title="A DKIM signature broke: the email was changed after signing", points=25,
      category="authentication", mitre=["T1566"])
def dkim_broken(f):
    if not f.dkim_recheck_enabled:
        return UNKNOWN
    broken = [check for check in f.dkim_recheck if check.status == "fail"]
    if broken:
        return "; ".join(f"{check.domain}: {check.reason}" for check in broken)


# ===== Sender (cap 50) ============================================================================
@rule("SENDER-001", title="Sender domain is not a valid domain", points=25, category="sender", mitre=["T1566"])
def sender_domain_invalid(f):
    if f.headers.sender.domain and not f.headers.sender.domain_is_valid:
        return f"the sender's domain '{f.headers.sender.domain}' has no valid extension"


@rule("SENDER-002", title="Sends from a shared platform anyone can sign up to", points=30, category="sender",
      mitre=["T1585.002", "T1566"])
def sender_on_shared_platform(f):
    if f.headers.sender.on_free_hosting:
        return f"sender domain {f.headers.sender.domain} is a shared platform (e.g. a free Microsoft 365 tenant)"


@rule("SENDER-003", title="Lookalike or invisible characters in the sender's name or address", points=30,
      category="sender", mitre=["T1656"])
def sender_lookalike_characters(f):
    if f.headers.sender.suspicious_characters:
        return "; ".join(f.headers.sender.suspicious_characters)


@rule("SENDER-004", title="The sender name shows a different email address", points=25, category="sender",
      mitre=["T1656"])
def sender_name_shows_other_address(f):
    if f.headers.sender.display_name_address_differs:
        return f"name shows {f.headers.sender.display_name_address}, real address {f.headers.sender.address}"


# ===== Reply path (cap 30) ========================================================================
@rule("REPLY-001", title="Replies go to another organization", points=20, category="reply-path",
      mitre=["T1656", "T1566"])
def reply_to_other_organization(f):
    if f.headers.reply_to_differs:
        return f"Reply-To {', '.join(f.headers.reply_to_domains)} instead of {f.headers.sender.org_domain}"


@rule("REPLY-002", title="Replies go to a free mail address, but the sender is not free mail", points=15,
      category="reply-path", mitre=["T1585.002", "T1656"])
def reply_to_free_mail(f):
    if f.headers.reply_to_is_freemail and not f.headers.sender.is_freemail:
        return f"Reply-To {', '.join(f.headers.reply_to_domains)}"


# ===== Brand impersonation (cap 50) ===============================================================
@rule("BRAND-001", title="Claims to be a brand it does not send from", points=35, category="brand", mitre=["T1656"])
def brand_impersonated(f):
    if f.brands.impersonated:
        return f"claims to be {', '.join(f.brands.impersonated)} but sends from {f.headers.sender.domain}"


@rule("BRAND-002", title="The sender's domains imitate a brand", points=40, category="brand",
      mitre=["T1583.001", "T1656"])
def sender_domain_lookalike(f):
    found = h.lookalikes(f, "sender", "reply-to", "return-path", "sender-name", "forwarded-sender", protected=False)
    if found:
        return "; ".join(f"{item.where} {item.domain} imitates {item.imitates} ({item.method})" for item in found)


@rule("BRAND-003", title="A domain imitates your own organization's domain", points=40, category="brand",
      mitre=["T1583.001", "T1656"], floor="Malicious",
      actions=["Block the lookalike domain and warn staff: lookalikes of your own domain are the core of BEC."])
def own_domain_lookalike(f):
    found = h.lookalikes(f, protected=True)
    if found:
        return "; ".join(f"{item.where} {item.domain} imitates {item.imitates}" for item in found)


@rule("BRAND-004", title="A link goes to a domain that imitates a brand", points=30, category="brand",
      mitre=["T1566.002", "T1583.001"])
def link_domain_lookalike(f):
    found = h.lookalikes(f, "link", protected=False)
    if found:
        return "; ".join(f"{item.domain} imitates {item.imitates} ({item.method})" for item in found)


# ===== Links (cap 45) =============================================================================
@rule("LINK-001", title="A link's text names a different site than where it goes", points=25, category="links",
      mitre=["T1566.002", "T1204.001"])
def link_text_mismatch(f):
    found = [l for l in h.web_links(f) if l.text_shows_other_domain and not l.click_tracker]
    if found:
        return "; ".join(f"shows {l.text_shows_other_domain}, goes to {l.host}" for l in found[:3])


@rule("LINK-002", title="A link hides its real host after an @", points=35, category="links",
      mitre=["T1566.002", "T1204.001"])
def link_userinfo_trick(f):
    found = [l for l in h.web_links(f) if l.has_userinfo]
    if found:
        return "; ".join(f"really goes to {l.host}" for l in found[:3])


@rule("LINK-003", title="A link goes to a bare IP address", points=25, category="links", mitre=["T1566.002"])
def link_to_ip(f):
    found = [l.host for l in h.web_links(f) if l.host_is_ip]
    if found:
        return "links to " + ", ".join(dict.fromkeys(found))


@rule("LINK-004", title="A dangerous link type (data:, javascript:, file share or Windows handler)", points=40,
      category="links", mitre=["T1204.001", "T1027.006"], floor="Suspicious")
def dangerous_link_scheme(f):
    found = [l for l in f.indicators.links if l.scheme in _RISKY_SCHEMES or l.scheme.startswith("ms-")]
    if found:
        return "; ".join(f"{l.scheme}: link" for l in found[:3])


@rule("LINK-005", title="A link uses a URL shortener", points=10, category="links", mitre=["T1566.002"])
def link_shortener(f):
    found = [l.host for l in h.web_links(f) if l.is_shortener]
    if found:
        return "shortener: " + ", ".join(dict.fromkeys(found))


@rule("LINK-006", title="A link goes to free hosting or file sharing (external email)", points=10, category="links",
      mitre=["T1608.005", "T1566.002"])
def link_free_hosting(f):
    if not h.external(f):
        return None
    found = [l.host for l in h.web_links(f) if l.on_free_hosting]
    if found:
        return "hosted on " + ", ".join(list(dict.fromkeys(found))[:3])


@rule("LINK-007", title="A link uses an unusual port", points=10, category="links", mitre=["T1566.002"])
def link_unusual_port(f):
    found = [l.host for l in h.web_links(f) if l.nonstandard_port]
    if found:
        return "unusual port on " + ", ".join(dict.fromkeys(found))


@rule("LINK-008", title="Lookalike characters in a link's host", points=15, category="links",
      mitre=["T1566.002", "T1583.001"])
def link_lookalike_characters(f):
    found = [l.host for l in h.web_links(f) if l.suspicious_characters]
    if found:
        return "lookalike characters in " + ", ".join(dict.fromkeys(found))


# ===== Attachments (no cap: each is a separate file risk) =========================================
@rule("ATTACH-001", title="Executable, disk-image or configuration-profile attachment", points=40,
      category="attachments", mitre=["T1566.001", "T1204.002"], floor="Malicious",
      actions=["Check whether any recipient opened the attachment; if so, isolate their device."])
def executable_attachment(f):
    risky = h.attachments(f, "executable", "disk-image", "config-profile")
    if risky:
        return "attached: " + ", ".join(item.filename or item.detected_type for item in risky)


@rule("ATTACH-002", title="HTML or SVG attachment", points=25, category="attachments", mitre=["T1566.001"])
def html_attachment(f):
    found = [item for item in h.attachments(f, "html") if not item.inline]
    if found:
        return "attached web page: " + ", ".join(item.filename or item.detected_type for item in found)


@rule("ATTACH-003", title="An attached web page asks for a password", points=40, category="attachments",
      mitre=["T1598.002", "T1566.001"], floor="Malicious")
def html_attachment_login_form(f):
    found = [item for item in h.attachments(f) if item.html_login_form]
    if found:
        return "password form inside " + ", ".join(item.filename or "an attachment" for item in found)


@rule("ATTACH-004", title="An attached web page builds a file or decodes hidden code (HTML smuggling)", points=40,
      category="attachments", mitre=["T1027.006", "T1566.001"], floor="Malicious")
def html_smuggling(f):
    signs = ("HTML smuggling", "builds code at runtime", "decodes hidden text")
    found = [item for item in h.attachments(f) if any(sign in trick for trick in item.html_script_tricks for sign in signs)]
    if found:
        return "; ".join(f"{item.filename or 'attachment'}: {', '.join(item.html_script_tricks)}" for item in found)


@rule("ATTACH-005", title="Office document with macros", points=35, category="attachments",
      mitre=["T1566.001", "T1204.002"], floor="Suspicious")
def macro_document(f):
    found = [item for item in h.attachments(f) if item.has_macros or item.category == "macro-document"]
    if found:
        return "macros in " + ", ".join(item.filename or "a document" for item in found)


@rule("ATTACH-006", title="Password-protected archive (hides its content from scanners)", points=30,
      category="attachments", mitre=["T1566.001", "T1027"])
def encrypted_archive(f):
    found = [item for item in h.attachments(f) if item.encrypted_archive]
    if found:
        return "password-protected: " + ", ".join(item.filename or "archive" for item in found)


@rule("ATTACH-007", title="An archive contains risky files", points=35, category="attachments",
      mitre=["T1566.001", "T1204.002"], floor="Suspicious")
def archive_with_risky_files(f):
    found = [(item, item.archive_risky_members) for item in h.attachments(f) if item.archive_risky_members]
    if found:
        return "; ".join(f"{item.filename or 'archive'} contains {', '.join(members[:3])}" for item, members in found)


@rule("ATTACH-008", title="A file disguised as another type", points=35, category="attachments",
      mitre=["T1036.007", "T1036.002"], floor="Suspicious")
def disguised_file(f):
    reasons = []
    for item in h.attachments(f):
        if item.inline and item.category == "image":
            continue  # a logo saved as .png that is really a .jpeg is not a disguise
        if item.extension_mismatch:
            reasons.append(f"{item.filename} is really {item.detected_type}")
        if item.double_extension:
            reasons.append(f"{item.filename} has a double extension")
        if item.name_suspicious_characters:
            reasons.append(f"{item.filename!r}: {', '.join(item.name_suspicious_characters)}")
    if reasons:
        return "; ".join(reasons)


@rule("ATTACH-009", title="Password-protected PDF", points=15, category="attachments", mitre=["T1566.001"])
def encrypted_pdf(f):
    found = [item.filename or "a PDF" for item in h.attachments(f) if item.pdf_encrypted]
    if found:
        return "encrypted: " + ", ".join(found)


# ===== QR codes ===================================================================================
@rule("QR-001", title="A QR code in a picture or PDF", points=20, category="qr", mitre=["T1566.002"])
def qr_code(f):
    if f.indicators.qr_codes:
        return "; ".join(f"{qr.source.removeprefix('qr:')}: {qr.text[:80]}" for qr in f.indicators.qr_codes[:2])


# ===== What the email says (cap 30) ===============================================================
@rule("TEXT-001", title="Asks for credentials or account verification", points=15, category="text", mitre=["T1598"])
def asks_for_credentials(f):
    if f.text.credential_request:
        return "; ".join(f.text.credential_request)


@rule("TEXT-002", title="Pressure: short deadline, threat, prize or delivery problem", points=10, category="text",
      mitre=["T1566"])
def pressure(f):
    phrases = f.text.urgency + f.text.prize + f.text.delivery
    if phrases:
        return "; ".join(phrases[:4])


@rule("TEXT-003", title="Money: payment, bank-detail change, gift cards or crypto", points=15, category="text",
      mitre=["T1656"])
def money(f):
    phrases = f.text.bank_details_change + f.text.gift_cards + f.text.payment + f.text.crypto
    if phrases:
        return "; ".join(phrases[:4])


@rule("TEXT-004", title="CEO-fraud tone: 'are you available', secrecy", points=15, category="text", mitre=["T1656"])
def ceo_fraud_tone(f):
    if f.text.secrecy:
        return "; ".join(f.text.secrecy)


@rule("TEXT-005", title="Asks the reader to phone a number", points=15, category="text", mitre=["T1566.004"])
def callback(f):
    if f.text.callback and f.indicators.phone_numbers:
        return f"{'; '.join(f.text.callback[:2])} ({', '.join(f.indicators.phone_numbers[:2])})"


@rule("TEXT-006", title="Asks the reader to scan a QR code", points=10, category="text", mitre=["T1566.002"])
def qr_prompt(f):
    if f.text.qr_prompt:
        return "; ".join(f.text.qr_prompt)


@rule("TEXT-007", title="Asks to enable macros or gives an attachment's password", points=15, category="text",
      mitre=["T1204.002"])
def risky_attachment_instructions(f):
    # "open the attachment" alone is ordinary; enabling macros or a password for the file is not
    risky = [p for p in f.text.open_attachment if any(word in p for word in ("macro", "password", "passcode",
                                                                            "enable", "activ", "mot de passe"))]
    if risky:
        return "; ".join(risky)


# ===== Hidden text and AI manipulation ============================================================
@rule("HIDDEN-001", title="Large amount of hidden text (filter evasion)", points=20, category="hidden-text",
      mitre=["T1566"])
def lots_of_hidden_text(f):
    if f.text.hidden_words > 200:
        return f"{f.text.hidden_words} hidden words ({', '.join(f.text.hidden_techniques)})"


@rule("AI-001", title="Hidden instructions aimed at an AI assistant", points=40, category="ai-manipulation",
      mitre=["T1566"], floor="Malicious",
      actions=["Keep this email as evidence of an attempt to manipulate AI-based mail tools."])
def hidden_ai_instructions(f):
    if f.text.hidden_injection_phrases:
        return "; ".join(f.text.hidden_injection_phrases)


@rule("AI-002", title="Visible instructions aimed at an AI assistant", points=15, category="ai-manipulation",
      mitre=["T1566"])
def visible_ai_instructions(f):
    # Visible only: security newsletters quote such phrases, so this alone stays weak
    if f.text.injection_phrases:
        return "; ".join(f.text.injection_phrases)


# ===== Language and timing ========================================================================
EXPECTED_LANGUAGES = ("en", "fr", "ar")  # languages your organization actually receives mail in


@rule("LANG-001", title="Written in a language your organization does not use", points=20, category="language",
      mitre=["T1566"])
def unexpected_language(f):
    if f.text.language not in EXPECTED_LANGUAGES and f.text.language != "unknown":
        return f"written in '{f.text.language}' (expected: {', '.join(EXPECTED_LANGUAGES)})"


@rule("TIME-001", title="Claimed send time is more than 2 hours from the arrival time", points=15, category="time",
      mitre=["T1566"])
def date_far_from_arrival(f):
    skew = f.headers.date_skew_hours
    if skew is not None and abs(skew) > 2:
        return f"the Date header is {abs(skew):.1f} hours {'before' if skew > 0 else 'after'} arrival"


# ===== Conversation tricks ========================================================================
@rule("THREAD-001", title="'RE:' subject that answers no earlier email (fake reply)", points=15, category="thread",
      mitre=["T1566", "T1656"])
def fake_reply(f):
    if f.forwarding.reply_prefix_without_thread:
        return f"subject {f.email.subject[:60]!r} has no In-Reply-To or References header"


# ===== Combinations: patterns far more telling than their parts ===================================
@rule("COMBO-001", title="Asks for credentials AND uses a deceptive link", points=25, category="combination",
      mitre=["T1598.003", "T1566.002"])
def credential_phishing_pattern(f):
    links = h.deceptive_links(f)
    if f.text.credential_request and links:
        return f"credential request with: {'; '.join(links[:3])}"


@rule("COMBO-004", title="Asks for credentials AND its links lead to another organization than the sender",
      points=20, category="combination", mitre=["T1598.003", "T1566.002"])
def credential_link_elsewhere(f):
    # A genuine account notice links to its own domain (or through its mailing service's tracker)
    if not f.text.credential_request:
        return None
    sender = f.headers.sender.org_domain
    elsewhere = [l.org_domain for l in h.web_links(f) if not l.click_tracker and l.org_domain != sender]
    if sender and elsewhere:
        return f"credential request from {sender}, links to {', '.join(list(dict.fromkeys(elsewhere))[:3])}"


@rule("COMBO-002", title="Asks for money AND the reply path or sender cannot be trusted", points=30,
      category="combination", mitre=["T1656"], floor="Suspicious",
      actions=["Confirm any payment or bank-detail change by phone, using a number you already know."])
def bec_pattern(f):
    asks = f.text.bank_details_change + f.text.gift_cards + f.text.secrecy
    if not asks:
        return None
    untrusted = []
    if f.headers.reply_to_differs:
        untrusted.append("replies go to another organization")
    if f.headers.sender.is_freemail:
        untrusted.append("sent from free mail")
    if h.headers_describe_sender(f) and h.external(f) and not h.authenticated(f):
        untrusted.append("sender not authenticated")
    if untrusted:
        return f"{'; '.join(asks[:2])} + {', '.join(untrusted)}"


@rule("COMBO-003", title="Claims a brand AND is not authenticated", points=15, category="combination",
      mitre=["T1656"])
def unauthenticated_brand_claim(f):
    if f.brands.impersonated and h.headers_describe_sender(f) and not h.authenticated(f):
        return f"{', '.join(f.brands.impersonated)} claim without authentication"


# ===== Evidence of legitimacy (negative points) ===================================================
# Authentication proves which domain sent the email, not that the domain is honest: attackers
# authenticate domains they own. So it only counts as legitimacy when the identity the reader is
# shown is the one that was authenticated, i.e. when there is no identity trick.
@rule("LEGIT-001", title="The From domain is authenticated, and the email does not disguise its sender",
      points=-15, category="legitimacy")
def from_domain_authenticated(f):
    if not h.headers_describe_sender(f):
        return UNKNOWN
    if h.authenticated(f) and not h.identity_tricks(f):
        return f"{f.headers.sender.domain} authenticated (DMARC {f.auth.dmarc}) and nothing disguises the sender"


@rule("LEGIT-002", title="Sent from inside your own organization, sender not disguised", points=-20,
      category="legitimacy")
def internal_mail(f):
    if f.forwarding.inline_forward:
        return UNKNOWN  # the forwarder is internal; the forwarded email may not be
    if f.headers.internal and not h.identity_tricks(f):
        return "Microsoft 365 marks it as internal"


# ===== Reputation lookups (only when lookups ran) =================================================
@rule("REP-001", title="VirusTotal engines flag an attachment", points=40, category="reputation", needs="lookups",
      mitre=["T1566.001"], floor="Malicious")
def virustotal_attachment(f):
    engines = h.vt_detections(f, "file")
    if engines is None:
        return UNKNOWN
    if engines >= 3:
        return f"{engines} VirusTotal engines flag an attachment"


@rule("REP-002", title="VirusTotal engines flag a link or its domain", points=30, category="reputation",
      needs="lookups", mitre=["T1566.002"], floor="Suspicious")
def virustotal_link(f):
    engines = [h.vt_detections(f, kind) for kind in ("url", "domain")]
    if all(value is None for value in engines):
        return UNKNOWN
    worst = max(value or 0 for value in engines)
    if worst >= 3:
        return f"{worst} VirusTotal engines flag a link or its domain"


@rule("REP-003", title="urlscan.io classifies a link as malicious", points=40, category="reputation",
      needs="lookups", mitre=["T1566.002"], floor="Malicious")
def urlscan_malicious(f):
    verdict = h.urlscan_malicious(f)
    if verdict is None:
        return UNKNOWN
    if verdict:
        return "urlscan.io: malicious"


@rule("REP-004", title="The sending IP is widely reported for abuse", points=15, category="reputation",
      needs="lookups", mitre=["T1566"])
def abusive_ip(f):
    score = h.abuse_score(f)
    if score is None:
        return UNKNOWN
    if score >= 75:
        return f"AbuseIPDB confidence {score}%"


@rule("REP-005", title="A domain in the email was registered in the last 30 days", points=25, category="reputation",
      needs="lookups", mitre=["T1583.001"])
def new_domain(f):
    age = h.newest_domain_age(f)
    if age is None:
        return UNKNOWN
    if age < 30:
        return f"youngest domain registered {age} days ago"
