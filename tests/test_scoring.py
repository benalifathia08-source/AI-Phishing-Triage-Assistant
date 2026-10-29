"""Every rule in phishtriage/rules/scoring.py: it fires when it should, and stays silent when it should.

Each case starts from an ordinary, authenticated newsletter and changes the facts one rule looks at.
"""
import copy

import pytest

from phishtriage.analyze import analyze
from phishtriage.attachments import AttachmentInfo
from phishtriage.brands import Lookalike
from phishtriage.config import Settings
from phishtriage.dkim_check import DkimCheck
from phishtriage.enrich import EnrichmentFacts
from phishtriage.enrich.base import Reputation
from phishtriage.indicators import QrCode
from phishtriage.links import make_link
from phishtriage.rules import UNKNOWN, evaluate, load_rules
from tests.helpers import make_eml

RULES = load_rules()
RULE = {meta.id: function for meta, function in RULES.rules}
POINTS = {meta.id: meta.points for meta, _ in RULES.rules}
BASE = analyze(make_eml(
    [("Authentication-Results", "mx.company.test; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; "
                                "dmarc=pass header.from=example.com")],
    from_="Example News <news@example.com>", subject="Monthly news",
    body="Hello, here is our monthly news about the product and the team.",
), Settings(dkim_recheck=False))


def base():
    return copy.deepcopy(BASE)


def attachment(**changes) -> AttachmentInfo:
    values = dict(filename="file.bin", extension="bin", declared_type="application/octet-stream", size=10,
                  sha256="0" * 64, inline=False, detected_type="unknown", category="other")
    values.update(changes)
    return AttachmentInfo(**values)


def unauthenticated(f):
    f.auth.dmarc, f.auth.spf, f.auth.spf_aligned, f.auth.dkim_aligned = "none", "fail", False, False


def looked_up(f, *results):
    f.enrichment = EnrichmentFacts(results=list(results))


CASES = {
    "AUTH-001": unauthenticated,
    "AUTH-002": lambda f: setattr(f.auth, "spf", "fail"),
    "AUTH-003": lambda f: setattr(f.auth, "dmarc", "fail"),
    "AUTH-004": lambda f: setattr(f.auth, "dmarc", "none"),
    "AUTH-005": lambda f: setattr(f.headers, "own_domain_from_outside", True),
    "AUTH-006": lambda f: (setattr(f, "dkim_recheck_enabled", True),
                           setattr(f, "dkim_recheck", [DkimCheck("example.com", "s1", "fail", "the body was changed")])),
    "SENDER-001": lambda f: (setattr(f.headers.sender, "domain", "muhbdrtdtbniig"),
                             setattr(f.headers.sender, "domain_is_valid", False)),
    "SENDER-002": lambda f: setattr(f.headers.sender, "on_free_hosting", True),
    "SENDER-003": lambda f: setattr(f.headers.sender, "suspicious_characters", ["invisible characters"]),
    "SENDER-004": lambda f: (setattr(f.headers.sender, "display_name_address_differs", True),
                             setattr(f.headers.sender, "display_name_address", "ceo@company.test")),
    "REPLY-001": lambda f: (setattr(f.headers, "reply_to_differs", True), setattr(f.headers, "reply_to_domains", ["other.example"])),
    "REPLY-002": lambda f: setattr(f.headers, "reply_to_is_freemail", True),
    "BRAND-001": lambda f: setattr(f.brands, "impersonated", ["PayPal"]),
    "BRAND-002": lambda f: f.brands.lookalikes.append(Lookalike("paypa1.com", "sender", "paypal.com", "PayPal", "confusable-letters")),
    "BRAND-003": lambda f: f.brands.lookalikes.append(Lookalike("medtech-tn.com", "link", "medtech.tn", "your organization", "brand-in-domain")),
    "BRAND-004": lambda f: f.brands.lookalikes.append(Lookalike("paypal-help.com", "link", "paypal.com", "PayPal", "brand-in-domain")),
    "LINK-001": lambda f: f.indicators.links.append(make_link("https://evil.example.net/x", "html:a", "www.paypal.com")),
    "LINK-002": lambda f: f.indicators.links.append(make_link("https://www.bank.example@evil.example.net/", "html:a")),
    "LINK-003": lambda f: f.indicators.links.append(make_link("http://198.51.100.20/login", "html:a")),
    "LINK-004": lambda f: f.indicators.links.append(make_link("data:text/html;base64,PGgxPg==", "html:a")),
    "LINK-005": lambda f: f.indicators.links.append(make_link("https://bit.ly/abc", "html:a")),
    "LINK-006": lambda f: f.indicators.links.append(make_link("https://login-portal.web.app/", "html:a")),
    "LINK-007": lambda f: f.indicators.links.append(make_link("https://example.net:8443/", "html:a")),
    "LINK-008": lambda f: f.indicators.links.append(make_link("https://xn--pypal-4ve.com/", "html:a")),
    "ATTACH-001": lambda f: f.indicators.attachments.append(attachment(filename="setup.exe", category="executable")),
    "ATTACH-002": lambda f: f.indicators.attachments.append(attachment(filename="message.html", category="html")),
    "ATTACH-003": lambda f: f.indicators.attachments.append(attachment(category="html", html_login_form=True)),
    "ATTACH-004": lambda f: f.indicators.attachments.append(attachment(
        category="html", html_script_tricks=["creates a downloadable file in the browser (HTML smuggling)"])),
    "ATTACH-005": lambda f: f.indicators.attachments.append(attachment(filename="order.docm", has_macros=True)),
    "ATTACH-006": lambda f: f.indicators.attachments.append(attachment(filename="secure.zip", encrypted_archive=True)),
    "ATTACH-007": lambda f: f.indicators.attachments.append(attachment(filename="docs.zip", archive_risky_members=["scan.js"])),
    "ATTACH-008": lambda f: f.indicators.attachments.append(attachment(filename="invoice.pdf", detected_type="html",
                                                                      extension_mismatch=True)),
    "ATTACH-009": lambda f: f.indicators.attachments.append(attachment(filename="statement.pdf", pdf_encrypted=True)),
    "QR-001": lambda f: f.indicators.qr_codes.append(QrCode("qr:code.png", "https://mfa.example.net")),
    "TEXT-001": lambda f: setattr(f.text, "credential_request", ["verify your account"]),
    "TEXT-002": lambda f: setattr(f.text, "urgency", ["within 24 hours"]),
    "TEXT-003": lambda f: setattr(f.text, "gift_cards", ["gift cards"]),
    "TEXT-004": lambda f: setattr(f.text, "secrecy", ["are you available"]),
    "TEXT-005": lambda f: (setattr(f.text, "callback", ["call us"]), setattr(f.indicators, "phone_numbers", ["+1 800 555 0100"])),
    "TEXT-006": lambda f: setattr(f.text, "qr_prompt", ["scan the qr"]),
    "TEXT-007": lambda f: setattr(f.text, "open_attachment", ["password is :"]),
    "HIDDEN-001": lambda f: (setattr(f.text, "hidden_words", 500), setattr(f.text, "hidden_techniques", ["display:none"])),
    "AI-001": lambda f: setattr(f.text, "hidden_injection_phrases", ["ignore all previous instructions"]),
    "AI-002": lambda f: setattr(f.text, "injection_phrases", ["note to the ai"]),
    "LANG-001": lambda f: setattr(f.text, "language", "nl"),
    "TIME-001": lambda f: setattr(f.headers, "date_skew_hours", 5.0),
    "THREAD-001": lambda f: setattr(f.forwarding, "reply_prefix_without_thread", True),
    "COMBO-001": lambda f: (setattr(f.text, "credential_request", ["verify your account"]),
                            f.indicators.links.append(make_link("https://bit.ly/abc", "html:a"))),
    "COMBO-002": lambda f: (setattr(f.text, "bank_details_change", ["nouveau rib"]), setattr(f.headers, "reply_to_differs", True)),
    "COMBO-003": lambda f: (setattr(f.brands, "impersonated", ["PayPal"]), unauthenticated(f)),
    "COMBO-004": lambda f: (setattr(f.text, "credential_request", ["verify your account"]),
                            f.indicators.links.append(make_link("https://login.example.net/", "html:a"))),
    "LEGIT-001": lambda f: None,  # the base email is authenticated and nothing disguises its sender
    "LEGIT-002": lambda f: setattr(f.headers, "internal", True),
    "REP-001": lambda f: looked_up(f, Reputation("virustotal", "file", "abc", "ok", malicious=5)),
    "REP-002": lambda f: looked_up(f, Reputation("virustotal", "url", "https://x.example.net", "ok", malicious=4)),
    "REP-003": lambda f: looked_up(f, Reputation("urlscan", "url", "https://x.example.net", "ok", verdict="malicious")),
    "REP-004": lambda f: looked_up(f, Reputation("abuseipdb", "ip", "203.0.113.9", "ok", score=90)),
    "REP-005": lambda f: looked_up(f, Reputation("rdap", "domain", "new.example", "ok", extra={"age_days": 3})),
}


def test_every_rule_has_a_case():
    assert sorted(CASES) == sorted(RULE)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires(rule_id):
    f = base()
    CASES[rule_id](f)
    result = RULE[rule_id](f)
    assert result and result is not UNKNOWN, f"{rule_id} did not fire"


def test_the_ordinary_newsletter_fires_no_positive_rule():
    verdict = evaluate(base(), RULES)
    assert [f.id for f in verdict.findings if f.points > 0] == []
    assert verdict.verdict == "No indicators found"


def test_precision_guards():
    f = base()
    f.indicators.links.append(make_link("https://abc.r.us-west-2.awstrack.me/L0/x", "html:a", "www.example.com"))
    assert not RULE["LINK-001"](f)  # a newsletter's click tracker is not a disguised link

    f = base()
    f.headers.internal = True
    f.indicators.links.append(make_link("https://company.sharepoint.com/doc", "html:a"))
    assert not RULE["LINK-006"](f)  # an internal SharePoint share is normal

    f = base()
    f.text.open_attachment = ["open the attachment"]
    assert not RULE["TEXT-007"](f)  # "open the attachment" alone is ordinary

    f = base()
    f.indicators.attachments.append(attachment(filename="logo.png", detected_type="jpeg", category="image",
                                               inline=True, extension_mismatch=True))
    assert not RULE["ATTACH-008"](f)  # a logo saved with the wrong picture extension is not a disguise

    f = base()
    f.text.credential_request = ["verify your account"]
    f.indicators.links.append(make_link("https://accounts.example.com/verify", "html:a"))
    assert not RULE["COMBO-004"](f)  # links to the sender's own organization

    for language in ("en", "fr", "ar", "unknown"):
        f = base()
        f.text.language = language
        assert not RULE["LANG-001"](f)

    f = base()
    f.headers.date_skew_hours = 1.5
    assert not RULE["TIME-001"](f)


def test_authentication_credit_needs_an_honest_sender():
    f = base()
    f.headers.reply_to_differs = True
    assert not RULE["LEGIT-001"](f)  # authenticated, but replies go elsewhere: no credit
    f = base()
    f.brands.impersonated = ["PayPal"]
    f.headers.internal = True
    assert not RULE["LEGIT-002"](f)


def test_inline_forwards_make_header_rules_unknown():
    f = base()
    unauthenticated(f)
    f.forwarding.inline_forward = True
    for rule_id in ("AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "LEGIT-001", "LEGIT-002"):
        assert RULE[rule_id](f) is UNKNOWN, rule_id


def test_internal_mail_is_not_punished_for_missing_authentication():
    f = base()
    unauthenticated(f)
    f.headers.internal = True
    assert not RULE["AUTH-001"](f) and not RULE["AUTH-002"](f)


def test_lookup_rules_say_unknown_without_lookups():
    f = base()
    looked_up(f)  # lookups ran but returned nothing usable
    for rule_id in ("REP-001", "REP-002", "REP-003", "REP-004", "REP-005"):
        assert RULE[rule_id](f) is UNKNOWN, rule_id


def test_verdicts_of_typical_combinations():
    f = base()
    unauthenticated(f)
    f.brands.impersonated = ["PayPal"]
    f.text.credential_request = ["verify your account"]
    f.indicators.links.append(make_link("https://paypal-help.example.net/login", "html:a", "www.paypal.com"))
    assert evaluate(f, RULES).verdict == "Malicious"  # classic credential phishing

    f = base()
    f.headers.own_domain_from_outside = True
    unauthenticated(f)
    assert evaluate(f, RULES).verdict == "Suspicious"  # the MedTech Moodle case: reviewed, not condemned
