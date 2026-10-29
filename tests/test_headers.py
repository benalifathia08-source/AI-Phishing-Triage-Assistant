from phishtriage.cli import safe
from phishtriage.domains import is_valid_domain, org_domain, suspicious_characters
from phishtriage.headers import header_facts
from phishtriage.parser import parse_eml
from tests.helpers import make_eml


def test_reply_to_and_return_path_to_other_organizations():
    facts = header_facts(parse_eml(make_eml(
        [("Return-Path", "<bounce@mailer.example.net>")],
        from_="Payroll <payroll@example.com>",
        to="staff@company.test\r\nReply-To: urgent.payroll@gmail.com",
    )))
    assert facts.reply_to_domains == ["gmail.com"]
    assert facts.reply_to_differs and facts.reply_to_is_freemail
    assert facts.return_path_domain == "mailer.example.net"
    assert facts.return_path_differs


def test_same_organization_subdomains_do_not_differ():
    facts = header_facts(parse_eml(make_eml(
        [("Return-Path", "<bounce@mail.example.com>")],
        from_="News <news@example.com>",
        to="staff@company.test\r\nReply-To: help@support.example.com",
    )))
    assert not facts.reply_to_differs
    assert not facts.return_path_differs


def test_display_name_showing_another_address():
    facts = header_facts(parse_eml(make_eml(from_='"support@bank.example" <random123@example.net>')))
    assert facts.sender.display_name_address == "support@bank.example"
    assert facts.sender.display_name_address_differs


def test_hidden_recipients_and_date_skew():
    facts = header_facts(parse_eml(make_eml(
        [("Received", "from host.example.net by mx.company.test; Wed, 07 Oct 2026 12:00:00 +0000")],
        to="",
        date="Wed, 07 Oct 2026 15:00:00 +0000",
    )))
    assert facts.recipients_hidden
    assert facts.date_skew_hours == -3.0  # dated 3 hours after it arrived


def test_internal_mail_and_own_domain_spoofing():
    protected = frozenset({"univ.example"})
    internal = header_facts(parse_eml(make_eml([("X-MS-Exchange-Organization-AuthAs", "Internal")],
                                               from_="IT Desk <it@univ.example>")), protected)
    assert internal.internal and internal.sender_is_protected and not internal.own_domain_from_outside
    spoofed = header_facts(parse_eml(make_eml([("X-MS-Exchange-Organization-AuthAs", "Anonymous")],
                                              from_="IT Desk <it@univ.example>")), protected)
    assert not spoofed.internal and spoofed.own_domain_from_outside
    gmail = header_facts(parse_eml(make_eml(from_="IT Desk <it@univ.example>")), protected)
    assert gmail.exchange_auth_as == "" and not gmail.own_domain_from_outside  # unknown, not spoofed


def test_authenticated_mail_from_a_sister_organization_is_not_spoofing():
    from phishtriage.analyze import analyze
    from phishtriage.config import Settings
    settings = Settings(dkim_recheck=False, protected_domains=frozenset({"school.example", "univ.example"}))
    signed = make_eml([("X-MS-Exchange-Organization-AuthAs", "Anonymous"),
                       ("Authentication-Results", "spf=pass smtp.mailfrom=univ.example;dkim=pass header.d=univ.example;"
                                                  "dmarc=pass action=none header.from=univ.example")],
                      from_="Registrar <registrar@univ.example>")
    unsigned = make_eml([("X-MS-Exchange-Organization-AuthAs", "Anonymous"),
                         ("Authentication-Results", "spf=fail smtp.mailfrom=univ.example;dmarc=none action=none header.from=univ.example")],
                        from_="Registrar <registrar@univ.example>")
    assert not analyze(signed, settings).headers.own_domain_from_outside
    assert analyze(unsigned, settings).headers.own_domain_from_outside


def test_domain_helpers():
    assert org_domain("mail.example.co.uk") == "example.co.uk"
    assert org_domain("attacker.github.io") == "attacker.github.io"  # private suffix
    assert is_valid_domain("example.com")
    assert is_valid_domain("xn--80ak6aa92e.com")
    assert not is_valid_domain("muhbdrtdtbniig")  # no extension, seen in real samples
    assert not is_valid_domain("-casinorewardstop-")
    assert not is_valid_domain("%example.com")


def test_lookalike_characters():
    assert suspicious_characters("PayPal") == []
    assert suspicious_characters("\U0001d40f\U0001d41a\U0001d432")  # bold "Pay"
    assert suspicious_characters("pay\u200bpal")  # zero-width space
    assert suspicious_characters("pаypal")  # Cyrillic a in a Latin word


def test_terminal_output_escapes_control_characters():
    assert safe("ok\x1b[2Jtext") == "ok\\u001b[2Jtext"
    assert safe("pay\u200bpal") == "pay\\u200bpal"
    assert safe("Co\U000e0139inbase") == "Co\\ue0139inbase"  # printable to Python, invisible to the reader


def test_variation_selectors_count_as_invisible():
    assert "invisible characters" in suspicious_characters("Co\U000e0139inbase")
    assert "invisible characters" in suspicious_characters("Pay\ufe0fPal")
