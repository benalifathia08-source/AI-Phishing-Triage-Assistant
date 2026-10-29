import base64

from phishtriage.analyze import analyze
from phishtriage.config import Settings
from tests.helpers import make_eml

OFFLINE = Settings(dkim_recheck=False)
ORIGINAL = make_eml(
    [("Authentication-Results", "mx.company.test; spf=fail smtp.mailfrom=paypa1.example; dmarc=fail header.from=paypa1.example")],
    from_="PayPal <service@paypa1.example>", subject="Your account is limited",
)


def report(original: bytes, as_rfc822: bool, subject: str = "FW: suspicious email") -> bytes:
    if as_rfc822:
        part = f"Content-Type: message/rfc822\r\n\r\n{original.decode()}\r\n"
    else:
        part = ("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"original.eml\"\r\n"
                f"Content-Transfer-Encoding: base64\r\n\r\n{base64.b64encode(original).decode()}\r\n")
    mime = ('Content-Type: multipart/mixed; boundary="r"\r\n\r\n'
            "--r\r\nContent-Type: text/plain\r\n\r\nThis looks fake, can you check?\r\n"
            f"--r\r\n{part}--r--\r\n")
    return make_eml(from_="Employee <employee@company.test>", subject=subject, extra_mime=mime)


def test_reported_email_analyzes_the_attached_original():
    facts = analyze(report(ORIGINAL, as_rfc822=False), OFFLINE)
    assert facts.forwarding.analyzed_attached_original
    assert facts.forwarding.reporter == "employee@company.test"
    assert facts.headers.sender.address == "service@paypa1.example"
    assert facts.auth.dmarc == "fail"
    assert facts.brands.impersonated == ["PayPal"]
    assert any("attached to a report" in note for note in facts.notes)


def test_re_encoded_original_skips_dkim_recheck():
    facts = analyze(report(ORIGINAL, as_rfc822=True), Settings(dkim_recheck=True))
    assert facts.forwarding.analyzed_attached_original
    assert facts.dkim_recheck == [] and not facts.dkim_recheck_enabled
    assert any("re-encoded" in note for note in facts.notes)


def test_inline_forward_warns_that_headers_are_the_forwarders():
    body = ("Please check this\r\n\r\n---------- Forwarded message ---------\r\nFrom: PayPal <service@paypa1.example>\r\n"
            "Date: Wed, 7 Oct 2026\r\nSubject: Your account is limited\r\n\r\nVerify your account now.\r\n")
    facts = analyze(make_eml(body=body, subject="Fwd: Your account is limited"), OFFLINE)
    assert facts.forwarding.inline_forward
    assert facts.forwarding.quoted_sender == "service@paypa1.example"
    assert any(item.where == "forwarded-sender" for item in facts.brands.lookalikes)
    assert any("forwarded inline" in note for note in facts.notes)


def test_outlook_french_forward_block():
    body = ("\r\nDe : Service Client <client@banque-alerte.example>\r\nEnvoyé : mercredi 7 octobre 2026 10:00\r\n"
            "À : moi@company.test\r\nObjet : Alerte\r\n\r\nConfirmez vos identifiants.\r\n")
    facts = analyze(make_eml(body=body, subject="TR: Alerte"), OFFLINE)
    assert facts.forwarding.inline_forward
    assert facts.forwarding.quoted_sender == "client@banque-alerte.example"


def test_fake_reply_without_a_thread():
    assert analyze(make_eml(subject="RE: Invoice 4821"), OFFLINE).forwarding.reply_prefix_without_thread
    real = make_eml([("In-Reply-To", "<abc@example.com>")], subject="RE: Invoice 4821")
    assert not analyze(real, OFFLINE).forwarding.reply_prefix_without_thread


def test_attached_email_lure_that_is_not_a_report_stays_on_the_outer_email():
    long_text = "Dear customer, " + "please review the attached statement carefully. " * 40
    mime = ('Content-Type: multipart/mixed; boundary="r"\r\n\r\n'
            f"--r\r\nContent-Type: text/plain\r\n\r\n{long_text}\r\n"
            f"--r\r\nContent-Type: message/rfc822\r\n\r\n{ORIGINAL.decode()}\r\n--r--\r\n")
    facts = analyze(make_eml(from_="Bank <info@bank-notice.example>", subject="Statement", extra_mime=mime), OFFLINE)
    assert not facts.forwarding.analyzed_attached_original
    assert facts.headers.sender.address == "info@bank-notice.example"
    assert facts.email.attached_emails == 1
