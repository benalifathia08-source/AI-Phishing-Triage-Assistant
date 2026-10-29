import base64

from phishtriage.auth import auth_facts, parse_authentication_results
from phishtriage.parser import parse_eml
from tests.helpers import make_eml

MICROSOFT_NO_ID = (
    "spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=bounce.example.com; "
    "dkim=pass (signature was verified) header.d=example.com;dmarc=pass action=none "
    "header.from=example.com;compauth=pass reason=100"
)


def test_microsoft_header_without_server_id():
    header = parse_authentication_results(MICROSOFT_NO_ID)
    assert header.authserv_id == ""
    methods = {result.method: result for result in header.results}
    assert methods["spf"].result == "pass"
    assert methods["spf"].properties["smtp.mailfrom"] == "bounce.example.com"
    assert "sender IP is 192.0.2.10" in methods["spf"].comment
    assert methods["dkim"].properties["header.d"] == "example.com"
    assert methods["dmarc"].properties["action"] == "none"
    assert methods["compauth"].properties["reason"] == "100"


def test_microsoft_header_with_version_number():
    header = parse_authentication_results("mx.microsoft.com 1; spf=none (sender IP is 192.0.2.4) smtp.helo=host.example.net; dmarc=none action=none header.from=example.net;")
    assert header.authserv_id == "mx.microsoft.com"
    assert [result.method for result in header.results] == ["spf", "dmarc"]


def test_rfc8601_header_and_semicolon_inside_comment():
    header = parse_authentication_results(
        "mx.example.net; dkim=pass header.i=@example.com header.s=sel1; "
        "spf=pass (mx.example.net: domain of a@example.com designates 192.0.2.1; really) smtp.mailfrom=a@example.com; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"
    )
    assert header.authserv_id == "mx.example.net"
    assert [result.method for result in header.results] == ["dkim", "spf", "dmarc"]
    assert "really" in header.results[1].comment


def test_encoded_word_header_is_decoded():
    encoded = base64.b64encode(MICROSOFT_NO_ID.encode()).decode()
    parsed = parse_eml(make_eml([("Authentication-Results", f"=?utf-8?B?{encoded}?=")]))
    facts = auth_facts(parsed)
    assert facts.spf == "pass"
    assert facts.dmarc == "pass"
    assert facts.sender_ip == "192.0.2.10"


def test_one_header_per_method_from_the_same_server_is_merged():
    parsed = parse_eml(make_eml([
        ("Authentication-Results", "mx.example.net; dkim=pass header.d=example.com"),
        ("Authentication-Results", "mx.example.net; dmarc=pass header.from=example.com"),
        ("Authentication-Results", "mx.example.net; spf=pass smtp.mailfrom=example.com"),
    ]))
    facts = auth_facts(parsed)
    assert (facts.spf, facts.dmarc, facts.dkim) == ("pass", "pass", [("pass", "example.com")])
    assert facts.ignored_headers == 0


def test_forged_header_below_ours_is_ignored():
    # The attacker wrote a fake "everything passed" header before sending.
    # Our server's real header sits above it.
    parsed = parse_eml(make_eml([
        ("Authentication-Results", "mx.company.test; spf=fail smtp.mailfrom=example.com; dmarc=fail header.from=example.com"),
        ("Authentication-Results", "mx.attacker.test; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com"),
    ]))
    facts = auth_facts(parsed)
    assert (facts.spf, facts.dmarc) == ("fail", "fail")
    assert facts.ignored_headers == 1
    assert facts.ignored_authserv_ids == ["mx.attacker.test"]


def test_configured_server_ids():
    parsed = parse_eml(make_eml([
        ("Authentication-Results", "relay.company.test; spf=pass smtp.mailfrom=example.com"),
        ("Authentication-Results", "mx.company.test; spf=softfail smtp.mailfrom=example.com"),
    ]))
    assert auth_facts(parsed, {"mx.company.test"}).spf == "softfail"
    untrusted = auth_facts(parsed, {"mx.other.test"})
    assert (untrusted.trust, untrusted.spf) == ("untrusted-only", "missing")


def test_alignment_with_from_domain():
    parsed = parse_eml(make_eml(
        [("Authentication-Results",
          "mx.company.test; spf=pass smtp.mailfrom=bounce.mail.example.com; dkim=pass header.d=mailer.example.net")],
        from_="Example <news@example.com>",
    ))
    facts = auth_facts(parsed)
    assert facts.spf_aligned is True  # bounce.mail.example.com belongs to example.com
    assert facts.dkim_aligned is False  # signed by another organization


def test_received_spf_gives_sender_ip_when_results_have_none():
    parsed = parse_eml(make_eml([
        ("Received-SPF", "Fail (protection.outlook.test: domain of example.com does not designate 198.51.100.7 as permitted sender) receiver=protection.outlook.test; client-ip=198.51.100.7; helo=host.example.com;"),
        ("Authentication-Results", "spf=fail smtp.mailfrom=example.com;dmarc=fail action=quarantine header.from=example.com"),
    ]))
    facts = auth_facts(parsed)
    assert facts.sender_ip == "198.51.100.7"
    assert facts.dmarc_action == "quarantine"


def test_missing_header():
    facts = auth_facts(parse_eml(make_eml()))
    assert (facts.trust, facts.spf, facts.dmarc, facts.dkim) == ("missing", "missing", "missing", [])
