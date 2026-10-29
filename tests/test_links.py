from phishtriage.indicators import phone_numbers
from phishtriage.links import LinkCollection, make_link


def links_from_html(html: str):
    collection = LinkCollection()
    collection.add_html(html)
    return collection.links


def test_link_text_naming_another_site():
    [link] = links_from_html('<a href="https://login.example.net/x">www.paypal.com</a>')
    assert link.text_shows_other_domain == "www.paypal.com"


def test_link_text_matching_its_target_is_fine():
    [link] = links_from_html('<a href="https://www.example.com/account">https://example.com/account</a>')
    assert link.text_shows_other_domain == ""


def test_sentence_with_a_dot_is_not_a_domain():
    [link] = links_from_html('<a href="https://news.example.com/">Enjoy your personal space.You deserve it</a>')
    assert link.text_shows_other_domain == ""


def test_safe_links_wrapper_is_unwrapped():
    href = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com%2Fpage&data=abc"
    links = links_from_html(f'<a href="{href}">www.example.com</a>')
    assert links[0].text_shows_other_domain == ""  # the wrapper carries the shown site
    assert links[0].embedded_urls == ["https://www.example.com/page"]
    assert links[1].source == "embedded" and links[1].host == "www.example.com"


def test_proofpoint_wrappers_are_unwrapped():
    v3 = make_link("https://urldefense.com/v3/__http:/www.example.com/__;!!abc!def$", "html:a", "www.example.com")
    assert v3.embedded_urls == ["http://www.example.com/"]
    assert v3.text_shows_other_domain == ""
    v2 = make_link("https://urldefense.proofpoint.com/v2/url?u=https-3A__www.example.com_login&d=x", "html:a")
    assert v2.embedded_urls == ["https://www.example.com/login"]


def test_url_tricks():
    userinfo = make_link("https://www.bank.example@login.example.net/", "html:a")
    assert userinfo.has_userinfo and userinfo.host == "login.example.net"
    assert make_link("http://198.51.100.20/login", "html:a").host_is_ip
    assert make_link("https://bit.ly/3abc", "html:a").is_shortener
    assert make_link("https://secure-login.web.app/", "html:a").on_free_hosting
    assert make_link("https://example.com:8443/", "html:a").nonstandard_port
    assert make_link("https://xn--pypal-4ve.com/", "html:a").suspicious_characters


def test_newsletter_click_tracking_is_recorded():
    link = make_link("https://abc.r.us-west-2.awstrack.me/L0/https:%2F%2Fwww.example.com", "html:a", "example.com")
    assert link.click_tracker
    assert not make_link("https://login.example.net/", "html:a").click_tracker


def test_tabs_and_newlines_inside_urls_are_removed():
    assert make_link("https://exa\tmple.com/lo\ngin", "html:a").url == "https://example.com/login"


def test_forms_refresh_frames_and_special_schemes():
    html = """
      <meta http-equiv="refresh" content="0; url=https://redirect.example.net/r">
      <form action="https://collect.example.net/post"><input type="password"></form>
      <iframe src="https://frame.example.net/"></iframe>
      <a href="tel:+18005550100">Call us</a>
      <a href="data:text/html;base64,PGgxPmhpPC9oMT4=">Open</a>
      <a href="mailto:someone@example.com">mail</a>
      <a href="#top">top</a>
    """
    sources = {(link.source, link.scheme) for link in links_from_html(html)}
    assert ("html:meta-refresh", "https") in sources
    assert ("html:form", "https") in sources
    assert ("html:iframe", "https") in sources
    assert ("html:a", "tel") in sources and ("html:a", "data") in sources
    assert not any(scheme == "mailto" for _, scheme in sources)


def test_plain_text_copies_are_not_duplicated():
    collection = LinkCollection()
    collection.add_html('<a href="https://example.com/a">https://example.com/a</a>')
    collection.add_text("Visit https://example.com/a today.")
    assert len(collection.links) == 1


def test_broken_html_still_yields_links():
    links = links_from_html('<div><a href="https://example.com/x">unclosed <b>bold<a href=https://example.net/y>next')
    assert [link.host for link in links] == ["example.com", "example.net"]


def test_phone_numbers_need_context():
    text = "Order 1234567890123 shipped. Questions? Call our help desk at +1 (800) 555-0199 or +18005550199."
    assert phone_numbers(text) == ["+1 (800) 555-0199"]
    assert phone_numbers("Invoice number 2026100800123 attached.") == []
