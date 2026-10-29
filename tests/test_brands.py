from phishtriage.brands import brand_facts, brands_named, edit_distance, find_lookalike, load_brands, skeleton

BRANDS = load_brands()


def lookalike(host, protected=frozenset()):
    found = find_lookalike(host, "link", BRANDS, protected)
    return (found.brand, found.imitates, found.method) if found else None


def test_typo_domains():
    assert lookalike("homtail.online") == ("Microsoft", "hotmail.com", "typo")  # seen in a real sample
    assert lookalike("microsfot-login.com")[2] in ("typo", "brand-in-domain")
    assert lookalike("paypall.com") == ("PayPal", "paypal.com", "typo")


def test_confusable_letters():
    assert lookalike("paypa1.com") == ("PayPal", "paypal.com", "confusable-letters")
    assert lookalike("rnicrosoft.com") == ("Microsoft", "microsoft.com", "confusable-letters")
    assert lookalike("xn--pypal-4ve.com") == ("PayPal", "paypal.com", "confusable-letters")  # Cyrillic a
    assert lookalike("micro-soft.com") == ("Microsoft", "microsoft.com", "confusable-letters")


def test_brand_inside_another_domain():
    assert lookalike("paypal-secure-login.com") == ("PayPal", "paypal.com", "brand-in-domain")
    assert lookalike("secure.paypal.com.account-check.example") == ("PayPal", "paypal.com", "brand-in-domain")
    # Bold Unicode letters, as in a real Zalando lure
    assert lookalike("\U0001d5ed\U0001d5ee\U0001d5f9\U0001d5ee\U0001d5fb\U0001d5f1\U0001d5fc-client-70760774.nl")[:2] == ("Zalando", "zalando.com")


def test_other_extension():
    assert lookalike("docusign.cc") == ("DocuSign", "docusign.com", "other-extension")


def test_real_brand_domains_are_not_lookalikes():
    for host in ["www.paypal.com", "accounts.google.com", "s3.amazonaws.com", "lh3.googleusercontent.com",
                 "login.microsoftonline.com", "mail.hotmail.com", "www.biat.com.tn"]:
        assert lookalike(host) is None, host


def test_ordinary_words_and_short_names_avoid_false_alarms():
    for host in ["pineapple.com", "apply.com", "bookings-hotel.example", "dhs.gov", "groups.io", "stream.example",
                 "orangebox.example", "startups.example", "pop-ups.example", "adore-beauty.example"]:
        assert lookalike(host) is None, host
    assert lookalike("apple-id-verify.com") == ("Apple", "apple.com", "brand-in-domain")  # whole word still counts


def test_shared_platforms_check_only_the_name_the_attacker_chose():
    # Seen in the samples: the platform itself is real, not a lookalike
    assert lookalike("erasaqu.onmicrosoft.com") is None
    assert lookalike("storage.googleapis.com") is None
    assert lookalike("outlook.fr") is None  # Microsoft's French free mail
    # ...but a brand in the tenant or site name still counts
    assert lookalike("paypal-billing.onmicrosoft.com") == ("PayPal", "paypal.com", "brand-in-domain")
    assert lookalike("microsoft-support.sharepoint.com") == ("Microsoft", "microsoft.com", "brand-in-domain")
    assert lookalike("docusign-review.web.app") == ("DocuSign", "docusign.com", "brand-in-domain")


def test_tunisian_banks_checked_by_fathia():
    assert lookalike("www.bna.com.tn") is None and lookalike("bna.tn") is None  # both real BNA domains
    assert lookalike("bna-securite.com") == ("BNA", "bna.tn", "brand-in-domain")
    assert lookalike("ubcinet-verification.com") == ("UBCI", "ubcinet.net", "brand-in-domain")
    assert lookalike("cnamera.example") is None  # whole word only: "cnam" inside another word does not count
    assert brands_named("Alerte sécurité QNB", BRANDS) == ["QNB Tunisia"]
    assert brands_named("Banque de l'Habitat - relevé", BRANDS) == ["BH Bank"]


def test_protected_domains():
    protected = frozenset({"atlas-trading.tn"})
    assert lookalike("atlas-tradlng.tn", protected) == ("your organization", "atlas-trading.tn", "confusable-letters")
    assert lookalike("atlas-trading.com", protected) == ("your organization", "atlas-trading.tn", "other-extension")
    assert lookalike("mail.atlas-trading.tn", protected) is None


def test_names_in_sender_and_subject():
    assert brands_named("Team Zalando", BRANDS) == ["Zalando"]
    assert brands_named("\U0001d40f\U0001d41a\U0001d432\U0001d40f\U0001d41a\U0001d425 Support", BRANDS) == ["PayPal"]
    assert brands_named("ups and downs of the market", BRANDS) == []  # short names need capitals
    assert brands_named("Your UPS parcel", BRANDS) == ["UPS"]
    assert brands_named("Crédit Agricole: alerte", BRANDS) == ["Crédit Agricole"]


def test_invisible_characters_inside_a_brand_name():
    # Seen in a real sample: invisible variation selectors (U+E0139) inside "Coinbase"
    name = "Co\U000e0139\U000e0139in\U000e0139base Serv\U000e0139ices"
    assert brands_named(name, BRANDS) == ["Coinbase"]
    facts = brand_facts(name, "", "xw@unrelated.example", [("unrelated.example", "sender")], BRANDS)
    assert facts.impersonated == ["Coinbase"]


def test_brand_facts_impersonation():
    facts = brand_facts("PayPal Service", "Your account is limited", "paypal-alerts@mailer.example",
                        [("mailer.example", "sender"), ("paypa1-resolution.com", "link")], BRANDS)
    assert facts.sender_name_brands == ["PayPal"]
    assert facts.sender_address_brands == ["PayPal"]
    assert facts.impersonated == ["PayPal"]
    assert [(item.domain, item.method) for item in facts.lookalikes] == [("paypa1-resolution.com", "brand-in-domain")]

    real = brand_facts("PayPal", "Receipt", "service@paypal.com", [("paypal.com", "sender")], BRANDS)
    assert real.sender_is_brand == ["PayPal"] and real.impersonated == [] and real.lookalikes == []


def test_helpers():
    assert skeleton("rn1cr0soft") == skeleton("microsoft")
    assert edit_distance("hotmail", "homtail", 1) == 1  # swapped neighbours count as one typo
    assert edit_distance("paypal", "paypal", 1) == 0
    assert edit_distance("abcdef", "uvwxyz", 1) == 2  # stops early above the limit
