"""Domain helpers: organizational domains, DMARC-style alignment and lookalike characters."""
from __future__ import annotations

import re
import unicodedata

import tldextract

# Use the public suffix list bundled with tldextract: no network call at runtime.
# Private suffixes (github.io, blogspot.com...) count, so attacker.github.io is
# its own organization rather than part of GitHub.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com",
    "gmx.net", "gmx.de", "web.de", "proton.me", "protonmail.com", "zoho.com", "yandex.com",
    "yandex.ru", "mail.ru", "qq.com", "163.com",
    # French and UK variants, common in mail reaching Tunisia
    "hotmail.fr", "outlook.fr", "live.fr", "yahoo.fr", "laposte.net", "orange.fr", "sfr.fr", "free.fr", "gmx.fr",
    "hotmail.co.uk", "yahoo.co.uk",
})

SHORTENER_DOMAINS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "lnkd.in", "qrco.de", "bl.ink",
    "short.io", "v.gd", "clck.ru", "u.to", "shorturl.asia",
})

# Free hosting, site builders and file sharing: legitimate services that phishing
# abuses because their domains have a good reputation. A fact, not a verdict.
FREE_HOSTING_SUFFIXES = (
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "r2.dev", "github.io", "gitlab.io",
    "netlify.app", "vercel.app", "glitch.me", "herokuapp.com", "onrender.com", "replit.app", "repl.co",
    "weebly.com", "wixsite.com", "square.site", "webflow.io", "framer.app", "godaddysites.com",
    "sites.google.com", "docs.google.com", "forms.gle", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "blob.core.windows.net", "web.core.windows.net",
    "azurewebsites.net", "sharepoint.com", "1drv.ms", "dropbox.com", "dl.dropboxusercontent.com",
    "s3.amazonaws.com", "ipfs.io", "dweb.link", "notion.site", "carrd.co", "jotform.com",
    "onmicrosoft.com",  # free Microsoft 365 tenant names: anyone can send from evil.onmicrosoft.com
)


def free_hosting_suffix(host: str) -> str:
    """The shared platform a host lives on ('web.app' for evil.web.app), or ''."""
    host = host.lower().strip(".")
    return next((suffix for suffix in FREE_HOSTING_SUFFIXES if host == suffix or host.endswith("." + suffix)), "")

# Click-tracking domains of mailing services. Legitimate newsletters route every link
# through them, so "the link text names another site" is expected there.
CLICK_TRACKERS = (
    "awstrack.me",  # Amazon SES
    "list-manage.com", "mailchi.mp",  # Mailchimp
    "sendgrid.net",
    "sendibm1.com", "sendibm2.com", "sendibm3.com", "sendibm4.com", "sendinblue.com", "brevo.com",  # Brevo
    "hubspotlinks.com",
    "exct.net", "exacttarget.com",  # Salesforce Marketing Cloud
    "rs6.net",  # Constant Contact
    "createsend.com", "cmail19.com", "cmail20.com",  # Campaign Monitor
    "mandrillapp.com", "mailgun.org", "sparkpostmail.com", "pstmrk.it", "klclick.com", "customeriomail.com",
    "convertkit-mail.com", "mlsend.com", "substack.com", "beehiiv.com", "redditmail.com",
)


def is_click_tracker(host: str) -> bool:
    host = host.lower().strip(".")
    return any(host == tracker or host.endswith("." + tracker) for tracker in CLICK_TRACKERS)


# Big sites that show up as footer icons and decoy links in almost every email.
# Their age and reputation are known, so lookups on them waste quota. Links on
# their abused services (docs.google.com, sharepoint.com...) are still checked.
WELL_KNOWN_DOMAINS = frozenset({
    "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "youtube.com", "youtu.be",
    "tiktok.com", "pinterest.com", "whatsapp.com", "t.me", "wikipedia.org", "wikimedia.org", "google.com",
    "gstatic.com", "googleapis.com", "microsoft.com", "office.com", "apple.com", "amazon.com", "w3.org", "schema.org",
})

# Characters that display as nothing. Attackers slip them inside words ("Co<invisible>inbase") so
# that filters looking for a brand name or a phrase no longer match.
INVISIBLE_CHARACTERS = (
    {0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x2800, 0x3164, 0xFEFF, 0xFFA0}  # soft hyphen, fillers, braille blank
    | set(range(0x180B, 0x1810))  # Mongolian variation selectors and vowel separator
    | set(range(0x200B, 0x2010)) | set(range(0x202A, 0x202F)) | set(range(0x2060, 0x2065))  # zero-width, direction
    | set(range(0xFE00, 0xFE10))  # variation selectors
    | set(range(0xE0000, 0xE0080))  # tag characters
    | set(range(0xE0100, 0xE01F0))  # variation selectors supplement (seen in a real "Coinbase" lure)
)


def strip_invisible(text: str) -> str:
    return "".join(char for char in text if ord(char) not in INVISIBLE_CHARACTERS)


def org_domain(domain: str) -> str:
    """example.co.uk for mail.example.co.uk. Falls back to the input when there is no known suffix."""
    domain = domain.strip().strip(".").lower()
    parts = _extract(domain)
    return f"{parts.domain}.{parts.suffix}" if parts.domain and parts.suffix else domain


def registrable_label(domain: str) -> str:
    """'example' for mail.example.co.uk: the name part an attacker imitates."""
    domain = domain.strip(".").lower()
    parts = _extract(domain)
    # Without a known extension (paypa1.example, muhbdrtdtbniig) the first label is the name.
    return parts.domain if parts.suffix and parts.domain else domain.split(".")[0]


def aligned(first: str, second: str) -> bool:
    """Relaxed DMARC alignment: both domains belong to the same organizational domain."""
    return bool(first and second) and org_domain(first) == org_domain(second)


def on_free_hosting(host: str) -> bool:
    return bool(free_hosting_suffix(host))


def has_public_suffix(text: str) -> bool:
    """True for 'example.com', false for 'invoice.pdf' or 'v1.2'."""
    parts = _extract(text)
    return bool(parts.suffix and parts.domain)


def is_valid_domain(domain: str) -> bool:
    """A syntactically valid ASCII hostname with a public suffix (punycode labels allowed)."""
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return False
    return bool(_extract(domain).suffix)


def suspicious_characters(text: str) -> list[str]:
    """Reasons a name or domain contains characters used to imitate other text."""
    reasons = []
    if any(0x1D400 <= ord(char) <= 0x1D7FF for char in text):
        reasons.append("bold or italic 'mathematical' letters that imitate normal text")
    if any(ord(char) in INVISIBLE_CHARACTERS for char in text):
        reasons.append("invisible characters")
    for word in re.findall(r"\w+", text):
        scripts = {unicodedata.name(char, "").split(" ")[0] for char in word if char.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}:
            reasons.append(f"mixed alphabets in one word ({word})")
            break
    if "xn--" in text.lower():
        reasons.append("punycode domain (may display as non-Latin lookalike letters)")
    return reasons
