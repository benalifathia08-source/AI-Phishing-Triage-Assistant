"""Brand impersonation: brands the sender claims to be, and domains that imitate real ones.

Domains are compared in a normalized "skeleton" form, so that letters which
look alike count as equal: 0 and o, 1 / l / i, rn and m, vv and w, Cyrillic
and Latin look-alikes, and bold or italic Unicode letters.
"""
from __future__ import annotations

import re
import tomllib
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from phishtriage.domains import aligned, free_hosting_suffix, org_domain, registrable_label, strip_invisible

DEFAULT_BRANDS_FILE = Path(__file__).parent / "data" / "brands.toml"
PROTECTED = "your organization"

# Cyrillic and Greek letters that look like Latin ones
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ν": "v", "α": "a", "ο": "o", "ρ": "p",
    "τ": "t", "κ": "k", "ι": "i", "ε": "e",
})
_LOOKALIKE_LETTERS = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "4": "a", "5": "s",
                                    "7": "t", "8": "b", "9": "g", "$": "s", "@": "a"})


@dataclass(frozen=True)
class Brand:
    name: str
    names: tuple[str, ...]
    domains: tuple[str, ...]
    keywords: tuple[str, ...]
    whole_word: bool = False


@dataclass
class Lookalike:
    domain: str  # the suspicious domain as it appears
    where: str  # sender, reply-to, return-path, sender-name, link
    imitates: str  # the real domain it resembles
    brand: str  # the brand, or "your organization" for PROTECTED_DOMAINS
    method: str  # typo, confusable-letters, brand-in-domain, other-extension


@dataclass
class BrandFacts:
    sender_name_brands: list[str] = field(default_factory=list)  # brands named in the sender's display name
    subject_brands: list[str] = field(default_factory=list)  # brands named in the subject
    sender_address_brands: list[str] = field(default_factory=list)  # e.g. paypal-service@unrelated.example
    sender_is_brand: list[str] = field(default_factory=list)  # the sender domain really belongs to these brands
    impersonated: list[str] = field(default_factory=list)  # named in sender name or address, but not the sender
    lookalikes: list[Lookalike] = field(default_factory=list)  # domains in the email that imitate a brand or one of your own domains


@lru_cache(maxsize=4)
def load_brands(path: str = str(DEFAULT_BRANDS_FILE)) -> tuple[Brand, ...]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return tuple(
        Brand(
            name=entry["name"],
            names=tuple(entry.get("names") or [entry["name"]]),
            domains=tuple(domain.lower() for domain in entry.get("domains", [])),
            keywords=tuple(keyword.lower() for keyword in entry.get("keywords", [])),
            whole_word=bool(entry.get("whole_word", False)),
        )
        for entry in data.get("brand", [])
    )


def plain(text: str) -> str:
    """Lowercase, no accents, bold/italic Unicode turned into normal letters, Cyrillic look-alikes made Latin."""
    text = unicodedata.normalize("NFKC", strip_invisible(text)).casefold()
    text = "".join(char for char in unicodedata.normalize("NFKD", text) if not unicodedata.combining(char))
    return text.translate(_HOMOGLYPHS)


def plain_host(host: str) -> str:
    labels = []
    for label in host.strip(".").split("."):
        if label.lower().startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")  # show what a reader would see
            except UnicodeError:
                pass
        labels.append(label)
    return plain(".".join(labels))


def skeleton(label: str) -> str:
    text = plain(label).replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return re.sub(r"[^a-z]", "", text.translate(_LOOKALIKE_LETTERS))


def edit_distance(first: str, second: str, limit: int) -> int:
    """Typo distance (insert, delete, change, or swap two neighbours). Stops early above `limit`."""
    if abs(len(first) - len(second)) > limit:
        return limit + 1
    previous2: list[int] = []
    previous = list(range(len(second) + 1))
    for i, char in enumerate(first, 1):
        current = [i] + [0] * len(second)
        for j, other in enumerate(second, 1):
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char != other))
            if i > 1 and j > 1 and char == second[j - 2] and first[i - 2] == other:
                current[j] = min(current[j], previous2[j - 2] + 1)
        if min(current) > limit:
            return limit + 1
        previous2, previous = previous, current
    return previous[-1]


def _references(brands: tuple[Brand, ...], protected: frozenset[str]) -> list[tuple[str, str]]:
    refs = [(brand.name, domain) for brand in brands for domain in brand.domains]
    return refs + [(PROTECTED, domain.lower()) for domain in protected]


def _typo_limit(real: str, ordinary_word: bool) -> int:
    # One-letter typos of ordinary words are other real words (apply, oranges, bookings),
    # and short names (ups, bna) are one letter away from countless unrelated names.
    if ordinary_word:
        return 0
    return 2 if len(real) >= 9 else 1 if len(real) >= 5 else 0


def _resembles(word: str, real: str, ordinary_word: bool) -> bool:
    if word == real:
        return True
    if len(real) >= 4 and skeleton(word) == skeleton(real):
        return True
    limit = _typo_limit(real, ordinary_word)
    return bool(limit) and edit_distance(word, real, limit) <= limit


def find_lookalike(host: str, where: str, brands: tuple[Brand, ...], protected: frozenset[str] = frozenset()) -> Lookalike | None:
    if not host or re.fullmatch(r"[\d.:]+", host):
        return None
    raw = host.strip(".").lower()
    references = _references(brands, protected)

    # Shared platforms (evil.onmicrosoft.com, site.web.app, storage.googleapis.com) are real
    # services, so the platform name is not a lookalike. Only the part the attacker chose
    # (tenant, site or bucket name) is checked for brand names.
    if platform := free_hosting_suffix(raw):
        tenant = raw[: -len(platform)].rstrip(".")
        return _brand_inside(host, where, plain_host(tenant), brands, protected) if tenant else None

    # Decide "is this the real domain?" on the raw name: after normalizing, a
    # Cyrillic "pаypal.com" would become "paypal.com" and pass as the real one.
    if any(raw == domain or raw.endswith("." + domain) or aligned(org_domain(raw), domain) for _, domain in references):
        return None
    raw_label = registrable_label(org_domain(raw))
    shown = plain_host(raw)
    label = registrable_label(org_domain(shown))
    if len(label) < 3:
        return None

    ordinary = {b.name for b in brands if b.whole_word}
    # 1. The whole name imitates a real one.
    for brand, domain in references:
        real_label = registrable_label(domain)
        if label == real_label:
            if raw_label != real_label:  # same once Unicode tricks are undone
                return Lookalike(host, where, domain, brand, "confusable-letters")
            if len(real_label) >= 5 or brand == PROTECTED:  # ups, live, zoom exist on many extensions
                return Lookalike(host, where, domain, brand, "other-extension")
            continue
        if len(real_label) >= 4 and skeleton(label) == skeleton(real_label):
            return Lookalike(host, where, domain, brand, "confusable-letters")
        limit = _typo_limit(real_label, brand in ordinary)
        if limit and edit_distance(label, real_label, limit) <= limit:
            return Lookalike(host, where, domain, brand, "typo")

    # 2. The brand sits inside a longer name: paypal-secure.com, microsfot-login.com, secure.paypal.com.evil.net
    return _brand_inside(host, where, shown, brands, protected)


def _brand_inside(host: str, where: str, shown: str, brands: tuple[Brand, ...], protected: frozenset[str]) -> Lookalike | None:
    tokens = [token for token in re.split(r"[.\-_]+", shown) if len(token) >= 3]
    squashed = skeleton(shown.replace(".", "").replace("-", ""))
    keywords = [(brand.name, brand.domains[0] if brand.domains else "", keyword, brand.whole_word)
                for brand in brands for keyword in brand.keywords]
    keywords += [(PROTECTED, domain, registrable_label(domain), False) for domain in protected]
    for name, domain, keyword, whole_word in keywords:
        if len(keyword) < 3:
            continue
        # Inside longer names, allow typos only for long keywords: "adore" is one letter from "adobe".
        no_typos = whole_word or len(keyword) < 6
        if any(_resembles(token, keyword, no_typos) for token in tokens) or (
                not whole_word and len(keyword) >= 6 and skeleton(keyword) in squashed):
            return Lookalike(host, where, domain, name, "brand-in-domain")
    return None


def _name_pattern(name: str) -> tuple[re.Pattern, bool]:
    """(pattern, case_sensitive). Short all-caps names (UPS, BIAT) must appear in capitals."""
    if name.isupper() and len(name) <= 5:
        return re.compile(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])"), True
    return re.compile(rf"(?<![a-z0-9]){re.escape(plain(name))}(?![a-z0-9])"), False


@lru_cache(maxsize=4)
def _brand_patterns(brands: tuple[Brand, ...]) -> list[tuple[Brand, list[tuple[re.Pattern, bool]]]]:
    return [(brand, [_name_pattern(name) for name in brand.names]) for brand in brands]


def brands_named(text: str, brands: tuple[Brand, ...]) -> list[str]:
    if not text:
        return []
    folded = plain(text)
    upper = unicodedata.normalize("NFKC", strip_invisible(text))
    return [brand.name for brand, patterns in _brand_patterns(brands)
            if any(pattern.search(upper if case_sensitive else folded) for pattern, case_sensitive in patterns)]


def brand_facts(display_name: str, subject: str, address: str, hosts: list[tuple[str, str]],
                brands: tuple[Brand, ...], protected: frozenset[str] = frozenset()) -> BrandFacts:
    """`hosts` is a list of (domain, where) pairs: the sender, reply-to, return-path and link domains."""
    local_part, _, sender_domain = address.rpartition("@")
    sender_domain = plain_host(sender_domain)
    local_tokens = set(re.split(r"[^a-z0-9]+", plain(local_part)))
    facts = BrandFacts(
        sender_name_brands=brands_named(display_name, brands),
        subject_brands=brands_named(subject, brands),
        sender_address_brands=[brand.name for brand in brands if local_tokens & set(brand.keywords)],
        sender_is_brand=[brand.name for brand in brands if any(aligned(sender_domain, d) for d in brand.domains)],
    )
    claimed = dict.fromkeys(facts.sender_name_brands + facts.sender_address_brands)
    facts.impersonated = [name for name in claimed if name not in facts.sender_is_brand]

    seen = set()
    for host, where in hosts:
        key = plain_host(host)
        if not host or key in seen:
            continue
        seen.add(key)
        if lookalike := find_lookalike(host, where, brands, protected):
            facts.lookalikes.append(lookalike)
        if len(facts.lookalikes) >= 10:
            break
    return facts
