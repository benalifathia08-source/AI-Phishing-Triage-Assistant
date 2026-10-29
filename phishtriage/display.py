"""Showing attacker-controlled text safely, in any output: invisible characters made visible, indicators defanged.

Email text is written by the attacker. Shown as it is, a right-to-left override turns "invoice<RLO>fdp.exe"
into "invoiceexe.pdf", zero-width characters hide inside words, and a link can be copied straight into a
browser. Every output of the tool (web page, Markdown, CSV) goes through these two functions.
"""
from __future__ import annotations

import re
import unicodedata

from phishtriage.domains import INVISIBLE_CHARACTERS

_URL = re.compile(r"(?i)\b(?:https?|ftp)://")
# Dots inside host-shaped words only: "login.example.net" and "a@evil.example", not "version 2.5" or "e.g."
_HOST_SHAPED = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62}\b")
# Controls, format characters (zero-width, bidi overrides and isolates), private use, surrogates and line or
# paragraph separators, plus the visible-but-empty fillers listed in INVISIBLE_CHARACTERS
_HIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}


def is_hidden(char: str) -> bool:
    if char in "\n\t":
        return False
    return ord(char) in INVISIBLE_CHARACTERS or unicodedata.category(char) in _HIDDEN_CATEGORIES


def visible_parts(text: str) -> list[tuple[str, bool]]:
    """Split text into (piece, is_hidden_character). A hidden character comes back as its code, e.g. 'U+202E'."""
    parts: list[tuple[str, bool]] = []
    plain = []
    for char in str(text):
        if is_hidden(char):
            if plain:
                parts.append(("".join(plain), False))
                plain = []
            parts.append((f"U+{ord(char):04X}", True))
        else:
            plain.append(char)
    if plain:
        parts.append(("".join(plain), False))
    return parts


def visible(text: str) -> str:
    """Plain-text form: hidden characters written as [U+202E]."""
    return "".join(f"[{piece}]" if hidden else piece for piece, hidden in visible_parts(text))


def defang(text: str) -> str:
    """hxxps://login[.]example[.]net and a@evil[.]example: readable, but not clickable or copyable as a link."""
    text = _URL.sub(lambda m: m.group(0).lower().replace("http", "hxxp").replace("ftp", "fxp"), str(text))
    return _HOST_SHAPED.sub(lambda m: m.group(0).replace(".", "[.]"), text)


def shorten(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"
