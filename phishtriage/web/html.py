"""HTML building where escaping is the default.

Every value is escaped unless this module built it (Markup), so forgetting to escape is not possible by
accident. Hidden characters (zero-width, bidi overrides) are shown as visible markers. Link attributes
accept internal paths only, so a URL from an email can never become a clickable link, even by mistake.
"""
from __future__ import annotations

import html
import re

from phishtriage.display import visible, visible_parts

# One leading slash only: "//evil.example/x" is a link to another site (protocol-relative), caught by a test
_INTERNAL_PATH = re.compile(r"^/(?!/)[A-Za-z0-9/_.\-]*$")
_URL_ATTRIBUTES = {"href", "src", "action", "formaction", "poster", "data"}
_VOID = {"br", "hr", "input", "meta", "link", "col"}
_TAG = re.compile(r"^[a-z][a-z0-9]*$")


class Markup(str):
    """HTML built by this module. Anything else is text, and is escaped.

    Adding plain text to Markup escapes the text: Markup("<b>") + "<i>" is "<b>&lt;i&gt;", so joining
    pieces can never smuggle unescaped text in (plain str + str would silently lose the marking)."""
    __slots__ = ()

    def __add__(self, other) -> Markup:
        return Markup(str.__add__(self, esc(other)))

    def __radd__(self, other) -> Markup:
        return Markup(str.__add__(esc(other), self))


def esc(value) -> Markup:
    if isinstance(value, Markup):
        return value
    if value is None:
        return Markup("")
    out = []
    for piece, hidden in visible_parts(str(value)):
        out.append(f'<span class="hidden-char" title="invisible or direction-changing character">{piece}</span>'
                   if hidden else html.escape(piece, quote=True))
    return Markup("".join(out))


def _flatten(children):
    for child in children:
        if isinstance(child, (list, tuple)):
            yield from _flatten(child)
        elif child is not None:
            yield child


def el(tag: str, *children, **attrs) -> Markup:
    """<tag attr="...">children</tag>. Use class_="x" for class, and data_x for data-x."""
    if not _TAG.match(tag):
        raise ValueError(f"bad tag {tag!r}")
    parts = [f"<{tag}"]
    for name, value in attrs.items():
        if value is None or value is False:
            continue
        name = name.rstrip("_").replace("_", "-")
        if name in _URL_ATTRIBUTES and not _INTERNAL_PATH.match(str(value)):
            raise ValueError(f"{name} must be an internal path, not {value!r}")
        parts.append(f" {name}" if value is True else f' {name}="{html.escape(visible(str(value)), quote=True)}"')
    parts.append(">")
    if tag in _VOID:
        return Markup("".join(parts))
    parts.extend(esc(child) for child in _flatten(children))
    parts.append(f"</{tag}>")
    return Markup("".join(parts))


def join(items, separator=", ") -> Markup:
    return Markup(esc(separator).join(esc(item) for item in items))
