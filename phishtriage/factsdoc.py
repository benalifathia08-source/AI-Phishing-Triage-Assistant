"""Generate docs/FACTS.md: every fact a rule can read, with its type and meaning.

Built from the dataclasses themselves (field names, types and the comments next to them),
so the documentation cannot drift away from the code.
"""
from __future__ import annotations

import dataclasses
import inspect
import re
import typing

from phishtriage.analyze import Facts
from phishtriage.enrich import EnrichmentFacts

_FIELD = re.compile(r"^\s{4}(\w+)\s*:\s*([^=#]+?)\s*(?:=[^#]*)?(?:#\s*(.*))?$")
_COMMENT = re.compile(r"^\s{4}#\s?(.*)$")
_SECTIONS = {
    "email": "The email itself", "headers": "Sender, reply path, routing, dates, internal mail",
    "auth": "Authentication results (SPF, DKIM, DMARC) from your own mail server",
    "dkim_recheck": "DKIM signatures re-checked by the tool", "indicators": "Links, attachments, QR codes, phone numbers",
    "text": "What the email says, and hidden text", "brands": "Brand claims and lookalike domains",
    "forwarding": "Reported and forwarded emails", "notes": "Notes for the analyst",
    "enrichment": "Reputation lookups (only when lookups ran; use the helpers in phishtriage/rules/helpers.py)",
}


def _descriptions(cls) -> dict[str, str]:
    """Field name -> the comment written next to it (or on the lines just above it)."""
    descriptions, pending = {}, []
    for line in inspect.getsource(cls).splitlines()[1:]:
        if comment := _COMMENT.match(line):
            pending.append(comment.group(1))
        elif field := _FIELD.match(line):
            descriptions[field.group(1)] = " ".join(pending + [field.group(3) or ""]).strip()
            pending = []
        else:
            pending = []
    return descriptions


def _inner_dataclass(hint):
    if dataclasses.is_dataclass(hint):
        return hint
    for argument in typing.get_args(hint):
        if dataclasses.is_dataclass(argument):
            return argument
    return None


def _type_name(hint) -> str:
    if dataclasses.is_dataclass(hint):
        return hint.__name__
    text = str(hint).replace("typing.", "")
    return re.sub(r"[\w.]+\.(\w+)", r"\1", text).replace("<class '", "").replace("'>", "")


def _walk(cls, path: str, rows: list, depth: int = 0) -> None:
    hints = typing.get_type_hints(cls)
    descriptions = _descriptions(cls)
    for field in dataclasses.fields(cls):
        hint = hints.get(field.name)
        name = f"{path}.{field.name}"
        inner = _inner_dataclass(hint)
        listed = typing.get_origin(hint) is list
        if field.name == "enrichment" and cls is Facts:
            inner, hint = EnrichmentFacts, EnrichmentFacts
        meaning = descriptions.get(field.name, "") or ("group of facts: see the rows below" if inner else "")
        rows.append((name, _type_name(hint), meaning))
        if inner and depth < 4:
            _walk(inner, name + ("[i]" if listed else ""), rows, depth + 1)
    for attribute, value in inspect.getmembers(cls, lambda member: isinstance(member, property)):
        summary = (inspect.getdoc(value) or "").split("\n")[0]
        rows.append((f"{path}.{attribute}", "property", summary))


def facts_markdown() -> str:
    rows: list[tuple[str, str, str]] = []
    _walk(Facts, "f", rows)
    lines = [
        "# Facts available to rules",
        "",
        "Generated from the code by `phishtriage rules facts`; do not edit by hand.",
        "A rule receives `f` and can read any of these. `[i]` means a list: loop over it, or use the helpers",
        "in `phishtriage/rules/helpers.py`. Facts marked as receiver-specific in `EVALUATION.md` "
        "(`compauth`, `exchange_auth_as`, `authserv_id`) must not be used by rules.",
    ]
    section = None
    for name, type_name, meaning in rows:
        top = name.split(".")[1].split("[")[0]
        if top != section:
            section = top
            lines += ["", f"## `f.{top}`: {_SECTIONS.get(top, top)}", "", "| Fact | Type | Meaning |", "|---|---|---|"]
        lines.append(f"| `{name}` | {type_name.replace('|', 'or')} | {meaning.replace('|', '/')} |")
    return "\n".join(lines) + "\n"
