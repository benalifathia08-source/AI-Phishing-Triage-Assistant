"""The pages of the local web interface. No JavaScript; every value from the email is escaped by el()."""
from __future__ import annotations

from phishtriage.display import defang, shorten
from phishtriage.pipeline import FAILED
from phishtriage.rules.engine import MALICIOUS, MITRE_TECHNIQUES, NO_INDICATORS, SUSPICIOUS, display_order
from phishtriage.web.html import Markup, el, esc, join

MAX_UPLOAD_MB = 25
_SERVICES = {"virustotal": "VirusTotal", "urlscan": "urlscan.io", "abuseipdb": "AbuseIPDB", "rdap": "RDAP"}
_SIGNALS = {
    "credential_request": "Asks for credentials", "urgency": "Urgency or threat", "payment": "Payment",
    "bank_details_change": "Bank details change", "gift_cards": "Gift cards", "secrecy": "Secrecy, 'are you available'",
    "prize": "Prize", "delivery": "Delivery problem", "callback": "Asks you to call", "crypto": "Crypto",
    "qr_prompt": "Asks to scan a QR code", "open_attachment": "Asks to open the attachment",
}


def layout(title: str, *body, notice: str = "") -> str:
    head = el("head", Markup('<meta charset="utf-8">'),
              Markup('<meta name="viewport" content="width=device-width, initial-scale=1">'),
              Markup('<meta name="referrer" content="same-origin">'),
              el("title", f"{title} · Phishing triage"), el("link", rel="stylesheet", href="/static/style.css"))
    header = el("header", el("a", "Phishing triage", href="/", class_="brand"),
                el("span", "local · 127.0.0.1 · no JavaScript", class_="where"))
    footer = el("footer", el("p", "Served from this computer only. Reports live in memory and disappear when the "
                                  "server stops. " + notice))
    return Markup("<!doctype html>") + el("html", head, el("body", header, el("main", *body), footer), lang="en")


def _token_field(token: str) -> Markup:
    return el("input", type="hidden", name="token", value=token)


def upload_page(token: str, recent: list[tuple[str, object]], ai_available: bool, notice: str = "") -> str:
    form = el("form", _token_field(token),
              el("label", "Suspicious email (.eml, up to 25 MB)", for_="file"),
              el("input", type="file", id="file", name="file", accept=".eml,message/rfc822", required=True),
              el("fieldset",
                 el("legend", "Options (all off: nothing leaves this computer)"),
                 el("label", el("input", type="checkbox", name="lookups", value="1"),
                    " Reputation lookups: send links, domains, file hashes and the sender IP to VirusTotal, AbuseIPDB "
                    "and RDAP. Never the email itself or its attachments."),
                 el("label", el("input", type="checkbox", name="scan", value="1"),
                    " Also have urlscan.io visit up to 2 links (private scans, your address removed from them). "
                    "Needs lookups."),
                 el("label", el("input", type="checkbox", name="ai", value="1", disabled=not ai_available),
                    " Add a summary written by the local AI (Ollama). It cannot change the verdict."
                    + ("" if ai_available else " (Ollama not reachable)"))),
              el("p", "Leave the lookups off for personal or confidential email.", class_="hint"),
              el("button", "Analyze", type="submit"),
              method="post", action="/analyze", enctype="multipart/form-data")
    body = [el("h1", "Analyze a suspicious email"), form]
    if recent:
        rows = [el("tr", el("td", el("a", shorten(report.filename, 60), href=f"/report/{report_id}")),
                   el("td", _badge(report.label)), el("td", report.analyzed_at[:16].replace("T", " ")))
                for report_id, report in recent]
        body += [el("h2", "This session"),
                 el("table", el("thead", el("tr", el("th", "File"), el("th", "Verdict"), el("th", "Analyzed (UTC)"))),
                    el("tbody", rows)),
                 el("form", _token_field(token), el("button", "Forget all reports", type="submit", class_="secondary"),
                    method="post", action="/forget", enctype="multipart/form-data")]
    return layout("Analyze", *body, notice=notice)


def _badge(label: str) -> Markup:
    kind = ("failed" if label == FAILED else "malicious" if label == MALICIOUS else "suspicious" if label == SUSPICIOUS
            else "none" if label == NO_INDICATORS else "low")
    return el("span", label, class_=f"badge v-{kind}")


def _section(title: str, *content, open_: bool = True) -> Markup:
    if open_:
        return el("section", el("h2", title), *content)
    return el("section", el("details", el("summary", title), *content))


def _flags(items) -> Markup:
    return Markup("".join(el("span", label, class_="flag") for flag, label in items if flag))


def _definition_list(rows) -> Markup:
    return el("dl", [Markup(el("dt", key) + el("dd", value)) for key, value in rows if value not in (None, "")])


def report_page(report_id: str, report, token: str) -> str:
    downloads = el("p", el("a", "JSON", href=f"/report/{report_id}/report.json"), " · ",
                   el("a", "Markdown (for a ticket)", href=f"/report/{report_id}/report.md"), " · ",
                   el("a", "IOCs (CSV)", href=f"/report/{report_id}/iocs.csv"), class_="downloads") \
        if not report.failed else Markup("")
    o = report.options
    mode = ", ".join(name for name, on in (("reputation lookups", o.lookups), ("urlscan.io scans", o.lookups and o.scan),
                                           ("local AI summary", o.ai)) if on) or "offline (no lookups)"
    head = el("section", el("p", _badge(report.label), class_="verdict"),
              el("h1", shorten(report.filename, 120)),
              el("p", f"SHA-256 {report.sha256} · {report.size:,} bytes · analyzed "
                      f"{report.analyzed_at[:16].replace('T', ' ')} UTC in {report.seconds:g} s · {mode}", class_="meta"),
              downloads, class_="report-head")
    if report.failed:
        return layout("Analysis failed", head, el("section", el("h2", "The email could not be analyzed"),
                      el("p", report.error),
                      el("p", el("strong", "That is not a sign it is safe."), " An email built to crash or stall a parser "
                              "is itself suspicious. Handle it as Suspicious, and keep the file as evidence."),
                      class_="failed"))
    v, f = report.verdict, report.facts
    body = [head, _verdict_section(v)]
    if report.summary is not None:
        body.append(_summary_section(report.summary))
    body += [_email_section(f), _auth_section(f), _links_section(f), _attachments_section(f), _text_section(f, report)]
    if f.enrichment is not None:
        body.append(_lookups_section(f.enrichment))
    notes = list(f.notes) + (list(f.enrichment.notes) if f.enrichment is not None else [])
    if notes:
        body.append(_section("Notes", el("ul", [el("li", note) for note in notes])))
    if report.preview.get("headers"):
        body.append(_section(f"All headers ({len(report.preview['headers'])})",
                             el("pre", "\n".join(f"{name}: {value}" for name, value in report.preview["headers"])),
                             open_=False))
    return layout(report.label, *body)


def _verdict_section(v) -> Markup:
    rows = [el("tr", el("td", f"{finding.points:+d}",
                        el("div", f"capped (rule +{finding.rule_points})", class_="sub") if finding.capped else None,
                        class_="num"),
               el("td", el("code", finding.id), class_="rule"), el("td", finding.title), el("td", defang(finding.evidence)),
               el("td", ", ".join(finding.mitre))) for finding in display_order(v.findings)]
    table = el("table", el("thead", el("tr", el("th", "Points"), el("th", "Rule"), el("th", "Finding"),
                                       el("th", "Evidence (from the email)"), el("th", "MITRE"))),
               el("tbody", rows), class_="findings") if rows else el("p", "No rule fired.")
    parts = [el("p", "; ".join(reason[0].upper() + reason[1:] for reason in v.reasons) + ".", class_="meta")]
    if v.weak_signs:
        parts.append(el("p", "Below the Suspicious threshold, but not clean: the weak signs are listed below. "
                             "\"No indicators found\" never means the email is safe.", class_="hint"))
    if v.actions:
        parts += [el("h3", "What to do"), el("ol", [el("li", action) for action in v.actions])]
    parts += [el("h3", "Findings"), table]
    if any(finding.capped for finding in v.findings):
        parts.append(el("p", "Capped: related signs, such as several authentication failures, count only up to a "
                             "limit per category, so that one weak area cannot decide the verdict alone. The finding "
                             "still holds; it just adds fewer points.", class_="hint"))
    parts.append(el("p", v.coverage, class_="coverage"))
    if v.errors:
        parts.append(el("p", f"Rule errors (a bug in the tool, not in the email): {'; '.join(v.errors)}", class_="hint"))
    if v.mitre:
        parts.append(el("p", "MITRE ATT&CK: ", join(f"{t} {MITRE_TECHNIQUES.get(t, '')}".strip() for t in v.mitre),
                        class_="meta"))
    return _section("Verdict", *parts)


def _summary_section(s) -> Markup:
    who = (f"Written by the local AI ({s.model}), checked by code. It cannot change the verdict." if s.source == "ai"
           else "Built from the findings: no AI text is shown.")
    parts = [el("p", who, class_="meta"), el("blockquote", s.summary)]
    if s.problems:
        parts.append(el("ul", [el("li", f"Check: {problem}") for problem in s.problems], class_="checks"))
    return _section("Summary", *parts)


def _email_section(f) -> Markup:
    s, h = f.headers.sender, f.headers
    recipients = "hidden (Bcc only)" if h.recipients_hidden else f"{h.to_count} To, {h.cc_count} Cc"
    sender_flags = _flags([(s.is_freemail, "free mail"), (not s.domain_is_valid, "invalid domain"),
                           (s.on_free_hosting, "shared platform"), (s.address_count > 1, f"{s.address_count} addresses"),
                           (s.display_name_address_differs, "name shows another address"),
                           (bool(s.suspicious_characters), "lookalike characters")])
    rows = [("Subject", f.email.subject),
            ("From", Markup(esc(s.display_name) + " " + el("code", defang(s.address)) + " " + sender_flags)),
            ("Name shows", defang(s.display_name_address) if s.display_name_address else ""),
            ("Reply-To", Markup(join(defang(d) for d in h.reply_to_domains) + " "
                                + _flags([(h.reply_to_differs, "other organization")])) if h.reply_to_domains else ""),
            ("Return-Path", Markup(esc(defang(h.return_path_domain)) + " "
                                   + _flags([(h.return_path_differs, "other organization")])) if h.return_path_domain else ""),
            ("Date", f.email.date or "missing"),
            ("Message-ID", defang(f.email.message_id)),
            ("Recipients", recipients),
            ("Route", f"{h.received_hops} servers, sending IP {f.auth.sender_ip or 'unknown'}")]
    if f.brands.impersonated:
        rows.append(("Brand", f"claims to be {', '.join(f.brands.impersonated)}, but sends from "
                              f"{defang(s.domain) or 'an unknown domain'}"))
    for item in f.brands.lookalikes:
        rows.append(("Lookalike", f"{item.where}: {defang(item.domain)} imitates {defang(item.imitates)} "
                                  f"({item.brand}, {item.method})"))
    if f.forwarding.reply_prefix_without_thread:
        rows.append(("Thread", "the subject starts with RE: but answers no earlier email"))
    if f.email.parse_defects:
        rows.append(("MIME defects", "; ".join(f.email.parse_defects)))
    return _section("Email", _definition_list(rows))


def _auth_section(f) -> Markup:
    a = f.auth
    trust = {"configured": "your configured server", "top-most-header": "the top-most header, assumed yours",
             "untrusted-only": "no header from your servers", "missing": "no Authentication-Results header"}[a.trust]
    rows = [("Read from", trust + (f" ({a.authserv_id})" if a.authserv_id else "")
             + (f"; {a.ignored_headers} other header(s) ignored" if a.ignored_headers else "")),
            ("SPF", Markup(esc(a.spf + (f" for {defang(a.spf_domain)}" if a.spf_domain else "")) + " "
                           + _flags([(a.spf_aligned, "aligned with From")]))),
            ("DKIM", Markup(join(f"{result} ({defang(domain)})" if domain else result for result, domain in a.dkim)
                            if a.dkim else esc("missing")) + Markup(" ") + _flags([(a.dkim_aligned, "aligned with From")])),
            ("DMARC", a.dmarc + (f", action {a.dmarc_action}" if a.dmarc_action else ""))]
    if a.compauth:
        rows.append(("compauth", f"{a.compauth} (reason {a.compauth_reason})"))
    if f.dkim_recheck_enabled:
        rows.append(("DKIM re-check", "; ".join(f"{defang(c.domain)} s={c.selector}: {c.status}, {c.reason}"
                                                for c in f.dkim_recheck) or "no signatures"))
    return _section("Authentication", _definition_list(rows))


def _warning(link) -> bool:
    """A sign worth showing first; click trackers are normal in newsletters, so they are not one."""
    return bool(link.text_shows_other_domain or link.has_userinfo or link.host_is_ip or link.is_shortener
                or link.on_free_hosting or link.nonstandard_port or link.suspicious_characters
                or link.scheme not in ("http", "https"))


def _link_flags(link) -> Markup:
    return _flags([(link.text_shows_other_domain, "text shows another site"), (link.has_userinfo, "host hidden after @"),
                   (link.host_is_ip, "IP address"), (link.is_shortener, "shortener"),
                   (link.on_free_hosting, "free hosting"), (link.nonstandard_port, "unusual port"),
                   (bool(link.suspicious_characters), "lookalike characters"), (link.click_tracker, "click tracker")])


def _links_table(links) -> Markup:
    rows = [el("tr", el("td", el("code", defang(link.host) or link.scheme)), el("td", el("code", defang(shorten(link.url, 140)))),
               el("td", defang(shorten(link.link_text, 80))), el("td", link.source), el("td", _link_flags(link)))
            for link in links]
    return el("table", el("thead", el("tr", el("th", "Host"), el("th", "Link (defanged, not clickable)"),
                                       el("th", "Text shown"), el("th", "Where"), el("th", "Flags"))),
              el("tbody", rows), class_="links")


def _links_section(f) -> Markup:
    ind = f.indicators
    # One count for one list: the first version said "4 web links" over "All 3 links" (a picture counted once)
    links = [link for link in ind.links if link.source != "html:img"]
    pictures = [link for link in ind.links if link.source == "html:img"]
    organizations = {link.org_domain for link in ind.links if link.org_domain}
    flagged = [link for link in links if _warning(link)]
    summary = (f"{len(links)} link(s)" + (f" and {len(pictures)} picture(s) loaded from the web" if pictures else "")
               + f", to {len(organizations)} organization(s)" + (" (list cut at 300)" if ind.links_truncated else "") + ".")
    parts = [el("p", summary, class_="meta")]
    if flagged:
        parts += [el("h3", "Links with warning signs"), _links_table(flagged)]
    if ind.links:
        title = f"All {len(links)} link(s)" + (f" and {len(pictures)} picture(s)" if pictures else "")
        parts.append(el("details", el("summary", title), _links_table(links + pictures)))
    if ind.qr_codes:
        parts += [el("h3", "QR codes"), el("ul", [el("li", qr.source, ": ", el("code", defang(shorten(qr.text, 200))))
                                                for qr in ind.qr_codes])]
    if ind.phone_numbers:
        parts += [el("h3", "Phone numbers"), el("p", join(ind.phone_numbers))]
    return _section("Links and QR codes", *parts)


def _attachments_section(f) -> Markup:
    items = f.indicators.attachments
    if not items:
        return _section("Attachments", el("p", "None.", class_="meta"))
    rows = []
    for item in items:
        flags = _flags([(item.extension_mismatch, f"really {item.detected_type}"), (item.double_extension, "double extension"),
                        (item.encrypted_archive, "password-protected"), (item.has_macros, "macros"),
                        (item.html_login_form, "asks for a password"), (bool(item.archive_risky_members), "risky files inside"),
                        (item.pdf_encrypted, "encrypted PDF"), (bool(item.name_suspicious_characters), "deceptive characters in name"),
                        (item.inline, "inline")])
        inside = [el("div", "inside: ", el("code", member), class_="sub") for member in item.archive_risky_members[:10]]
        inside += [el("div", "script: ", trick, class_="sub") for trick in item.html_script_tricks]
        inside += [el("div", "profile would install: ", join(item.config_profile_payloads), class_="sub")]  \
            if item.config_profile_payloads else []
        rows.append(el("tr", el("td", el("code", item.filename or "(no name)"), inside),
                       el("td", f"{item.category} ({item.detected_type or 'unknown'}); declared {item.declared_type}"),
                       el("td", f"{item.size:,} B", class_="num"), el("td", el("code", item.sha256), class_="hash"),
                       el("td", flags)))
    table = el("table", el("thead", el("tr", el("th", "Name"), el("th", "Type"), el("th", "Size"), el("th", "SHA-256"),
                                       el("th", "Flags"))), el("tbody", rows), class_="attachments")
    return _section("Attachments", el("p", "Listed, never opened: archives are listed without extracting, and nothing "
                                           "is uploaded anywhere (lookups send the SHA-256 only).", class_="meta"), table)


def _text_section(f, report) -> Markup:
    t = f.text
    rows = [el("tr", el("td", label), el("td", join(getattr(t, name))))
            for name, label in _SIGNALS.items() if getattr(t, name, None)]
    if t.injection_phrases:
        rows.append(el("tr", el("td", "Instructions to an AI"), el("td", join(t.injection_phrases))))
    parts = [el("p", f"Language {t.language}, {t.words} visible words, {t.images} image(s)."
                     + (" Mostly images." if t.mostly_images else ""), class_="meta")]
    if rows:
        parts.append(el("table", el("tbody", rows), class_="signals"))
    if t.hidden_words:
        parts.append(el("p", f"Hidden text: {t.hidden_words} words via {', '.join(t.hidden_techniques)}. Sample: ",
                        el("q", shorten(t.hidden_sample, 200))))
        if t.hidden_injection_phrases:
            parts.append(el("p", "Hidden instructions to an AI: ", join(t.hidden_injection_phrases), class_="warn"))
    if t.invisible_characters:
        parts.append(el("p", f"{t.invisible_characters} invisible characters in the text (shown as markers below)."))
    text = report.preview.get("text", "")
    if text:
        parts.append(el("details", el("summary", "Visible text of the email (plain text, links not clickable)"),
                        el("pre", defang(text) + ("\n[cut]" if report.preview.get("text_truncated") else ""))))
    return _section("Text", *parts)


def _lookup_summary(r) -> str:
    if r.status != "ok":
        return f"{r.status}: {r.detail}"
    if r.service == "virustotal":
        return f"{r.malicious}/{r.engines} engines malicious" + (f", {r.suspicious} suspicious" if r.suspicious else "")
    if r.service == "urlscan":
        final = r.extra.get("final_url")
        return f"{r.verdict}, score {r.score}" + (f"; ends at {defang(shorten(final, 100))}" if final and final != r.target else "")
    if r.service == "abuseipdb":
        return f"{r.score}% abuse confidence, {r.extra.get('reports', 0)} reports"
    age = r.extra.get("age_days")
    return f"registered {r.extra.get('registered') or 'unknown'}" + (f" ({age} days ago)" if age is not None else "")


def _lookups_section(enrichment) -> Markup:
    rows = [el("tr", el("td", _SERVICES.get(r.service, r.service)), el("td", r.kind),
               el("td", el("code", defang(shorten(r.target, 100)))),
               el("td", _lookup_summary(r) + (" (cached)" if r.cached else ""))) for r in enrichment.results]
    return _section("Reputation lookups", el("table", el("thead", el("tr", el("th", "Service"), el("th", "Kind"),
                                                                     el("th", "Indicator"), el("th", "Result"))),
                                             el("tbody", rows)))


def error_page(status: int, message: str) -> str:
    return layout(f"Error {status}", el("h1", f"Error {status}"), el("p", message), el("p", el("a", "Back", href="/")))
