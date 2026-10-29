"""Command line.

  phishtriage analyze suspicious.eml [--format text|json|markdown|iocs] [--offline] [--no-scan] [--no-dkim] [--ai]
  phishtriage web [--port 8765]                             (local web interface, http://127.0.0.1:8765)
  phishtriage batch FOLDER... [--out results.csv] [--details results.jsonl] [--lookups] [--scan] [--ai]
  phishtriage cache purge [--older-than-days N] [--facts] | stats   (lookups kept CACHE_RETENTION_DAYS)
  phishtriage evaluate run --split dev                      (M7 rehearsal; the test run needs --confirm-test-run)
  phishtriage rules report [--show RULE-ID] [--misses]      (development sets only)
  phishtriage rules facts                                   (writes docs/FACTS.md)
  phishtriage dataset split-mbox | split ...
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

from phishtriage.analyze import Facts, analyze, facts_to_dict
from phishtriage.config import Settings
from phishtriage.domains import INVISIBLE_CHARACTERS
from phishtriage.parser import EmailTooLarge
from phishtriage.rules import Verdict, evaluate, load_rules
from phishtriage.rules.engine import MITRE_TECHNIQUES


def safe(text: str) -> str:
    """Show control and invisible characters as escapes.

    Email text is attacker-controlled: printed raw, an ESC character could
    rewrite the analyst's terminal, and zero-width characters would stay hidden.
    """
    return "".join(char if char.isprintable() and ord(char) not in INVISIBLE_CHARACTERS else f"\\u{ord(char):04x}"
                   for char in str(text))


def _yes(flag: bool, label: str) -> str:
    return f" [{label}]" if flag else ""


def render_text(facts: Facts) -> str:
    h, a, s = facts.headers, facts.auth, facts.headers.sender
    lines = [f"NOTE         {safe(note)}" for note in facts.notes]
    lines += [
        f"Subject      {safe(facts.email.subject)}",
        f"From         {safe(s.display_name)} <{safe(s.address)}>"
        + _yes(s.is_freemail, "free mail")
        + _yes(not s.domain_is_valid, "invalid domain")
        + _yes(s.address_count > 1, f"{s.address_count} addresses")
        + _yes(s.display_name_address_differs, f"name shows {safe(s.display_name_address)}"),
    ]
    if s.suspicious_characters:
        lines.append(f"             lookalike characters: {'; '.join(s.suspicious_characters)}")
    if h.reply_to_domains:
        lines.append(f"Reply-To     {', '.join(map(safe, h.reply_to_domains))}{_yes(h.reply_to_differs, 'other organization')}")
    lines.append(f"Return-Path  {safe(h.return_path_domain) or '-'}{_yes(h.return_path_differs, 'other organization')}")

    trust = {"configured": "your configured server", "top-most-header": "top-most header (assumed yours)",
             "untrusted-only": "NO header from your servers", "missing": "no Authentication-Results header"}[a.trust]
    lines += [
        f"Auth source  {trust}{f' ({safe(a.authserv_id)})' if a.authserv_id else ''}"
        + (f", ignored {a.ignored_headers} other header(s)" if a.ignored_headers else ""),
        f"SPF          {a.spf}{f' for {safe(a.spf_domain)}' if a.spf_domain else ''}{_yes(a.spf_aligned, 'aligned with From')}",
        f"DKIM         {', '.join(f'{r} ({safe(d)})' if d else r for r, d in a.dkim) or 'missing'}{_yes(a.dkim_aligned, 'aligned with From')}",
        f"DMARC        {a.dmarc}{f' action={safe(a.dmarc_action)}' if a.dmarc_action else ''}",
    ]
    if a.compauth:
        lines.append(f"compauth     {a.compauth} (reason {safe(a.compauth_reason)})")
    if facts.dkim_recheck_enabled:
        for check in facts.dkim_recheck or []:
            lines.append(f"DKIM recheck {safe(check.domain)} s={safe(check.selector)}: {check.status}, {safe(check.reason)}")
        if not facts.dkim_recheck:
            lines.append("DKIM recheck no signatures")
    lines.append(f"Routing      {h.received_hops} hops, sender IP {safe(a.sender_ip) or 'unknown'}")
    if h.date_missing:
        lines.append("Date         missing")
    elif h.date_skew_hours is not None and abs(h.date_skew_hours) >= 1:
        lines.append(f"Date         {h.date_skew_hours:+.1f} h between the Date header and arrival")
    recipients = "hidden (Bcc only)" if h.recipients_hidden else f"{h.to_count} To, {h.cc_count} Cc"
    lines.append(f"Recipients   {recipients}")
    if h.exchange_auth_as:
        origin = ("inside your organization" if h.internal else
                  "SPOOFED: uses your domain but came from the internet" if h.own_domain_from_outside else
                  f"from outside ({safe(h.exchange_auth_as)})")
        lines.append(f"Origin       {origin} (Microsoft 365)")
    if facts.forwarding.reply_prefix_without_thread:
        lines.append("Thread       subject starts with RE: but answers no earlier email (fake reply)")
    lines += _render_brands(facts)
    lines += _render_text_signals(facts)
    lines += _render_indicators(facts)
    if facts.email.attached_emails:
        lines.append(f"Attached     {facts.email.attached_emails} email(s) inside this email")
    if facts.email.parse_defects:
        lines.append(f"MIME defects {', '.join(facts.email.parse_defects)}")
    if facts.enrichment is not None:
        lines += _render_enrichment(facts.enrichment)
    return "\n".join(lines)


def _render_brands(facts: Facts) -> list[str]:
    b = facts.brands
    lines = []
    if b.impersonated:
        lines.append(f"Brand        claims to be {', '.join(map(safe, b.impersonated))}, but sends from "
                     f"{safe(facts.headers.sender.domain) or 'an unknown domain'}")
    elif b.subject_brands and not b.sender_is_brand:
        lines.append(f"Brand        subject names {', '.join(map(safe, b.subject_brands))}")
    for item in b.lookalikes:
        lines.append(f"Lookalike    {item.where}: {safe(item.domain)} imitates {safe(item.imitates)} "
                     f"({safe(item.brand)}, {item.method})")
    return lines


_SIGNAL_LABELS = {
    "credential_request": "asks for credentials", "urgency": "urgency or threat", "payment": "payment",
    "bank_details_change": "bank details change", "gift_cards": "gift cards", "secrecy": "secrecy / are you available",
    "prize": "prize", "delivery": "delivery problem", "callback": "asks you to call", "crypto": "crypto",
    "qr_prompt": "QR code prompt", "open_attachment": "open the attachment",
}


def _render_text_signals(facts: Facts) -> list[str]:
    t = facts.text
    lines = [f"Text         {t.language}, {t.words} words, {t.images} image(s)" + _yes(t.mostly_images, "mostly images")]
    for name, label in _SIGNAL_LABELS.items():
        if phrases := getattr(t, name):
            lines.append(f"  {label:<26} {'; '.join(safe(p) for p in phrases)}")
    if t.injection_phrases:
        lines.append(f"  {'instructions to an AI':<26} {'; '.join(map(safe, t.injection_phrases))}")
    if t.hidden_words:
        lines.append(f"Hidden text  {t.hidden_words} words via {', '.join(t.hidden_techniques)}: \"{safe(t.hidden_sample[:80])}\"")
        if t.hidden_injection_phrases:
            lines.append(f"  {'hidden instructions to AI':<26} {'; '.join(map(safe, t.hidden_injection_phrases))}")
    if t.invisible_characters:
        lines.append(f"Invisible    {t.invisible_characters} zero-width or invisible characters in the text")
    return lines


def _link_flags(link) -> str:
    flags = [
        (link.text_shows_other_domain, f"text shows {safe(link.text_shows_other_domain)}"),
        (link.has_userinfo, "real host hidden after @"),
        (link.host_is_ip, "IP address"),
        (link.is_shortener, "shortener"),
        (link.on_free_hosting, "free hosting"),
        (link.nonstandard_port, "unusual port"),
        (bool(link.suspicious_characters), "lookalike characters"),
    ]
    return "".join(f" [{label}]" for flag, label in flags if flag)


def _render_indicators(facts: Facts) -> list[str]:
    ind = facts.indicators
    web = ind.web_links
    lines = [f"Links        {len(web)} web link(s) to {len(ind.link_domains)} organization(s)"
             + (" (list truncated)" if ind.links_truncated else "")]
    flagged = [link for link in web if _link_flags(link) and link.source != "html:img"]
    for link in flagged[:10]:
        lines.append(f"  {link.source:<14} {safe(link.url[:100])}{_link_flags(link)}")
    for link in [link for link in ind.links if link.scheme not in ("http", "https")][:5]:
        lines.append(f"  {link.scheme + ' link':<14} {safe(link.url[:100])}")
    for qr in ind.qr_codes:
        lines.append(f"QR code      {safe(qr.source)}: {safe(qr.text[:100])}")
    if ind.phone_numbers:
        lines.append(f"Phone        {', '.join(map(safe, ind.phone_numbers))}")
    for item in ind.attachments:
        flags = [
            (item.extension_mismatch, f"really {item.detected_type}"), (item.double_extension, "double extension"),
            (item.encrypted_archive, "password-protected"), (item.has_macros, "macros"),
            (item.html_login_form, "asks for a password"), (bool(item.archive_risky_members), "risky files inside"),
            (item.pdf_encrypted, "encrypted PDF"), (bool(item.name_suspicious_characters), "lookalike characters in name"),
        ]
        lines.append(f"Attachment   {safe(item.filename) or '(no name)'}  {item.category} ({item.detected_type})  "
                     f"{item.size} B  sha256 {item.sha256[:16]}..." + "".join(f" [{label}]" for flag, label in flags if flag))
        for trick in item.html_script_tricks:
            lines.append(f"             script: {trick}")
        if item.config_profile_payloads:
            lines.append(f"             profile would install: {', '.join(map(safe, item.config_profile_payloads))}")
        for member in item.archive_risky_members[:5]:
            lines.append(f"             inside: {safe(member)}")
    return lines


_SERVICE_NAMES = {"virustotal": "VirusTotal", "urlscan": "urlscan.io", "abuseipdb": "AbuseIPDB", "rdap": "RDAP"}


def _render_enrichment(enrichment) -> list[str]:
    lines = ["Reputation"]
    for r in enrichment.results:
        target = safe(r.target if len(r.target) <= 70 else r.target[:67] + "...")
        if r.status != "ok":
            summary = f"{r.status}: {safe(r.detail)}"
        elif r.service == "virustotal":
            summary = f"{r.malicious}/{r.engines} engines malicious" + (f", {r.suspicious} suspicious" if r.suspicious else "")
            summary += f" ({', '.join(map(safe, r.labels))})" if r.labels else ""
        elif r.service == "urlscan":
            summary = f"{r.verdict}, score {r.score}" + (f", {', '.join(map(safe, r.labels))}" if r.labels else "")
            if r.extra.get("final_url") and r.extra["final_url"] != r.target:
                summary += f"; ends at {safe(r.extra['final_url'][:80])}"
        elif r.service == "abuseipdb":
            summary = f"{r.score}% abuse confidence, {r.extra.get('reports', 0)} reports, {safe(r.extra.get('country', ''))}"
            summary += f", {', '.join(map(safe, r.labels))}" if r.labels else ""
        else:
            age = r.extra.get("age_days")
            summary = f"registered {r.extra.get('registered') or 'unknown'}" + (f" ({age} days ago)" if age is not None else "")
            summary += f" via {safe(r.extra['registrar'])}" if r.extra.get("registrar") else ""
            summary += f" [{', '.join(r.labels)}]" if r.labels else ""
        lines.append(f"  {_SERVICE_NAMES.get(r.service, r.service):<11} {r.kind:<6} {target}  {summary}"
                     + (" (cached)" if r.cached else ""))
        if r.link and r.status in ("ok", "pending"):
            lines.append(f"  {'':<11} {'':<6} {r.link}")
    for note in enrichment.notes:
        lines.append(f"  note: {note}")
    return lines


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(prog="phishtriage", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    analyze_cmd = commands.add_parser("analyze", help="analyze one .eml file")
    analyze_cmd.add_argument("file", type=Path)
    analyze_cmd.add_argument("--json", action="store_true", help="print machine-readable JSON (same as --format json)")
    analyze_cmd.add_argument("--format", choices=["text", "json", "markdown", "iocs"], default="text",
                             help="markdown: a note for a ticket; iocs: indicators as CSV")
    analyze_cmd.add_argument("--no-dkim", action="store_true", help="skip the DKIM re-check (no DNS lookups)")
    analyze_cmd.add_argument("--offline", action="store_true", help="no network at all: no reputation lookups, no DKIM re-check")
    analyze_cmd.add_argument("--no-scan", action="store_true", help="look links up but do not have urlscan.io visit them")
    analyze_cmd.add_argument("--ai", action="store_true", help="add a summary written by the local AI (Ollama)")

    web_cmd = commands.add_parser("web", help="start the local web interface (127.0.0.1 only)")
    web_cmd.add_argument("--port", type=int, default=8765)

    batch_cmd = commands.add_parser("batch", help="triage many .eml files (offline unless --lookups)")
    batch_cmd.add_argument("paths", type=Path, nargs="+", help=".eml files or folders")
    batch_cmd.add_argument("--out", type=Path, help="CSV of verdicts (default: printed)")
    batch_cmd.add_argument("--details", type=Path, help="JSON lines with every fact: keep it private, it holds email content")
    batch_cmd.add_argument("--lookups", action="store_true", help="reputation lookups (indicators leave the computer)")
    batch_cmd.add_argument("--scan", action="store_true", help="also urlscan.io private scans (needs --lookups)")
    batch_cmd.add_argument("--ai", action="store_true", help="add the local AI summary to the details")
    batch_cmd.add_argument("--timeout", type=float, default=None, help="seconds per email (default ANALYSIS_TIMEOUT, 60)")

    cache_cmd = commands.add_parser("cache", help="the lookup cache")
    cache_tasks = cache_cmd.add_subparsers(dest="task", required=True)
    purge_cmd = cache_tasks.add_parser("purge", help="delete old lookup results")
    purge_cmd.add_argument("--older-than-days", type=float, default=None,
                           help="default CACHE_RETENTION_DAYS (30); 0 deletes everything")
    purge_cmd.add_argument("--facts", action="store_true",
                           help="also delete cached email facts of older code versions (.cache/facts)")
    purge_cmd.add_argument("--all-facts", action="store_true", help="delete every cached email fact (rebuilt on demand)")
    cache_tasks.add_parser("stats", help="how many results are cached, and how old")

    evaluate_cmd = commands.add_parser("evaluate", help="M7: the one run on the held-out test sets (EVALUATION.md)")
    evaluate_tasks = evaluate_cmd.add_subparsers(dest="task", required=True)
    run_cmd = evaluate_tasks.add_parser("run", help="measure a split; refuses the test split unless every check passes")
    run_cmd.add_argument("--split", choices=["dev", "test"], required=True)
    run_cmd.add_argument("--confirm-test-run", action="store_true", help="the test sets are run once: say so")
    run_cmd.add_argument("--addendum", default="", help="a later rule version: marked as tuned after the test run")
    run_cmd.add_argument("--snapshot", type=Path, default=None, help="add lookups replayed from this frozen snapshot")
    run_cmd.add_argument("--output", type=Path, default=None)
    snapshot_cmd = evaluate_tasks.add_parser("snapshot", help="record the frozen lookup snapshot for the M7 subset")
    snapshot_cmd.add_argument("--split", choices=["dev", "test"], required=True)
    snapshot_cmd.add_argument("--confirm-test-run", action="store_true")
    snapshot_cmd.add_argument("--limit", type=int, default=None, help="first N subset emails only (rehearsal)")
    snapshot_cmd.add_argument("--path", type=Path, default=None, help="default: phishing-samples/m7_lookup_snapshot.sqlite")

    dataset_cmd = commands.add_parser("dataset", help="prepare evaluation datasets")
    dataset_tasks = dataset_cmd.add_subparsers(dest="task", required=True)
    mbox_cmd = dataset_tasks.add_parser("split-mbox", help="write each message of an .mbox export as an .eml file")
    mbox_cmd.add_argument("mbox", type=Path)
    mbox_cmd.add_argument("out_dir", type=Path)
    mbox_cmd.add_argument("--prefix", default="gmail")
    split_cmd = dataset_tasks.add_parser("split", help="split phishing and legitimate samples into dev and test sets")
    split_cmd.add_argument("--root", type=Path, required=True, help="the phishing-samples folder")
    split_cmd.add_argument("--test-newest", type=int, default=200, help="newest phishing samples held out for testing")
    split_cmd.add_argument("--phishing-manifest", type=Path, required=True)
    split_cmd.add_argument("--legit-manifest", type=Path, help="kept outside the repository: it lists personal emails")

    rules_cmd = commands.add_parser("rules", help="tune and document the scoring rules")
    rules_tasks = rules_cmd.add_subparsers(dest="task", required=True)
    report_cmd = rules_tasks.add_parser("report", help="how each rule behaves on the development sets")
    report_cmd.add_argument("--show", metavar="RULE-ID", help="list the emails this rule fires on")
    report_cmd.add_argument("--misses", action="store_true", help="list missed phishing and false alarms")
    report_cmd.add_argument("--rules", default=None, help="a different rules module or .py file")
    facts_cmd = rules_tasks.add_parser("facts", help="write docs/FACTS.md, the list of facts rules can use")
    facts_cmd.add_argument("--output", type=Path, default=None)

    ai_cmd = commands.add_parser("ai", help="the local AI summary")
    ai_tasks = ai_cmd.add_subparsers(dest="task", required=True)
    injection_cmd = ai_tasks.add_parser("injection-test", help="run the prompt-injection test emails (needs Ollama)")
    injection_cmd.add_argument("--output", type=Path, default=None)
    injection_cmd.add_argument("--no-naive", action="store_true", help="skip the naive-design comparison")
    injection_cmd.add_argument("--cases", default=None, help="only these test emails, e.g. 20-25")
    args = parser.parse_args(argv)
    if args.command == "web":
        from phishtriage.web.server import serve

        return serve(Settings.load(), args.port)
    if args.command == "batch":
        from phishtriage import batch
        from phishtriage.pipeline import Options

        options = Options(lookups=args.lookups, scan=args.lookups and args.scan, ai=args.ai)
        return batch.main(args.paths, Settings.load(), options, args.out, args.details, args.timeout)
    if args.command == "cache":
        return _cache(args)
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "dataset":
        return _dataset(args)
    if args.command == "rules":
        return _rules(args)
    if args.command == "ai":
        from phishtriage.ai import injection_eval
        from phishtriage.config import PROJECT_ROOT

        cases = tuple(int(x) for x in args.cases.split("-")) if args.cases else None
        if cases and len(cases) == 1:
            cases = (cases[0], cases[0])
        return injection_eval.main(args.output or PROJECT_ROOT / "docs" / "INJECTION_RESULTS.md",
                                   naive=not args.no_naive, cases=cases)

    settings = Settings.load()
    if args.no_dkim or args.offline:
        settings = replace(settings, dkim_recheck=False)
    enricher = None
    if not args.offline:
        from phishtriage.enrich import Enricher
        enricher = Enricher(settings, scan_urls=not args.no_scan)
    try:
        facts = analyze(args.file.read_bytes(), settings, enricher=enricher)
    except (OSError, EmailTooLarge) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    verdict = evaluate(facts, load_rules())  # decided before any AI runs
    summary = None
    if args.ai:
        from phishtriage.ai.client import OllamaClient
        from phishtriage.ai.summary import summarize
        summary = summarize(facts, verdict, OllamaClient(settings))
    output_format = "json" if args.json else args.format
    if output_format in ("markdown", "iocs"):
        from phishtriage import exports
        from phishtriage.pipeline import Options, Report

        raw = args.file.read_bytes()
        report = Report(args.file.name, hashlib.sha256(raw).hexdigest(), len(raw),
                        Options(lookups=not args.offline, scan=not args.offline and not args.no_scan, ai=args.ai),
                        facts=facts, verdict=verdict, summary=summary)
        print(exports.report_markdown(report) if output_format == "markdown" else exports.iocs_csv(report), end="")
    elif output_format == "json":
        output = {"verdict": {**asdict(verdict), "label": verdict.label, "coverage": verdict.coverage},
                  "facts": facts_to_dict(facts)}
        if summary:
            output["summary"] = {key: value for key, value in asdict(summary).items() if key != "raw_output"}
        print(json.dumps(output, indent=2))
    else:
        blocks = [render_verdict(verdict)] + ([render_summary(summary)] if summary else []) + [render_text(facts)]
        print("\n\n".join(blocks))
    return 0


def render_summary(summary) -> str:
    if summary.source == "ai":
        lines = [f"AI SUMMARY   written by {summary.model}, checked by code; it cannot change the verdict"]
    else:
        lines = ["SUMMARY      built from the rule findings (no AI text shown)"]
    lines.append(f"  {safe(summary.summary)}")
    if summary.key_points:
        lines.append("  Look at first (from the rules):")
        lines += [f"  - {safe(point)}" for point in summary.key_points]
    if summary.coverage:
        lines.append(f"  {safe(summary.coverage)}")
    lines += [f"  check: {safe(problem)}" for problem in summary.problems]
    return "\n".join(lines)


def render_verdict(verdict: Verdict) -> str:
    head = verdict.verdict.upper()
    if verdict.weak_signs:  # "LOW RISK (1 weak sign below the Suspicious threshold)", not "NO INDICATORS FOUND"
        head = "LOW RISK " + verdict.label.split(" ", 2)[2]
    lines = [f"VERDICT      {head}  ({'; '.join(verdict.reasons)})"]
    for finding in verdict.findings:
        techniques = f"  [{', '.join(finding.mitre)}]" if finding.mitre else ""
        lines.append(f"  {finding.points:>+4}  {finding.id:<12} {safe(finding.evidence)}{techniques}")
    for item in verdict.not_checked:
        lines.append(f"Not checked  {safe(item)}")
    for item in verdict.errors:
        lines.append(f"RULE ERROR   {safe(item)}")
    if verdict.mitre:
        lines.append("MITRE        " + "; ".join(f"{t} {MITRE_TECHNIQUES.get(t, '')}".strip() for t in verdict.mitre))
    for number, action in enumerate(verdict.actions, 1):
        lines.append(f"{'Actions' if number == 1 else '':<12} {number}. {action}")
    return "\n".join(lines)


def _evaluate(args) -> int:
    from phishtriage import evaluation

    try:
        if args.task == "run":
            details = evaluation.run(args.split, confirm=args.confirm_test_run, addendum=args.addendum,
                                     output=args.output, snapshot=args.snapshot)
            m = details["metrics"]
            print(f"{args.split}: phishing caught {m['caught']} of {m['phishing']}, legitimate Malicious "
                  f"{m['legit_malicious']} of {m['legit']}, flagged {m['legit_flagged']} of {m['legit']}")
            return 0
        counts = evaluation.snapshot_main(args.split, confirm=args.confirm_test_run, limit=args.limit, path=args.path)
        print("lookup statuses:", counts)
        return 0
    except evaluation.RefusedToRun as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2


def _cache(args) -> int:
    from datetime import datetime

    from phishtriage.enrich.cache import Cache

    settings = Settings.load()
    if args.task == "purge" and (args.facts or args.all_facts):
        from phishtriage.rules.report import purge_facts

        folders, files = purge_facts(all_versions=args.all_facts)
        print(f"deleted {files} cached email fact file(s) in {folders} folder(s)"
              + ("" if args.all_facts else " of older code versions"))
    if not Path(settings.cache_path).exists():
        print(f"no lookup cache yet ({settings.cache_path})")
        return 0
    cache = Cache(settings.cache_path)
    try:
        if args.task == "purge":
            days = settings.cache_retention_days if args.older_than_days is None else args.older_than_days
            print(f"deleted {cache.purge(days * 86400)} lookup result(s) older than {days:g} day(s)")
        else:
            stats = cache.stats()
            for service, (count, oldest, newest) in sorted(stats.items()):
                print(f"{service:<11} {count:>5} result(s), {datetime.fromtimestamp(oldest):%Y-%m-%d} to "
                      f"{datetime.fromtimestamp(newest):%Y-%m-%d}")
            print(f"{sum(item[0] for item in stats.values())} in total; kept {settings.cache_retention_days} days")
    finally:
        cache.close()
    return 0


def _rules(args) -> int:
    if args.task == "facts":
        from phishtriage.config import PROJECT_ROOT
        from phishtriage.factsdoc import facts_markdown

        output = args.output or PROJECT_ROOT / "docs" / "FACTS.md"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(facts_markdown(), encoding="utf-8", newline="\n")
        print(f"wrote {output}")
        return 0
    from phishtriage.rules import report

    rules = load_rules(args.rules) if args.rules else load_rules()
    print(report.render(report.run(rules), rules, show=args.show, misses=args.misses))
    return 0


def _dataset(args) -> int:
    from phishtriage import dataset
    from phishtriage.domains import org_domain

    if args.task == "split-mbox":
        print(f"wrote {dataset.split_mbox(args.mbox, args.out_dir, args.prefix)} .eml files to {args.out_dir}")
        return 0
    phishing = dataset.split_phishing(args.root, test_newest=args.test_newest)
    dataset.write_manifest(phishing, args.phishing_manifest)
    entries = list(phishing)
    sources = {name: folder for name, folder in dataset.legit_sources(args.root).items()
               if any((args.root / folder).glob("*.eml"))}
    if sources and args.legit_manifest:
        protected = frozenset(org_domain(domain) for domain in Settings.load().protected_domains)
        legit = dataset.split_legit(args.root, sources, protected=protected)
        dataset.write_manifest(legit, args.legit_manifest)
        entries += legit
    elif sources:
        print("legitimate emails found but no --legit-manifest given: they were not split", file=sys.stderr)
    print(dataset.summary(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
