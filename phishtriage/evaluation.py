"""M7: the one evaluation on the held-out test sets (EVALUATION.md), and the checks that make it trustworthy.

    phishtriage evaluate run --split dev                       rehearsal on the development sets, any time
    phishtriage evaluate run --split test --confirm-test-run   THE test run: once, after every check passes
    phishtriage evaluate snapshot --record                     the frozen, dated lookup snapshot (part of M7)

Before the test run reads a single test email, it refuses unless:
  - no tracked file has an uncommitted change, so the result belongs to a commit;
  - scoring.py is the frozen blob and the behaviour fingerprint is rules-v1.1's (EVALUATION.md section 5);
  - every email still has the SHA-256 its manifest recorded: the labelled data has not changed;
  - no earlier test run is recorded in datasets/m7_test_run.json (the test sets are run once), unless
    --addendum names a later version, whose numbers are then marked as tuned after seeing the test set.

Offline numbers are the headline (no lookups, no DKIM re-check: the samples' redaction breaks DKIM). Lookups are
evaluated separately on a subset, replayed from a frozen snapshot that never touches the network.
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, UTC
from importlib import metadata
from pathlib import Path

from phishtriage.config import PROJECT_ROOT, Settings
from phishtriage.dataset import Entry, long_path, read_manifest
from phishtriage.rules import MALICIOUS, NO_INDICATORS, SUSPICIOUS, evaluate, load_rules
from phishtriage.stats import count_with_range, wilson

FROZEN_TAG = "rules-v1.1"
FROZEN_SCORING_BLOB = "992ce24647984321d8e77a1ac12b1d610997eead"
FROZEN_FINGERPRINT = "2ed349b15a66dae8"
LEDGER = PROJECT_ROOT / "datasets" / "m7_test_run.json"
PREVALENCES = (0.10, 0.30, 0.50)
PACKAGES = ("dkimpy", "dnspython", "tldextract", "opencv-python-headless", "pillow", "pypdfium2", "truststore")


# ===== Checks before the run ======================================================================================
def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=PROJECT_ROOT, capture_output=True, text=True,  # noqa: S603, S607
                            encoding="utf-8")  # fixed git commands, never email data
    return result.stdout.strip() if result.returncode == 0 else ""


def scoring_blob() -> str:
    """The git blob ID of scoring.py as it is on disk (what `git hash-object` prints)."""
    path = PROJECT_ROOT / "phishtriage" / "rules" / "scoring.py"
    return git("hash-object", str(path)) or hashlib.sha1(  # noqa: S324 - git's own object ID, not security
        b"blob %d\0" % len(data := path.read_bytes().replace(b"\r\n", b"\n")) + data).hexdigest()


def uncommitted_changes() -> list[str]:
    return [line for line in git("status", "--porcelain", "--untracked-files=no").splitlines() if line.strip()]


def freeze_problems(fingerprint: str) -> list[str]:
    problems = []
    if (blob := scoring_blob()) != FROZEN_SCORING_BLOB:
        problems.append(f"scoring.py is blob {blob}, not the frozen {FROZEN_SCORING_BLOB}")
    if fingerprint != FROZEN_FINGERPRINT:
        problems.append(f"the behaviour fingerprint is {fingerprint}, not {FROZEN_TAG}'s {FROZEN_FINGERPRINT}: "
                        "a decision on the development sets changed")
    return problems


def manifest_problems(entries: list[Entry], root: Path) -> list[str]:
    """Files whose bytes no longer match the SHA-256 recorded when the sets were labelled and split."""
    problems = []
    for entry in entries:
        path = long_path(root / entry.file)
        if not path.exists():
            problems.append(f"{entry.file}: missing")
        elif entry.sha256 and hashlib.sha256(path.read_bytes()).hexdigest() != entry.sha256:
            problems.append(f"{entry.file}: changed since it was labelled")
    return problems


def environment() -> dict:
    import tldextract

    versions = {}
    for name in PACKAGES:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = "not installed"
    return {
        "python": sys.version.split()[0], "platform": platform.platform(), "packages": versions,
        "commit": git("rev-parse", "HEAD"), "tag_at_commit": git("tag", "--points-at", "HEAD"),
        "tldextract_suffix_list": "bundled snapshot of tldextract " + getattr(tldextract, "__version__", "?"),
    }


# ===== Running a split ============================================================================================
@dataclass
class Row:
    file: str
    kind: str  # phishing or legit
    source: str  # phishing_pot, gmail, university
    group: str  # campaign (phishing) or sender (legit)
    verdict: str
    score: int
    findings: str  # "SENDER-002+30 AUTH-001+20 ...": rule IDs and points, never evidence (it can be personal)

    @property
    def caught(self) -> bool:
        return self.verdict != NO_INDICATORS

    def public(self) -> dict:
        """What the results files keep: a legitimate email's group is its sender, a real person's address."""
        return asdict(self) | ({"group": ""} if self.kind == "legit" else {})


def entries_for(split: str, manifests) -> list[Entry]:
    return [entry for manifest in manifests if Path(manifest).exists() for entry in read_manifest(Path(manifest))
            if entry.split == split]


def run_split(entries: list[Entry], root: Path, rules, facts_source, enrichment=None) -> list[Row]:
    """`facts_source(path)` gives the offline facts; `enrichment(entry, facts)` adds replayed lookups."""
    rows = []
    for entry in entries:
        facts = facts_source(root / entry.file)
        if enrichment is not None:
            facts.enrichment = enrichment(entry, facts)
        verdict = evaluate(facts, rules)
        rows.append(Row(entry.file, entry.kind, "phishing_pot" if entry.kind == "phishing" else entry.source,
                        entry.group, verdict.verdict, verdict.score,
                        " ".join(f"{f.id}{f.points:+d}" for f in verdict.findings)))
    return rows


# ===== Metrics ====================================================================================================
def _precision(tpr: float, fpr: float, share: float) -> float | None:
    denominator = tpr * share + fpr * (1 - share)
    return tpr * share / denominator if denominator else None


def metrics(rows: list[Row]) -> dict:
    phishing = [r for r in rows if r.kind == "phishing"]
    legit = [r for r in rows if r.kind == "legit"]
    caught = sum(r.caught for r in phishing)
    flagged = sum(r.caught for r in legit)
    campaigns: dict[str, list[bool]] = defaultdict(list)
    for r in phishing:
        campaigns[r.group].append(r.caught)
    shares = [sum(found) / len(found) for found in campaigns.values()]
    tpr, fpr = (caught / len(phishing) if phishing else 0.0), (flagged / len(legit) if legit else 0.0)
    tpr_low, tpr_high = wilson(caught, len(phishing))
    fpr_low, fpr_high = wilson(flagged, len(legit))
    precision = {f"{share:.0%}": {
        "point": _precision(tpr, fpr, share),
        "low": _precision(tpr_low, fpr_high, share),  # fewest caught, most false alarms the ranges allow
        "high": _precision(tpr_high, fpr_low, share)} for share in PREVALENCES}
    return {
        "phishing": len(phishing), "legit": len(legit),
        "caught": caught, "malicious": sum(r.verdict == MALICIOUS for r in phishing),
        "legit_flagged": flagged, "legit_malicious": sum(r.verdict == MALICIOUS for r in legit),
        "legit_by_source": {source: {"emails": sum(r.source == source for r in legit),
                                     "flagged": sum(r.caught for r in legit if r.source == source),
                                     "malicious": sum(r.verdict == MALICIOUS for r in legit if r.source == source)}
                            for source in sorted({r.source for r in legit})},
        "campaigns": {"groups": len(campaigns), "mean_share_caught": sum(shares) / len(shares) if shares else 0.0,
                      "all_caught": sum(share == 1 for share in shares), "some_caught": sum(0 < s < 1 for s in shares),
                      "none_caught": sum(share == 0 for share in shares)},
        "confusion": {kind: dict(Counter(r.verdict for r in rows if r.kind == kind))
                      for kind in ("phishing", "legit")},
        "precision": precision,
        "targets": {
            "caught_at_least_90%": caught >= math.ceil(0.9 * len(phishing)),
            "no_legit_malicious": sum(r.verdict == MALICIOUS for r in legit) == 0,
            "flagged_at_most_10%": flagged <= round(0.1 * len(legit)),
        },
    }


# ===== Report =====================================================================================================
def _pct(value) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def render(split: str, m: dict, rows: list[Row], env: dict, checks: list[str], lookups: dict | None = None,
           addendum: str = "") -> str:
    title = {"test": "M7 results: the held-out test sets", "dev": "M7 rehearsal on the development sets"}[split]
    lines = [f"# {title}" + (f" (ADDENDUM: {addendum}, tuned after seeing the test set)" if addendum else ""), "",
             f"Run on {datetime.now(UTC):%Y-%m-%d %H:%M} UTC by `phishtriage evaluate run --split {split}`, "
             f"commit `{env['commit'][:12]}`, rules `{FROZEN_TAG}`. Protocol: `EVALUATION.md`.", "",
             f"Checks passed before any {split} email was analyzed:", ""] + [f"- {check}" for check in checks] + [""]
    t = m["targets"]
    yes = lambda ok: "**met**" if ok else "**not met**"  # noqa: E731
    lines += [
        "## Headline (offline: the email alone, no lookups)", "",
        "| Metric | Result | Target |", "|---|---|---|",
        f"| Phishing caught (Suspicious or Malicious) | {count_with_range(m['caught'], m['phishing'])} | "
        f"at least 90%: {yes(t['caught_at_least_90%'])} |",
        f"| Phishing called Malicious | {count_with_range(m['malicious'], m['phishing'])} | reported, no target |",
        f"| Legitimate called Malicious (serious false alarm) | {count_with_range(m['legit_malicious'], m['legit'])} | "
        f"0: {yes(t['no_legit_malicious'])} |",
        f"| Legitimate flagged (any false alarm) | {count_with_range(m['legit_flagged'], m['legit'])} | "
        f"at most 10%: {yes(t['flagged_at_most_10%'])} |", "",
        "False alarms by mailbox: " + "; ".join(f"{source} {v['flagged']} of {v['emails']} flagged, {v['malicious']} "
                                                 f"Malicious" for source, v in m["legit_by_source"].items()) + ".", "",
        "## Per campaign (each campaign group counts once)", "",
        f"{m['campaigns']['groups']} campaign groups. Mean share caught per campaign: "
        f"**{m['campaigns']['mean_share_caught']:.1%}**. All copies caught: {m['campaigns']['all_caught']}; some: "
        f"{m['campaigns']['some_caught']}; none: {m['campaigns']['none_caught']}.", "",
        "## Confusion matrix", "", "| Label | Malicious | Suspicious | No indicators found |", "|---|---|---|---|"]
    for kind in ("phishing", "legit"):
        c = m["confusion"][kind]
        lines.append(f"| {kind} | {c.get(MALICIOUS, 0)} | {c.get(SUSPICIOUS, 0)} | {c.get(NO_INDICATORS, 0)} |")
    lines += ["", "## Precision at assumed shares of phishing in the queue", "",
              "Precision = share of flagged emails that really are phishing. The range combines the 95% ranges of the "
              "detection and false-alarm rates (fewest caught with most false alarms, and the reverse).", "",
              "| Phishing share | Precision | Range |", "|---|---|---|"]
    for share, p in m["precision"].items():
        lines.append(f"| {share} | {_pct(p['point'])} | {_pct(p['low'])} – {_pct(p['high'])} |")
    if lookups:
        lines += ["", "## With reputation lookups (subset, replayed from a frozen snapshot)", "",
                  f"Snapshot recorded {lookups['recorded']}, months after the samples arrived: lookups now know what "
                  "people reported since, so these numbers flatter the tool (hindsight). Personal emails got "
                  "domain-level lookups only. Not the headline.", "",
                  "| Subset | Offline | With lookups |", "|---|---|---|",
                  f"| Phishing caught | {lookups['offline']['caught']} of {lookups['offline']['phishing']} | "
                  f"{lookups['online']['caught']} of {lookups['online']['phishing']} |",
                  f"| Legitimate flagged | {lookups['offline']['legit_flagged']} of {lookups['offline']['legit']} | "
                  f"{lookups['online']['legit_flagged']} of {lookups['online']['legit']} |",
                  f"| Lookups missing from the snapshot (counted as not checked) | | {lookups['missing']} |", "",
                  f"Verdicts the lookups changed ({len(lookups['changed'])}):", ""]
        lines += [f"- {c['file']} ({c['kind']}): {c['offline']} -> {c['with_lookups']} ({c['findings']})"
                  for c in lookups["changed"]] or ["- none"]
    misses = [r for r in rows if r.kind == "phishing" and not r.caught]
    alarms = [r for r in rows if r.kind == "legit" and r.caught]
    lines += ["", f"## Phishing not caught ({len(misses)})", "",
              "Causes: one line each, written after the run in `docs/M7_CAUSES.md`, so this file stays exactly as "
              "generated (its SHA-256 is in the ledger).", "",
              "| File | Score | Findings | Cause |", "|---|---|---|---|"]
    lines += [f"| {Path(r.file).name} | {r.score} | {r.findings or '-'} | |" for r in misses]
    lines += ["", f"## False alarms ({len(alarms)})", "", "| File | Verdict | Score | Findings | Cause |",
              "|---|---|---|---|---|"]
    lines += [f"| {Path(r.file).name} | {r.verdict} | {r.score} | {r.findings or '-'} | |" for r in alarms]
    lines += ["", "## Environment", "", f"Python {env['python']} on {env['platform']}; "
              + ", ".join(f"{name} {version}" for name, version in env["packages"].items())
              + f"; {env['tldextract_suffix_list']}.", "",
              "Limits: `EVALUATION.md` section 6. Injection suite, run at the same commit: "
              "`docs/M7_INJECTION_RESULTS.md`."]
    return "\n".join(lines) + "\n"


# ===== The run ====================================================================================================
class RefusedToRun(Exception):
    pass


def run(split: str, confirm: bool = False, addendum: str = "", root: Path | None = None, manifests=None,
        output: Path | None = None, snapshot: Path | None = None, fingerprint_source=None, facts_source=None,
        ledger: Path = LEDGER) -> dict:
    from phishtriage.rules.report import DEFAULT_MANIFESTS, DEFAULT_ROOT, FactsCache, behaviour_fingerprint, offline_settings
    from phishtriage.rules.report import run as dev_report_run

    root, manifests = root or DEFAULT_ROOT, manifests or DEFAULT_MANIFESTS
    rules = load_rules()
    cache = FactsCache(offline_settings())
    facts_source = facts_source or cache.facts
    checks = []
    entries = entries_for(split, manifests)
    if split == "test":
        if not confirm:
            raise RefusedToRun("the test sets are run once: add --confirm-test-run when everything is ready")
        if ledger.exists() and not addendum:
            raise RefusedToRun(f"a test run is already recorded in {ledger.name}; a later version needs --addendum NAME")
        if changes := uncommitted_changes():
            raise RefusedToRun(f"uncommitted changes to tracked files ({len(changes)}): commit first, so the result "
                               "belongs to a commit")
    fingerprint = (fingerprint_source or (lambda: behaviour_fingerprint(dev_report_run(rules, cache=cache))))()
    if (problems := freeze_problems(fingerprint)) and not addendum:  # before a single test file is read
        raise RefusedToRun("; ".join(problems))
    if problems := manifest_problems(entries, root):
        raise RefusedToRun("; ".join(problems[:5]) + (f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""))
    checks += [f"`scoring.py` is blob `{FROZEN_SCORING_BLOB[:12]}` ({FROZEN_TAG})",
               f"behaviour fingerprint on the development sets is `{FROZEN_FINGERPRINT}`",
               f"all {len(entries)} {split} emails match the SHA-256 in their manifests"]
    if split == "test":
        checks += ["no uncommitted change to tracked files", "no earlier test run recorded" if not addendum
                   else f"addendum `{addendum}`: numbers tuned after seeing the test set"]
    rows = run_split(entries, root, rules, facts_source)
    m = metrics(rows)
    lookups = replay_lookups(snapshot, entries, root, rules, facts_source) if snapshot else None
    env = environment()
    text = render(split, m, rows, env, checks, lookups, addendum)
    output = output or (PROJECT_ROOT / "docs" / ("M7_RESULTS.md" if split == "test" else "M7_REHEARSAL_DEV.md"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8", newline="\n")
    details = {"split": split, "addendum": addendum, "metrics": m, "environment": env, "lookups": lookups,
               # Personal mail is published as counts only, except the false alarms the protocol lists
               "rows": [r.public() for r in rows if r.kind == "phishing" or r.caught]}
    output.with_suffix(".json").write_text(json.dumps(details, indent=1) + "\n", encoding="utf-8", newline="\n")
    if split == "test":
        record = {"date": datetime.now(UTC).isoformat(timespec="seconds"), "commit": env["commit"],
                  "rules": FROZEN_TAG, "fingerprint": fingerprint, "addendum": addendum,
                  "results_sha256": hashlib.sha256(text.encode()).hexdigest(), "output": output.name}
        history = json.loads(ledger.read_text(encoding="utf-8")) if ledger.exists() else []
        ledger.write_text(json.dumps(history + [record], indent=1) + "\n", encoding="utf-8", newline="\n")
    return details


# ===== The frozen lookup snapshot =================================================================================
SNAPSHOT_PHISHING = 40  # one email per campaign group: VirusTotal (4 a minute) and urlscan.io (50 a day) set the size


def lookup_subset(entries: list[Entry], phishing: int = SNAPSHOT_PHISHING) -> list[Entry]:
    """Fixed before any result is seen: one phishing email per campaign group (the first by SHA-256), groups in
    SHA-256 order of their names, up to `phishing`; plus every legitimate email (domain-level lookups only)."""
    by_group: dict[str, list[Entry]] = defaultdict(list)
    for entry in entries:
        if entry.kind == "phishing":
            by_group[entry.group].append(entry)
    order = sorted(by_group, key=lambda name: hashlib.sha256(name.encode()).hexdigest())
    chosen = [min(by_group[name], key=lambda e: e.sha256) for name in order][:phishing]
    return chosen + sorted((entry for entry in entries if entry.kind == "legit"), key=lambda e: e.sha256)


def snapshot_settings(settings: Settings) -> Settings:
    """The same lookup budget when recording and when replaying, whatever .env says: the defaults, with one
    urlscan.io scan per email (40 private scans fit one day of the free quota of 50)."""
    defaults = Settings()
    return replace(settings, virustotal_max_per_email=defaults.virustotal_max_per_email, urlscan_max_per_email=1,
                   abuseipdb_max_per_email=defaults.abuseipdb_max_per_email,
                   rdap_max_per_email=defaults.rdap_max_per_email)


def _recipients(raw: bytes) -> list[str]:
    from phishtriage.forwarding import pick_target
    from phishtriage.parser import parse_eml

    target, _ = pick_target(parse_eml(raw))
    return [address.address for address in target.to + target.cc]


def record_snapshot(path: Path, entries: list[Entry], root: Path, settings: Settings, facts_source,
                    http=None, progress=print) -> dict:
    """Look up every subset email once and store the answers in `path`, which nothing ever purges. Resumable:
    answers already stored are kept as they were (frozen at first fetch), so a second run only fills gaps."""
    from phishtriage.enrich import Enricher
    from phishtriage.enrich.cache import SnapshotCache

    cache = SnapshotCache(path)
    kwargs = {"http": http} if http is not None else {}
    # Built once and sharing one set of rate limiters: a limiter only counts its own calls, so one per email
    # would let every email make 4 VirusTotal lookups in the same minute (VirusTotal then refuses them)
    enrichers = {personal: Enricher(settings, cache=cache, scan_urls=not personal, domains_only=personal, **kwargs)
                 for personal in (False, True)}
    for service in ("virustotal", "urlscan", "abuseipdb", "rdap"):
        getattr(enrichers[True], service).limiter = getattr(enrichers[False], service).limiter
    counts = Counter()
    for number, entry in enumerate(entries, 1):
        raw = long_path(root / entry.file).read_bytes()
        facts = facts_source(root / entry.file)
        result = enrichers[entry.kind == "legit"].enrich(facts, recipients=_recipients(raw))
        counts.update(r.status for r in result.results)
        progress(f"{number}/{len(entries)} {entry.kind:<8} {len(result.results)} lookups")
    cache.set_meta("recorded", datetime.now(UTC).date().isoformat())
    cache.set_meta("subset_sha256", hashlib.sha256("\n".join(e.file for e in entries).encode()).hexdigest())
    cache.close()
    return dict(counts)


def replay_lookups(path: Path, entries: list[Entry], root: Path, rules, facts_source) -> dict:
    """The subset evaluated offline and with the snapshot's answers. Never touches the network."""
    from phishtriage.enrich import Enricher
    from phishtriage.enrich.cache import SnapshotCache
    from phishtriage.enrich.http import HttpResponse

    cache = SnapshotCache(path, read_only=True)
    subset = lookup_subset(entries)  # the same fixed rule that chose what was recorded
    expected = hashlib.sha256("\n".join(e.file for e in subset).encode()).hexdigest()
    if cache.get_meta("subset_sha256") != expected:
        cache.close()
        raise RefusedToRun(f"the snapshot {path.name} was recorded for a different subset of emails")
    missing = Counter()

    def refuse(*args, **kwargs):  # a lookup the snapshot does not hold is not checked, never fetched
        missing["lookups"] += 1
        return HttpResponse(0, None, "not in the frozen snapshot")

    keyed = snapshot_settings(replace(Settings(dkim_recheck=False), virustotal_api_key="snapshot",
                                      urlscan_api_key="snapshot", abuseipdb_api_key="snapshot"))

    def enrichment(entry, facts):
        personal = entry.kind == "legit"
        enricher = Enricher(keyed, cache=cache, http=refuse, scan_urls=not personal, domains_only=personal)
        for service in (enricher.virustotal, enricher.urlscan, enricher.abuseipdb, enricher.rdap):
            service.limiter = _NoLimit()
            service.http = refuse
        raw = long_path(root / entry.file).read_bytes()
        return enricher.enrich(facts, recipients=_recipients(raw))

    offline_rows = run_split(subset, root, rules, facts_source)
    online_rows = run_split(subset, root, rules, facts_source, enrichment)
    changed = [{"file": Path(before.file).name, "kind": before.kind, "offline": before.verdict, "with_lookups": after.verdict,
                "findings": after.findings} for before, after in zip(offline_rows, online_rows, strict=True)
               if before.verdict != after.verdict]
    recorded = cache.get_meta("recorded") or "unknown"
    cache.close()
    return {"recorded": recorded, "offline": metrics(offline_rows), "online": metrics(online_rows),
            "missing": missing["lookups"], "changed": changed}


class _NoLimit:
    def acquire(self, max_wait: float) -> str:
        return ""


def snapshot_main(split: str, confirm: bool = False, limit: int | None = None, path: Path | None = None,
                  root: Path | None = None, manifests=None, settings: Settings | None = None, http=None,
                  facts_source=None, fingerprint_source=None) -> dict:
    """Record the frozen lookup snapshot for the fixed subset of a split. On the test split this is part of the
    M7 run, so the same checks come first; on the development split it is a rehearsal."""
    from phishtriage.rules.report import DEFAULT_MANIFESTS, DEFAULT_ROOT, FactsCache, behaviour_fingerprint, offline_settings
    from phishtriage.rules.report import run as dev_report_run

    root, manifests = root or DEFAULT_ROOT, manifests or DEFAULT_MANIFESTS
    if split == "test":
        if not confirm:
            raise RefusedToRun("recording the test-set snapshot is part of the M7 run: add --confirm-test-run")
        if changes := uncommitted_changes():
            raise RefusedToRun(f"uncommitted changes to tracked files ({len(changes)}): commit first")
        cache = FactsCache(offline_settings())
        fingerprint = (fingerprint_source or (lambda: behaviour_fingerprint(dev_report_run(load_rules(), cache=cache))))()
        if problems := freeze_problems(fingerprint):
            raise RefusedToRun("; ".join(problems))
    entries = entries_for(split, manifests)
    if problems := manifest_problems(entries, root):
        raise RefusedToRun("; ".join(problems[:5]))
    subset = lookup_subset(entries)[:limit] if limit else lookup_subset(entries)
    settings = snapshot_settings(settings or Settings.load())
    path = path or root / ("m7_lookup_snapshot.sqlite" if split == "test" else "m7_lookup_snapshot_dev.sqlite")
    return record_snapshot(path, subset, root, settings, facts_source or FactsCache(offline_settings()).facts, http)
