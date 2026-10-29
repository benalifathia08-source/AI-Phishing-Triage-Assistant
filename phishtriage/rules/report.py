"""The rule-tuning report: how each rule behaves on the DEVELOPMENT sets.

Only development emails are ever read here. The test sets are run once, at M7, on a
frozen copy of the rules (see EVALUATION.md).
"""
from __future__ import annotations

import hashlib
import inspect
import pickle
import platform
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from phishtriage.analyze import Facts, analyze
from phishtriage.config import PROJECT_ROOT, Settings
from phishtriage.dataset import Entry, long_path, read_manifest
from phishtriage.rules.engine import MALICIOUS, NO_INDICATORS, SUSPICIOUS, RuleSet, Verdict, evaluate
from phishtriage.stats import count_with_range

DEFAULT_ROOT = PROJECT_ROOT.parent / "phishing-samples"
DEFAULT_MANIFESTS = (PROJECT_ROOT / "datasets" / "phishing_pot_split.json", DEFAULT_ROOT / "legit" / "manifest.json")
# Facts that say which server received the email rather than whether it is phishing (EVALUATION.md, section 6)
RECEIVER_SPECIFIC = re.compile(r"\.(compauth|compauth_reason|exchange_auth_as|authserv_id|ignored_authserv_ids)\b")


def offline_settings() -> Settings:
    """The evaluation settings: the email alone, no network (no lookups, no DKIM re-check)."""
    loaded = Settings.load()
    return Settings(trusted_authserv_ids=loaded.trusted_authserv_ids, dkim_recheck=False,
                    protected_domains=loaded.protected_domains, brands_file=loaded.brands_file)


# Code that never changes a fact: editing it must not start a new cache of everyone's email facts
# (before 2026-10-22 every web-page edit did, and 9 versions of personal email facts piled up)
_NOT_FACT_CODE_DIRS = ("rules", "ai", "web")
_NOT_FACT_CODE_FILES = ("cli.py", "factsdoc.py", "evaluation.py", "batch.py", "exports.py", "pipeline.py",
                        "isolate.py", "display.py")


# Third-party code that extracts facts: a new version can change them (found 2026-10-22, M8: a Pillow update
# reused facts cached with the old Pillow, so the behaviour fingerprint could not see it)
FACT_LIBRARIES = ("dkimpy", "dnspython", "tldextract", "opencv-python-headless", "pillow", "pypdfium2", "numpy")


def _library_versions() -> str:
    from importlib.metadata import PackageNotFoundError, version

    def installed(name: str) -> str:
        try:
            return version(name)
        except PackageNotFoundError:
            return "missing"

    return f"python {platform.python_version()}; " + ", ".join(f"{name} {installed(name)}" for name in FACT_LIBRARIES)


def _fingerprint(settings: Settings) -> str:
    """Changes whenever fact extraction could give different results."""
    digest = hashlib.sha256(_library_versions().encode())
    package = PROJECT_ROOT / "phishtriage"
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(package)
        if relative.parts[0] not in _NOT_FACT_CODE_DIRS and path.name not in _NOT_FACT_CODE_FILES:
            digest.update(relative.as_posix().encode() + path.read_bytes())
    digest.update(Path(settings.brands_file).read_bytes())
    digest.update(repr((sorted(settings.protected_domains), sorted(settings.trusted_authserv_ids))).encode())
    return digest.hexdigest()[:16]


FACTS_FOLDER = PROJECT_ROOT / ".cache" / "facts"


def purge_facts(all_versions: bool = False, folder: Path = FACTS_FOLDER) -> tuple[int, int]:
    """Delete cached email facts: those of older code versions (never read again), or all of them.
    Returns (folders, files) deleted. The facts of personal emails should not outlive their use."""
    import shutil

    if not folder.exists():
        return 0, 0
    current = _fingerprint(offline_settings())
    folders = files = 0
    for sub in folder.iterdir():
        if sub.is_dir() and (all_versions or sub.name != current):
            files += sum(1 for _ in sub.iterdir())
            shutil.rmtree(sub)
            folders += 1
    return folders, files


class FactsCache:
    """Facts per email, stored under .cache/facts/ (git-ignored, on this laptop only)."""

    def __init__(self, settings: Settings, folder: Path = FACTS_FOLDER) -> None:
        self.settings = settings
        self.folder = folder / _fingerprint(settings)
        self.folder.mkdir(parents=True, exist_ok=True)

    def facts(self, path: Path) -> Facts:
        raw = long_path(path).read_bytes()
        cached = self.folder / f"{hashlib.sha256(raw).hexdigest()}.pickle"
        if cached.exists():
            return pickle.loads(cached.read_bytes())  # noqa: S301 - only this tool writes these files, in a git-ignored local folder
        facts = analyze(raw, self.settings)
        cached.write_bytes(pickle.dumps(facts))
        return facts


@dataclass
class Result:
    entry: Entry
    verdict: Verdict

    @property
    def group(self) -> str:
        return "phishing" if self.entry.kind == "phishing" else self.entry.source


def run(rules: RuleSet, root: Path = DEFAULT_ROOT, manifests=DEFAULT_MANIFESTS, cache: FactsCache | None = None) -> list[Result]:
    cache = cache or FactsCache(offline_settings())
    results = []
    for manifest in manifests:
        if not Path(manifest).exists():
            continue
        for entry in read_manifest(Path(manifest)):
            if entry.split != "dev":
                continue  # never the test sets
            results.append(Result(entry, evaluate(cache.facts(root / entry.file), rules)))
    return results


def behaviour_fingerprint(results: list[Result]) -> str:
    """A hash of every development email's verdict, score and findings (points included, evidence text not).

    Freezing scoring.py alone does not freeze the verdicts: they also depend on the fact code (content.py,
    brands.py, auth.py, ...), the brand list and library versions (tldextract's suffix list, OpenCV). If this
    hash is unchanged, no development decision changed, whichever file was edited."""
    digest = hashlib.sha256()
    for result in sorted(results, key=lambda r: r.entry.file):
        findings = ",".join(f"{f.id}{f.points:+d}" for f in result.verdict.findings)
        digest.update(f"{result.entry.file}|{result.verdict.verdict}|{result.verdict.score}|{findings}\n".encode())
    return digest.hexdigest()[:16]


def _fires(result: Result, rule_id: str) -> bool:
    return any(finding.id == rule_id for finding in result.verdict.findings)


def render(results: list[Result], rules: RuleSet, show: str | None = None, misses: bool = False) -> str:
    phishing = [r for r in results if r.entry.kind == "phishing"]
    legit = [r for r in results if r.entry.kind == "legit"]
    sources = sorted({r.group for r in legit})
    lines = [
        "DEVELOPMENT SETS ONLY (the test sets are never used here)",
        f"phishing {len(phishing)} | legitimate {len(legit)} ("
        + ", ".join(f"{s} {sum(r.group == s for r in legit)}" for s in sources) + ")"
        + f" | {len(rules.rules)} rules from {rules.source} | Suspicious from {rules.suspicious_at}, Malicious from {rules.malicious_at}",
        "",
        f"{'Rule':<14}{'Points':>7}  {'Phishing':>13}  {'Legitimate':>13}  " + "".join(f"{s[:10]:>11}" for s in sources) + "  Title",
    ]
    warnings = []
    for meta, function in rules.rules:
        on_phishing = sum(_fires(r, meta.id) for r in phishing)
        on_legit = sum(_fires(r, meta.id) for r in legit)
        rate_p = on_phishing / len(phishing) if phishing else 0
        rate_l = on_legit / len(legit) if legit else 0
        mark = "!" if on_legit and rate_l >= rate_p and meta.points > 0 else " "
        per_source = "".join(f"{sum(_fires(r, meta.id) for r in legit if r.group == s):>11}" for s in sources)
        lines.append(f"{meta.id:<14}{meta.points:>+7}  {on_phishing:>5} {rate_p:>6.1%}  {on_legit:>5} {rate_l:>6.1%} "
                     f"{per_source} {mark}{meta.title}")
        if RECEIVER_SPECIFIC.search(inspect.getsource(function)):
            warnings.append(f"{meta.id} reads a receiver-specific fact (compauth, exchange_auth_as, authserv_id): "
                            "it would learn which server received the email, not whether it is phishing")
        if meta.needs == "email" and on_phishing == 0 and on_legit == 0:
            warnings.append(f"{meta.id} never fires on the development sets")
    lines.append("(! = a positive-points rule that fires at least as often on legitimate mail as on phishing)")

    lines += ["", f"{'Verdicts':<26}{'Malicious':>11}{'Suspicious':>12}{'None':>8}"]
    for name, group in [("phishing", phishing)] + [(f"legitimate: {s}", [r for r in legit if r.group == s]) for s in sources]:
        counts = Counter(r.verdict.verdict for r in group)
        lines.append(f"{name + f' ({len(group)})':<26}{counts[MALICIOUS]:>11}{counts[SUSPICIOUS]:>12}{counts[NO_INDICATORS]:>8}")

    caught = sum(r.verdict.caught for r in phishing)
    legit_malicious = sum(r.verdict.verdict == MALICIOUS for r in legit)
    legit_flagged = sum(r.verdict.caught for r in legit)
    lines += [
        "",
        "Against the targets (development numbers only guide tuning; the test run is what counts):",
        f"  phishing caught      {count_with_range(caught, len(phishing)):<45} target at least 90%  "
        + ("met" if phishing and caught / len(phishing) >= 0.9 else "not yet"),
        f"  legitimate Malicious {count_with_range(legit_malicious, len(legit)):<45} target 0            "
        + ("met" if legit_malicious == 0 else "not yet"),
        f"  legitimate flagged   {count_with_range(legit_flagged, len(legit)):<45} target at most 10%  "
        + ("met" if legit and legit_flagged / len(legit) <= 0.10 else "not yet"),
    ]
    errors = Counter(error.split(":")[0] for r in results for error in r.verdict.errors)
    warnings += [f"{rule_id} crashed on {count} email(s): fix the rule" for rule_id, count in errors.items()]
    if warnings:
        lines += ["", "Warnings:"] + [f"  - {warning}" for warning in warnings]
    lines += ["", f"Behaviour fingerprint (every development verdict, score and finding): {behaviour_fingerprint(results)}"]

    if show:
        lines += ["", f"Emails where {show} fires (legitimate first):"]
        hits = [r for r in legit + phishing if _fires(r, show)]
        for r in hits[:60]:
            evidence = next(f.evidence for f in r.verdict.findings if f.id == show)
            lines.append(f"  {r.entry.file:<45} {r.verdict.verdict:<20} {evidence[:90]}")
        if len(hits) > 60:
            lines.append(f"  ... and {len(hits) - 60} more")
    if misses:
        lines += ["", "Legitimate emails flagged (false alarms):"]
        lines += [_line(r) for r in legit if r.verdict.caught] or ["  none"]
        missed = [r for r in phishing if not r.verdict.caught]
        lines += ["", f"Phishing not caught ({len(missed)}):"]
        lines += [_line(r) for r in missed[:40]] or ["  none"]
        if len(missed) > 40:
            lines.append(f"  ... and {len(missed) - 40} more")
    return "\n".join(lines)


def _line(result: Result) -> str:
    top = ", ".join(f"{f.id}{f.points:+d}" for f in result.verdict.findings[:4]) or "no rule fired"
    return f"  {result.entry.file:<45} score {result.verdict.score:>4}  {top}"
