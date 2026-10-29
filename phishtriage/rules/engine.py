"""The rule engine: turns facts into a score, a verdict, findings, MITRE techniques and actions.

Rules are plain Python functions written by the analyst in phishtriage/rules/scoring.py:

    @rule("SENDER-001", title="Sender domain is not a valid domain", points=20, category="sender")
    def sender_domain_invalid(f):
        return not f.headers.sender.domain_is_valid

A rule fires when it returns something true. Returning a string fires it and uses the string
as the evidence shown to the analyst. Returning UNKNOWN says "I could not tell" (for example a
lookup that did not run), which is reported as not checked instead of being treated as clean.

The verdict comes only from this code. The AI summary added later cannot change it.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

MALICIOUS, SUSPICIOUS, NO_INDICATORS = "Malicious", "Suspicious", "No indicators found"
_RANK = {NO_INDICATORS: 0, SUSPICIOUS: 1, MALICIOUS: 2}
DEFAULT_RULES = "phishtriage.rules.scoring"


class _Unknown:
    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "UNKNOWN"


UNKNOWN = _Unknown()  # a rule returns this when the data it needs is missing

MITRE_TECHNIQUES = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1566.003": "Phishing: Spearphishing via Service",
    "T1566.004": "Phishing: Spearphishing Voice",
    "T1598": "Phishing for Information",
    "T1598.002": "Phishing for Information: Spearphishing Attachment",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1598.004": "Phishing for Information: Spearphishing Voice",
    "T1656": "Impersonation",
    "T1534": "Internal Spearphishing",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1036.007": "Masquerading: Double File Extension",
    "T1027": "Obfuscated Files or Information",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1585.002": "Establish Accounts: Email Accounts",
    "T1608.005": "Stage Capabilities: Link Target",
}

DEFAULT_VERDICT_ACTIONS = {
    MALICIOUS: [
        "Block the sender domain, sending IP and the links' domains at the email gateway and proxy.",
        "Search all mailboxes for copies of this email and remove them.",
        "Ask the recipients whether they clicked, replied or opened an attachment; if anyone entered a "
        "password, reset it and sign the account out of all sessions.",
    ],
    SUSPICIOUS: [
        "Keep the email in quarantine until an analyst has reviewed the findings.",
        "Do not click links or open attachments outside a sandbox.",
    ],
    NO_INDICATORS: [
        # Not "release it": "No indicators found" is not proof of safety, and the rules miss about 1 phishing
        # email in 10 on the development sets (the old wording also said "no rule fired" when LEGIT-001 had)
        "Nothing here is enough to flag the email, which is not proof that it is safe. Before releasing it, check "
        "the sender, the links and any weak signs listed, and thank the reporter.",
    ],
}


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    points: int  # negative points are evidence that the email is legitimate
    category: str = "other"  # used for caps and for grouping in reports
    mitre: tuple[str, ...] = ()
    needs: str = "email"  # "email": the email alone; "lookups": reputation lookups must have run
    floor: str = ""  # "Suspicious" or "Malicious": when the rule fires, the verdict is at least this
    actions: tuple[str, ...] = ()  # recommended actions added when the rule fires


def rule(id: str, *, title: str, points: int, category: str = "other", mitre=(), needs: str = "email",
         floor: str = "", actions=()):
    def decorate(function):
        function.rule = RuleMeta(id, title, int(points), category, tuple(mitre), needs, floor, tuple(actions))
        return function
    return decorate


@dataclass
class Finding:
    id: str
    title: str
    points: int  # after category caps
    category: str
    evidence: str
    mitre: list[str] = field(default_factory=list)
    floor: str = ""
    rule_points: int = 0  # the rule's own points: more than `points` when a category cap cut them (display only)

    @property
    def capped(self) -> bool:
        return self.points < self.rule_points


def display_order(findings: list[Finding]) -> list[Finding]:
    """Strongest applied points first. The engine orders by the rules' own points, so after a cap a +15 could
    sit above a +20 (Fathia's first-user test, 2026-10-22). Display only: the score is the same either way."""
    return sorted(findings, key=lambda f: (-f.points, -f.rule_points))


@dataclass
class Verdict:
    verdict: str
    score: int
    findings: list[Finding] = field(default_factory=list)  # strongest first
    reasons: list[str] = field(default_factory=list)  # why this verdict
    not_checked: list[str] = field(default_factory=list)  # rules that could not tell
    errors: list[str] = field(default_factory=list)  # rules that crashed (a bug in the rule, never in the email)
    mitre: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)

    @property
    def caught(self) -> bool:
        """Suspicious or Malicious: what EVALUATION.md counts as caught (phishing) or flagged (legitimate)."""
        return self.verdict != NO_INDICATORS

    @property
    def weak_signs(self) -> list[Finding]:
        """Findings that added points but not enough to reach Suspicious."""
        return [f for f in self.findings if f.points > 0] if self.verdict == NO_INDICATORS else []

    @property
    def label(self) -> str:
        """What the analyst reads. 'No indicators found' next to a score of 20 misleads (Fathia's grading,
        2026-10-19), so emails with weak signs say so. Display only: the verdict itself is unchanged."""
        count = len(self.weak_signs)
        if count:
            return f"Low risk ({count} weak sign{'s' if count > 1 else ''} below the Suspicious threshold)"
        return self.verdict

    @property
    def coverage(self) -> str:
        """One fixed line saying which rules could not run. Written by code, because the model guessed
        ("no other checks were done", wrong in 2 of 10 graded summaries)."""
        groups: dict[str, list[str]] = {}
        for item in self.not_checked:  # "ID (title): reason"; titles may contain ':' or '(' themselves
            head, _, reason = item.rpartition("): ")
            groups.setdefault(reason or "not run", []).append(head.split(" (", 1)[0])
        parts = [f"{', '.join(ids)} ({reason})" for reason, ids in groups.items()]
        if self.errors:
            parts.append(f"{len(self.errors)} rule{'s' if len(self.errors) > 1 else ''} crashed (a bug in the tool)")
        return "Not checked: " + "; ".join(parts) + "." if parts else "Every rule could run."


@dataclass
class RuleSet:
    rules: list[tuple[RuleMeta, object]]
    suspicious_at: int
    malicious_at: int
    category_caps: dict[str, int]
    verdict_actions: dict[str, list[str]]
    source: str
    module: ModuleType | None = None


def _import(source: str) -> ModuleType:
    path = Path(source)
    if path.suffix == ".py" and path.exists():
        spec = importlib.util.spec_from_file_location(f"phishtriage_rules_{path.stem}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return importlib.import_module(source)


def load_rules(source: str = DEFAULT_RULES) -> RuleSet:
    """Load the rules of a module (default) or a .py file, checking them for mistakes."""
    module = _import(source)
    found = [(function.rule, function) for _, function in inspect.getmembers(module, inspect.isfunction)
             if isinstance(getattr(function, "rule", None), RuleMeta)]
    found.sort(key=lambda item: inspect.getsourcelines(item[1])[1])  # file order
    problems = []
    ids = [meta.id for meta, _ in found]
    problems += [f"rule id {rule_id} is used twice" for rule_id in sorted({i for i in ids if ids.count(i) > 1})]
    for meta, _ in found:
        if meta.floor not in ("", SUSPICIOUS, MALICIOUS):
            problems.append(f"{meta.id}: floor must be '', '{SUSPICIOUS}' or '{MALICIOUS}'")
        if meta.needs not in ("email", "lookups"):
            problems.append(f"{meta.id}: needs must be 'email' or 'lookups'")
    suspicious_at = int(getattr(module, "SUSPICIOUS_AT", 30))
    malicious_at = int(getattr(module, "MALICIOUS_AT", 70))
    if malicious_at <= suspicious_at:
        problems.append("MALICIOUS_AT must be higher than SUSPICIOUS_AT")
    if problems:
        raise ValueError("problems in the rules: " + "; ".join(problems))
    actions = {**DEFAULT_VERDICT_ACTIONS, **getattr(module, "VERDICT_ACTIONS", {})}
    return RuleSet(found, suspicious_at, malicious_at, dict(getattr(module, "CATEGORY_CAPS", {})), actions, source, module)


def evaluate(facts, rules: RuleSet) -> Verdict:
    fired: list[tuple[RuleMeta, str]] = []
    not_checked, errors = [], []
    for meta, function in rules.rules:
        if meta.needs == "lookups" and facts.enrichment is None:
            not_checked.append(f"{meta.id} ({meta.title}): reputation lookups were not run")
            continue
        try:
            result = function(facts)
        except Exception as error:  # noqa: BLE001 - a buggy rule must not stop the analysis
            errors.append(f"{meta.id}: {type(error).__name__}: {error}")
            continue
        if result is UNKNOWN:
            not_checked.append(f"{meta.id} ({meta.title}): the data it needs was not available")
        elif result:
            fired.append((meta, result if isinstance(result, str) else meta.title))

    # Category caps: correlated rules (e.g. several text phrases) cannot pile up beyond the cap.
    # Applied to positive points, strongest first; evidence of legitimacy is never capped.
    used: dict[str, int] = {}
    findings = []
    for meta, evidence in sorted(fired, key=lambda item: -item[0].points):
        points = meta.points
        cap = rules.category_caps.get(meta.category)
        if cap is not None and points > 0:
            points = max(0, min(points, cap - used.get(meta.category, 0)))
            used[meta.category] = used.get(meta.category, 0) + points
        findings.append(Finding(meta.id, meta.title, points, meta.category, evidence, list(meta.mitre), meta.floor,
                                meta.points))

    score = sum(finding.points for finding in findings)
    verdict = MALICIOUS if score >= rules.malicious_at else SUSPICIOUS if score >= rules.suspicious_at else NO_INDICATORS
    reasons = [f"score {score} (Suspicious from {rules.suspicious_at}, Malicious from {rules.malicious_at})"]
    for finding in findings:
        if finding.floor and _RANK[finding.floor] > _RANK[verdict]:
            verdict = finding.floor
            reasons.append(f"{finding.id} sets the verdict to at least {finding.floor}")

    mitre = list(dict.fromkeys(technique for finding in findings if finding.points > 0 for technique in finding.mitre))
    actions = list(rules.verdict_actions.get(verdict, []))
    if verdict != NO_INDICATORS:
        actions = list(dict.fromkeys(actions + [action for meta, _ in fired for action in meta.actions]))
    return Verdict(verdict, score, findings, reasons, not_checked, errors, mitre, actions)
