"""The rule engine, the rules template, the tuning report and the facts documentation."""
import json
import textwrap

import pytest

from phishtriage.analyze import analyze
from phishtriage.config import Settings
from phishtriage.dataset import Entry
from phishtriage.factsdoc import facts_markdown
from phishtriage.rules import MALICIOUS, NO_INDICATORS, SUSPICIOUS, evaluate, load_rules
from phishtriage.rules import report
from phishtriage.stats import count_with_range, wilson
from tests.helpers import make_eml

OFFLINE = Settings(dkim_recheck=False)


def rules_file(tmp_path, body: str, name: str = "my_rules.py"):
    path = tmp_path / name
    path.write_text("from phishtriage.rules import UNKNOWN, rule\n" + textwrap.dedent(body), encoding="utf-8")
    return load_rules(str(path))


def facts(**kwargs):
    return analyze(make_eml(**kwargs), OFFLINE)


def test_thresholds_negative_points_and_evidence(tmp_path):
    rules = rules_file(tmp_path, """
        SUSPICIOUS_AT = 30
        MALICIOUS_AT = 60

        @rule("A-1", title="Subject says invoice", points=35, mitre=["T1566"])
        def invoice(f):
            return "invoice" in f.email.subject.lower() and f"subject: {f.email.subject}"

        @rule("A-2", title="Subject says urgent", points=30)
        def urgent(f):
            return "urgent" in f.email.subject.lower()

        @rule("L-1", title="Legitimate sign", points=-10)
        def legit(f):
            return True
    """)
    assert evaluate(facts(subject="Hello"), rules).verdict == NO_INDICATORS
    v = evaluate(facts(subject="Your invoice"), rules)
    assert (v.verdict, v.score) == (NO_INDICATORS, 25)  # 35 - 10
    v = evaluate(facts(subject="URGENT invoice"), rules)
    assert (v.verdict, v.score) == (SUSPICIOUS, 55)
    assert v.findings[0].evidence == "subject: URGENT invoice"
    assert v.mitre == ["T1566"]
    assert v.caught


def test_floor_unknown_errors_and_lookups(tmp_path):
    rules = rules_file(tmp_path, """
        @rule("F-1", title="Decisive", points=5, floor="Malicious")
        def decisive(f):
            return f.email.subject == "decisive"

        @rule("U-1", title="Unknown data", points=50)
        def unknown(f):
            return UNKNOWN

        @rule("E-1", title="Buggy rule", points=50)
        def buggy(f):
            return 1 / 0

        @rule("R-1", title="Needs lookups", points=50, needs="lookups")
        def needs_lookups(f):
            return True
    """)
    v = evaluate(facts(subject="decisive"), rules)
    assert v.verdict == MALICIOUS and v.score == 5
    assert any("F-1 sets the verdict to at least Malicious" in reason for reason in v.reasons)
    assert [item.split(" ")[0] for item in v.not_checked] == ["U-1", "R-1"]
    assert v.errors == ["E-1: ZeroDivisionError: division by zero"]


def test_category_caps(tmp_path):
    rules = rules_file(tmp_path, """
        CATEGORY_CAPS = {"text": 30}

        @rule("T-1", title="Phrase one", points=20, category="text")
        def one(f):
            return True

        @rule("T-2", title="Phrase two", points=20, category="text")
        def two(f):
            return True

        @rule("L-1", title="Legitimate", points=-5, category="text")
        def legit(f):
            return True
    """)
    v = evaluate(facts(), rules)
    assert sorted(f.points for f in v.findings) == [-5, 10, 20]  # second phrase capped, negatives untouched
    assert v.score == 25


def test_mistakes_in_rules_are_reported(tmp_path):
    with pytest.raises(ValueError, match="used twice"):
        rules_file(tmp_path, """
            @rule("X-1", title="a", points=1)
            def a(f):
                return True

            @rule("X-1", title="b", points=1)
            def b(f):
                return True
        """)
    with pytest.raises(ValueError, match="floor"):
        rules_file(tmp_path, """
            @rule("X-2", title="a", points=1, floor="Dangerous")
            def a(f):
                return True
        """, name="other.py")


def test_real_rule_set_loads_and_runs():
    rules = load_rules()
    ids = [meta.id for meta, _ in rules.rules]
    assert len(ids) == len(set(ids)) and len(ids) >= 40
    v = evaluate(facts(from_="Shop <news@shop.invalidtld>"), rules)
    assert any(f.id == "SENDER-001" for f in v.findings)
    assert any(item.startswith("REP-001") for item in v.not_checked)  # offline: lookups did not run


def test_report_uses_development_sets_only(tmp_path):
    root = tmp_path / "samples"
    (root / "p").mkdir(parents=True)
    (root / "l").mkdir()
    (root / "p" / "dev.eml").write_bytes(make_eml(subject="dev phish", from_="X <x@bad.invalidtld>"))
    (root / "p" / "test.eml").write_bytes(make_eml(subject="test phish"))
    (root / "l" / "dev.eml").write_bytes(make_eml(subject="dev legit"))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([
        Entry("p/dev.eml", "", "phishing", "phishing_pot", "dev", "g1").__dict__,
        Entry("p/test.eml", "", "phishing", "phishing_pot", "test", "g2").__dict__,
        Entry("l/dev.eml", "", "legit", "gmail", "dev", "g3").__dict__,
    ]))
    rules = rules_file(tmp_path, """
        @rule("SENDER-X", title="Invalid sender domain", points=20)
        def invalid(f):
            return not f.headers.sender.domain_is_valid
    """)
    cache = report.FactsCache(OFFLINE, folder=tmp_path / "cache")
    results = report.run(rules, root, [manifest], cache)
    assert sorted(r.entry.file for r in results) == ["l/dev.eml", "p/dev.eml"]  # the test email is never read
    text = report.render(results, rules, show="SENDER-X", misses=True)
    assert "DEVELOPMENT SETS ONLY" in text and "p/dev.eml" in text and "p/test.eml" not in text
    assert "phishing caught      0 of 1" in text  # 20 points is below Suspicious (30)
    assert "p/dev.eml" in text.split("Phishing not caught")[1] and "SENDER-X+20" in text
    assert any((tmp_path / "cache").rglob("*.pickle"))  # facts cached for the next run
    assert "Behaviour fingerprint" in text


def test_behaviour_fingerprint_tracks_decisions_not_wording():
    from phishtriage.rules.engine import Finding, Verdict

    def result(file: str, points: int, evidence: str = "e") -> report.Result:
        finding = Finding("X-1", "t", points, "c", evidence)
        return report.Result(Entry(file, "", "phishing", "s", "dev", "g"), Verdict(SUSPICIOUS, points, [finding]))

    base = report.behaviour_fingerprint([result("a.eml", 30), result("b.eml", 40)])
    assert report.behaviour_fingerprint([result("b.eml", 40), result("a.eml", 30)]) == base  # order does not matter
    assert report.behaviour_fingerprint([result("a.eml", 30, "reworded"), result("b.eml", 40)]) == base
    assert report.behaviour_fingerprint([result("a.eml", 35), result("b.eml", 40)]) != base  # a decision changed


def test_report_warns_about_receiver_specific_facts(tmp_path):
    rules = rules_file(tmp_path, """
        @rule("BAD-1", title="Uses compauth", points=10)
        def bad(f):
            return f.auth.compauth == "fail"
    """)
    text = report.render([], rules)
    assert "BAD-1 reads a receiver-specific fact" in text


def test_facts_documentation_is_generated_from_the_code():
    text = facts_markdown()
    assert "| `f.headers.sender.domain` |" in text
    assert "`f.indicators.links[i].text_shows_other_domain`" in text
    assert "`f.enrichment.results[i].malicious`" in text
    assert "spoofing" in text  # the comment written next to own_domain_from_outside


def test_wilson_ranges():
    low, high = wilson(0, 62)
    assert low == 0 and 0.055 < high < 0.062
    assert count_with_range(3, 62).startswith("3 of 62 (4.8%, 95% range")


def test_mitre_table_is_current():
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parent.parent / "scripts" / "make_mitre_table.py"
    spec = importlib.util.spec_from_file_location("make_mitre_table", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.OUTPUT.read_text(encoding="utf-8") == module.render(), "run scripts/make_mitre_table.py"
