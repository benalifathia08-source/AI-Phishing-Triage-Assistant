"""The M7 runner and the frozen lookup snapshot, on synthetic data: no test email is ever read here."""
import hashlib
import json
from dataclasses import asdict

import pytest

from phishtriage import evaluation
from phishtriage.analyze import analyze
from phishtriage.config import Settings
from phishtriage.dataset import Entry
from phishtriage.enrich import Enricher
from phishtriage.enrich.cache import Cache, SnapshotCache
from phishtriage.enrich.http import HttpResponse
from phishtriage.evaluation import Row, RefusedToRun, lookup_subset, metrics
from tests.helpers import make_eml

OFFLINE = Settings(dkim_recheck=False)


@pytest.fixture(autouse=True)
def frozen_scoring_file(monkeypatch):
    """These tests are about the runner, not about which scoring.py is checked out (the published copy differs from
    the frozen file by one comment line, EVALUATION.md section 9)."""
    monkeypatch.setattr(evaluation, "scoring_blob", lambda: evaluation.FROZEN_SCORING_BLOB)


def offline_facts(path):
    return analyze(path.read_bytes(), OFFLINE)


def row(kind, verdict, group="g", source=None):
    return Row(f"{kind}/{group}.eml", kind, source or ("phishing_pot" if kind == "phishing" else "gmail"), group,
               verdict, 0, "")


def test_metrics():
    rows = ([row("phishing", "Malicious", "c1"), row("phishing", "Suspicious", "c1"),  # campaign c1: 2 of 2
             row("phishing", "No indicators found", "c2"), row("phishing", "Malicious", "c2"),  # c2: 1 of 2
             row("phishing", "No indicators found", "c3")]  # c3: 0 of 1
            + [row("legit", "No indicators found", f"s{i}") for i in range(9)] + [row("legit", "Suspicious", "s9")])
    m = metrics(rows)
    assert (m["caught"], m["malicious"], m["legit_flagged"], m["legit_malicious"]) == (3, 2, 1, 0)
    assert m["campaigns"] == {"groups": 3, "mean_share_caught": 0.5, "all_caught": 1, "some_caught": 1,
                              "none_caught": 1}
    assert m["confusion"]["phishing"] == {"Malicious": 2, "Suspicious": 1, "No indicators found": 2}
    p = m["precision"]["50%"]  # tpr 0.6, fpr 0.1: 0.3 / (0.3 + 0.05)
    assert abs(p["point"] - 0.6 / 0.7) < 1e-9 and p["low"] < p["point"] < p["high"]
    assert m["targets"] == {"caught_at_least_90%": False, "no_legit_malicious": True, "flagged_at_most_10%": True}


def test_lookup_subset_is_fixed_one_per_campaign_plus_every_legit_email():
    entries = [Entry(f"p{i}.eml", f"{i:064x}", "phishing", "phishing_pot", "test", f"g{i % 5}") for i in range(20)]
    entries += [Entry(f"l{i}.eml", f"{i:064x}", "legit", "gmail", "test", f"s{i}") for i in range(3)]
    subset = lookup_subset(entries, phishing=4)
    phishing = [e for e in subset if e.kind == "phishing"]
    assert len(phishing) == 4 and len({e.group for e in phishing}) == 4 and len(subset) == 7
    assert lookup_subset(list(reversed(entries)), phishing=4) == subset  # order of the manifest does not matter


@pytest.fixture
def dataset(tmp_path):
    """Two phishing emails (two campaigns) and one legitimate one, with a manifest of the 'test' split."""
    emails = {
        "p/a.eml": ("phishing", "c1", make_eml(
            body='<p>Verify your account within 24 hours</p><a href="https://login-portal-fake.com/x">Verify</a>',
            content_type="text/html; charset=utf-8", from_="IT Desk <desk@notify-fake-sender.com>")),
        "p/b.eml": ("phishing", "c2", make_eml(subject="Hello", from_="Bob <bob@other-fake-sender.com>")),
        "l/c.eml": ("legit", "s1", make_eml(body='<a href="https://www.news-fake-site.com/article">read</a>',
                                            content_type="text/html; charset=utf-8",
                                            from_="News <news@news-fake-site.com>")),
    }
    entries = []
    for name, (kind, group, raw) in emails.items():
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_bytes(raw)
        entries.append(Entry(name, hashlib.sha256(raw).hexdigest(), kind, "phishing_pot" if kind == "phishing"
                             else "gmail", "test", group))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([asdict(e) for e in entries]))
    return tmp_path, [manifest]


def run_test_split(tmp_path, manifests, **kwargs):
    return evaluation.run("test", root=tmp_path, manifests=manifests, output=tmp_path / "out.md",
                          ledger=tmp_path / "ledger.json", facts_source=offline_facts, **kwargs)


def test_the_test_run_refuses_until_every_check_passes(dataset, monkeypatch):
    root, manifests = dataset
    monkeypatch.setattr(evaluation, "uncommitted_changes", lambda: [])
    with pytest.raises(RefusedToRun, match="--confirm-test-run"):
        run_test_split(root, manifests, fingerprint_source=lambda: evaluation.FROZEN_FINGERPRINT)
    with pytest.raises(RefusedToRun, match="behaviour fingerprint"):  # a development decision changed
        run_test_split(root, manifests, confirm=True, fingerprint_source=lambda: "0000000000000000")
    monkeypatch.setattr(evaluation, "uncommitted_changes", lambda: [" M phishtriage/content.py"])
    with pytest.raises(RefusedToRun, match="uncommitted"):
        run_test_split(root, manifests, confirm=True, fingerprint_source=lambda: evaluation.FROZEN_FINGERPRINT)
    monkeypatch.setattr(evaluation, "uncommitted_changes", lambda: [])
    (root / "p" / "b.eml").write_bytes(b"changed after labelling")
    with pytest.raises(RefusedToRun, match="changed since it was labelled"):
        run_test_split(root, manifests, confirm=True, fingerprint_source=lambda: evaluation.FROZEN_FINGERPRINT)


def test_the_test_run_happens_once_and_later_versions_are_marked(dataset, monkeypatch):
    root, manifests = dataset
    monkeypatch.setattr(evaluation, "uncommitted_changes", lambda: [])
    details = run_test_split(root, manifests, confirm=True, fingerprint_source=lambda: evaluation.FROZEN_FINGERPRINT)
    assert details["metrics"]["phishing"] == 2 and details["metrics"]["legit"] == 1
    text = (root / "out.md").read_text(encoding="utf-8")
    assert "M7 results: the held-out test sets" in text and "no earlier test run recorded" in text
    assert len(json.loads((root / "ledger.json").read_text())) == 1
    saved = json.loads((root / "out.json").read_text(encoding="utf-8"))["rows"]
    assert {r["group"] for r in saved if r["kind"] == "phishing"} == {"c1", "c2"}
    assert not [r for r in saved if r["kind"] == "legit"]  # personal mail not flagged: counts only
    flagged = Row("l/c.eml", "legit", "gmail", "sender@private-fake-mail.com", "Suspicious", 40, "AUTH-005+25")
    assert flagged.public()["group"] == ""  # a false alarm is listed, but never with its sender's address
    with pytest.raises(RefusedToRun, match="already recorded"):
        run_test_split(root, manifests, confirm=True, fingerprint_source=lambda: evaluation.FROZEN_FINGERPRINT)
    run_test_split(root, manifests, confirm=True, addendum="rules-v2", fingerprint_source=lambda: "changed-version")
    assert "ADDENDUM: rules-v2, tuned after seeing the test set" in (root / "out.md").read_text(encoding="utf-8")
    assert [r["addendum"] for r in json.loads((root / "ledger.json").read_text())] == ["", "rules-v2"]


class FakeNetwork:
    """VirusTotal flags the phishing link; every other lookup answers 'not found'. Records every call."""

    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers=None, body=None, timeout=20):
        self.calls.append((method, url, body))
        if "virustotal.com/api/v3/urls/" in url or "virustotal.com/api/v3/domains/login-portal-fake.com" in url:
            return HttpResponse(200, {"data": {"attributes": {"last_analysis_stats": {
                "malicious": 9, "suspicious": 0, "undetected": 60, "harmless": 0}}}})
        return HttpResponse(404, None, "HTTP 404")


def test_snapshot_records_once_and_replays_without_the_network(dataset, monkeypatch):
    root, manifests = dataset
    keyed = Settings(dkim_recheck=False, virustotal_api_key="k", urlscan_api_key="", abuseipdb_api_key="")
    snapshot = root / "snapshot.sqlite"
    network = FakeNetwork()
    snapshot_args = dict(root=root, manifests=manifests, settings=keyed, http=network, path=snapshot,
                         facts_source=offline_facts, fingerprint_source=lambda: evaluation.FROZEN_FINGERPRINT)
    monkeypatch.setattr(evaluation, "uncommitted_changes", lambda: [])
    with pytest.raises(RefusedToRun, match="--confirm-test-run"):  # recording is part of the M7 run
        evaluation.snapshot_main("test", **snapshot_args)
    evaluation.snapshot_main("test", confirm=True, **snapshot_args)
    entries = evaluation.entries_for("test", manifests)
    # Personal mail got domain-level lookups only: no VirusTotal URL lookup and no scan of its link
    legit_url_lookups = [c for c in network.calls if "/urls/" in c[1] and "news-fake-site" in str(c)]
    assert not legit_url_lookups and not any("urlscan" in c[1] for c in network.calls if "news-fake-site" in str(c))
    assert any("virustotal.com/api/v3/domains/news-fake-site.com" in c[1] for c in network.calls)
    before = snapshot.read_bytes()
    from phishtriage.rules import load_rules
    result = evaluation.replay_lookups(snapshot, entries, root, load_rules(), offline_facts)
    assert snapshot.read_bytes() == before  # replay never writes: the snapshot stays frozen
    # The recorded VirusTotal answer changed exactly the phishing email whose link it flagged
    assert [(c["file"], c["offline"], c["with_lookups"]) for c in result["changed"]] == \
        [("a.eml", "Suspicious", "Malicious")]
    assert "REP-002" in result["changed"][0]["findings"] and result["recorded"]


def test_recording_shares_one_rate_limit_across_emails(dataset, monkeypatch):
    root, manifests = dataset
    built = []
    original = Enricher.__init__

    def counting_init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        built.append(self)

    monkeypatch.setattr(Enricher, "__init__", counting_init)
    keyed = Settings(dkim_recheck=False, virustotal_api_key="k", urlscan_api_key="", abuseipdb_api_key="")
    entries = evaluation.entries_for("test", manifests)
    evaluation.record_snapshot(root / "s.sqlite", entries, root, keyed, offline_facts, FakeNetwork(),
                               progress=lambda line: None)
    assert len(built) == 2  # one per kind of email, not one per email
    assert built[0].virustotal.limiter is built[1].virustotal.limiter


def test_recording_and_replay_use_the_same_lookup_budget():
    for local in (Settings(), Settings(virustotal_max_per_email=9, urlscan_max_per_email=5, rdap_max_per_email=1)):
        caps = evaluation.snapshot_settings(local)
        assert (caps.virustotal_max_per_email, caps.urlscan_max_per_email, caps.abuseipdb_max_per_email,
                caps.rdap_max_per_email) == (4, 1, 5, 6)


def test_snapshot_cache_keeps_the_first_answer_and_replay_is_read_only(tmp_path):
    path = tmp_path / "s.sqlite"
    recording = SnapshotCache(path)
    recording.put("virustotal", "url:x", {"first": True})
    recording.put("virustotal", "url:x", {"first": False})  # frozen at first fetch
    recording.set_meta("recorded", "2026-10-22")
    recording.close()
    replay = SnapshotCache(path, read_only=True)
    assert replay.get("virustotal", "url:x", 0) == {"first": True}  # served whatever its age
    replay.put("virustotal", "url:y", {"x": 1})
    assert replay.get("virustotal", "url:y", 10**9) is None and replay.used_today("virustotal") == 0
    assert replay.get_meta("recorded") == "2026-10-22"
    replay.close()
    with pytest.raises(FileNotFoundError):
        SnapshotCache(tmp_path / "missing.sqlite", read_only=True)


def test_domains_only_mode_never_sends_links_or_files():
    raw = make_eml(body='<a href="https://www.news-fake-site.com/private/doc?id=1">doc</a>',
                   content_type="text/html; charset=utf-8", from_="News <news@news-fake-site.com>")
    network = FakeNetwork()
    settings = Settings(dkim_recheck=False, virustotal_api_key="k", urlscan_api_key="k", abuseipdb_api_key="k")
    Enricher(settings, cache=Cache(), http=network, scan_urls=True, domains_only=True).enrich(analyze(raw, OFFLINE))
    assert network.calls and not [c for c in network.calls if "/urls/" in c[1] or "/files/" in c[1] or "urlscan" in c[1]]


def test_cached_facts_are_redone_when_a_fact_library_changes(monkeypatch):
    from phishtriage.rules import report

    before = report._fingerprint(report.offline_settings())
    monkeypatch.setattr(report, "_library_versions", lambda: "python 3.12; pillow 99.0")
    assert report._fingerprint(report.offline_settings()) != before


def test_facts_purge_keeps_the_current_version(tmp_path):
    from phishtriage.rules.report import _fingerprint, offline_settings, purge_facts

    current = tmp_path / _fingerprint(offline_settings())
    stale = tmp_path / "0123456789abcdef"
    for folder in (current, stale):
        folder.mkdir()
        (folder / "x.pickle").write_bytes(b"facts")
    assert purge_facts(folder=tmp_path) == (1, 1) and current.exists() and not stale.exists()
    assert purge_facts(all_versions=True, folder=tmp_path) == (1, 1) and not current.exists()


def test_a_different_scoring_file_is_refused(monkeypatch):
    monkeypatch.setattr(evaluation, "scoring_blob", lambda: "0" * 40)
    assert any("scoring.py" in problem for problem in evaluation.freeze_problems(evaluation.FROZEN_FINGERPRINT))
