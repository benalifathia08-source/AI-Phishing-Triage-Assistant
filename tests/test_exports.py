"""Exports, the batch command and the cache retention."""
import csv
import io
import time
from dataclasses import replace

from phishtriage import batch, exports
from phishtriage.config import Settings
from phishtriage.display import defang, visible
from phishtriage.enrich.cache import Cache, purge_expired
from phishtriage.isolate import AnalysisFailed, InProcessAnalyzer
from phishtriage.pipeline import Options, triage
from tests.helpers import make_eml

SETTINGS = Settings(dkim_recheck=False)


def test_display_helpers():
    assert defang("see https://login.example.net/a and mail a@evil.example") == \
        "see hxxps://login[.]example[.]net/a and mail a@evil[.]example"
    assert defang("version 2.5, e.g. this") == "version 2.5, e.g. this"
    assert visible("invoice\u202efdp.exe\u200b") == "invoice[U+202E]fdp.exe[U+200B]"
    assert visible("line one\nline\ttwo") == "line one\nline\ttwo"


def test_markdown_code_spans_cannot_break_out():
    assert exports.code("a `tick` here") == "``a `tick` here``"
    assert exports.code("`edge`") == "`` `edge` ``"
    assert exports.code("![x](https://exfil.example/?d=1)") == "`![x](hxxps://exfil[.]example/?d=1)`"
    assert exports.code("invoice.pdf.exe", defanged=False) == "`invoice.pdf.exe`"


def test_csv_cells_never_start_a_formula():
    text = exports.write_csv([{"a": '=HYPERLINK("x")', "b": "+1", "c": "@SUM(A1)", "d": "-1", "e": "safe"}],
                             ["a", "b", "c", "d", "e"])
    row = list(csv.reader(io.StringIO(text)))[1]
    assert row == ["'=HYPERLINK(\"x\")", "'+1", "'@SUM(A1)", "'-1", "safe"]


def test_report_exports():
    raw = make_eml(body='<a href="https://login.evil.example/x">https://www.paypal.com</a> Verify your account',
                   content_type="text/html; charset=utf-8", from_="PayPal <service@evil.example>",
                   subject="Verify your account")
    report = triage(raw, "case.eml", SETTINGS, InProcessAnalyzer(SETTINGS))
    rows = exports.iocs(report)
    assert {"type": "url", "value": "https://login.evil.example/x", "defanged": "hxxps://login[.]evil[.]example/x",
            "context": "link (html:a)"} in rows
    markdown = exports.report_markdown(report)
    assert markdown.startswith(f"# Phishing triage: {report.label}") and "hxxps://login[.]evil[.]example/x" in markdown
    data = exports.report_json(report)
    assert data["label"] == report.label and data["facts"]["email"]["subject"] == "Verify your account"
    assert "preview" not in data  # the email's text is shown on the page, never exported


class Flaky(InProcessAnalyzer):
    def analyze(self, raw):
        if b"broken" in raw:
            raise AnalysisFailed("the analysis process stopped unexpectedly (a parser crashed)")
        return super().analyze(raw)


def test_batch_reports_every_email_and_goes_on_after_a_failure(tmp_path):
    (tmp_path / "a.eml").write_bytes(make_eml(subject="hello"))
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.eml").write_bytes(make_eml(subject="broken"))
    out, details = io.StringIO(), io.StringIO()
    rows = batch.run([tmp_path], SETTINGS, Flaky(SETTINGS), Options(), out, details)
    assert [row["label"] for row in rows] == ["No indicators found", "Analysis failed"]
    assert "a parser crashed" in rows[1]["error"]
    assert len(details.getvalue().splitlines()) == 2 and out.getvalue().startswith("file,sha256,label")
    assert batch.summary_line(rows) == "2 email(s): 1 Analysis failed, 1 No indicators found"


def test_cache_retention(tmp_path):
    path = tmp_path / "cache.sqlite"
    settings = replace(SETTINGS, cache_path=path, cache_retention_days=30)
    assert purge_expired(settings) == 0 and not path.exists()  # never creates the cache
    cache = Cache(path)
    cache.put("virustotal", "old", {"x": 1})
    cache._db.execute("UPDATE results SET fetched = ?", (time.time() - 31 * 86400,))
    cache._db.commit()
    cache.put("virustotal", "new", {"x": 2})
    assert cache.stats()["virustotal"][0] == 2
    cache.close()
    assert purge_expired(settings) == 1
    cache = Cache(path)
    assert cache.get("virustotal", "new", 86400) == {"x": 2} and cache.get("virustotal", "old", 10**9) is None
    assert b"old" not in path.read_bytes()  # overwritten and compacted, not left in the file
    cache.close()
