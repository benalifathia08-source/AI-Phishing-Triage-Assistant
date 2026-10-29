"""The analysis child process: real time-outs, crashes and errors, and the same facts as in-process."""
import os
import time
from dataclasses import replace

import pytest

from phishtriage.config import Settings
from phishtriage.isolate import AnalysisFailed, InProcessAnalyzer, IsolatedAnalyzer, offline_job
from phishtriage.rules import evaluate, load_rules
from tests.helpers import make_eml

SETTINGS = Settings(dkim_recheck=False)
RAW = make_eml(subject="Verify your account within 24 hours", from_="Desk <a@bad.invalidtld>")


# Jobs run in the child: they must be top-level functions so that it can import them
def stalls(raw, settings):
    if raw == b"stall":
        time.sleep(30)
    return offline_job(raw, settings)


def crashes(raw, settings):
    os._exit(3)  # what a native parser crash looks like from outside


def raises(raw, settings):
    raise ValueError("bad input")


def test_isolated_facts_match_in_process():
    with IsolatedAnalyzer(SETTINGS, timeout=60) as analyzer:
        facts, recipients, preview = analyzer.analyze(RAW)
    local_facts, local_recipients, local_preview = InProcessAnalyzer(SETTINGS).analyze(RAW)
    rules = load_rules()
    assert evaluate(facts, rules) == evaluate(local_facts, rules)
    assert recipients == local_recipients == ["analyst@company.test"]
    assert preview == local_preview and "This is a test message." in preview["text"]


def test_a_stalled_parser_is_stopped_and_replaced():
    with IsolatedAnalyzer(SETTINGS, timeout=2, job=stalls) as analyzer:
        start = time.monotonic()
        with pytest.raises(AnalysisFailed, match="did not finish within 2 seconds"):
            analyzer.analyze(b"stall")
        assert time.monotonic() - start < 15
        assert analyzer.analyze(RAW)[0].email.subject == "Verify your account within 24 hours"  # a fresh process


def test_a_crashed_parser_is_reported_not_hidden():
    with IsolatedAnalyzer(SETTINGS, timeout=30, job=crashes) as analyzer:
        with pytest.raises(AnalysisFailed, match="stopped unexpectedly"):
            analyzer.analyze(RAW)


def test_an_error_is_reported_and_the_child_keeps_no_keys():
    with IsolatedAnalyzer(SETTINGS, timeout=30, job=raises) as analyzer:
        with pytest.raises(AnalysisFailed, match="ValueError: bad input"):
            analyzer.analyze(RAW)
    keyed = replace(SETTINGS, virustotal_api_key="secret", urlscan_api_key="secret", abuseipdb_api_key="secret")
    child_settings = IsolatedAnalyzer(keyed).settings
    assert not (child_settings.virustotal_api_key or child_settings.urlscan_api_key or child_settings.abuseipdb_api_key)
