"""One email from bytes to report: isolated analysis, optional lookups, rules, optional AI summary.

Shared by the web interface and the batch command. The order is the security design in miniature:
the rules decide before the AI runs, and a failed analysis is reported as a failure, never as clean.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, UTC

from phishtriage.analyze import Facts
from phishtriage.config import Settings
from phishtriage.isolate import AnalysisFailed
from phishtriage.rules import Verdict, evaluate, load_rules

FAILED = "Analysis failed"


@dataclass
class Options:
    lookups: bool = False  # VirusTotal, AbuseIPDB and RDAP lookups (indicators leave the computer)
    scan: bool = False  # urlscan.io private scans: its servers visit the links
    ai: bool = False  # the local AI summary


@dataclass
class Report:
    filename: str
    sha256: str
    size: int
    options: Options
    analyzed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    facts: Facts | None = None
    verdict: Verdict | None = None
    summary: object | None = None  # AISummary when the AI ran
    error: str = ""  # why the analysis failed ('' when it did not)
    seconds: float = 0.0
    preview: dict = field(default_factory=dict, repr=False)  # visible text and headers, for the page only, never exported

    @property
    def failed(self) -> bool:
        return bool(self.error)

    @property
    def label(self) -> str:
        return FAILED if self.failed else self.verdict.label


_RULES = None


def _rules():
    global _RULES
    if _RULES is None:
        _RULES = load_rules()
    return _RULES


def triage(raw: bytes, filename: str, settings: Settings, analyzer, options: Options | None = None,
           enricher_factory=None, ai_client_factory=None) -> Report:
    """`analyzer` is an IsolatedAnalyzer (or InProcessAnalyzer in tests). The factories build an Enricher
    and an OllamaClient only when the options ask for them, so nothing leaves the computer by default."""
    options = options or Options()
    start = time.monotonic()
    report = Report(filename, hashlib.sha256(raw).hexdigest(), len(raw), options)
    try:
        facts, recipients, report.preview = analyzer.analyze(raw)
    except AnalysisFailed as error:
        report.error = str(error)
        report.seconds = round(time.monotonic() - start, 1)
        return report
    if options.lookups and enricher_factory is not None:
        facts.enrichment = enricher_factory(options.scan).enrich(facts, recipients=recipients)
    report.facts = facts
    report.verdict = evaluate(facts, _rules())  # decided before any AI runs
    if options.ai and ai_client_factory is not None:
        from phishtriage.ai.summary import summarize

        report.summary = summarize(facts, report.verdict, ai_client_factory())
    report.seconds = round(time.monotonic() - start, 1)
    return report


def default_factories(settings: Settings):
    """The real Enricher and OllamaClient, imported only when used."""
    def enricher(scan: bool):
        from phishtriage.enrich import Enricher

        return Enricher(settings, scan_urls=scan)

    def ai_client():
        from phishtriage.ai.client import OllamaClient

        return OllamaClient(settings)

    return enricher, ai_client
