"""Run the offline analysis of an email in a child process, with a time limit.

PDFs (pypdfium2, Chrome's PDF engine) and pictures (OpenCV) are parsed by native code, fed with files an
attacker made. A crash there would take the whole tool down, and a file built to make a parser spin would
block it. So the analysis runs in a separate process: when it does not answer within the time limit, or
dies, the process is killed and replaced, and the email is reported as "analysis failed", never as clean.
The process gets no API keys: it never makes a lookup.
"""
from __future__ import annotations

import multiprocessing
from dataclasses import replace

from phishtriage.analyze import Facts, analyze_offline
from phishtriage.config import Settings
from phishtriage.content import visible_text

STARTUP_TIMEOUT = 120  # seconds to import the parsers in a fresh process (slow disks, antivirus scans)
PREVIEW_CHARACTERS = 20_000  # of the email's visible text, for the analyst to read
PREVIEW_HEADERS = 200


class AnalysisFailed(Exception):
    """The analysis did not finish: a time-out, a crash of the child process, or an error in the code."""


def offline_job(raw: bytes, settings: Settings):
    """What the child runs. Returns the facts; the recipients, whose addresses the URL scanner removes from
    links; and a preview for the analyst: the visible text (never the HTML) and the headers, both bounded."""
    facts, target = analyze_offline(raw, settings)
    shown, _ = visible_text(target.html_body, target.text_body)
    preview = {"text": shown[:PREVIEW_CHARACTERS], "text_truncated": len(shown) > PREVIEW_CHARACTERS,
               "headers": [(name, value[:2000]) for name, value in target.headers[:PREVIEW_HEADERS]]}
    return facts, [address.address for address in target.to + target.cc], preview


def _worker(conn, settings: Settings, job) -> None:
    conn.send(("ready", None))
    while True:
        try:
            raw = conn.recv()
        except (EOFError, OSError):
            return
        try:
            conn.send(("ok", job(raw, settings)))
        except Exception as error:  # noqa: BLE001 - reported to the parent, which decides
            conn.send(("error", f"{type(error).__name__}: {error}"))


class IsolatedAnalyzer:
    """One child process, reused from email to email, and replaced after a time-out or a crash."""

    def __init__(self, settings: Settings, timeout: float | None = None, job=offline_job) -> None:
        self.settings = replace(settings, virustotal_api_key="", urlscan_api_key="", abuseipdb_api_key="")
        self.timeout = float(settings.analysis_timeout if timeout is None else timeout)
        self.job = job  # a top-level function, so that the child can import it
        self._context = multiprocessing.get_context("spawn")  # the same behaviour on Windows, macOS and Linux
        self._process = None
        self._conn = None

    def analyze(self, raw: bytes) -> tuple[Facts, list[str], dict]:
        if self._process is None or not self._process.is_alive():
            self._start()
        try:
            self._conn.send(raw)
            if not self._conn.poll(self.timeout):
                self._stop()
                raise AnalysisFailed(f"the analysis did not finish within {self.timeout:g} seconds and was stopped")
            status, value = self._conn.recv()
        except (EOFError, OSError, BrokenPipeError) as error:
            self._stop()
            raise AnalysisFailed("the analysis process stopped unexpectedly (a parser crashed)") from error
        if status != "ok":
            raise AnalysisFailed(f"the analysis failed with an error: {value}")
        return value

    def _start(self) -> None:
        parent, child = self._context.Pipe()
        self._process = self._context.Process(target=_worker, args=(child, self.settings, self.job), daemon=True,
                                              name="phishtriage-analysis")
        self._process.start()
        child.close()
        self._conn = parent
        if not parent.poll(STARTUP_TIMEOUT) or parent.recv()[0] != "ready":
            self._stop()
            raise AnalysisFailed("the analysis process did not start")

    def _stop(self) -> None:
        if self._process is not None and self._process.is_alive():
            self._process.kill()
        if self._process is not None:
            self._process.join(5)
        if self._conn is not None:
            self._conn.close()
        self._process = self._conn = None

    def close(self) -> None:
        self._stop()

    def __enter__(self) -> IsolatedAnalyzer:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class InProcessAnalyzer:
    """The same interface without a child process: for tests and for code that is already isolated."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def analyze(self, raw: bytes) -> tuple[Facts, list[str], dict]:
        try:
            return offline_job(raw, self.settings)
        except Exception as error:  # noqa: BLE001 - same contract as the isolated analyzer
            raise AnalysisFailed(f"the analysis failed with an error: {type(error).__name__}: {error}") from error

    def close(self) -> None:
        pass
