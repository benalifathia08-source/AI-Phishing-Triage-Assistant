"""Triage many emails: `phishtriage batch FOLDER [--out results.csv] [--details results.jsonl]`.

Each email goes through the same isolated pipeline as the web interface, so one hostile file that crashes
or stalls a parser is reported as "Analysis failed" and the batch goes on. Offline by default.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from phishtriage import exports
from phishtriage.dataset import long_path
from phishtriage.pipeline import Options, triage

COLUMNS = ["file", "sha256", "label", "verdict", "score", "findings", "error", "seconds"]


def email_files(paths: list[Path]) -> list[Path]:
    files = []
    for path in paths:
        files += sorted(path.rglob("*.eml")) if path.is_dir() else [path]
    return files


def row(path: Path, report) -> dict:
    return {
        "file": str(path), "sha256": report.sha256, "label": report.label,
        "verdict": "" if report.failed else report.verdict.verdict,
        "score": "" if report.failed else report.verdict.score,
        "findings": "" if report.failed else " ".join(f"{f.id}{f.points:+d}" for f in report.verdict.findings),
        "error": report.error, "seconds": report.seconds,
    }


def run(paths: list[Path], settings, analyzer, options: Options, out=None, details=None,
        enricher_factory=None, ai_client_factory=None, progress=None) -> list[dict]:
    """Returns one row per email; writes the CSV to `out` and full JSON lines to `details` when given."""
    rows = []
    files = email_files(paths)
    for number, path in enumerate(files, 1):
        try:
            raw = long_path(path).read_bytes()
        except OSError as error:
            rows.append({"file": str(path), "label": "Unreadable", "error": str(error)})
            continue
        report = triage(raw, path.name, settings, analyzer, options, enricher_factory, ai_client_factory)
        rows.append(row(path, report))
        if details is not None:
            details.write(json.dumps({"path": str(path), **exports.report_json(report)}, ensure_ascii=False,
                                     default=str) + "\n")
        if progress:
            progress(f"{number}/{len(files)} {report.label:<40} {path.name}")
    if out is not None:
        out.write(exports.write_csv(rows, COLUMNS))
    return rows


def summary_line(rows: list[dict]) -> str:
    counts: dict[str, int] = {}
    for item in rows:
        counts[item["label"].split(" (")[0]] = counts.get(item["label"].split(" (")[0], 0) + 1
    return f"{len(rows)} email(s): " + ", ".join(f"{count} {label}" for label, count in sorted(counts.items()))


def main(paths: list[Path], settings, options: Options, out_path: Path | None, details_path: Path | None,
         timeout: float | None) -> int:
    from phishtriage.isolate import IsolatedAnalyzer
    from phishtriage.pipeline import default_factories

    enricher_factory, ai_client_factory = default_factories(settings)
    out = out_path.open("w", encoding="utf-8-sig", newline="") if out_path else sys.stdout
    details = details_path.open("w", encoding="utf-8") if details_path else None
    try:
        with IsolatedAnalyzer(settings, timeout) as analyzer:
            rows = run(paths, settings, analyzer, options, out, details, enricher_factory, ai_client_factory,
                       progress=lambda line: print(line, file=sys.stderr))
    finally:
        if out_path:
            out.close()
        if details:
            details.close()
    print(summary_line(rows), file=sys.stderr)
    return 0
