"""Write AI summaries of 10 development emails for Fathia to grade (M6).

Usage: python scripts/make_grading_sheet.py [output.md]   (model: OLLAMA_MODEL, default qwen3:4b)
The same 10 emails every time, so a re-grade after a change compares like with like.
The sheet goes OUTSIDE the repository by default (phishing-samples/ai_summaries_to_grade.md),
because summaries of legitimate emails contain personal details. Development emails only.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from phishtriage.ai.client import OllamaClient
from phishtriage.ai.summary import summarize
from phishtriage.config import Settings
from phishtriage.dataset import read_manifest
from phishtriage.rules import evaluate, load_rules
from phishtriage.rules.report import DEFAULT_MANIFESTS, DEFAULT_ROOT, FactsCache, offline_settings

OUTPUT = DEFAULT_ROOT / "ai_summaries_to_grade.md"
PICK = {"phishing": 6, "gmail": 2, "university": 2}


def choose() -> list:
    """A fixed, varied pick: spread across sources, and always one MedTech Moodle email (uni-005)."""
    entries = [e for m in DEFAULT_MANIFESTS for e in read_manifest(m) if e.split == "dev"]
    order = sorted(entries, key=lambda e: hashlib.sha256(f"grading:{e.file}".encode()).hexdigest())
    chosen = [e for e in entries if e.file.endswith("uni-005.eml")]
    for source, count in PICK.items():
        pool = [e for e in order if (e.source if e.kind == "legit" else "phishing") == source and e not in chosen]
        chosen += pool[: count - sum(1 for c in chosen if (c.source if c.kind == "legit" else "phishing") == source)]
    return chosen


def main(output: Path = OUTPUT) -> None:
    rules, cache = load_rules(), FactsCache(offline_settings())
    client = OllamaClient(Settings.load())
    lines = ["# AI summaries to grade (M6)", "",
             f"Model `{client.model}`. For each email, open the file, read the verdict and the summary, then fill in:",
             "- **Accurate** (1-5): does the summary match the email and the findings?",
             "- **Useful** (1-5): would it help an analyst decide faster?",
             "- **Made up?** (yes/no): does it state anything that is not in the email or the findings?",
             "- **Comment**: anything wrong, missing or badly worded.", "",
             "Only the summary paragraph is written by the AI. The verdict line, the key points and the "
             "\"Not checked\" line are written by code from the rules, so grade the summary paragraph.", ""]
    for number, entry in enumerate(choose(), 1):
        facts = cache.facts(DEFAULT_ROOT / entry.file)
        verdict = evaluate(facts, rules)
        summary = summarize(facts, verdict, client)
        lines += [f"## {number}. `{entry.file}` ({'phishing' if entry.kind == 'phishing' else 'legitimate'})", "",
                  f"**Verdict:** {verdict.label} (score {verdict.score}). Findings: "
                  + (", ".join(f"{f.id} {f.points:+d}" for f in verdict.findings) or "none"), "",
                  f"**Summary** ({'AI' if summary.source == 'ai' else 'built from the findings: ' + '; '.join(summary.problems)}):",
                  "", summary.summary, ""]
        if summary.key_points:
            lines += ["Look at first (from the rules):", ""] + [f"- {point}" for point in summary.key_points] + [""]
        lines.append(summary.coverage)
        if summary.problems and summary.source == "ai":
            lines += ["", "Checks applied: " + "; ".join(summary.problems)]
        lines += ["", "| Accurate (1-5) | Useful (1-5) | Made up? | Comment |", "|---|---|---|---|", "| | | | |", ""]
        print(f"{number}. {entry.file}: {verdict.verdict}, summary from {summary.source}")
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {output}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT)
