"""Run the AI summary on every development email and count what the code checks did (M6 quality audit).

Usage: python scripts/audit_summaries.py [details.jsonl]   (model: OLLAMA_MODEL, default qwen3:4b)
       python scripts/audit_summaries.py --recheck [details.jsonl]
--recheck needs no model: it re-applies the current code checks to the raw answers saved by an earlier run,
so a change to the checks can be measured on exactly the same answers.

Ten graded summaries cannot show how often a check misfires; this run can. It prints aggregate counts only.
Per-email details (the model's raw answer, what was shown, what the checks did) go OUTSIDE the repository by
default (phishing-samples/ai_summary_audit.jsonl), because summaries of legitimate emails hold personal data.
Development emails only: the test sets stay unseen until M7.
"""
from __future__ import annotations

import json
import re
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

from phishtriage.ai.client import OllamaClient, parse_json
from phishtriage.ai.summary import check_output, summarize
from phishtriage.config import Settings
from phishtriage.dataset import read_manifest
from phishtriage.rules import evaluate, load_rules
from phishtriage.rules.report import DEFAULT_MANIFESTS, DEFAULT_ROOT, FactsCache, offline_settings

OUTPUT = DEFAULT_ROOT / "ai_summary_audit.jsonl"


def _kind(problem: str) -> str:
    """'removed 2 sentences no finding supports (a; b)' -> one count per reason; other problems as they are."""
    match = re.match(r"removed \d+ sentences? no finding supports \((.*)\)$", problem)
    if match:
        return "; ".join(f"sentence removed: {reason}" for reason in match.group(1).split("; "))
    return problem.split(":")[0] if problem.startswith(("AI unavailable", "AI summary rejected")) else problem


def main(output: Path = OUTPUT) -> None:
    rules, cache = load_rules(), FactsCache(offline_settings())
    client = OllamaClient(Settings.load())
    entries = [e for m in DEFAULT_MANIFESTS for e in read_manifest(m) if e.split == "dev"]
    counts: dict[str, Counter] = {"phishing": Counter(), "legit": Counter()}
    seconds, words = [], []
    start = time.monotonic()
    with output.open("w", encoding="utf-8") as details:
        for number, entry in enumerate(entries, 1):
            facts = cache.facts(DEFAULT_ROOT / entry.file)
            verdict = evaluate(facts, rules)
            summary = summarize(facts, verdict, client)
            count = counts[entry.kind]
            count["emails"] += 1
            count[f"shown from {summary.source}"] += 1
            for problem in summary.problems:
                for kind in _kind(problem).split("; "):
                    count[kind] += 1
            if summary.source == "ai":
                words.append(len(summary.summary.split()))
            seconds.append(summary.seconds)
            details.write(json.dumps({"file": entry.file, "kind": entry.kind, "verdict": verdict.label,
                                      "source": summary.source, "shown": summary.summary, "problems": summary.problems,
                                      "raw": summary.raw_output}, ensure_ascii=False) + "\n")
            if number % 50 == 0:
                print(f"{number}/{len(entries)} done", flush=True)
    print(f"\nModel {client.model}, {len(entries)} development emails, {time.monotonic() - start:.0f} s "
          f"(median {statistics.median(seconds):.1f} s per summary); AI summaries average {statistics.mean(words):.0f} words\n")
    keys = sorted(set(counts["phishing"]) | set(counts["legit"]), key=lambda k: (k != "emails", k))
    print(f"{'':<80} {'phishing':>9} {'legit':>6}")
    for key in keys:
        print(f"{key:<80} {counts['phishing'][key]:>9} {counts['legit'][key]:>6}")
    print(f"\nPer-email details: {output}")


def recheck(details: Path = OUTPUT) -> None:
    rules, cache = load_rules(), FactsCache(offline_settings())
    counts: dict[str, Counter] = {"phishing": Counter(), "legit": Counter()}
    changed = 0
    for line in details.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        facts = cache.facts(DEFAULT_ROOT / row["file"])
        verdict = evaluate(facts, rules)
        count = counts[row["kind"]]
        count["emails"] += 1
        answer = parse_json(row["raw"]) or {}
        if not isinstance(answer.get("summary"), str):
            count["shown from rules"] += 1  # no usable answer, as in the original run
            continue
        summary, problems, rejected = check_output(answer["summary"], verdict, facts.email.subject)
        problems += [f"AI summary rejected: {rejected}"] if rejected else []
        count[f"shown from {'rules' if rejected else 'ai'}"] += 1
        for problem in problems:
            for kind in _kind(problem).split("; "):
                count[kind] += 1
        changed += (problems != row["problems"])
    print(f"Current checks re-applied to the saved answers in {details} ({changed} emails differ from the saved run)\n")
    keys = sorted(set(counts["phishing"]) | set(counts["legit"]), key=lambda k: (k != "emails", k))
    print(f"{'':<80} {'phishing':>9} {'legit':>6}")
    for key in keys:
        print(f"{key:<80} {counts['phishing'][key]:>9} {counts['legit'][key]:>6}")


if __name__ == "__main__":
    arguments = [a for a in sys.argv[1:] if a != "--recheck"]
    path = Path(arguments[0]) if arguments else OUTPUT
    recheck(path) if "--recheck" in sys.argv else main(path)
