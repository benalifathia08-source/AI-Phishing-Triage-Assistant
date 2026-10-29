"""Write docs/MITRE.md: every MITRE ATT&CK technique the scoring rules point to, and which rules detect it.

Run: .venv\\Scripts\\python scripts\\make_mitre_table.py   (tests/test_rules.py checks that the file is current)
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = PROJECT_ROOT / "docs" / "MITRE.md"

# ATT&CK Enterprise tactic of each technique (the names come from MITRE_TECHNIQUES in phishtriage/rules/engine.py,
# which the web interface shows next to each finding)
TACTICS = {
    "Reconnaissance": ["T1598", "T1598.002", "T1598.003", "T1598.004"],
    "Resource Development": ["T1583.001", "T1585.002", "T1608.005"],
    "Initial Access": ["T1566", "T1566.001", "T1566.002", "T1566.003", "T1566.004"],
    "Execution": ["T1204.001", "T1204.002"],
    "Lateral Movement": ["T1534"],
    "Defense Evasion": ["T1027", "T1027.006", "T1036.002", "T1036.007", "T1656"],
}
TACTIC_OF = {technique: tactic for tactic, techniques in TACTICS.items() for technique in techniques}
TACTIC_ORDER = list(TACTICS)


def render() -> str:
    sys.path.insert(0, str(PROJECT_ROOT))
    from phishtriage.rules import load_rules
    from phishtriage.rules.engine import MITRE_TECHNIQUES

    rules = load_rules()
    by_technique: dict[str, list] = defaultdict(list)
    for meta, _ in rules.rules:
        for technique in meta.mitre:
            by_technique[technique].append(meta)
    unknown = sorted(t for t in by_technique if t not in MITRE_TECHNIQUES or t not in TACTIC_OF)
    if unknown:
        raise SystemExit(f"name these in MITRE_TECHNIQUES and TACTICS first: {', '.join(unknown)}")

    def link(technique: str) -> str:
        return f"[{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)"

    lines = [
        "# MITRE ATT&CK mapping",
        "",
        "Generated from the rules by `scripts/make_mitre_table.py`; do not edit by hand. Each scoring rule names the "
        "attacker techniques its evidence points to, and the analyst sees them next to each finding. "
        f"{len(by_technique)} techniques across {len({TACTIC_OF[t] for t in by_technique})} tactics; "
        f"{sum(1 for meta, _ in rules.rules if meta.mitre)} of {len(rules.rules)} rules carry at least one. "
        "The two that carry none (LEGIT-001, LEGIT-002) are signs of legitimacy, not of an attack.",
        "",
        "| Tactic | Technique | Rules (points) |",
        "|---|---|---|",
    ]
    ordered = sorted(by_technique, key=lambda t: (TACTIC_ORDER.index(TACTIC_OF[t]), t))
    for technique in ordered:
        tactic, name = TACTIC_OF[technique], MITRE_TECHNIQUES[technique]
        rule_list = "<br>".join(f"{meta.id} {meta.title} ({meta.points:+d})" for meta in by_technique[technique])
        lines.append(f"| {tactic} | {link(technique)} {name} | {rule_list} |")
    lines += ["", "Rule details, points and the evidence behind each choice: `docs/RULES.md`."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    OUTPUT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(PROJECT_ROOT)}")
