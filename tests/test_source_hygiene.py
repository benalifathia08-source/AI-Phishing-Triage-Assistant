"""No invisible or text-reordering characters in our own source code ("Trojan Source"). Tests and rules that need
them write escapes like \\u202e, so a reviewer always sees what the code says."""
from pathlib import Path

from phishtriage.display import is_hidden

ROOT = Path(__file__).resolve().parent.parent


def test_source_files_have_no_hidden_characters():
    found = []
    for folder in ("phishtriage", "scripts", "tests"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                hidden = sorted({f"U+{ord(c):04X}" for c in line if is_hidden(c)})
                if hidden:
                    found.append(f"{path.relative_to(ROOT)}:{number} {', '.join(hidden)}")
    assert not found, found
