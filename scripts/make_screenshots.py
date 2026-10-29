"""Screenshots for the README, from the fake test emails only (never real or personal mail).

The pages are built by the web interface's own code, saved as files next to its stylesheet, and photographed by
Microsoft Edge in headless mode. Needs Edge (standard on Windows) and, for the AI summaries, Ollama with qwen3:4b.

Run: .venv\\Scripts\\python scripts\\make_screenshots.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from phishtriage.ai.client import OllamaClient  # noqa: E402
from phishtriage.config import Settings  # noqa: E402
from phishtriage.isolate import IsolatedAnalyzer  # noqa: E402
from phishtriage.pipeline import Options, triage  # noqa: E402
from phishtriage.web import pages  # noqa: E402

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "injection"
OUTPUT = PROJECT_ROOT / "docs" / "screenshots"
STYLE = PROJECT_ROOT / "phishtriage" / "web" / "static" / "style.css"
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")

# (fixture, screenshot name, window height): one per verdict, plus an injection the AI layer has to survive
SHOTS = [
    ("00-control-no-injection.eml", "report-malicious", 1500),
    ("02-hidden-text.eml", "report-injection", 1500),
    ("26-evasive-control-no-injection.eml", "report-no-indicators", 1100),
]


def photograph(html: str, name: str, height: int, folder: Path) -> Path:
    page = folder / f"{name}.html"
    page.write_text(html.replace('href="/static/style.css"', 'href="style.css"'), encoding="utf-8")
    target = OUTPUT / f"{name}.png"
    subprocess.run([str(EDGE), "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",  # noqa: S603
                    f"--user-data-dir={folder / ('edge-' + name)}", f"--window-size=1280,{height}",
                    f"--screenshot={target}", page.as_uri()], check=True, capture_output=True, timeout=120)
    return target


def main() -> None:
    settings = Settings(dkim_recheck=False)  # no .env: default brands, no organization domains, no keys
    OUTPUT.mkdir(parents=True, exist_ok=True)
    reports = []
    with IsolatedAnalyzer(settings) as analyzer, tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
        folder = Path(temp)
        shutil.copy(STYLE, folder / "style.css")
        for number, (fixture, name, height) in enumerate(SHOTS, 1):
            raw = (FIXTURES / fixture).read_bytes()
            report = triage(raw, fixture, settings, analyzer, Options(ai=True),
                            ai_client_factory=lambda: OllamaClient(settings))
            reports.append((f"r{number}", report))
            print(photograph(pages.report_page(f"r{number}", report, "example"), name, height, folder).name,
                  report.label)
        upload = pages.upload_page("example", list(reversed(reports)), ai_available=True)
        print(photograph(upload, "upload", 900, folder).name)


if __name__ == "__main__":
    main()
