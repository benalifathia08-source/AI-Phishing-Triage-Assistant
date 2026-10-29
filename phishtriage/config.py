"""Settings from environment variables, with the project's .env file as a fallback."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            values[name.strip()] = value.strip().strip("\"'")
    return values


def _int(values: dict, name: str, default: int) -> int:
    try:
        return int(values.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Server IDs of YOUR receiving mail servers, e.g. "mx.google.com". Empty means
    # trust the top-most Authentication-Results header (needed for Microsoft 365,
    # which writes no server ID).
    trusted_authserv_ids: frozenset[str] = frozenset()
    dkim_recheck: bool = True

    # API keys are excluded from repr() so they never appear in logs or tracebacks.
    virustotal_api_key: str = field(default="", repr=False)
    urlscan_api_key: str = field(default="", repr=False)
    abuseipdb_api_key: str = field(default="", repr=False)

    urlscan_visibility: str = "private"  # private or unlisted; public is never used
    urlscan_daily_scans: int = 50  # free account: 50 private scans a day
    virustotal_max_per_email: int = 4  # the free per-minute limit, so one email never waits
    urlscan_max_per_email: int = 2
    abuseipdb_max_per_email: int = 5
    rdap_max_per_email: int = 6
    cache_path: Path = PROJECT_ROOT / ".cache" / "enrichment.sqlite"
    # Lookup results name the links and senders of the emails analyzed, so they are not kept forever.
    cache_retention_days: int = 30
    # The offline analysis runs in a child process (PDF and picture parsers are native code fed with
    # attacker-made files) and is stopped after this many seconds. Lookups are not counted.
    analysis_timeout: int = 60
    # Your organization's own domains: lookalikes of these are the core of BEC.
    protected_domains: frozenset[str] = frozenset()
    brands_file: str = str(PROJECT_ROOT / "phishtriage" / "data" / "brands.toml")
    # Local AI (Ollama). Email content is personal data, so a non-local server is refused
    # unless AI_ALLOW_REMOTE=yes is set on purpose.
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:4b"
    ai_timeout: int = 180
    ai_allow_remote: bool = False

    @classmethod
    def load(cls, env_file: Path = PROJECT_ROOT / ".env") -> Settings:
        values = {**read_env_file(env_file), **os.environ}  # real environment variables win
        server_ids = values.get("TRUSTED_AUTHSERV_IDS", "")
        return cls(
            trusted_authserv_ids=frozenset(item.strip().lower() for item in server_ids.split(",") if item.strip()),
            dkim_recheck=values.get("DKIM_RECHECK", "on").strip().lower() not in ("off", "0", "false", "no"),
            virustotal_api_key=values.get("VIRUSTOTAL_API_KEY", ""),
            urlscan_api_key=values.get("URLSCAN_API_KEY", ""),
            abuseipdb_api_key=values.get("ABUSEIPDB_API_KEY", ""),
            urlscan_visibility=values.get("URLSCAN_VISIBILITY", "private").strip().lower(),
            urlscan_daily_scans=_int(values, "URLSCAN_DAILY_SCANS", 50),
            virustotal_max_per_email=_int(values, "VIRUSTOTAL_MAX_PER_EMAIL", 4),
            urlscan_max_per_email=_int(values, "URLSCAN_MAX_PER_EMAIL", 2),
            protected_domains=frozenset(item.strip().lower() for item in values.get("PROTECTED_DOMAINS", "").split(",")
                                        if item.strip()),
            brands_file=values.get("BRANDS_FILE") or str(PROJECT_ROOT / "phishtriage" / "data" / "brands.toml"),
            ollama_host=values.get("OLLAMA_HOST") or "http://127.0.0.1:11434",
            ollama_model=values.get("OLLAMA_MODEL") or "qwen3:4b",
            ai_timeout=_int(values, "AI_TIMEOUT", 180),
            cache_retention_days=_int(values, "CACHE_RETENTION_DAYS", 30),
            analysis_timeout=_int(values, "ANALYSIS_TIMEOUT", 60),
            ai_allow_remote=values.get("AI_ALLOW_REMOTE", "").strip().lower() in ("yes", "true", "1"),
        )
