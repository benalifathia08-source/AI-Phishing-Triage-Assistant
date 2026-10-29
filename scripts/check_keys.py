"""Check that the API keys in .env work, without ever printing them.

Usage: python scripts/check_keys.py
Costs 1 VirusTotal lookup and 1 AbuseIPDB check. The urlscan.io check is free.
"""
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
TEST_IP = "8.8.8.8"  # Google public DNS: a well-known, harmless lookup target


def load_env(path):
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip().strip("\"'")
    return values


def get_json(url, headers):
    request = urllib.request.Request(url, headers={**headers, "Accept": "application/json"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - fixed https API URLs only
        return json.load(response)


def check_virustotal(key):
    get_json(f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}", {"x-apikey": key})
    return "lookup worked"


def check_urlscan(key):
    quotas = get_json("https://urlscan.io/user/quotas/", {"API-Key": key})
    limits = quotas.get("limits", {})
    parts = []
    for scan_type in ("private", "unlisted", "public"):
        day = limits.get(scan_type, {}).get("day", {})
        if "limit" in day:
            parts.append(f"{scan_type} scans {day.get('remaining', '?')}/{day['limit']} left today")
    return "key accepted" + (" (" + ", ".join(parts) + ")" if parts else "")


def check_abuseipdb(key):
    get_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={TEST_IP}", {"Key": key})
    return "lookup worked"


CHECKS = [
    ("VirusTotal", "VIRUSTOTAL_API_KEY", check_virustotal),
    ("urlscan.io", "URLSCAN_API_KEY", check_urlscan),
    ("AbuseIPDB", "ABUSEIPDB_API_KEY", check_abuseipdb),
]


def main():
    if not ENV_FILE.exists():
        print(f"No .env file at {ENV_FILE}. Copy .env.example to .env and add your keys.")
        return 1

    env = load_env(ENV_FILE)
    failures = 0
    for service, variable, check in CHECKS:
        key = env.get(variable, "")
        if not key:
            result = f"FAIL  {variable} is empty in .env"
        else:
            try:
                result = f"OK    {check(key)}"
            except urllib.error.HTTPError as error:
                reason = {401: "key rejected", 403: "key rejected", 429: "rate limit reached, try again later"}
                result = f"FAIL  HTTP {error.code}: {reason.get(error.code, 'unexpected answer')}"
            except urllib.error.URLError as error:
                result = f"FAIL  network problem: {error.reason}"
        failures += result.startswith("FAIL")
        print(f"{service:<11} {result}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
