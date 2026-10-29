"""Dataset tools: turn a Gmail export into .eml files, and split emails into development and test sets.

Rules are written while looking only at the development sets. The test sets
stay unseen until the final evaluation (M7), so the accuracy numbers measure
how the rules handle email they were not tuned on.

  Phishing   The newest samples form the test set (rules written on last month's
             phishing meet this month's). Copies of one campaign (same subject
             template or same body) always stay together, so the test set holds
             no near-twins of development emails.
  Legitimate Grouped by sender organization, and whole senders are held out, so
             the test set contains senders the rules have never seen.
"""
from __future__ import annotations

import hashlib
import json
import mailbox
import os
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from phishtriage.domains import org_domain
from phishtriage.parser import EmailTooLarge, parse_eml

# Headers Google Takeout adds to every message. They are not part of the email
# as received, and only the legitimate set would have them.
TAKEOUT_HEADERS = (b"x-gm-thrid:", b"x-gmail-labels:")


@dataclass
class Entry:
    file: str  # path relative to the samples folder
    sha256: str
    kind: str  # phishing or legit
    source: str  # phishing_pot, gmail, outlook
    split: str  # dev or test
    group: str  # campaign (phishing) or sender organization (legit)
    order: int = 0  # collection order: the phishing_pot sample number


def strip_takeout_headers(raw: bytes) -> bytes:
    end = min((i for i in (raw.find(b"\r\n\r\n"), raw.find(b"\n\n")) if i >= 0), default=len(raw))
    head, body = raw[:end], raw[end:]
    kept, skipping = [], False
    for line in re.split(rb"(?<=\n)", head):
        if line[:1] in (b" ", b"\t") and skipping:
            continue  # folded continuation of a removed header
        skipping = line.lower().startswith(TAKEOUT_HEADERS)
        if not skipping:
            kept.append(line)
    return b"".join(kept) + body


def split_mbox(mbox_path: Path, out_dir: Path, prefix: str = "gmail") -> int:
    """Write each message of an .mbox file (e.g. from Google Takeout) as its own .eml file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    box = mailbox.mbox(str(mbox_path), create=False)
    count = 0
    try:
        for count, key in enumerate(box.iterkeys(), start=1):
            (out_dir / f"{prefix}-{count:05d}.eml").write_bytes(strip_takeout_headers(box.get_bytes(key)))
    finally:
        box.close()
    return count


def _subject_template(subject: str) -> str:
    subject = re.sub(r"^\s*((re|fwd?|tr|aw)\s*:\s*)+", "", subject.lower())
    return " ".join(re.sub(r"[\d\W_]+", " ", subject).split())


def _body_fingerprint(text: str) -> str:
    # Drop digits, links and spacing so per-victim tokens do not hide copies of one campaign
    normalized = re.sub(r"https?://\S+|\d+|\s+", "", text.lower())[:5000]
    return hashlib.sha1(normalized.encode(), usedforsecurity=False).hexdigest() if len(normalized) > 50 else ""


class _Groups:
    """Union-find: emails sharing any key end up in one group."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def join(self, first: str, second: str) -> None:
        self.parent[self.find(first)] = self.find(second)


def long_path(path: Path) -> Path:
    """Windows refuses paths over 260 characters unless they carry the \\\\?\\ prefix.
    Outlook names downloaded emails after their full subject, which easily goes over."""
    if os.name == "nt" and not str(path).startswith("\\\\?\\"):
        return Path("\\\\?\\" + str(path.resolve()))
    return path


def _read(path: Path):
    raw = long_path(path).read_bytes()
    try:
        return raw, parse_eml(raw)
    except EmailTooLarge:
        return raw, None


def split_phishing(root: Path, folder: str = "phishing_pot/email", test_newest: int = 200) -> list[Entry]:
    groups = _Groups()
    rows = []
    seen: set[str] = set()
    for path in sorted((root / folder).glob("*.eml")):
        raw, parsed = _read(path)
        if hashlib.sha256(raw).hexdigest() in seen:
            continue  # exact duplicate
        seen.add(hashlib.sha256(raw).hexdigest())
        number = int(re.sub(r"\D", "", path.stem) or 0)
        name = path.relative_to(root).as_posix()
        groups.find(name)
        if parsed:
            body = parsed.text_body or re.sub(r"<[^>]+>", " ", parsed.html_body)
            for key in (f"subject:{_subject_template(parsed.subject)}", f"body:{_body_fingerprint(body)}"):
                if not key.endswith(":"):
                    groups.join(name, key)
        rows.append((number, name, hashlib.sha256(raw).hexdigest()))

    rows.sort()
    newest = {name for _, name, _ in rows[-test_newest:]} if test_newest else set()
    test_groups = {groups.find(name) for name in newest}  # a campaign with any new email goes to test whole
    return [Entry(name, sha, "phishing", "phishing_pot", "test" if groups.find(name) in test_groups else "dev",
                  groups.find(name)[:60], number) for number, name, sha in rows]


def legit_sources(root: Path) -> dict[str, str]:
    """Every subfolder of legit/ is one source: gmail, university, outlook..."""
    folder = root / "legit"
    return {sub.name: f"legit/{sub.name}" for sub in sorted(folder.iterdir()) if sub.is_dir()} if folder.is_dir() else {}


def split_legit(root: Path, sources: dict[str, str], test_fraction: float = 1 / 3, seed: str = "phishtriage",
                protected: frozenset[str] = frozenset()) -> list[Entry]:
    entries = []
    seen: set[str] = set()  # content hashes and Message-IDs already taken
    for source, folder in sources.items():
        by_sender: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for path in sorted((root / folder).glob("*.eml")):
            raw, parsed = _read(path)
            # The same email downloaded twice would otherwise risk landing on both sides
            keys = {hashlib.sha256(raw).hexdigest()} | ({parsed.message_id} if parsed and parsed.message_id else set())
            if keys & seen:
                continue
            seen.update(keys)
            address = parsed.sender.address.lower() if parsed and parsed.sender else ""
            domain = org_domain(address.rpartition("@")[2]) if address else ""
            # Inside your own organization every email shares one domain, so group by
            # sending address instead (the IT desk, the e-learning platform, a department).
            key = address if domain and domain in protected else domain or "(no sender)"
            by_sender[key].append((path.relative_to(root).as_posix(), hashlib.sha256(raw).hexdigest()))
        total = sum(len(items) for items in by_sender.values())
        # A fixed pseudo-random order of senders: the same files always give the same split
        order = sorted(by_sender, key=lambda sender: hashlib.sha256(f"{seed}:{sender}".encode()).hexdigest())
        target, in_test = test_fraction * total, 0
        for sender in order:
            # A sender joins the test set only if it fits, so one huge sender (80 LinkedIn
            # emails) cannot fill the whole test set by itself.
            size = len(by_sender[sender])
            split = "test" if in_test + size <= target * 1.25 else "dev"
            in_test += size if split == "test" else 0
            entries += [Entry(name, sha, "legit", source, split, sender) for name, sha in by_sender[sender]]
    return entries


def write_manifest(entries: list[Entry], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(entry) for entry in entries], indent=1) + "\n", encoding="utf-8")


def read_manifest(path: Path) -> list[Entry]:
    return [Entry(**item) for item in json.loads(path.read_text(encoding="utf-8"))]


def summary(entries: list[Entry]) -> str:
    counts = Counter((entry.kind, entry.source, entry.split) for entry in entries)
    lines = [f"{kind:<9} {source:<13} dev {counts[(kind, source, 'dev')]:>4}   test {counts[(kind, source, 'test')]:>4}"
             for kind, source in sorted({(k, s) for k, s, _ in counts})]
    groups = Counter(entry.group for entry in entries)
    lines.append(f"{len(groups)} groups; largest {max(groups.values(), default=0)} emails")
    return "\n".join(lines)
