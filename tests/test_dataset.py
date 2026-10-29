import mailbox

from phishtriage.dataset import legit_sources, split_legit, split_mbox, split_phishing, strip_takeout_headers
from tests.helpers import make_eml


def test_takeout_headers_are_removed():
    raw = (b"X-GM-THRID: 1234\r\nX-Gmail-Labels: Inbox,triage-legit,\r\n Category Updates\r\n"
           b"From: a@example.com\r\nSubject: hi\r\n\r\nX-Gmail-Labels: stays in the body\r\n")
    assert strip_takeout_headers(raw) == b"From: a@example.com\r\nSubject: hi\r\n\r\nX-Gmail-Labels: stays in the body\r\n"


def test_split_mbox(tmp_path):
    box = mailbox.mbox(str(tmp_path / "export.mbox"))
    for n in range(3):
        box.add(b"X-GM-THRID: 1\nX-Gmail-Labels: triage-legit\n" + make_eml(subject=f"Message {n}").replace(b"\r\n", b"\n"))
    box.close()
    assert split_mbox(tmp_path / "export.mbox", tmp_path / "out") == 3
    files = sorted((tmp_path / "out").glob("*.eml"))
    assert [f.name for f in files] == ["gmail-00001.eml", "gmail-00002.eml", "gmail-00003.eml"]
    assert b"X-Gmail-Labels" not in files[0].read_bytes()
    assert b"Subject: Message 0" in files[0].read_bytes()


def test_phishing_split_keeps_campaigns_together(tmp_path):
    folder = tmp_path / "phishing_pot" / "email"
    folder.mkdir(parents=True)
    subjects = {1: "Old campaign A", 2: "Your parcel 123 is waiting", 3: "Old campaign B", 4: "Unique newer one",
                5: "Your parcel 987 is waiting", 6: "Newest one"}
    for number, subject in subjects.items():
        (folder / f"sample-{number}.eml").write_bytes(make_eml(subject=subject, body=f"Body {subject}"))
    entries = {e.file.rsplit("/", 1)[-1]: e for e in split_phishing(tmp_path, test_newest=2)}
    assert entries["sample-6.eml"].split == entries["sample-5.eml"].split == "test"
    # sample-2 is old, but the same campaign as sample-5 ("your parcel ... is waiting"): it follows it into test
    assert entries["sample-2.eml"].split == "test"
    assert entries["sample-1.eml"].split == entries["sample-3.eml"].split == entries["sample-4.eml"].split == "dev"


def test_legit_split_holds_out_whole_senders(tmp_path):
    folder = tmp_path / "legit" / "gmail"
    folder.mkdir(parents=True)
    for n in range(30):
        sender = f"news@mail.shop{n % 6}.example"  # six organizations, five emails each
        (folder / f"gmail-{n:05d}.eml").write_bytes(make_eml(from_=f"Sender <{sender}>", subject=f"Issue {n}"))
    for n in range(40):  # one huge sender
        (folder / f"gmail-big-{n:03d}.eml").write_bytes(make_eml(from_="Jobs <jobs@social.example>", subject=f"Job {n}"))
    entries = split_legit(tmp_path, {"gmail": "legit/gmail"})
    assert {e.split for e in entries if e.group == "social.example"} == {"dev"}  # too big for the test set
    by_sender = {}
    for entry in entries:
        by_sender.setdefault(entry.group, set()).add(entry.split)
    assert all(len(splits) == 1 for splits in by_sender.values())  # no sender on both sides
    assert 15 <= sum(e.split == "test" for e in entries) <= 30  # about a third of 70
    assert entries == split_legit(tmp_path, {"gmail": "legit/gmail"})  # same files, same split


def test_duplicates_are_skipped(tmp_path):
    folder = tmp_path / "legit" / "university"
    folder.mkdir(parents=True)
    email = make_eml(from_="Library <library@univ.example>", subject="Opening hours")
    (folder / "a.eml").write_bytes(email)
    (folder / "a (1).eml").write_bytes(email)  # downloaded twice
    assert len(split_legit(tmp_path, legit_sources(tmp_path))) == 1


def test_own_organization_is_grouped_by_sending_address(tmp_path):
    folder = tmp_path / "legit" / "university"
    folder.mkdir(parents=True)
    senders = ["it-desk", "elearning", "registrar", "library", "events", "dean"]
    for n in range(36):
        sender = f"{senders[n % 6]}@univ.example"
        (folder / f"uni-{n:03d}.eml").write_bytes(make_eml(from_=f"Univ <{sender}>", subject=f"Notice {n}"))
    assert legit_sources(tmp_path) == {"university": "legit/university"}
    entries = split_legit(tmp_path, legit_sources(tmp_path), protected=frozenset({"univ.example"}))
    assert len({e.group for e in entries}) == 6  # six senders, not one organization
    assert {e.split for e in entries} == {"dev", "test"}
    without = split_legit(tmp_path, legit_sources(tmp_path))
    assert {e.split for e in without} == {"dev"}  # as one huge group it could never reach the test set
