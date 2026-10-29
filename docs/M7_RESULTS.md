# M7 results: the held-out test sets

Run on 2026-10-22 18:28 UTC by `phishtriage evaluate run --split test`, commit `e3ca28638db0`, rules `rules-v1.1`. Protocol: `EVALUATION.md`.

Checks passed before any test email was analyzed:

- `scoring.py` is blob `992ce2464798` (rules-v1.1)
- behaviour fingerprint on the development sets is `2ed349b15a66dae8`
- all 266 test emails match the SHA-256 in their manifests
- no uncommitted change to tracked files
- no earlier test run recorded

## Headline (offline: the email alone, no lookups)

| Metric | Result | Target |
|---|---|---|
| Phishing caught (Suspicious or Malicious) | 189 of 204 (92.6%, 95% range 88.2%-95.5%) | at least 90%: **met** |
| Phishing called Malicious | 181 of 204 (88.7%, 95% range 83.7%-92.4%) | reported, no target |
| Legitimate called Malicious (serious false alarm) | 0 of 62 (0.0%, 95% range 0.0%-5.8%) | 0: **met** |
| Legitimate flagged (any false alarm) | 3 of 62 (4.8%, 95% range 1.7%-13.3%) | at most 10%: **met** |

False alarms by mailbox: gmail 0 of 37 flagged, 0 Malicious; university 3 of 25 flagged, 0 Malicious.

## Per campaign (each campaign group counts once)

109 campaign groups. Mean share caught per campaign: **87.6%**. All copies caught: 95; some: 1; none: 13.

## Confusion matrix

| Label | Malicious | Suspicious | No indicators found |
|---|---|---|---|
| phishing | 181 | 8 | 15 |
| legit | 0 | 3 | 59 |

## Precision at assumed shares of phishing in the queue

Precision = share of flagged emails that really are phishing. The range combines the 95% ranges of the detection and false-alarm rates (fewest caught with most false alarms, and the reverse).

| Phishing share | Precision | Range |
|---|---|---|
| 10% | 68.0% | 42.5% – 86.5% |
| 30% | 89.1% | 74.0% – 96.1% |
| 50% | 95.0% | 86.9% – 98.3% |

## With reputation lookups (subset, replayed from a frozen snapshot)

Snapshot recorded 2026-10-22, months after the samples arrived: lookups now know what people reported since, so these numbers flatter the tool (hindsight). Personal emails got domain-level lookups only. Not the headline.

| Subset | Offline | With lookups |
|---|---|---|
| Phishing caught | 38 of 40 | 38 of 40 |
| Legitimate flagged | 3 of 62 | 3 of 62 |
| Lookups missing from the snapshot (counted as not checked) | | 7 |

Verdicts the lookups changed (0):

- none

## Phishing not caught (15)

Causes: one line each, written after the run in `docs/M7_CAUSES.md`, so this file stays exactly as generated (its SHA-256 is in the ledger).

| File | Score | Findings | Cause |
|---|---|---|---|
| sample-12145.eml | 25 | HIDDEN-001+20 LANG-001+20 LEGIT-001-15 | |
| sample-12189.eml | 5 | LINK-006+10 TEXT-002+10 LEGIT-001-15 | |
| sample-12192.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12194.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12199.eml | 25 | HIDDEN-001+20 LANG-001+20 LEGIT-001-15 | |
| sample-12202.eml | 5 | LINK-006+10 TEXT-002+10 LEGIT-001-15 | |
| sample-12203.eml | 20 | LANG-001+20 TIME-001+15 LEGIT-001-15 | |
| sample-12204.eml | 25 | HIDDEN-001+20 LANG-001+20 LEGIT-001-15 | |
| sample-12205.eml | 25 | HIDDEN-001+20 LANG-001+20 LEGIT-001-15 | |
| sample-12214.eml | 20 | LANG-001+20 TIME-001+15 LEGIT-001-15 | |
| sample-12229.eml | 25 | HIDDEN-001+20 LANG-001+20 LEGIT-001-15 | |
| sample-12248.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12249.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12252.eml | 0 | TEXT-003+15 LEGIT-001-15 | |
| sample-12271.eml | 25 | HIDDEN-001+20 LANG-001+20 LEGIT-001-15 | |

## False alarms (3)

| File | Verdict | Score | Findings | Cause |
|---|---|---|---|---|
| uni-024.eml | Suspicious | 60 | BRAND-002+40 BRAND-001+10 LINK-006+10 | |
| uni-046.eml | Suspicious | 35 | BRAND-001+35 | |
| uni-054.eml | Suspicious | 35 | BRAND-001+35 | |

## Environment

Python 3.12.10 on Windows-11-10.0.26200-SP0; dkimpy 1.1.8, dnspython 2.8.0, tldextract 5.4.0, opencv-python-headless 5.0.0.93, pillow 12.3.0, pypdfium2 5.14.0, truststore 0.10.4; bundled snapshot of tldextract 5.4.0.

Limits: `EVALUATION.md` section 6. Injection suite, run at the same commit: `docs/M7_INJECTION_RESULTS.md`.
