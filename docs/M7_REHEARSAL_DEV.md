# M7 rehearsal on the development sets

Run on 2026-10-22 18:06 UTC by `phishtriage evaluate run --split dev`, commit `99604ecd1a7b`, rules `rules-v1.1`. Protocol: `EVALUATION.md`.

Checks passed before any dev email was analyzed:

- `scoring.py` is blob `992ce2464798` (rules-v1.1)
- behaviour fingerprint on the development sets is `2ed349b15a66dae8`
- all 384 dev emails match the SHA-256 in their manifests

## Headline (offline: the email alone, no lookups)

| Metric | Result | Target |
|---|---|---|
| Phishing caught (Suspicious or Malicious) | 267 of 296 (90.2%, 95% range 86.3%-93.1%) | at least 90%: **met** |
| Phishing called Malicious | 215 of 296 (72.6%, 95% range 67.3%-77.4%) | reported, no target |
| Legitimate called Malicious (serious false alarm) | 0 of 88 (0.0%, 95% range 0.0%-4.2%) | 0: **met** |
| Legitimate flagged (any false alarm) | 4 of 88 (4.5%, 95% range 1.8%-11.1%) | at most 10%: **met** |

False alarms by mailbox: gmail 0 of 52 flagged, 0 Malicious; university 4 of 36 flagged, 0 Malicious.

## Per campaign (each campaign group counts once)

197 campaign groups. Mean share caught per campaign: **86.5%**. All copies caught: 169; some: 3; none: 25.

## Confusion matrix

| Label | Malicious | Suspicious | No indicators found |
|---|---|---|---|
| phishing | 215 | 52 | 29 |
| legit | 0 | 4 | 84 |

## Precision at assumed shares of phishing in the queue

Precision = share of flagged emails that really are phishing. The range combines the 95% ranges of the detection and false-alarm rates (fewest caught with most false alarms, and the reverse).

| Phishing share | Precision | Range |
|---|---|---|
| 10% | 68.8% | 46.3% – 85.3% |
| 30% | 89.5% | 76.9% – 95.7% |
| 50% | 95.2% | 88.6% – 98.1% |

## Phishing not caught (29)

Causes: one line each, written after the run in `docs/M7_CAUSES.md`, so this file stays exactly as generated (its SHA-256 is in the ledger).

| File | Score | Findings | Cause |
|---|---|---|---|
| sample-43.eml | -15 | LEGIT-001-15 | |
| sample-456.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-535.eml | -5 | TEXT-002+10 LEGIT-001-15 | |
| sample-575.eml | 10 | SENDER-001+25 LEGIT-001-15 | |
| sample-770.eml | -15 | LEGIT-001-15 | |
| sample-925.eml | -5 | LINK-006+10 LEGIT-001-15 | |
| sample-1176.eml | -15 | LEGIT-001-15 | |
| sample-2524.eml | -15 | LEGIT-001-15 | |
| sample-3313.eml | 10 | TEXT-003+15 TEXT-002+10 LEGIT-001-15 | |
| sample-3502.eml | -15 | LEGIT-001-15 | |
| sample-5014.eml | 0 | TIME-001+15 LEGIT-001-15 | |
| sample-5414.eml | -15 | LEGIT-001-15 | |
| sample-5474.eml | 0 | TEXT-003+15 LEGIT-001-15 | |
| sample-6272.eml | 10 | TIME-001+15 LINK-006+10 LEGIT-001-15 | |
| sample-6366.eml | 0 | TEXT-003+15 LEGIT-001-15 | |
| sample-6617.eml | 10 | TIME-001+15 LINK-006+10 LEGIT-001-15 | |
| sample-8264.eml | -5 | TEXT-002+10 LEGIT-001-15 | |
| sample-11189.eml | 20 | AUTH-001+20 | |
| sample-11884.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-11907.eml | 10 | TEXT-003+15 LINK-006+10 LEGIT-001-15 | |
| sample-11984.eml | 20 | COMBO-004+20 TEXT-001+15 LEGIT-001-15 | |
| sample-11989.eml | -15 | LEGIT-001-15 | |
| sample-11996.eml | 0 | TEXT-003+15 LEGIT-001-15 | |
| sample-11997.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12000.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12004.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12005.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12008.eml | 5 | LANG-001+20 LEGIT-001-15 | |
| sample-12073.eml | -15 | LEGIT-001-15 | |

## False alarms (4)

| File | Verdict | Score | Findings | Cause |
|---|---|---|---|---|
| uni-005.eml | Suspicious | 40 | AUTH-005+25 AUTH-001+15 AUTH-002+0 AUTH-004+0 | |
| uni-006.eml | Suspicious | 40 | AUTH-005+25 AUTH-001+15 AUTH-002+0 AUTH-004+0 | |
| uni-019.eml | Suspicious | 40 | AUTH-005+25 AUTH-001+15 AUTH-003+0 AUTH-002+0 | |
| uni-023.eml | Suspicious | 35 | ATTACH-007+35 | |

## Environment

Python 3.12.10 on Windows-11-10.0.26200-SP0; dkimpy 1.1.8, dnspython 2.8.0, tldextract 5.4.0, opencv-python-headless 5.0.0.93, pillow 12.3.0, pypdfium2 5.14.0, truststore 0.10.4; bundled snapshot of tldextract 5.4.0.

Limits: `EVALUATION.md` section 6. Injection suite, run at the same commit: `docs/M7_INJECTION_RESULTS.md`.
