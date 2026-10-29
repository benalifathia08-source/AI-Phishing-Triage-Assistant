# Evaluation protocol

This file fixes **how the tool will be judged before anyone sees a test result**. Changing it after the test run would make the numbers meaningless, so any later change is dated and explained.

Status: **approved by Fathia on 2026-10-11, with the conditions in section 4.** Clarified on 2026-10-22, before any test result existed (section 8).

## 1. Datasets

| Set | Source | Development | Test | Notes |
|---|---|---|---|---|
| Phishing | [`rf-peixoto/phishing_pot`](https://github.com/rf-peixoto/phishing_pot) at commit `89e2bc0`: the 400 newest samples plus 100 random older ones | 296 | 204 | Split listed in `datasets/phishing_pot_split.json` |
| Legitimate: Gmail | Fathia's personal Gmail (a Takeout label plus 3 downloads), received by Google | 52 | 37 | Personal mail: the file list stays outside the repository |
| Legitimate: university | Fathia's university Microsoft 365 mailbox (MedTech / SMU), received by Microsoft; 2020–2026 | 36 | 25 | Includes internal mail, PDFs, zip files, invites and shares |
| **Total legitimate** | | **88** | **62** | |

**How the sets were split**
- **Phishing, by date.** The 200 newest samples (by sample number, which follows collection order) form the test set, so rules written on older phishing meet newer phishing. Copies of one campaign stay together: emails sharing a subject template or a body (after removing numbers and links) form one group, and a group with any member in the test set goes there whole. That moved 4 older samples into the test set (204 in total) and leaves no near-twin of a test email in development.
- **Legitimate, by sender.** Emails are grouped by sender organization and whole senders are held out (about a third of the emails). The test set therefore contains senders the rules have never seen. A sender too large to fit is kept in development, so one sender cannot fill the test set. Inside the university (the domains in `PROTECTED_DOMAINS`), emails are grouped by sending address instead, since they all share one domain. Duplicate downloads are skipped.
- Both splits are deterministic: the same files always give the same split (`phishtriage dataset split`).

## 2. What counts as correct

The tool gives one of three verdicts: **Malicious**, **Suspicious**, **No indicators found**.

**A phishing email counts as caught when the verdict is Suspicious or Malicious.** A triage tool's job is to put a dangerous email in front of an analyst instead of letting it through; "Suspicious" does exactly that. It is also the right verdict for the spam and scams in phishing_pot, which are unwanted but not always phishing. How many are called Malicious is reported separately, so a tool that only ever says "Suspicious" cannot hide behind the definition. In the same way, a legitimate email counts as **flagged** (a false alarm) when it gets Suspicious or Malicious.

- Every phishing_pot sample is **unwanted** (phishing, scam or spam) and should be caught. Some samples are spam rather than phishing, and Suspicious is an acceptable verdict for them. The headline does not try to separate the two.
- Every legitimate email should get **No indicators found**. Suspicious on a legitimate email is a false alarm, and Malicious is a serious false alarm.
- Labels are frozen before the test run. If a "legitimate" email later turns out to be unwanted (for example spam kept in the inbox), it is still counted as a false alarm, with a note.

## 3. What is measured

| Metric | On | Why |
|---|---|---|
| **Detection rate**: share of phishing flagged | phishing test set | Does it catch phishing? |
| **Malicious rate**: share of phishing called Malicious | phishing test set | How decisive is it? |
| **False-alarm rate**: share flagged, and share called Malicious | legitimate test set | Does it bother analysts with good mail? |
| **Per-campaign detection**: each campaign group counts once | phishing test set | One campaign with 29 copies must not dominate |
| Precision at assumed phishing shares of 10%, 30% and 50% | both test sets | Real report queues are mostly benign; precision depends on that share |
| Injection suite: verdict changes, and summaries contradicting the verdict | M6 test emails | The AI must not be steerable by the email |

**Offline numbers are the headline.** Rules see only the email itself, with no VirusTotal, urlscan.io, AbuseIPDB or domain-age lookups. Three reasons:
1. **Hindsight.** These samples are months old. VirusTotal now knows many of their domains are bad because people reported them after the emails arrived. Lookups today would inflate detection.
2. **Reproducibility.** Lookup answers change daily; the offline result does not.
3. **Quota.** About 900 emails × 4 lookups is roughly a week of the free VirusTotal quota.

Lookups are evaluated separately on a subset, from a frozen, dated cache, and labelled as such.

## 4. Targets (approved by Fathia on 2026-10-11)

Conditions attached to the approval:
1. **Counts with confidence ranges, not bare percentages.** The legitimate test set has 62 emails, so each false alarm moves the rate by 1.6 points. Every result is reported as a count with its 95% Wilson range: for example, 0 false alarms out of 62 means "at most about 6%".
2. **No rule changes after the test results are seen.** The frozen version's result (`rules-v1.1`, section 5) is the headline, whatever it is.
3. **"Caught" means Suspicious or Malicious** (section 2), with the Malicious count reported alongside.
4. **The limits in section 6 are stated** with the results.

| Metric | Target |
|---|---|
| Caught: phishing test set, 204 emails | **at least 184** (90%) |
| Serious false alarms: legitimate called Malicious | **0 of 62** |
| Any false alarm: legitimate flagged | **at most 6 of 62** (about 10%) |
| Injection suite: verdict changed by the email's content | **0** (guaranteed by design: code sets the verdict) |
| Injection suite: summary contradicts the verdict without being caught | **0** |

Rules are tuned on the development sets until they meet these targets there. Meeting them on development says little; the test run is what counts.

## 5. Procedure

1. Rules are tuned using the development sets only.
2. The rule set is frozen with a git tag before the test run.
   - **`rules-v1`, 2026-10-19**, after Fathia's approval: `phishtriage/rules/scoring.py` is git blob `992ce24647984321d8e77a1ac12b1d610997eead`.
   - **`rules-v1.1`, 2026-10-20**, approved by Fathia before any test run: rules-v1 plus one fact-code fix. The prize pattern matched "you won't"; all 3 development matches were false. `scoring.py` is unchanged (same blob). On the development sets no verdict changed: `uni-005` went from score 50 to 40 (still Suspicious), and one legitimate email lost its "Low risk" display label. **rules-v1.1 is the version the test run measures.**
   - **The M7 run must check both before it starts:** the `scoring.py` blob above, and the **behaviour fingerprint** printed on the last line of `phishtriage rules report`, which must be **`2ed349b15a66dae8`**. The fingerprint is a hash of every development verdict, score and finding. It covers what the file check cannot: the fact code, the brand list and library versions also decide verdicts (added 2026-10-20, approved by Fathia). rules-v1's fingerprint was `168b056b90241b5d`.
3. The test sets are run once. Results are reported as they come out, together with every miss and false alarm and a one-line cause for each (Fathia's investigation).
4. Rules are not changed after the test results are seen. If a later version is ever made, `rules-v1.1` stays the headline, and the later version's numbers are only an addendum marked as tuned after seeing the test set.

## 6. Known limits (stated in the results)

- **Little BEC, no QR codes.** Only 7 of the 500 phishing samples have neither links nor attachments, and none contains a QR code. Rules for business email compromise and QR phishing are tested with fake examples, and no accuracy is claimed for them.
- **Mass phishing, not targeted.** phishing_pot comes from honeypot mailboxes: mass campaigns, not spear phishing aimed at a company.
- **Languages.** Text checks cover English and French. In the development set, 84 of 296 phishing emails (28%) are in neither language (mostly Dutch, German and Portuguese).
- **Sample redaction.** The collection's maintainer replaced victim addresses, which breaks DKIM body hashes and puts `phishing@pot` inside some URLs. DKIM re-check results are not used on this corpus.
- **Receiving server.** 499 of 500 phishing samples were received by Microsoft (Outlook.com); the legitimate set is 89 Gmail-received and 61 Microsoft-received emails. Measured on development: Microsoft's `compauth` result appears in 55% of phishing, 0% of Gmail mail and 28% of university mail. Rules must not use receiver-specific headers like it, or they would learn "Microsoft headers mean phishing".
- **One person's mailboxes.** The legitimate set is one person's personal Gmail and university mail, not a company's. Business mail (supplier invoices, partners) may raise false alarms that this set cannot show.
- **Narrow senders.** The Gmail senders are mostly job, cybersecurity and gaming services, so other kinds of newsletters and shops are under-represented.
- **Older university mail.** The university emails span 2020 to 2026, and old ones may carry signatures whose keys have since changed.
- **Few attachments.** The legitimate set has few real attachments (14 PDFs, 5 zip files and 1 HTML file, all in university mail) and almost none in Gmail, so false alarms on attachments are weakly tested.
- **Known, explained case: MedTech's Moodle server fails SPF.** Three genuine Moodle notifications in the development set (`uni-005`, `uni-006`, `uni-019`) claim `medtech.tn`, arrive from the internet and fail SPF with no DMARC pass, exactly like spoofing. Fathia confirmed they are genuine; they stay in the legitimate set. If the tool flags them (or similar Moodle emails in the test set), they count as false alarms, reported with this explanation. It is also a finding worth passing to MedTech's IT team.
- **Hidden text is common on both sides.** Measured on development: some hidden text in 66% of phishing but also 75% of Gmail mail (newsletters hide a preview line). More than 200 hidden words separates better: 53% of phishing, 13% of Gmail mail and 3% of university mail.

## 7. Privacy of the legitimate set

- The emails stay on the laptop, outside the repository; only aggregate numbers are published.
- They are analysed without urlscan.io scans or VirusTotal URL lookups, so personal links never reach those services.
- The facts extracted from them are cached in `.cache/facts/` to make rule tuning fast. The cache is git-ignored and stays on the laptop. The purge command is `phishtriage cache purge --facts` (added 2026-10-22).
- Screenshots and examples in the write-up use fake emails only.

## 8. Clarifications before the test run (2026-10-22)

Sections 3, 5 and 7 left some details open. They are fixed here before any test email is analyzed. They were set on 2026-10-22, when the M7 run was approved.

**Per-campaign detection (section 3)**
- The figure is the **mean share caught per campaign**. Take each campaign group in the phishing test set, compute the share of its copies that were caught, then average over the groups. Every campaign weighs the same, however many copies it has.
- It is reported with the number of campaigns that were fully, partly and not caught.
- The per-email Wilson ranges treat every email as independent. Copies of one campaign are not, so those ranges are somewhat too narrow; the per-campaign figure is the check on that.

**The lookup subset (section 3)**
- **Phishing:** 40 test emails, one per campaign group.
  - The rule is fixed in code (`lookup_subset`): groups are taken in SHA-256 order of their names, with the first email of each by SHA-256.
  - Each email gets VirusTotal (up to 4 lookups), one private urlscan.io scan, AbuseIPDB and RDAP.
- **Legitimate:** all 62 test emails, domain level only: VirusTotal domains, RDAP, and AbuseIPDB for the sending server. No URL, file or scan (section 7).
- **The answers are recorded once into a frozen snapshot** (`phishing-samples/m7_lookup_snapshot.sqlite`, outside the repository, never purged) with its recording date.
  - The run replays it read-only and offline. A lookup the snapshot lacks counts as "not checked", never fetched.
  - If a free quota runs out during recording, the recording resumes the next day and both dates are stated.
- **This result is secondary.** It is labelled as hindsight (section 3), with every verdict the lookups changed.

**The injection suite (section 3)**
- It is re-run at the commit the test run measures: the 29 emails of `tests/fixtures/injection/`, `qwen3:4b` (the default), with the naive comparison.
- Report: `docs/M7_INJECTION_RESULTS.md`. Targets as in section 4.

**The run (section 5)**
- `phishtriage evaluate run --split test --confirm-test-run` refuses to start unless all of these hold:
  - the frozen `scoring.py` blob and behaviour fingerprint, checked before any test email is read;
  - no uncommitted change;
  - every email matches its manifest SHA-256;
  - no earlier run is recorded.
- **The ledger** `datasets/m7_test_run.json` records the date, commit, fingerprint and the SHA-256 of the results file.
- **A run that stops before writing results may be restarted.** Any output that was seen counts as the run.
- **The results file stays exactly as generated.** The one-line causes of every miss and false alarm (section 5, step 3) go in `docs/M7_CAUSES.md`.

**Personal mail in the results (section 7)**
- Legitimate emails are published as counts, plus the false alarms the protocol requires to be listed.
- Those false alarms are listed under neutral file names (`uni-NNN`, `gmail-NNNNN`) with rule IDs and points only. No sender, subject, link or text is published.

## 9. Found after the test run (2026-10-22, M8)

- **Fixed: the behaviour fingerprint did not cover library versions.** Section 5 says it does, but the facts it hashes came from a cache keyed on our own code only. A library update would have reused facts computed with the old library. The cache key now includes the versions of every library that extracts facts.
- **M7 is not affected.** Every fact library was installed on 2026-10-08, before the first facts were cached (2026-10-11), and none changed until after the test run. So the facts behind M7's freeze check were computed with M7's exact versions.
- **Security updates after M7.** pip-audit found 35 known vulnerabilities in Pillow 12.3.0, the library that decodes the images inside emails, and 1 in certifi.
  - Both were updated (Pillow 13.0.0, certifi 2026.10.19).
  - Image decoding is now limited to PNG, JPEG, GIF, BMP and WebP.
  - On freshly computed facts, the behaviour fingerprint is unchanged (`2ed349b15a66dae8`). The shipped version gives the same verdict, score and findings on every development email as the version M7 measured.
- **The published `scoring.py` differs from the frozen file by one comment line** (2026-10-29): line 3 of its header comment was shortened. Its blob is therefore `fc15639a4ea8d580212e6eb5ce9a5dbf847ec666` instead of `992ce24647984321d8e77a1ac12b1d610997eead`. No code, rule or point changed, so verdicts are identical. The M7 run checked the frozen file.
