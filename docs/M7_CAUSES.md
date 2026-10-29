# M7: the cause of every miss and false alarm

Written on 2026-10-22, after the one test run. The run's report is `docs/M7_RESULTS.md`, whose SHA-256 is recorded in `datasets/m7_test_run.json`. That file stays exactly as generated, which is why the causes live here.

Nothing below changed a rule: **rules-v1.1 is the headline**, and any later version can only be an addendum marked as tuned after seeing the test set (EVALUATION.md section 5).

## In short

- **15 phishing emails were missed (of 204).**
  - 12 are German-language prize and casino spam, 2 are French casino spam, and 1 is an English crypto "airdrop". Judging by subject and findings, all 15 are scams; none looks like a credential-phishing lure.
  - **All 15 come from a domain that authenticates**, so LEGIT-001 subtracted 15 points from each.
- **3 legitimate emails were flagged (of 62).** All 3 are university mail, flagged by the brand rules; none was called Malicious.
  - 1 is a genuine Microsoft SharePoint notification: a gap in the brand list.
  - 2 are online-course newsletters that name a partner brand: a limit of the brand-claim rule.

## What the misses have in common

1. **Language.** 12 of the 15 are in German. The text checks cover English and French only, a limit stated before the run (EVALUATION.md section 6). So the prize and money lure goes unseen, and the only text signal is LANG-001 (+20).
2. **Authentication credit (LEGIT-001, −15).** The spammers send from domains they own and authenticate (aligned SPF or DKIM).
   - **LEGIT-001 decided 8 of the 15 misses:** without it they would have reached the Suspicious threshold (30).
   - Across the test sets it fired on 17 phishing and 41 legitimate emails. It kept 1 legitimate email from being flagged.
   - **On the test sets the credit cost 8 catches to save 1 false alarm.**
   - **RULES.md section 7 had already named this rule as the weak spot, before the test run.** On the development sets it changed exactly one verdict, a missed phish, and kept no legitimate email from a stronger verdict. The test run confirms that warning on new data.
3. **No DMARC record.** 7 of those 17 phishing emails come from domains that publish no DMARC policy at all (Microsoft writes `dmarc=bestguesspass`). They earn the credit through aligned SPF or DKIM alone. No legitimate test email does. 5 of the 15 misses are among them.
4. **The newest samples.** The misses cluster among the newest samples (`sample-12145` to `sample-12271`), a wave of German casino spam from throwaway, authenticated domains. This is what the date-based split was meant to test: rules written on older phishing meeting newer phishing.

**The lookups did not rescue any of them.** Two of the misses are in the 40-email lookup subset, and the frozen snapshot changed no verdict there.

## Phishing not caught (15)

Score: the total; Suspicious starts at 30. Findings and points are in `docs/M7_RESULTS.md`.

| File | Score | Cause |
|---|---|---|
| sample-12145.eml | 25 | German prize lure ("8,000 € ready, claim within 48 hours"): the text checks don't read German. 290 hidden words (+20) and LANG-001 (+20) are offset by LEGIT-001 (−15). |
| sample-12189.eml | 5 | French casino bonus: "félicitations" (+10) and a Google Cloud Storage link (+10) are offset by LEGIT-001 (−15). Gambling-bonus words are not in the prize list. |
| sample-12192.eml | 5 | German casino bonus: only LANG-001 (+20) fires; LEGIT-001 (−15). |
| sample-12194.eml | 5 | German casino bonus, same sender domain as 12192: only LANG-001 (+20); LEGIT-001 (−15). |
| sample-12199.eml | 25 | German prize lure: hidden text (+20) and LANG-001 (+20); LEGIT-001 (−15) from a domain with no DMARC record. Without the credit: 40, Suspicious. |
| sample-12202.eml | 5 | French casino bonus, same pattern as 12189. |
| sample-12203.eml | 20 | German prize lure: LANG-001 (+20) and a Date header 128 hours before arrival (+15); LEGIT-001 (−15). Without the credit: 35. |
| sample-12204.eml | 25 | German prize lure, same campaign as 12205: hidden text and LANG-001; LEGIT-001 from a domain with no DMARC record. Without the credit: 40. |
| sample-12205.eml | 25 | Same campaign as 12204, same cause. |
| sample-12214.eml | 20 | German casino bonus, same sender domain as 12203, same cause (LANG-001, TIME-001, LEGIT-001). |
| sample-12229.eml | 25 | German money lure ("selected for 5,000 €, check your details"): hidden text and LANG-001; LEGIT-001 from a domain with no DMARC record. |
| sample-12248.eml | 5 | German casino bonus, same sender domain as 12192: only LANG-001; LEGIT-001. |
| sample-12249.eml | 5 | Same sender domain and cause as 12248. |
| sample-12252.eml | 0 | English crypto airdrop: the crypto mention (TEXT-003, +15) is cancelled by LEGIT-001 (−15). It was sent through a university domain that authenticates, most likely a hijacked account. Authentication proves the domain, not the intent. |
| sample-12271.eml | 25 | German "payment confirmed, 1,500 € tomorrow" lure: hidden text and LANG-001; LEGIT-001 from a domain with no DMARC record. |

## False alarms (3)

Per EVALUATION.md section 8, personal emails are described without sender, subject, link or text.

| File | Verdict | Cause |
|---|---|---|
| uni-024.eml | Suspicious (60) | A genuine SharePoint sharing notification. Microsoft sends these from `sharepointonline.com`, which is missing from Microsoft's domains in `phishtriage/data/brands.toml`. So the "Microsoft" sender name looks like a claim from a foreign domain (BRAND-001), the domain's "sharepoint" keyword looks like a lookalike (BRAND-002), and the link to the university's own SharePoint site counts as file sharing (LINK-006). **A data gap, not a logic error.** |
| uni-046.eml | Suspicious (35) | An online-course platform's newsletter whose sender name and subject name Google, a course partner. BRAND-001 cannot tell "from Google" from "about a Google course". Because a brand claim counts as a disguise, the platform's passing DMARC earns no LEGIT-001 credit. |
| uni-054.eml | Suspicious (35) | The same platform naming Microsoft: same cause as uni-046. |

The development set's false alarms were different (MedTech's Moodle server failing SPF, EVALUATION.md section 6). None of those senders is in the test set, which was split by sender.

## What a later version could try (not done)

These are candidates only. They are to be judged on new data, never on these test sets (RULES.md section 7). Any result is an addendum marked as tuned after seeing the test set.

- **LEGIT-001:**
  - require a real `dmarc=pass` (not aligned SPF or DKIM alone on a domain with no DMARC policy);
  - or skip it when money or prize signals fire;
  - or drop it.
- **Prize and money vocabulary in German, Dutch and Portuguese**, the languages most common in the phishing collection besides English and French.
- **Brand list:** add `sharepointonline.com` to Microsoft. **Brand claims:** treat "<brand> via <platform>"-style course and certificate senders separately.

## Notes on the run

- **Injection suite:** run from commit `5e4644e`. The test run itself is at `e3ca286`. The commits in between changed only the snapshot recorder (`phishtriage/evaluation.py`) and added the injection results. No code the AI or the rules use changed, which is what "run at the same commit" in the results file stands for.
- **Lookup snapshot:** recorded on 2026-10-22 in two passes.
  - In the first pass, the recorder built new rate limiters for every email, and RDAP (domain registration) lookups were refused for going too fast. Refusals are never stored, so nothing wrong was frozen.
  - The limiter was fixed (`eb7fcb3`), and a second pass the same day filled every gap.
  - 7 urlscan.io scans were refused twice (the sites no longer resolve) and count as "not checked".
