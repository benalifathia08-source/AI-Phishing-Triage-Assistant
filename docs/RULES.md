# Scoring rules: choices, decisions and best practices

Rule set **v1.1 (frozen)**, in [`phishtriage/rules/scoring.py`](../phishtriage/rules/scoring.py). Written on 2026-10-19, approved and frozen by Fathia as `rules-v1` the same day; `rules-v1.1` (2026-10-20) adds one fact fix and no rule change (section 7). It has **not been run on the test sets**; that happens once, at M7 (see [EVALUATION.md](../EVALUATION.md)).

## 1. Summary

- **58 rules in 16 categories**: authentication, sender, reply path, brand impersonation, links, attachments, QR codes, text, hidden text, AI manipulation, language, timing, conversation tricks, combinations, evidence of legitimacy, and reputation lookups.
- Every rule returns an **evidence sentence** for the analyst, carries **MITRE ATT&CK** techniques, and has a **test** (`tests/test_scoring.py`, one firing case per rule plus precision guards).
- Results on the **development sets only** (offline, the headline mode):

| | Result | 95% range | Target (test sets) |
|---|---|---|---|
| Phishing caught (Suspicious or Malicious) | **267 of 296** (90.2%) | 86.3%–93.1% | at least 90% |
| …of which Malicious | 215 of 296 | | reported alongside |
| Legitimate called Malicious | **0 of 88** | 0.0%–4.2% | 0 |
| Legitimate flagged at all | **4 of 88** (4.5%) | 1.8%–11.1% | at most 10% |

These numbers are **optimistic by construction**: the rules were tuned while looking at these emails. Only the test run counts, and its range could reasonably fall anywhere around 86–93% for phishing.

## 2. How a verdict is made

1. Each rule that fires adds its **points**. Negative points are evidence of legitimacy.
2. **Category caps** stop correlated signs from piling up. For example, the authentication rules together add at most 40.
3. The total gives the verdict: **Suspicious from 30, Malicious from 70.**
4. A rule with a **floor** forces at least that verdict, whatever the score. Floors are only for evidence that is decisive on its own.
5. A rule that cannot judge returns **UNKNOWN**. The report lists it as "not checked"; it never counts as clean.

**Point scale**, fixed before any tuning:

| Points | Meaning |
|---|---|
| 40 | Decisive on its own; usually also a floor |
| 30–35 | Strong: one such sign makes the email Suspicious |
| 20–25 | Medium: needs a second sign |
| 10–15 | Weak: only counts together with others |
| −15 / −20 | Evidence of legitimacy |

**Why 30 and 70.** Suspicious means "an analyst should look", so one strong sign, or a medium and a weak one, is enough. Malicious means "act without waiting for an analyst", so it needs either several independent signs or one decisive one. The thresholds were set before the first test run and never moved, so the tuning could not fit them to the data.

## 3. Best practices followed

### 3.1 Evidence first, from the development sets only
Every frequent rule is backed by how often its fact appears in development phishing versus development legitimate mail (the comparison table in section 10). The test sets were never opened: the report command refuses them, and every statistic in this document comes from development emails.

### 3.2 Points from judgment, checked against evidence
Points were chosen by security judgment, in the tiers above, then compared with a **smoothed likelihood ratio** from the development sets:

> evidence points = 20 × log10( (phishing hits + 1)/(296 + 2) ÷ (legitimate hits + 1)/(88 + 2) )

A rule was moved only when judgment and evidence disagreed by more than one tier, and then by one tier only:
- **LANG-001** went from 15 to 20 (evidence +27);
- **TIME-001** went from 10 to 15 (evidence +20).

Two limits of this check are deliberate:
- **Rare rules:** with only 88 legitimate emails, a rule that never fires on them can at best reach a modest ratio. For rare rules (brand impersonation, lookalike characters, attachments) judgment decides.
- **Correlated rules:** the "no DMARC policy" rule scores +27 on its own, but fires on the same emails as the other authentication rules, so its evidence is double-counted. It stays at 10, and the authentication cap handles the overlap.

### 3.3 Correlated signs are capped
SPF fail, "not authenticated" and "no DMARC policy" usually describe one underlying fact. Without a cap, a sloppy but legitimate sender would collect 45 points from authentication alone. The caps are:

| Category | Cap |
|---|---|
| Authentication | 40 |
| Text | 30 |
| Links | 45 |
| Sender | 50 |
| Reply path | 30 |
| Brand | 50 |

Evidence of legitimacy is never capped.

### 3.4 Authentication proves the domain, not the honesty
This is the most important decision in the rule set. SPF, DKIM and DMARC prove *which domain* sent the email, and attackers can authenticate domains they own. The first draft gave −15 to every authenticated email. That cancelled real deception signs: an email showing "PayPal" from an authenticated `random-shop.example` scored 35 − 15 = 20, and was missed.

**Rule adopted:** authentication (LEGIT-001), and internal origin (LEGIT-002), count as legitimacy **only when nothing disguises the sender**. That means no brand impersonation, no lookalike sender domain or characters, no name showing another address, no reply-to elsewhere, no shared-platform sender, and no fake reply. Effects on the development sets:
- LEGIT-001's hits on phishing fell from 60 to 28, and on legitimate mail from 61 to 60.
- **Measured in isolation**, with the final rules run with and without this condition: phishing caught goes from 253 to 267 (85.5% to 90.2%), and legitimate mail stays at 0 Malicious and 4 flagged. It is the single largest improvement in the rule set, at no cost in false alarms.

### 3.5 Never score what the receiving server writes
Microsoft's `compauth` appears in 55% of the phishing samples, 0% of Gmail mail and 28% of university mail. It describes *which server received the email*, so a rule using it would learn "Microsoft-received means phishing". Rules do not read `compauth`, `exchange_auth_as` or `authserv_id`, and the report warns if one does. The `internal` fact is used, because it describes the *sender's* origin. It only lowers suspicion, and never raises it.

### 3.6 Headers that describe the wrong person are ignored, not trusted
In an **inline forward**, the headers belong to the colleague who forwarded the email, not to the original sender. So every header-based rule returns UNKNOWN for inline forwards, including the negative ones: a colleague's internal, authenticated forward of a phish must not earn legitimacy credit. **Internal mail** often carries no SPF/DKIM result at all (64% of university emails), so the "not authenticated" rules skip internal mail.

### 3.7 Unknown is not clean
Lookups that did not run, a DKIM re-check that was switched off, or missing authentication results make a rule say UNKNOWN. The report lists these as "not checked". An email is never called clean because a check was skipped.

### 3.8 Floors only for decisive evidence
These rules force **Malicious**, because legitimate mail essentially never does any of them:
- executables, disk images or configuration profiles attached (ATTACH-001);
- an attached web page asking for a password (ATTACH-003) or building a file (ATTACH-004);
- a lookalike of your own organization's domain (BRAND-003);
- hidden instructions to an AI (AI-001);
- strong reputation hits (REP-001, REP-003).

These force only **Suspicious**, because legitimate exceptions exist and a human should decide:
- macros (ATTACH-005), risky files inside an archive (ATTACH-007) and disguised file types (ATTACH-008);
- dangerous link types (LINK-004);
- your own domain arriving unauthenticated from outside (AUTH-005): MedTech's Moodle does exactly this;
- the BEC money pattern (COMBO-002);
- a link or domain flagged by VirusTotal (REP-002).

### 3.9 Combinations where the whole says more than the parts
- "Asks for credentials" is weak alone (15), but asking for credentials with a deceptive link (COMBO-001), or with links to another organization than the sender (COMBO-004), is the shape of credential phishing.
- "Bank details changed" with a free-mail or foreign reply path is the shape of BEC (COMBO-002).
- A brand claim without authentication (COMBO-003) is likewise worse than either sign.

### 3.10 Precision guards
Each rule that could plausibly fire on normal mail has a guard, and a test proves the guard holds:

| Rule | Guard |
|---|---|
| LINK-001 | Ignores newsletter click trackers |
| LINK-006 | Ignores internal SharePoint shares |
| TEXT-007 | Ignores plain "open the attachment" (only macros or passwords count) |
| ATTACH-008 | Ignores a logo saved with the wrong picture extension |
| COMBO-004 | Ignores links to the sender's own organization |
| LANG-001 | Ignores "unknown" (too little text to tell) |
| AI-002 | Visible AI instructions stay weak (15), because security newsletters quote such phrases |

### 3.11 Knowledge-based rules for threats the data lacks
The public collection has almost no business email compromise, QR phishing, macros or HTML smuggling, and no AI-injection attempts. Rules for these exist because they are among the most common real threats. They are marked "knowledge" in the catalogue below, tested with fake examples only, and **no accuracy is claimed for them**.

### 3.12 Explainable, mapped, tested
- Every rule returns a sentence an analyst can check: for example "claims to be Coinbase but sends from panfluterivera.com", not just "BRAND-001".
- Every positive rule carries MITRE ATT&CK techniques: T1566.x phishing, T1598.x phishing for information, T1656 impersonation, T1583.001 lookalike domains, T1036.002/.007 masquerading, T1027.006 HTML smuggling.
- Every rule has a test.

### 3.13 Stop tuning early
Tuning stopped at the first version that met the development targets. The margin is thin, at 90.2% against 90%, and that is accepted: every further tweak would fit these 296 particular emails rather than phishing in general. The three iterations are listed in section 6.

## 4. Rule catalogue

"Dev" columns count development emails where the rule fires: phishing out of 296, legitimate out of 88. Basis: **evidence** means the development data supports it; **knowledge** means security practice, because the threat is rare or absent in the data.

### Authentication (cap 40)
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| AUTH-001 From domain not authenticated | +20 | | 235 | 3 | evidence | No DMARC pass and no aligned SPF/DKIM: nothing ties the email to the domain it shows. Skips internal mail and inline forwards |
| AUTH-002 SPF fails | +15 | | 156 | 3 | evidence | The domain says this server may not send for it |
| AUTH-003 DMARC fails | +20 | | 7 | 1 | knowledge + evidence | The domain owner's own policy rejects the email: the clearest spoofing signal authentication gives |
| AUTH-004 No DMARC policy | +10 | | 223 | 2 | evidence | Throwaway domains rarely publish DMARC; real bulk senders must (Gmail and Yahoo rules since 2024). Kept low because it overlaps AUTH-001 |
| AUTH-005 Own domain from outside, unauthenticated | +25 | Suspicious | 0 | 3 | knowledge | Spoofing your own domain is a BEC classic. It fires on MedTech's Moodle (genuine), hence Suspicious and not Malicious |
| AUTH-006 DKIM broke after signing | +25 | | 0 | 0 | knowledge | The content was changed in transit. Not used on phishing_pot, whose redaction breaks signatures |

### Sender (cap 50)
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| SENDER-001 Invalid sender domain | +25 | | 60 | 0 | evidence | Domains like `muhbdrtdtbniig` cannot belong to a real organization |
| SENDER-002 Shared-platform sender | +30 | | 149 | 0 | evidence | `evil.onmicrosoft.com` is a free tenant anyone can create. Real organizations send from their own domain |
| SENDER-003 Lookalike or invisible characters | +30 | | 19 | 0 | evidence + knowledge | Bold Unicode, mixed alphabets or invisible selectors ("Co<invisible>inbase") are always deliberate |
| SENDER-004 Name shows another address | +25 | | 0 | 0 | knowledge | `"support@bank.example" <x@evil.example>` is classic display-name spoofing |

### Reply path (cap 30)
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| REPLY-001 Replies go to another organization | +20 | | 67 | 1 | evidence | Answers are diverted to the attacker |
| REPLY-002 Replies to free mail, sender is not | +15 | | 6 | 0 | knowledge + evidence | The BEC classic: the "company" email answers to a Gmail address |

### Brand impersonation (cap 50)
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| BRAND-001 Claims a brand it does not send from | +35 | | 14 | 0 | evidence + knowledge | "Microsoft account team" from `plugandplay.co.id` |
| BRAND-002 Sender's domains imitate a brand | +40 | | 1 | 0 | knowledge | Typos, confusable letters, brand inside another domain |
| BRAND-003 Imitates your own domain | +40 | Malicious | 0 | 0 | knowledge | Cousin domains of your own organization exist only to deceive your staff |
| BRAND-004 A link's domain imitates a brand | +30 | | 0 | 0 | knowledge | The fake login page |

### Links (cap 45)
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| LINK-001 Link text names another site | +25 | | 4 | 1 | knowledge + evidence | Shows `zalando.nl`, goes to `emailservicesnetau.com`. Click trackers excluded; the 1 legitimate hit is Notion linking `notion.com` text to `notion.so` |
| LINK-002 Real host hidden after @ | +35 | | 4 | 0 | knowledge | `https://hotmail.com-...@176.189.202.64...` really goes to the IP |
| LINK-003 Link to a bare IP | +25 | | 2 | 0 | knowledge | Legitimate services use names |
| LINK-004 Dangerous link type | +40 | Suspicious | 0 | 0 | knowledge | `data:` (HTML smuggling), `javascript:`, `file:`, Windows handlers such as `search-ms:` |
| LINK-005 URL shortener | +10 | | 9 | 0 | evidence | Hides the destination; legitimate senders occasionally use them too |
| LINK-006 Free hosting or file sharing (external) | +10 | | 11 | 0 | evidence | Phishing pages live on `web.app`, `pages.dev`, SharePoint… so do legitimate files |
| LINK-007 Unusual port | +10 | | 0 | 0 | knowledge | Throwaway servers |
| LINK-008 Lookalike characters in a host | +15 | | 1 | 0 | knowledge | Punycode and mixed alphabets |

### Attachments (no cap: each is a separate file risk)
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| ATTACH-001 Executable, disk image, configuration profile | +40 | Malicious | 1 | 0 | knowledge + evidence | No business sends programs by email. It caught the hidden Apple profiles that VirusTotal rated clean |
| ATTACH-002 HTML or SVG attachment | +25 | | 0 | 0 | knowledge | A local copy of a phishing page |
| ATTACH-003 Attached page asks for a password | +40 | Malicious | 0 | 0 | knowledge | Credential harvesting inside the attachment |
| ATTACH-004 HTML smuggling or decoded code | +40 | Malicious | 0 | 0 | knowledge | Builds a malicious file inside the browser to slip past scanners |
| ATTACH-005 Macros | +35 | Suspicious | 0 | 0 | knowledge | Still a common malware route; some businesses use macros legitimately |
| ATTACH-006 Password-protected archive | +30 | | 0 | 0 | knowledge | Hides its content from scanners |
| ATTACH-007 Risky files inside an archive | +35 | Suspicious | 0 | 1 | knowledge | `.js`, `.exe`, `.lnk` in a zip is how much malware arrives. The 1 legitimate hit is a university zip holding JavaScript (accepted, see section 7) |
| ATTACH-008 Disguised file type | +35 | Suspicious | 0 | 0 | knowledge | `invoice.pdf` that is really HTML, `scan.pdf.exe`, right-to-left override |
| ATTACH-009 Password-protected PDF | +15 | | 0 | 0 | knowledge | Evades scanning; legitimate payslips do it too |

### Other content
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| QR-001 QR code found | +20 | | 0 | 1 | knowledge | Quishing moves the link out of reach of link scanners. Legitimate mail carries QR codes too (1 university email here), hence medium and never alone |
| TEXT-001 Asks for credentials | +15 | | 14 | 0 | evidence | |
| TEXT-002 Pressure (deadline ≤ 72 h, threat, prize, delivery) | +10 | | 107 | 5 | evidence | Common in marketing too, hence weak |
| TEXT-003 Money (payment, bank change, gift cards, crypto) | +15 | | 17 | 0 | evidence | |
| TEXT-004 CEO-fraud tone | +15 | | 0 | 0 | knowledge | "Are you available?", "keep this confidential" |
| TEXT-005 Asks to phone a number | +15 | | 0 | 0 | knowledge | Callback phishing (T1566.004); needs both the phrase and a number |
| TEXT-006 Asks to scan a QR code | +10 | | 0 | 0 | knowledge | |
| TEXT-007 Enable macros or attachment password | +15 | | 0 | 0 | knowledge | |
| HIDDEN-001 More than 200 hidden words | +20 | | 157 | 8 | evidence | Spam "salting". Any hidden text is useless (75% of newsletters); the threshold makes it useful |
| AI-001 Hidden instructions to an AI | +40 | Malicious | 0 | 0 | knowledge | Hiding instructions for an AI is intent to deceive |
| AI-002 Visible instructions to an AI | +15 | | 0 | 0 | knowledge | Weak, because security newsletters quote such phrases |
| LANG-001 Language your organization does not use | +20 | | 73 | 0 | evidence | Set by `EXPECTED_LANGUAGES = ("en", "fr", "ar")` for a Tunisian organization. Change it for another |
| TIME-001 Send time more than 2 h from arrival | +15 | | 33 | 0 | evidence | Forged or batch-queued Date headers. Real mail arrives within minutes, but clocks can be wrong, hence weak |
| THREAD-001 Fake reply | +15 | | 4 | 0 | knowledge + evidence | "RE:" with no earlier email fakes an existing conversation |

### Combinations
| Rule | Points | Floor | Dev phish | Dev legit | Basis | Why |
|---|---|---|---|---|---|---|
| COMBO-001 Credentials + deceptive link | +25 | | 0 | 0 | knowledge | The shape of credential phishing |
| COMBO-002 Money request + untrustworthy reply path or sender | +30 | Suspicious | 9 | 0 | knowledge + evidence | The shape of BEC; the action says to confirm by phone |
| COMBO-003 Brand claim + not authenticated | +15 | | 5 | 0 | knowledge | |
| COMBO-004 Credentials + links to another organization | +20 | | 11 | 0 | knowledge | Genuine account notices link to their own domain |

### Evidence of legitimacy
| Rule | Points | Dev phish | Dev legit | Why |
|---|---|---|---|---|
| LEGIT-001 Authenticated, and the sender is not disguised | −15 | 28 | 60 | See 3.4 |
| LEGIT-002 Internal, and the sender is not disguised | −20 | 0 | 19 | Internal phishing from compromised accounts exists, so the credit is moderate and floors still apply |

### Reputation (only when lookups ran; not part of the offline headline)
| Rule | Points | Floor | Why |
|---|---|---|---|
| REP-001 VirusTotal: ≥ 3 engines flag an attachment | +40 | Malicious | File detections are reliable |
| REP-002 VirusTotal: ≥ 3 engines flag a link or domain | +30 | Suspicious | Domain detections are noisier |
| REP-003 urlscan.io: malicious | +40 | Malicious | A sandbox saw the page |
| REP-004 AbuseIPDB ≥ 75% | +15 | | Large providers' IPs carry reports too, hence weak and a high threshold |
| REP-005 A domain registered in the last 30 days | +25 | | Phishing domains are usually days old |

## 5. Signals deliberately not used

Numbers are development phishing / Gmail / university.

| Signal | Numbers | Why not |
|---|---|---|
| Return-Path to another organization | 26% / 31% / 0% | Newsletters do it more than phishing does |
| Message-ID from another organization | 88% / 56% / 75% | Common everywhere |
| Any hidden text | 66% / 75% / 22% | Newsletters hide a preview line; replaced by the 200-word threshold |
| Mostly images | 9% / 27% / 0% | Points the wrong way |
| Phone number alone | 2% / 2% / 25% | Email signatures; only counts with a "call us" phrase |
| Recipients hidden (Bcc) | 3% / 0% / 8% | Announcements are Bcc'd |
| Free-mail sender alone | 2% / 6% / 3% | Ordinary people use free mail; only counts inside combinations |
| Inline forward | 0% / 0% / 11% | A note for the analyst, not a sign of phishing |
| `compauth`, `exchange_auth_as`, `authserv_id` | 55% / 0% / 28% (`compauth`) | They describe the receiving server (3.5) |
| Brand named only in the subject | 1% / 0% / 3% | Newsletters write about brands |

## 6. Tuning log (development sets only)

| Draft | Change | Caught | Legit Malicious | Legit flagged |
|---|---|---|---|---|
| 1 | 55 rules from judgment and the comparison table | 246 / 296 (83.1%) | 0 / 88 | 4 / 88 |
| 2 | LEGIT-001/002 need an honest sender (3.4); fact fixes (below); brands added (below); new LANG-001 (15) and TIME-001 (10) | 266 / 296 (89.9%) | 0 / 88 | 4 / 88 |
| 3 | Evidence check (3.2): LANG-001 to 20, TIME-001 to 15; new COMBO-004 (knowledge). **Stopped here** (3.13) | 267 / 296 (90.2%) | 0 / 88 | 4 / 88 |

**Draft 2 details.**
- **Fact fixes, found by reading why phishing was missed, not by targeting emails:**
  - "storage limit has been exceeded" was not recognized as a mailbox-full lure;
  - Solana and other coins were missing from the crypto words;
  - a bare "RE" subject was not seen as a reply prefix;
  - languages other than English and French were all lumped together, so Dutch, German, Portuguese, Spanish and Italian are now identified.
- **Brands added:** the crypto wallets and exchanges phished most (Ledger, Trezor, Trust Wallet, Exodus, Phantom, Kraken) and Proton.

## 7. Known false alarms, misses and limits

**The 4 flagged legitimate development emails**, all Suspicious and none Malicious:
- **3 MedTech Moodle notifications** (`uni-005`, `uni-006`, `uni-019`). They claim `medtech.tn`, arrive from the internet and fail SPF with no DMARC pass, exactly like spoofing. Confirmed genuine by Fathia. Reported as "MedTech's Moodle server fails SPF", which is also a finding worth passing to MedTech's IT team.
- **1 university zip holding a JavaScript file** (`uni-023`), probably a student project. Accepted: a `.js` file in a zip from an outside sender deserves an analyst's look.

**The 29 missed development phishing emails** are mostly authenticated and show weak signs or none:
- spam rather than phishing: Dutch dating mail (5 from one sender), German casino mail, Portuguese and Spanish prize mail;
- a few lures with a single sign;
- label noise: for example an authenticated EC-Council renewal email that looks like genuine marketing.

Reputation lookups (domain age, VirusTotal) would catch several of them in real use. The offline headline leaves lookups out on purpose (EVALUATION.md, section 3).

**A legitimacy rule that, on this data, only cost a catch.** Found through Fathia's grading of the AI summaries (2026-10-19, graded email #6), after the rules were frozen:
- `sample-11984` is an authenticated storage-quota credential lure. COMBO-004 (+20) and TEXT-001 (+15) reach 35, which is Suspicious. LEGIT-001 (−15) takes it to 20, under the threshold.
- Measured afterwards on the development sets, with the rules run with and without LEGIT-001: it fires on 60 legitimate and 28 phishing emails, but changes **exactly one verdict**, this one, and in the wrong direction. Without it, no legitimate email would get a stronger verdict.
- Section 3.4 explains why authentication proves the domain and not the honesty. LEGIT-001's gate already applies that idea to disguised senders; this email shows the gap that remains: an honest-looking, authenticated sender whose links go elsewhere.
- **rules-v1 is frozen, so this stays a limit.** Candidate for a later rule version, to be judged on new data and never on the test sets: skip LEGIT-001 when a credential request links to another organization (COMBO-004), or drop LEGIT-001.
- What changed instead is the display only. The verdict now reads "Low risk (2 weak signs below the Suspicious threshold)" with the two signs listed, not "No indicators found". On the development sets, **21 of the 29 missed phishing emails** get this label, against **15 of the 84 unflagged legitimate emails**. It is not a verdict and is not counted as caught, but it tells the analyst where the near misses are.

**A fact bug found after the freeze, fixed in `rules-v1.1` (2026-10-20, through the AI summary of graded email #1).** The prize pattern `you('ve| have)? (won|...)` also matches "you won't": "I know that you won't have a class" became TEXT-002 evidence "you won" on `uni-005`. On the development sets, "you won" fires on 3 emails (1 phishing, 2 legitimate), and all 3 are "won't". Fixing the pattern changes no development verdict: the phishing email keeps TEXT-002 through "immediately", `uni-005` stays Suspicious, and one legitimate email loses its "Low risk" label. The fact code belongs to the frozen system, so Fathia decided: fixed before any test run, tagged `rules-v1.1` (`EVALUATION.md` section 5). After the fix, `uni-005` scores 40 instead of 50, still Suspicious; development results are unchanged. Checked at the same time: across all text signals, only two phrases ever fire on legitimate development mail ("immediately" 3 times, "you won" twice), so this is the only misfire of its kind found.

**Limits to keep in mind:**
- **SENDER-002 is strong partly because of this collection.** Half the honeypot phishing comes from `onmicrosoft.com` tenants, and other phishing mixes will show it less often.
- **LANG-001 depends on who receives the mail.** It is only right for an organization whose mail really is English, French and Arabic; set `EXPECTED_LANGUAGES` per organization.
- **TIME-001 was measured on 87 legitimate emails.** Rarer legitimate delays exist.
- **Free-mail brands are a gap.** "Google Security" sending from `attacker@gmail.com` is not counted as impersonation, because `gmail.com` belongs to Google. Solving it means telling a provider's system addresses from personal ones.
- **Text checks cover English and French only.** The new language detection recognizes other languages, but does not read them.
- **The development numbers are optimistic.** The test run decides.

## 8. Changing a rule safely

1. Change the rule in `scoring.py`, keeping its evidence sentence and MITRE techniques.
2. Run `phishtriage rules report` and look at both columns: phishing gained and legitimate gained. A change that adds even one Malicious legitimate email is rejected.
3. Use `--show RULE-ID` to read where it fires, and `--misses` for what is still missed or wrongly flagged.
4. Add or update its case in `tests/test_scoring.py` and run the tests.
5. Update this document: the catalogue row, and a tuning-log line explaining why.
6. After the frozen version (`rules-v1.1`) has met the test sets, its result stays the headline, whatever later versions do. Before the test run, check the change with the behaviour fingerprint (last line of `phishtriage rules report`): if it moved, a decision changed somewhere.

## 9. Explaining the rules in an interview

- **"Authentication proves the domain, not the honesty."** The first draft rewarded every authenticated email and missed authenticated phishing. Making that credit depend on an honest sender caught 14 more phishing emails on development (85.5% to 90.2%, measured with and without the condition), without a single new false alarm.
- **"I measured what not to use."** Return-Path mismatches fire more often on newsletters than on phishing, and `compauth` only says which server received the email. The legitimate set exists to catch exactly that kind of mistake.
- **"Floors only where legitimate mail never goes."** An executable attachment is Malicious on its own; macros or a spoofed own domain are only Suspicious, because legitimate exceptions exist (MedTech's Moodle is one).
- **"Unknown is not clean."** Skipped lookups and untrustworthy headers (inline forwards) give "not checked", never a pass.
- **"Points from judgment, checked against evidence, and tuning stopped early."** Fixed tiers, a likelihood-ratio check that moved only two rules by one tier, and a halt at the first version meeting the targets: the test set, untouched until then, decides.

## 10. Appendix: fact comparison on the development sets (2026-10-11)

Share of development emails where each fact is true: 296 phishing / 52 Gmail / 36 university. Test emails were not used.

| Fact | Phishing | Gmail | University | Reading |
|---|---|---|---|---|
| Sender on a shared platform (e.g. `onmicrosoft.com`) | 50% | 0% | 0% | Strong, but partly this collection's habit |
| Sender domain invalid | 25% | 0% | 0% | Strong |
| SPF fail | 53% | 0% | 8% | Strong (the 8% are the 3 MedTech emails under review) |
| Reply-To to another organization | 23% | 2% | 0% | Strong |
| More than 200 hidden words | 53% | 13% | 3% | Good with a high threshold |
| Urgency phrases | 23% | 4% | 3% | Good |
| Prize phrases | 16% | 2% | 3% | Good |
| Claims a brand it does not send from | 4% | 0% | 0% | Rare but precise |
| Asks for credentials / gift cards | 4% / 3% | 0% | 0% | Rare but precise |
| DMARC pass | 15% | 100% | 28% | Evidence of legitimacy (negative points) |
| DKIM aligned with From | 14% | 100% | 28% | Evidence of legitimacy |
| Return-Path to another organization | 26% | **31%** | 0% | **Useless**: newsletters do it too |
| Message-ID from another organization | 88% | 56% | 75% | Nearly useless |
| Any hidden text | 66% | **75%** | 22% | **Useless** without a word threshold |
| Mostly images | 9% | **27%** | 0% | **Points the wrong way** |
| Phone number near "call" | 2% | 2% | **25%** | Useless alone (email signatures) |
| Inline forward | 0% | 0% | 11% | A note for the analyst, not a sign of phishing |
| `compauth` present | 55% | 0% | 28% | **Never use**: says which server received it |
| No SPF/DMARC result at all | 0% | 0% | 64% | Internal mail: use the `internal` fact instead |
