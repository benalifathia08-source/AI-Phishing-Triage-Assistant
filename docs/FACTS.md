# Facts available to rules

Generated from the code by `phishtriage rules facts`; do not edit by hand.
A rule receives `f` and can read any of these. `[i]` means a list: loop over it, or use the helpers
in `phishtriage/rules/helpers.py`. Facts marked as receiver-specific in `EVALUATION.md` (`compauth`, `exchange_auth_as`, `authserv_id`) must not be used by rules.

## `f.email`: The email itself

| Fact | Type | Meaning |
|---|---|---|
| `f.email` | EmailFacts | group of facts: see the rows below |
| `f.email.sha256` | str | SHA-256 of the whole .eml file |
| `f.email.size` | int | size of the .eml file in bytes |
| `f.email.subject` | str | the decoded subject line |
| `f.email.date` | str | the Date header in ISO format ('' when missing or unreadable) |
| `f.email.message_id` | str | the Message-ID header |
| `f.email.attached_emails` | int | emails attached inside this one |
| `f.email.parse_defects` | list[str] | MIME structure problems noticed while parsing |

## `f.headers`: Sender, reply path, routing, dates, internal mail

| Fact | Type | Meaning |
|---|---|---|
| `f.headers` | HeaderFacts | group of facts: see the rows below |
| `f.headers.sender` | SenderFacts | group of facts: see the rows below |
| `f.headers.sender.display_name` | str | the name shown before the address, e.g. 'PayPal Service' |
| `f.headers.sender.address` | str | the From address, lowercase |
| `f.headers.sender.domain` | str | the From domain |
| `f.headers.sender.org_domain` | str | organization part of the From domain: example.co.uk for mail.example.co.uk |
| `f.headers.sender.domain_is_valid` | bool | False when the domain has no real extension (muhbdrtdtbniig) or invalid characters |
| `f.headers.sender.is_freemail` | bool | the From domain is a free mail provider (gmail.com, outlook.fr...) |
| `f.headers.sender.on_free_hosting` | bool | sends from a shared platform anyone can sign up to, e.g. evil.onmicrosoft.com |
| `f.headers.sender.address_count` | int | From normally holds exactly one address |
| `f.headers.sender.display_name_address` | str | an email address written inside the display name |
| `f.headers.sender.display_name_address_differs` | bool | ...that belongs to another organization |
| `f.headers.sender.suspicious_characters` | list[str] | why the name or address looks deceptive: bold Unicode, mixed alphabets, invisible characters, punycode |
| `f.headers.reply_to_domains` | list[str] | domains of the Reply-To addresses |
| `f.headers.reply_to_differs` | bool | replies go to another organization than From |
| `f.headers.reply_to_is_freemail` | bool | a Reply-To address is at a free mail provider |
| `f.headers.return_path_domain` | str | envelope sender, where bounces go |
| `f.headers.return_path_differs` | bool | the bounce address belongs to another organization than From (newsletters do this too) |
| `f.headers.message_id_domain` | str | domain of the Message-ID header |
| `f.headers.message_id_differs` | bool | the Message-ID domain belongs to another organization than From (common in newsletters) |
| `f.headers.received_hops` | int | number of Received headers: servers the email passed through |
| `f.headers.date_missing` | bool | no readable Date header |
| `f.headers.date_skew_hours` | float or None | receive time minus the Date header; negative = dated in the future |
| `f.headers.to_count` | int | number of To addresses |
| `f.headers.cc_count` | int | number of Cc addresses |
| `f.headers.recipients_hidden` | bool | no To or Cc: everyone was Bcc'd |
| `f.headers.subject_suspicious_characters` | list[str] | lookalike or invisible characters in the subject |
| `f.headers.exchange_auth_as` | str | Microsoft 365 stamps how it authenticated the sender: Internal (inside your organization), Anonymous (from the internet), Partner. Exchange strips this header from mail arriving from outside, so an outsider cannot fake "Internal". Empty when not received by Microsoft. |
| `f.headers.internal` | bool | sent from inside your own Microsoft 365 organization |
| `f.headers.sender_is_protected` | bool | the From domain is one of PROTECTED_DOMAINS |
| `f.headers.own_domain_from_outside` | bool | Claims your domain, arrived from the internet, and nothing (SPF, DKIM, DMARC) authenticates it: spoofing, or one of your own systems sending without authorization (still worth fixing) |

## `f.auth`: Authentication results (SPF, DKIM, DMARC) from your own mail server

| Fact | Type | Meaning |
|---|---|---|
| `f.auth` | AuthFacts | group of facts: see the rows below |
| `f.auth.trust` | str | configured, top-most-header, untrusted-only, missing |
| `f.auth.authserv_id` | str | server ID of the trusted header (receiver-specific: not for rules) |
| `f.auth.spf` | str | pass, fail, softfail, neutral, none, temperror, permerror, or missing |
| `f.auth.spf_domain` | str | envelope sender (smtp.mailfrom) or HELO name |
| `f.auth.dkim` | list[tuple[str, str]] | (result, signing domain) |
| `f.auth.dmarc` | str | pass, fail, none (no DMARC policy), bestguesspass, permerror, temperror, or missing |
| `f.auth.dmarc_from_domain` | str | the From domain that DMARC checked |
| `f.auth.dmarc_action` | str | what the receiving server did because of DMARC: none, quarantine, reject... |
| `f.auth.compauth` | str | Microsoft composite authentication, when present |
| `f.auth.compauth_reason` | str | Microsoft's reason code (receiver-specific: not for rules) |
| `f.auth.sender_ip` | str | IP of the server that handed the email to your mail server |
| `f.auth.spf_aligned` | bool | Aligned = the authenticated domain belongs to the same organization as the From address the user sees. A pass without alignment proves nothing about From. |
| `f.auth.dkim_aligned` | bool | a passing DKIM signature belongs to the From domain's organization |
| `f.auth.ignored_headers` | int | Authentication-Results headers we did not trust |
| `f.auth.ignored_authserv_ids` | list[str] | server IDs of the ignored headers (receiver-specific: not for rules) |
| `f.auth.dkim_pass_domains` | property | Signing domains whose DKIM result was pass. |

## `f.dkim_recheck`: DKIM signatures re-checked by the tool

| Fact | Type | Meaning |
|---|---|---|
| `f.dkim_recheck` | list[DkimCheck] | one result per DKIM signature re-checked by the tool (empty when not re-checked) |
| `f.dkim_recheck[i].domain` | str | signing domain (d=) |
| `f.dkim_recheck[i].selector` | str | key selector (s=) |
| `f.dkim_recheck[i].status` | str | pass, fail, unverifiable, error |
| `f.dkim_recheck[i].reason` | str | why, in plain words |

## `f.dkim_recheck_enabled`: dkim_recheck_enabled

| Fact | Type | Meaning |
|---|---|---|
| `f.dkim_recheck_enabled` | bool | False when the re-check was switched off or not possible |

## `f.indicators`: Links, attachments, QR codes, phone numbers

| Fact | Type | Meaning |
|---|---|---|
| `f.indicators` | IndicatorFacts | group of facts: see the rows below |
| `f.indicators.links` | list[Link] | every link found: web links and tel:, data:, javascript: and similar |
| `f.indicators.links[i].url` | str | the link as found (cut at 2,000 characters) |
| `f.indicators.links[i].source` | str | text, html:a, html:form, html:iframe, html:meta-refresh, html:img, attachment:<name>, qr:<name>, embedded |
| `f.indicators.links[i].scheme` | str | http, https, tel, data, javascript, file, ms-... |
| `f.indicators.links[i].host` | str | the host the link really goes to |
| `f.indicators.links[i].org_domain` | str | organization of the host |
| `f.indicators.links[i].link_text` | str | the text shown for the link (cut at 200 characters) |
| `f.indicators.links[i].text_shows_other_domain` | str | the link text names a different site than the real target |
| `f.indicators.links[i].host_is_ip` | bool | the host is a bare IP address |
| `f.indicators.links[i].is_shortener` | bool | a URL shortener (bit.ly, tinyurl.com...) |
| `f.indicators.links[i].on_free_hosting` | bool | free hosting, site builder or file sharing (web.app, sharepoint.com...) |
| `f.indicators.links[i].click_tracker` | bool | a mailing service's click-tracking domain (normal in newsletters) |
| `f.indicators.links[i].has_userinfo` | bool | http://trusted.example@evil.test/ really goes to evil.test |
| `f.indicators.links[i].nonstandard_port` | bool | an unusual port, such as :8443 |
| `f.indicators.links[i].suspicious_characters` | list[str] | lookalike characters in the host |
| `f.indicators.links[i].embedded_urls` | list[str] | web addresses carried in the query (redirectors, Safe Links) |
| `f.indicators.links_truncated` | bool | more than 300 links: the list was cut |
| `f.indicators.attachments` | list[AttachmentInfo] | every attachment, including inline pictures |
| `f.indicators.attachments[i].filename` | str | file name as declared by the sender |
| `f.indicators.attachments[i].extension` | str | extension from the file name ('' when none) |
| `f.indicators.attachments[i].declared_type` | str | MIME type declared by the sender |
| `f.indicators.attachments[i].size` | int | size in bytes |
| `f.indicators.attachments[i].sha256` | str | SHA-256: what VirusTotal is asked about |
| `f.indicators.attachments[i].inline` | bool | shown inside the email (logos, pictures) rather than attached |
| `f.indicators.attachments[i].detected_type` | str | from magic bytes: pdf, zip, ooxml, ole, html, svg, pe, iso, lnk, rtf, onenote, png, ... |
| `f.indicators.attachments[i].category` | str | executable, config-profile, disk-image, archive, html, macro-document, document, image, other |
| `f.indicators.attachments[i].extension_mismatch` | bool | the name says one type, the bytes say another |
| `f.indicators.attachments[i].double_extension` | bool | invoice.pdf.html |
| `f.indicators.attachments[i].name_suspicious_characters` | list[str] | e.g. right-to-left override |
| `f.indicators.attachments[i].encrypted_archive` | bool | password-protected archives hide their content from scanners |
| `f.indicators.attachments[i].archive_members` | list[str] | file names inside a zip (listed, never extracted; first 50) |
| `f.indicators.attachments[i].archive_risky_members` | list[str] | risky files inside a zip: executables, scripts, HTML, disk images, macro documents |
| `f.indicators.attachments[i].has_macros` | bool | an Office document with VBA macros |
| `f.indicators.attachments[i].html_login_form` | bool | asks for a password inside the attachment itself |
| `f.indicators.attachments[i].html_script_tricks` | list[str] | script tricks in an HTML or SVG attachment: atob, eval, redirects, HTML smuggling... |
| `f.indicators.attachments[i].pdf_encrypted` | bool | a password-protected PDF |
| `f.indicators.attachments[i].pdf_pages` | int | pages in a PDF (0 when not a PDF or unreadable) |
| `f.indicators.attachments[i].config_profile_payloads` | list[str] | What an Apple configuration profile would change, e.g. com.apple.vpn.managed, com.apple.security.root (trusted root certificate), com.apple.mdm (device management) |
| `f.indicators.qr_codes` | list[QrCode] | QR codes decoded from pictures and PDF pages |
| `f.indicators.qr_codes[i].source` | str | the attachment or inline image it was found in |
| `f.indicators.qr_codes[i].text` | str | the decoded content, often a link |
| `f.indicators.phone_numbers` | list[str] | numbers next to "call", "support"... (callback phishing) |
| `f.indicators.link_domains` | property | Organizations the web links point to, in order of appearance. |
| `f.indicators.web_links` | property | Links with http or https (images included; helpers.web_links leaves them out). |

## `f.text`: What the email says, and hidden text

| Fact | Type | Meaning |
|---|---|---|
| `f.text` | TextFacts | group of facts: see the rows below |
| `f.text.language` | str | en, fr, ar, de, nl, pt, es, it, or unknown (too little text to tell) |
| `f.text.words` | int | visible words |
| `f.text.images` | int | number of pictures in the HTML |
| `f.text.mostly_images` | bool | pictures but almost no text: filters and readers have nothing to judge |
| `f.text.credential_request` | list[str] | phrases asking for passwords, codes or account verification |
| `f.text.urgency` | list[str] | deadlines of 72 hours or less, threats of suspension or closure |
| `f.text.payment` | list[str] | invoices, failed payments, transfers |
| `f.text.bank_details_change` | list[str] | new bank details, IBAN or RIB changes |
| `f.text.gift_cards` | list[str] | gift cards and prepaid vouchers |
| `f.text.secrecy` | list[str] | "are you available?", "keep this confidential" (CEO fraud) |
| `f.text.prize` | list[str] | prizes, lotteries, 'you have won' |
| `f.text.delivery` | list[str] | parcel delivery problems, customs fees |
| `f.text.callback` | list[str] | asks the reader to phone (callback phishing) |
| `f.text.crypto` | list[str] | bitcoin, wallets, recovery phrases |
| `f.text.qr_prompt` | list[str] | asks the reader to scan a QR code |
| `f.text.open_attachment` | list[str] | asks to open the attachment, enable macros, or gives its password |
| `f.text.injection_phrases` | list[str] | instructions to an AI in the visible text or subject |
| `f.text.hidden_words` | int | number of words a reader cannot see |
| `f.text.hidden_techniques` | list[str] | how it was hidden: display:none, zero font size, same colour as background... |
| `f.text.hidden_injection_phrases` | list[str] | instructions to an AI in hidden text |
| `f.text.hidden_sample` | str | start of the hidden text, for the analyst |
| `f.text.invisible_characters` | int | zero-width and similar characters in the visible text |

## `f.brands`: Brand claims and lookalike domains

| Fact | Type | Meaning |
|---|---|---|
| `f.brands` | BrandFacts | group of facts: see the rows below |
| `f.brands.sender_name_brands` | list[str] | brands named in the sender's display name |
| `f.brands.subject_brands` | list[str] | brands named in the subject |
| `f.brands.sender_address_brands` | list[str] | e.g. paypal-service@unrelated.example |
| `f.brands.sender_is_brand` | list[str] | the sender domain really belongs to these brands |
| `f.brands.impersonated` | list[str] | named in sender name or address, but not the sender |
| `f.brands.lookalikes` | list[Lookalike] | domains in the email that imitate a brand or one of your own domains |
| `f.brands.lookalikes[i].domain` | str | the suspicious domain as it appears |
| `f.brands.lookalikes[i].where` | str | sender, reply-to, return-path, sender-name, link |
| `f.brands.lookalikes[i].imitates` | str | the real domain it resembles |
| `f.brands.lookalikes[i].brand` | str | the brand, or "your organization" for PROTECTED_DOMAINS |
| `f.brands.lookalikes[i].method` | str | typo, confusable-letters, brand-in-domain, other-extension |

## `f.forwarding`: Reported and forwarded emails

| Fact | Type | Meaning |
|---|---|---|
| `f.forwarding` | ForwardFacts | group of facts: see the rows below |
| `f.forwarding.analyzed_attached_original` | bool | the email analyzed is the original attached to a report |
| `f.forwarding.reporter` | str | who reported or forwarded it |
| `f.forwarding.report_subject` | str | subject of the report that carried the original |
| `f.forwarding.inline_forward` | bool | forwarded in the body: authentication results describe the forwarder |
| `f.forwarding.quoted_sender` | str | sender named in the forwarded text ("From: ...") |
| `f.forwarding.quoted_sender_domain` | str | domain of quoted_sender |
| `f.forwarding.reply_prefix_without_thread` | bool | "RE:" but no In-Reply-To or References header: a fake reply |

## `f.notes`: Notes for the analyst

| Fact | Type | Meaning |
|---|---|---|
| `f.notes` | list[str] | what the analyst should know about how this was analyzed |

## `f.enrichment`: Reputation lookups (only when lookups ran; use the helpers in phishtriage/rules/helpers.py)

| Fact | Type | Meaning |
|---|---|---|
| `f.enrichment` | EnrichmentFacts | EnrichmentFacts, filled in when lookups are enabled |
| `f.enrichment.results` | list[Reputation] | one entry per lookup |
| `f.enrichment.results[i].service` | str | virustotal, urlscan, abuseipdb, rdap |
| `f.enrichment.results[i].kind` | str | file, url, domain, ip |
| `f.enrichment.results[i].target` | str | what was looked up: a hash, URL, domain or IP |
| `f.enrichment.results[i].status` | str | ok, not_found, pending, refused, skipped, disabled, error |
| `f.enrichment.results[i].detail` | str | a short reason for anything other than ok |
| `f.enrichment.results[i].malicious` | int or None | VirusTotal: engines calling it malicious |
| `f.enrichment.results[i].suspicious` | int or None | VirusTotal: engines calling it suspicious |
| `f.enrichment.results[i].engines` | int or None | VirusTotal: engines that gave any verdict |
| `f.enrichment.results[i].score` | int or None | urlscan.io score, AbuseIPDB abuse confidence (0-100) |
| `f.enrichment.results[i].verdict` | str | urlscan.io: malicious / no classification |
| `f.enrichment.results[i].labels` | list[str] | threat names, categories, impersonated brands |
| `f.enrichment.results[i].link` | str | page where the analyst can see the full report |
| `f.enrichment.results[i].extra` | dict | final URL, country, ISP, domain age... |
| `f.enrichment.results[i].cached` | bool | from the 24-hour cache rather than a fresh lookup |
| `f.enrichment.notes` | list[str] | what was left out and why |
