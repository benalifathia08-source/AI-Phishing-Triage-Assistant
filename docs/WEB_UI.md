# The local web interface (M5)

`phishtriage web` starts a small web interface on this computer for analysts who prefer a browser to a terminal. It shows the same verdict, findings and facts as `phishtriage analyze`, plus exports for a ticket and a blocklist. This document covers how to use it, how it is protected (every email it shows was written by an attacker), how that was tested, and its limits.

## 1. Using it

```
.venv\Scripts\phishtriage web            # prints: http://127.0.0.1:8765/?key=...
```

1. **Open the printed link.** It is valid until the server stops. The key leaves the address bar at once and a session cookie takes over. Run one server at a time: a second one on the same port stops with "Port 8765 is already in use".
2. **Choose an .eml file** (up to 25 MB). Everything is off by default, so nothing leaves the computer:
   - **Reputation lookups** send links, domains, file hashes and the sender IP to VirusTotal, AbuseIPDB and RDAP. Never the email or its attachments.
   - **urlscan.io** visits up to 2 links in private scans, with the recipient's address removed from them.
   - **AI summary** is written by the local model (Ollama); it cannot change the verdict ([`AI_SAFETY.md`](AI_SAFETY.md)).
3. **Read the report:** the verdict and what to do first, then the findings, the AI summary, the email, authentication, links and QR codes, attachments, text, lookups and all headers.
4. **Export it:**
   - **JSON**, everything, for tools;
   - **Markdown**, a note to paste into a ticket;
   - **IOCs (CSV)**, indicators with a defanged column, for a blocklist or a hunt.

Reports stay in memory, up to the last 20, and disappear when the server stops. "Forget all reports" clears them sooner.

The same pipeline is available without a browser:

| Command | What it does |
|---|---|
| `phishtriage analyze FILE --format markdown` / `--format iocs` | The exports for one email |
| `phishtriage batch FOLDER --out results.csv [--details results.jsonl]` | Every .eml in a folder, offline unless `--lookups`. A file that crashes or stalls a parser is reported as "Analysis failed" and the batch goes on |
| `phishtriage cache purge [--older-than-days N] [--facts]` / `cache stats` | Lookup results are kept `CACHE_RETENTION_DAYS` (30) days; the web interface purges at every start. `--facts` also deletes the email facts cached for rule tuning by older code versions (`--all-facts`: all of them) |

Settings (in `.env` or the environment): `ANALYSIS_TIMEOUT` (60 s per email), `CACHE_RETENTION_DAYS` (30).

## 2. How it is protected

The page runs in the analyst's own browser, which is logged in to everything else, and it displays text an attacker chose. So it is built as if every email were an attack on the analyst.

| Threat | Protection | Where |
|---|---|---|
| Script in the email (subject, sender name, file name, link text) runs in the page (XSS) | **No JavaScript at all.** `Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` forbids every script, plugin, frame and outside resource. Every value is escaped *by default*: the HTML builder escapes anything it did not build itself, so forgetting is not possible | `web/server.py`, `web/html.py` |
| The email's own HTML, remote pictures, tracking pixels, forms | **Never rendered.** The page shows facts and the *visible text* as plain text; no tag from the email reaches the page | `web/pages.py` |
| A malicious link clicked or copied | **Links are never links.** They are defanged (`hxxps://login[.]evil[.]example`) and shown as text. The builder refuses any `href`/`src`/`action` that is not an internal path; a test caught `//evil.example/x`, a protocol-relative link, slipping through the first version | `web/html.py`, `display.py` |
| Hidden characters: a right-to-left override turning `invoice[U+202E]fdp.exe` into "invoiceexe.pdf"; zero-width characters inside words | Every control, format, bidi and zero-width character is shown as a red marker (`U+202E`) instead of being applied | `display.py` |
| Another website makes the browser submit emails here (CSRF), spending the lookup quotas or scanning its own URLs | POSTs need a token from this run, and the browser's own `Sec-Fetch-Site` header must say the request came from this site (or, in older browsers, `Origin` must be ours). The session cookie is `SameSite=Strict`, so it is not even sent with a cross-site form. `Origin` alone cannot decide: under a no-referrer policy a browser sends `Origin: null` for the page's own form | `web/server.py` |
| DNS rebinding: a website makes its own name point to 127.0.0.1 to read the pages | Only `Host: 127.0.0.1:port` or `localhost:port` is answered | `web/server.py` |
| Other programs or users on the same computer (127.0.0.1 is reachable by all of them) | A secret link printed at start sets an `HttpOnly`, `SameSite=Strict` session cookie; every page and report needs it. Report IDs are 128-bit random | `web/server.py` |
| The page framed by another site (clickjacking) | `frame-ancestors 'none'` and `X-Frame-Options: DENY` | `web/server.py` |
| Exposure to the network | The server listens on 127.0.0.1 only; there is no option to change that | `web/server.py` |
| Another program opens the same port and receives the uploads | On Windows, the `SO_REUSEADDR` that Python's servers set lets a second program bind the same port while the first listens, and connections then go to either. The port is held with `SO_EXCLUSIVEADDRUSE`, and a second copy of the tool stops with a clear message. Found 2026-10-22, when an old copy of the server kept answering some of Fathia's requests | `web/server.py` |
| A PDF or picture built to crash or stall a native parser (pypdfium2, OpenCV) | The offline analysis runs in a **child process with a time limit**. A crash or a time-out kills and replaces it, and the email is reported as **"Analysis failed: that is not a sign it is safe"**, never as clean. The child gets no API keys | `isolate.py` |
| Oversized uploads, slow clients | 25 MB limit, `Content-Length` required, 60-second request time-out, one analysis at a time | `web/server.py` |
| Personal data left behind | Reports in memory only, `Cache-Control: no-store`, `Referrer-Policy: same-origin` (the pages hold no outside link, so no address ever leaves). Lookups are off by default. The lookup cache is purged after 30 days, with deleted rows overwritten (`secure_delete`) and the file compacted | `web/server.py`, `enrich/cache.py` |
| An export turned into an attack where it is pasted or opened | **Markdown:** email text inside code spans, so `![x](https://exfil…)` in a subject cannot become a tracking image in the ticketing system. **CSV:** a cell starting with `= + - @` is prefixed with `'` (CSV injection: `=HYPERLINK(...)` in a file name). **JSON** keeps raw values for tools, which must escape them | `exports.py` |
| An injection in the email steers the AI summary | The AI layer's own defenses ([`AI_SAFETY.md`](AI_SAFETY.md)); the summary is shown as escaped plain text, labelled as the AI's | `ai/` |

The uploaded file is parsed by a small multipart parser written for this tool, which keeps the bytes exactly as sent. Python's `cgi` module is gone, and parsing the form as an email would treat the .eml as an attached message and re-encode it, breaking DKIM signatures.

## 3. How it was tested

`tests/test_web.py` runs a real server on a random port and attacks it with HTTP requests. `tests/test_isolate.py` uses real child processes.

| Test | Shows |
|---|---|
| A hostile email | Script tags, an `<svg onload>` sender name, a `javascript:` link, a tracking pixel, an iframe, a `<base>` tag, a right-to-left override in a file name, zero-width characters and a `=HYPERLINK` file name. The page then has no script, no event handler, nothing loading from outside, no link leaving the tool, the overrides shown and not applied, and every indicator defanged |
| Exports of the same email | The Markdown keeps the markup inside code spans, with no live image; no CSV cell starts a formula; downloads are attachments |
| Without the launch link or cookie | 401 for pages, reports and uploads. A wrong key gives 403. The right key gives a 303 to `/` and an `HttpOnly; SameSite=Strict` cookie |
| A foreign `Host` header | 421 |
| Cross-site POSTs | A wrong token, a foreign `Origin`, `Origin: null` and `Sec-Fetch-Site: cross-site` all give 403, and nothing is analyzed |
| A second server on the same port | Refused: neither a second copy of the tool nor a plain server with `SO_REUSEADDR` can open it |
| An old login link while logged in | Opens the page; without a session it gives 403 |
| Oversized or malformed uploads | 413 and 400 |
| Report IDs | Guessed IDs and path traversal give 404; "Forget" removes reports |
| A failed analysis | Shown as "Analysis failed … not a sign it is safe", never as "No indicators found", with nothing to export |
| The form parser | Keeps file bytes exactly, including a fake boundary and binary bytes inside; refuses broken forms |
| The HTML builder | Escapes by default; `Markup + text` escapes the text; outside links are refused |
| The child process | Gives the same facts as in-process. A parser that stalls is stopped after the limit and replaced; one that crashes (`os._exit`) or raises is reported; the child holds no API keys |
| Batch | Goes on after a failure |
| Cache retention | Purges old results without creating the cache, and the purged values are gone from the file |

It was also checked in a real browser: the hostile email, dark and light themes, phone width, and **forms submitted by the browser itself** (upload with and without the AI option, the session list, "Forget all reports", an export download).

That last check was missing from the first version, and Fathia's first-user test (2026-10-22) found two bugs the test client could not show:
- **Every upload was refused (403).** The pages set `Referrer-Policy: no-referrer`, under which Chrome sends `Origin: null` for the page's own form, and the server took that for a sandboxed attacker frame. The test client always sent a proper `Origin`.
- **"Forget all reports" was refused (400).** Its form had no `enctype`, so the browser posted it URL-encoded to a server that reads multipart only. The test client always sent multipart.

A third problem came from running two servers at once. On Windows both could hold the port (see section 2), so an old copy kept answering some requests: its key was "not valid for this run", and it still refused uploads. The port is now held exclusively.

The first two are fixed, and each has a test that reproduces what the browser sends: `Origin: null` with `Sec-Fetch-Site: same-origin` is accepted, and every rendered POST form must declare `multipart/form-data`. The lesson: a test client that builds its own requests proves the server, not the page and the browser together.

## 4. Limits

- **The browser is trusted.** A browser extension with access to all sites can read the page, like any other page. The page itself runs no code.
- **Plain HTTP on the loopback interface.** The traffic never leaves the computer, so it is not encrypted; the session cookie cannot be `Secure`.
- **Anyone who can read the terminal can use the link.** That is the same model as Jupyter's token. Another user on the computer cannot see your terminal; malware running as you can do anything you can, with or without this tool.
- **The child process has a time limit but no memory limit** (Windows offers no simple per-process limit). A file built to exhaust memory could slow the computer before the time limit stops it.
- **One analysis at a time.** With lookups switched on, an email can take a minute (VirusTotal allows 4 lookups a minute on the free plan), and the next one waits.
- **The visible text is shown defanged and cut at 20,000 characters,** and the headers at 200. The full email is in the file you uploaded.
- **The lookup cache is the working cache only.** The frozen, dated snapshot that M7 needs for its lookup subset must be a separate file, so that the purge can never touch it.
