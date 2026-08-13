# cookiestuff

**Cookie stuffing detector.** Point at a URL or a HAR file; find out which domains are secretly dropping affiliate cookies on your browser.

No dependencies for HAR analysis. Optional `playwright` for live URL scanning.

**Paper:** [Detecting Affiliate Cookie Stuffing via Information-Theoretic Navigation Novelty Scoring](paper/cookiestuff_detection.md) — describes the algorithm, validates it, and outlines how organizations with existing software distribution can deploy this detection in products to protect their customers.  
**License:** Apache 2.0 — includes explicit patent grant and patent retaliation clause.

---

## What is cookie stuffing?

Cookie stuffing is affiliate marketing fraud:

1. You visit a website — a shopping app, a news site, anything with web traffic.
2. Without your knowledge, that site fires hidden requests to affiliate tracking URLs — tiny 1×1 pixel images, invisible iframes, background XHR calls.
3. Those requests drop **affiliate cookies** on your browser. You never clicked an affiliate link. The cookies were *stuffed*.
4. Later, you visit a retailer and make a purchase you found yourself.
5. The retailer's checkout reads your browser cookies, finds the stuffed affiliate cookie, and pays the fraudster a commission for a sale they had nothing to do with.

The retailer loses margin. Legitimate affiliates who actually drove traffic get nothing. You get tracked without consent. The fraudster collects.

---

## Quick start

```bash
git clone https://github.com/quantumcelnav/cookiestuff
cd cookiestuff

# No install needed — demo requires only Python 3.8+ stdlib
python3 cookiestuff.py --demo

# With removal instructions
python3 cookiestuff.py --demo --guide
```

---

## Scanning a live URL (recommended)

This is the easiest path — no manual browser steps. Install Playwright once:

```bash
pip install playwright
playwright install chromium
```

Then point at any site:

```bash
python3 cookiestuff.py --url https://example.com
python3 cookiestuff.py --url https://example.com --verbose --guide
```

The tool visits the URL in a headless Chromium browser, waits 4 seconds for lazy-loaded affiliate scripts to fire, records every network request and cookie, then analyzes the result.

**Options:**

```
--wait SECONDS     How long to wait after page load (default: 4).
                   Increase to 8–10 for heavy single-page apps.

--no-headless      Show the browser window. Useful for sites that
                   block headless browsers or require login.

--guide            Print step-by-step cookie removal instructions
                   after the report.

--verbose          Show per-signal breakdown for each domain.

--threshold 0.5    Raise the suspicion bar (default: 0.35).
                   Use 0.5+ to suppress borderline cases.
```

**Example — scan and get removal guide:**

```bash
python3 cookiestuff.py --url https://example.com --guide --verbose
```

---

## Scanning a HAR file (manual capture)

If you prefer to capture traffic yourself, or the site requires login:

### Chrome / Edge

1. Open **DevTools** → **Network** tab (F12)
2. Check **Preserve log** (important — keeps requests across redirects)
3. Navigate to the site, browse around naturally
4. Right-click anywhere in the request list → **Save all as HAR with content**
5. Run the tool:

```bash
python3 cookiestuff.py session.har --guide
```

### Firefox

1. Open **DevTools** → **Network** tab (F12)
2. Navigate to the site
3. Click the **gear icon** → **Save All As HAR**

### Burp Suite

Proxy history → select requests → right-click → **Save items** → export as HAR.

---

## Understanding the output

```
Cookie Stuffing Analysis
──────────────────────────────────────────────────
  Navigated domains  : 2       ← domains you actually visited
  Cookies observed   : 11      ← total cookies set this session
  Cookie-setting doms: 7       ← unique domains that set cookies

  Information-theoretic signals:
    Navigation entropy  : 1.00 bits
    Cookie entropy      : 2.73 bits
    LZ novelty rate     : 63.6%  ← KEY SIGNAL (see below)

  SUSPICIOUS (4 domains):
    ⚠  HIGH    linksynergy.com  [Rakuten]   1 cookie  score=1.00
    ⚠  HIGH    cj.com           [Comm. Jn.] 2 cookies  score=0.95
    ⚠  HIGH    shareasale.com   [ShareASale] 2 cookies  score=0.95
    ⚠  HIGH    awin1.com        [Awin]       1 cookie  score=0.80
```

**LZ novelty rate** is the primary signal: the fraction of cookie-setting events that came from domains you never navigated to. A clean session has a rate near 0%. A stuffed session typically runs 40–80%.

The name comes from LZ78 data compression — your navigation history forms a "dictionary," and any cookie-setter not in the dictionary is a "miss." High miss rate = stuffing.

**Suspicion score** per domain combines six signals:

| Signal | What it means |
|---|---|
| LZ novelty (30%) | Domain not in your navigation path |
| Affiliate URL (25%) | URL matches known affiliate network pattern |
| Affiliate cookie (15%) | Cookie name matches affiliate tracking pattern |
| Hidden resource (15%) | Set via image/iframe/XHR, not direct navigation |
| Early timing (10%) | Fired within 500ms of page load — before any click is possible |
| No referrer (5%) | No Referer header — injected directly, not triggered by a link click |

**Verdicts:**
- `HIGH` (score ≥ 0.65) — strong evidence of stuffing
- `MEDIUM` (score ≥ 0.35) — suspicious; inspect with `--verbose`
- `CLEAN` (score < 0.35) — likely legitimate

---

## Discovering what was stuffed (`--verbose`)

```bash
python3 cookiestuff.py session.har --verbose
```

Verbose output shows the per-signal bar chart and the actual cookie names and timestamps for each suspicious domain:

```
    ⚠  HIGH    linksynergy.com  [Rakuten]  1 cookie  score=1.00
         LZ novelty      [██████████] 1.00
         Affiliate URL   [██████████] 1.00
         Affiliate cookie[██████████] 1.00
         Hidden resource [██████████] 1.00
         Early timing    [██████████] 1.00   ← fired at 0.2s, before any click
         No referrer     [██████████] 1.00   ← no Referer, injected by page JS
         cookie: rakuten_ls=phia_publisher… via xhr @ 0.2s
```

The timestamp (`@ 0.2s`) is the smoking gun for stuffing: if an affiliate cookie is set within the first half-second of page load, no human interaction was possible. It was placed automatically by the page's code.

---

## Removing the cookies

### Chrome / Edge

**Nuclear option** (clears all cookies):
1. Settings → Privacy and security → **Delete browsing data**
2. Time range: **All time** — check **Cookies and other site data** → Delete

**Surgical removal** (one domain at a time):
1. Settings → Privacy and security → **Cookies and other site data**
2. **See all site data and permissions**
3. Search for the suspicious domain (e.g. `linksynergy.com`)
4. Click the trash icon next to it

**Via DevTools** (fastest):
1. F12 → **Application** tab → **Cookies** in the left sidebar
2. Select the suspicious domain
3. Right-click any cookie → **Delete All** for this domain
4. Repeat for each flagged domain

### Firefox

1. Settings → Privacy & Security → **Cookies and Site Data** → **Manage Data**
2. Search for the suspicious domain
3. Select it → **Remove Selected** → **Save Changes**

**Via DevTools:**
1. F12 → **Storage** tab → **Cookies**
2. Select the suspicious domain
3. Select all rows (Ctrl+A / Cmd+A) → Delete

### Safari

1. **Develop** menu → **Show Web Inspector** → **Storage** tab → **Cookies**
2. Find the suspicious domain, right-click → **Delete**

Or: Safari → **Settings** → **Privacy** → **Manage Website Data** → search and remove.

### Prevent future stuffing

- **uBlock Origin** (Chrome/Firefox) blocks most affiliate tracking pixels before they load. Install it and enable the "Privacy" filter lists.
- **Firefox with Enhanced Tracking Protection** set to **Strict** blocks many of the same patterns.
- **Privacy Badger** (EFF) learns which domains track across sites and blocks them automatically.

---

## Reporting the fraud

Cookie stuffing harms retailers (they pay commissions for sales they generated themselves) and legitimate affiliates (who did the work but get no credit). It is considered fraud under the Computer Fraud and Abuse Act and equivalent laws in most jurisdictions.

**Report to the retailer:**
Search `<retailer name> affiliate program` — almost every major retailer has an affiliate team that investigates publisher fraud. They want to know.

**Report to the affiliate network:**
Each network has a publisher fraud reporting channel. Log into their dashboard and look for "Report a Publisher" or contact their compliance team directly.

**Report to regulators:**
- **United States:** [reportfraud.ftc.gov](https://reportfraud.ftc.gov)
- **United Kingdom:** [ico.org.uk/make-a-complaint](https://ico.org.uk/make-a-complaint)
- **European Union:** your national data protection authority (GDPR violation — setting cookies without consent)
- **Your state attorney general** — most states have consumer fraud units

---

## How the detection works (technical)

The core is an LZ78-inspired novelty scorer. As the HAR is parsed, every domain the user explicitly navigated to (`_resourceType: document`) joins the **navigation dictionary**. A cookie-setting event from a domain *outside* that dictionary is a **miss** — a novel domain writing to your cookie jar without your navigation.

The session-level **LZ novelty rate** (fraction of cookie events that are misses) is the primary stuffing signal. This is the same LZ78 dictionary-miss approach used in [styloprobe](https://github.com/quantumcelnav/stylometric-fingerprint) to detect model swaps in LLM conversations. The insight is identical: a stationary source (normal browsing, same model) has a low miss rate; a distribution shift (injected affiliate requests, swapped model) spikes it.

Six signals are combined into a weighted suspicion score per domain (see `DomainReport.suspicion` in `cookiestuff.py`). The affiliate network fingerprint database (`AFFILIATE_DOMAINS`, `AFFILIATE_URL_PATTERNS`, `AFFILIATE_COOKIE_NAMES`) covers 16+ major networks.

---

## Covered affiliate networks

Commission Junction · ShareASale · Awin / Zanox · Rakuten / LinkSynergy · Impact / ImpactRadius · PartnerStack · Partnerize · ClickBank · FlexOffers · PepperJam · Tradedoubler · Viglink / Skimlinks · MaxBounty · Refersion · Tune / HasOffers

To add a network: edit `AFFILIATE_DOMAINS` in `cookiestuff.py`. PRs welcome.

---

## Limitations

- **HAR / Playwright only.** This is a forensic analyzer, not a real-time blocker. For live blocking use uBlock Origin.
- **Legitimate affiliate cookies.** If you clicked an affiliate link in a banner, the resulting cookie is legitimate — this tool may still flag it. Use `--verbose` and check the timestamp: a cookie set seconds after a user click is likely legitimate; one set within 500ms of page load almost certainly is not.
- **First-party programs.** Retailers running their own affiliate tracking on custom subdomains won't match the network list. The LZ novelty and timing signals still apply.
- **Headless detection.** Some sites serve different content to headless browsers. Use `--no-headless` to load the real page.

---

## References

- Ziv, J. & Merhav, N. (1993). A measure of relative entropy between individual sequences. *IEEE Trans. Inf. Theory* 39(4).
- Page, E.S. (1954). Continuous inspection schemes. *Biometrika* 41(1).
- [styloprobe](https://github.com/quantumcelnav/stylometric-fingerprint) — companion project: same information-theoretic framework applied to LLM behavioral fingerprinting.

---

*Justin Fritz / TCA — justin@thecanonicalart.com*
