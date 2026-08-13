# cookiestuff

**Cookie stuffing detector.** Analyzes HAR files for affiliate fraud using information-theoretic signals.

---

## What is cookie stuffing?

Cookie stuffing is affiliate marketing fraud. Here is how it works:

1. You visit a website — a shopping app, a news site, anything with web traffic.
2. Without your knowledge, that site fires hidden requests to affiliate tracking URLs — tiny 1×1 pixel images, invisible iframes, background XHR calls.
3. Those requests drop **affiliate cookies** on your browser. You never clicked an affiliate link. You never consented. The cookies were *stuffed*.
4. Later, you visit a retailer (Amazon, Nordstrom, Sephora) and make a purchase — something you found yourself, through your own research.
5. The retailer's checkout process reads your browser cookies. It finds the stuffed affiliate cookie. It pays the fraudster a commission for a sale they had nothing to do with.

The retailer loses margin. The legitimate affiliate who actually influenced you gets nothing. You get tracked without consent. The fraudster collects.

This tool detects the stuffing step — the hidden requests that drop fraudulent cookies.

---

## How the detection works

The core insight is **information-theoretic**: every website you explicitly navigate to joins your "navigation dictionary." Cookie-setting events from domains *outside* that dictionary are anomalous — they are LZ78 misses, domains the user never visited that are nonetheless writing to their cookie jar.

Six signals combine into a per-domain suspicion score:

| Signal | Weight | What it measures |
|---|---|---|
| **LZ novelty** | 30% | Cookie-setting domain not in navigation dictionary |
| **Affiliate URL** | 25% | URL matches known affiliate network patterns |
| **Affiliate cookie** | 15% | Cookie name matches affiliate tracking patterns |
| **Hidden resource** | 15% | Set via image/iframe/XHR rather than direct navigation |
| **Early timing** | 10% | Fired within 500ms of page load (no user interaction possible) |
| **No referrer** | 5% | No Referer header — injected, not clicked |

The **LZ novelty rate** — the fraction of all cookie-setting events from unvisited domains — is the session-level summary statistic. A clean session has a rate near 0. A stuffed session has a rate above 0.4.

This is the same LZ78 dictionary-miss approach used in the companion project [styloprobe](https://github.com/quantumcelnav/stylometric-fingerprint) for detecting model swaps in LLM conversations. The same math applies: a stationary source (normal browsing) has a low miss rate; a distribution shift (injected affiliate requests) spikes it.

---

## Usage

No dependencies beyond Python 3.8+ stdlib.

```bash
git clone https://github.com/quantumcelnav/cookiestuff
cd cookiestuff

# Run on a built-in synthetic demo (no file needed)
python cookiestuff.py --demo

# Run on your own HAR file
python cookiestuff.py session.har

# Verbose: show per-signal breakdown for each suspicious domain
python cookiestuff.py session.har --verbose

# Adjust suspicion threshold (default 0.35)
python cookiestuff.py session.har --threshold 0.5

# JSON output for scripting
python cookiestuff.py session.har --json
```

Exit code: `1` if suspicious domains found, `0` if clean.

---

## Capturing a HAR file

**Chrome / Edge:**
1. Open DevTools → Network tab
2. Visit the site you want to audit
3. Right-click anywhere in the request list → "Save all as HAR with content"

**Firefox:**
1. Open DevTools → Network tab
2. Visit the site
3. Click the gear icon → "Save All As HAR"

**Burp Suite:**
Proxy history → select requests → right-click → "Save items" → export as HAR.

---

## Demo output

```
[demo mode — synthetic stuffed session]

Cookie Stuffing Analysis
──────────────────────────────────────────────────
  Navigated domains  : 2
  Cookies observed   : 11
  Cookie-setting doms: 7

  Information-theoretic signals:
    Navigation entropy  : 1.00 bits
    Cookie entropy      : 2.46 bits
    LZ novelty rate     : 72.7%  (fraction of cookies from unvisited domains)

  SUSPICIOUS (4 domains):
    ⚠  HIGH    cj.com            [Commission Junction]  2 cookies  score=0.90
    ⚠  HIGH    awin1.com         [Awin]                 1 cookie   score=0.88
    ⚠  HIGH    shareasale.com    [ShareASale]           2 cookies  score=0.88
    ⚠  HIGH    linksynergy.com   [Rakuten]              1 cookie   score=0.85

  Summary:
  4 of 7 cookie-setting domains
  look like affiliate stuffing.
  Run with --verbose for per-signal breakdown.
```

---

## Limitations

- **HAR files only.** This tool does not intercept live traffic. It is a forensic analyzer, not a real-time blocker. For live blocking, use a browser extension with network request interception.
- **Known affiliate networks.** The domain and URL pattern lists cover the major networks but are not exhaustive. Novel or private affiliate programs may be missed. Contributions welcome.
- **Legitimate uses of affiliate cookies.** Not every affiliate cookie is stuffed. If you clicked an affiliate link in a banner ad, the resulting cookie is legitimate — and this tool may flag it. Context matters; use the `--verbose` output to inspect the specific request.
- **First-party affiliate programs.** Some retailers run their own affiliate tracking (no third-party network). These use custom domains and will not match the affiliate network list; the LZ novelty and timing signals still apply.

---

## Covered affiliate networks

Commission Junction, ShareASale, Awin / Zanox, Rakuten / LinkSynergy, Impact / ImpactRadius, PartnerStack, Partnerize, ClickBank, FlexOffers, PepperJam, Tradedoubler, Viglink / Skimlinks, MaxBounty, Refersion, Tune / HasOffers, and generic tracker patterns.

To add a network: edit `AFFILIATE_DOMAINS` in `cookiestuff.py`.

---

## References

- Ziv, J. & Merhav, N. (1993). A measure of relative entropy between individual sequences. *IEEE Trans. Inf. Theory* 39(4):1270–1279.
- Page, E.S. (1954). Continuous inspection schemes. *Biometrika* 41(1):100–115.
- [styloprobe](https://github.com/quantumcelnav/stylometric-fingerprint) — companion project applying the same information-theoretic framework to LLM behavioral fingerprinting.

---

*Justin Fritz / TCA — justin@thecanonicalart.com*
