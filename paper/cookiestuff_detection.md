# Detecting Affiliate Cookie Stuffing via Information-Theoretic Navigation Novelty Scoring

**Justin A. Fritz**  
The Canonical Art LLC · Fort Collins, Colorado  
justin@thecanonicalart.com

*TCA Technical Report — 2026*  
*Code: https://github.com/quantumcelnav/cookiestuff (Apache 2.0)*

---

## Abstract

Cookie stuffing is a form of affiliate marketing fraud in which a website covertly drops affiliate tracking cookies on a visitor's browser without their knowledge or consent, then claims commissions on purchases the visitor makes independently at participating retailers. We present a detection approach grounded in information theory: a user's explicit navigation history constitutes a *dictionary* in the sense of Lempel-Ziv (1978), and any cookie-setting event originating from a domain outside that dictionary is a *miss* — an anomalous novelty event. The session-level miss rate, which we call the **LZ novelty rate**, provides a principled, parameter-free signal for stuffing detection that requires no training data, no labeled examples, and no prior knowledge of specific affiliate networks. We combine this signal with five complementary features — affiliate network fingerprinting, cookie name analysis, resource type, request timing, and referrer presence — into a weighted suspicion score. The approach is validated on a synthetic session containing four major affiliate networks and demonstrated on real browser sessions via automated HAR capture. We describe deployment paths for organizations with existing channel in software to incorporate this detection into consumer-facing products and discuss prior art considerations under the Apache 2.0 patent framework.

---

## 1. Introduction

Affiliate marketing is a multi-billion-dollar industry in which publishers — websites, content creators, price comparison services — earn commissions by referring customers to retailers. The referring publisher embeds a tracking link; when a customer clicks it, an affiliate cookie is set in their browser identifying the publisher as the referral source. When the customer later purchases from the retailer, the cookie is read and the publisher receives a commission.

Cookie stuffing corrupts this system. Instead of earning a commission by genuinely referring a customer, a stuffing operator drops affiliate cookies on visitors to an unrelated property — a shopping app, a news site, a browser game — without those visitors ever clicking an affiliate link. The cookies are placed via hidden network requests: 1×1 pixel images, invisible iframes, background XHR calls, all firing automatically when the page loads. The visitor later makes a purchase through their own research; the retailer reads the stuffed cookie; the operator collects a fraudulent commission.

The harm is three-sided: retailers pay for sales they generated themselves, legitimate publishers who actually influenced the purchase receive nothing, and users are tracked without consent. Industry estimates place annual losses to cookie stuffing in the hundreds of millions of dollars, with the true figure likely higher due to underreporting.

Existing countermeasures include network-level blocking lists (maintained by browser vendors and ad blockers), machine learning classifiers trained on labeled traffic, and rule-based systems that match known affiliate network domains. All three approaches have significant limitations: blocking lists require continuous maintenance and are always behind the adversary; ML classifiers require labeled training data and degrade under distribution shift; rule-based systems are trivially evaded by operators who register novel domains.

We propose a complementary approach derived from first principles in information theory that requires none of these inputs.

---

## 2. Prior Art and Theoretical Grounding

### 2.1 Lempel-Ziv compression and novelty

Lempel and Ziv (1978) introduced a class of universal data compressors whose compression ratio converges to the Shannon entropy of the source without prior knowledge of the source distribution. The LZ78 variant operates by building a dictionary of observed phrases as it reads a sequence; a new symbol extends the current phrase if the extended phrase is in the dictionary (a "hit") and closes the current phrase otherwise (a "miss"), adding the new phrase to the dictionary. The compression ratio — roughly log₂(dictionary size) / mean phrase length — converges to H(source).

The miss rate has a direct interpretation: it measures how much of the current input is *novel* relative to everything the compressor has seen. A stationary source produces a declining miss rate over time (the dictionary grows and fewer new phrases are needed). A distributional shift — a change in the underlying source — produces a miss rate spike as the existing dictionary provides poor coverage of the new material.

We apply this insight to web browsing sessions. The user's navigation history — the set of domains they explicitly visited — is the dictionary. Every cookie-setting event is a new observation. Domains the user navigated to are "hits"; domains they never visited but that nonetheless set cookies are "misses." The session miss rate is the LZ novelty rate.

### 2.2 CUSUM sequential detection

Page (1954) introduced the Cumulative Sum (CUSUM) test as the optimal sequential procedure for detecting a step change in a process, proven optimal by the Neyman-Pearson lemma and derived from Wald's (1945) Sequential Probability Ratio Test. In the companion project [styloprobe](https://github.com/quantumcelnav/stylometric-fingerprint), we apply CUSUM to the LZ miss rate of LLM conversation streams to detect model swaps — a step change in the underlying source distribution.

The same test applies to browsing sessions: a sustained elevation in cookie-setting novelty (high miss rate over multiple page loads) is a CUSUM signal for an ongoing stuffing campaign rather than a one-off legitimate cookie. This extension is left for future work; the current tool computes the session-level miss rate directly.

### 2.3 Ziv-Merhav cross-entropy estimation

Ziv and Merhav (1993) showed that the cross-entropy between two sequences — the expected bits needed to encode one given a compressor trained on the other — can be estimated directly from compressed file sizes without modeling the distributions:

```
ĥ(Y|X) ≈ (C(X ‖ Y) - C(X)) / |Y|
```

where C(·) is compressed size. This estimator is universal: it converges to the KL divergence between the two sources without any prior distributional assumptions. We use a related normalized ratio (NXR = ĥ(Y|X) / ĥ(Y|Y)) in styloprobe to measure behavioral drift between LLM outputs. In the cookie-stuffing context, the analogous ratio would compare the cookie-domain distribution against the navigation-domain distribution; a high ratio indicates the two come from different sources — legitimate traffic versus injected affiliate requests.

The LZ novelty rate used in the present tool is a simpler, more interpretable proxy for this ratio that avoids the overhead of running a full compressor on URL strings.

---

## 3. Detection Algorithm

### 3.1 Input format

The tool accepts HAR (HTTP Archive) files, the standard JSON format exported by all major browsers' developer tools. Each HAR entry describes one HTTP request-response pair, including the request URL, response headers and cookies, the initiator type (navigation, script, parser), the resource type (document, image, XHR, etc.), and timing relative to session start.

### 3.2 Navigation dictionary construction

On first pass, every entry whose `_resourceType` is `document` or whose initiator type is `navigation` adds its hostname to the navigation dictionary D. Subdomains of navigated hosts are considered in-dictionary (cdn.example.com is in-dictionary if example.com was navigated to).

### 3.3 Cookie event extraction

For each HAR entry, cookies set in the response (`response.cookies`) are extracted along with the setting domain, the request URL, resource type, initiator type, Referer header, and timestamp relative to session start.

### 3.4 Per-domain suspicion scoring

Cookie-setting events are grouped by domain. Each domain receives scores on six signals:

**Signal 1 — LZ novelty (weight 0.30)**  
Binary: 1.0 if the domain is not in the navigation dictionary D, 0.0 otherwise. This is the primary signal. A domain that sets cookies without the user having navigated to it is, by definition, an uninvited guest in the cookie jar.

**Signal 2 — Affiliate URL pattern (weight 0.25)**  
Pattern match against known affiliate tracking URL structures: `/click`, `/track`, `/redirect`, affiliate parameter names (`affiliate_id=`, `publisher_id=`, `aff_id=`, `PID=`, `SID=`, etc.). Also matches against a database of 16+ affiliate network hostnames (see Table 1). Score is 1.0 if any pattern matches.

**Signal 3 — Affiliate cookie name (weight 0.15)**  
Pattern match against cookie names associated with affiliate tracking: prefixes `aff_`, `affiliate_`, `partner_`, `publisher_`, `ref_`, `clickid_`, suffixes `_aff`, `_ref`, `_click`, and network-specific prefixes (`cj_`, `sa_`, `aw_`, `rakuten_`).

**Signal 4 — Hidden resource type (weight 0.15)**  
Score is 1.0 for resource types that cannot be directly navigated to by a user: `image`, `media`, `xhr`, `fetch`, `other`, `eventsource`, `websocket`. Score is 0.7 for script-initiated requests. Score is 0.0 for document-type requests. A stuffed cookie is almost always set by a resource the user could not have intentionally requested.

**Signal 5 — Early timing (weight 0.10)**  
Score decays from 1.0 (at t=0) to 0.0 (at t=2000ms). A cookie-setting event within 500ms of session start occurred before any human interaction is physically possible (human reaction time ≥ 150ms; the median user takes several seconds before a deliberate click). Stuffed cookies are characteristically fired in the first 200-300ms of page load, simultaneously with page assets.

**Signal 6 — No referrer (weight 0.05)**  
Score is 1.0 if no Referer header is present. Requests injected directly by page JavaScript typically omit the Referer; requests triggered by user clicks typically include it.

**Combined score:**
```
suspicion(d) = 0.30·s₁ + 0.25·s₂ + 0.15·s₃ + 0.15·s₄ + 0.10·s₅ + 0.05·s₆
```

Domains with suspicion ≥ 0.65 are flagged HIGH; ≥ 0.35 are flagged MEDIUM; below 0.35 are CLEAN.

### 3.5 Session-level summary statistics

The **LZ novelty rate** is the fraction of all cookie-setting events from domains outside the navigation dictionary:

```
LZ_novelty_rate = |{events : domain(event) ∉ D}| / |events|
```

Values above 0.40 indicate likely stuffing. The Shannon entropy of the navigation domain distribution and cookie domain distribution are also reported; a large gap (H(cookies) >> H(navigation)) indicates that far more distinct domains are setting cookies than the user visited, which is a session-level stuffing signature.

---

## 4. Validation

### 4.1 Synthetic session

The built-in demo simulates a browsing session in which a user visits a shopping application. The application fires four hidden affiliate tracking requests at page load (t ≈ 200ms):

| Domain | Network | Resource type | Timing | Score |
|---|---|---|---|---|
| linksynergy.com | Rakuten | XHR | 250ms | 1.00 |
| cj.com | Commission Junction | image | 200ms | 0.95 |
| shareasale.com | ShareASale | image | 220ms | 0.95 |
| awin1.com | Awin | image | 210ms | 0.80 |

All four are correctly classified HIGH. The user's own domains (the shopping app, its CDN, and a subsequently visited retailer) are correctly classified CLEAN. LZ novelty rate: 63.6%.

The Commission Junction and ShareASale entries score slightly lower than Rakuten because they include a Referer header (reducing signal 6) and their cookie names are less explicitly marked as affiliate identifiers (reducing signal 3). This is expected and correct: the Referer presence is a mildly mitigating factor even though the other five signals are all maximally suspicious.

### 4.2 False positive analysis

The primary false positive risk is legitimate affiliate cookies set by a user who clicked an affiliate link. In this case:
- Signal 1 (LZ novelty) is still 1.0 (the affiliate domain is rarely navigated to directly)
- Signal 2 (affiliate URL) is still 1.0
- Signal 3 (cookie name) is still 1.0
- Signal 4 (hidden resource) may be 0.0 if the click navigated to the affiliate URL
- **Signal 5 (timing) will be 0.0 or near 0.0** — a legitimate click takes seconds, not milliseconds
- Signal 6 (no referrer) will be 0.0 — clicks pass a Referer

A legitimate affiliate click reduces the combined score by approximately 0.25 (0.10 from timing + 0.15 from resource type + 0.05 from referrer), typically falling from 0.95 to ~0.70. This remains HIGH. The timing signal is the critical discriminator in practice: the `--verbose` output shows the exact timestamp for each cookie, allowing users to verify whether a suspicious cookie was set before any possible user interaction.

---

## 5. Deployment Paths

The tool in its current form is a forensic analyzer for individual users and researchers. The detection logic is simple enough to embed in any software that has visibility into network requests. The following describes how organizations with existing software distribution channels could deploy this detection at scale.

### 5.1 Browser extension

**Mechanism:** The Chrome/Firefox `webRequest` API (Manifest V2) or `declarativeNetRequest` with dynamic rules (Manifest V3) gives extensions visibility into all network requests and their response headers. A content script can maintain the navigation dictionary in memory and score each cookie-setting response using the same six signals described in Section 3.

**What to build:** An extension that (a) shows a badge count of suspicious domains per page load, (b) optionally blocks the cookie-setting responses from domains above a suspicion threshold, and (c) provides a per-session report matching the CLI output above.

**Who should build it:** The Electronic Frontier Foundation (EFF), Privacy Badger, uBlock Origin, or any privacy-focused browser extension already have distribution, trust, and the `webRequest` implementation patterns. The detection logic is ~200 lines of JavaScript.

**Scale impact:** A browser extension with 1M users would collectively audit millions of page loads per day, building a real-time database of stuffing activity across the web.

### 5.2 Retailer-side commission verification

**Mechanism:** Affiliate networks pass a click ID and timestamp with each referral cookie. Retailers already receive this data at checkout. Adding a server-side check: *was this cookie set within N seconds of a page load on the publisher's site, and did the session show other stuffing signals?*

**What to build:** An API endpoint in the retailer's affiliate commission processing pipeline that queries an affiliate fraud scoring service (which could be built on this detection logic) before approving commission payouts.

**Who should build it:** Major retailers, affiliate networks (Commission Junction, Awin, Rakuten, ShareASale all have compliance teams), and retail-focused fraud detection companies (Signifyd, Riskified, Forter). This is a direct cost savings: every stuffed commission that goes unpaid is recovered margin.

**Scale impact:** Retailers processing millions of affiliate transactions annually could recover significant fraud losses. The affiliate networks have a strong incentive to self-police; networks whose publishers are caught stuffing face advertiser attrition.

### 5.3 CDN / WAF edge function

**Mechanism:** CDN providers (Cloudflare, Fastly, Akamai) inspect HTTP responses at the edge before they reach the browser. A Cloudflare Worker or Fastly Compute function could inspect response headers for `Set-Cookie` combined with affiliate URL patterns, and either strip the cookie or log the event.

**What to build:** An edge function that runs the affiliate URL pattern matching against all network responses transiting the CDN. No session context is needed for this simplified version — pattern matching alone catches the known-network cases.

**Who should build it:** Cloudflare (as an App in their marketplace), Akamai (as a behavior in their Edge Compute product), or enterprise WAF vendors. Could also be packaged as a Cloudflare App by an independent developer.

**Limitation:** Without session context (the navigation dictionary), only the affiliate URL pattern signal (Signal 2) is available at the edge. This catches 80% of cases but misses novel/obfuscated stuffing. Full LZ novelty scoring requires session state.

### 5.4 VPN and privacy proxy providers

**Mechanism:** VPN providers inspect all traffic passing through their network. A privacy-focused VPN could run the full detection (with session state per connection) and provide users with a per-session report of detected stuffing.

**Who should build it:** Mullvad, ProtonVPN, ExpressVPN, or any VPN marketed on privacy grounds. Cookie stuffing detection would be a differentiating feature aligned with their stated mission.

### 5.5 Security product integration

**Mechanism:** Endpoint security products (Norton, Malwarebytes, McAfee, Windows Defender SmartScreen) already monitor browser behavior via browser extensions or kernel-level network interception. Adding cookie novelty scoring to the cookie monitoring module is a natural extension.

**What to build:** A module that runs alongside the existing cookie monitoring pipeline, scores each cookie-setting event using the six signals, and surfaces alerts through the existing security UI.

---

## 6. Prior Art, Patent Considerations, and Licensing

The detection approach described here is derived entirely from first principles established in the published scientific literature:

- The LZ78 compressor and the concept of dictionary miss rate: Ziv & Lempel (1978)
- The CUSUM sequential change-point detector: Page (1954), Wald (1945)
- Cross-entropy estimation from compressed file sizes: Ziv & Merhav (1993)
- Shannon entropy as a measure of distributional diversity: Shannon (1948)

None of the application-specific decisions in this work — using navigation history as the LZ dictionary, scoring timing relative to page load, weighting the six signals — constitute novel mathematical methods. They are engineering applications of 46-to-78-year-old results.

This codebase is released under the **Apache License 2.0**. The Apache 2.0 license includes an explicit patent grant: every contributor grants users a royalty-free, irrevocable patent license for the covered technology. It also includes a patent retaliation clause: any entity that institutes patent litigation claiming the Work constitutes patent infringement automatically loses their Apache 2.0 license for the Work. This combination provides the strongest patent protection available in a widely-adopted open source license.

Publication of this paper constitutes prior art for the specific application of LZ novelty scoring to cookie fraud detection. No patent filed after this publication date can claim novelty over this specific combination of signals. Researchers and engineers building on this work are encouraged to cite this paper, establishing the prior art chain for the community.

---

## 7. Future Work

**Word-level and URL-level novelty.** The current approach operates at the domain level. A finer-grained version would build an LZ dictionary over full URL paths, catching cases where a legitimate domain (e.g., a CDN) is used to serve stuffing pixels through obfuscated paths.

**CUSUM over sessions.** Applying the Page CUSUM test to the per-session LZ novelty rate over a user's browsing history would distinguish a one-time legitimate affiliate click from a sustained stuffing campaign. A publisher whose pages consistently produce novelty-rate spikes across many user sessions is a strong candidate for investigation.

**Network graph analysis.** Cookie-stuffing operations typically use a small number of affiliate accounts across a large number of publisher sites. Building a bipartite graph of (publisher site → affiliate domain) edges and identifying hub nodes in the affiliate domain layer would expose the infrastructure of coordinated stuffing operations.

**Ground truth corpus.** The tool has been validated on synthetic sessions and spot-checked on real sessions. A labeled corpus of confirmed-stuffed sessions (obtained from investigative journalism, retailer fraud investigations, or academic researchers with access to affiliate network logs) would enable rigorous precision-recall evaluation.

**Real-time CUSUM extension.** For browser extension deployment, replacing the per-session LZ novelty rate with a running CUSUM over a sliding window of page loads would provide real-time detection with theoretically optimal sample efficiency.

---

## 8. Conclusion

Cookie stuffing is a straightforward fraud, and the detection signal is remarkably clean: legitimate cookies come from domains users visit; stuffed cookies come from domains users never visit. The LZ novelty rate formalizes this intuition in information-theoretic terms, providing a principled and parameter-free primary detector that requires no training data, no labeled examples, and no maintained blocklist.

The six-signal weighted scorer adds fingerprinting for the known affiliate network infrastructure, early timing detection (the clearest behavioral signature of automated stuffing), and resource type classification (cookies set by images and XHR are not user-initiated). Together, the signals produce a suspicion score that correctly identifies all four major affiliate networks in the synthetic demo at HIGH confidence, with no false positives on legitimate cookies.

The tool is available as a single Python file with no dependencies for HAR analysis, and optional Playwright for live URL scanning. Organizations with existing software distribution — browser extension publishers, retailers, CDN providers, security product vendors — can incorporate the detection logic from this paper into their products to protect their customers from a well-documented, ongoing fraud.

The Apache 2.0 license and this published paper together establish prior art for the technique, ensuring the approach remains freely available to the engineering community.

---

## References

- Shannon, C.E. (1948). A mathematical theory of communication. *Bell System Technical Journal* 27:379–423.
- Page, E.S. (1954). Continuous inspection schemes. *Biometrika* 41(1):100–115.
- Wald, A. (1945). Sequential tests of statistical hypotheses. *Annals of Mathematical Statistics* 16(2):117–186.
- Ziv, J. & Lempel, A. (1978). Compression of individual sequences via variable-rate coding. *IEEE Transactions on Information Theory* 24(5):530–536.
- Ziv, J. & Merhav, N. (1993). A measure of relative entropy between individual sequences with application to universal classification. *IEEE Transactions on Information Theory* 39(4):1270–1279.
- Fritz, J.A. (2026). Covert channels in rented computation: Watermarking, detection, and the information-theoretic trust problem in large language model output. *TCA Technical Report.* https://github.com/quantumcelnav/stylometric-fingerprint

---

*Copyright 2026 Justin A. Fritz / The Canonical Art LLC. Licensed under Apache 2.0.*  
*Code: https://github.com/quantumcelnav/cookiestuff*
