#!/usr/bin/env python3
"""
cookiestuff.py — Cookie stuffing detector

Cookie stuffing is affiliate fraud: a website secretly fires hidden requests
to affiliate tracking URLs, dropping commission cookies on your browser without
your knowledge. When you later buy from a retailer naturally, the fraudulent
affiliate claims credit and collects the commission.

This tool analyzes HAR (HTTP Archive) files for stuffing signals using an
information-theoretic approach: the user's explicit navigation history forms
a "dictionary" (in the LZ78 sense). Cookie-setting events from domains
outside that dictionary are "misses" — the primary stuffing signal. The
overall miss rate, combined with affiliate network fingerprinting and timing
analysis, produces a per-domain suspicion score.

Detection signals:
  1. LZ novelty       — cookie-setting domain not in navigation dictionary
  2. Affiliate match  — URL matches known affiliate network patterns
  3. Hidden resource  — set by image/iframe/XHR, not direct navigation
  4. Early timing     — fired within 500ms of page load (no user interaction possible)
  5. No referrer      — request has no Referer header (injected, not clicked)
  6. Cookie name      — cookie name matches affiliate tracking patterns

Usage:
    python cookiestuff.py session.har
    python cookiestuff.py session.har --threshold 0.4
    python cookiestuff.py session.har --verbose
    python cookiestuff.py session.har --json
    python cookiestuff.py --demo          # run on built-in synthetic HAR
"""

import argparse
import json
import math
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Affiliate network fingerprints
# ---------------------------------------------------------------------------

AFFILIATE_DOMAINS = {
    # Network name → list of domain fragments
    "Commission Junction": ["cj.com", "cjour.com", "dpbolvw.net", "emjcd.com",
                            "ftjcfx.com", "jdoqocy.com", "kqzyfj.com", "lduhtrp.net",
                            "ojrq.net", "qksrv.net", "tkqlhce.com", "yceml.net"],
    "ShareASale":          ["shareasale.com", "shareasale-analytics.com"],
    "Awin":                ["awin1.com", "awin.com", "zanox.com", "zanox-affiliate.com",
                            "affili.net"],
    "Rakuten":             ["rakutenadvertising.com", "linksynergy.com", "click.linksynergy.com",
                            "ad.linksynergy.com"],
    "Impact":              ["impact.com", "impactradius.com", "sjv.io", "evyy.net",
                            "7eer.net", "jdoqocy.com"],
    "PartnerStack":        ["partnerstack.com", "partnero.com"],
    "Partnerize":          ["partnerize.com", "prf.hn"],
    "ClickBank":           ["clickbank.com", "hop.clickbank.net"],
    "FlexOffers":          ["flexoffers.com", "flexlinks.com"],
    "PepperJam":           ["pepperjam.com", "pjtra.com"],
    "Tradedoubler":        ["tradedoubler.com"],
    "Viglink":             ["viglink.com", "skimlinks.com", "skimresources.com"],
    "MaxBounty":           ["maxbounty.com"],
    "Refersion":           ["refersion.com"],
    "Tune/HasOffers":      ["tune.com", "hasoffers.com", "app.link"],
    "CivicScience":        ["civicscience.com"],
    "Generic trackers":    ["doubleclick.net", "googleadservices.com"],
}

# URL path/query patterns that strongly indicate affiliate tracking
AFFILIATE_URL_PATTERNS = [
    r"/click\b",
    r"/track\b",
    r"/redirect\b",
    r"/go\b",
    r"/refer\b",
    r"[?&]affiliate[_-]?id=",
    r"[?&]publisher[_-]?id=",
    r"[?&]aff[_-]?id=",
    r"[?&]partner[_-]?id=",
    r"[?&]ref(erral)?=",
    r"[?&]subid=",
    r"[?&]clickid=",
    r"[?&]source=affiliate",
    r"[?&]PID=",
    r"[?&]SID=",
    r"[?&]CID=",
]

# Cookie names that indicate affiliate tracking
AFFILIATE_COOKIE_NAMES = [
    r"^aff",
    r"^affiliate",
    r"^partner",
    r"^ref(erral)?",
    r"^publisher",
    r"^clickid",
    r"^subid",
    r"_aff$",
    r"_ref$",
    r"_click$",
    r"^cj_",
    r"^sa_",     # ShareASale
    r"^aw_",     # Awin
    r"^rakuten",
    r"^impact_",
]

# Resource types that suggest hidden injection (not user navigation)
HIDDEN_RESOURCE_TYPES = {"image", "media", "other", "xhr", "fetch", "eventsource",
                          "websocket", "preflight"}

NAVIGATION_RESOURCE_TYPES = {"document", "navigate"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CookieEvent:
    """One cookie set by one response."""
    name:          str
    value:         str
    domain:        str
    url:           str
    resource_type: str
    initiator:     str        # "parser", "script", "redirect", "other"
    referer:       str
    timestamp:     float      # seconds since session start
    page_ref:      str        # HAR page ID


@dataclass
class DomainReport:
    """Aggregated analysis for one cookie-setting domain."""
    domain:         str
    cookies:        list[CookieEvent]       = field(default_factory=list)
    network_name:   Optional[str]           = None

    # Signals (each 0.0–1.0)
    lz_novelty:     float = 0.0   # not in navigation dictionary
    affiliate_url:  float = 0.0   # URL matches affiliate patterns
    affiliate_cookie: float = 0.0 # cookie names match affiliate patterns
    hidden_resource: float = 0.0  # not a direct navigation
    early_timing:   float = 0.0   # fired before user could interact
    no_referrer:    float = 0.0   # no Referer header

    @property
    def suspicion(self) -> float:
        """Weighted suspicion score 0.0–1.0."""
        return min(1.0, (
            0.30 * self.lz_novelty +
            0.25 * self.affiliate_url +
            0.15 * self.affiliate_cookie +
            0.15 * self.hidden_resource +
            0.10 * self.early_timing +
            0.05 * self.no_referrer
        ))

    @property
    def verdict(self) -> str:
        s = self.suspicion
        if s >= 0.65: return "HIGH"
        if s >= 0.35: return "MEDIUM"
        return "CLEAN"


# ---------------------------------------------------------------------------
# HAR parser
# ---------------------------------------------------------------------------

def _domain(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        return host.lower()
    except Exception:
        return ""


def _parse_timestamp(dt_str: str) -> float:
    """Parse ISO8601 HAR timestamp to epoch float. Returns 0.0 on failure."""
    try:
        dt_str = dt_str.rstrip("Z")
        if "." in dt_str:
            dt = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S")
        return dt.timestamp()
    except Exception:
        return 0.0


def parse_har(har: dict) -> tuple[set[str], list[CookieEvent]]:
    """
    Returns:
        navigated_domains: set of domains the user explicitly navigated to
        cookie_events:     all cookie-setting events in the session
    """
    entries     = har.get("log", {}).get("entries", [])
    navigated   = set()
    events      = []

    # First pass: find the session start time
    t0 = None
    for e in entries:
        t = _parse_timestamp(e.get("startedDateTime", ""))
        if t and (t0 is None or t < t0):
            t0 = t
    if t0 is None:
        t0 = 0.0

    for e in entries:
        url      = e.get("request", {}).get("url", "")
        dom      = _domain(url)
        rtype    = (e.get("_resourceType") or
                    e.get("type") or "other").lower()
        init     = (e.get("_initiator") or {})
        init_type = (init.get("type") or "other").lower()
        t        = _parse_timestamp(e.get("startedDateTime", "")) - t0
        page_ref = e.get("pageref", "")

        # Navigation: user explicitly loaded this domain
        if rtype in NAVIGATION_RESOURCE_TYPES or init_type == "navigation":
            navigated.add(dom)

        # Gather cookies set in response
        referer = ""
        for h in e.get("request", {}).get("headers", []):
            if h.get("name", "").lower() == "referer":
                referer = h.get("value", "")
                break

        for ck in e.get("response", {}).get("cookies", []):
            name   = ck.get("name", "")
            value  = ck.get("value", "")
            ck_dom = ck.get("domain", dom).lstrip(".")
            events.append(CookieEvent(
                name=name, value=value, domain=ck_dom or dom,
                url=url, resource_type=rtype, initiator=init_type,
                referer=referer, timestamp=t, page_ref=page_ref,
            ))

    return navigated, events


# ---------------------------------------------------------------------------
# Signal scorers
# ---------------------------------------------------------------------------

def _match_affiliate_domain(domain: str) -> Optional[str]:
    for network, frags in AFFILIATE_DOMAINS.items():
        for frag in frags:
            if domain == frag or domain.endswith("." + frag):
                return network
    return None


def _affiliate_url_score(url: str) -> float:
    for pat in AFFILIATE_URL_PATTERNS:
        if re.search(pat, url, re.IGNORECASE):
            return 1.0
    return 0.0


def _affiliate_cookie_score(name: str) -> float:
    name_lower = name.lower()
    for pat in AFFILIATE_COOKIE_NAMES:
        if re.search(pat, name_lower, re.IGNORECASE):
            return 1.0
    return 0.0


def _hidden_resource_score(resource_type: str, initiator: str) -> float:
    if resource_type in HIDDEN_RESOURCE_TYPES:
        return 1.0
    if initiator == "script":
        return 0.7
    return 0.0


def _early_timing_score(timestamp: float, threshold_ms: float = 500.0) -> float:
    """Fires within threshold_ms of session start with no user interaction possible."""
    if timestamp < 0:
        return 0.0
    t_ms = timestamp * 1000.0
    if t_ms < threshold_ms:
        return 1.0
    if t_ms < threshold_ms * 4:
        return max(0.0, 1.0 - (t_ms - threshold_ms) / (threshold_ms * 3))
    return 0.0


# ---------------------------------------------------------------------------
# Information-theoretic summary
# ---------------------------------------------------------------------------

def _entropy(domains: list[str]) -> float:
    """Shannon entropy of domain distribution (bits)."""
    counts: dict[str, int] = defaultdict(int)
    for d in domains:
        counts[d] += 1
    n = len(domains)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _lz_novelty_rate(navigated: set[str], cookie_events: list[CookieEvent]) -> float:
    """
    Fraction of cookie-setting events from domains not in the navigation dictionary.
    Analogous to the LZ78 'miss rate': novel domains setting cookies.
    A rate near 0 = all cookies from visited domains (normal).
    A rate near 1 = almost all cookies from unvisited domains (stuffing).
    """
    if not cookie_events:
        return 0.0
    misses = sum(1 for e in cookie_events if e.domain not in navigated)
    return misses / len(cookie_events)


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(har: dict, threshold: float = 0.35) -> dict:
    navigated, events = parse_har(har)

    # Group events by cookie-setting domain
    by_domain: dict[str, DomainReport] = {}
    for ev in events:
        if ev.domain not in by_domain:
            by_domain[ev.domain] = DomainReport(domain=ev.domain)
        by_domain[ev.domain].cookies.append(ev)

    # Score each domain
    for domain, report in by_domain.items():
        # LZ novelty: not navigated (subdomains of navigated domains are clean)
        def _in_dict(d: str, nav: set) -> bool:
            if d in nav:
                return True
            return any(d.endswith("." + n) or n.endswith("." + d) for n in nav)
        report.lz_novelty = 0.0 if _in_dict(domain, navigated) else 1.0

        # Affiliate network match
        report.network_name = _match_affiliate_domain(domain)
        report.affiliate_url = max(
            (_affiliate_url_score(ev.url) for ev in report.cookies), default=0.0
        )
        report.affiliate_cookie = max(
            (_affiliate_cookie_score(ev.name) for ev in report.cookies), default=0.0
        )
        if report.network_name:
            report.affiliate_url  = max(report.affiliate_url, 1.0)

        # Hidden resource
        report.hidden_resource = max(
            (_hidden_resource_score(ev.resource_type, ev.initiator)
             for ev in report.cookies), default=0.0
        )

        # Early timing
        report.early_timing = max(
            (_early_timing_score(ev.timestamp) for ev in report.cookies), default=0.0
        )

        # No referrer
        no_ref_count = sum(1 for ev in report.cookies if not ev.referer)
        report.no_referrer = no_ref_count / len(report.cookies)

    # Information-theoretic summary
    nav_domains  = list(navigated)
    ck_domains   = [ev.domain for ev in events]
    nav_entropy  = _entropy(nav_domains)
    ck_entropy   = _entropy(ck_domains)
    novelty_rate = _lz_novelty_rate(navigated, events)

    suspicious = {d: r for d, r in by_domain.items() if r.suspicion >= threshold}
    clean      = {d: r for d, r in by_domain.items() if r.suspicion < threshold}

    return {
        "navigated_domains":  sorted(navigated),
        "total_cookies":      len(events),
        "total_domains":      len(by_domain),
        "suspicious":         suspicious,
        "clean":              clean,
        "nav_entropy_bits":   round(nav_entropy, 3),
        "cookie_entropy_bits": round(ck_entropy, 3),
        "lz_novelty_rate":    round(novelty_rate, 3),
        "threshold":          threshold,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

BOLD  = "\033[1m"
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
DIM   = "\033[2m"
RST   = "\033[0m"

VERDICT_COLOR = {"HIGH": RED, "MEDIUM": YEL, "CLEAN": GRN}


def _color(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return code + text + RST
    return text


def print_report(result: dict, verbose: bool = False) -> None:
    suspicious = result["suspicious"]
    clean      = result["clean"]

    print()
    print(_color("Cookie Stuffing Analysis", BOLD))
    print("─" * 50)
    print(f"  Navigated domains  : {len(result['navigated_domains'])}")
    print(f"  Cookies observed   : {result['total_cookies']}")
    print(f"  Cookie-setting doms: {result['total_domains']}")
    print()
    print("  Information-theoretic signals:")
    print(f"    Navigation entropy  : {result['nav_entropy_bits']:.2f} bits")
    print(f"    Cookie entropy      : {result['cookie_entropy_bits']:.2f} bits")
    nr = result["lz_novelty_rate"]
    nr_col = RED if nr > 0.4 else (YEL if nr > 0.15 else GRN)
    print(f"    LZ novelty rate     : {_color(f'{nr:.1%}', nr_col)}  "
          f"(fraction of cookies from unvisited domains)")
    print()

    if suspicious:
        print(_color(f"  SUSPICIOUS ({len(suspicious)} domain{'s' if len(suspicious) != 1 else ''}):", BOLD))
        for dom, r in sorted(suspicious.items(), key=lambda x: -x[1].suspicion):
            vc = VERDICT_COLOR[r.verdict]
            label = f"[{r.network_name}]" if r.network_name else "[unknown]"
            n_ck = len(r.cookies)
            print(f"    {_color(f'⚠  {r.verdict:<6}', vc)}  {dom}  "
                  f"{_color(label, DIM)}  "
                  f"{n_ck} cookie{'s' if n_ck != 1 else ''}  "
                  f"score={r.suspicion:.2f}")
            if verbose:
                _print_signals(r)
    else:
        print(_color("  No suspicious cookie stuffing detected.", GRN))

    print()
    if clean and verbose:
        print(_color(f"  CLEAN ({len(clean)} domains):", DIM))
        for dom, r in sorted(clean.items()):
            print(f"    {_color('✓', GRN)}  {dom}  ({len(r.cookies)} cookie{'s' if len(r.cookies) != 1 else ''})")
        print()

    if suspicious:
        print(_color("  Summary:", BOLD))
        print(f"  {len(suspicious)} of {result['total_domains']} cookie-setting domains")
        print(f"  look like affiliate stuffing.")
        print(f"  Run with --verbose for per-signal breakdown.")
    print()


def _print_signals(r: DomainReport) -> None:
    def bar(v: float) -> str:
        n = int(v * 10)
        return "█" * n + "░" * (10 - n)
    print(f"         LZ novelty      [{bar(r.lz_novelty)}] {r.lz_novelty:.2f}")
    print(f"         Affiliate URL   [{bar(r.affiliate_url)}] {r.affiliate_url:.2f}")
    print(f"         Affiliate cookie[{bar(r.affiliate_cookie)}] {r.affiliate_cookie:.2f}")
    print(f"         Hidden resource [{bar(r.hidden_resource)}] {r.hidden_resource:.2f}")
    print(f"         Early timing    [{bar(r.early_timing)}] {r.early_timing:.2f}")
    print(f"         No referrer     [{bar(r.no_referrer)}] {r.no_referrer:.2f}")
    for ev in r.cookies[:3]:
        print(f"         cookie: {ev.name}={ev.value[:20]}… "
              f"via {ev.resource_type} @ {ev.timestamp:.1f}s")


# ---------------------------------------------------------------------------
# Built-in demo HAR (no file needed)
# ---------------------------------------------------------------------------

def _make_demo_har() -> dict:
    """
    Synthetic HAR simulating a shopping-app session with cookie stuffing.

    Scenario:
      - User visits phia-demo.example (the shopping app)
      - Page silently fires requests to 4 affiliate networks via hidden pixels
      - User then loads amazon-demo.example (legitimate navigation)
      - Stuffed affiliate cookies will claim credit for any purchase there
    """
    import time
    t0 = "2026-08-13T10:00:00.000Z"

    def _entry(url, rtype, init_type, resp_cookies, referer="", delay_ms=0):
        return {
            "startedDateTime": f"2026-08-13T10:00:0{delay_ms // 1000}.{delay_ms % 1000:03d}Z",
            "time": 50,
            "_resourceType": rtype,
            "_initiator": {"type": init_type},
            "request": {
                "method": "GET",
                "url": url,
                "headers": ([{"name": "Referer", "value": referer}] if referer else []),
                "cookies": [],
            },
            "response": {
                "status": 200,
                "headers": [],
                "cookies": resp_cookies,
            },
            "pageref": "page_1",
        }

    def _ck(name, value, domain):
        return {"name": name, "value": value, "domain": domain, "path": "/"}

    return {"log": {"version": "1.2", "pages": [], "entries": [
        # Legitimate navigation: user visits the shopping app
        _entry("https://phia-demo.example/",
               "document", "navigation",
               [_ck("session", "abc123", "phia-demo.example"),
                _ck("_ga", "GA1.2.xyz", "phia-demo.example")],
               delay_ms=0),

        # Legitimate: CDN asset from same origin
        _entry("https://cdn.phia-demo.example/app.js",
               "script", "parser",
               [_ck("cdn_cache", "v2", "cdn.phia-demo.example")],
               referer="https://phia-demo.example/",
               delay_ms=100),

        # ── STUFFING: hidden 1x1 affiliate pixels fired at page load ──

        # Commission Junction pixel — no user interaction possible at 200ms
        _entry("https://www.cj.com/click/?SID=phia123&PID=9876&url=https://amazon.com",
               "image", "script",
               [_ck("cj_g", "5f3a9c", "cj.com"),
                _ck("cje", "session_xyz", "cj.com")],
               referer="https://phia-demo.example/",
               delay_ms=200),

        # Awin pixel
        _entry("https://www.awin1.com/cread.php?awinmid=1234&awinaffid=567890",
               "image", "script",
               [_ck("aw", "partner_phia", "awin1.com")],
               referer="https://phia-demo.example/",
               delay_ms=210),

        # ShareASale redirect
        _entry("https://www.shareasale.com/click.cfm?merchantID=5678&affid=9999",
               "image", "script",
               [_ck("SSAID", "9999_phia", "shareasale.com"),
                _ck("affiliate_ref", "phia_app", "shareasale.com")],
               referer="https://phia-demo.example/",
               delay_ms=220),

        # Rakuten XHR
        _entry("https://click.linksynergy.com/deeplink?id=phia&mid=12345&u1=track",
               "xhr", "script",
               [_ck("rakuten_ls", "phia_publisher", "linksynergy.com")],
               delay_ms=250),  # no referer — injected directly

        # Legitimate: user navigates to Amazon (separate visit)
        _entry("https://amazon-demo.example/",
               "document", "navigation",
               [_ck("session-id", "amz_abc", "amazon-demo.example"),
                _ck("csm-hit", "tb:xyz", "amazon-demo.example")],
               delay_ms=30000),  # 30 seconds later

        # Legitimate: Amazon CDN
        _entry("https://images-na.amazon-demo.example/image.jpg",
               "image", "parser",
               [],
               referer="https://amazon-demo.example/",
               delay_ms=30100),
    ]}}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Detect cookie stuffing in HAR files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1].strip() if "Usage:" in __doc__ else "",
    )
    ap.add_argument("har_file", nargs="?", help="Path to .har file")
    ap.add_argument("--threshold", type=float, default=0.35,
                    help="Suspicion score threshold for flagging (default: 0.35)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Show per-signal breakdown and clean domains")
    ap.add_argument("--json", action="store_true",
                    help="Output raw JSON result instead of formatted report")
    ap.add_argument("--demo", action="store_true",
                    help="Run on built-in synthetic stuffed session (no file needed)")
    args = ap.parse_args()

    if args.demo:
        har = _make_demo_har()
        print(_color("[demo mode — synthetic stuffed session]", DIM))
    elif args.har_file:
        try:
            with open(args.har_file, "r", errors="replace") as f:
                har = json.load(f)
        except FileNotFoundError:
            print(f"Error: file not found: {args.har_file}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON in {args.har_file}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        ap.print_help()
        sys.exit(0)

    result = analyze(har, threshold=args.threshold)

    if args.json:
        # Make serializable
        out = {k: v for k, v in result.items()
               if k not in ("suspicious", "clean")}
        out["suspicious"] = {
            d: {"suspicion": round(r.suspicion, 3), "verdict": r.verdict,
                "network": r.network_name, "cookies": len(r.cookies),
                "signals": {
                    "lz_novelty": r.lz_novelty,
                    "affiliate_url": r.affiliate_url,
                    "affiliate_cookie": r.affiliate_cookie,
                    "hidden_resource": r.hidden_resource,
                    "early_timing": r.early_timing,
                    "no_referrer": r.no_referrer,
                }}
            for d, r in result["suspicious"].items()
        }
        print(json.dumps(out, indent=2))
    else:
        print_report(result, verbose=args.verbose)

    sys.exit(1 if result["suspicious"] else 0)


if __name__ == "__main__":
    main()
