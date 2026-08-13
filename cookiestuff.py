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
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
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
# Live URL capture via Playwright
# ---------------------------------------------------------------------------

def _check_playwright() -> None:
    try:
        import playwright  # noqa: F401
    except ImportError:
        print(
            "Error: --url requires playwright.\n\n"
            "Install with:\n"
            "  pip install playwright\n"
            "  playwright install chromium\n",
            file=sys.stderr,
        )
        sys.exit(1)


async def _capture_har_async(url: str, wait: float, headless: bool,
                              har_path: str) -> None:
    from playwright.async_api import async_playwright
    import asyncio

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(
            record_har_path=har_path,
            record_har_content="omit",   # skip response bodies — we only need headers/cookies
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
        )
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        except Exception:
            pass  # partial loads still capture cookies
        # wait for lazy-loaded affiliate scripts (the stuffing often fires 1-3s in)
        await asyncio.sleep(wait)
        await context.close()
        await browser.close()


def capture_url(url: str, wait: float = 4.0, headless: bool = True) -> dict:
    """
    Visit *url* in a headless Chromium browser, record all network traffic as
    HAR, and return the parsed HAR dict.  Waits *wait* seconds after DOMContentLoaded
    to catch lazy-loaded affiliate scripts.
    """
    import asyncio, tempfile, os

    _check_playwright()

    with tempfile.NamedTemporaryFile(suffix=".har", delete=False) as f:
        har_path = f.name

    try:
        asyncio.run(_capture_har_async(url, wait, headless, har_path))
        with open(har_path, "r", errors="replace") as f:
            return json.load(f)
    finally:
        try:
            os.unlink(har_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Browser-native cookie scanner
# ---------------------------------------------------------------------------

def _browser_profile_dirs() -> list[tuple[str, Path]]:
    """Return (label, profile_path) for every detected Chromium-family browser profile."""
    home = Path.home()
    plat = sys.platform

    if plat == "darwin":
        roots = [
            ("Chrome",      home / "Library/Application Support/Google/Chrome"),
            ("Chrome Beta", home / "Library/Application Support/Google/Chrome Beta"),
            ("Chromium",    home / "Library/Application Support/Chromium"),
            ("Edge",        home / "Library/Application Support/Microsoft Edge"),
            ("Brave",       home / "Library/Application Support/BraveSoftware/Brave-Browser"),
            ("Vivaldi",     home / "Library/Application Support/Vivaldi"),
            ("Opera",       home / "Library/Application Support/com.operasoftware.Opera"),
        ]
    elif plat.startswith("linux"):
        roots = [
            ("Chrome",   home / ".config/google-chrome"),
            ("Chromium", home / ".config/chromium"),
            ("Edge",     home / ".config/microsoft-edge"),
            ("Brave",    home / ".config/BraveSoftware/Brave-Browser"),
        ]
    elif plat == "win32":
        ld = Path(os.environ.get("LOCALAPPDATA", ""))
        roots = [
            ("Chrome",   ld / "Google/Chrome/User Data"),
            ("Edge",     ld / "Microsoft/Edge/User Data"),
            ("Brave",    ld / "BraveSoftware/Brave-Browser/User Data"),
        ]
    else:
        roots = []

    results = []
    for name, root in roots:
        if not root.exists():
            continue
        for profile in ["Default", "Profile 1", "Profile 2", "Profile 3",
                        "Profile 4", "Profile 5"]:
            p = root / profile
            if (p / "Cookies").exists() or (p / "History").exists():
                label = name if profile == "Default" else f"{name} / {profile}"
                results.append((label, p))
    return results


def _firefox_profile_dirs() -> list[tuple[str, Path]]:
    home = Path.home()
    plat = sys.platform

    if plat == "darwin":
        base = home / "Library/Application Support/Firefox/Profiles"
    elif plat.startswith("linux"):
        base = home / ".mozilla/firefox"
    elif plat == "win32":
        base = Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles"
    else:
        return []

    if not base.exists():
        return []

    return [
        (f"Firefox ({d.name})", d)
        for d in base.iterdir()
        if d.is_dir() and (d / "cookies.sqlite").exists()
    ]


def _copy_db(src: Path) -> Optional[Path]:
    """Copy a SQLite file to temp so we can read it while the browser holds the lock."""
    if not src.exists():
        return None
    try:
        fd, dst = tempfile.mkstemp(suffix=".sqlite", prefix="cookiestuff_")
        os.close(fd)
        shutil.copy2(src, dst)
        return Path(dst)
    except OSError:
        return None


def _chromium_history_domains(profile: Path) -> set[str]:
    tmp = _copy_db(profile / "History")
    if not tmp:
        return set()
    domains: set[str] = set()
    try:
        conn = sqlite3.connect(str(tmp))
        for (url,) in conn.execute("SELECT url FROM urls WHERE url IS NOT NULL"):
            d = _domain(url)
            if d:
                domains.add(d)
        conn.close()
    except sqlite3.Error:
        pass
    finally:
        tmp.unlink(missing_ok=True)
    return domains


def _firefox_history_domains(profile: Path) -> set[str]:
    tmp = _copy_db(profile / "places.sqlite")
    if not tmp:
        return set()
    domains: set[str] = set()
    try:
        conn = sqlite3.connect(str(tmp))
        for (url,) in conn.execute(
            "SELECT url FROM moz_places WHERE url IS NOT NULL"
        ):
            d = _domain(url)
            if d:
                domains.add(d)
        conn.close()
    except sqlite3.Error:
        pass
    finally:
        tmp.unlink(missing_ok=True)
    return domains


@dataclass
class BrowserCookie:
    browser: str
    domain:  str
    name:    str


def _chromium_cookies(profile: Path, label: str) -> list[BrowserCookie]:
    tmp = _copy_db(profile / "Cookies")
    if not tmp:
        return []
    cookies: list[BrowserCookie] = []
    try:
        conn = sqlite3.connect(str(tmp))
        for (host, name) in conn.execute("SELECT host_key, name FROM cookies"):
            if host:
                cookies.append(BrowserCookie(label, host.lstrip("."), name or ""))
        conn.close()
    except sqlite3.Error:
        pass
    finally:
        tmp.unlink(missing_ok=True)
    return cookies


def _firefox_cookies(profile: Path, label: str) -> list[BrowserCookie]:
    tmp = _copy_db(profile / "cookies.sqlite")
    if not tmp:
        return []
    cookies: list[BrowserCookie] = []
    try:
        conn = sqlite3.connect(str(tmp))
        for (host, name) in conn.execute("SELECT host, name FROM moz_cookies"):
            if host:
                cookies.append(BrowserCookie(label, host.lstrip("."), name or ""))
        conn.close()
    except sqlite3.Error:
        pass
    finally:
        tmp.unlink(missing_ok=True)
    return cookies


def scan_browser(threshold: float = 0.35) -> dict:
    """
    Scan all browser cookie databases on this machine.

    Reads browser history as the navigation dictionary (same LZ novelty approach as HAR
    analysis). Three of six signals are available without a live session: LZ novelty,
    affiliate domain fingerprint, and affiliate cookie name. Score is renormalized to
    the 0.0–1.0 range so the same HIGH/MEDIUM/CLEAN thresholds apply.
    """
    all_cookies: list[BrowserCookie] = []
    nav_domains: set[str] = set()
    scanned: list[str] = []

    for label, profile in _browser_profile_dirs():
        h = _chromium_history_domains(profile)
        c = _chromium_cookies(profile, label)
        if h or c:
            nav_domains |= h
            all_cookies.extend(c)
            scanned.append(label)

    for label, profile in _firefox_profile_dirs():
        h = _firefox_history_domains(profile)
        c = _firefox_cookies(profile, label)
        if h or c:
            nav_domains |= h
            all_cookies.extend(c)
            scanned.append(label)

    by_domain: dict[str, list[BrowserCookie]] = defaultdict(list)
    for ck in all_cookies:
        if ck.domain:
            by_domain[ck.domain].append(ck)

    def _in_dict(d: str) -> bool:
        return d in nav_domains or any(
            d.endswith("." + n) or n.endswith("." + d) for n in nav_domains
        )

    suspicious: dict[str, dict] = {}
    clean:      dict[str, dict] = {}

    for domain, cks in by_domain.items():
        lz      = 0.0 if _in_dict(domain) else 1.0
        network = _match_affiliate_domain(domain)
        aff_dom = 1.0 if network else 0.0
        aff_ck  = max((_affiliate_cookie_score(ck.name) for ck in cks), default=0.0)

        # Renormalize over available signal weights: 0.30 + 0.25 + 0.15 = 0.70
        score   = min(1.0, (0.30 * lz + 0.25 * aff_dom + 0.15 * aff_ck) / 0.70)
        verdict = "HIGH" if score >= 0.65 else ("MEDIUM" if score >= 0.35 else "CLEAN")

        rec = {
            "domain":     domain,
            "cookies":    cks,
            "network":    network,
            "lz_novelty": lz,
            "aff_domain": aff_dom,
            "aff_cookie": aff_ck,
            "score":      score,
            "verdict":    verdict,
            "browsers":   sorted({ck.browser for ck in cks}),
        }
        if score >= threshold:
            suspicious[domain] = rec
        else:
            clean[domain] = rec

    return {
        "mode":          "browser_scan",
        "scanned":       scanned,
        "nav_count":     len(nav_domains),
        "total_cookies": len(all_cookies),
        "total_domains": len(by_domain),
        "suspicious":    suspicious,
        "clean":         clean,
        "threshold":     threshold,
    }


def print_scan_report(result: dict, verbose: bool = False, guide: bool = False) -> None:
    suspicious = result["suspicious"]
    clean      = result["clean"]

    print()
    print(_color("Browser Cookie Audit", BOLD))
    print("─" * 50)
    for b in result["scanned"]:
        print(f"  Browser : {b}")
    print(f"  History : {result['nav_count']:,} domains  (navigation dictionary from history)")
    print(f"  Cookies : {result['total_cookies']:,} total across {result['total_domains']:,} domains")
    print()
    print(_color("  Active signals: LZ novelty · affiliate domain · affiliate cookie name", DIM))
    print(_color("  Timing + referrer signals require a live session (--url or HAR file)", DIM))
    print()

    if suspicious:
        print(_color(f"  SUSPICIOUS ({len(suspicious)} domain{'s' if len(suspicious) != 1 else ''}):", BOLD))
        for domain, r in sorted(suspicious.items(), key=lambda x: -x[1]["score"]):
            vc         = VERDICT_COLOR[r["verdict"]]
            label      = f"[{r['network']}]" if r["network"] else "[unknown network]"
            n_ck       = len(r["cookies"])
            verdict_str = f"⚠  {r['verdict']:<6}"
            print(f"    {_color(verdict_str, vc)}  {domain}  "
                  f"{_color(label, DIM)}  "
                  f"{n_ck} cookie{'s' if n_ck != 1 else ''}  "
                  f"score={r['score']:.2f}")
            print(f"             {_color(', '.join(r['browsers']), DIM)}")
            if verbose:
                _print_scan_signals(r)
    else:
        print(_color("  No suspicious affiliate cookies found.", GRN))

    print()
    if clean and verbose:
        print(_color(f"  CLEAN ({len(clean)} domains):", DIM))
        for domain, r in sorted(clean.items()):
            print(f"    {_color('✓', GRN)}  {domain}  ({len(r['cookies'])} cookies)")
        print()

    if suspicious:
        print(_color("  Summary:", BOLD))
        print(f"  {len(suspicious)} of {result['total_domains']} cookie domains are suspicious.")
        print(f"  Run with --verbose for per-signal detail and cookie names.")
        print(f"  Run with --guide for step-by-step removal instructions.")
    print()

    if guide:
        _print_scan_removal_guide(result)


def _print_scan_signals(r: dict) -> None:
    def bar(v: float) -> str:
        n = int(v * 10)
        return "█" * n + "░" * (10 - n)
    na = "─" * 10
    print(f"         LZ novelty      [{bar(r['lz_novelty'])}] {r['lz_novelty']:.2f}  "
          f"({'not in history' if r['lz_novelty'] else 'in history'})")
    print(f"         Affiliate domain[{bar(r['aff_domain'])}] {r['aff_domain']:.2f}")
    print(f"         Affiliate cookie[{bar(r['aff_cookie'])}] {r['aff_cookie']:.2f}")
    print(f"         Hidden resource [{na}] N/A")
    print(f"         Early timing    [{na}] N/A")
    print(f"         No referrer     [{na}] N/A")
    for ck in r["cookies"][:5]:
        print(f"         cookie: {ck.name!r}  ({ck.browser})")


def _print_scan_removal_guide(result: dict) -> None:
    suspicious = result["suspicious"]
    if not suspicious:
        return

    by_browser: dict[str, list[str]] = defaultdict(list)
    for domain, r in suspicious.items():
        for b in r["browsers"]:
            by_browser[b].append(domain)

    print(_color("How to remove these cookies", BOLD))
    print("─" * 50)
    print()
    print("  Suspicious domains found:")
    for domain, r in sorted(suspicious.items(), key=lambda x: -x[1]["score"]):
        label = f"  [{r['network']}]" if r["network"] else ""
        print(f"    • {domain}{label}")
    print()

    for browser_label in sorted(by_browser.keys()):
        domains = by_browser[browser_label]
        print(_color(f"  {browser_label}", BOLD))
        if "Firefox" in browser_label:
            print("  1. Settings → Privacy & Security → Cookies and Site Data → Manage Data")
            for d in domains:
                print(f"  2. Search '{d}' → Remove Selected → Save Changes")
            print("  — Or: F12 → Storage → Cookies → select domain → delete all rows")
        else:
            print("  Surgical removal:")
            print("  1. Settings → Privacy and security → Cookies and other site data")
            print("  2. See all site data and permissions")
            for d in domains:
                print(f"  3. Search '{d}' → click the trash icon")
            print("  — Or nuclear: Settings → Delete browsing data → All time → Cookies → Delete")
        print()

    print(_color("  DevTools (fastest — works in any browser)", BOLD))
    print("  F12 → Application tab → Cookies (left sidebar)")
    for domain in sorted(suspicious.keys()):
        print(f"    Select '{domain}' → Ctrl+A / Cmd+A → Delete")
    print()

    print(_color("  Report the fraud", BOLD))
    print("  • The retailer's affiliate team  (search '<retailer> affiliate program')")
    print("  • FTC (US):   reportfraud.ftc.gov")
    print("  • ICO (UK):   ico.org.uk/make-a-complaint")
    print("  • Your state attorney general")
    print()


# ---------------------------------------------------------------------------
# Removal guide printer
# ---------------------------------------------------------------------------

def print_removal_guide(result: dict) -> None:
    suspicious = result["suspicious"]
    if not suspicious:
        return

    domains = sorted(suspicious)
    print(_color("How to remove these cookies", BOLD))
    print("─" * 50)
    print()
    print("  The following domains dropped cookies without your consent:")
    for d in domains:
        r = suspicious[d]
        label = f"  [{r.network_name}]" if r.network_name else ""
        print(f"    • {d}{label}")
    print()

    print(_color("  Chrome / Edge", BOLD))
    print("  1. Open Settings → Privacy and security → Delete browsing data")
    print("  2. Choose 'All time', check 'Cookies and other site data', click Delete")
    print("     — OR — for surgical removal:")
    print("  1. Settings → Privacy and security → Cookies and other site data")
    print("  2. 'See all site data and permissions'")
    for d in domains:
        print(f"  3. Search '{d}', click the trash icon")
    print()

    print(_color("  Firefox", BOLD))
    print("  1. Settings → Privacy & Security → Cookies and Site Data → Manage Data")
    for d in domains:
        print(f"  2. Search '{d}', select, click 'Remove Selected'")
    print()

    print(_color("  Safari", BOLD))
    print("  1. Develop menu → Show Web Inspector → Storage tab → Cookies")
    for d in domains:
        print(f"  2. Find '{d}', right-click → Delete")
    print("  — OR — Safari → Settings → Privacy → Manage Website Data")
    print()

    print(_color("  DevTools (any browser) — surgical, one domain at a time", BOLD))
    print("  1. F12 → Application tab → Cookies (left sidebar)")
    for d in domains:
        print(f"  2. Select '{d}' → select all rows → Delete")
    print()

    print(_color("  Report the fraud", BOLD))
    print("  Stuffing harms the retailers who pay commissions and the legitimate")
    print("  affiliates who drove the sale. Report to:")
    print()
    print("  • The retailer's affiliate team")
    print("    (search '<retailer> affiliate program contact')")
    print("  • The affiliate network directly:")
    for d, r in suspicious.items():
        if r.network_name:
            print(f"    - {r.network_name}: report publisher fraud via their dashboard")
    print("  • FTC (US):  reportfraud.ftc.gov")
    print("  • ICO (UK):  ico.org.uk/make-a-complaint")
    print("  • Your state attorney general")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Detect cookie stuffing in HAR files or live URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("har_file", nargs="?", help="Path to .har file to analyze")
    ap.add_argument("--url", metavar="URL",
                    help="Visit this URL in headless Chromium, capture HAR, and analyze")
    ap.add_argument("--wait", type=float, default=4.0, metavar="SECONDS",
                    help="Seconds to wait after page load when using --url (default: 4)")
    ap.add_argument("--no-headless", action="store_true",
                    help="Show browser window when using --url (useful for debugging)")
    ap.add_argument("--threshold", type=float, default=0.35,
                    help="Suspicion score threshold for flagging (default: 0.35)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Show per-signal breakdown and clean domains")
    ap.add_argument("--json", action="store_true",
                    help="Output raw JSON instead of formatted report")
    ap.add_argument("--guide", action="store_true",
                    help="After the report, print browser cookie removal instructions")
    ap.add_argument("--demo", action="store_true",
                    help="Run on built-in synthetic stuffed session (no file needed)")
    ap.add_argument("--scan-browser", action="store_true",
                    help="Scan browser cookie databases on this machine (Chrome, Firefox, Edge, Brave)")
    args = ap.parse_args()

    # --- Browser scan mode (reads local databases, no HAR needed) ---
    if args.scan_browser:
        print(_color("[scanning browser databases…]", DIM), flush=True)
        result = scan_browser(threshold=args.threshold)
        if args.json:
            out = {k: v for k, v in result.items() if k not in ("suspicious", "clean")}
            out["suspicious"] = {
                d: {
                    "score":    round(r["score"], 3),
                    "verdict":  r["verdict"],
                    "network":  r["network"],
                    "cookies":  len(r["cookies"]),
                    "browsers": r["browsers"],
                    "signals": {
                        "lz_novelty": r["lz_novelty"],
                        "aff_domain": r["aff_domain"],
                        "aff_cookie": r["aff_cookie"],
                    },
                }
                for d, r in result["suspicious"].items()
            }
            print(json.dumps(out, indent=2))
        else:
            print_scan_report(result, verbose=args.verbose, guide=args.guide)
        sys.exit(1 if result["suspicious"] else 0)

    # --- Load HAR ---
    if args.demo:
        har = _make_demo_har()
        print(_color("[demo mode — synthetic stuffed session]", DIM))

    elif args.url:
        print(_color(f"[capturing {args.url} — please wait {args.wait:.0f}s …]", DIM),
              flush=True)
        har = capture_url(args.url, wait=args.wait, headless=not args.no_headless)
        print(_color(f"[captured {len(har.get('log',{}).get('entries',[]))} requests]", DIM))

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
        print("\nExamples:")
        print("  python cookiestuff.py --scan-browser --guide   # audit your machine right now")
        print("  python cookiestuff.py --demo                   # see the tool in action")
        print("  python cookiestuff.py --url https://example.com --verbose --guide")
        print("  python cookiestuff.py session.har --guide")
        sys.exit(0)

    # --- Analyze ---
    result = analyze(har, threshold=args.threshold)

    if args.json:
        out = {k: v for k, v in result.items() if k not in ("suspicious", "clean")}
        out["suspicious"] = {
            d: {"suspicion": round(r.suspicion, 3), "verdict": r.verdict,
                "network": r.network_name, "cookies": len(r.cookies),
                "signals": {
                    "lz_novelty":       r.lz_novelty,
                    "affiliate_url":    r.affiliate_url,
                    "affiliate_cookie": r.affiliate_cookie,
                    "hidden_resource":  r.hidden_resource,
                    "early_timing":     r.early_timing,
                    "no_referrer":      r.no_referrer,
                }}
            for d, r in result["suspicious"].items()
        }
        print(json.dumps(out, indent=2))
    else:
        print_report(result, verbose=args.verbose)
        if args.guide:
            print_removal_guide(result)

    sys.exit(1 if result["suspicious"] else 0)


if __name__ == "__main__":
    main()
