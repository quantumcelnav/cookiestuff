#!/usr/bin/env python3
"""
sweep.py — Automated cookie stuffing detection sweep.

Drives Firefox with the CookieStuff extension across N domains, collecting
per-site suspicion scores for analysis and empirical validation.

Requirements:
    pip install selenium
    brew install geckodriver     # or: apt-get install geckodriver

Usage:
    python sweep.py --quick                        # 30 curated retail/news sites
    python sweep.py --count 200                    # first 200 from Tranco list
    python sweep.py --domains tranco.csv --count 1000 --dwell 8

Download the Tranco top-1M domain list:
    curl -L https://tranco-list.eu/top-1m.csv.zip -o top-1m.csv.zip
    unzip top-1m.csv.zip && mv top-1m.csv tranco_1m.csv
"""

import argparse
import csv
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.common.exceptions import (
        TimeoutException, WebDriverException, JavascriptException
    )
except ImportError:
    print("selenium not found. Run:  pip install selenium", file=sys.stderr)
    sys.exit(1)

EXT_DIR   = Path(__file__).parent / "extension"
GECKO_ID  = "cookiestuff@thecanonicalart.com"
PAGE_TIMEOUT = 15   # seconds max for page load before giving up

# Curated quick-test list: sites with known affiliate cookie activity.
QUICK_SITES = [
    # Coupon / deal aggregators — very high affiliate cookie density
    "slickdeals.net", "retailmenot.com", "coupons.com", "dealnews.com",
    "brad'sdeals.com",
    # Major retail
    "amazon.com", "target.com", "walmart.com", "bestbuy.com",
    "ebay.com", "etsy.com", "wayfair.com", "homedepot.com",
    "kohls.com", "macys.com", "nordstrom.com", "gap.com",
    "newegg.com", "bhphotovideo.com", "rei.com",
    # Travel (heavy affiliate embedding)
    "booking.com", "expedia.com", "tripadvisor.com",
    # News / media with embedded affiliate links
    "yahoo.com", "cnn.com", "buzzfeed.com", "wirecutter.com",
    "theverge.com", "techcrunch.com", "cnet.com", "pcmag.com",
    "tomsguide.com", "techradar.com",
]


# ─── Domain list loading ──────────────────────────────────────────────────────

def load_tranco(path: str, count: int) -> list[str]:
    """Load domains from a Tranco-format CSV (rank,domain)."""
    domains = []
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if not row:
                continue
            domain = row[-1].strip().lower()
            if domain and not domain.startswith("#"):
                domains.append(domain)
            if len(domains) >= count:
                break
    return domains


# ─── Firefox / extension setup ────────────────────────────────────────────────

def get_popup_url(driver: webdriver.Firefox, gecko_id: str) -> str | None:
    """
    Discover the extension's popup URL from the Firefox profile.

    After install_addon(), Firefox writes the extension UUID to prefs.js under
    extensions.webextensions.uuids. We parse that to build the popup URL.
    The popup runs in the extension context, giving us access to browser.*.
    """
    profile_dir = driver.capabilities.get("moz:profile", "")
    if not profile_dir:
        return None

    # Retry a few times — Firefox may not have written prefs.js yet.
    for attempt in range(8):
        prefs_path = Path(profile_dir) / "prefs.js"
        if prefs_path.exists():
            content = prefs_path.read_text(errors="replace")
            for line in content.splitlines():
                if "webextensions.uuids" not in line:
                    continue
                # prefs.js stores this as a JSON string with escaped quotes:
                # user_pref("extensions.webextensions.uuids", "{\"id\":\"uuid\"}");
                m = re.search(
                    r'user_pref\("extensions\.webextensions\.uuids",\s*"(.+)"\)',
                    line
                )
                if m:
                    try:
                        raw = m.group(1).replace('\\"', '"')
                        uuid_map = json.loads(raw)
                        uuid = uuid_map.get(gecko_id)
                        if uuid:
                            return f"moz-extension://{uuid}/popup/popup.html"
                    except Exception:
                        pass
                # Direct regex fallback (handles minor formatting variations).
                m2 = re.search(
                    r'"' + re.escape(gecko_id) + r'":\s*"([a-f0-9-]+)"', line
                )
                if m2:
                    return f"moz-extension://{m2.group(1)}/popup/popup.html"
        time.sleep(0.4)

    return None


def make_driver(headless: bool = True) -> tuple[webdriver.Firefox, str | None]:
    """Launch Firefox with CookieStuff extension; return (driver, popup_url)."""
    opts = Options()
    if headless:
        opts.add_argument("-headless")
    opts.set_preference("browser.startup.homepage", "about:blank")
    opts.set_preference("browser.tabs.warnOnClose", False)
    opts.set_preference("browser.shell.checkDefaultBrowser", False)
    opts.set_preference("extensions.autoDisableScopes", 0)
    opts.set_preference("extensions.enabledScopes", 15)
    # Suppress update nags and first-run UI.
    opts.set_preference("app.update.enabled", False)
    opts.set_preference("datareporting.policy.dataSubmissionEnabled", False)

    driver = webdriver.Firefox(options=opts)
    driver.set_page_load_timeout(PAGE_TIMEOUT)

    # Install extension and let Firefox register the UUID.
    driver.install_addon(str(EXT_DIR), temporary=True)
    driver.get("about:blank")   # triggers extension activation
    time.sleep(1.5)

    popup_url = get_popup_url(driver, GECKO_ID)
    if not popup_url:
        print(
            "WARNING: could not auto-detect popup URL.\n"
            "  UUID discovery failed. Re-run with --no-headless and check\n"
            "  about:debugging#/runtime/this-firefox to find the UUID,\n"
            "  then set COOKIESTUFF_POPUP_URL in your environment.",
            file=sys.stderr
        )
        # Allow manual override via environment variable.
        import os
        if url := os.environ.get("COOKIESTUFF_POPUP_URL"):
            popup_url = url
            print(f"  Using env override: {popup_url}", file=sys.stderr)

    return driver, popup_url


# ─── Extension communication ──────────────────────────────────────────────────

def read_and_clear_state(
    driver: webdriver.Firefox, popup_url: str
) -> dict:
    """
    Navigate to the popup URL (extension context), read GET_STATE, then
    send CLEAR_SESSION so the next site starts with a clean slate.

    The navDict (persistent across sessions) is NOT cleared — only the
    in-memory domainReports for the current session.
    """
    if not popup_url:
        return {}
    try:
        driver.get(popup_url)
        time.sleep(0.4)
        result = driver.execute_async_script("""
            const done = arguments[arguments.length - 1];
            if (typeof browser === 'undefined') { done(null); return; }
            browser.runtime.sendMessage({type: 'GET_STATE'})
                .then(state =>
                    browser.runtime.sendMessage({type: 'CLEAR_SESSION'})
                        .then(() => done(state))
                )
                .catch(err => done(null));
        """)
        return result or {}
    except (JavascriptException, WebDriverException) as e:
        print(f"  [warn] state read: {e.__class__.__name__}", file=sys.stderr)
        return {}


# ─── Site visit ───────────────────────────────────────────────────────────────

def visit_site(driver: webdriver.Firefox, domain: str, dwell: int) -> bool:
    """
    Navigate to https://domain, wait dwell seconds for cookies to load.
    Returns True even on timeout — the extension may have captured cookies
    before the page fully loaded.
    """
    try:
        driver.get(f"https://{domain}")
        time.sleep(dwell)
        return True
    except TimeoutException:
        return True     # partial load is fine; extension still collected data
    except WebDriverException:
        return False


# ─── Output ───────────────────────────────────────────────────────────────────

def write_output(results: list[dict], out: str):
    """Write JSON and a flattened CSV of per-site × per-domain results."""
    out_path = Path(out)
    out_path.write_text(json.dumps(results, indent=2))

    csv_path = out_path.with_suffix(".csv")
    rows = []
    for r in results:
        for cd in r.get("cookie_domains", []):
            sig = cd.get("signals", {})
            rows.append({
                "site":            r["site"],
                "cookie_domain":   cd.get("domain", ""),
                "network":         cd.get("network") or "",
                "isFraud":         cd.get("isFraud", False),
                "suspicion":       cd.get("suspicion", 0),
                "verdict":         cd.get("verdict", ""),
                "lzNovelty":       sig.get("lzNovelty", 0),
                "affiliateUrl":    sig.get("affiliateUrl", 0),
                "affiliateCookie": sig.get("affiliateCookie", 0),
                "hiddenResource":  sig.get("hiddenResource", 0),
                "earlyTiming":     sig.get("earlyTiming", 0),
                "noReferrer":      sig.get("noReferrer", 0),
                "cookieCount":     cd.get("cookieCount", 0),
            })

    if rows:
        with csv_path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)


# ─── Main sweep ───────────────────────────────────────────────────────────────

def sweep(
    domains: list[str],
    dwell: int,
    headless: bool,
    out: str,
    batch_size: int = 75,
) -> list[dict]:
    """
    Visit domains in batches. Firefox is restarted between batches to avoid
    memory bloat. The navDict persists via storage.local across restarts,
    so the dictionary grows continuously throughout the sweep.
    """
    results: list[dict] = []
    total_batches = (len(domains) + batch_size - 1) // batch_size

    for batch_idx in range(total_batches):
        batch = domains[batch_idx * batch_size : (batch_idx + 1) * batch_size]
        print(f"\n{'─'*60}")
        print(f"Batch {batch_idx+1}/{total_batches}  "
              f"({len(batch)} sites, "
              f"sites {batch_idx*batch_size+1}–{batch_idx*batch_size+len(batch)})")
        print(f"{'─'*60}")

        driver, popup_url = make_driver(headless)
        if popup_url:
            print(f"Popup URL: {popup_url}\n")

        # Clear any leftover session state from a previous run on the same
        # profile (navDict is preserved intentionally).
        read_and_clear_state(driver, popup_url)

        try:
            for i, domain in enumerate(batch):
                global_idx = batch_idx * batch_size + i + 1
                print(
                    f"[{global_idx:>4}/{len(domains)}] {domain:<40}",
                    end="", flush=True
                )

                ok = visit_site(driver, domain, dwell)
                if not ok:
                    print("SKIP")
                    continue

                state = read_and_clear_state(driver, popup_url)
                suspicious   = state.get("suspicious", [])
                total_cookies = state.get("totalCookies", 0)
                lz_rate      = state.get("lzNoveltyRate", 0)
                nav_size     = state.get("navDictSize", 0)

                high  = sum(1 for r in suspicious if r.get("verdict") == "HIGH")
                fraud = sum(1 for r in suspicious if r.get("isFraud"))

                print(
                    f"cookies={total_cookies:>3}  "
                    f"susp={len(suspicious):>2}  "
                    f"high={high:>2}  "
                    f"fraud={fraud:>2}  "
                    f"lz={lz_rate:>4.0f}%  "
                    f"dict={nav_size}"
                )

                results.append({
                    "site":            domain,
                    "visited_at":      datetime.now(timezone.utc).isoformat(),
                    "ok":              ok,
                    "total_cookies":   total_cookies,
                    "lz_novelty_rate": lz_rate,
                    "nav_dict_size":   nav_size,
                    "suspicious_count": len(suspicious),
                    "high_count":      high,
                    "fraud_count":     fraud,
                    "cookie_domains":  suspicious,
                })

                # Checkpoint after each site so a crash loses minimal data.
                write_output(results, out)

        finally:
            driver.quit()

    return results


# ─── Summary stats ────────────────────────────────────────────────────────────

def print_summary(results: list[dict]):
    visited = [r for r in results if r.get("ok", True)]
    if not visited:
        print("No results.")
        return

    sites_with_fraud = sum(1 for r in visited if r.get("fraud_count", 0) > 0)
    sites_with_high  = sum(1 for r in visited if r.get("high_count",  0) > 0)

    # Deduplicate cookie-setting domains across all sites, keeping highest score.
    all_domains: dict[str, dict] = {}
    for r in visited:
        for cd in r.get("cookie_domains", []):
            d = cd.get("domain", "")
            if d not in all_domains or \
               cd.get("suspicion", 0) > all_domains[d].get("suspicion", 0):
                all_domains[d] = cd

    scores  = [cd.get("suspicion", 0) for cd in all_domains.values()]
    n_high  = sum(1 for s in scores if s >= 0.65)
    n_med   = sum(1 for s in scores if 0.35 <= s < 0.65)
    n_fraud = sum(1 for cd in all_domains.values() if cd.get("isFraud"))

    lz_rates = [r["lz_novelty_rate"] for r in visited
                if r.get("lz_novelty_rate") is not None]
    mean_lz = sum(lz_rates) / len(lz_rates) if lz_rates else 0

    network_counts: dict[str, int] = {}
    for cd in all_domains.values():
        if cd.get("isFraud") and cd.get("network"):
            net = cd["network"]
            network_counts[net] = network_counts.get(net, 0) + 1

    width = 60
    print("\n" + "=" * width)
    print("SWEEP RESULTS")
    print("=" * width)
    print(f"Sites visited:                    {len(visited)}")
    print(f"Sites with confirmed fraud:       {sites_with_fraud}")
    print(f"Sites with HIGH suspicion:        {sites_with_high}")
    print(f"Unique cookie-setting domains:    {len(all_domains)}")
    print(f"  HIGH (score >= 0.65):           {n_high}")
    print(f"  MEDIUM (0.35 – 0.65):           {n_med}")
    print(f"  Confirmed affiliate networks:   {n_fraud}")
    print(f"Mean LZ novelty rate:             {mean_lz:.1f}%")

    if network_counts:
        print()
        print("Affiliate networks found (unique domains seen):")
        for net, count in sorted(network_counts.items(), key=lambda x: -x[1]):
            print(f"  {count:>4}×  {net}")

    # False positive estimate: HIGH-score domains NOT in the fingerprint DB.
    fp_candidates = [
        cd for cd in all_domains.values()
        if cd.get("suspicion", 0) >= 0.65 and not cd.get("isFraud")
    ]
    if fp_candidates:
        print()
        print(f"HIGH-score domains NOT in fingerprint DB (review for FP): "
              f"{len(fp_candidates)}")
        for cd in sorted(fp_candidates, key=lambda x: -x.get("suspicion", 0))[:10]:
            print(f"  {cd.get('suspicion',0):.2f}  {cd.get('domain','')}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--quick", action="store_true",
        help=f"Visit {len(QUICK_SITES)} curated retail/news/coupon sites"
    )
    p.add_argument(
        "--domains", default="tranco_1m.csv",
        help="Tranco CSV (rank,domain). See header for download instructions."
    )
    p.add_argument(
        "--count", type=int, default=200,
        help="Number of domains to visit from the CSV (default 200)"
    )
    p.add_argument(
        "--dwell", type=int, default=7,
        help="Seconds to wait on each page for cookies to load (default 7)"
    )
    p.add_argument(
        "--out", default="sweep_results.json",
        help="Output JSON path (a .csv is written alongside it)"
    )
    p.add_argument(
        "--batch-size", type=int, default=75,
        help="Restart Firefox every N sites to avoid memory bloat (default 75)"
    )
    p.add_argument(
        "--no-headless", action="store_true",
        help="Show the Firefox window (useful for debugging UUID discovery)"
    )
    args = p.parse_args()

    if not EXT_DIR.exists():
        print(f"Extension directory not found: {EXT_DIR}", file=sys.stderr)
        sys.exit(1)

    if args.quick:
        domains = QUICK_SITES
        print(f"Quick mode: {len(domains)} curated sites")
    else:
        if not Path(args.domains).exists():
            print(f"Domain list not found: {args.domains}", file=sys.stderr)
            print(
                "Download the Tranco top-1M list:\n"
                "  curl -L https://tranco-list.eu/top-1m.csv.zip -o top-1m.csv.zip\n"
                "  unzip top-1m.csv.zip && mv top-1m.csv tranco_1m.csv",
                file=sys.stderr
            )
            sys.exit(1)
        domains = load_tranco(args.domains, args.count)
        print(f"Loaded {len(domains)} domains from {args.domains}")

    print(f"Extension:  {EXT_DIR}")
    print(f"Output:     {args.out}  (+ .csv)")
    print(f"Dwell time: {args.dwell}s per site")
    print(f"Batch size: {args.batch_size} sites per Firefox session")
    print(f"Headless:   {not args.no_headless}")
    est = len(domains) * (args.dwell + 3) / 60
    print(f"Est. time:  {est:.0f} min (rough; excludes restarts)")

    results = sweep(
        domains=domains,
        dwell=args.dwell,
        headless=not args.no_headless,
        out=args.out,
        batch_size=args.batch_size,
    )

    write_output(results, args.out)
    print_summary(results)
    print(f"\nJSON: {args.out}")
    print(f"CSV:  {Path(args.out).with_suffix('.csv')}")


if __name__ == "__main__":
    main()
