"use strict";

// ─── Affiliate fingerprint database (mirrors cookiestuff.py) ─────────────────

const AFFILIATE_DOMAINS = {
  "Commission Junction": ["cj.com","cjour.com","dpbolvw.net","emjcd.com","ftjcfx.com",
                          "jdoqocy.com","kqzyfj.com","lduhtrp.net","ojrq.net","qksrv.net",
                          "tkqlhce.com","yceml.net"],
  "ShareASale":          ["shareasale.com","shareasale-analytics.com"],
  "Awin":                ["awin1.com","awin.com","zanox.com","zanox-affiliate.com","affili.net"],
  "Rakuten":             ["rakutenadvertising.com","linksynergy.com","click.linksynergy.com",
                          "ad.linksynergy.com"],
  "Impact":              ["impact.com","impactradius.com","sjv.io","evyy.net","7eer.net"],
  "PartnerStack":        ["partnerstack.com","partnero.com"],
  "Partnerize":          ["partnerize.com","prf.hn"],
  "ClickBank":           ["clickbank.com","hop.clickbank.net"],
  "FlexOffers":          ["flexoffers.com","flexlinks.com"],
  "PepperJam":           ["pepperjam.com","pjtra.com"],
  "Tradedoubler":        ["tradedoubler.com"],
  "Viglink":             ["viglink.com","skimlinks.com","skimresources.com"],
  "MaxBounty":           ["maxbounty.com"],
  "Refersion":           ["refersion.com"],
  "Tune/HasOffers":      ["tune.com","hasoffers.com","app.link"],
  "CivicScience":        ["civicscience.com"],
  "Generic trackers":    ["doubleclick.net","googleadservices.com"],
};

const AFFILIATE_URL_PATTERNS = [
  /\/click\b/i, /\/track\b/i, /\/redirect\b/i, /\/go\b/i, /\/refer\b/i,
  /[?&]affiliate[_-]?id=/i, /[?&]publisher[_-]?id=/i, /[?&]aff[_-]?id=/i,
  /[?&]partner[_-]?id=/i, /[?&]ref(erral)?=/i, /[?&]subid=/i,
  /[?&]clickid=/i, /[?&]source=affiliate/i, /[?&]PID=/i, /[?&]SID=/i,
];

const AFFILIATE_COOKIE_NAMES = [
  /^aff/i, /^affiliate/i, /^partner/i, /^ref(erral)?/i, /^publisher/i,
  /^clickid/i, /^subid/i, /_aff$/i, /_ref$/i, /_click$/i,
  /^cj_/i, /^sa_/i, /^aw_/i, /^rakuten/i, /^impact_/i,
];

const HIDDEN_RESOURCE_TYPES = new Set([
  "image", "media", "other", "xmlhttprequest", "ping", "beacon", "websocket",
]);

const DEFAULT_THRESHOLD = 0.35;

// ─── Session state (in-memory; resets each browser session) ──────────────────

let navDict         = new Set();   // domains the user has navigated to (persistent)
let domainReports   = new Map();   // domain → report object (session)
let pageStartTimes  = new Map();   // tabId → ms epoch of last main-frame navigation
let pendingReferers = new Map();   // requestId → referer string
let totalCookieEvents = 0;

// ─── Persistence ──────────────────────────────────────────────────────────────

async function loadNavDict() {
  try {
    const data = await browser.storage.local.get("navDict");
    if (Array.isArray(data.navDict)) {
      navDict = new Set(data.navDict);
    }
  } catch (e) {
    console.warn("[CookieStuff] navDict load failed:", e);
  }
}

let _saveTimer = null;
function scheduleSaveNavDict() {
  clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => {
    browser.storage.local.set({ navDict: [...navDict] });
  }, 3000);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractHostname(url) {
  try { return new URL(url).hostname.toLowerCase(); }
  catch { return ""; }
}

function inNavDict(domain) {
  if (!domain) return false;
  if (navDict.has(domain)) return true;
  const parts = domain.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    if (navDict.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

function addToNavDict(hostname) {
  if (!hostname || hostname === "localhost" || hostname.endsWith(".local")) return;

  let changed = false;
  if (!navDict.has(hostname)) { navDict.add(hostname); changed = true; }

  const parts = hostname.split(".");
  if (parts.length > 2) {
    const apex = parts.slice(-2).join(".");
    if (!navDict.has(apex)) { navDict.add(apex); changed = true; }
  }

  if (changed) {
    // Recalculate lzNovelty for all existing reports — navigating to a domain
    // retroactively de-risks cookies it set before you visited.
    for (const r of domainReports.values()) {
      r.lzNovelty = inNavDict(r.domain) ? 0 : 1;
      r.suspicion  = computeSuspicion(r);
      r.verdict    = getVerdict(r.suspicion);
    }
    updateBadge();
    scheduleSaveNavDict();
  }
}

function parseCookieHeader(header, fallbackDomain) {
  if (!header) return null;
  const parts   = header.split(";");
  const nameVal = parts[0].trim();
  const eq      = nameVal.indexOf("=");
  if (eq === -1) return null;

  const name  = nameVal.substring(0, eq).trim();
  const value = nameVal.substring(eq + 1).trim();

  let domain = fallbackDomain;
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i].trim();
    if (p.toLowerCase().startsWith("domain=")) {
      domain = p.substring(7).replace(/^\./, "").toLowerCase();
      break;
    }
  }

  return { name, value, domain };
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

function matchAffiliateNetwork(domain) {
  for (const [network, frags] of Object.entries(AFFILIATE_DOMAINS)) {
    for (const frag of frags) {
      if (domain === frag || domain.endsWith("." + frag)) return network;
    }
  }
  return null;
}

function affiliateUrlScore(url) {
  return AFFILIATE_URL_PATTERNS.some(p => p.test(url)) ? 1.0 : 0.0;
}

function affiliateCookieScore(name) {
  const lower = (name || "").toLowerCase();
  return AFFILIATE_COOKIE_NAMES.some(p => p.test(lower)) ? 1.0 : 0.0;
}

function hiddenResourceScore(type) {
  return HIDDEN_RESOURCE_TYPES.has(type) ? 1.0 : type === "script" ? 0.7 : 0.0;
}

function earlyTimingScore(sec) {
  if (sec < 0) return 0;
  if (sec < 0.5) return 1.0;
  if (sec < 2.0) return Math.max(0, 1 - (sec - 0.5) / 1.5);
  return 0.0;
}

function computeSuspicion(r) {
  return Math.min(1.0,
    0.30 * r.lzNovelty    +
    0.25 * r.affiliateUrl +
    0.15 * r.affiliateCookie +
    0.15 * r.hiddenResource  +
    0.10 * r.earlyTiming  +
    0.05 * r.noReferrer
  );
}

function getVerdict(s) {
  if (s >= 0.65) return "HIGH";
  if (s >= 0.35) return "MEDIUM";
  return "CLEAN";
}

// ─── Event processing ─────────────────────────────────────────────────────────

function createReport(domain) {
  return {
    domain,
    network:         null,
    cookies:         [],
    lzNovelty:       0,
    affiliateUrl:    0,
    affiliateCookie: 0,
    hiddenResource:  0,
    earlyTiming:     0,
    noReferrer:      0,
    suspicion:       0,
    verdict:         "CLEAN",
    notified:        false,
  };
}

function processEvent(ev) {
  totalCookieEvents++;
  const { domain } = ev;

  if (!domainReports.has(domain)) {
    domainReports.set(domain, createReport(domain));
  }

  const r = domainReports.get(domain);
  r.cookies.push(ev);

  r.lzNovelty      = inNavDict(domain) ? 0 : 1;
  r.network        = matchAffiliateNetwork(domain);
  r.affiliateUrl   = Math.max(r.affiliateUrl, affiliateUrlScore(ev.url));
  if (r.network) r.affiliateUrl = 1;
  r.affiliateCookie = Math.max(r.affiliateCookie, affiliateCookieScore(ev.name));
  r.hiddenResource  = Math.max(r.hiddenResource,  hiddenResourceScore(ev.resourceType));
  r.earlyTiming     = Math.max(r.earlyTiming,     earlyTimingScore(ev.timestamp));
  r.noReferrer      = r.cookies.filter(c => !c.referer).length / r.cookies.length;

  r.suspicion = computeSuspicion(r);
  r.verdict   = getVerdict(r.suspicion);

  updateBadge();

  // Notify only for confirmed affiliate networks — avoids constant noise from
  // generic ad trackers, which are a privacy problem but not commission fraud.
  if (r.verdict === "HIGH" && r.network && !r.notified) {
    r.notified = true;
    browser.notifications.create(`cs-${domain}`, {
      type:    "basic",
      title:   `Affiliate stuffing: ${r.network}`,
      message: `${domain} dropped a commission cookie you never clicked.\nDelete it from the CookieStuff popup.`,
      iconUrl: browser.runtime.getURL("icons/icon.svg"),
    }).catch(() => {});
  }
}

// ─── Navigation listeners ─────────────────────────────────────────────────────

browser.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId === 0) {
    pageStartTimes.set(details.tabId, details.timeStamp);
  }
});

browser.webNavigation.onCommitted.addListener(details => {
  if (details.frameId === 0) {
    const hostname = extractHostname(details.url);
    if (hostname) addToNavDict(hostname);
  }
});

// pageStartTimes is session-only and bounded by open tab count; no explicit cleanup needed.

// ─── Request listeners ────────────────────────────────────────────────────────

// Capture outgoing Referer headers so we can score the "no referrer" signal
browser.webRequest.onBeforeSendHeaders.addListener(
  details => {
    const h = (details.requestHeaders || []).find(
      h => h.name.toLowerCase() === "referer"
    );
    if (h) pendingReferers.set(details.requestId, h.value);
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// Observe Set-Cookie headers — this is the primary detection hook
browser.webRequest.onCompleted.addListener(
  details => {
    const setCookies = (details.responseHeaders || []).filter(
      h => h.name.toLowerCase() === "set-cookie"
    );

    const referer = pendingReferers.get(details.requestId) || "";
    pendingReferers.delete(details.requestId);

    if (setCookies.length === 0) return;

    const url          = details.url;
    const reqHostname  = extractHostname(url);
    const resourceType = details.type || "other";
    const tabId        = details.tabId;
    const pageStart    = pageStartTimes.get(tabId) ?? details.timeStamp;
    const timingSec    = (details.timeStamp - pageStart) / 1000;

    for (const h of setCookies) {
      const parsed = parseCookieHeader(h.value, reqHostname);
      if (!parsed || !parsed.name) continue;

      processEvent({
        name:         parsed.name,
        value:        parsed.value,
        domain:       parsed.domain || reqHostname,
        url,
        resourceType,
        referer,
        timestamp:    timingSec,
        tabId,
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

browser.webRequest.onErrorOccurred.addListener(
  details => pendingReferers.delete(details.requestId),
  { urls: ["<all_urls>"] }
);

// ─── Badge ────────────────────────────────────────────────────────────────────

function getSuspicious(threshold = DEFAULT_THRESHOLD) {
  return [...domainReports.values()].filter(r => r.suspicion >= threshold);
}

// Confirmed fraud: known affiliate network + high suspicion score.
// General ad trackers score HIGH too but are a privacy issue, not commission fraud.
function getConfirmedFraud() {
  return getSuspicious().filter(r => r.network !== null);
}

function updateBadge() {
  const fraud   = getConfirmedFraud().length;
  const suspect = getSuspicious().length;

  if (fraud > 0) {
    // Red badge: confirmed affiliate network stuffing
    browser.action.setBadgeText({ text: String(fraud) });
    browser.action.setBadgeBackgroundColor({ color: "#f7768e" });
  } else if (suspect > 0) {
    // Amber badge: suspicious trackers but no confirmed affiliate network
    browser.action.setBadgeText({ text: "!" });
    browser.action.setBadgeBackgroundColor({ color: "#e0af68" });
  } else {
    browser.action.setBadgeText({ text: "" });
  }
}

// ─── Cookie deletion ──────────────────────────────────────────────────────────

async function deleteCookiesForDomain(targetDomain) {
  const all = await browser.cookies.getAll({});
  const matches = all.filter(ck => {
    const cd = ck.domain.replace(/^\./, "");
    return cd === targetDomain
      || cd.endsWith("." + targetDomain)
      || targetDomain.endsWith("." + cd);
  });

  let count = 0;
  for (const ck of matches) {
    const proto  = ck.secure ? "https" : "http";
    const domain = ck.domain.replace(/^\./, "");
    const url    = `${proto}://${domain}${ck.path || "/"}`;
    try {
      await browser.cookies.remove({ url, name: ck.name, storeId: ck.storeId });
      count++;
    } catch (_) {}
  }

  domainReports.delete(targetDomain);
  updateBadge();
  return count;
}

async function deleteAllSuspicious() {
  // Default: delete confirmed fraud (known affiliate networks) only.
  // Trackers are bad but deleting them indiscriminately surprises users.
  const targets = getConfirmedFraud().length > 0 ? getConfirmedFraud() : getSuspicious();
  let total = 0;
  for (const r of targets) {
    total += await deleteCookiesForDomain(r.domain);
  }
  return total;
}

// ─── State query (called by popup) ───────────────────────────────────────────

function serializeReport(r) {
  return {
    domain:      r.domain,
    network:     r.network,
    isFraud:     r.network !== null,   // confirmed affiliate network = commission fraud
    suspicion:   Math.round(r.suspicion * 100) / 100,
    verdict:     r.verdict,
    cookieCount: r.cookies.length,
    cookieNames: [...new Set(r.cookies.map(c => c.name))].slice(0, 6),
    signals: {
      lzNovelty:       r.lzNovelty,
      affiliateUrl:    r.affiliateUrl,
      affiliateCookie: r.affiliateCookie,
      hiddenResource:  r.hiddenResource,
      earlyTiming:     r.earlyTiming,
      noReferrer:      r.noReferrer,
    },
    topCookie: r.cookies[0] ? {
      name:       r.cookies[0].name,
      type:       r.cookies[0].resourceType,
      timestamp:  Math.round(r.cookies[0].timestamp * 10) / 10,
      hasReferer: !!r.cookies[0].referer,
    } : null,
  };
}

function getState() {
  const allSuspicious = getSuspicious().sort((a, b) => b.suspicion - a.suspicion);
  const suspicious = allSuspicious.map(serializeReport);

  // LZ novelty rate = fraction of all cookie events from novel domains
  const missEvents = [...domainReports.values()]
    .filter(r => r.lzNovelty > 0)
    .reduce((s, r) => s + r.cookies.length, 0);
  const lzNoveltyRate = totalCookieEvents > 0
    ? Math.round((missEvents / totalCookieEvents) * 1000) / 10
    : 0;

  return {
    suspicious,
    totalCookies:  totalCookieEvents,
    totalDomains:  domainReports.size,
    navDictSize:   navDict.size,
    lzNoveltyRate,
  };
}

// ─── Message handler ──────────────────────────────────────────────────────────

browser.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.type) {

    case "GET_STATE":
      sendResponse(getState());
      break;

    case "DELETE_DOMAIN":
      deleteCookiesForDomain(msg.domain)
        .then(n  => sendResponse({ deleted: n }))
        .catch(e => sendResponse({ error: String(e) }));
      return true;   // keep channel open for async response

    case "DELETE_ALL":
      deleteAllSuspicious()
        .then(n  => sendResponse({ deleted: n }))
        .catch(e => sendResponse({ error: String(e) }));
      return true;

    case "CLEAR_SESSION":
      domainReports.clear();
      totalCookieEvents = 0;
      updateBadge();
      sendResponse({ ok: true });
      break;
  }
});

// ─── Init ─────────────────────────────────────────────────────────────────────

loadNavDict().then(() => {
  console.log(`[CookieStuff] ready — nav dict: ${navDict.size} domains`);
});
