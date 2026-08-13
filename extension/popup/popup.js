"use strict";

const $  = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);

// ─── Rendering helpers ────────────────────────────────────────────────────────

function lzColor(rate) {
  if (rate > 40) return "high";
  if (rate > 15) return "medium";
  return "clean";
}

function fmtScore(v) { return v.toFixed(2); }

function buildSignalRows(signals) {
  const rows = [
    ["LZ novelty",       signals.lzNovelty],
    ["Affiliate URL",    signals.affiliateUrl],
    ["Affiliate cookie", signals.affiliateCookie],
    ["Hidden resource",  signals.hiddenResource],
    ["Early timing",     signals.earlyTiming],
    ["No referrer",      signals.noReferrer],
  ];
  return rows.map(([name, val]) => `
    <div class="sig-row">
      <span class="sig-name">${name}</span>
      <div class="sig-track">
        <div class="sig-fill" style="width:${(val * 100).toFixed(1)}%"></div>
      </div>
      <span class="sig-num">${fmtScore(val)}</span>
    </div>`).join("");
}

function buildDomainCard(r) {
  const netTag = r.network
    ? `<span class="network-tag">[${r.network}]</span>` : "";

  const chips = r.cookieNames.map(n =>
    `<span class="chip">${n}</span>`
  ).join("") + (r.cookieCount > r.cookieNames.length
    ? `<span class="chip more">+${r.cookieCount - r.cookieNames.length}</span>` : "");

  const topLine = r.topCookie
    ? `<span>${r.topCookie.type} @ ${r.topCookie.timestamp}s` +
      `${r.topCookie.hasReferer ? "" : " · no referer"}</span>`
    : "";

  // Escape domain for use as DOM id
  const safeId = "sig-" + r.domain.replace(/[^a-zA-Z0-9]/g, "_");

  return `
    <div class="domain-card ${r.verdict}" data-domain="${r.domain}">
      <div class="card-header">
        <span class="verdict-pill ${r.verdict}">${r.verdict}</span>
        <span class="domain-name" title="${r.domain}">${r.domain}</span>
        <span class="score-val">${fmtScore(r.suspicion)}</span>
      </div>
      <div class="card-meta">
        ${netTag}
        <span>${r.cookieCount} cookie${r.cookieCount !== 1 ? "s" : ""}</span>
        ${topLine}
      </div>
      <div class="cookie-chips">${chips}</div>
      <div class="signals-panel" id="${safeId}">${buildSignalRows(r.signals)}</div>
      <div class="card-actions">
        <button class="btn-toggle" data-target="${safeId}">▸ signals</button>
        <button class="btn-del-domain" data-domain="${r.domain}">Delete cookies</button>
      </div>
    </div>`;
}

// ─── Render state into the popup ──────────────────────────────────────────────

function buildSection(title, items, colorClass) {
  if (items.length === 0) return "";
  return `
    <div class="section-header ${colorClass}">${title}</div>
    ${items.map(buildDomainCard).join("")}`;
}

function render(state) {
  // Stats
  const lzEl = $("lz-rate");
  lzEl.textContent = state.lzNoveltyRate.toFixed(1) + "%";
  lzEl.className   = "stat-value " + lzColor(state.lzNoveltyRate);
  $("cookie-count").textContent = state.totalCookies;
  $("nav-count").textContent    = state.navDictSize;

  const list         = $("domain-list");
  const deleteAllBtn = $("delete-all-btn");

  if (!state.suspicious || state.suspicious.length === 0) {
    list.innerHTML = `
      <div id="empty-state">
        <span class="clean-icon">✓</span>
        <p>Session is clean</p>
        <p class="dim">No affiliate stuffing detected yet.</p>
      </div>`;
    deleteAllBtn.hidden = true;
    $("header-status").textContent = "";
    return;
  }

  const fraud    = state.suspicious.filter(r => r.isFraud);
  const trackers = state.suspicious.filter(r => !r.isFraud);

  list.innerHTML =
    buildSection(`AFFILIATE FRAUD — ${fraud.length} confirmed network${fraud.length !== 1 ? "s" : ""}`,
      fraud, "section-fraud") +
    buildSection(`AD TRACKERS — ${trackers.length} suspicious (not fraud)`,
      trackers, "section-tracker");

  const fraudCount = fraud.length;
  deleteAllBtn.textContent = fraudCount > 0
    ? `Delete fraud cookies (${fraudCount})`
    : `Delete all trackers (${trackers.length})`;
  deleteAllBtn.hidden = false;

  // Header shows only confirmed fraud count — that's what matters
  $("header-status").textContent = fraudCount > 0
    ? `${fraudCount} fraud`
    : `${trackers.length} trackers`;

  attachCardListeners();
}

// ─── Card interaction ─────────────────────────────────────────────────────────

function attachCardListeners() {
  // Signal detail toggles
  document.querySelectorAll(".btn-toggle").forEach(btn => {
    btn.addEventListener("click", () => {
      const panel = document.getElementById(btn.dataset.target);
      if (!panel) return;
      const open = panel.classList.toggle("open");
      btn.textContent = open ? "▾ signals" : "▸ signals";
    });
  });

  // Per-domain deletion
  document.querySelectorAll(".btn-del-domain").forEach(btn => {
    btn.addEventListener("click", async () => {
      const domain = btn.dataset.domain;
      btn.disabled    = true;
      btn.textContent = "…";
      try {
        await browser.runtime.sendMessage({ type: "DELETE_DOMAIN", domain });
        const card = btn.closest(".domain-card");
        card.style.opacity = "0";
        card.style.transition = "opacity 0.2s";
        setTimeout(() => { card.remove(); checkEmpty(); }, 220);
      } catch (e) {
        btn.textContent = "Error";
        btn.disabled = false;
      }
    });
  });
}

function checkEmpty() {
  if (document.querySelectorAll(".domain-card").length === 0) {
    refreshState();
  }
}

// ─── State refresh ────────────────────────────────────────────────────────────

async function refreshState() {
  try {
    const state = await browser.runtime.sendMessage({ type: "GET_STATE" });
    render(state);
  } catch (e) {
    console.error("[CookieStuff popup] GET_STATE failed:", e);
  }
}

// ─── Footer buttons ───────────────────────────────────────────────────────────

$("delete-all-btn").addEventListener("click", async () => {
  const btn    = $("delete-all-btn");
  btn.disabled = true;
  btn.textContent = "Deleting…";
  try {
    await browser.runtime.sendMessage({ type: "DELETE_ALL" });
    await refreshState();
  } catch (e) {
    btn.textContent = "Error";
    btn.disabled    = false;
  }
});

$("clear-btn").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ type: "CLEAR_SESSION" });
  await refreshState();
});

// ─── Init and live refresh ────────────────────────────────────────────────────

refreshState();

// Refresh every 2s while popup is open so new detections appear in real time
const timer = setInterval(refreshState, 2000);
window.addEventListener("unload", () => clearInterval(timer));
