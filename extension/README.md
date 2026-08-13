# CookieStuff — Firefox Extension

Real-time affiliate cookie stuffing detector. Uses the same LZ novelty scoring as the CLI tool, now running live in the browser with all six detection signals active.

## Installing (developer mode)

1. Open Firefox and navigate to `about:debugging`
2. Click **This Firefox** in the left sidebar
3. Click **Load Temporary Add-on…**
4. Navigate to this `extension/` directory and select `manifest.json`

The extension loads immediately — no build step, no npm. It stays loaded until Firefox restarts.

To install permanently (your own signed copy), use [web-ext](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/):

```bash
npm install -g web-ext
cd extension/
web-ext run          # live-reload dev mode
web-ext build        # produces a .zip for AMO submission
```

## What it does

The background script attaches to two Firefox hooks:

- **`webNavigation.onCommitted`** — every URL you navigate to joins the *navigation dictionary*, the same LZ78-inspired concept as the CLI tool. Persists across browser sessions in `storage.local`.
- **`webRequest.onCompleted`** with `responseHeaders` — every response that sets a cookie is scored against the navigation dictionary and the affiliate network fingerprint database.

A domain that drops a cookie without appearing in your navigation dictionary is a **LZ novelty miss** — the primary stuffing signal. Combined with affiliate URL patterns, affiliate cookie name patterns, hidden resource type (image/XHR), timing (< 500ms from page load = no click possible), and missing Referer headers, each domain gets a weighted suspicion score.

When a domain crosses **HIGH** (score ≥ 0.65), a desktop notification fires. The toolbar badge shows the count of suspicious domains in the current session. Clicking the badge opens the popup, which lets you inspect the signal breakdown and delete flagged cookies with one click.

## Signals (all six active in real time)

| Signal | Weight | Source |
|---|:---:|---|
| LZ novelty — domain not in navigation history | 30% | webNavigation |
| Affiliate URL pattern | 25% | webRequest URL |
| Affiliate cookie name | 15% | Set-Cookie header |
| Hidden resource (image/XHR/beacon) | 15% | webRequest type |
| Early timing (< 500ms of page load) | 10% | webRequest timestamp |
| No Referer header | 5% | webRequest headers |

## Popup

- **Stats bar**: LZ novelty rate for the session, total cookies observed, navigation dictionary size.
- **Domain cards**: sorted by suspicion score, color-coded HIGH/MEDIUM. Expandable signal breakdown. Per-domain cookie deletion.
- **Delete all suspicious**: removes all flagged cookies in one click using `browser.cookies.remove()` — no browser restart needed.
- **Clear session**: resets in-memory state without clearing the persistent navigation dictionary.

## Files

```
extension/
├── manifest.json       MV3 manifest (Firefox)
├── background.js       Detection engine — all scoring and cookie management
├── popup/
│   ├── popup.html
│   ├── popup.css       Dark theme (Catppuccin palette)
│   └── popup.js        Popup logic, talks to background via runtime.sendMessage
└── icons/
    └── icon.svg        Cookie with alert badge
```

## Porting to Chrome

The extension is Chrome-compatible with two changes:

1. `manifest.json`: change `"scripts": ["background.js"]` to `"service_worker": "background.js"` under `"background"`.
2. `background.js`: Chrome MV3 requires `"extraHeaders"` in the `webRequest.onCompleted` extraInfoSpec to see `Set-Cookie` headers. Change the listener to:
   ```js
   ["responseHeaders", "extraHeaders"]
   ```
   And add `"webRequestBlocking"` to permissions if you want to block requests (not needed for detection only).

State management will also need updating since Chrome service workers get suspended — use `chrome.storage.session` for session state instead of in-memory variables.

## License

Apache 2.0 — same as the CLI tool. See `../LICENSE`.
