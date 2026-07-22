# understory-browser — "Understory Safe View"

> [!CAUTION]
> **PUBLIC DEBUG SIGNING INCIDENT:** the former shared debug private key is
> public. Existing debug APKs and continuous debug releases cannot prove
> authorship and are untrusted development artifacts. Only a future APK signed
> by the externally held release key can be an authenticated Understory
> distribution. Tracking: `Zheke32174/understory-common#3`.

The suite's **quarantine viewer**: the place you open a link you do NOT trust — an SMS-phish, a strange email, a QR code, a stranger's chat — one share-sheet tap from Chrome/Brave. Chrome keeps the default-browser role, the logins, the tabs; Safe View offers what Chrome structurally cannot: in its **Hardened** mode, JavaScript dead by default, no cookies, no storage, no downloads, no popups, no permission prompts, ephemeral by construction, and a permission-stripped APK.

Two things the user controls, added in P1:

- **Tabs.** A real multi-tab model (a single reused WebView driven by per-tab saved-state bundles). The tab-count button in the toolbar opens a switcher; closing the last tab returns to home. Config-change-durable; still ephemeral on exit.
- **Mode — not an infinity lockdown tomb.** A per-app-default + per-tab toggle between **Hardened** (the quarantine defaults above) and **Standard** (JavaScript on, first-party cookies + history kept within the app, downloads allowed behind a prompt) — for when you just want to browse. **Both** modes keep the non-negotiable posture: `FLAG_SECURE`/no-screenshot, mixed-content blocked, cleartext denied, SSL errors hard-rejected, third-party cookies blocked, Safe Browsing on, and a full wipe on *Clear now* / app exit. A link opened through the intake doorway is **always** Hardened; Standard is opt-in for normal browsing.

The package id stays `com.understory.browser`; the store-facing display name is **Safe View**.

Status: **alpha** (functional; working the release-blockers list in understory-common).

## The doorway and the exit

- **Doorway (intake):** a `text/plain` share target ("Share → Open in Safe View", always on) plus an opt-in `http/https` VIEW filter (first-run choice; never becomes your default browser). Both funnel through **one mandatory confirmation interstitial** that shows the full normalized URL (host emphasized so a look-alike domain is legible) with JavaScript already OFF — a drive-by `startActivity` can put a URL on that screen but cannot load it.
- **Exit (hand-off):** once you trust the page, **Open in default browser** hands the canonical URL back to Chrome/Brave via a chooser (Safe View claims no browser role). The same hand-off backs blocked downloads ("Download in Chrome") and `mailto:`/`tel:`/`sms:` links (opt-out in settings).

## Hardened WebView config (defense-matrix reference)

Implements the RELEASE_BLOCKERS.md "Browser" hardening items. Canonical per-item list lives in the `MainActivity.kt` KDoc header; summary:

| Item | Where |
| --- | --- |
| JavaScript OFF by default; per-site opt-in toggle backed by a persisted host allowlist | `BrowserSettings.isJsAllowed`/`setJsAllowed`; policy re-derived per navigation in `HardenedWebViewClient` |
| `file://` / `content://` blocked entirely | `allowFileAccess`/`allowContentAccess`/`allowFileAccessFromFileURLs`/`allowUniversalAccessFromFileURLs` all false + `shouldOverrideUrlLoading` refuses every non-https scheme |
| Third-party cookies always blocked; first-party per settings toggle (default off) | `CookieManager.setAcceptThirdPartyCookies(wv, false)` + `setAcceptCookie(BrowserSettings.getFirstPartyCookies(...))`; all cookies wiped on destroy |
| Mixed content blocked | `MIXED_CONTENT_NEVER_ALLOW` + cleartext denied in `network_security_config.xml` |
| Safe Browsing enabled | `WebSettingsCompat.setSafeBrowsingEnabled(true)` behind `WebViewFeature` check — degrades gracefully when the device's WebView provider lacks the feature |
| Geolocation / camera / mic auto-denied | `onGeolocationPermissionsShowPrompt` denies, `onPermissionRequest` denies; Android permissions are stripped in the manifest |
| No form autofill / no saved passwords in the WebView | `saveFormData`/`savePassword` false; credential fill defers to the system autofill service |
| Ephemeral sessions | cookies, storage, cache, history, form data wiped on Activity destroy or on **Clear now**; switching apps does not clear the session |
| SSL errors rejected hard; no popups, no file chooser | `HardenedWebViewClient`/`HardenedWebChromeClient` |
| Downloads disabled | `DownloadListener` shows a prompt with a default-browser hand-off; no storage permission |
| Main-frame failures render the app's own error panel | `onReceivedError`/`onReceivedHttpError` with Retry and Open-in-default |
| Screenshots blocked (`FLAG_SECURE`) | Eng builds have a testing-only override; production does not |

The overlay-proxy surface (`ProxyScreen` + `overlay-i2p`) rides on WebView `ProxyController` and is orthogonal to the hardening above. I2P is the only doctrine-compatible overlay; the whole proxy surface is eng-gated and no I2P binary is currently bundled.

## Build

Requires JDK 17+ and the Android SDK with platform 35 + build-tools 35.0.0.

```bash
# Copy local.properties.example to local.properties, set sdk.dir
gradle :browser:assembleDebug
# APK: browser/build/outputs/apk/debug/browser-debug.apk
```

CI assembles a local debug APK and runs the unit-test suite as validation. It does not upload or publish APKs. Local debug signing is developer-specific and asserts no Understory distribution identity.

## Provenance & suite

Split 2026-07-02 from `Zheke32174/underward` `android/` (commit `f867493`) into per-app repos — one repo per suite app.

Part of the **Understory Suite** — rootless, in-bounds, local-first Android security apps (design constraints: no root, no Shizuku, public APIs only, zero network unless explicitly opted in).

Shared modules vendored here for a self-contained build: `common-security/` (+ `common-backup/`, `overlay-*/` where used). The `keystore/` directory contains documentation only; signing private keys are forbidden. **Do not edit shared modules in this repo.** Their canonical home is [`understory-common`](https://github.com/Zheke32174/understory-common); propagate changes with its `tools/sync-common.sh`.

Suite-level docs live in `understory-common`.

## Verify your install

Debug APKs cannot be authenticated as Understory distributions. Their signer is developer-local, and the former shared debug signer is revoked.

For a future authenticated release, verify the APK certificate with `apksigner` and require the release fingerprint recorded in `common-security/.../SuitePins.kt`:

```bash
apksigner verify --print-certs the-downloaded.apk | grep -i 'SHA-256'
```

Expected authenticated release certificate:

`59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a`

Certificate verification must be combined with an immutable versioned release, checksum/provenance verification, and the source commit. No such release receipt is claimed by this draft.
