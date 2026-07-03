# understory-browser — "Understory Safe View"

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
| Safe Browsing enabled | `WebSettingsCompat.setSafeBrowsingEnabled(true)` behind `WebViewFeature` check — degrades gracefully (silently absent) when the device's WebView provider lacks the feature |
| Geolocation / camera / mic auto-denied | `onGeolocationPermissionsShowPrompt` denies, `onPermissionRequest` denies; the Android permissions are also stripped in the manifest |
| No form autofill / no saved passwords in the WebView | `saveFormData`/`savePassword` false; credential fill defers to the system autofill service (passgen/aegis path) |
| Ephemeral sessions | cookies, storage, cache, history, form data wiped on Activity **destroy, or on the explicit "Clear now"** control — never merely "on leave". Switching apps does NOT clear the session (singleTask + recents-visible); the placeholder copy says so. |
| SSL errors rejected hard; no popups, no file chooser | `HardenedWebViewClient`/`HardenedWebChromeClient` |
| Downloads disabled | `DownloadListener` shows an honest snackbar with a "Download in Chrome" hand-off; no storage permission, view-only stays the policy |
| Main-frame load failures render the app's own dark error panel | `onReceivedError`/`onReceivedHttpError` → custom panel with Retry + Open-in-default (no Chromium grey page) |
| Screenshots blocked (`FLAG_SECURE`) | Core anti-emanation posture. **Trade-off:** you cannot screenshot a suspicious page to forward it — the report-the-scam path is *Open in default browser → screenshot there*. An `ALLOW_SCREENSHOTS` override exists in `TestingMode` for eng builds only; prod never exposes it. |

The overlay-proxy surface (`ProxyScreen` + `overlay-i2p`) rides on WebView `ProxyController` and is orthogonal to the hardening above. I2P is the only doctrine-compatible overlay (userspace SOCKS/HTTP, never the VpnService slot); the Lokinet/Yggdrasil VpnService/TUN cards were dropped from the browser. **The whole proxy surface is eng-gated** — a prod build shows no proxy entry point at all (phase α bundles no I2P binary, so there is nothing honest to show).

## Build

Requires JDK 17+ and the Android SDK with platform 35 + build-tools 35.0.0.

```bash
# Copy local.properties.example to local.properties, set sdk.dir
gradle :browser:assembleDebug
# APK: browser/build/outputs/apk/debug/browser-debug.apk
```

CI (GitHub Actions) builds the debug APK + runs unit tests on every push; the APK is attached as a workflow artifact. Debug builds are signed with the committed suite debug keystore so the signing-cert digest matches the suite pin (Tamper.EXPECTED_CERT_SHA256) — installs update-in-place over other suite-pin builds.

## Provenance & suite

Split 2026-07-02 from `Zheke32174/underward` `android/` (commit `f867493`) into per-app repos — one repo per suite app.

Part of the **Understory Suite** — rootless, in-bounds, local-first Android security apps (design constraints: no root, no Shizuku, public APIs only, zero network unless explicitly opted in).

Shared modules vendored here for a self-contained build: `common-security/` (+ `common-backup/`, `overlay-*/` where used) and `keystore/` (pinned suite debug keystore — cert digest is the Tamper/SuiteAttestation pin). **Do not edit shared modules in this repo.** Their canonical home is [`understory-common`](https://github.com/Zheke32174/understory-common); propagate changes with its `tools/sync-common.sh`.

Suite-level docs (SUITE_DESIGN, SUITE_ROADMAP, RELEASE_BLOCKERS, SAMSUNG_QUIRKS, BlackArch defense matrix + runbooks) live in `understory-common`.

## Verify your install

Before trusting the app, confirm the APK you are about to install (or did install) is signed by the suite key. With Android build-tools on any machine:

```bash
apksigner verify --print-certs the-downloaded.apk | grep -i 'SHA-256'
```

The signer certificate SHA-256 digest must be exactly one of the two suite pins (single source of truth: `common-security/.../SuitePins.kt`):

- **Debug** builds (CI artifacts; committed suite debug keystore): `aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e`
- **Release** builds (offline release keystore): `59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a`

Any other digest means the APK was not signed by the suite keys — do not install it. The apps also enforce these pins at runtime (Tamper self-check + SuiteAttestation cross-check of installed siblings), but verifying before install is the stronger position. Signing doctrine: `docs/SIGNING.md` in understory-common.
