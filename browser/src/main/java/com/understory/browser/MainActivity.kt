package com.understory.browser

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.KeyEvent
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.webkit.CookieManager
import android.webkit.PermissionRequest
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.compose.foundation.lazy.items
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.view.WindowCompat
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.SuiteStatusFooter
import com.understory.security.Tamper
import com.understory.security.TestingMode

/**
 * Hardened browser MVP — single Activity, single WebView, locked-down
 * defaults. Phase-1 scope:
 *   - JavaScript OFF by default (toggleable per session).
 *   - file://, content://, mixed-content all denied.
 *   - No save passwords, no save form data, no geolocation.
 *   - All web permission requests (camera/mic/location/midi/etc.) refused.
 *   - All cookies + storage cleared on Activity destroy.
 *   - SSL errors rejected hard (no proceed-anyway dialog).
 *   - No file chooser, no window-create.
 *   - INTERNET permission required (only suite app besides firewall).
 *
 * Deferred to phase 2:
 *   - Cromite-fork integration (the SUITE_DESIGN target).
 *   - Tabs.
 *   - Fingerprint randomization.
 *   - DNS-over-HTTPS toggle.
 *   - Per-site permission granularity beyond global denial.
 *   - Cross-app autofill integration with passgen + aegis (the system
 *     autofill API will pick them up automatically if installed; no
 *     browser-side wiring needed for that path).
 */
class MainActivity : ComponentActivity() {

    private var webView: WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("browser.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        super.onCreate(savedInstanceState)
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("browser.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("browser crash", color = Color(0xFFEF5350), fontSize = 18.sp)
                        Text(t.toString(), color = Color(0xFFE0E0E0), fontSize = 11.sp)
                    }
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        Diagnostics.log("browser.MainActivity", "onPause")
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    override fun onStop() {
        super.onStop()
        Diagnostics.log("browser.MainActivity", "onStop (changingConfigs=$isChangingConfigurations)")
        DiagnosticsDump.snapshotState(this, "onStop")
    }

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            com.understory.security.SuiteAttestation.verify(applicationContext).hardFail
        ) {
            finishAndRemoveTask(); return
        }

        if (!TestingMode.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                window.setHideOverlayWindows(true)
            }
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        // Hard-off WebView debugging on every launch. The default is off
        // on production builds, but explicit is better.
        runCatching { WebView.setWebContentsDebuggingEnabled(false) }

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                    BrowserAppRoot(onWebViewReady = { webView = it })
                }
            }
        }

        // Note: lifted `window.decorView.filterTouchesWhenObscured = true`
        // per SAMSUNG_QUIRKS.md — the global decor filter silently drops
        // legitimate taps under Samsung Edge Panel and similar overlays.
        // FLAG_SECURE on the window still prevents screenshots / overlay
        // capture of browsed content.
    }

    override fun onResume() {
        super.onResume()
        Diagnostics.log("browser.MainActivity", "onResume")
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error("browser.MainActivity", "Tamper.check hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }

    override fun onDestroy() {
        Diagnostics.log("browser.MainActivity", "onDestroy")
        super.onDestroy()
        // Wipe cookies + storage on every Activity destroy. The
        // Activity is noHistory + singleInstance + excludeFromRecents,
        // so any time we destroy, we want zero residue. Persistent web
        // state would be a huge fingerprinting + tracking surface;
        // making sessions ephemeral is the strongest sovereign default.
        runCatching {
            CookieManager.getInstance().removeAllCookies(null)
            CookieManager.getInstance().flush()
            WebStorage.getInstance().deleteAllData()
        }
        runCatching { webView?.clearCache(true) }
        runCatching { webView?.clearHistory() }
        runCatching { webView?.clearFormData() }
        runCatching { webView?.clearSslPreferences() }
        webView?.destroy()
        webView = null
    }

    override fun onBackPressed() {
        // Browser back-stack — if WebView can go back, do that; otherwise
        // either minimize-to-background (testing phase, when
        // KEEP_ALIVE_ON_LEAVE is on) or fall through to the system
        // default finish (release).
        val wv = webView
        if (wv != null && wv.canGoBack()) {
            wv.goBack()
        } else if (TestingMode.KEEP_ALIVE_ON_LEAVE) {
            Diagnostics.log("browser.MainActivity",
                "back at root (no WebView history): moveTaskToBack")
            moveTaskToBack(true)
        } else {
            super.onBackPressed()
        }
    }
}

@Composable
private fun BrowserAppRoot(onWebViewReady: (WebView) -> Unit) {
    // Diagnostics + Bookmarks render as overlays on top of BrowserRoot
    // rather than swapping it out, so the WebView's composition (and
    // its loaded page) survives a trip to either surface and back.
    // pendingLoad is a one-shot URL pushed from the Bookmarks overlay
    // back into BrowserRoot, which consumes + clears it on next
    // composition.
    val ctx = androidx.compose.ui.platform.LocalContext.current
    var showDiagnostics by rememberSaveable { mutableStateOf(false) }
    var showBookmarks by rememberSaveable { mutableStateOf(false) }
    var showProxy by rememberSaveable { mutableStateOf(false) }
    var pendingLoad by remember { mutableStateOf<String?>(null) }
    // Bookmarks state lives at the AppRoot so the BrowserRoot star icon
    // and the BookmarksScreen list both observe one source of truth.
    // Without this, deletes from the overlay would leave a stale star
    // glyph in the toolbar until the next external trigger.
    var bookmarks by remember { mutableStateOf(BrowserSettings.getBookmarks(ctx)) }
    val refreshBookmarks = { bookmarks = BrowserSettings.getBookmarks(ctx) }
    androidx.compose.foundation.layout.Box(modifier = Modifier.fillMaxSize()) {
        BrowserRoot(
            onWebViewReady = onWebViewReady,
            onDiagnostics = {
                Diagnostics.log("browser.AppRoot", "show diagnostics overlay")
                showDiagnostics = true
            },
            onOpenBookmarks = {
                Diagnostics.log("browser.AppRoot", "show bookmarks overlay")
                showBookmarks = true
            },
            onOpenProxy = {
                Diagnostics.log("browser.AppRoot", "show proxy overlay")
                showProxy = true
            },
            bookmarks = bookmarks,
            onBookmarkToggle = { url, title ->
                BrowserSettings.toggle(ctx, url, title)
                refreshBookmarks()
            },
            pendingLoad = pendingLoad,
            onPendingLoadConsumed = { pendingLoad = null },
        )
        if (showDiagnostics) {
            BackHandler { showDiagnostics = false }
            // Opaque background so the WebView underneath doesn't show through.
            Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                DiagnosticsScreen(onBack = { showDiagnostics = false })
            }
        }
        if (showBookmarks) {
            BackHandler { showBookmarks = false }
            Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                BookmarksScreen(
                    bookmarks = bookmarks,
                    onBack = { showBookmarks = false },
                    onPick = { url ->
                        Diagnostics.log("browser.AppRoot",
                            "bookmark pick: scheme=${url.substringBefore("://", "?")}")
                        pendingLoad = url
                        showBookmarks = false
                    },
                    onRemove = { url ->
                        BrowserSettings.remove(ctx, url)
                        refreshBookmarks()
                    },
                )
            }
        }
        if (showProxy) {
            BackHandler { showProxy = false }
            Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                ProxyScreen(onBack = { showProxy = false })
            }
        }
    }
}

@Composable
private fun BrowserRoot(
    onWebViewReady: (WebView) -> Unit,
    onDiagnostics: () -> Unit,
    onOpenBookmarks: () -> Unit,
    onOpenProxy: () -> Unit,
    bookmarks: List<Bookmark>,
    onBookmarkToggle: (url: String, title: String?) -> Unit,
    pendingLoad: String?,
    onPendingLoadConsumed: () -> Unit,
) {
    val ctx = LocalContext.current
    var url by remember { mutableStateOf("") }
    var loadedUrl by remember { mutableStateOf<String?>(null) }
    var jsEnabled by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(false) }
    // WebView reference + nav state. We capture the WebView on factory
    // construction so the toolbar buttons (back / forward / reload-stop)
    // can drive it without lifting the AndroidView's internal state up.
    // The Activity also holds a reference for lifecycle teardown — the
    // two refs aren't redundant: the Activity's persists across Compose
    // recomposition; this one's scoped to the Composable.
    var wvRef by remember { mutableStateOf<WebView?>(null) }
    var canGoBackState by remember { mutableStateOf(false) }
    var canGoForwardState by remember { mutableStateOf(false) }
    var pageTitle by remember { mutableStateOf<String?>(null) }
    // Find-in-page state. Active = the find bar is visible. Match
    // counts come from WebView.FindListener; -1 sentinel means no
    // search has been issued yet (UI shows count area blank).
    var findActive by remember { mutableStateOf(false) }
    var findQuery by remember { mutableStateOf("") }
    var findCurrent by remember { mutableStateOf(-1) }
    var findTotal by remember { mutableStateOf(-1) }
    // Star indicator derives directly from the lifted `bookmarks`
    // state — when BrowserAppRoot refreshes the list (after toggle or
    // delete), this Set rebuilds on the next recomposition.
    val bookmarkedKeys = remember(bookmarks) { bookmarks.mapTo(HashSet(bookmarks.size)) { it.url } }

    // pendingLoad is a one-shot URL pushed in from BrowserAppRoot
    // (currently: from the Bookmarks overlay). Consume + acknowledge.
    LaunchedEffect(pendingLoad) {
        val target = pendingLoad ?: return@LaunchedEffect
        val normalized = normalizeUrl(target)
        loadedUrl = normalized
        url = normalized
        onPendingLoadConsumed()
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("https://", color = Color(0xFF9E9E9E)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Go,
                ),
                keyboardActions = KeyboardActions(onGo = {
                    if (url.isNotEmpty()) {
                        val normalized = normalizeUrl(url)
                        loadedUrl = normalized
                        url = normalized
                    }
                }),
                trailingIcon = if (url.isNotEmpty()) {
                    @Composable {
                        Text(
                            "✕",
                            color = Color(0xFF9E9E9E),
                            fontSize = 16.sp,
                            modifier = Modifier
                                .clickable {
                                    Diagnostics.log("browser.Root", "URL clear: tap")
                                    url = ""
                                }
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                        )
                    }
                } else null,
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = {
                    Diagnostics.log("browser.Root", "Go: tap (urlLen=${url.length})")
                    if (url.isNotEmpty()) {
                        val normalized = normalizeUrl(url)
                        Diagnostics.log("browser.Root", "load url scheme=${normalized.substringBefore("://", "?")}")
                        loadedUrl = normalized
                        url = normalized
                    }
                },
                modifier = Modifier.height(56.dp),
            ) { Text("Go") }
        }

        // Navigation row — only meaningful once a page has loaded. Back
        // and Forward drive the WebView's history; Reload doubles as
        // Stop while a load is in flight (matches every desktop browser
        // and saves a button slot). Tapping the page-title strip copies
        // the loaded URL to the clipboard — the URL bar above shows
        // what's been typed/normalized, but on a redirect the loaded
        // URL drifts from what the user typed, so this gives them the
        // canonical address.
        if (loadedUrl != null) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                NavIconButton(
                    label = "‹",
                    enabled = canGoBackState,
                    onClick = {
                        Diagnostics.log("browser.Root", "Nav back: tap")
                        wvRef?.goBack()
                    },
                )
                NavIconButton(
                    label = "›",
                    enabled = canGoForwardState,
                    onClick = {
                        Diagnostics.log("browser.Root", "Nav forward: tap")
                        wvRef?.goForward()
                    },
                )
                NavIconButton(
                    label = if (loading) "⏹" else "⟳",
                    enabled = wvRef != null,
                    onClick = {
                        if (loading) {
                            Diagnostics.log("browser.Root", "Stop load: tap")
                            wvRef?.stopLoading()
                        } else {
                            Diagnostics.log("browser.Root", "Reload: tap")
                            wvRef?.reload()
                        }
                    },
                )
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clickable {
                            val target = wvRef?.url ?: loadedUrl
                            if (target != null) {
                                Diagnostics.log("browser.Root",
                                    "Copy URL: tap (len=${target.length})")
                                val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                cm?.setPrimaryClip(ClipData.newPlainText("URL", target))
                                Toast.makeText(ctx, "URL copied", Toast.LENGTH_SHORT).show()
                            }
                        }
                        .padding(horizontal = 6.dp, vertical = 6.dp),
                ) {
                    Text(
                        pageTitle?.takeIf { it.isNotBlank() } ?: (wvRef?.url ?: loadedUrl ?: ""),
                        color = Color(0xFF9E9E9E),
                        fontSize = 11.sp,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    )
                }
                // Star toggle for the loaded URL. Filled when bookmarked,
                // outlined otherwise. The star reads the canonical URL
                // off the WebView (post-redirect) rather than the typed
                // URL — same call as Copy URL above.
                val starTarget = wvRef?.url ?: loadedUrl
                val starOn = starTarget != null && starTarget in bookmarkedKeys
                NavIconButton(
                    label = if (starOn) "★" else "☆",
                    enabled = starTarget != null,
                    onClick = {
                        if (starTarget != null) {
                            Diagnostics.log("browser.Root",
                                "Bookmark toggle: was=${if (starOn) "ON" else "OFF"}")
                            onBookmarkToggle(starTarget, pageTitle)
                            Toast.makeText(
                                ctx,
                                if (starOn) "Removed bookmark" else "Bookmarked",
                                Toast.LENGTH_SHORT,
                            ).show()
                        }
                    },
                )
                NavIconButton(
                    label = if (findActive) "⌕" else "⌕",
                    enabled = wvRef != null,
                    onClick = {
                        Diagnostics.log("browser.Root",
                            "Find toggle: now ${if (!findActive) "ON" else "OFF"}")
                        findActive = !findActive
                        if (!findActive) {
                            findQuery = ""
                            findCurrent = -1
                            findTotal = -1
                            wvRef?.clearMatches()
                        }
                    },
                )
            }
        }

        // Find-in-page bar — visible only while active. Sits directly
        // below the nav row so the user can scan results without losing
        // the URL bar context. WebView.findAllAsync feeds matches back
        // via FindListener; we display "i / N" against the live total.
        if (findActive) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = findQuery,
                    onValueChange = { newValue ->
                        findQuery = newValue
                        if (newValue.isEmpty()) {
                            findCurrent = -1
                            findTotal = -1
                            wvRef?.clearMatches()
                        } else {
                            wvRef?.findAllAsync(newValue)
                        }
                    },
                    label = { Text("Find in page", color = Color(0xFF9E9E9E)) },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    when {
                        findTotal < 0 -> ""
                        findTotal == 0 -> "0"
                        else -> "${findCurrent + 1} / $findTotal"
                    },
                    color = Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
                NavIconButton(
                    label = "‹",
                    enabled = findTotal > 0,
                    onClick = {
                        Diagnostics.log("browser.Root", "Find prev: tap")
                        wvRef?.findNext(false)
                    },
                )
                NavIconButton(
                    label = "›",
                    enabled = findTotal > 0,
                    onClick = {
                        Diagnostics.log("browser.Root", "Find next: tap")
                        wvRef?.findNext(true)
                    },
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            OutlinedButton(
                onClick = {
                    jsEnabled = !jsEnabled; loadedUrl = loadedUrl?.let { it }
                    Diagnostics.log("browser.Root", "JS toggle: now ${if (jsEnabled) "ON" else "OFF"}")
                },
                modifier = Modifier.weight(1f),
            ) {
                Text(if (jsEnabled) "JS: on (per session)" else "JS: off (default)")
            }
            OutlinedButton(
                onClick = {
                    // Hard-clear: blank the URL, drop loaded URL, drop JS toggle.
                    Diagnostics.log("browser.Root", "Clear session: tap")
                    url = ""; loadedUrl = null; jsEnabled = false
                    pageTitle = null
                    canGoBackState = false
                    canGoForwardState = false
                    Toast.makeText(ctx, "Session cleared", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.weight(1f),
            ) { Text("Clear session") }
        }
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            OutlinedButton(
                onClick = onOpenBookmarks,
                modifier = Modifier.weight(1f),
            ) { Text("Bookmarks (${bookmarks.size})") }
            OutlinedButton(
                onClick = onOpenProxy,
                modifier = Modifier.weight(1f),
            ) {
                // Status glance — chooses the most-active overlay across
                // the three networks. Priority: a Ready overlay > any
                // Starting overlay > any Error > Idle/BinaryMissing. Only
                // one network can hold WebView's ProxyController override
                // at a time today; the label reflects whichever is wired
                // through (currently I2P only — Lokinet / Yggdrasil are
                // scaffold-only until binaries land).
                val i2p = com.understory.overlay.i2p.I2pStatus.state
                val loki = com.understory.overlay.lokinet.LokinetStatus.state
                val ygg = com.understory.overlay.yggdrasil.YggdrasilStatus.state
                val overlayLabel = when {
                    i2p is com.understory.overlay.i2p.I2pStatus.State.Ready ->
                        "Proxy · I2P :${i2p.httpPort}"
                    loki is com.understory.overlay.lokinet.LokinetStatus.State.Ready ->
                        "Proxy · Lokinet :${loki.socksPort}"
                    ygg is com.understory.overlay.yggdrasil.YggdrasilStatus.State.Ready ->
                        "Proxy · Yggdrasil"
                    i2p == com.understory.overlay.i2p.I2pStatus.State.Starting ||
                        loki == com.understory.overlay.lokinet.LokinetStatus.State.Starting ||
                        ygg == com.understory.overlay.yggdrasil.YggdrasilStatus.State.Starting ->
                        "Proxy · starting"
                    i2p is com.understory.overlay.i2p.I2pStatus.State.Error ||
                        loki is com.understory.overlay.lokinet.LokinetStatus.State.Error ||
                        ygg is com.understory.overlay.yggdrasil.YggdrasilStatus.State.Error ->
                        "Proxy · err"
                    else -> "Proxy"
                }
                Text(overlayLabel)
            }
            OutlinedButton(
                onClick = onDiagnostics,
                modifier = Modifier.weight(1f),
            ) { Text("Diagnostics") }
        }

        if (loading) {
            Spacer(Modifier.height(2.dp))
            Box(
                modifier = Modifier.fillMaxWidth()
                    .height(2.dp)
                    .background(Color(0xFF3F51B5)),
            )
        }

        // The WebView host. Only instantiated once a URL has been loaded —
        // before that we show a placeholder. This avoids a known Compose +
        // WebView interop issue where the WebView's hardware-accelerated
        // surface composites on top of the Compose controls above it,
        // making the URL bar / buttons appear blank/invisible on first
        // launch on some devices (Samsung One UI in particular). Once a
        // URL is loaded the WebView surface has actual content to draw and
        // the surface ordering settles correctly; the placeholder is only
        // for the empty initial state.
        if (loadedUrl == null) {
            Box(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Text(
                    "Type an https:// URL above and tap Go.\n\n" +
                        "JS is off by default per session — toggle to enable for this " +
                        "session only. Clear session wipes URL + JS state.",
                    color = Color(0xFF707070),
                    fontSize = 12.sp,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier = Modifier.padding(20.dp),
                )
            }
        } else {
            AndroidView(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                factory = { factoryCtx ->
                    buildHardenedWebView(factoryCtx).also { wv ->
                        // Transparent background so the Compose backdrop
                        // shows through during paint cycles where the page
                        // hasn't yet drawn — reduces the white-flash that
                        // otherwise covers Compose controls above us.
                        wv.setBackgroundColor(android.graphics.Color.TRANSPARENT)
                        wv.webViewClient = HardenedWebViewClient(
                            onLoadStart = { loading = true },
                            onLoadFinish = { loading = false },
                            onNavState = { v ->
                                canGoBackState = v?.canGoBack() ?: false
                                canGoForwardState = v?.canGoForward() ?: false
                            },
                        )
                        wv.webChromeClient = HardenedWebChromeClient(
                            onTitle = { t -> pageTitle = t },
                        )
                        wv.setFindListener { active, total, isDoneCounting ->
                            // Android calls back twice: once with the
                            // partial count + isDoneCounting=false, then
                            // again with the final total + true. We
                            // accept both — the final values overwrite
                            // any partial render harmlessly.
                            if (isDoneCounting || total > 0) {
                                findCurrent = active
                                findTotal = total
                            }
                        }
                        wvRef = wv
                        onWebViewReady(wv)
                    }
                },
                update = { wv ->
                    wv.settings.javaScriptEnabled = jsEnabled
                    val target = loadedUrl
                    if (target != null && wv.url != target) {
                        wv.loadUrl(target)
                    }
                },
            )
        }

        SuiteStatusFooter(modifier = Modifier.padding(8.dp))
    }
}

@Composable
private fun NavIconButton(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    // Compact square button for the nav row — Material's IconButton would
    // pull in icon vector deps for the symbols we already render as text
    // glyphs (‹ › ⟳ ⏹). Disabled state dims the label rather than
    // greying-out a Material drawable, matching the rest of the suite's
    // sparse Compose-text aesthetic.
    val bg = if (enabled) Color(0xFF1C1C1C) else Color(0xFF141414)
    val fg = if (enabled) Color(0xFFE0E0E0) else Color(0xFF424242)
    Box(
        modifier = Modifier
            .height(36.dp)
            .background(bg, RoundedCornerShape(6.dp))
            .clickable(enabled = enabled) { onClick() }
            .padding(horizontal = 14.dp),
        contentAlignment = androidx.compose.ui.Alignment.Center,
    ) {
        Text(label, color = fg, fontSize = 18.sp)
    }
}

@Composable
private fun BookmarksScreen(
    bookmarks: List<Bookmark>,
    onBack: () -> Unit,
    onPick: (String) -> Unit,
    onRemove: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize().padding(20.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Bookmarks", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text(
                    "${bookmarks.size} saved. Persistent across app launches.",
                    color = Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                )
            }
            OutlinedButton(onClick = onBack) { Text("Back") }
        }

        Spacer(Modifier.height(16.dp))

        if (bookmarks.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxWidth().weight(1f),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Text(
                    "No bookmarks yet.\n\nTap ☆ in the toolbar while a page is loaded to add one.",
                    color = Color(0xFF707070),
                    fontSize = 12.sp,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                )
            }
        } else {
            androidx.compose.foundation.lazy.LazyColumn(
                verticalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier.fillMaxWidth().weight(1f),
            ) {
                // androidx.compose.foundation.lazy.items is an extension on
                // LazyListScope — calling it via fully-qualified name doesn't
                // resolve the receiver. Use the in-scope (imported) form.
                items(
                    items = bookmarks,
                    key = { it.url },
                ) { bookmark ->
                    BookmarkRow(
                        bookmark = bookmark,
                        onTap = { onPick(bookmark.url) },
                        onRemove = { onRemove(bookmark.url) },
                    )
                }
            }
        }
    }
}

@Composable
private fun BookmarkRow(
    bookmark: Bookmark,
    onTap: () -> Unit,
    onRemove: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .clickable { onTap() },
        ) {
            Text(
                bookmark.title,
                color = Color(0xFFE0E0E0),
                fontSize = 13.sp,
                maxLines = 1,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )
            Text(
                bookmark.url,
                color = Color(0xFF707070),
                fontSize = 10.sp,
                maxLines = 1,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )
        }
        Text(
            "✕",
            color = Color(0xFF9E9E9E),
            fontSize = 16.sp,
            modifier = Modifier
                .clickable { onRemove() }
                .padding(horizontal = 12.dp, vertical = 4.dp),
        )
    }
}

/**
 * Resolve a user-typed string to a navigable URL. Bare hosts get
 * https:// prepended; never http://. Anything that doesn't look like a
 * URL after normalization is rejected (returned as-is for the WebView
 * to fail predictably).
 */
private fun normalizeUrl(raw: String): String {
    val trimmed = raw.trim()
    if (trimmed.startsWith("https://", ignoreCase = true)) return trimmed
    // Reject http:// at the input layer; the network-security-config
    // would block it anyway, but failing fast gives a better UX.
    if (trimmed.startsWith("http://", ignoreCase = true)) {
        return "https://" + trimmed.removePrefix("http://").removePrefix("HTTP://")
    }
    // Bare host or path — assume https.
    return "https://$trimmed"
}

@SuppressLint("SetJavaScriptEnabled")
private fun buildHardenedWebView(ctx: android.content.Context): WebView {
    val wv = WebView(ctx)
    val s: WebSettings = wv.settings
    // JavaScript starts off; user can enable per-session.
    s.javaScriptEnabled = false
    // No file:// or content:// access — would let a malicious page
    // read app data via crafted iframes.
    s.allowFileAccess = false
    s.allowContentAccess = false
    @Suppress("DEPRECATION")
    s.allowFileAccessFromFileURLs = false
    @Suppress("DEPRECATION")
    s.allowUniversalAccessFromFileURLs = false
    // No mixed content — the network-security-config also blocks
    // cleartext, but belt-and-suspenders.
    s.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    // No saved passwords (defer to passgen autofill) and no form data.
    @Suppress("DEPRECATION")
    s.saveFormData = false
    s.savePassword = false
    // No geolocation; we don't have ACCESS_*_LOCATION anyway, so this
    // is just consistency.
    s.setGeolocationEnabled(false)
    // Require user gesture to play audio/video — blocks autoplay
    // tracking pixels and surprise audio.
    s.mediaPlaybackRequiresUserGesture = true
    // Don't surface JavaScript-can-open-new-windows; we handle window
    // creation in WebChromeClient by refusing.
    s.javaScriptCanOpenWindowsAutomatically = false
    s.setSupportMultipleWindows(false)
    // Use a smaller, hopefully less-fingerprintable cache mode.
    s.cacheMode = WebSettings.LOAD_NO_CACHE
    // Deliberately leave userAgentString at default. Phase 2 will
    // randomize this; the MVP doesn't because randomizing without
    // matching font/canvas/timezone changes is more fingerprintable
    // than the default.
    // Layout / rendering surface area we don't need.
    s.databaseEnabled = false
    s.domStorageEnabled = false

    // Block third-party cookies on this WebView. The system default
    // varies by platform/version (and was true on older Androids);
    // the explicit per-WebView call is the only way to be sure. Pure
    // tracking surface — first-party cookies still work for sessions.
    runCatching {
        CookieManager.getInstance().setAcceptThirdPartyCookies(wv, false)
    }

    // SafeBrowsing — Google's malicious-URL list. Modern Android has
    // it on by default; the explicit set documents intent and is the
    // RELEASE_BLOCKERS.md callout. Gated by WebViewFeature because the
    // capability ships with the WebView component, not the platform,
    // and a stripped-down OEM build may not include it. WebSettingsCompat
    // delegates to the underlying WebSettings.setSafeBrowsingEnabled
    // when supported and is a no-op otherwise.
    runCatching {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SAFE_BROWSING_ENABLE)) {
            WebSettingsCompat.setSafeBrowsingEnabled(s, true)
        }
    }
    return wv
}

private class HardenedWebViewClient(
    val onLoadStart: (WebView?) -> Unit,
    val onLoadFinish: (WebView?) -> Unit,
    val onNavState: (WebView?) -> Unit,
) : WebViewClient() {

    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        // Refuse non-https navigation. The transport layer would block
        // it (network-security-config), but failing earlier here keeps
        // the failure mode crisp.
        val uri = request?.url ?: return true
        if (!uri.scheme.equals("https", ignoreCase = true)) return true
        return false  // let the WebView load the URL
    }

    override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
        onLoadStart(view)
        onNavState(view)
    }

    override fun onPageFinished(view: WebView?, url: String?) {
        onLoadFinish(view)
        onNavState(view)
    }

    override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
        // History entries can shift without onPageStarted/onPageFinished
        // bracketing — back-navigation, history.pushState in JS-on
        // single-page apps. Refresh nav state so the toolbar's back/
        // forward buttons stay honest. Strictly nav-state, not loading
        // state — calling onLoadFinish here would prematurely clear
        // `loading` mid-fetch (the URL commit can land before the page
        // is actually finished loading).
        super.doUpdateVisitedHistory(view, url, isReload)
        onNavState(view)
    }

    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        // Hard reject — never proceed past an SSL error. The default
        // WebViewClient calls handler.cancel() too, but we're explicit.
        handler?.cancel()
    }
}

private class HardenedWebChromeClient(
    val onTitle: (String?) -> Unit = {},
) : WebChromeClient() {

    override fun onReceivedTitle(view: WebView?, title: String?) {
        // Page titles surface in our toolbar strip. Stripped of any
        // control characters by Compose's text rendering; we don't need
        // additional sanitization for display, only for trust — and we
        // never use it as a trust signal (security comes from FLAG_SECURE
        // + the locked-down scheme/SSL handling, not from title text).
        onTitle(title)
    }

    override fun onPermissionRequest(request: PermissionRequest?) {
        // Refuse every web permission request — camera, mic, location,
        // midi, protected-media, etc. We don't have those Android
        // permissions anyway, but refusing at the WebChrome layer is
        // belt-and-suspenders.
        request?.deny()
    }

    override fun onPermissionRequestCanceled(request: PermissionRequest?) {
        // No-op: nothing to clean up since we always deny.
    }

    override fun onShowFileChooser(
        webView: WebView?,
        filePathCallback: android.webkit.ValueCallback<Array<Uri>>?,
        fileChooserParams: FileChooserParams?,
    ): Boolean {
        // No file picker. Drive-by-upload is a real exfiltration
        // vector; the MVP refuses every upload-form prompt.
        filePathCallback?.onReceiveValue(null)
        return false
    }

    override fun onCreateWindow(
        view: WebView?,
        isDialog: Boolean,
        isUserGesture: Boolean,
        resultMsg: android.os.Message?,
    ): Boolean {
        // No popups, no _blank target, no window.open. Pages that try
        // hit the dead end.
        return false
    }
}
