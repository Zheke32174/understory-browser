package com.understory.browser

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.PermissionRequest
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
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
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.FatalScreen
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch

/**
 * Hardened browser MVP — single Activity, single WebView, locked-down
 * defaults. Phase-1 hardening matrix (each line is a defense-matrix
 * item; RELEASE_BLOCKERS.md "Browser" section references this list):
 *   - JavaScript OFF by default for every navigation. Explicit per-site
 *     opt-in toggle in the toolbar, backed by a persisted host allowlist
 *     in [BrowserSettings]. Cross-site navigation re-derives the policy
 *     for the target host before the new document commits.
 *   - file:// and content:// loads blocked entirely: allowFileAccess /
 *     allowContentAccess / allowFileAccessFromFileURLs /
 *     allowUniversalAccessFromFileURLs all false, AND
 *     shouldOverrideUrlLoading refuses every non-https scheme.
 *   - Third-party cookies always blocked
 *     (CookieManager.setAcceptThirdPartyCookies(wv, false)); first-party
 *     cookies OFF by default behind a persisted settings toggle. Both
 *     wiped on Activity destroy either way.
 *   - Mixed content blocked (MIXED_CONTENT_NEVER_ALLOW) + cleartext
 *     denied at the transport layer (network_security_config).
 *   - Safe Browsing enabled where the WebView provider supports it;
 *     degrades gracefully (silently absent) on providers that lack the
 *     feature — no fallback network call of our own.
 *   - Geolocation / camera / mic auto-denied: settings geolocation off,
 *     onGeolocationPermissionsShowPrompt denies, onPermissionRequest
 *     denies every web permission. The Android permissions themselves
 *     are also stripped in the manifest.
 *   - No form autofill, no saved passwords in the WebView
 *     (saveFormData / savePassword false). Credential fill defers to
 *     the system autofill service (passgen/aegis integration path).
 *   - All cookies + storage cleared on Activity destroy, or on the
 *     explicit "Clear now" control (a real wipe, not a UI-only reset).
 *   - SSL errors rejected hard (no proceed-anyway dialog).
 *   - No file chooser, no window-create, no popups.
 *   - Main-frame load failures render the app's own dark error panel,
 *     not Chromium's grey page.
 *   - INTERNET permission required (only suite app besides firewall).
 *
 * v2 adds the doorway (share-target + opt-in VIEW filter → a mandatory
 * confirmation interstitial) and the exit (open-in-default-browser
 * hand-off), plus honest feedback on every previously-silent dead-end.
 *
 * Deferred to phase 2:
 *   - Cromite-fork integration (the SUITE_DESIGN target).
 *   - Tabs.
 *   - Fingerprint randomization.
 *   - DNS-over-HTTPS toggle.
 */
class MainActivity : ComponentActivity() {

    private var webView: WebView? = null

    // The URL an inbound Intent (SEND / VIEW) wants opened. Set ONLY by
    // intent parsing; consumed ONLY by the IntakeInterstitial's Open
    // button. There is no code path from here straight to loadUrl — that
    // is the whole injection mitigation (design §2.3).
    private var pendingIntake by mutableStateOf<PendingIntake?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("browser.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        super.onCreate(savedInstanceState)
        pendingIntake = parseIntake(intent)
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("browser.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.BROWSER) {
                    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                        FatalScreen(
                            title = getString(R.string.crash_title),
                            reason = t.javaClass.simpleName,
                            details = t.toString(),
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // singleTask: a live task gets onNewIntent for a re-delivered
        // Intent. Route it to the interstitial (pendingIntake) — never to
        // a load. A background app cannot silently replace the page.
        parseIntake(intent)?.let { pendingIntake = it }
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
            // Route through the honest integrity-failure screen instead of
            // a bare finishAndRemoveTask() (indistinguishable from a crash
            // on a false positive). The user is told why, then exits.
            renderIntegrityFail()
            return
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
            UnderstoryTheme(accent = UnderstoryAccent.BROWSER) {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    BrowserAppRoot(
                        onWebViewReady = { webView = it },
                        pendingIntake = pendingIntake,
                        onIntakeConsumed = { pendingIntake = null },
                        onEnableViewFilter = { setViewFilterAliasEnabled(true) },
                    )
                }
            }
        }

        // Note: lifted `window.decorView.filterTouchesWhenObscured = true`
        // per SAMSUNG_QUIRKS.md — the global decor filter silently drops
        // legitimate taps under Samsung Edge Panel and similar overlays.
        // FLAG_SECURE on the window still prevents screenshots / overlay
        // capture of browsed content.
    }

    private fun renderIntegrityFail() {
        Diagnostics.error("browser.MainActivity", "integrity hardFail — rendering fatal screen")
        runCatching {
            if (!TestingMode.ALLOW_SCREENSHOTS) {
                window.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE,
                )
            }
        }
        setContent {
            UnderstoryTheme(accent = UnderstoryAccent.BROWSER) {
                BackHandler { finishAndRemoveTask() }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column(modifier = Modifier.fillMaxSize()) {
                        Box(modifier = Modifier.weight(1f)) {
                            FatalScreen(
                                title = stringRes(R.string.integrity_title),
                                reason = stringRes(R.string.integrity_reason),
                            )
                        }
                        Button(
                            onClick = { finishAndRemoveTask() },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(UnderstoryTheme.spacing.lg)
                                .height(48.dp),
                        ) { Text(stringRes(R.string.action_exit)) }
                    }
                }
            }
        }
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
        // Wipe cookies + storage on every Activity destroy. The manifest
        // is singleTask + recents-visible, so the ephemeral guarantee is
        // "on destroy, or on Clear now" — never "on leave". Persistent web
        // state would be a huge fingerprinting + tracking surface; making
        // sessions ephemeral is the strongest sovereign default.
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

    /**
     * Extract the first http(s) URL from an inbound SEND / VIEW Intent.
     * Returns null for MAIN/LAUNCHER (cold app launch, no intake). A
     * PendingIntake with a null url signals "delivered but no link found"
     * so the interstitial can show a paste-manually empty state.
     */
    private fun parseIntake(intent: Intent?): PendingIntake? {
        intent ?: return null
        val sourceLabel = resolveSourceLabel(intent)
        return when (intent.action) {
            Intent.ACTION_SEND -> {
                if (intent.type != "text/plain") return null
                val text = intent.getStringExtra(Intent.EXTRA_TEXT) ?: return PendingIntake(null, sourceLabel, null)
                PendingIntake(firstUrlIn(text), sourceLabel, text)
            }
            Intent.ACTION_VIEW -> {
                val data = intent.data ?: return null
                val scheme = data.scheme?.lowercase()
                if (scheme != "http" && scheme != "https") return null
                PendingIntake(data.toString(), sourceLabel, null)
            }
            else -> null
        }
    }

    /**
     * The delivering app's display label when resolvable via the launch
     * referrer, else null (the interstitial then reads "Opened by another
     * app" — we never claim a source we can't verify).
     */
    private fun resolveSourceLabel(intent: Intent): String? {
        val pkg = runCatching { referrer?.host }.getOrNull()
            ?: intent.getStringExtra(Intent.EXTRA_REFERRER_NAME)
            ?: return null
        return runCatching {
            val pm = packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        }.getOrNull()
    }

    /** Flip the disabled-by-default VIEW-filter alias on (first-run opt-in). */
    private fun setViewFilterAliasEnabled(on: Boolean) {
        runCatching {
            val comp = ComponentName(this, "com.understory.browser.ViewIntakeAlias")
            packageManager.setComponentEnabledSetting(
                comp,
                if (on) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP,
            )
            BrowserSettings.setViewFilterEnabled(this, on)
            Diagnostics.log("browser.MainActivity", "VIEW filter alias enabled=$on")
        }.onFailure {
            Diagnostics.error("browser.MainActivity",
                "setComponentEnabledSetting failed: ${it.javaClass.simpleName}")
        }
    }

    private fun stringRes(id: Int): String = getString(id)
}

/** A link delivered by an inbound Intent, awaiting the interstitial gate. */
data class PendingIntake(
    val url: String?,
    val sourceLabel: String?,
    val rawText: String?,
)

/**
 * A main-frame load failure, mapped to a friendly title for the custom
 * error panel (design §3.5). [titleArgs] is spread into the string
 * resource (e.g. an HTTP status code).
 */
data class MainFrameError(
    val url: String,
    val titleRes: Int,
    val titleArgs: Array<Any> = emptyArray(),
) {
    companion object {
        fun fromWebResourceError(url: String, code: Int): MainFrameError {
            val titleRes = when (code) {
                WebViewClient.ERROR_HOST_LOOKUP -> R.string.err_host_lookup
                WebViewClient.ERROR_CONNECT,
                WebViewClient.ERROR_TIMEOUT,
                WebViewClient.ERROR_IO -> R.string.err_connect
                WebViewClient.ERROR_UNSUPPORTED_SCHEME -> R.string.err_cleartext
                else -> R.string.err_generic
            }
            return MainFrameError(url, titleRes)
        }

        fun fromHttpStatus(url: String, status: Int): MainFrameError =
            MainFrameError(url, R.string.err_http, arrayOf(status))
    }

    // data class with an Array field: override equals/hashCode so the
    // Compose state comparison is by content, not reference identity.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MainFrameError) return false
        return url == other.url && titleRes == other.titleRes &&
            titleArgs.contentEquals(other.titleArgs)
    }

    override fun hashCode(): Int {
        var result = url.hashCode()
        result = 31 * result + titleRes
        result = 31 * result + titleArgs.contentHashCode()
        return result
    }
}

/** Result of resolving a user-typed string to a load action. */
sealed interface NormalizeResult {
    data object Empty : NormalizeResult
    data class NotAUrl(val raw: String) : NormalizeResult
    data class Url(val url: String) : NormalizeResult
}

@Composable
private fun BrowserAppRoot(
    onWebViewReady: (WebView) -> Unit,
    pendingIntake: PendingIntake?,
    onIntakeConsumed: () -> Unit,
    onEnableViewFilter: () -> Unit,
) {
    // Diagnostics + Bookmarks + JS-allowlist + Proxy render as overlays on
    // top of BrowserRoot rather than swapping it out, so the WebView's
    // composition (and its loaded page) survives a trip to a secondary
    // surface and back. pendingLoad is a one-shot URL pushed from an
    // overlay (or the interstitial) back into BrowserRoot, which consumes
    // + clears it on next composition.
    val ctx = LocalContext.current
    var showDiagnostics by rememberSaveable { mutableStateOf(false) }
    var showBookmarks by rememberSaveable { mutableStateOf(false) }
    var showJsAllowlist by rememberSaveable { mutableStateOf(false) }
    var showProxy by rememberSaveable { mutableStateOf(false) }
    var pendingLoad by remember { mutableStateOf<String?>(null) }

    // First-run VIEW-filter opt-in card. Shows once, on the very first
    // launch, only when there's no intake to handle (an intake is a more
    // urgent surface).
    var showFirstRun by rememberSaveable {
        mutableStateOf(!BrowserSettings.isFirstRunDone(ctx))
    }

    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    // showSnack drives the shared SnackbarHost. An optional action label +
    // callback backs the "Download in Chrome" / hand-off affordances.
    val showSnack: (String, String?, (() -> Unit)?) -> Unit = { msg, actionLabel, action ->
        scope.launch {
            val result = snackbarHostState.showSnackbar(
                message = msg,
                actionLabel = actionLabel,
            )
            if (result == SnackbarResult.ActionPerformed) action?.invoke()
        }
    }

    // Bookmarks state lives at the AppRoot so the star icon and the
    // BookmarksScreen list both observe one source of truth.
    var bookmarks by remember { mutableStateOf(BrowserSettings.getBookmarks(ctx)) }
    val refreshBookmarks = { bookmarks = BrowserSettings.getBookmarks(ctx) }

    // Proxy override applier lives here (design §6.4), keyed on I2P state,
    // so a Ready transition lands the WebView override even if the user has
    // left the proxy overlay. Eng-only — prod has no proxy surface at all.
    if (isEngBuild(ctx)) {
        ProxyOverrideEffect()
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { pad ->
        Box(modifier = Modifier.fillMaxSize().padding(pad)) {
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
                onOpenJsAllowlist = {
                    Diagnostics.log("browser.AppRoot", "show JS allowlist overlay")
                    showJsAllowlist = true
                },
                onOpenProxy = {
                    Diagnostics.log("browser.AppRoot", "show proxy overlay")
                    showProxy = true
                },
                bookmarks = bookmarks,
                onBookmarkToggle = { url, title ->
                    val nowOn = BrowserSettings.toggle(ctx, url, title)
                    val wasAtCap = bookmarks.size >= 200
                    refreshBookmarks()
                    if (nowOn && wasAtCap) {
                        showSnack(ctx.getString(R.string.msg_bookmark_cap_dropped), null, null)
                    }
                },
                pendingLoad = pendingLoad,
                onPendingLoadConsumed = { pendingLoad = null },
                showSnack = showSnack,
                proxyEnabled = isEngBuild(ctx),
            )

            // Intake interstitial — a full-bleed modal over whatever is
            // loaded. The single gate between an inbound Intent and a load.
            if (pendingIntake != null) {
                BackHandler {
                    Diagnostics.log("browser.AppRoot", "intake cancel via back")
                    onIntakeConsumed()
                }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    IntakeInterstitial(
                        intake = pendingIntake,
                        onOpen = { normalizedUrl ->
                            Diagnostics.log("browser.AppRoot", "intake open confirmed")
                            pendingLoad = normalizedUrl
                            onIntakeConsumed()
                        },
                        onCopy = { link ->
                            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            cm?.setPrimaryClip(ClipData.newPlainText("URL", link))
                            showSnack(ctx.getString(R.string.msg_url_copied), null, null)
                        },
                        onCancel = onIntakeConsumed,
                    )
                }
            } else if (showFirstRun) {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    FirstRunOptIn(
                        onEnable = {
                            onEnableViewFilter()
                            BrowserSettings.setFirstRunDone(ctx)
                            showFirstRun = false
                        },
                        onNotNow = {
                            BrowserSettings.setFirstRunDone(ctx)
                            showFirstRun = false
                        },
                    )
                }
            }

            if (showDiagnostics) {
                BackHandler { showDiagnostics = false }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    DiagnosticsScreen(onBack = { showDiagnostics = false })
                }
            }
            if (showBookmarks) {
                BackHandler { showBookmarks = false }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
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
            if (showJsAllowlist) {
                BackHandler { showJsAllowlist = false }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    JsAllowlistScreen(onBack = { showJsAllowlist = false })
                }
            }
            if (showProxy) {
                BackHandler { showProxy = false }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    ProxyScreen(onBack = { showProxy = false })
                }
            }
        }
    }
}

@Composable
private fun BrowserRoot(
    onWebViewReady: (WebView) -> Unit,
    onDiagnostics: () -> Unit,
    onOpenBookmarks: () -> Unit,
    onOpenJsAllowlist: () -> Unit,
    onOpenProxy: () -> Unit,
    bookmarks: List<Bookmark>,
    onBookmarkToggle: (url: String, title: String?) -> Unit,
    pendingLoad: String?,
    onPendingLoadConsumed: () -> Unit,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
    proxyEnabled: Boolean,
) {
    val ctx = LocalContext.current
    var url by remember { mutableStateOf("") }
    var loadedUrl by remember { mutableStateOf<String?>(null) }
    // The "not a web address" chip under the URL bar (search-off honesty).
    var notAUrlHint by remember { mutableStateOf(false) }
    var jsEnabled by remember { mutableStateOf(false) }
    var cookiesFirstParty by remember { mutableStateOf(BrowserSettings.getFirstPartyCookies(ctx)) }
    var loading by remember { mutableStateOf(false) }
    var wvRef by remember { mutableStateOf<WebView?>(null) }
    var canGoBackState by remember { mutableStateOf(false) }
    var canGoForwardState by remember { mutableStateOf(false) }
    var pageTitle by remember { mutableStateOf<String?>(null) }
    var findActive by remember { mutableStateOf(false) }
    var findQuery by remember { mutableStateOf("") }
    var findCurrent by remember { mutableStateOf(-1) }
    var findTotal by remember { mutableStateOf(-1) }
    // Main-frame error overlay. Non-null renders the custom dark panel over
    // the WebView; cleared on the next successful load of a new URL.
    var errorState by remember { mutableStateOf<MainFrameError?>(null) }

    val bookmarkedKeys = remember(bookmarks) { bookmarks.mapTo(HashSet(bookmarks.size)) { it.url } }

    // The shared load path — used by the URL bar, the interstitial's
    // pendingLoad, retry, and reload. Resolves NotAUrl to the chip and a
    // real URL to a WebView load.
    val loadFromInput: (String) -> Unit = { raw ->
        when (val r = normalizeUrl(raw)) {
            is NormalizeResult.Empty -> { /* nothing to do */ }
            is NormalizeResult.NotAUrl -> {
                notAUrlHint = true
            }
            is NormalizeResult.Url -> {
                notAUrlHint = false
                errorState = null
                jsEnabled = BrowserSettings.isJsAllowed(ctx, hostOf(r.url))
                loadedUrl = r.url
                url = r.url
            }
        }
    }

    // pendingLoad is a one-shot URL pushed in from BrowserAppRoot (from the
    // Bookmarks overlay or the intake interstitial — both already
    // normalized). Consume + acknowledge.
    LaunchedEffect(pendingLoad) {
        val target = pendingLoad ?: return@LaunchedEffect
        notAUrlHint = false
        errorState = null
        jsEnabled = BrowserSettings.isJsAllowed(ctx, hostOf(target))
        loadedUrl = target
        url = target
        onPendingLoadConsumed()
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            OutlinedTextField(
                value = url,
                onValueChange = { url = it; if (notAUrlHint) notAUrlHint = false },
                label = { Text(stringResource(R.string.hint_url), color = MaterialTheme.colorScheme.onSurfaceVariant) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Go,
                ),
                keyboardActions = KeyboardActions(onGo = {
                    if (url.isNotEmpty()) loadFromInput(url)
                }),
                trailingIcon = if (url.isNotEmpty()) {
                    @Composable {
                        IconButton(onClick = {
                            Diagnostics.log("browser.Root", "URL clear: tap")
                            url = ""
                            notAUrlHint = false
                        }) {
                            Icon(
                                imageVector = Icons.Filled.Clear,
                                contentDescription = stringResource(R.string.cd_clear_url),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                } else null,
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = {
                    Diagnostics.log("browser.Root", "Go: tap (urlLen=${url.length})")
                    if (url.isNotEmpty()) loadFromInput(url)
                },
                modifier = Modifier.height(56.dp),
            ) { Text(stringResource(R.string.action_go)) }
        }

        if (notAUrlHint) {
            Text(
                stringResource(R.string.msg_not_a_web_address),
                color = UnderstoryTheme.semantic.warning,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp),
            )
        }

        // Navigation row — only meaningful once a page has loaded.
        if (loadedUrl != null) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                NavIconButton(
                    icon = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.cd_nav_back),
                    enabled = canGoBackState,
                    onClick = {
                        Diagnostics.log("browser.Root", "Nav back: tap")
                        wvRef?.goBack()
                    },
                )
                NavIconButton(
                    icon = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = stringResource(R.string.cd_nav_forward),
                    enabled = canGoForwardState,
                    onClick = {
                        Diagnostics.log("browser.Root", "Nav forward: tap")
                        wvRef?.goForward()
                    },
                )
                NavIconButton(
                    icon = if (loading) Icons.Filled.Close else Icons.Filled.Refresh,
                    contentDescription = if (loading) stringResource(R.string.cd_stop)
                    else stringResource(R.string.cd_reload),
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
                NavIconButton(
                    icon = Icons.Filled.OpenInNew,
                    contentDescription = stringResource(R.string.cd_open_in_default),
                    enabled = wvRef != null || loadedUrl != null,
                    onClick = {
                        val target = wvRef?.url ?: loadedUrl
                        if (target != null) openInDefault(ctx, target, showSnack)
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
                                showSnack(ctx.getString(R.string.msg_url_copied), null, null)
                            }
                        }
                        .semantics { contentDescription = ctx.getString(R.string.cd_copy_url) }
                        .padding(horizontal = 6.dp, vertical = 6.dp),
                ) {
                    Text(
                        pageTitle?.takeIf { it.isNotBlank() } ?: (wvRef?.url ?: loadedUrl ?: ""),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                val starTarget = wvRef?.url ?: loadedUrl
                val starOn = starTarget != null && starTarget in bookmarkedKeys
                NavIconButton(
                    icon = if (starOn) Icons.Filled.Star else Icons.Outlined.StarBorder,
                    contentDescription = if (starOn) stringResource(R.string.cd_bookmark_on)
                    else stringResource(R.string.cd_bookmark_off),
                    enabled = starTarget != null,
                    tint = if (starOn) MaterialTheme.colorScheme.primary else null,
                    onClick = {
                        if (starTarget != null) {
                            Diagnostics.log("browser.Root",
                                "Bookmark toggle: was=${if (starOn) "ON" else "OFF"}")
                            onBookmarkToggle(starTarget, pageTitle)
                            showSnack(
                                ctx.getString(
                                    if (starOn) R.string.msg_bookmark_removed
                                    else R.string.msg_bookmarked
                                ),
                                null, null,
                            )
                        }
                    },
                )
                NavIconButton(
                    icon = if (findActive) Icons.Filled.Search else Icons.Outlined.Search,
                    contentDescription = stringResource(R.string.cd_find_toggle),
                    enabled = wvRef != null,
                    tint = if (findActive) MaterialTheme.colorScheme.primary else null,
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

        // Find-in-page bar.
        if (findActive) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically,
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
                    label = { Text(stringResource(R.string.hint_find), color = MaterialTheme.colorScheme.onSurfaceVariant) },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    when {
                        findTotal < 0 -> ""
                        findTotal == 0 -> "0"
                        else -> "${findCurrent + 1} / $findTotal"
                    },
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
                NavIconButton(
                    icon = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.cd_find_prev),
                    enabled = findTotal > 0,
                    onClick = {
                        Diagnostics.log("browser.Root", "Find prev: tap")
                        wvRef?.findNext(false)
                    },
                )
                NavIconButton(
                    icon = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = stringResource(R.string.cd_find_next),
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
            // Per-site JS opt-in. Long-press opens the allowlist manager.
            JsToggleButton(
                jsEnabled = jsEnabled,
                enabled = loadedUrl != null,
                onClick = {
                    val host = hostOf(wvRef?.url ?: loadedUrl)
                    if (host != null) {
                        val nowOn = !jsEnabled
                        jsEnabled = nowOn
                        BrowserSettings.setJsAllowed(ctx, host, nowOn)
                        Diagnostics.log("browser.Root",
                            "JS toggle: now ${if (nowOn) "ALLOW" else "OFF"} (persisted per-site)")
                        wvRef?.settings?.javaScriptEnabled = nowOn
                        wvRef?.reload()
                    }
                },
                onLongClick = onOpenJsAllowlist,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(
                onClick = {
                    cookiesFirstParty = !cookiesFirstParty
                    BrowserSettings.setFirstPartyCookies(ctx, cookiesFirstParty)
                    Diagnostics.log("browser.Root",
                        "Cookie toggle: first-party now ${if (cookiesFirstParty) "ON" else "OFF"}")
                    runCatching {
                        CookieManager.getInstance().setAcceptCookie(cookiesFirstParty)
                        if (!cookiesFirstParty) {
                            CookieManager.getInstance().removeAllCookies(null)
                        }
                    }
                },
                modifier = Modifier.weight(1f),
            ) {
                Text(if (cookiesFirstParty) stringResource(R.string.cookies_first_party) else stringResource(R.string.cookies_off))
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            OutlinedButton(
                onClick = {
                    // Real wipe (mirrors onDestroy without killing the
                    // Activity): cookies + storage globally, plus the
                    // visible page + its DOM/JS context.
                    Diagnostics.log("browser.Root", "Clear now: tap")
                    runCatching {
                        CookieManager.getInstance().removeAllCookies(null)
                        CookieManager.getInstance().flush()
                        WebStorage.getInstance().deleteAllData()
                    }
                    wvRef?.clearCache(true)
                    wvRef?.clearHistory()
                    wvRef?.clearFormData()
                    wvRef?.clearSslPreferences()
                    wvRef?.loadUrl("about:blank")
                    url = ""; loadedUrl = null; jsEnabled = false; pageTitle = null
                    canGoBackState = false; canGoForwardState = false
                    notAUrlHint = false
                    errorState = null
                    showSnack(ctx.getString(R.string.msg_cleared), null, null)
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.action_clear_now)) }
            OutlinedButton(
                onClick = onOpenBookmarks,
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.action_bookmarks, bookmarks.size)) }
        }
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            // Proxy entry point only in eng builds — prod ships no overlay
            // surface at all (design §6; nothing honest to show in phase α).
            if (proxyEnabled) {
                OutlinedButton(
                    onClick = onOpenProxy,
                    modifier = Modifier.weight(1f),
                ) {
                    val i2p = com.understory.overlay.i2p.I2pStatus.state
                    val overlayLabel = when (val s = i2p) {
                        is com.understory.overlay.i2p.I2pStatus.State.Ready ->
                            stringResource(R.string.action_proxy_i2p_ready, s.httpPort)
                        com.understory.overlay.i2p.I2pStatus.State.Starting ->
                            stringResource(R.string.action_proxy_starting)
                        is com.understory.overlay.i2p.I2pStatus.State.Error ->
                            stringResource(R.string.action_proxy_err)
                        else -> stringResource(R.string.action_proxy)
                    }
                    Text(overlayLabel)
                }
            }
            OutlinedButton(
                onClick = onDiagnostics,
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.action_diagnostics)) }
        }

        if (loading) {
            Spacer(Modifier.height(2.dp))
            Box(
                modifier = Modifier.fillMaxWidth()
                    .height(2.dp)
                    .background(MaterialTheme.colorScheme.primary),
            )
        }

        // The WebView host. Only instantiated once a URL has been loaded —
        // before that we show a placeholder (also avoids the Compose +
        // WebView surface-ordering flash on first launch).
        if (loadedUrl == null) {
            Box(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    stringResource(R.string.placeholder_main),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier = Modifier.padding(20.dp),
                )
            }
        } else {
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
                    factory = { factoryCtx ->
                        buildHardenedWebView(factoryCtx).also { wv ->
                            wv.setBackgroundColor(android.graphics.Color.TRANSPARENT)
                            wv.webViewClient = HardenedWebViewClient(
                                onLoadStart = { loading = true },
                                onLoadFinish = { loading = false },
                                onNavState = { v ->
                                    canGoBackState = v?.canGoBack() ?: false
                                    canGoForwardState = v?.canGoForward() ?: false
                                },
                                jsAllowed = { host -> BrowserSettings.isJsAllowed(ctx, host) },
                                onJsApplied = { allowed -> jsEnabled = allowed },
                                onUrlCommitted = { committed ->
                                    if (committed != null && committed != loadedUrl) {
                                        loadedUrl = committed
                                    }
                                },
                                onPageStartedForUrl = {
                                    // A new main-frame navigation succeeded
                                    // in starting — clear any stale error.
                                    errorState = null
                                },
                                onMainFrameError = { err -> errorState = err },
                                onBlockedScheme = { uri ->
                                    handleBlockedScheme(ctx, uri, showSnack)
                                },
                            )
                            wv.webChromeClient = HardenedWebChromeClient(
                                onTitle = { t -> pageTitle = t },
                            )
                            wv.setDownloadListener { downloadUrl, _, _, _, _ ->
                                Diagnostics.log("browser.Root", "download blocked (view-only)")
                                showSnack(
                                    ctx.getString(R.string.msg_downloads_disabled),
                                    ctx.getString(R.string.action_download_in_chrome),
                                ) { openInDefault(ctx, downloadUrl, showSnack) }
                            }
                            wv.setFindListener { active, total, isDoneCounting ->
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

                // Custom dark error panel — overlays the WebView so the
                // page underneath is fully covered (no Chromium grey page).
                errorState?.let { err ->
                    ErrorPanel(
                        error = err,
                        onRetry = {
                            errorState = null
                            wvRef?.reload()
                        },
                        onOpenInDefault = {
                            val target = wvRef?.url ?: loadedUrl ?: err.url
                            openInDefault(ctx, target, showSnack)
                        },
                    )
                }
            }
        }

        SuiteStatusFooter(modifier = Modifier.padding(8.dp))
    }
}

/**
 * Small square icon button for the nav / find rows. 48dp target with a
 * vector [Icon] + contentDescription (a11y). Disabled state dims via the
 * standard IconButton colors.
 */
@Composable
private fun NavIconButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDescription: String,
    enabled: Boolean,
    onClick: () -> Unit,
    tint: Color? = null,
) {
    IconButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.size(48.dp),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = contentDescription,
            tint = tint
                ?: if (enabled) MaterialTheme.colorScheme.onSurface
                else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
        )
    }
}

/**
 * The per-site JS toggle. An outlined-button look built on a Box so it can
 * carry a long-press (open the allowlist manager) that a Material
 * OutlinedButton can't. Merged semantics announce the current state and
 * the long-press affordance to TalkBack.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun JsToggleButton(
    jsEnabled: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ctx = LocalContext.current
    val outline = MaterialTheme.colorScheme.outline
    val labelColor = if (enabled) MaterialTheme.colorScheme.primary
    else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
    Box(
        modifier = modifier
            .height(48.dp)
            .background(Color.Transparent, MaterialTheme.shapes.small)
            .combinedClickable(
                enabled = enabled,
                onClick = onClick,
                onLongClick = onLongClick,
            )
            .semantics {
                contentDescription = ctx.getString(
                    R.string.cd_js_toggle,
                    ctx.getString(if (jsEnabled) R.string.js_state_on else R.string.js_state_off),
                )
            }
            .padding(horizontal = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.foundation.layout.Box(
            modifier = Modifier
                .matchParentSize()
                .androidxOutline(outline, enabled),
        )
        Text(
            if (jsEnabled) stringResource(R.string.js_on) else stringResource(R.string.js_off),
            color = labelColor,
            style = MaterialTheme.typography.labelLarge,
        )
    }
}

/** Draw a 1dp outline border matching the OutlinedButton look. */
private fun Modifier.androidxOutline(color: Color, enabled: Boolean): Modifier =
    this.then(
        androidx.compose.foundation.border(
            width = 1.dp,
            color = if (enabled) color else color.copy(alpha = 0.4f),
            shape = androidx.compose.foundation.shape.RoundedCornerShape(50),
        ),
    )

/**
 * The confirmation interstitial (design §2.3) — the injection neutralizer.
 * An inbound Intent can put a URL on this screen; only the Open button
 * loads it. Host is emphasized so a look-alike domain is legible.
 */
@Composable
private fun IntakeInterstitial(
    intake: PendingIntake,
    onOpen: (String) -> Unit,
    onCopy: (String) -> Unit,
    onCancel: () -> Unit,
) {
    // Normalize the delivered URL for display + load. A raw share with no
    // URL falls to the empty state (paste-manually).
    val normalized = intake.url?.let {
        (normalizeUrl(it) as? NormalizeResult.Url)?.url
    }
    SuiteScaffold(
        title = stringResource(R.string.app_name),
        onBack = onCancel,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                stringResource(R.string.intake_heading),
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                stringResource(R.string.intake_sub),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (normalized == null) {
                Text(
                    stringResource(R.string.intake_no_link),
                    style = MaterialTheme.typography.bodyMedium,
                    color = UnderstoryTheme.semantic.warning,
                )
            } else {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    SelectionContainer {
                        Text(
                            text = emphasizedUrl(normalized),
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(UnderstoryTheme.spacing.md),
                        )
                    }
                }
            }

            Text(
                intake.sourceLabel?.let { stringResource(R.string.intake_source_from, it) }
                    ?: stringResource(R.string.intake_source_unknown),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

            if (normalized != null) {
                Button(
                    onClick = { onOpen(normalized) },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                ) { Text(stringResource(R.string.action_open_in_safe_view)) }
                OutlinedButton(
                    onClick = { onCopy(normalized) },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                ) { Text(stringResource(R.string.action_copy_link)) }
            }
            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) { Text(stringResource(R.string.action_cancel)) }
        }
    }
}

/** Bold the registrable host; dim scheme + path/query so look-alikes read. */
@Composable
private fun emphasizedUrl(url: String): androidx.compose.ui.text.AnnotatedString {
    // Read theme colors in composable scope BEFORE entering the plain
    // (non-composable) buildAnnotatedString builder.
    val dim = MaterialTheme.colorScheme.onSurfaceVariant
    val strong = MaterialTheme.colorScheme.onSurface
    return buildAnnotatedString {
        val schemeSep = url.indexOf("://")
        if (schemeSep < 0) {
            withStyle(SpanStyle(color = strong)) { append(url) }
            return@buildAnnotatedString
        }
        val scheme = url.substring(0, schemeSep + 3)
        val rest = url.substring(schemeSep + 3)
        val hostEnd = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
        val host = if (hostEnd < 0) rest else rest.substring(0, hostEnd)
        val tail = if (hostEnd < 0) "" else rest.substring(hostEnd)
        withStyle(SpanStyle(color = dim)) { append(scheme) }
        withStyle(SpanStyle(color = strong, fontWeight = FontWeight.Bold)) { append(host) }
        if (tail.isNotEmpty()) withStyle(SpanStyle(color = dim)) { append(tail) }
    }
}

/** First-run opt-in for the VIEW filter (design §2.2 ship decision). */
@Composable
private fun FirstRunOptIn(onEnable: () -> Unit, onNotNow: () -> Unit) {
    SuiteScaffold(
        title = stringResource(R.string.app_name),
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                stringResource(R.string.optin_title),
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            Text(
                stringResource(R.string.optin_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
            Button(
                onClick = onEnable,
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) { Text(stringResource(R.string.action_optin_enable)) }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            OutlinedButton(
                onClick = onNotNow,
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) { Text(stringResource(R.string.action_optin_not_now)) }
        }
    }
}

/** Custom dark error panel (design §3.5) — overlays the failed WebView. */
@Composable
private fun ErrorPanel(
    error: MainFrameError,
    onRetry: () -> Unit,
    onOpenInDefault: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.xl),
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                stringResource(error.titleRes, *error.titleArgs),
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            SelectionContainer {
                Text(
                    error.url,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
            Button(
                onClick = onRetry,
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) { Text(stringResource(R.string.action_retry)) }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            OutlinedButton(
                onClick = onOpenInDefault,
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) { Text(stringResource(R.string.cd_open_in_default)) }
        }
    }
}

@Composable
private fun BookmarksScreen(
    bookmarks: List<Bookmark>,
    onBack: () -> Unit,
    onPick: (String) -> Unit,
    onRemove: (String) -> Unit,
) {
    SuiteScaffold(
        title = stringResource(R.string.bookmarks_title),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(modifier = Modifier.fillMaxSize().padding(pad).padding(UnderstoryTheme.spacing.lg)) {
            Text(
                stringResource(R.string.bookmarks_sub, bookmarks.size),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            if (bookmarks.isEmpty()) {
                EmptyState(
                    title = stringResource(R.string.bookmarks_empty_title),
                    body = stringResource(R.string.bookmarks_empty_body),
                )
            } else {
                androidx.compose.foundation.lazy.LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                    modifier = Modifier.fillMaxWidth().weight(1f),
                ) {
                    items(items = bookmarks, key = { it.url }) { bookmark ->
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
            .background(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.shapes.small)
            .padding(start = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .clickable { onTap() }
                .padding(vertical = 10.dp),
        ) {
            Text(
                bookmark.title,
                color = MaterialTheme.colorScheme.onSurface,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                bookmark.url,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        IconButton(
            onClick = onRemove,
            modifier = Modifier.size(48.dp),
        ) {
            Icon(
                imageVector = Icons.Filled.Clear,
                contentDescription = stringResource(R.string.cd_remove_bookmark, bookmark.title),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** JS-allowlist management overlay (design §4). */
@Composable
private fun JsAllowlistScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var hosts by remember { mutableStateOf(BrowserSettings.getJsHosts(ctx)) }
    SuiteScaffold(
        title = stringResource(R.string.js_allowlist_title),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(modifier = Modifier.fillMaxSize().padding(pad).padding(UnderstoryTheme.spacing.lg)) {
            if (hosts.isEmpty()) {
                EmptyState(
                    title = stringResource(R.string.js_allowlist_empty_title),
                    body = stringResource(R.string.js_allowlist_empty_body),
                )
            } else {
                androidx.compose.foundation.lazy.LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                    modifier = Modifier.fillMaxWidth().weight(1f),
                ) {
                    items(items = hosts, key = { it }) { host ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.shapes.small)
                                .padding(start = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                host,
                                color = MaterialTheme.colorScheme.onSurface,
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.weight(1f).padding(vertical = 10.dp),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            IconButton(
                                onClick = {
                                    BrowserSettings.removeJsHost(ctx, host)
                                    hosts = BrowserSettings.getJsHosts(ctx)
                                    Diagnostics.log("browser.JsAllowlist", "removed a host")
                                },
                                modifier = Modifier.size(48.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Clear,
                                    contentDescription = stringResource(R.string.cd_js_remove, host),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Load-path helpers
// ---------------------------------------------------------------------------

/**
 * Host key for the per-site JS allowlist — lowercase host, or null when
 * the string doesn't parse to one. Allowlist lookups treat null as "not
 * allowed", so unparseable input fails closed.
 */
private fun hostOf(url: String?): String? =
    url?.let { runCatching { Uri.parse(it).host?.lowercase() }.getOrNull() }

/** True on the eng flavor (applicationId ends `.eng`) — gates the proxy surface. */
private fun isEngBuild(ctx: Context): Boolean = ctx.packageName.endsWith(".eng")

/** First http(s) URL inside a free-form shared string, or null. */
private fun firstUrlIn(text: String): String? {
    val m = android.util.Patterns.WEB_URL.matcher(text)
    while (m.find()) {
        val candidate = m.group()
        // WEB_URL matches bare "example.com" too; keep only http(s) or a
        // dotted host we can upgrade. The interstitial re-normalizes.
        if (candidate.startsWith("http://", true) ||
            candidate.startsWith("https://", true) ||
            candidate.contains('.')
        ) return candidate
    }
    return null
}

/**
 * Resolve a user-typed string to a load action. Bare hosts get https://
 * prepended; http:// is force-upgraded to https:// (the intent everywhere
 * else, and the transport layer hard-blocks residual cleartext). Non-URL
 * input (a space, or no dot and not localhost/http) returns [NotAUrl] so
 * the caller shows the "not a web address" chip instead of loading garbage.
 */
private fun normalizeUrl(raw: String): NormalizeResult {
    val t = raw.trim()
    if (t.isEmpty()) return NormalizeResult.Empty
    val looksLikeUrl = !t.contains(' ') &&
        (t.contains('.') || t.startsWith("localhost", ignoreCase = true) ||
            t.startsWith("http", ignoreCase = true))
    if (!looksLikeUrl) return NormalizeResult.NotAUrl(t)
    val lower = t.lowercase()
    val stripped = when {
        lower.startsWith("https://") -> t.substring("https://".length)
        lower.startsWith("http://") -> t.substring("http://".length)
        else -> t
    }
    if (stripped.isBlank()) return NormalizeResult.NotAUrl(t)
    return NormalizeResult.Url("https://$stripped")
}

/**
 * Open a trusted URL in the user's default browser — the complement exit
 * (inspect here → trust it → continue in Chrome). Claims no role of our
 * own; a chooser lets the user land in whichever real browser they prefer.
 */
private fun openInDefault(
    ctx: Context,
    url: String,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    Diagnostics.log("browser.handoff", "open-in-default: tap")
    val i = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        .addCategory(Intent.CATEGORY_BROWSABLE)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching {
        ctx.startActivity(Intent.createChooser(i, ctx.getString(R.string.chooser_open_in_browser)))
    }.onFailure {
        showSnack(ctx.getString(R.string.msg_no_browser), null, null)
    }
}

/**
 * Feedback + opt-out hand-off for a non-https scheme the WebView refused
 * (design §3.9). mailto:/tel:/sms: hand off to the user's real apps when
 * the hand-off pref is on; everything else refuses with a snackbar.
 */
private fun handleBlockedScheme(
    ctx: Context,
    uri: Uri,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    val scheme = uri.scheme?.lowercase() ?: return
    val handoffScheme = scheme == "mailto" || scheme == "tel" || scheme == "sms"
    if (handoffScheme && BrowserSettings.getExternalHandoffEnabled(ctx)) {
        Diagnostics.log("browser.scheme", "handoff scheme (opt-out available)")
        val i = Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { ctx.startActivity(i) }
            .onFailure { showSnack(ctx.getString(R.string.msg_no_handler), null, null) }
    } else {
        Diagnostics.log("browser.scheme", "refused scheme with feedback")
        showSnack(ctx.getString(R.string.msg_blocked_scheme, scheme), null, null)
    }
}

@SuppressLint("SetJavaScriptEnabled")
private fun buildHardenedWebView(ctx: android.content.Context): WebView {
    val wv = WebView(ctx)
    val s: WebSettings = wv.settings
    s.javaScriptEnabled = false
    s.allowFileAccess = false
    s.allowContentAccess = false
    @Suppress("DEPRECATION")
    s.allowFileAccessFromFileURLs = false
    @Suppress("DEPRECATION")
    s.allowUniversalAccessFromFileURLs = false
    s.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    @Suppress("DEPRECATION")
    s.saveFormData = false
    s.savePassword = false
    s.setGeolocationEnabled(false)
    s.mediaPlaybackRequiresUserGesture = true
    s.javaScriptCanOpenWindowsAutomatically = false
    s.setSupportMultipleWindows(false)
    s.cacheMode = WebSettings.LOAD_NO_CACHE
    s.databaseEnabled = false
    s.domStorageEnabled = false

    runCatching {
        val cm = CookieManager.getInstance()
        cm.setAcceptCookie(BrowserSettings.getFirstPartyCookies(ctx))
        cm.setAcceptThirdPartyCookies(wv, false)
    }

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
    val jsAllowed: (String?) -> Boolean,
    val onJsApplied: (Boolean) -> Unit,
    val onUrlCommitted: (String?) -> Unit,
    val onPageStartedForUrl: (String?) -> Unit,
    val onMainFrameError: (MainFrameError) -> Unit,
    val onBlockedScheme: (Uri) -> Unit,
) : WebViewClient() {

    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        val req = request ?: return true
        val uri = req.url ?: return true
        if (!uri.scheme.equals("https", ignoreCase = true)) {
            // Refuse non-https navigation — this is what makes file:// and
            // content:// (and intent:, javascript:, etc.) unreachable. The
            // hardening is unchanged; we only add feedback + an opt-out
            // hand-off for mailto/tel/sms instead of the old silent swallow.
            if (req.isForMainFrame) onBlockedScheme(uri)
            return true
        }
        if (req.isForMainFrame) {
            val allow = jsAllowed(uri.host?.lowercase())
            view?.settings?.javaScriptEnabled = allow
            onJsApplied(allow)
        }
        return false
    }

    override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
        onLoadStart(view)
        onNavState(view)
        onPageStartedForUrl(url)
    }

    override fun onPageFinished(view: WebView?, url: String?) {
        onLoadFinish(view)
        onNavState(view)
    }

    override fun onReceivedError(
        view: WebView?,
        request: WebResourceRequest?,
        error: WebResourceError?,
    ) {
        super.onReceivedError(view, request, error)
        if (request?.isForMainFrame != true) return
        val code = error?.errorCode ?: ERROR_UNKNOWN
        onMainFrameError(
            MainFrameError.fromWebResourceError(request.url?.toString() ?: "", code),
        )
    }

    override fun onReceivedHttpError(
        view: WebView?,
        request: WebResourceRequest?,
        errorResponse: WebResourceResponse?,
    ) {
        super.onReceivedHttpError(view, request, errorResponse)
        if (request?.isForMainFrame != true) return
        val status = errorResponse?.statusCode ?: 0
        onMainFrameError(
            MainFrameError.fromHttpStatus(request.url?.toString() ?: "", status),
        )
    }

    override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
        super.doUpdateVisitedHistory(view, url, isReload)
        onNavState(view)
        onUrlCommitted(url)
        val allow = jsAllowed(hostOf(url))
        if (view?.settings?.javaScriptEnabled != allow) {
            view?.settings?.javaScriptEnabled = allow
            onJsApplied(allow)
        }
    }

    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        // Hard reject — never proceed past an SSL error.
        handler?.cancel()
    }
}

private class HardenedWebChromeClient(
    val onTitle: (String?) -> Unit = {},
) : WebChromeClient() {

    override fun onReceivedTitle(view: WebView?, title: String?) {
        onTitle(title)
    }

    override fun onGeolocationPermissionsShowPrompt(
        origin: String?,
        callback: android.webkit.GeolocationPermissions.Callback?,
    ) {
        callback?.invoke(origin, false, false)
    }

    override fun onPermissionRequest(request: PermissionRequest?) {
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
        filePathCallback?.onReceiveValue(null)
        return false
    }

    override fun onCreateWindow(
        view: WebView?,
        isDialog: Boolean,
        isUserGesture: Boolean,
        resultMsg: android.os.Message?,
    ): Boolean {
        return false
    }
}
