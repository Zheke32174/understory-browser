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
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.BookmarkBorder
import androidx.compose.material.icons.filled.Bookmarks
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Cookie
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
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
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.view.WindowCompat
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.understory.browser.BuildConfig
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
 * P1 adds tabs (a single reused WebView driven by per-tab saved-state
 * bundles; see [TabManager] / [Tab]) and a per-app-default + per-tab
 * browsing mode ([BrowseMode]): the current locked-down defaults are the
 * HARDENED mode, and an opt-in STANDARD mode relaxes JS/cookies/downloads/
 * cache for ordinary browsing while keeping the invariant posture
 * (FLAG_SECURE, mixed-content block, cleartext block, SSL-hard-reject,
 * third-party-cookie block, Safe Browsing, wipe-on-exit). Links arriving
 * through the intake doorway are ALWAYS opened Hardened.
 *
 * Deferred to phase 2:
 *   - Cromite-fork integration (the SUITE_DESIGN target).
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
    var showHardening by rememberSaveable { mutableStateOf(false) }
    var showTabs by rememberSaveable { mutableStateOf(false) }
    var pendingLoad by remember { mutableStateOf<String?>(null) }

    // The open-tab set + active pointer. Held in a plain `remember`: the
    // Activity declares configChanges for orientation/screenSize/uiMode, so
    // it is not recreated on rotation and this survives config changes. A
    // single reused WebView (in BrowserRoot) is driven by the active tab's
    // saved state (see the switch effect there).
    val tabs = remember { TabManager(BrowserSettings.getDefaultMode(ctx)) }

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
                tabs = tabs,
                onWebViewReady = onWebViewReady,
                onOpenTabs = {
                    Diagnostics.log("browser.AppRoot", "show tab switcher")
                    showTabs = true
                },
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
                onOpenHardening = {
                    Diagnostics.log("browser.AppRoot", "show hardening overlay")
                    showHardening = true
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

            // Tab switcher — a full-bleed overlay list of open tabs. New-tab
            // opens a home tab; picking a tab selects it; closing the last
            // tab returns to home (TabManager guarantees a non-empty set).
            if (showTabs) {
                BackHandler { showTabs = false }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    TabSwitcherScreen(
                        tabs = tabs,
                        onBack = { showTabs = false },
                        onPick = { id ->
                            tabs.select(id)
                            showTabs = false
                        },
                        onNewTab = {
                            tabs.open()
                            showTabs = false
                        },
                        onClose = { id -> tabs.close(id) },
                    )
                }
            }

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
                            // Intake links ALWAYS open in a fresh HARDENED tab,
                            // independent of the per-app default mode: the
                            // doorway is the untrusted-input path (design §2.3).
                            Diagnostics.log("browser.AppRoot", "intake open confirmed (new hardened tab)")
                            tabs.open(url = normalizedUrl, mode = BrowseMode.HARDENED)
                            showTabs = false
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
            if (showHardening) {
                BackHandler { showHardening = false }
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    HardeningScreen(
                        onBack = { showHardening = false },
                        showSnack = showSnack,
                    )
                }
            }
        }
    }
}

@Composable
private fun BrowserRoot(
    tabs: TabManager,
    onWebViewReady: (WebView) -> Unit,
    onOpenTabs: () -> Unit,
    onDiagnostics: () -> Unit,
    onOpenBookmarks: () -> Unit,
    onOpenJsAllowlist: () -> Unit,
    onOpenProxy: () -> Unit,
    onOpenHardening: () -> Unit,
    bookmarks: List<Bookmark>,
    onBookmarkToggle: (url: String, title: String?) -> Unit,
    pendingLoad: String?,
    onPendingLoadConsumed: () -> Unit,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
    proxyEnabled: Boolean,
) {
    val ctx = LocalContext.current

    // The active tab is the single source of truth for what the reused
    // WebView shows. url/title/mode are read from it; a committed load or
    // mode switch writes back to it. Referencing tabs.active in composition
    // subscribes to activeId changes (it is state-backed).
    val active = tabs.active
    val activeMode = active.mode

    var url by remember { mutableStateOf("") }
    // The "not a web address" chip under the URL bar (search-off honesty).
    var notAUrlHint by remember { mutableStateOf(false) }
    var jsEnabled by remember { mutableStateOf(false) }
    var cookiesFirstParty by remember { mutableStateOf(BrowserSettings.getFirstPartyCookies(ctx)) }
    var loading by remember { mutableStateOf(false) }
    var wvRef by remember { mutableStateOf<WebView?>(null) }
    var canGoBackState by remember { mutableStateOf(false) }
    var canGoForwardState by remember { mutableStateOf(false) }
    var findActive by remember { mutableStateOf(false) }
    var findQuery by remember { mutableStateOf("") }
    var findCurrent by remember { mutableStateOf(-1) }
    var findTotal by remember { mutableStateOf(-1) }
    // Progress 0..100 from onProgressChanged; drives the determinate bar and
    // the reload-vs-stop affordance. Reset to 0 when idle so the bar hides.
    var progress by remember { mutableStateOf(0) }
    var showModeSheet by remember { mutableStateOf(false) }
    // A pending Standard-mode download awaiting the user's explicit confirm.
    var pendingDownload by remember { mutableStateOf<PendingDownload?>(null) }
    // Main-frame error overlay. Non-null renders the custom dark panel over
    // the WebView; cleared on the next successful load of a new URL.
    var errorState by remember { mutableStateOf<MainFrameError?>(null) }

    // loadedUrl is the active tab's committed page (null = home). Reading it
    // through the tab keeps every derived affordance (home vs page, star,
    // share target) correct after a tab switch.
    val loadedUrl = active.url

    val bookmarkedKeys = remember(bookmarks) { bookmarks.mapTo(HashSet(bookmarks.size)) { it.url } }

    // The shared load path — used by the URL bar, retry, and reload. Resolves
    // NotAUrl to the chip and a real URL to a load in the CURRENT tab.
    val loadFromInput: (String) -> Unit = { raw ->
        when (val r = normalizeUrl(raw)) {
            is NormalizeResult.Empty -> { /* nothing to do */ }
            is NormalizeResult.NotAUrl -> {
                notAUrlHint = true
            }
            is NormalizeResult.Url -> {
                notAUrlHint = false
                errorState = null
                jsEnabled = active.mode == BrowseMode.STANDARD ||
                    BrowserSettings.isJsAllowed(ctx, hostOf(r.url))
                active.url = r.url
                url = r.url
                // A fresh URL supersedes any stale restore bundle for this tab.
                active.savedState = null
                wvRef?.let { wv ->
                    applyMode(ctx, wv, active.mode, hostOf(r.url))
                    wv.loadUrl(r.url)
                }
            }
        }
    }

    // pendingLoad is a one-shot URL pushed in from BrowserAppRoot (the
    // Bookmarks overlay — already normalized). It loads into the active tab.
    LaunchedEffect(pendingLoad) {
        val target = pendingLoad ?: return@LaunchedEffect
        notAUrlHint = false
        errorState = null
        jsEnabled = active.mode == BrowseMode.STANDARD ||
            BrowserSettings.isJsAllowed(ctx, hostOf(target))
        active.url = target
        active.savedState = null
        url = target
        wvRef?.let { wv ->
            applyMode(ctx, wv, active.mode, hostOf(target))
            wv.loadUrl(target)
        }
        onPendingLoadConsumed()
    }

    // ---- Tab-switch orchestration for the single reused WebView.
    // On every activeId change: capture the outgoing tab's live WebView
    // state into its bundle, then restore the incoming tab (its saved bundle
    // if any, else a fresh load of its url, else about:blank for a home tab).
    var lastActiveId by remember { mutableStateOf(tabs.activeId) }
    LaunchedEffect(tabs.activeId) {
        val wv = wvRef
        val newId = tabs.activeId
        if (wv != null && newId != lastActiveId) {
            tabs.tabs.firstOrNull { it.id == lastActiveId }?.let { outgoing ->
                val b = Bundle()
                runCatching { wv.saveState(b) }
                outgoing.savedState = b
            }
            val incoming = tabs.tabs.firstOrNull { it.id == newId }
            // Reset transient UI to the incoming tab's baseline.
            errorState = null; notAUrlHint = false; findActive = false
            loading = false; progress = 0
            if (incoming != null) {
                url = incoming.url ?: ""
                // Re-assert the incoming tab's mode policy (cache/DOM/cookies/JS)
                // on the shared WebView BEFORE restore/load, so a switch from a
                // Standard tab to a Hardened tab doesn't leak the relaxed
                // settings into the hardened page.
                applyMode(ctx, wv, incoming.mode, hostOf(incoming.url))
                when {
                    incoming.savedState != null ->
                        runCatching { wv.restoreState(incoming.savedState!!) }
                    incoming.url != null -> wv.loadUrl(incoming.url!!)
                    else -> wv.loadUrl("about:blank")
                }
                jsEnabled = incoming.mode == BrowseMode.STANDARD ||
                    BrowserSettings.isJsAllowed(ctx, hostOf(incoming.url))
                canGoBackState = wv.canGoBack()
                canGoForwardState = wv.canGoForward()
            }
        }
        lastActiveId = newId
    }

    // Omnibox edit mode: while true the field is an editable TextField focused
    // for typing; while false it's a compact display of the current host with a
    // lock glyph. Tap-to-edit flips it on; a committed load or Cancel flips off.
    var editingUrl by remember { mutableStateOf(false) }
    var showMenu by remember { mutableStateOf(false) }

    val focusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current

    val displayUrl = wvRef?.url?.takeIf { it != "about:blank" } ?: loadedUrl
    val starTarget = displayUrl
    val starOn = starTarget != null && starTarget in bookmarkedKeys

    // Apply a mode switch to the active tab live: persist nothing (the per-app
    // DEFAULT is set separately from the mode sheet), update the tab + WebView,
    // and reload so the new policy governs the current page.
    val switchMode: (BrowseMode) -> Unit = { newMode ->
        if (newMode != active.mode) {
            Diagnostics.log("browser.Root", "mode switch: ${active.mode} -> $newMode")
            active.mode = newMode
            wvRef?.let { wv ->
                val allow = applyMode(ctx, wv, newMode, hostOf(wvRef?.url ?: loadedUrl))
                jsEnabled = allow
                if (loadedUrl != null) wv.reload()
            }
        }
    }

    // Commit the omnibox: normalize + load, drop focus, leave edit mode. Empty
    // input just closes the editor without touching the loaded page.
    val commitOmnibox: () -> Unit = {
        val entered = url.trim()
        editingUrl = false
        focusManager.clearFocus()
        if (entered.isNotEmpty()) {
            Diagnostics.log("browser.Root", "omnibox go (len=${entered.length})")
            loadFromInput(entered)
        }
    }

    // Real wipe (mirrors onDestroy without killing the Activity): cookies +
    // storage globally, plus the visible page + its DOM/JS context. Also
    // discards every tab's saved bundle so no wiped page can be restored by a
    // later tab switch, and resets the tab set to a single fresh home tab.
    val clearNow: () -> Unit = {
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
        tabs.tabs.forEach { it.savedState = null }
        // Reset to a single fresh home tab (keeps the ephemeral guarantee: no
        // other tab's page survives a Clear).
        tabs.resetToSingleHome()
        lastActiveId = tabs.activeId
        url = ""; jsEnabled = false
        canGoBackState = false; canGoForwardState = false
        notAUrlHint = false; errorState = null; progress = 0; editingUrl = false
        showSnack(ctx.getString(R.string.msg_cleared), null, null)
    }

    val toggleBookmark: () -> Unit = {
        if (starTarget != null) {
            Diagnostics.log("browser.Root", "Bookmark toggle: was=${if (starOn) "ON" else "OFF"}")
            onBookmarkToggle(starTarget, active.title)
            showSnack(
                ctx.getString(if (starOn) R.string.msg_bookmark_removed else R.string.msg_bookmarked),
                null, null,
            )
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {

        // ---- Top browser toolbar: back/close · omnibox · reload/stop · overflow
        Surface(
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 2.dp,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = UnderstoryTheme.spacing.xs, vertical = UnderstoryTheme.spacing.xs),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
            ) {
                // Back if the page has history; otherwise a close/home affordance
                // that clears the viewer back to the start surface.
                val canBack = canGoBackState && loadedUrl != null
                NavIconButton(
                    icon = if (canBack) Icons.AutoMirrored.Filled.ArrowBack else Icons.Filled.Close,
                    contentDescription = if (canBack) stringResource(R.string.cd_nav_back)
                    else stringResource(R.string.cd_close),
                    enabled = true,
                    onClick = {
                        if (canBack) {
                            Diagnostics.log("browser.Root", "Toolbar back: tap")
                            wvRef?.goBack()
                        } else if (loadedUrl != null) {
                            clearNow()
                        }
                    },
                )

                Omnibox(
                    text = url,
                    displayUrl = displayUrl,
                    editing = editingUrl,
                    focusRequester = focusRequester,
                    onTextChange = { url = it; if (notAUrlHint) notAUrlHint = false },
                    onBeginEdit = {
                        editingUrl = true
                        // Seed the field with the current URL so the user edits
                        // rather than retypes; select-all is the platform default.
                        url = displayUrl ?: ""
                    },
                    onGo = commitOmnibox,
                    onClear = {
                        url = ""
                        notAUrlHint = false
                    },
                    modifier = Modifier.weight(1f),
                )

                // Reload becomes Stop while loading. Disabled with no page.
                NavIconButton(
                    icon = if (loading) Icons.Filled.Stop else Icons.Filled.Refresh,
                    contentDescription = if (loading) stringResource(R.string.cd_stop)
                    else stringResource(R.string.cd_reload),
                    enabled = loadedUrl != null,
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

                // Mode indicator — reads the active tab's mode at a glance and
                // opens the mode chooser. Shield (dim accent) = Hardened,
                // Public (warning tint) = Standard, so the relaxed mode is the
                // one that visibly stands out.
                ModeIndicatorButton(
                    mode = activeMode,
                    onClick = { showModeSheet = true },
                )

                // Tab-count button — opens the tab switcher; the badge shows
                // the number of open tabs.
                TabCountButton(
                    count = tabs.count,
                    onClick = onOpenTabs,
                )

                // Overflow menu.
                Box {
                    NavIconButton(
                        icon = Icons.Filled.MoreVert,
                        contentDescription = stringResource(R.string.cd_overflow),
                        enabled = true,
                        onClick = { showMenu = true },
                    )
                    OverflowMenu(
                        expanded = showMenu,
                        onDismiss = { showMenu = false },
                        hasPage = loadedUrl != null,
                        jsEnabled = jsEnabled,
                        cookiesFirstParty = cookiesFirstParty,
                        bookmarkCount = bookmarks.size,
                        engBuild = proxyEnabled,
                        onShare = {
                            val target = wvRef?.url ?: loadedUrl
                            if (target != null) shareLink(ctx, target, showSnack)
                        },
                        onOpenInDefault = {
                            val target = wvRef?.url ?: loadedUrl
                            if (target != null) openInDefault(ctx, target, showSnack)
                        },
                        onFind = {
                            findActive = true
                        },
                        onClearNow = clearNow,
                        modeStandard = activeMode == BrowseMode.STANDARD,
                        onToggleJs = {
                            // The per-site JS allowlist governs HARDENED mode only.
                            // In STANDARD, JS is on for every site by definition,
                            // so the row is disabled (see OverflowMenu) and this
                            // never fires. Guard anyway.
                            if (activeMode == BrowseMode.HARDENED) {
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
                            }
                        },
                        onToggleCookies = {
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
                        onManageJs = onOpenJsAllowlist,
                        onBookmarks = onOpenBookmarks,
                        onDiagnostics = onDiagnostics,
                        onProxy = onOpenProxy,
                        onHardening = onOpenHardening,
                    )
                }
            }
        }

        // Search-off honesty chip: shown under the toolbar when the typed text
        // isn't a web address (this is a viewer, not a search engine).
        if (notAUrlHint) {
            Text(
                stringResource(R.string.msg_not_a_web_address),
                color = UnderstoryTheme.semantic.warning,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(
                    horizontal = UnderstoryTheme.spacing.md,
                    vertical = UnderstoryTheme.spacing.xs,
                ),
            )
        }

        // ---- Thin determinate progress bar under the toolbar; hidden when idle.
        val animatedProgress by animateFloatAsState(
            targetValue = (progress.coerceIn(0, 100)) / 100f,
            label = "loadProgress",
        )
        if (loading && progress in 1..99) {
            LinearProgressIndicator(
                progress = { animatedProgress },
                modifier = Modifier.fillMaxWidth().height(2.dp),
                color = MaterialTheme.colorScheme.primary,
                trackColor = Color.Transparent,
            )
        } else {
            // Reserve the 2dp so content doesn't jump when the bar appears.
            Spacer(Modifier.height(2.dp))
        }

        // ---- Find-in-page bar (opens above the content when active).
        if (findActive) {
            FindInPageBar(
                query = findQuery,
                current = findCurrent,
                total = findTotal,
                onQueryChange = { newValue ->
                    findQuery = newValue
                    if (newValue.isEmpty()) {
                        findCurrent = -1; findTotal = -1
                        wvRef?.clearMatches()
                    } else {
                        wvRef?.findAllAsync(newValue)
                    }
                },
                onPrev = {
                    Diagnostics.log("browser.Root", "Find prev: tap")
                    wvRef?.findNext(false)
                },
                onNext = {
                    Diagnostics.log("browser.Root", "Find next: tap")
                    wvRef?.findNext(true)
                },
                onClose = {
                    findActive = false
                    findQuery = ""; findCurrent = -1; findTotal = -1
                    wvRef?.clearMatches()
                },
            )
        }

        // ---- Content area. The single reused WebView is ALWAYS present (so a
        // tab switch can save/restore its state even when a tab sits on home);
        // BrowserHome is overlaid on top of it whenever the active tab has no
        // committed page. The download listener + error panel layer over it.
        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { factoryCtx ->
                    buildHardenedWebView(factoryCtx, active.mode).also { wv ->
                        wv.setBackgroundColor(android.graphics.Color.TRANSPARENT)
                        wv.webViewClient = HardenedWebViewClient(
                            ctx = ctx,
                            onLoadStart = { loading = true; progress = 0 },
                            onLoadFinish = { loading = false; progress = 0 },
                            onNavState = { v ->
                                canGoBackState = v?.canGoBack() ?: false
                                canGoForwardState = v?.canGoForward() ?: false
                            },
                            currentMode = { tabs.active.mode },
                            onJsApplied = { allowed -> jsEnabled = allowed },
                            onUrlCommitted = { committed ->
                                // about:blank is the home placeholder — never a
                                // committed page; don't let it overwrite tab.url.
                                if (committed != null && committed != "about:blank") {
                                    if (committed != tabs.active.url) tabs.active.url = committed
                                    if (!editingUrl) url = committed
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
                            onTitle = { t -> tabs.active.title = t },
                            onProgress = { p -> progress = p },
                        )
                        wv.setDownloadListener { downloadUrl, _, contentDisposition, mimeType, _ ->
                            handleDownload(
                                ctx = ctx,
                                mode = tabs.active.mode,
                                url = downloadUrl,
                                userAgent = wv.settings.userAgentString,
                                contentDisposition = contentDisposition,
                                mimeType = mimeType,
                                showSnack = showSnack,
                                onPrompt = { pendingDownload = it },
                            )
                        }
                        wv.setFindListener { active, total, isDoneCounting ->
                            if (isDoneCounting || total > 0) {
                                findCurrent = active
                                findTotal = total
                            }
                        }
                        wvRef = wv
                        // If a tab already carries a url at first composition
                        // (e.g. an intake tab opened before the WebView existed),
                        // load it now.
                        active.url?.let { u ->
                            applyMode(ctx, wv, active.mode, hostOf(u))
                            wv.loadUrl(u)
                        }
                        onWebViewReady(wv)
                    }
                },
                update = { wv ->
                    // Keep the live JS setting in sync with the reflected state.
                    // Loads are driven explicitly (loadFromInput / pendingLoad /
                    // tab-switch effect), never from update, to avoid re-load races.
                    wv.settings.javaScriptEnabled = jsEnabled
                },
            )

            // Home surface — overlaid opaquely over the (blank) WebView while
            // the active tab has no committed page.
            if (loadedUrl == null) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    BrowserHome(
                        mode = activeMode,
                        onPickBookmark = { picked -> loadFromInput(picked) },
                        onOpenBar = {
                            editingUrl = true
                            url = ""
                        },
                        onChangeMode = { showModeSheet = true },
                        bookmarks = bookmarks,
                    )
                }
            }

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

        // ---- Slim bottom browser bar: back / forward / reload / bookmark.
        // Present once a page is loaded so the app reads as a browser even
        // one-handed. (Tabs live in the top toolbar's tab-count button.)
        if (loadedUrl != null) {
            Surface(
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 2.dp,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.sm),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    NavIconButton(
                        icon = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.cd_nav_back),
                        enabled = canGoBackState,
                        onClick = { wvRef?.goBack() },
                    )
                    NavIconButton(
                        icon = Icons.AutoMirrored.Filled.ArrowForward,
                        contentDescription = stringResource(R.string.cd_nav_forward),
                        enabled = canGoForwardState,
                        onClick = { wvRef?.goForward() },
                    )
                    NavIconButton(
                        icon = if (loading) Icons.Filled.Stop else Icons.Filled.Refresh,
                        contentDescription = if (loading) stringResource(R.string.cd_stop)
                        else stringResource(R.string.cd_reload),
                        enabled = true,
                        onClick = { if (loading) wvRef?.stopLoading() else wvRef?.reload() },
                    )
                    NavIconButton(
                        icon = if (starOn) Icons.Filled.Bookmark else Icons.Filled.BookmarkBorder,
                        contentDescription = if (starOn) stringResource(R.string.cd_bookmark_on)
                        else stringResource(R.string.cd_bookmark_off),
                        enabled = starTarget != null,
                        tint = if (starOn) MaterialTheme.colorScheme.primary else null,
                        onClick = toggleBookmark,
                    )
                }
            }
        }

        // Dev/debug suite status strip: eng builds only. The prod ("shipping")
        // face never carries it — it's a wiring smoke test, not a user surface.
        if (proxyEnabled) {
            SuiteStatusFooter(modifier = Modifier.padding(UnderstoryTheme.spacing.sm))
        }
    }

    // ---- Mode chooser (dialog overlay). Honest about what each mode does;
    // lets the user also set the per-app default for future user-opened tabs.
    if (showModeSheet) {
        ModeChooserDialog(
            current = activeMode,
            isDefault = BrowserSettings.getDefaultMode(ctx) == activeMode,
            onPick = { mode ->
                switchMode(mode)
                showModeSheet = false
            },
            onSetDefault = { mode ->
                BrowserSettings.setDefaultMode(ctx, mode)
                tabs.newTabMode = mode
                Diagnostics.log("browser.Root", "default mode set: $mode")
            },
            onDismiss = { showModeSheet = false },
        )
    }

    // ---- Standard-mode download confirm. Hardened never reaches this: its
    // download listener hands off to the default browser with a snackbar.
    pendingDownload?.let { dl ->
        DownloadConfirmDialog(
            download = dl,
            onConfirm = {
                startSystemDownload(ctx, dl, showSnack)
                pendingDownload = null
            },
            onDismiss = { pendingDownload = null },
        )
    }
}

/**
 * The address bar. Two faces sharing one row height so the toolbar never
 * reflows: a compact display chip (lock glyph + host, tap to edit) when idle,
 * and a focused single-line editor when [editing]. Honest hint: this is a
 * viewer, not a search box, so the placeholder is "Enter a URL".
 */
@Composable
private fun Omnibox(
    text: String,
    displayUrl: String?,
    editing: Boolean,
    focusRequester: FocusRequester,
    onTextChange: (String) -> Unit,
    onBeginEdit: () -> Unit,
    onGo: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ctx = LocalContext.current
    val shape = RoundedCornerShape(50)
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurface,
        shape = shape,
        modifier = modifier.heightIn(min = 44.dp),
    ) {
        if (editing) {
            TextField(
                value = text,
                onValueChange = onTextChange,
                singleLine = true,
                placeholder = {
                    Text(
                        stringResource(R.string.hint_url),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                    )
                },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.Public,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                },
                trailingIcon = if (text.isNotEmpty()) {
                    @Composable {
                        IconButton(onClick = onClear) {
                            Icon(
                                imageVector = Icons.Filled.Clear,
                                contentDescription = stringResource(R.string.cd_clear_url),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                } else null,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Go,
                ),
                keyboardActions = KeyboardActions(onGo = { onGo() }, onDone = { onGo() }),
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = Color.Transparent,
                    disabledContainerColor = Color.Transparent,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent,
                    disabledIndicatorColor = Color.Transparent,
                ),
                modifier = Modifier.fillMaxWidth().focusRequester(focusRequester),
            )
            LaunchedEffect(Unit) { runCatching { focusRequester.requestFocus() } }
        } else {
            val isHttps = displayUrl?.startsWith("https://", ignoreCase = true) == true
            val host = hostOf(displayUrl) ?: displayUrl
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onBeginEdit() }
                    .semantics { contentDescription = ctx.getString(R.string.cd_edit_url) }
                    .padding(horizontal = UnderstoryTheme.spacing.md),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
            ) {
                if (displayUrl == null) {
                    Icon(
                        imageVector = Icons.Filled.Search,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        stringResource(R.string.omnibox_empty),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                } else {
                    Icon(
                        imageVector = if (isHttps) Icons.Filled.Lock else Icons.Filled.Public,
                        contentDescription = if (isHttps) stringResource(R.string.cd_secure_https) else null,
                        tint = if (isHttps) UnderstoryTheme.semantic.success
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        host ?: "",
                        color = MaterialTheme.colorScheme.onSurface,
                        style = MaterialTheme.typography.bodyLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

/** The toolbar overflow menu (Share / Open in default / Find / Clear / JS / cookies / …). */
@Composable
private fun OverflowMenu(
    expanded: Boolean,
    onDismiss: () -> Unit,
    hasPage: Boolean,
    jsEnabled: Boolean,
    cookiesFirstParty: Boolean,
    bookmarkCount: Int,
    engBuild: Boolean,
    onShare: () -> Unit,
    onOpenInDefault: () -> Unit,
    onFind: () -> Unit,
    onClearNow: () -> Unit,
    modeStandard: Boolean,
    onToggleJs: () -> Unit,
    onToggleCookies: () -> Unit,
    onManageJs: () -> Unit,
    onBookmarks: () -> Unit,
    onDiagnostics: () -> Unit,
    onProxy: () -> Unit,
    onHardening: () -> Unit,
) {
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        MenuRow(Icons.Filled.Share, stringResource(R.string.menu_share), enabled = hasPage) {
            onDismiss(); onShare()
        }
        MenuRow(Icons.Filled.OpenInNew, stringResource(R.string.menu_open_in_default), enabled = hasPage) {
            onDismiss(); onOpenInDefault()
        }
        MenuRow(Icons.Filled.Search, stringResource(R.string.menu_find), enabled = hasPage) {
            onDismiss(); onFind()
        }
        HorizontalDivider()
        // The per-site JS allowlist governs HARDENED mode. In STANDARD mode JS
        // is on for every site by definition, so the row reports that and is
        // disabled (it isn't a per-site choice there).
        MenuRow(
            Icons.Filled.Code,
            when {
                modeStandard -> stringResource(R.string.menu_js_standard)
                jsEnabled -> stringResource(R.string.menu_js_on)
                else -> stringResource(R.string.menu_js_off)
            },
            enabled = hasPage && !modeStandard,
        ) { onDismiss(); onToggleJs() }
        MenuRow(
            Icons.Filled.Cookie,
            if (cookiesFirstParty) stringResource(R.string.menu_cookies_on) else stringResource(R.string.menu_cookies_off),
            enabled = true,
        ) { onDismiss(); onToggleCookies() }
        MenuRow(Icons.Filled.Tune, stringResource(R.string.menu_manage_js), enabled = true) {
            onDismiss(); onManageJs()
        }
        // Hardening — the elevated (Shizuku-gated) browser-hygiene surface. Always
        // listed (not eng-gated): the screen itself fails closed to the grant
        // invite when Shizuku isn't granted, so the entry is never a dead end.
        MenuRow(Icons.Filled.Shield, stringResource(R.string.menu_hardening), enabled = true) {
            onDismiss(); onHardening()
        }
        HorizontalDivider()
        MenuRow(Icons.Filled.Bookmarks, stringResource(R.string.menu_bookmarks, bookmarkCount), enabled = true) {
            onDismiss(); onBookmarks()
        }
        MenuRow(Icons.Filled.DeleteSweep, stringResource(R.string.menu_clear), enabled = true) {
            onDismiss(); onClearNow()
        }
        // Developer-only entries: eng flavor only. The prod build shows NEITHER
        // the Diagnostics screen entry nor the network-proxy overlay entry.
        if (engBuild) {
            HorizontalDivider()
            MenuRow(Icons.Filled.Shield, stringResource(R.string.menu_proxy), enabled = true) {
                onDismiss(); onProxy()
            }
            MenuRow(Icons.Filled.VisibilityOff, stringResource(R.string.menu_diagnostics), enabled = true) {
                onDismiss(); onDiagnostics()
            }
        }
    }
}

@Composable
private fun MenuRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    DropdownMenuItem(
        text = { Text(label) },
        leadingIcon = {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (enabled) MaterialTheme.colorScheme.onSurface
                else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
            )
        },
        enabled = enabled,
        onClick = onClick,
    )
}

/** The find-in-page bar (matches count + prev/next + close). */
@Composable
private fun FindInPageBar(
    query: String,
    current: Int,
    total: Int,
    onQueryChange: (String) -> Unit,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onClose: () -> Unit,
) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 1.dp,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.sm, vertical = UnderstoryTheme.spacing.xs),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextField(
                value = query,
                onValueChange = onQueryChange,
                placeholder = { Text(stringResource(R.string.hint_find), color = MaterialTheme.colorScheme.onSurfaceVariant) },
                singleLine = true,
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = Color.Transparent,
                    focusedIndicatorColor = MaterialTheme.colorScheme.primary,
                    unfocusedIndicatorColor = MaterialTheme.colorScheme.outline,
                ),
                modifier = Modifier.weight(1f),
            )
            Text(
                when {
                    total < 0 -> ""
                    total == 0 -> "0"
                    else -> "${current + 1} / $total"
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.xs),
            )
            NavIconButton(
                icon = Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = stringResource(R.string.cd_find_prev),
                enabled = total > 0,
                onClick = onPrev,
            )
            NavIconButton(
                icon = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = stringResource(R.string.cd_find_next),
                enabled = total > 0,
                onClick = onNext,
            )
            NavIconButton(
                icon = Icons.Filled.Close,
                contentDescription = stringResource(R.string.cd_find_toggle),
                enabled = true,
                onClick = onClose,
            )
        }
    }
}

/**
 * The start / home surface shown before any page loads. A branded header, a
 * short honest description of what this viewer is (and is NOT), the three
 * standing-policy cards (JS-off, ephemeral, capture-blocked), and — when the
 * user has bookmarks — a quick-launch list. Replaces the wall-of-text
 * placeholder so an empty viewer still reads as an intentional browser home.
 */
@Composable
private fun BrowserHome(
    mode: BrowseMode,
    bookmarks: List<Bookmark>,
    onPickBookmark: (String) -> Unit,
    onOpenBar: () -> Unit,
    onChangeMode: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(UnderstoryTheme.spacing.lg),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
        Icon(
            imageVector = Icons.Filled.Shield,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(48.dp),
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.md))
        Text(
            stringResource(R.string.home_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            stringResource(R.string.home_tagline),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        // The active tab's mode as a tappable chip — opens the mode chooser so
        // the choice (and what it means) is one tap from the home surface.
        Spacer(Modifier.height(UnderstoryTheme.spacing.md))
        ModeChip(mode = mode, onClick = onChangeMode)

        Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        Button(
            onClick = onOpenBar,
            modifier = Modifier.fillMaxWidth().height(48.dp),
        ) {
            Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            Text(stringResource(R.string.home_hint))
        }

        // The policy cards read the ACTIVE mode so the home surface never
        // over-claims: in Standard the copy honestly says JS is on and
        // first-party cookies/history persist within the app.
        Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        HomeInfoCard(
            icon = Icons.Filled.Code,
            title = if (mode == BrowseMode.HARDENED) stringResource(R.string.home_card_js_title)
            else stringResource(R.string.home_card_js_title_std),
            body = if (mode == BrowseMode.HARDENED) stringResource(R.string.home_card_js_body)
            else stringResource(R.string.home_card_js_body_std),
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        HomeInfoCard(
            icon = Icons.Filled.DeleteSweep,
            title = if (mode == BrowseMode.HARDENED) stringResource(R.string.home_card_ephemeral_title)
            else stringResource(R.string.home_card_session_title_std),
            body = if (mode == BrowseMode.HARDENED) stringResource(R.string.home_card_ephemeral_body)
            else stringResource(R.string.home_card_session_body_std),
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        HomeInfoCard(
            icon = Icons.Filled.VisibilityOff,
            title = stringResource(R.string.home_card_capture_title),
            body = stringResource(R.string.home_card_capture_body),
        )

        if (bookmarks.isNotEmpty()) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    Icons.Filled.Bookmarks,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                Text(
                    stringResource(R.string.home_bookmarks_header),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.medium,
                tonalElevation = 1.dp,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    // Cap the home quick-list; the full list lives in Bookmarks.
                    bookmarks.take(6).forEachIndexed { index, bookmark ->
                        if (index > 0) HorizontalDivider(
                            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f),
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onPickBookmark(bookmark.url) }
                                .padding(
                                    horizontal = UnderstoryTheme.spacing.lg,
                                    vertical = UnderstoryTheme.spacing.md,
                                ),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
                        ) {
                            Icon(
                                Icons.Filled.Public,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(20.dp),
                            )
                            Column(Modifier.weight(1f)) {
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
                                    style = MaterialTheme.typography.bodySmall,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }
}

@Composable
private fun HomeInfoCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    body: String,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(22.dp),
            )
            Column(Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
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
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                contentColor = MaterialTheme.colorScheme.onSurface,
                shape = MaterialTheme.shapes.large,
                tonalElevation = 2.dp,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(UnderstoryTheme.spacing.xl),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Shield,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(40.dp),
                    )
                    Text(
                        stringResource(R.string.intake_heading),
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Center,
                    )

                    if (normalized == null) {
                        Text(
                            stringResource(R.string.intake_no_link),
                            style = MaterialTheme.typography.bodyMedium,
                            color = UnderstoryTheme.semantic.warning,
                            textAlign = TextAlign.Center,
                        )
                    } else {
                        // The link, host emphasized, in an inset panel so a
                        // look-alike domain is legible before the user commits.
                        Surface(
                            color = MaterialTheme.colorScheme.background,
                            shape = MaterialTheme.shapes.medium,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            SelectionContainer {
                                Text(
                                    text = emphasizedUrl(normalized),
                                    fontFamily = FontFamily.Monospace,
                                    style = MaterialTheme.typography.bodyLarge,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(UnderstoryTheme.spacing.md),
                                )
                            }
                        }
                        // Standing-policy badge: JavaScript is off for this load.
                        JsOffBadge()
                    }

                    Text(
                        stringResource(R.string.intake_sub),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                    Text(
                        intake.sourceLabel?.let { stringResource(R.string.intake_source_from, it) }
                            ?: stringResource(R.string.intake_source_unknown),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )

                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

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
    }
}

/** A small "JavaScript off" pill — the interstitial's standing-policy badge. */
@Composable
private fun JsOffBadge() {
    Row(
        modifier = Modifier
            .background(
                UnderstoryTheme.semantic.successContainer,
                RoundedCornerShape(50),
            )
            .padding(horizontal = UnderstoryTheme.spacing.md, vertical = UnderstoryTheme.spacing.xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
    ) {
        Icon(
            imageVector = Icons.Filled.Code,
            contentDescription = null,
            tint = UnderstoryTheme.semantic.success,
            modifier = Modifier.size(16.dp),
        )
        Text(
            stringResource(R.string.intake_badge_js_off),
            style = MaterialTheme.typography.labelMedium,
            color = UnderstoryTheme.semantic.success,
        )
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
// Tabs + mode UI (P1)
// ---------------------------------------------------------------------------

/** The label ("Hardened" / "Standard") for a mode. */
@Composable
private fun modeLabel(mode: BrowseMode): String = when (mode) {
    BrowseMode.HARDENED -> stringResource(R.string.mode_hardened)
    BrowseMode.STANDARD -> stringResource(R.string.mode_standard)
}

/**
 * Toolbar mode indicator: Shield (dim, on-surface-variant) for Hardened,
 * Public (warning-tinted) for Standard, so the relaxed mode is the one that
 * visibly stands out. Tapping opens the mode chooser.
 */
@Composable
private fun ModeIndicatorButton(mode: BrowseMode, onClick: () -> Unit) {
    val hardened = mode == BrowseMode.HARDENED
    NavIconButton(
        icon = if (hardened) Icons.Filled.Shield else Icons.Filled.Public,
        contentDescription = stringResource(R.string.cd_mode_indicator, modeLabel(mode)),
        enabled = true,
        tint = if (hardened) MaterialTheme.colorScheme.onSurfaceVariant
        else UnderstoryTheme.semantic.warning,
        onClick = onClick,
    )
}

/**
 * A mode pill for the home surface: a tinted rounded chip that reads
 * "Hardened mode" / "Standard mode" and opens the chooser on tap. Hardened
 * uses the success container (safe), Standard the warning container (relaxed).
 */
@Composable
private fun ModeChip(mode: BrowseMode, onClick: () -> Unit) {
    val hardened = mode == BrowseMode.HARDENED
    val container = if (hardened) UnderstoryTheme.semantic.successContainer
    else UnderstoryTheme.semantic.warningContainer
    val fg = if (hardened) UnderstoryTheme.semantic.success else UnderstoryTheme.semantic.warning
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(container, RoundedCornerShape(50))
            .clickable { onClick() }
            .semantics { role = androidx.compose.ui.semantics.Role.Button }
            .defaultMinSize(minHeight = 40.dp)
            .padding(horizontal = UnderstoryTheme.spacing.md, vertical = UnderstoryTheme.spacing.xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
    ) {
        Icon(
            imageVector = if (hardened) Icons.Filled.Shield else Icons.Filled.Public,
            contentDescription = null,
            tint = fg,
            modifier = Modifier.size(16.dp),
        )
        Text(
            stringResource(R.string.mode_chip, modeLabel(mode)),
            style = MaterialTheme.typography.labelLarge,
            color = fg,
        )
    }
}

/**
 * Tab-count toolbar button: a bordered rounded square carrying the number of
 * open tabs (capped display at "9+"). Opens the tab switcher.
 */
@Composable
private fun TabCountButton(count: Int, onClick: () -> Unit) {
    val desc = stringResource(R.string.cd_tab_count, count)
    IconButton(
        onClick = onClick,
        modifier = Modifier.size(48.dp).semantics {
            contentDescription = desc
        },
    ) {
        Box(
            modifier = Modifier
                .size(22.dp)
                .border(
                    width = 2.dp,
                    color = MaterialTheme.colorScheme.onSurface,
                    shape = RoundedCornerShape(6.dp),
                ),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = if (count > 9) "9+" else count.toString(),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
            )
        }
    }
}

/**
 * The tab switcher — a full-screen list of open tabs (title + host + close)
 * plus a "New tab" action. New-tab opens a fresh BrowserHome tab; picking a
 * tab selects it; the last tab can't be emptied (TabManager reseeds home).
 */
@Composable
private fun TabSwitcherScreen(
    tabs: TabManager,
    onBack: () -> Unit,
    onPick: (Long) -> Unit,
    onNewTab: () -> Unit,
    onClose: (Long) -> Unit,
) {
    val activeId = tabs.activeId
    SuiteScaffold(
        title = stringResource(R.string.tabs_title, tabs.count),
        onBack = onBack,
        showSuiteFooter = false,
        actions = {
            IconButton(onClick = onNewTab) {
                Icon(
                    Icons.Filled.Add,
                    contentDescription = stringResource(R.string.cd_new_tab),
                )
            }
        },
    ) { pad ->
        androidx.compose.foundation.lazy.LazyColumn(
            modifier = Modifier.fillMaxSize().padding(pad),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            items(items = tabs.tabs.toList(), key = { it.id }) { tab ->
                TabRow(
                    tab = tab,
                    isActive = tab.id == activeId,
                    onTap = { onPick(tab.id) },
                    onClose = { onClose(tab.id) },
                )
            }
            item(key = "__new_tab__") {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = MaterialTheme.shapes.medium,
                    tonalElevation = 1.dp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(MaterialTheme.shapes.medium)
                        .clickable { onNewTab() }
                        .semantics { role = androidx.compose.ui.semantics.Role.Button },
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .defaultMinSize(minHeight = 56.dp)
                            .padding(UnderstoryTheme.spacing.lg),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
                    ) {
                        Icon(
                            Icons.Filled.Add,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                        )
                        Text(
                            stringResource(R.string.tabs_new),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }
        }
    }
}

/** One row in the tab switcher: mode glyph · title/host · close. */
@Composable
private fun TabRow(
    tab: Tab,
    isActive: Boolean,
    onTap: () -> Unit,
    onClose: () -> Unit,
) {
    val hardened = tab.mode == BrowseMode.HARDENED
    val title = tab.title?.takeIf { it.isNotBlank() }
        ?: tab.host
        ?: stringResource(R.string.tabs_home_label)
    val sub = tab.host ?: stringResource(R.string.tabs_home_sub)
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = if (isActive) 3.dp else 1.dp,
        border = if (isActive) androidx.compose.foundation.BorderStroke(
            2.dp, MaterialTheme.colorScheme.primary,
        ) else null,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.medium)
                .clickable { onTap() }
                .semantics(mergeDescendants = true) {
                    role = androidx.compose.ui.semantics.Role.Button
                }
                .defaultMinSize(minHeight = 56.dp)
                .padding(start = UnderstoryTheme.spacing.lg),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Icon(
                imageVector = if (hardened) Icons.Filled.Shield else Icons.Filled.Public,
                contentDescription = null,
                tint = if (hardened) MaterialTheme.colorScheme.onSurfaceVariant
                else UnderstoryTheme.semantic.warning,
                modifier = Modifier.size(20.dp),
            )
            Column(Modifier.weight(1f).padding(vertical = UnderstoryTheme.spacing.sm)) {
                Text(
                    title,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    sub,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            IconButton(onClick = onClose, modifier = Modifier.size(48.dp)) {
                Icon(
                    Icons.Filled.Close,
                    contentDescription = stringResource(R.string.cd_close_tab, title),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * The mode chooser dialog. Honest, side-by-side copy on what each mode does;
 * picking a mode applies it to the current tab. A checkbox row lets the user
 * also make the chosen mode the default for future user-opened tabs.
 */
@Composable
private fun ModeChooserDialog(
    current: BrowseMode,
    isDefault: Boolean,
    onPick: (BrowseMode) -> Unit,
    onSetDefault: (BrowseMode) -> Unit,
    onDismiss: () -> Unit,
) {
    var selected by remember { mutableStateOf(current) }
    var makeDefault by remember { mutableStateOf(isDefault) }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.mode_dialog_title), style = MaterialTheme.typography.titleLarge) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                ModeOptionRow(
                    selected = selected == BrowseMode.HARDENED,
                    title = stringResource(R.string.mode_hardened),
                    body = stringResource(R.string.mode_hardened_body),
                    onSelect = { selected = BrowseMode.HARDENED },
                )
                ModeOptionRow(
                    selected = selected == BrowseMode.STANDARD,
                    title = stringResource(R.string.mode_standard),
                    body = stringResource(R.string.mode_standard_body),
                    onSelect = { selected = BrowseMode.STANDARD },
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(MaterialTheme.shapes.small)
                        .clickable { makeDefault = !makeDefault }
                        .semantics {
                            role = androidx.compose.ui.semantics.Role.Checkbox
                        }
                        .padding(vertical = UnderstoryTheme.spacing.xs),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                ) {
                    androidx.compose.material3.Checkbox(
                        checked = makeDefault,
                        onCheckedChange = null,
                        modifier = Modifier.clearAndSetSemantics {},
                    )
                    Text(
                        stringResource(R.string.mode_make_default),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        },
        confirmButton = {
            androidx.compose.material3.TextButton(onClick = {
                if (makeDefault) onSetDefault(selected)
                onPick(selected)
            }) { Text(stringResource(R.string.action_apply)) }
        },
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

@Composable
private fun ModeOptionRow(
    selected: Boolean,
    title: String,
    body: String,
    onSelect: () -> Unit,
) {
    Surface(
        color = if (selected) MaterialTheme.colorScheme.surfaceVariant
        else MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = if (selected) 2.dp else 0.dp,
        border = if (selected) androidx.compose.foundation.BorderStroke(
            1.dp, MaterialTheme.colorScheme.primary,
        ) else androidx.compose.foundation.BorderStroke(
            1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f),
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.medium)
                .selectable(
                    selected = selected,
                    role = androidx.compose.ui.semantics.Role.RadioButton,
                    onClick = onSelect,
                )
                .padding(UnderstoryTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            androidx.compose.material3.RadioButton(
                selected = selected,
                onClick = null,
                modifier = Modifier.clearAndSetSemantics {},
            )
            Column(Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * Standard-mode download confirm. Names the file + host so the user knows
 * exactly what they're about to save and from where. Confirm routes to the
 * system DownloadManager.
 */
@Composable
private fun DownloadConfirmDialog(
    download: PendingDownload,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.download_title), style = MaterialTheme.typography.titleLarge) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                Text(
                    download.fileName,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    stringResource(R.string.download_from, download.host ?: download.url),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    stringResource(R.string.download_dest),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            androidx.compose.material3.TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.action_download))
            }
        },
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

/** A download awaiting the Standard-mode confirm prompt. */
data class PendingDownload(
    val url: String,
    val userAgent: String?,
    val contentDisposition: String?,
    val mimeType: String?,
    val fileName: String,
    val host: String?,
)

/**
 * WebView download hook. In HARDENED mode downloads are refused and offered
 * to the default browser (the pre-P1 behavior, unchanged). In STANDARD mode
 * a confirm prompt is surfaced; only an explicit confirm reaches
 * [startSystemDownload].
 */
private fun handleDownload(
    ctx: Context,
    mode: BrowseMode,
    url: String,
    userAgent: String?,
    contentDisposition: String?,
    mimeType: String?,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
    onPrompt: (PendingDownload) -> Unit,
) {
    if (mode == BrowseMode.HARDENED) {
        Diagnostics.log("browser.download", "download refused (hardened) — offer to default browser")
        showSnack(
            ctx.getString(R.string.msg_downloads_disabled),
            ctx.getString(R.string.action_download_in_chrome),
        ) { openInDefault(ctx, url, showSnack) }
        return
    }
    // STANDARD: only https downloads (the transport block already refuses
    // cleartext, but be explicit — never hand a non-https URL to DownloadManager).
    if (!url.startsWith("https://", ignoreCase = true)) {
        Diagnostics.log("browser.download", "refused non-https download")
        showSnack(ctx.getString(R.string.msg_download_insecure), null, null)
        return
    }
    val fileName = runCatching {
        android.webkit.URLUtil.guessFileName(url, contentDisposition, mimeType)
    }.getOrDefault("download")
    Diagnostics.log("browser.download", "standard download prompt")
    onPrompt(
        PendingDownload(
            url = url,
            userAgent = userAgent,
            contentDisposition = contentDisposition,
            mimeType = mimeType,
            fileName = fileName,
            host = hostOf(url),
        ),
    )
}

/**
 * Enqueue a confirmed Standard-mode download via the system DownloadManager
 * into the app-scoped external Downloads dir (no storage permission needed on
 * minSdk 33). Cookies for the request are pulled from the CookieManager so a
 * gated file downloads correctly in Standard mode.
 */
private fun startSystemDownload(
    ctx: Context,
    dl: PendingDownload,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    val ok = runCatching {
        val req = android.app.DownloadManager.Request(Uri.parse(dl.url)).apply {
            setMimeType(dl.mimeType)
            dl.userAgent?.let { addRequestHeader("User-Agent", it) }
            runCatching {
                CookieManager.getInstance().getCookie(dl.url)?.let { c ->
                    addRequestHeader("Cookie", c)
                }
            }
            setTitle(dl.fileName)
            setNotificationVisibility(
                android.app.DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED,
            )
            setDestinationInExternalFilesDir(
                ctx, android.os.Environment.DIRECTORY_DOWNLOADS, dl.fileName,
            )
        }
        val dm = ctx.getSystemService(Context.DOWNLOAD_SERVICE) as android.app.DownloadManager
        dm.enqueue(req)
    }.isSuccess
    showSnack(
        ctx.getString(if (ok) R.string.msg_download_started else R.string.msg_download_failed),
        null, null,
    )
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

/**
 * True on the eng product flavor — the single gate for every developer-only
 * surface (the Diagnostics screen entry and the network-proxy overlay). Reads
 * the generated [BuildConfig.FLAVOR] rather than sniffing the applicationId, so
 * the shipping ("prod") build has NO diagnostics affordance and NO proxy entry
 * at all. [ctx] is unused now but kept so call sites don't churn.
 */
@Suppress("UNUSED_PARAMETER")
private fun isEngBuild(ctx: Context): Boolean = BuildConfig.FLAVOR == "eng"

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
 * Share the current URL as plain text via the system share sheet. A text-only
 * share of an https link — no page content, no secrets — the honest "send this
 * link somewhere" exit that complements open-in-default.
 */
private fun shareLink(
    ctx: Context,
    url: String,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    Diagnostics.log("browser.handoff", "share link: tap")
    val i = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, url)
    }
    runCatching {
        ctx.startActivity(
            Intent.createChooser(i, ctx.getString(R.string.share_chooser_title))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }.onFailure {
        showSnack(ctx.getString(R.string.msg_no_share), null, null)
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

/**
 * Build the one reused WebView with the invariant hardening that holds in
 * BOTH modes, then layer the mode-specific relaxations via [applyMode]. The
 * invariants here are never reachable by a mode toggle: file/content access
 * off, mixed content never allowed, no autofill/saved passwords, geolocation
 * off, no auto-window-open, no multiple windows, third-party cookies blocked,
 * Safe Browsing on.
 */
@SuppressLint("SetJavaScriptEnabled")
private fun buildHardenedWebView(ctx: android.content.Context, mode: BrowseMode): WebView {
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

    runCatching {
        val cm = CookieManager.getInstance()
        cm.setAcceptThirdPartyCookies(wv, false)
    }

    runCatching {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SAFE_BROWSING_ENABLE)) {
            WebSettingsCompat.setSafeBrowsingEnabled(s, true)
        }
    }

    applyMode(ctx, wv, mode, host = null)
    return wv
}

/**
 * Apply the mode-dependent settings to the (already-invariant-hardened)
 * WebView. Called on build, on an explicit mode switch, and on every
 * main-frame navigation (so per-host JS and cache/storage track the active
 * tab's mode + the site being shown).
 *
 * HARDENED: cache off, DOM storage off, first-party cookies per the global
 *   toggle, JS on ONLY when [host] is on the per-site allowlist.
 * STANDARD: normal cache + DOM storage, first-party cookies accepted, JS on.
 *
 * @return the effective javaScriptEnabled value applied, so the caller can
 *   reflect the JS indicator honestly.
 */
private fun applyMode(
    ctx: android.content.Context,
    wv: WebView,
    mode: BrowseMode,
    host: String?,
): Boolean {
    val s = wv.settings
    val jsOn: Boolean
    when (mode) {
        BrowseMode.HARDENED -> {
            s.cacheMode = WebSettings.LOAD_NO_CACHE
            s.databaseEnabled = false
            s.domStorageEnabled = false
            jsOn = BrowserSettings.isJsAllowed(ctx, host)
            runCatching {
                CookieManager.getInstance()
                    .setAcceptCookie(BrowserSettings.getFirstPartyCookies(ctx))
            }
        }
        BrowseMode.STANDARD -> {
            s.cacheMode = WebSettings.LOAD_DEFAULT
            s.databaseEnabled = true
            s.domStorageEnabled = true
            jsOn = true
            runCatching { CookieManager.getInstance().setAcceptCookie(true) }
        }
    }
    s.javaScriptEnabled = jsOn
    return jsOn
}

private class HardenedWebViewClient(
    val ctx: Context,
    val onLoadStart: (WebView?) -> Unit,
    val onLoadFinish: (WebView?) -> Unit,
    val onNavState: (WebView?) -> Unit,
    // The active tab's current mode, read fresh on each navigation so a
    // mid-session mode switch takes effect on the next load.
    val currentMode: () -> BrowseMode,
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
            // Applies in BOTH modes: Standard relaxes JS/cookies/downloads,
            // never the scheme allowlist or the cleartext block.
            if (req.isForMainFrame) onBlockedScheme(uri)
            return true
        }
        if (req.isForMainFrame && view != null) {
            val allow = applyMode(ctx, view, currentMode(), uri.host?.lowercase())
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
        if (view != null) {
            val allow = applyMode(ctx, view, currentMode(), hostOf(url))
            if (view.settings.javaScriptEnabled != allow) onJsApplied(allow)
        }
    }

    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        // Hard reject — never proceed past an SSL error.
        handler?.cancel()
    }
}

private class HardenedWebChromeClient(
    val onTitle: (String?) -> Unit = {},
    val onProgress: (Int) -> Unit = {},
) : WebChromeClient() {

    override fun onReceivedTitle(view: WebView?, title: String?) {
        onTitle(title)
    }

    override fun onProgressChanged(view: WebView?, newProgress: Int) {
        onProgress(newProgress)
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
