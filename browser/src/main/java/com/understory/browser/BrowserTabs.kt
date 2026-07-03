package com.understory.browser

import android.os.Bundle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * Browsing mode — the per-app default + per-tab toggle added in P1.
 *
 * This is NOT an "infinity lockdown tomb": the user chooses per tab, and
 * the app is honest in the UI about what each mode does. The default for
 * user-opened tabs is persisted in [BrowserSettings.getDefaultMode] and
 * remains [HARDENED] out of the box. A link arriving through the intake
 * doorway (share / VIEW) is ALWAYS opened Hardened regardless of the
 * default — the doorway is the untrusted-input path.
 *
 * Two invariants hold in BOTH modes and are never governed by this enum:
 *   - FLAG_SECURE / no-screenshot / no-recents-thumbnail (suite posture).
 *   - Mixed content blocked (MIXED_CONTENT_NEVER_ALLOW), cleartext denied
 *     at the transport layer, SSL errors rejected hard, third-party
 *     cookies always blocked, geolocation/camera/mic auto-denied,
 *     file://+content:// unreachable, no window-create / no popups,
 *     no form autofill / no saved passwords, Safe Browsing on.
 *
 * What the mode DOES change (see [buildHardenedWebView] / the mode-apply
 * path in MainActivity):
 *   - HARDENED: JavaScript off unless the host is on the per-site
 *     allowlist; first-party cookies follow the global toggle (default
 *     off); no downloads (offered to the default browser instead);
 *     no cache, no DOM storage; page + cookies + storage wiped on leave.
 *   - STANDARD: JavaScript on; first-party cookies accepted and retained
 *     within the app session; downloads allowed behind a clear prompt;
 *     normal cache + DOM storage so ordinary sites work; history/session
 *     retained within the app. Still wiped on the explicit "Clear now"
 *     and on Activity destroy (the ephemeral-on-exit guarantee).
 */
enum class BrowseMode {
    HARDENED,
    STANDARD,
}

/**
 * One browser tab. The suite uses a SINGLE reused [android.webkit.WebView]
 * driven by per-tab [savedState] bundles (WebView.saveState / restoreState)
 * rather than retaining N live WebView instances — retention of several
 * hardened WebViews is heavy, and a bundle-swap keeps exactly one live web
 * context, which also bounds the attack surface to the visible tab.
 *
 * @param id stable identity for keys + the active-tab pointer. Never reused.
 * @param url the load target, or null for a tab sitting on BrowserHome.
 * @param title last page title seen (falls back to the host in the UI).
 * @param mode this tab's browsing mode (independent of other tabs).
 * @param savedState the outgoing WebView state captured on the last switch
 *   away from this tab, replayed via restoreState when it is shown again.
 *   Null for a tab that has never been rendered (fresh load from [url]).
 */
class Tab(
    val id: Long,
    url: String? = null,
    title: String? = null,
    mode: BrowseMode = BrowseMode.HARDENED,
) {
    var url by mutableStateOf(url)
    var title by mutableStateOf(title)
    var mode by mutableStateOf(mode)

    // Not Compose state: read only when restoring a WebView, written only on
    // switch-away. A bundle isn't a stable snapshot key and shouldn't drive
    // recomposition.
    var savedState: Bundle? = null

    /** Host of [url] for the tab-strip / switcher subtitle, or null on home. */
    val host: String?
        get() = url?.let { runCatching { android.net.Uri.parse(it).host?.lowercase() }.getOrNull() }
}

/**
 * The open-tab set + active pointer. Plain observable holder (SnapshotState
 * list + a state-backed active id) so Compose recomposes on any mutation.
 * Owned by a `remember { }` at the app root; the Activity's `configChanges`
 * cover rotation/uiMode without recreation, so this survives config changes
 * without a Saver. (Process-death restore is explicitly out of scope for P1;
 * the ephemeral-session posture already discards web state on exit.)
 *
 * There is ALWAYS at least one tab. Closing the last tab does not empty the
 * list — it resets that tab to a fresh home tab, so the viewer returns to
 * BrowserHome rather than to an invalid empty state.
 */
class TabManager(defaultMode: BrowseMode) {
    private var nextId = 1L

    val tabs = mutableStateListOf<Tab>()
    var activeId by mutableStateOf(0L)
        private set

    // The mode a brand-new user-opened tab inherits (the persisted per-app
    // default). Intake tabs override this to HARDENED at their call site.
    var newTabMode: BrowseMode = defaultMode

    init {
        val first = Tab(id = nextId++, mode = defaultMode)
        tabs.add(first)
        activeId = first.id
    }

    val active: Tab
        get() = tabs.firstOrNull { it.id == activeId } ?: tabs.first()

    val count: Int
        get() = tabs.size

    fun indexOfActive(): Int = tabs.indexOfFirst { it.id == activeId }.coerceAtLeast(0)

    /** Open a new tab (optionally pre-seeded with a url + mode) and select it. */
    fun open(url: String? = null, mode: BrowseMode = newTabMode): Tab {
        val t = Tab(id = nextId++, url = url, mode = mode)
        tabs.add(t)
        activeId = t.id
        return t
    }

    /** Select an existing tab by id. No-op if it isn't present. */
    fun select(id: Long) {
        if (tabs.any { it.id == id }) activeId = id
    }

    /**
     * Collapse the whole tab set to a single fresh home tab. Used by the
     * "Clear now" wipe so no page (in any tab) survives the clear — the
     * ephemeral-session guarantee has to cover every tab, not just the
     * visible one.
     */
    fun resetToSingleHome() {
        val fresh = Tab(id = nextId++, mode = newTabMode)
        tabs.clear()
        tabs.add(fresh)
        activeId = fresh.id
    }

    /**
     * Close a tab. Closing the currently-active tab selects a sensible
     * neighbour (the previous tab, else the next). Closing the LAST tab
     * replaces it with a fresh home tab and returns that tab so the caller
     * can reset the visible WebView to home.
     *
     * @return the tab that should become / remain active after the close.
     */
    fun close(id: Long): Tab {
        val idx = tabs.indexOfFirst { it.id == id }
        if (idx < 0) return active

        if (tabs.size == 1) {
            // Last tab: reset to a fresh home tab (never an empty list).
            val fresh = Tab(id = nextId++, mode = newTabMode)
            tabs[0] = fresh
            activeId = fresh.id
            return fresh
        }

        val wasActive = tabs[idx].id == activeId
        tabs.removeAt(idx)
        if (wasActive) {
            val neighbour = tabs[(idx - 1).coerceAtLeast(0)]
            activeId = neighbour.id
        }
        return active
    }
}
