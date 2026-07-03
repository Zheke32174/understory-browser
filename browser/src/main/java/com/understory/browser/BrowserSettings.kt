package com.understory.browser

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persisted browser preferences. Bookmarks are NOT credentials — they're
 * just URL+title pairs the user has chosen to remember. Plain
 * SharedPreferences, no encryption layer; the suite's security boundary
 * for the browser is "ephemeral session, no cookies/storage carried
 * across launches" (see MainActivity.onDestroy). Bookmarks are an
 * explicit opt-in to persistence: starring a URL is a deliberate user
 * act that says "this one is worth keeping."
 */
object BrowserSettings {
    private const val PREF = "browser_settings"
    private const val K_BOOKMARKS = "bookmarks_v1"
    private const val K_I2P_PROVIDER = "i2p_provider"
    private const val K_JS_ALLOWLIST = "js_allowlist_v1"
    private const val K_FIRST_PARTY_COOKIES = "first_party_cookies"
    private const val K_VIEW_FILTER_ENABLED = "view_filter_enabled"
    private const val K_FIRST_RUN_DONE = "first_run_done"
    private const val K_EXTERNAL_HANDOFF = "external_handoff"
    private const val K_DEFAULT_MODE = "default_browse_mode"

    /**
     * Per-site JavaScript allowlist, keyed by lowercase host. JS is OFF
     * by default for every navigation; a host on this list gets JS
     * re-enabled whenever it is the top-level page. Keyed by host (not
     * full URL) because the opt-in the user is expressing is "this site
     * needs scripts" — per-URL entries would silently multiply. Like
     * bookmarks, this is a deliberate, persistent user act; it is not
     * part of the wiped-on-destroy session state.
     */
    fun isJsAllowed(ctx: Context, host: String?): Boolean =
        host != null && host.lowercase() in getJsAllowlist(ctx)

    fun setJsAllowed(ctx: Context, host: String, allowed: Boolean) {
        val key = host.lowercase()
        val current = getJsAllowlist(ctx).toMutableSet()
        val changed = if (allowed) current.add(key) else current.remove(key)
        if (!changed) return
        val json = JSONArray()
        for (h in current) json.put(h)
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putString(K_JS_ALLOWLIST, json.toString())
            .apply()
    }

    fun getJsAllowlist(ctx: Context): Set<String> {
        val raw = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(K_JS_ALLOWLIST, null) ?: return emptySet()
        return runCatching {
            val arr = JSONArray(raw)
            val out = HashSet<String>(arr.length())
            for (i in 0 until arr.length()) out += arr.getString(i)
            out
        }.getOrDefault(emptySet())
    }

    /**
     * The JS allowlist as a stable, alphabetically-sorted list — the shape
     * the JS-allowlist management screen renders. Sorting keeps the list
     * order deterministic across launches (the backing set is unordered).
     */
    fun getJsHosts(ctx: Context): List<String> =
        getJsAllowlist(ctx).sorted()

    /**
     * Revoke JS for a single host. Convenience over [setJsAllowed] for the
     * allowlist-management screen's per-row remove control.
     */
    fun removeJsHost(ctx: Context, host: String) {
        setJsAllowed(ctx, host, false)
    }

    /**
     * Whether the opt-in ACTION_VIEW http/https alias (`.ViewIntakeAlias`)
     * is enabled. Default OFF — the strictly-safe default install exports
     * only the SEND share target. Flipping this true is a one-time user
     * choice in the first-run card; the caller pairs it with a
     * PackageManager.setComponentEnabledSetting on the alias so the
     * manifest state and this pref stay in sync.
     */
    fun getViewFilterEnabled(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_VIEW_FILTER_ENABLED, false)

    fun setViewFilterEnabled(ctx: Context, on: Boolean) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_VIEW_FILTER_ENABLED, on)
            .apply()
    }

    /**
     * Whether the first-run VIEW-filter opt-in card has been shown and
     * answered. Once true the card never shows again regardless of the
     * choice made.
     */
    fun isFirstRunDone(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_FIRST_RUN_DONE, false)

    fun setFirstRunDone(ctx: Context) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_FIRST_RUN_DONE, true)
            .apply()
    }

    /**
     * Whether `mailto:` / `tel:` / `sms:` links hand off to the user's real
     * apps via an implicit ACTION_VIEW intent. Default ON (the complement
     * hand-off). Users who want zero outbound intents can turn it off, in
     * which case those schemes take the "refuse with feedback" branch.
     */
    fun getExternalHandoffEnabled(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_EXTERNAL_HANDOFF, true)

    fun setExternalHandoffEnabled(ctx: Context, on: Boolean) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_EXTERNAL_HANDOFF, on)
            .apply()
    }

    /**
     * First-party cookie acceptance. Default OFF — cookies are a
     * tracking surface first and a login convenience second. Third-party
     * cookies are unconditionally blocked in MainActivity regardless of
     * this toggle, and whatever is accepted here is still wiped on
     * Activity destroy (ephemeral-session posture) — the toggle governs
     * within-session acceptance only.
     */
    fun getFirstPartyCookies(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_FIRST_PARTY_COOKIES, false)

    fun setFirstPartyCookies(ctx: Context, on: Boolean) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_FIRST_PARTY_COOKIES, on)
            .apply()
    }

    /**
     * The per-app default browsing mode applied to a NEW tab the user
     * opens from the home surface. Stored as the [BrowseMode] name; an
     * unrecognized or absent value falls back to [BrowseMode.HARDENED]
     * — the suite's fail-safe posture (a corrupt pref never silently
     * relaxes the sandbox). Note this governs only user-opened tabs:
     * a link arriving through the intake doorway is ALWAYS Hardened,
     * independent of this setting (see MainActivity's intake path).
     */
    fun getDefaultMode(ctx: Context): BrowseMode {
        val raw = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(K_DEFAULT_MODE, null) ?: return BrowseMode.HARDENED
        return runCatching { BrowseMode.valueOf(raw) }.getOrDefault(BrowseMode.HARDENED)
    }

    fun setDefaultMode(ctx: Context, mode: BrowseMode) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putString(K_DEFAULT_MODE, mode.name)
            .apply()
    }

    /**
     * The user's I2P provider preference, identified by
     * `I2pProvider.id` from the `:overlay-i2p` module. Default =
     * the safe "eepsites only" entry. Whether the proxy is *active*
     * is session-only (not persisted); only the provider choice
     * survives launches.
     */
    fun getI2pProviderId(ctx: Context): String =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(K_I2P_PROVIDER, "eepsites_only")
            ?: "eepsites_only"

    fun setI2pProviderId(ctx: Context, id: String) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putString(K_I2P_PROVIDER, id)
            .apply()
    }

    /**
     * Bookmark list, ordered most-recently-added first. Capped at
     * [MAX_BOOKMARKS] entries — the suite isn't a bookmark manager,
     * and an unbounded list erodes the "pick one" UX. Adding when
     * already at cap drops the oldest.
     */
    fun getBookmarks(ctx: Context): List<Bookmark> {
        val raw = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(K_BOOKMARKS, null) ?: return emptyList()
        return runCatching { decode(raw) }.getOrDefault(emptyList())
    }

    fun isBookmarked(ctx: Context, url: String): Boolean =
        getBookmarks(ctx).any { it.url == url }

    fun toggle(ctx: Context, url: String, title: String?): Boolean {
        // Returns the new state (true = bookmarked, false = removed).
        // Same shape as Switch's onCheckedChange so the call site is
        // straightforward.
        val current = getBookmarks(ctx).toMutableList()
        val idx = current.indexOfFirst { it.url == url }
        return if (idx >= 0) {
            current.removeAt(idx)
            persist(ctx, current)
            false
        } else {
            current.add(0, Bookmark(url = url, title = title?.takeIf { it.isNotBlank() } ?: url, addedAtMillis = System.currentTimeMillis()))
            while (current.size > MAX_BOOKMARKS) current.removeAt(current.size - 1)
            persist(ctx, current)
            true
        }
    }

    fun remove(ctx: Context, url: String) {
        val current = getBookmarks(ctx).filterNot { it.url == url }
        persist(ctx, current)
    }

    private fun persist(ctx: Context, list: List<Bookmark>) {
        val json = JSONArray()
        for (b in list) {
            json.put(
                JSONObject().apply {
                    put("url", b.url)
                    put("title", b.title)
                    put("addedAt", b.addedAtMillis)
                },
            )
        }
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putString(K_BOOKMARKS, json.toString())
            .apply()
    }

    private fun decode(raw: String): List<Bookmark> {
        val arr = JSONArray(raw)
        val out = ArrayList<Bookmark>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += Bookmark(
                url = o.getString("url"),
                title = o.optString("title", o.getString("url")),
                addedAtMillis = o.optLong("addedAt", 0L),
            )
        }
        return out
    }

    private const val MAX_BOOKMARKS = 200
}

data class Bookmark(
    val url: String,
    val title: String,
    val addedAtMillis: Long,
)
