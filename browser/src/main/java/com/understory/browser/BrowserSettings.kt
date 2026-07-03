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
