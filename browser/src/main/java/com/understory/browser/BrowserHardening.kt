package com.understory.browser

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import com.understory.elevation.Elevation
import com.understory.elevation.PrivateDnsMode

/**
 * Pure (non-Compose) support for the browser Hardening screen. Enumeration,
 * exclusion, and defensive parsing live here; the screen ([HardeningScreen])
 * owns only rendering + the elevated-action calls.
 *
 * Doctrine baked in:
 *  - Every target-selection helper HARD-EXCLUDES apps we must never touch:
 *    this app, every com.understory.* sibling, Tailscale, Shizuku/Sui managers,
 *    the active launcher, and com.android.settings. See [isExcludedTarget].
 *  - The Private-DNS snapshot parser DEGRADES on a null/blank read (returns an
 *    Unknown snapshot) — it never fabricates a value or blocks on a parse miss.
 */
object BrowserHardening {

    /** This app's own package — always excluded from any cross-app action. */
    private fun selfPkg(ctx: Context): String = ctx.packageName.removeSuffix(".eng")

    /**
     * Packages that must never be a target of an elevated action, regardless of
     * how they were enumerated. Fail-closed: an unresolved launcher just means
     * we exclude nothing extra, never that we'd accidentally include a suite app.
     */
    val STATIC_EXCLUDES: Set<String> = setOf(
        // Tailscale — holds the single VpnService slot; never touch it.
        "com.tailscale.ipn",
        // Shizuku / Sui managers — our own elevation broker's manager apps.
        "moe.shizuku.privileged.api",
        "moe.shizuku.manager",
        // System settings — never freeze/strip the settings app.
        "com.android.settings",
    )

    /**
     * True when [pkg] must be excluded from cross-app actions: self, any suite
     * sibling (com.understory.*), a static exclude (Tailscale / Shizuku / Sui /
     * Settings), or the resolved home launcher package.
     */
    fun isExcludedTarget(ctx: Context, pkg: String, launcherPkg: String?): Boolean {
        if (pkg.isBlank()) return true
        if (pkg == selfPkg(ctx) || pkg == ctx.packageName) return true
        if (pkg.startsWith("com.understory.")) return true
        if (pkg in STATIC_EXCLUDES) return true
        if (launcherPkg != null && pkg == launcherPkg) return true
        return false
    }

    /** The current home/launcher package, or null when it can't be resolved. */
    fun launcherPackage(ctx: Context): String? = runCatching {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
        val ri: ResolveInfo? =
            ctx.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
        ri?.activityInfo?.packageName
    }.getOrNull()

    /**
     * Installed browsers: apps that handle an ACTION_VIEW http/https intent,
     * de-duplicated by package and with every excluded target removed. Sorted by
     * display label. Never throws — an enumeration failure yields an empty list
     * (the screen then shows its honest "no other browsers" empty state).
     */
    fun installedBrowsers(ctx: Context): List<InstalledApp> {
        val pm = ctx.packageManager
        val launcher = launcherPackage(ctx)
        val probe = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"))
        return runCatching {
            pm.queryIntentActivities(probe, PackageManager.MATCH_ALL)
                .mapNotNull { it.activityInfo?.packageName }
                .distinct()
                .filterNot { isExcludedTarget(ctx, it, launcher) }
                .mapNotNull { appOf(ctx, it) }
                .sortedBy { it.label.lowercase() }
        }.getOrDefault(emptyList())
    }

    /**
     * User-visible launchable apps eligible to be frozen: everything with a
     * launcher entry, minus excluded targets. Sorted by label. Never throws.
     */
    fun freezableApps(ctx: Context): List<InstalledApp> {
        val pm = ctx.packageManager
        val launcher = launcherPackage(ctx)
        val probe = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return runCatching {
            pm.queryIntentActivities(probe, PackageManager.MATCH_ALL)
                .mapNotNull { it.activityInfo?.packageName }
                .distinct()
                .filterNot { isExcludedTarget(ctx, it, launcher) }
                .mapNotNull { appOf(ctx, it) }
                .sortedBy { it.label.lowercase() }
        }.getOrDefault(emptyList())
    }

    /** Resolve a package to a label + package pair, or null if uninstalled. */
    private fun appOf(ctx: Context, pkg: String): InstalledApp? = runCatching {
        val pm = ctx.packageManager
        val ai = pm.getApplicationInfo(pkg, 0)
        InstalledApp(pkg = pkg, label = pm.getApplicationLabel(ai).toString())
    }.getOrNull()

    // ---- Private DNS snapshot -------------------------------------------------

    /**
     * Read the current global Private DNS mode + specifier via the read-only
     * shell. DEGRADES to [PrivateDnsSnapshot.Unknown] when unelevated or on any
     * parse miss — never fabricates a value, never blocks the screen. The
     * `settings get` values can be the literal "null" string on stock Android;
     * that is normalized to a null field, not shown to the user as text.
     */
    suspend fun readPrivateDnsSnapshot(ctx: Context): PrivateDnsSnapshot {
        if (!Elevation.canRunShell(ctx)) return PrivateDnsSnapshot.Unknown
        val mode = Elevation.readShell(
            ctx, listOf("settings", "get", "global", "private_dns_mode"),
        )?.let { normalizeSetting(it) }
        val specifier = Elevation.readShell(
            ctx, listOf("settings", "get", "global", "private_dns_specifier"),
        )?.let { normalizeSetting(it) }
        // A null mode read = we simply couldn't determine it; degrade to Unknown
        // rather than claim "off".
        if (mode == null) return PrivateDnsSnapshot.Unknown
        return PrivateDnsSnapshot.Known(mode = mode, specifier = specifier)
    }

    /** Map a raw `settings get` line to a value, treating "null"/blank as absent. */
    private fun normalizeSetting(raw: String): String? {
        val t = raw.trim()
        return if (t.isEmpty() || t.equals("null", ignoreCase = true)) null else t
    }

    /** Human line for a snapshot (mode + hostname when strict). */
    fun snapshotDisplay(snapshot: PrivateDnsSnapshot): String? = when (snapshot) {
        is PrivateDnsSnapshot.Unknown -> null
        is PrivateDnsSnapshot.Known -> {
            val mode = snapshot.mode ?: "unknown"
            if (snapshot.specifier != null) "$mode (${snapshot.specifier})" else mode
        }
    }

    /**
     * Basic sanity check for a DoT hostname before we hand it to the shell. Not a
     * full RFC validation — just enough to reject obvious junk / injection-shaped
     * input (whitespace, control chars, schemes). The elevated call passes argv,
     * so this is defense-in-depth, not the only guard.
     */
    fun looksLikeDnsHost(input: String): Boolean {
        val h = input.trim()
        if (h.length !in 1..253) return false
        if (h.any { it.isWhitespace() }) return false
        if (h.contains("://") || h.contains('/')) return false
        // Only DNS-name characters.
        return h.all { it.isLetterOrDigit() || it == '.' || it == '-' } && h.contains('.')
    }

    // ---- The revocation matrix ------------------------------------------------

    /**
     * The three web-escalation permissions this screen can strip, each paired
     * with the AppOps op name to also set to "ignore" so a lingering grant can't
     * be silently used. Reversible: `pm grant` + appops "allow"/"default".
     */
    enum class RiskyPerm(
        val manifestPermission: String,
        val appOp: String,
    ) {
        CAMERA("android.permission.CAMERA", "CAMERA"),
        MIC("android.permission.RECORD_AUDIO", "RECORD_AUDIO"),
        LOCATION("android.permission.ACCESS_FINE_LOCATION", "FINE_LOCATION"),
    }
}

/** A resolved installed app (package + display label) for a picker row. */
data class InstalledApp(val pkg: String, val label: String)

/** Snapshot of the device Private DNS setting; Unknown when we couldn't read it. */
sealed interface PrivateDnsSnapshot {
    /** Unelevated, or a read/parse miss — the screen degrades honestly. */
    data object Unknown : PrivateDnsSnapshot

    /** A read succeeded. [mode] is the global mode; [specifier] the strict host. */
    data class Known(val mode: String?, val specifier: String?) : PrivateDnsSnapshot
}
