package com.understory.browser

import android.content.Context
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import com.understory.overlay.i2p.I2pProvider
import java.util.concurrent.Executor
import com.understory.overlay.i2p.I2pProxyService
import com.understory.overlay.i2p.I2pStatus
import com.understory.overlay.lokinet.LokinetStatus
import com.understory.overlay.yggdrasil.YggdrasilStatus
import com.understory.security.Diagnostics
import com.understory.security.secureClickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll

/**
 * Browser proxy / overlay-network screen. Phase α exposes:
 *   - I2P toggle (off by default; off-on triggers I2pProxyService and
 *     applies WebView ProxyController override when the supervisor
 *     reports Ready)
 *   - I2P provider catalog selector (a curated list — we ship the
 *     pointer, the user picks)
 *   - A literal "no binary bundled in this build" banner when the
 *     supervisor reports BinaryMissing, so the user understands why
 *     toggling does nothing
 *
 * Phase γ adds Yggdrasil + Lokinet + DNSCrypt sections here. The
 * structure is identical: status + catalog + on/off, distinct module
 * supervisor per network. See android/OVERLAY_NETWORKS.md.
 *
 * Settings persistence: which provider is selected is stored in
 * [BrowserSettings]; whether the proxy is on is **session-only** by
 * design — every browser launch starts with the proxy off, matching
 * the suite's "ephemeral session" posture for the browser app.
 */
@Composable
fun ProxyScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val status = I2pStatus.state

    var i2pEnabled by remember { mutableStateOf(false) }
    var providerId by remember { mutableStateOf(BrowserSettings.getI2pProviderId(ctx)) }
    val provider = remember(providerId) { I2pProvider.byId(providerId) }

    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(20.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Network proxy", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text(
                    "Optional overlay routing for this browser session.",
                    color = Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                )
            }
            OutlinedButton(onClick = onBack) { Text("Back") }
        }

        Spacer(Modifier.height(16.dp))

        // Status banner — single line summary of the supervisor's
        // current state. Color-coded: amber = needs attention,
        // green = active, neutral = idle.
        StatusBanner(status)

        Spacer(Modifier.height(12.dp))

        // I2P section.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                .padding(14.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Route via I2P", color = Color(0xFFE0E0E0), fontSize = 14.sp)
                    Text(
                        "Tunnels this browser's HTTP traffic through 127.0.0.1:4444. " +
                            "Other apps unaffected — the firewall keeps doing its job " +
                            "independently.",
                        color = Color(0xFF9E9E9E),
                        fontSize = 11.sp,
                    )
                }
                val canToggle = status !is I2pStatus.State.BinaryMissing &&
                    WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)
                Switch(
                    checked = i2pEnabled,
                    enabled = canToggle,
                    onCheckedChange = { wantOn ->
                        Diagnostics.log("browser.Proxy", "I2P toggle: wantOn=$wantOn")
                        if (wantOn) {
                            I2pProxyService.start(ctx)
                            i2pEnabled = true
                            // applyProxyOverride() lands the override
                            // once the supervisor reports Ready —
                            // observed through I2pStatus from the
                            // applyEffect below.
                        } else {
                            ProxyApplier.clear(ctx)
                            I2pProxyService.stop(ctx)
                            i2pEnabled = false
                        }
                    },
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        // Apply / reapply ProxyController override when the supervisor
        // transitions to Ready. We re-read on every recomposition (cheap)
        // because tying it to LaunchedEffect on `status` would miss the
        // "user toggled on AFTER status was already Ready from a previous
        // run" edge case.
        val ready = status as? I2pStatus.State.Ready
        if (i2pEnabled && ready != null) {
            androidx.compose.runtime.LaunchedEffect(ready, i2pEnabled) {
                ProxyApplier.applyHttpLocal(ctx, ready.httpPort)
            }
        }

        // Provider catalog.
        Text(
            "Provider",
            color = Color(0xFFE0E0E0),
            fontSize = 13.sp,
            modifier = Modifier.padding(top = 4.dp, bottom = 4.dp),
        )
        Text(
            "We ship a curated catalog. We do not host any of these.",
            color = Color(0xFF9E9E9E),
            fontSize = 11.sp,
        )
        Spacer(Modifier.height(8.dp))

        // I2P provider catalog. Inlined as a Column instead of a
        // LazyColumn so we can append Lokinet + Yggdrasil status cards
        // below within the same verticalScroll-bound parent Column —
        // the catalog is short (~5 entries), lazy-scroll overhead would
        // exceed the cost of just rendering them.
        Column(
            verticalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            I2pProvider.ALL.forEach { p ->
                ProviderRow(
                    provider = p,
                    isSelected = p.id == providerId,
                    onSelect = {
                        Diagnostics.log("browser.Proxy", "I2P provider pick: ${p.id}")
                        BrowserSettings.setI2pProviderId(ctx, p.id)
                        providerId = p.id
                    },
                )
            }
        }

        Spacer(Modifier.height(20.dp))

        // Other overlay networks — scaffold sections (phase α). The
        // module status singletons ship in this commit; the binaries
        // and supervisor services will land in follow-up phases. Until
        // then these cards are read-only — toggling routing through
        // them via the firewall app will see BinaryMissing and refuse.
        Text("Other overlay networks", color = Color(0xFFE0E0E0), fontSize = 14.sp)
        Text(
            "Scaffold only — daemons not bundled in this build. " +
                "Firewall → Overlay routing reads these states to gate the " +
                "Enforce-routing toggle.",
            color = Color(0xFF707070), fontSize = 11.sp,
        )
        Spacer(Modifier.height(6.dp))
        OtherOverlayStatus(name = "Lokinet", status = lokinetLabel())
        Spacer(Modifier.height(6.dp))
        OtherOverlayStatus(name = "Yggdrasil", status = yggdrasilLabel())
    }
}

@Composable
private fun OtherOverlayStatus(name: String, status: Pair<String, Color>) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF141414), RoundedCornerShape(6.dp))
            .padding(12.dp),
    ) {
        Column {
            Text(name, color = Color(0xFFE0E0E0), fontSize = 12.sp)
            Text(status.first, color = status.second, fontSize = 11.sp)
        }
    }
}

@Composable
private fun lokinetLabel(): Pair<String, Color> = when (val s = LokinetStatus.state) {
    LokinetStatus.State.Idle -> "Idle" to Color(0xFF9E9E9E)
    LokinetStatus.State.BinaryMissing ->
        "Scaffold only — lokinet binary not bundled" to Color(0xFFFFB74D)
    LokinetStatus.State.Starting -> "Starting…" to Color(0xFF90CAF9)
    is LokinetStatus.State.Ready -> "Ready · SOCKS :${s.socksPort}" to Color(0xFF66BB6A)
    is LokinetStatus.State.Error -> "Error: ${s.reason}" to Color(0xFFEF5350)
}

@Composable
private fun yggdrasilLabel(): Pair<String, Color> = when (val s = YggdrasilStatus.state) {
    YggdrasilStatus.State.Idle -> "Idle" to Color(0xFF9E9E9E)
    YggdrasilStatus.State.BinaryMissing ->
        "Scaffold only — yggdrasil binary not bundled" to Color(0xFFFFB74D)
    YggdrasilStatus.State.Starting -> "Starting…" to Color(0xFF90CAF9)
    is YggdrasilStatus.State.Ready ->
        "Ready · ${s.meshIp} (${s.peerCount} peers)" to Color(0xFF66BB6A)
    is YggdrasilStatus.State.Error -> "Error: ${s.reason}" to Color(0xFFEF5350)
}

@Composable
private fun StatusBanner(status: I2pStatus.State) {
    val (label, color) = when (status) {
        I2pStatus.State.Idle -> "Idle — no proxy active" to Color(0xFF9E9E9E)
        I2pStatus.State.BinaryMissing ->
            "Scaffolding only — i2pd binary not bundled in this build (phase α). " +
                "The toggle below is disabled. See android/overlay-i2p/BUILD_RECIPE.md." to
                Color(0xFFFFB74D)
        I2pStatus.State.Starting -> "Starting i2pd…" to Color(0xFF90CAF9)
        is I2pStatus.State.Ready ->
            "Ready · 127.0.0.1:${status.httpPort}" to Color(0xFF66BB6A)
        is I2pStatus.State.Error -> "Error: ${status.reason}" to Color(0xFFEF5350)
    }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF141414), RoundedCornerShape(6.dp))
            .padding(12.dp),
    ) {
        Text(label, color = color, fontSize = 11.sp)
    }
}

@Composable
private fun ProviderRow(
    provider: I2pProvider,
    isSelected: Boolean,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (isSelected) Color(0xFF1A2A1A) else Color(0xFF1C1C1C),
                RoundedCornerShape(6.dp),
            )
            .secureClickable { onSelect() }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(10.dp)
                .background(
                    if (isSelected) Color(0xFF66BB6A) else Color(0xFF424242),
                    RoundedCornerShape(5.dp),
                ),
        )
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(provider.name, color = Color(0xFFE0E0E0), fontSize = 13.sp)
            if (provider.outproxyHost.isNotEmpty()) {
                Text(
                    "outproxy: ${provider.outproxyHost}:${provider.outproxyPort}",
                    color = Color(0xFF707070),
                    fontSize = 10.sp,
                )
            }
            Text(
                provider.privacyNote,
                color = Color(0xFF9E9E9E),
                fontSize = 10.sp,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

/**
 * Thin wrapper around [ProxyController] for the "point WebView at
 * localhost:port" case. Falls back to a logged no-op when the WebView
 * component on this device doesn't support the PROXY_OVERRIDE feature
 * (rare on modern Android but possible on stripped-down OEM builds).
 */
internal object ProxyApplier {
    private val DIRECT_EXECUTOR: Executor = Executor { it.run() }

    fun applyHttpLocal(ctx: Context, port: Int) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            Diagnostics.error("browser.ProxyApplier",
                "PROXY_OVERRIDE not supported by this device's WebView")
            return
        }
        val config = ProxyConfig.Builder()
            .addProxyRule("127.0.0.1:$port")
            .build()
        runCatching {
            ProxyController.getInstance().setProxyOverride(
                config,
                DIRECT_EXECUTOR,
                Runnable {
                    Diagnostics.log("browser.ProxyApplier", "ProxyOverride applied :$port")
                },
            )
        }.onFailure {
            Diagnostics.error("browser.ProxyApplier",
                "setProxyOverride threw: ${it.javaClass.simpleName}")
        }
    }

    fun clear(ctx: Context) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) return
        runCatching {
            ProxyController.getInstance().clearProxyOverride(
                DIRECT_EXECUTOR,
                Runnable {
                    Diagnostics.log("browser.ProxyApplier", "ProxyOverride cleared")
                },
            )
        }
    }
}
