package com.understory.browser

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import com.understory.overlay.i2p.I2pProxyService
import com.understory.overlay.i2p.I2pStatus
import com.understory.security.Diagnostics
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import java.util.concurrent.Executor

/**
 * Browser proxy / overlay-network screen — ENG BUILDS ONLY.
 *
 * v2 (design §6) shrinks this honestly: the entire surface is gated behind
 * the eng build (the caller in [MainActivity] only composes the entry point
 * when `applicationId` ends `.eng`), because phase α ships no I2P binary, so
 * a prod build has nothing honest to show.
 *
 * Dropped from the UI vs v1:
 *   - Lokinet + Yggdrasil status cards — both VpnService/TUN designs,
 *     permanently vetoed (they'd take the single VpnService slot Tailscale
 *     holds). The browser no longer advertises them.
 *   - The I2P provider picker + "Custom (advanced)" — nothing consumed the
 *     persisted provider id, and "Custom" pointed at a screen that never
 *     existed. The catalog data + tests stay in `:overlay-i2p` for phase β;
 *     they just aren't rendered. This also removes the `secureClickable`
 *     misuse (deletion, not replacement).
 *
 * The I2P switch is now a pure function of supervisor state — never a
 * latched local bool — so it can't render the stuck checked+disabled bug.
 * The ProxyController override is applied at the AppRoot level (keyed on
 * [I2pStatus.state]), not inside this screen's composition, so a Ready
 * transition applies even if the user has navigated back out.
 */
@Composable
fun ProxyScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val status = I2pStatus.state

    // `checked` derives from status, not a free local bool. Phase α can
    // only reach BinaryMissing, so in practice the switch renders disabled
    // with the banner explaining why — never checked+disabled.
    val checked = status is I2pStatus.State.Ready
    val proxyOverrideSupported = WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)
    val canToggle = proxyOverrideSupported &&
        (status is I2pStatus.State.Ready || status is I2pStatus.State.Idle)

    SuiteScaffold(
        title = stringResource(R.string.proxy_title),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
        ) {
            Text(
                stringResource(R.string.proxy_sub),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )

            Spacer(Modifier.height(UnderstoryTheme.spacing.md))

            StatusBanner(status)

            Spacer(Modifier.height(UnderstoryTheme.spacing.md))

            SuiteCard {
                SwitchRow(
                    label = stringResource(R.string.proxy_i2p_title),
                    supporting = stringResource(R.string.proxy_i2p_body),
                    checked = checked,
                    enabled = canToggle,
                    onCheckedChange = { wantOn ->
                        Diagnostics.log("browser.Proxy", "I2P toggle: wantOn=$wantOn")
                        if (wantOn) {
                            // The supervisor probes for the binary on start;
                            // at Idle this transitions toward Starting/Ready
                            // or BinaryMissing. The AppRoot applier lands the
                            // override on Ready.
                            I2pProxyService.start(ctx)
                        } else {
                            ProxyApplier.clear(ctx)
                            I2pProxyService.stop(ctx)
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun StatusBanner(status: I2pStatus.State) {
    val (label, color) = when (status) {
        I2pStatus.State.Idle ->
            stringResource(R.string.proxy_status_idle) to MaterialTheme.colorScheme.onSurfaceVariant
        I2pStatus.State.BinaryMissing ->
            stringResource(R.string.proxy_status_missing) to UnderstoryTheme.semantic.warning
        I2pStatus.State.Starting ->
            stringResource(R.string.proxy_status_starting) to MaterialTheme.colorScheme.primary
        is I2pStatus.State.Ready ->
            stringResource(R.string.proxy_status_ready, status.httpPort) to UnderstoryTheme.semantic.success
        is I2pStatus.State.Error ->
            stringResource(R.string.proxy_status_error, status.reason) to MaterialTheme.colorScheme.error
    }
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            label,
            color = color,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(UnderstoryTheme.spacing.md),
        )
    }
}

/**
 * Applies the ProxyController override when the I2P supervisor reaches
 * Ready, and clears it otherwise. Hosted at the AppRoot (design §6.4) so a
 * Ready transition applies even if the user has left the proxy overlay.
 * Eng-only in practice — the caller gates it behind the eng build.
 */
@Composable
fun ProxyOverrideEffect() {
    val ctx = LocalContext.current
    val status = I2pStatus.state
    LaunchedEffect(status) {
        when (val s = status) {
            is I2pStatus.State.Ready -> ProxyApplier.applyHttpLocal(ctx, s.httpPort)
            else -> ProxyApplier.clear(ctx)
        }
    }
}

/**
 * Thin wrapper around [ProxyController] for the "point WebView at
 * localhost:port" case. Falls back to a logged no-op when the WebView
 * component on this device doesn't support the PROXY_OVERRIDE feature.
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
