package com.understory.browser

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import com.understory.elevation.Elevation
import com.understory.elevation.Outcome
import com.understory.elevation.PrivateDnsMode
import com.understory.elevation.ui.ElevationCard
import com.understory.elevation.ui.rememberElevationState
import com.understory.security.Diagnostics
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.ConfirmDestructiveDialog
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Browser Hardening screen — the app's FIRST elevated surface.
 *
 * Three opt-in, reversible actions, each fail-closed on `canRunShell`:
 *   1. Strip camera / mic / location from ANOTHER installed browser.
 *   2. Freeze (suspend) a flagged app — reversible, never an uninstall.
 *   3. Pin strict Private DNS — with a live snapshot + Restore.
 *
 * Doctrine:
 *  - When Shizuku is not granted the whole action area is REPLACED by the shared
 *    [ElevationCard] grant flow — never a dead/greyed control that does nothing.
 *  - Destructive-shaped confirms go through [ConfirmDestructiveDialog].
 *  - Cross-app targets are hard-excluded (self, suite, Tailscale, Shizuku/Sui,
 *    launcher, Settings) in [BrowserHardening].
 *  - Every [Outcome] is reported honestly through [showSnack].
 *  - The Private-DNS snapshot degrades to "unavailable" on a read miss.
 */
@Composable
fun HardeningScreen(
    onBack: () -> Unit,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    val ctx = LocalContext.current

    // refreshKey bumps after a grant so rememberElevationState re-reads the tier
    // (returning from the Shizuku prompt doesn't recompose on its own).
    var refreshKey by remember { mutableIntStateOf(0) }
    val elevation = rememberElevationState(refreshKey)

    SuiteScaffold(
        title = stringResource(R.string.hard_title),
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
                stringResource(R.string.hard_sub),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )

            Spacer(Modifier.height(UnderstoryTheme.spacing.md))

            if (!elevation.isElevated) {
                // Fail-closed: no dead controls. The grant flow (or the honest
                // rootless fallback) is the ONLY thing shown until Shizuku is on.
                ElevationCard(
                    unlocks = listOf(
                        stringResource(R.string.hard_unlock_browsers),
                        stringResource(R.string.hard_unlock_freeze),
                        stringResource(R.string.hard_unlock_dns),
                    ),
                    rootlessFallback = stringResource(R.string.hard_rootless_fallback),
                    onRootlessFallback = { openThisAppInfo(ctx) },
                )
                // Re-read the tier when the user returns from the grant prompt.
                LaunchedEffect(Unit) { refreshKey++ }
            } else {
                BrowserPermSection(showSnack = showSnack)
                Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
                FreezeSection(showSnack = showSnack)
                Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
                PrivateDnsSection(showSnack = showSnack)
            }
        }
    }
}

// ---- Section 1: strip risky perms from another browser ----------------------

@Composable
private fun BrowserPermSection(
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var browsers by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<InstalledApp?>(null) }
    // A pending (perm,target) awaiting a plain-English confirm.
    var pending by remember { mutableStateOf<Pair<BrowserHardening.RiskyPerm, InstalledApp>?>(null) }

    LaunchedEffect(Unit) {
        browsers = withContext(Dispatchers.Default) { BrowserHardening.installedBrowsers(ctx) }
        loaded = true
    }

    SuiteSectionHeader(stringResource(R.string.hard_browsers_header))
    SuiteCard {
        Text(
            stringResource(R.string.hard_browsers_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.md))

        when {
            loaded && browsers.isEmpty() ->
                Text(
                    stringResource(R.string.hard_browsers_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = UnderstoryTheme.semantic.dim,
                )
            else -> {
                AppPicker(
                    label = stringResource(R.string.hard_browsers_pick),
                    apps = browsers,
                    selected = selected,
                    onSelect = { selected = it },
                )
                selected?.let { target ->
                    Spacer(Modifier.height(UnderstoryTheme.spacing.md))
                    BrowserHardening.RiskyPerm.entries.forEach { perm ->
                        SuiteListRow(
                            headline = permLabel(perm),
                            supporting = stringResource(R.string.hard_perm_revoke),
                            trailing = {
                                SecureOutlinedButton(onClick = { pending = perm to target }) {
                                    Text(stringResource(R.string.hard_perm_revoke))
                                }
                            },
                        )
                    }
                }
            }
        }
    }

    // Plain-English confirm before any revoke. Not requireHold — revoking a
    // permission is reversible, so a hold-to-confirm would be theater.
    pending?.let { (perm, target) ->
        val permName = permLabel(perm)
        ConfirmDestructiveDialog(
            visible = true,
            title = stringResource(R.string.hard_perm_confirm_title, permName, target.label),
            body = stringResource(R.string.hard_perm_confirm_body, permName, target.label),
            confirmLabel = stringResource(R.string.hard_perm_revoke),
            onConfirm = {
                pending = null
                scope.launch {
                    Diagnostics.log("browser.Hardening", "revoke ${perm.name} from target")
                    // Revoke the runtime permission, then set the app-op to ignore
                    // so a lingering grant can't be used. Report the FIRST failure
                    // honestly; a success needs both.
                    val a = Elevation.revokePermission(ctx, target.pkg, perm.manifestPermission)
                    val b = if (a is Outcome.Success) {
                        Elevation.setAppOpMode(ctx, target.pkg, perm.appOp, "ignore")
                    } else a
                    reportOutcome(
                        ctx, b, showSnack,
                        success = ctx.getString(R.string.hard_perm_done, permName, target.label),
                    )
                }
            },
            onDismiss = { pending = null },
        )
    }
}

// ---- Section 2: freeze a flagged app ----------------------------------------

@Composable
private fun FreezeSection(
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var selected by remember { mutableStateOf<InstalledApp?>(null) }
    var alsoForceStop by remember { mutableStateOf(false) }
    var confirming by remember { mutableStateOf<InstalledApp?>(null) }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.Default) { BrowserHardening.freezableApps(ctx) }
    }

    SuiteSectionHeader(stringResource(R.string.hard_freeze_header))
    SuiteCard {
        Text(
            stringResource(R.string.hard_freeze_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.md))

        AppPicker(
            label = stringResource(R.string.hard_freeze_pick),
            apps = apps,
            selected = selected,
            onSelect = { selected = it },
        )

        selected?.let { target ->
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SwitchRow(
                label = stringResource(R.string.hard_freeze_forcestop),
                checked = alsoForceStop,
                onCheckedChange = { alsoForceStop = it },
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
            ) {
                SecureButton(onClick = { confirming = target }) {
                    Text(stringResource(R.string.hard_freeze_action))
                }
                // Unfreeze is always safe + reversible — no confirm needed.
                SecureOutlinedButton(onClick = {
                    scope.launch {
                        val r = Elevation.setAppSuspended(ctx, target.pkg, false)
                        reportOutcome(
                            ctx, r, showSnack,
                            success = ctx.getString(R.string.hard_unfreeze_done, target.label),
                        )
                    }
                }) {
                    Text(stringResource(R.string.hard_unfreeze_action))
                }
            }
        }
    }

    confirming?.let { target ->
        ConfirmDestructiveDialog(
            visible = true,
            title = stringResource(R.string.hard_freeze_confirm_title, target.label),
            body = stringResource(R.string.hard_freeze_confirm_body, target.label),
            confirmLabel = stringResource(R.string.hard_freeze_action),
            onConfirm = {
                confirming = null
                scope.launch {
                    Diagnostics.log("browser.Hardening", "freeze target (forceStop=$alsoForceStop)")
                    val r = Elevation.setAppSuspended(ctx, target.pkg, true)
                    if (r is Outcome.Success) {
                        if (alsoForceStop) {
                            val f = Elevation.forceStop(ctx, target.pkg)
                            reportOutcome(
                                ctx, f, showSnack,
                                success = ctx.getString(R.string.hard_forcestop_done, target.label),
                            )
                        } else {
                            showSnack(ctx.getString(R.string.hard_freeze_done, target.label), null, null)
                        }
                    } else {
                        reportOutcome(ctx, r, showSnack, success = null)
                    }
                }
            },
            onDismiss = { confirming = null },
        )
    }
}

// ---- Section 3: private DNS pin ---------------------------------------------

@Composable
private fun PrivateDnsSection(
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var host by remember { mutableStateOf("") }
    var snapshot by remember { mutableStateOf<PrivateDnsSnapshot>(PrivateDnsSnapshot.Unknown) }
    var snapshotKey by remember { mutableIntStateOf(0) }
    var confirming by remember { mutableStateOf(false) }

    LaunchedEffect(snapshotKey) {
        snapshot = BrowserHardening.readPrivateDnsSnapshot(ctx)
    }

    SuiteSectionHeader(stringResource(R.string.hard_dns_header))
    SuiteCard {
        Text(
            stringResource(R.string.hard_dns_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

        // Live snapshot — degrades to "unavailable" on a read miss (fail-open).
        val current = BrowserHardening.snapshotDisplay(snapshot)
        Text(
            text = if (current != null) stringResource(R.string.hard_dns_current, current)
            else stringResource(R.string.hard_dns_current_unknown),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )

        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

        // Honest MagicDNS-shadowing warning.
        Text(
            stringResource(R.string.hard_dns_warning),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.warning,
        )

        Spacer(Modifier.height(UnderstoryTheme.spacing.md))

        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            singleLine = true,
            label = { Text(stringResource(R.string.hard_dns_hint)) },
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Uri,
                imeAction = ImeAction.Done,
            ),
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(UnderstoryTheme.spacing.md))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            SecureButton(onClick = {
                if (!BrowserHardening.looksLikeDnsHost(host)) {
                    showSnack(ctx.getString(R.string.hard_dns_need_host), null, null)
                } else {
                    confirming = true
                }
            }) {
                Text(stringResource(R.string.hard_dns_pin))
            }
            SecureOutlinedButton(onClick = {
                scope.launch {
                    Diagnostics.log("browser.Hardening", "restore Private DNS -> automatic")
                    // Restore = back to opportunistic (Automatic), the platform
                    // default. We don't try to re-pin a prior strict host we may
                    // not have captured; Automatic is the safe, honest reset.
                    val r = Elevation.setPrivateDns(ctx, PrivateDnsMode.AUTOMATIC, null)
                    reportOutcome(
                        ctx, r, showSnack,
                        success = ctx.getString(R.string.hard_dns_restored),
                    )
                    snapshotKey++
                }
            }) {
                Text(stringResource(R.string.hard_dns_restore))
            }
        }
    }

    if (confirming) {
        val h = host.trim()
        ConfirmDestructiveDialog(
            visible = true,
            title = stringResource(R.string.hard_dns_pin_confirm_title, h),
            body = stringResource(R.string.hard_dns_pin_confirm_body, h),
            confirmLabel = stringResource(R.string.hard_dns_pin),
            onConfirm = {
                confirming = false
                scope.launch {
                    Diagnostics.log("browser.Hardening", "pin Private DNS (strict)")
                    val r = Elevation.setPrivateDns(ctx, PrivateDnsMode.HOSTNAME, h)
                    reportOutcome(
                        ctx, r, showSnack,
                        success = ctx.getString(R.string.hard_dns_pinned, h),
                    )
                    snapshotKey++
                }
            },
            onDismiss = { confirming = false },
        )
    }
}

// ---- shared bits ------------------------------------------------------------

/**
 * A minimal single-select app picker: a scrollable list of [SuiteListRow]s. The
 * selected row reads its label as the chosen app. Kept inline (not a dropdown)
 * so the whole choice is visible + TalkBack-friendly.
 */
@Composable
private fun AppPicker(
    label: String,
    apps: List<InstalledApp>,
    selected: InstalledApp?,
    onSelect: (InstalledApp) -> Unit,
) {
    Text(
        label,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    apps.forEach { app ->
        val isSel = app.pkg == selected?.pkg
        SuiteListRow(
            headline = app.label,
            supporting = app.pkg,
            trailing = if (isSel) {
                { Text("✓", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary) }
            } else null,
            onClick = { onSelect(app) },
        )
    }
}

@Composable
private fun permLabel(perm: BrowserHardening.RiskyPerm): String = when (perm) {
    BrowserHardening.RiskyPerm.CAMERA -> stringResource(R.string.hard_perm_camera)
    BrowserHardening.RiskyPerm.MIC -> stringResource(R.string.hard_perm_mic)
    BrowserHardening.RiskyPerm.LOCATION -> stringResource(R.string.hard_perm_location)
}

/** Honestly surface an [Outcome]: success line, or the Unsupported/Failed reason. */
private fun reportOutcome(
    ctx: android.content.Context,
    outcome: Outcome,
    showSnack: (String, String?, (() -> Unit)?) -> Unit,
    success: String?,
) {
    when (outcome) {
        is Outcome.Success ->
            if (success != null) showSnack(success, null, null)
        is Outcome.Unsupported ->
            showSnack(ctx.getString(R.string.hard_outcome_unsupported, outcome.reason), null, null)
        is Outcome.Failed ->
            showSnack(ctx.getString(R.string.hard_outcome_failed, outcome.message), null, null)
    }
}

/** Deep-link to THIS app's App-info screen (the rootless-fallback action). */
private fun openThisAppInfo(ctx: android.content.Context) {
    runCatching {
        val intent = android.content.Intent(
            android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            android.net.Uri.fromParts("package", ctx.packageName, null),
        ).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(intent)
    }.onFailure {
        Diagnostics.error("browser.Hardening", "open app info failed: ${it.javaClass.simpleName}")
    }
}
