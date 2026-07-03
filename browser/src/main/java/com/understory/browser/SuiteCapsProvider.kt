package com.understory.browser

import com.understory.security.BaseCapabilityProvider

/**
 * browser's capability beacon. It attests only "I am
 * com.understory.browser at version 1" — the capability *meaning* is the
 * consumer's local knowledge (`SuiteCapabilityRegistry.KNOWN_PEERS`).
 *
 * At v1 the authoritative registry maps this app to an EMPTY capability
 * set (BEACON RULE): the browser has no peer-invocable IPC surface. The
 * v2 share-target / VIEW intake is a user-facing doorway from the system
 * share sheet, not a signature-gated peer-callable path, so it does not
 * yet back the [SuiteCapability.HARDENED_BROWSER] "open in trusted
 * browser" hand-off a peer could compose against. The browser is still a
 * full suite member (discovered, cert-checked, tier-counted) — it simply
 * offers no capability to peers until that IPC ships, at which point the
 * capability is added at a new version row across all consumers in one
 * coordinated change. Do not claim HARDENED_BROWSER here before then.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
