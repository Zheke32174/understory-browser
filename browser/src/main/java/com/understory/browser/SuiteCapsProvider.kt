package com.understory.browser

import com.understory.security.BaseCapabilityProvider

/**
 * browser's capability beacon. Consumers translate
 * `(com.understory.browser, version=1)` into [SuiteCapability.HARDENED_BROWSER]
 * via their KNOWN_PEERS table.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
