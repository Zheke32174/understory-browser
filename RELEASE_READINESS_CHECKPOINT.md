# Release-readiness checkpoint

## Identity

- Repository: `Zheke32174/understory-browser`
- Checkpoint branch: `security/public-signing-containment-v1`
- Reviewed default head: `63f86dc6be25d1b392a8f543b7ccedd9272a8794`
- Validated complete branch head: `f2fb9b77d63826197a240ff843015a51e659a68d`
- Coordination: `Zheke32174/understory-common#3`

## Last completed scope

Public signing identity, APK publication authority, current-tree key exposure,
install-verification claims, vendored trust primitives, debug assembly, unit
tests, security reporting, licensing presence, and durable public-presentation
policy.

## Resolved on this draft

- Removed the shared public debug private key from the current tree.
- Removed committed debug-signing configuration.
- Revoked debug signatures for authorship, sibling identity, and capabilities.
- Replaced automatic latest-release publication with read-only validation.
- Removed tag force-update and release-asset overwrite authority.
- Corrected install-verification, CI-artifact, and public-distribution claims.
- Added security guidance, incident provenance, key ignore rules, and a
  deterministic signing-boundary validator that rejects stale README trust
  claims.
- Verified the repaired tree assembles and its unit tests pass.

## Validation receipts

GitHub Actions run `29920487397` passed at exact complete branch head
`f2fb9b77d63826197a240ff843015a51e659a68d`:

- immutable read-only checkout;
- public signing and presentation boundary validation;
- Android SDK provisioning;
- debug APK assembly without a committed suite signing key;
- complete Gradle unit-test execution.

Earlier implementation head `e41451b6b474623ebae5a577e62973709dce69dc`
also passed run `29918227985` before the presentation invariant was added.

## Changed conclusion

The current source, presentation, build, and test boundary is green. The
repository is not publishable because historical artifacts, release governance,
licensing, and an authorized signed candidate remain unresolved.

## Open blockers

- The key remains reachable in public history and prior artifacts/releases.
- Existing movable tags and release assets need an explicit steward disposition.
- No independently verified signed release candidate exists.
- No immutable versioned publication workflow is approved.
- The repository has no explicit license; no license was invented.
- Offline release-key custody remains unverified.
- Branch rules, secret scanning, push protection, private vulnerability
  reporting, and immutable-release settings need administrative verification.
- All sibling repositories must complete the same exact-head boundary before the
  suite can claim coordinated release identity.

## Reconsideration triggers

New commit, changed CI, newly discovered key material, changed release asset,
license decision, signing rotation, changed public claim, changed repository
visibility, or explicit steward request.

## Next action

Review the remaining sibling receipts, select a source license, and decide the
disposition of prior public debug releases before designing any authenticated
release candidate.
