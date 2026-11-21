package net.atlasauth.pca.verifier

import org.junit.Test

/**
 * Differential test against the TypeScript reference: the salted ledger commit and its opening, the root of a commit sequence, the v2
 * goal parser, the profile revocation scope and exposure window, and the budget-allocation caveat.
 */
@Suppress("UNCHECKED_CAST")
class CoreKotlinGapsDiffTest {
    private val module = "ref-core-kotlin-gaps"

    @Test fun entryCommit() = OracleCases.each(module, "entryCommit") { a -> Ledger.entryCommit(a[0] as String, a[1]) }

    @Test fun verifyOpening() = OracleCases.each(module, "verifyOpening") { a -> Ledger.verifyOpening(a[0] as String, a[1]) }

    @Test fun ledgerRootOf() = OracleCases.each(module, "ledgerRootOf") { a -> Ledger.ledgerRootOf((a[0] as List<Any?>).map { it as String }) }

    @Test fun parseIntentGoalV2() = OracleCases.each(module, "parseIntentGoalV2") { a -> IntentSession.parseIntentGoalV2(a[0]) }

    @Test fun profileRevocationScope() = OracleCases.each(module, "profileRevocationScope") { a -> IntentRevocation.profileRevocationScope(a[0] as String) }

    @Test fun revocationExposureEnd() = OracleCases.each(module, "revocationExposureEnd") { a ->
        val skew = IntentJs.num(a[2])
        if (skew == null) IntentRevocation.revocationExposureEnd(IntentJs.num(a[0])!!, IntentJs.num(a[1])!!)
        else IntentRevocation.revocationExposureEnd(IntentJs.num(a[0])!!, IntentJs.num(a[1])!!, skew)
    }

    @Test fun budgetAllocCaveat() = OracleCases.each(module, "budgetAllocCaveat") { a -> Pca.budgetAllocCaveat(IntentJs.num(a[0])!!) }
}
