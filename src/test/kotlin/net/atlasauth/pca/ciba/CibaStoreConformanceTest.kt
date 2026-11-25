package net.atlasauth.pca.ciba

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The store and broker conformance cases, run against the in-memory approval store (the reference store of the kit). */
class CibaStoreConformanceTest {
    @Test fun theMemoryStoreMeetsTheStoreContract() {
        // a memory store has no backing location to reopen, so the durability case is checked with a "reopen" that returns the same object
        val cases = CibaStoreConformance.approvalStoreCases({ CibaApproval.createMemoryApprovalStore() }) { previous -> previous }
        assertEquals(12, cases.size)
        for (c in cases) c.run()
    }

    @Test fun theBrokerKeepsOneDecisionAndOneRedemptionOverTheMemoryStore() {
        val cases = CibaStoreConformance.approvalBrokerCases { CibaApproval.createMemoryApprovalStore() }
        assertEquals(3, cases.size)
        for (c in cases) c.run()
    }

    @Test fun aBrokenStoreFailsTheCases() {
        // a store whose cas ignores the expected version must fail the contract
        val broken = object : CibaApproval.ApprovalStore {
            private val m = HashMap<String, CibaApproval.Versioned>()
            @Synchronized override fun get(key: String): CibaApproval.Versioned? = m[key]
            @Synchronized override fun cas(key: String, expectedVersion: Long, value: Any?): Boolean {
                m[key] = CibaApproval.Versioned((m[key]?.version ?: 0L) + 1, value)
                return true
            }
        }
        var failed = 0
        for (c in CibaStoreConformance.approvalStoreCases({ broken })) try { c.run() } catch (e: AssertionError) { failed++ }
        assertTrue(failed > 0)
    }
}
