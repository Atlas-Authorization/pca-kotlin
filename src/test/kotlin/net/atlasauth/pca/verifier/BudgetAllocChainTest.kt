package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** capability.ts:174-193 allocationsMonotone, run in the chain check: a child never allocates more than its parent carried. */
class BudgetAllocChainTest {
    private val root = Keys.ed25519(Keys.edGenerate())
    private val agent = Keys.ed25519(Keys.edGenerate())
    private fun alloc(limit: Any?) = Issue.obj("type" to "budget_alloc", "limit" to limit)
    private fun other() = Issue.obj("type" to "ttl")

    private fun chain(parent: List<Any?>, added: List<Any?>): String {
        val r = Issue.mintRoot(root, agent.id()!!, null, parent)
        val leaf = Issue.attenuate(r, added, agent)
        return Pca.verifyChain(listOf(r, leaf), root.id()!!, true, null)
    }

    @Test
    fun aChildCannotWidenItsAllocation() {
        assertEquals("", chain(listOf(alloc(10L)), listOf(alloc(10L), alloc(4L))))
        assertEquals("", chain(listOf(alloc(10L)), listOf(other(), alloc(0L))))
        assertEquals("", chain(listOf(other()), emptyList()))
        assertEquals(
            "budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)",
            chain(listOf(alloc(10L)), listOf(alloc(100L))),
        )
        // an unrelated caveat in between does not reset the carried allocation, and a fraction prints as JS prints it
        assertEquals(
            "budget_alloc caveat 2: allocation 6.5 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)",
            chain(listOf(alloc(5L), other()), listOf(alloc(Json.Num("6.5")))),
        )
    }

    @Test
    fun aMalformedLimitIsRefused() {
        val want = "budget_alloc caveat 0: limit must be a finite number >= 0"
        assertEquals(want, chain(listOf(alloc("3")), emptyList()))
        assertEquals(want, chain(listOf(Issue.obj("type" to "budget_alloc")), emptyList()))
        assertEquals(want, chain(listOf(alloc(-1L)), emptyList()))
        assertEquals("", chain(listOf(alloc(0L)), emptyList()))
    }
}
