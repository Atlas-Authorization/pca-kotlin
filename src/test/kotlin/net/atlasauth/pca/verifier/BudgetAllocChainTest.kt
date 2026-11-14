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

    /** A root signed by hand with the given `caveats` member (absent when [present] is false): only the leaf rule can refuse it. */
    private fun rootWith(present: Boolean, caveats: Any?): String {
        val body = LinkedHashMap<String, Any?>()
        body["issuer"] = root.id()
        body["holder"] = agent.id()
        if (present) body["caveats"] = caveats
        body["parent"] = null
        val digest = Pca.hashCanonical(body)
        val sig = root.sign(Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32)!!)).first
        val cap = LinkedHashMap<String, Any?>()
        cap["id"] = digest
        cap["issuer"] = root.id()
        cap["holder"] = agent.id()
        if (present) cap["caveats"] = caveats
        cap["body_digest"] = digest
        cap["sig"] = sig
        return Pca.verifyChain(listOf(cap), root.id()!!, true, null)
    }

    @Test
    fun aLeafWhoseCaveatsAreNotAnArrayIsMalformed() {
        assertEquals("", rootWith(true, emptyList<Any?>())) // the control: a well-formed empty list passes
        // the chain's well-typed check (capability.ts wellTyped) refuses such a capability before the allocation rule runs
        val why = "hop 0: malformed capability"
        assertEquals(why, rootWith(false, null))
        assertEquals(why, rootWith(true, null))
        assertEquals(why, rootWith(true, LinkedHashMap<String, Any?>()))
        assertEquals(why, rootWith(true, "x"))
        assertEquals(why, rootWith(true, 5L))
        // the allocation rule itself refuses a missing or non-array list
        for (v in listOf<Any?>(null, LinkedHashMap<String, Any?>(), "x", 5L)) assertEquals("malformed caveats", Pca.allocationsMonotone(v))
    }
}
