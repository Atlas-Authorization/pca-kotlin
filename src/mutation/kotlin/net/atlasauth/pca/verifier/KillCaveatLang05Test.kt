package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.n
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for [CaveatLang] that the k05 differential oracle (JSON inputs only) cannot reach: non-object middle hops,
 * non-string map keys, a PQ-signed narrow block, the evaluator's own fail-closed catch handlers, and a `null` id colliding with
 * the id "null". Expected values follow the TS reference (caveat-lang.ts): a malformed input is a refusal, never an exception.
 */
class KillCaveatLang05Test {
    private val FAR = n("9000000000000")
    private val ND = m(
        "type" to "needs_discharge", "id" to "kyc", "issuer" to "risk-team", "issuer_class" to "human", "bind" to "chain_hop",
        "ttl_ms" to n("600000"), "require" to l(m("claim" to "kyc_level", "op" to "gte", "value" to n("2"))),
    )

    /** A map whose every read throws [t] (an action / header source the verifier does not control). */
    private fun <V> throwing(t: () -> Throwable): Map<String, V> = object : AbstractMap<String, V>() {
        override val entries: Set<Map.Entry<String, V>> get() = throw t()
    }

    // ---- boundCaveats: a non-object hop or a non-list caveats member before the introducing hop is skipped, not fatal ----
    @Test fun boundCaveatsSkipsMalformedMiddleHops() {
        val g = m("caveats" to l(ND))
        val leaf = m("caveats" to l(ND, m("type" to "sealed")))
        val b = CaveatLang.boundCaveats(g, l(g, n("5"), m("caveats" to "x"), leaf))!!
        assertEquals(listOf(0, 3), b.map { it.hop })
        assertEquals(listOf(Pca.capHash(g), Pca.capHash(leaf)), b.map { it.capHash })
    }

    // ---- dischargeShapeError: a non-string claim key is malformed (refused, not a ClassCastException) ----
    @Test fun dischargeClaimWithNonStringKeyIsMalformed() {
        val d = m(
            "v" to n("1"), "kind" to "pca-discharge", "caveat_id" to "kyc", "issuer" to "risk-team", "cap_hash" to KUtil.B32,
            "bind" to "chain_hop", "claims" to mapOf(1 to "x"), "iat" to n("1"), "not_after" to n("2"), "nonce" to KUtil.B32, "sig" to "x",
        )
        assertEquals("claim '1' is malformed", CaveatLang.dischargeShapeError(d))
    }

    // ---- claimHolds: an op outside eq/neq/gte/lte/in never holds (fail closed even past the shape check) ----
    @Test fun claimHoldsRefusesAnUnknownOp() {
        val holds: Boolean = KUtil.priv(CaveatLang, "claimHolds", m("claim" to "a", "op" to "zz", "value" to n("1")), m("a" to n("1")))
        assertFalse(holds)
        val eq: Boolean = KUtil.priv(CaveatLang, "claimHolds", m("claim" to "a", "op" to "eq", "value" to n("1")), m("a" to n("1")))
        assertTrue(eq)
    }

    // ---- verifyNarrow: an ml-dsa-65 narrow block verifies only under the pq_pk the leaf's holder_pq commits to ----
    @Test fun pqNarrowVerifiesUnderTheLeafHolderPqCommitment() {
        val pq = PqChainTest.pqKey()
        val pqPk = PqChainTest.pk(pq)
        val holder = KUtil.B32
        val leaf = m("issuer" to "x", "holder" to holder, "caveats" to l(), "holder_pq" to Pca.holderPqCommitment(pqPk))
        val cav = l(m("type" to "max_amount", "max" to n("5")))
        val nb = m(
            "v" to n("1"), "kind" to "pca-narrow", "cap_hash" to Pca.capHash(leaf), "holder" to holder, "caveats" to cav,
            "iat" to n("1000"), "not_after" to n("2000"), "nonce" to KUtil.B32, "alg" to "ml-dsa-65", "pq_pk" to pqPk,
        )
        nb["sig"] = PqChainTest.pqSign(pq, IntentArtifacts.artifactMessage(CaveatLang.NARROW_DOMAIN, nb))
        assertNull(CaveatLang.narrowShapeError(nb))
        val ok = CaveatLang.verifyNarrow(nb, leaf, null, 1500L)
        assertTrue(ok.toString(), ok.ok)
        assertEquals(cav, ok.caveats)
        // no holder_pq on the leaf: the block's own pq_pk is never enough
        val unpinned = LinkedHashMap(leaf).also { it.remove("holder_pq") }
        val nb2 = LinkedHashMap(nb).also { it["cap_hash"] = Pca.capHash(unpinned) }
        nb2["sig"] = PqChainTest.pqSign(pq, IntentArtifacts.artifactMessage(CaveatLang.NARROW_DOMAIN, nb2))
        assertEquals("narrow signature invalid", CaveatLang.verifyNarrow(nb2, unpinned, null, 1500L).reason)
    }

    // ---- deriveError: a closed-member error is the reason; later member checks never overwrite it ----
    @Test fun deriveCountMemberErrorIsNotOverwritten() {
        fun derive(d: Any?) = m("type" to "derive", "id" to "d", "defs" to l(d), "check" to m("const" to true))
        val verb = m("name" to "a", "kind" to "count", "window_ms" to n("1000"), "verb" to n("7"), "zz" to n("1"))
        assertEquals("def 'a': unknown member 'count.zz'", CaveatLang.deriveError(derive(verb)))
        val pre = m("name" to "a", "kind" to "count", "window_ms" to n("1000"), "resource_prefix" to n("7"), "zz" to n("1"))
        assertEquals("def 'a': unknown member 'count.zz'", CaveatLang.deriveError(derive(pre)))
        assertNull(CaveatLang.deriveError(derive(m("name" to "a", "kind" to "count", "window_ms" to n("1000")))))
    }

    // ---- evaluateDerive: a non-object action reads as no action; a non-scalar param is an unknown fact ----
    @Test fun deriveActionAndParamEdges() {
        val always = m("type" to "derive", "id" to "d", "defs" to l(), "check" to m("const" to true))
        assertEquals(true, CaveatLang.evaluateDerive(always, 0L, "not-an-object", null, emptyMap()))
        val param = m(
            "type" to "derive", "id" to "d", "defs" to l(m("name" to "p", "kind" to "param", "path" to "a")),
            "check" to m("op" to "neq", "a" to m("ref" to "p"), "b" to m("const" to n("1"))),
        )
        assertNull(CaveatLang.evaluateDerive(param, 0L, m("params" to m("a" to m())), null, emptyMap()))
        assertEquals(true, CaveatLang.evaluateDerive(param, 0L, m("params" to m("a" to n("2"))), null, emptyMap()))
    }

    // ---- evaluateK1: a null id is not the id "null" (only string ids take part in the duplicate count) ----
    @Test fun nullIdDoesNotCollideWithTheIdNull() {
        val g = m("caveats" to l(
            m("type" to "max_uses", "id" to "null", "n" to n("1"), "until" to FAR),
            m("type" to "max_uses", "id" to null, "n" to n("1"), "until" to FAR),
        ))
        val r = CaveatLang.evaluateK1(g, null, CaveatLang.K1Input(), 1000L)
        assertEquals(listOf("max_uses"), r.failed)
        assertEquals(listOf("id is malformed"), r.reasons)
    }

    // ---- evaluateK1: an exception while evaluating is one '<malformed>' refusal, never a throw ----
    private fun deriveOnAction() = m("caveats" to l(m(
        "type" to "derive", "id" to "d", "defs" to l(m("name" to "v", "kind" to "action", "field" to "verb")), "check" to m("const" to true),
    )))

    @Test fun evaluateK1RuntimeExceptionFailsClosed() {
        val r = CaveatLang.evaluateK1(deriveOnAction(), null, CaveatLang.K1Input(), 1000L, throwing<Any?> { IllegalStateException("boom") })
        assertFalse(r.ok)
        assertEquals(listOf("<malformed>"), r.failed)
        assertEquals(listOf("caveat language error (fail closed): boom"), r.reasons)
        assertEquals(emptyList<Any?>(), r.plain)
        assertEquals(emptyList<Any?>(), r.bound)
    }

    @Test fun evaluateK1StackOverflowFailsClosed() {
        val r = CaveatLang.evaluateK1(deriveOnAction(), null, CaveatLang.K1Input(), 1000L, throwing<Any?> { StackOverflowError() })
        assertFalse(r.ok)
        assertEquals(listOf("<malformed>"), r.failed)
        assertEquals(listOf("caveat language error (fail closed): unknown"), r.reasons)
        assertEquals(emptyList<Any?>(), r.plain)
        assertEquals(emptyList<Any?>(), r.bound)
    }

    // ---- presentedK1: a StackOverflowError while reading headers is an unreadable-headers error ----
    @Test fun presentedK1StackOverflowIsAnError() {
        val p = CaveatLang.presentedK1(throwing<String?> { StackOverflowError() })
        assertFalse(p.ok)
        assertNull(p.discharges)
        assertSame(CaveatLang.K1Input.ABSENT, p.narrow)
        assertEquals("unknown", p.error)
    }
}
