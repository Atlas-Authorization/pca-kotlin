package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.AuthorizeTestKit.case
import net.atlasauth.pca.verifier.AuthorizeTestKit.grant
import net.atlasauth.pca.verifier.AuthorizeTestKit.pcactn
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `Authorize.authorize` with caveat language v2 (`Input.k1`, `Input.usesStore`). The K1 caveats are appended to the leaf hop of a
 * signed fixture; the edit breaks the hop signature, so the module-internal [Authorize.coreHook] takes the core verdict out of
 * the picture and these tests judge only the policy layer.
 */
@Suppress("UNCHECKED_CAST")
class CaveatLangAuthorizeTest {
    private val c = case("delegated-max-spend-within")

    @After
    fun reset() { Authorize.coreHook = null }

    private fun withLeafCaveats(vararg extra: String): Map<String, Any?> {
        val p = IntentJs.normalize(pcactn(c)) as MutableMap<String, Any?>
        val chain = p["cap_chain"] as MutableList<Any?>
        val leaf = chain[chain.size - 1] as MutableMap<String, Any?>
        val cs = leaf["caveats"] as MutableList<Any?>
        for (e in extra) cs.add(ParityVectors.parse(e))
        Authorize.coreHook = { core ->
            for (k in core.checks.keys.toList()) core.checks[k] = true
            for (k in listOf("counter_format", "audience", "validity", "grant_ref_bound")) core.checks[k] = true
            core.reasons.clear()
            core.reason = ""
            core.allow = true
        }
        return p
    }

    private fun run(p: Map<String, Any?>, k1: CaveatLang.K1Input? = null, uses: Authorize.StateStore? = null, store: Authorize.StateStore = Authorize.MemoryStateStore()) =
        Authorize.authorize(
            p,
            Authorize.Input(
                operation = AuthorizeTestKit.op(c), audience = AuthorizeTestKit.AUD, resolveGrant = { grant(c) }, stateStore = store,
                isRevoked = { _, _ -> false }, now = AuthorizeTestKit.NOW, plan = Authorize.SINGLE_STEP, k1 = k1, usesStore = uses,
            ),
        )

    @Test
    fun withoutAK1CaveatNothingChanges() {
        val p = withLeafCaveats()
        assertTrue(run(p).reasons.toString(), run(p).allow)
        assertTrue(run(p, CaveatLang.K1Input()).allow)
    }

    @Test
    fun aK1CaveatIsRefusedWithoutK1AndEvaluatedWithIt() {
        val p = withLeafCaveats("""{"type":"sealed"}""")
        val off = run(p)
        assertFalse(off.allow)
        assertEquals("fail", off.checks["delegated_caveats"])
        assertTrue(off.reasons.toString(), off.reasons.any { it.contains("sealed") && it.contains("not configured (no k1 input)") })
        val on = run(p, CaveatLang.K1Input())
        assertTrue(on.reasons.toString(), on.allow)
    }

    @Test
    fun aMissingDischargeRefusesWithTheK1Reason() {
        val p = withLeafCaveats("""{"type":"needs_discharge","id":"kyc","issuer":"risk","issuer_class":"human","bind":"chain_hop","ttl_ms":60000,"require":[]}""")
        val r = run(p, CaveatLang.K1Input())
        assertFalse(r.allow)
        assertEquals("fail", r.checks["delegated_caveats"])
        assertTrue(r.reasons.toString(), r.reasons.any { it.contains("needs_discharge") && it.contains("no discharge presented") })
    }

    @Test
    fun maxUsesIsSpentAfterTheCounterAndNeedsAStore() {
        val p = withLeafCaveats("""{"type":"max_uses","id":"u","n":1,"until":${AuthorizeTestKit.NOW + 100_000}}""")
        val noStore = run(p, CaveatLang.K1Input())
        assertFalse(noStore.allow)
        assertEquals("fail", noStore.checks["max_uses"])
        assertTrue(noStore.reasons.toString(), noStore.reasons.any { it.contains("no usesStore") })
        val uses = Authorize.MemoryStateStore()
        val first = run(p, CaveatLang.K1Input(), uses)
        assertTrue(first.reasons.toString(), first.allow)
        val second = run(p, CaveatLang.K1Input(), uses) // a fresh replay store: only the use count refuses
        assertFalse(second.allow)
        assertEquals("fail", second.checks["max_uses"])
        assertTrue(second.reasons.toString(), second.reasons.any { it.contains("max_uses 'u' is exhausted") })
    }

    @Test
    fun aRefusedActionSpendsNoUse() {
        val p = withLeafCaveats("""{"type":"max_uses","id":"u","n":1,"until":${AuthorizeTestKit.NOW + 100_000}}""", """{"type":"needs_discharge","id":"kyc","issuer":"risk","issuer_class":"human","bind":"chain_hop","ttl_ms":60000,"require":[]}""")
        val uses = Authorize.MemoryStateStore()
        assertFalse(run(p, CaveatLang.K1Input(), uses).allow)
        val bound = CaveatLang.boundCaveats(grant(c), p["cap_chain"])!!.first { CaveatLang.isK1Caveat(it.caveat) && (it.caveat as Map<*, *>)["type"] == CaveatLang.MAX_USES }
        assertEquals(null, uses.last(CaveatLang.maxUsesSlotKey(bound.capHash, "u", 0)))
    }
}
