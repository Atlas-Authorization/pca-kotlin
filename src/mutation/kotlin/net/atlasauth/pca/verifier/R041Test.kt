package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.n
import java.math.BigDecimal
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** PCA 0.4.1: per-suite threshold-share wire validation and the policy-layer root-caveat helpers (incl. `max_spend`). */
class R041Test {
    private fun b(n: Int) = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(n))
    private fun share(vararg extra: Pair<String, Any?>) = m("role" to "guardian", "publicKey" to b(32), *extra)
    private fun sw(s: Map<String, Any?>) = Pq.validateShareSignatureWire(s)

    // ---- Fix 2: share signature per suite ----------------------------------------------------------------

    @Test fun shareWireAcceptsEachImplementedSuite() {
        assertNull(sw(share("sig" to b(64))))
        assertNull(sw(share("alg" to "ed25519", "sig" to b(64))))
        assertNull(sw(share("alg" to "ml-dsa-65", "sig" to b(3309))))
        assertNull(sw(share("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to b(64), "pq_sig" to b(3309))))
        assertNull(sw(share("alg" to "ml-dsa-65", "sig" to b(3309), "pq_pk" to "junk"))) // pq_pk: judged by the threshold check
        assertNull(sw(share("sig" to b(64), "pq_pk" to b(1952))))
    }

    @Test fun shareWireRefusesWrongLengthsAndFields() {
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", sw(share("sig" to b(3309))))
        assertNotNull(sw(share("alg" to "ed25519", "sig" to b(3309))))
        assertEquals("'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'", sw(share("alg" to "ml-dsa-65", "sig" to b(3308))))
        assertNotNull(sw(share("alg" to "ml-dsa-65", "sig" to b(3310))))
        assertNotNull(sw(share("alg" to "ml-dsa-65", "sig" to b(64))))
        assertEquals("'pq_sig' is not canonical base64url (3309 bytes) for alg 'hybrid-ed25519-ml-dsa-65'",
            sw(share("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to b(64))))
        assertNotNull(sw(share("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to b(64), "pq_sig" to b(3308))))
        assertNotNull(sw(share("alg" to "hybrid-ed25519-ml-dsa-65", "sig" to b(3309), "pq_sig" to b(3309))))
        assertEquals("'pq_sig' must be absent for alg 'ed25519'", sw(share("sig" to b(64), "pq_sig" to b(3309))))
        assertEquals("'pq_sig' must be absent for alg 'ml-dsa-65'", sw(share("alg" to "ml-dsa-65", "sig" to b(3309), "pq_sig" to b(3309))))
        assertEquals("'pq_sig' must be absent for alg 'ed25519'", sw(share("sig" to b(64), "pq_sig" to null)))
        assertEquals("unknown signature alg 'ml-dsa-44'", sw(share("alg" to "ml-dsa-44", "sig" to b(2420))))
        assertEquals("'alg' must be a string", sw(share("alg" to n("1"), "sig" to b(64))))
        assertEquals("'alg' must be a string", sw(share("alg" to null, "sig" to b(64))))
        assertNotNull(sw(share("alg" to "ml-dsa-65", "sig" to b(3309) + "=")))
        assertNotNull(sw(share()))
    }

    // ---- Fix 1: policy caveats ---------------------------------------------------------------------------

    private fun ctx(amount: Any?) = m("now" to n("1800000000000"),
        "action" to m("verb" to "pay", "resource" to "invoice:42", "reversibility_class" to "reversible", "params" to m("amount" to amount)))
    private fun ev(caveats: Any?, c: Any?) = Caveats.evaluateCaveats(caveats, c)
    @Suppress("UNCHECKED_CAST") private fun params(c: Map<String, Any?>) = (c["action"] as MutableMap<String, Any?>)["params"] as MutableMap<String, Any?>
    @Suppress("UNCHECKED_CAST") private fun action(c: Map<String, Any?>) = c["action"] as MutableMap<String, Any?>

    @Test fun maxSpend() {
        val cv = l(m("type" to "max_spend", "usd" to n("100")))
        assertTrue(ev(cv, ctx(n("100"))).ok)
        assertTrue(ev(cv, ctx(n("99.5"))).ok)
        assertTrue(ev(cv, ctx(n("0"))).ok)
        assertFalse(ev(cv, ctx(n("150"))).ok)
        assertEquals(listOf("max_spend"), ev(cv, ctx(n("150"))).failed)
        for (bad in listOf(n("-1"), "100", true, null, n("1e400"))) assertFalse("$bad", ev(cv, ctx(bad)).ok)
        assertTrue(ev(l(m("type" to "max_spend", "usd" to 100)), ctx(42L)).ok)
        assertTrue(ev(l(m("type" to "max_spend", "usd" to BigDecimal("100.5"))), ctx(100.25)).ok)
        assertFalse(ev(l(m("type" to "max_spend", "usd" to 100)), ctx(Double.NaN)).ok)
        assertFalse(ev(l(m("type" to "max_spend", "usd" to "100")), ctx(n("1"))).ok)
        assertFalse(ev(l(m("type" to "max_spend", "usd" to n("-1"))), ctx(n("0"))).ok)
        assertFalse(ev(l(m("type" to "max_spend")), ctx(n("0"))).ok)
        assertFalse(ev(l(m("type" to "max_spend", "usd" to n("1e400"))), ctx(n("1"))).ok)
        val noNow = ctx(n("5")); noNow.remove("now")
        assertTrue(ev(cv, noNow).ok) // max_spend does not need `now`
    }

    @Test fun maxSpendCurrencyAndShape() {
        val cv = l(m("type" to "max_spend", "usd" to n("100")))
        for (cur in listOf<Any?>("usd", "USD")) { val c = ctx(n("5")); params(c)["currency"] = cur; assertTrue("$cur", ev(cv, c).ok) }
        for (cur in listOf<Any?>("eur", "Usd", null, n("1"), l("usd"))) { val c = ctx(n("5")); params(c)["currency"] = cur; assertFalse("$cur", ev(cv, c).ok) }
        val c = ctx(n("5"))
        action(c)["params"] = l(n("5")); assertFalse(ev(cv, c).ok)
        action(c).remove("params"); assertFalse(ev(cv, c).ok)
        action(c)["params"] = m(); assertFalse(ev(cv, c).ok)
        c["action"] = "pay"; assertFalse(ev(cv, c).ok)
        c.remove("action"); assertFalse(ev(cv, c).ok)
    }

    @Test fun timeAndContextCaveats() {
        val c = m("now" to n("1000"), "delegation_depth" to n("2"), "blast_radius" to n("5"), "reversibility_class" to "rate_limited",
            "recent_action_times" to l(n("1000"), n("500"), n("0"), "x", n("1001")))
        assertTrue(ev(l(m("type" to "expires", "at" to n("1001"))), c).ok)
        assertFalse(ev(l(m("type" to "expires", "at" to n("1000"))), c).ok)
        assertTrue(ev(l(m("type" to "not_before", "at" to n("1000"))), c).ok)
        assertFalse(ev(l(m("type" to "not_before", "at" to n("1001"))), c).ok)
        assertFalse(ev(l(m("type" to "not_before", "at" to "0")), c).ok)
        assertTrue(ev(l(m("type" to "rate", "max" to n("3"), "per_secs" to n("1"))), c).ok)
        assertFalse(ev(l(m("type" to "rate", "max" to n("2"), "per_secs" to n("1"))), c).ok)
        assertFalse(ev(l(m("type" to "rate", "max" to n("3"), "per_secs" to n("0"))), c).ok)
        assertTrue(ev(l(m("type" to "max_blast_radius", "max" to n("5"))), c).ok)
        assertFalse(ev(l(m("type" to "max_blast_radius", "max" to n("4"))), c).ok)
        assertTrue(ev(l(m("type" to "reversibility_max", "class" to "rate_limited")), c).ok)
        assertTrue(ev(l(m("type" to "reversibility_max", "class" to "irreversible")), c).ok)
        assertFalse(ev(l(m("type" to "reversibility_max", "class" to "reversible")), c).ok)
        assertFalse(ev(l(m("type" to "reversibility_max", "class" to l("irreversible"))), c).ok)
        assertTrue(ev(l(m("type" to "delegation_depth", "max" to n("2"))), c).ok)
        assertFalse(ev(l(m("type" to "delegation_depth", "max" to n("1"))), c).ok)
        assertTrue(ev(l(m("type" to "budget_alloc", "limit" to n("0"))), c).ok)
        assertFalse(ev(l(m("type" to "budget_alloc", "limit" to n("-1"))), c).ok)
        for (t in listOf("note", "envelope", "resource_prefix", "predicates", "tool_schema", "nope")) assertFalse(t, ev(l(m("type" to t)), c).ok)
        val bare = m("now" to n("1000"))
        for (cv in listOf(m("type" to "rate", "max" to n("3"), "per_secs" to n("1")), m("type" to "max_blast_radius", "max" to n("5")),
                m("type" to "reversibility_max", "class" to "irreversible"), m("type" to "delegation_depth", "max" to n("9"))))
            assertFalse("$cv", ev(l(cv), bare).ok)
        assertFalse(ev(l(m("type" to "budget_alloc", "limit" to n("1"))), m()).ok)
        assertFalse(ev(l(m("type" to "expires", "at" to n("1"))), m("now" to "1000")).ok)
    }

    @Test fun evaluateIsTotalAndOrdered() {
        assertEquals(Caveats.Result(false, listOf("<malformed caveats>")), ev("nope", m()))
        assertEquals(listOf("<malformed caveats>"), ev(null, m()).failed)
        val r = ev(l(m("type" to "note"), "x", m("type" to n("1")), m("type" to "budget_alloc", "limit" to n("1")), m("type" to "expires", "at" to n("0"))),
            m("now" to n("5")))
        assertFalse(r.ok)
        assertEquals(listOf("note", "<malformed>", "<malformed>", "expires"), r.failed)
        assertEquals(Caveats.Result(true, listOf()), ev(l(), null))
        assertFalse(ev(l(m("type" to "budget_alloc", "limit" to n("1"))), "ctx").ok)
    }

    @Test fun policyCaveatsDropsFirstEnvelopeAndAppendsHopCaveats() {
        val env = m("type" to "envelope", "x" to n("1"))
        val env2 = m("type" to "envelope", "x" to n("2"))
        val spend = m("type" to "max_spend", "usd" to n("10"))
        val grant = m("caveats" to l(spend, env, env2))
        assertEquals(l(spend, env2), Caveats.policyCaveats(grant, null))
        assertEquals(l(spend, env2), Caveats.rootCaveats(grant))
        val hopCv = m("type" to "expires", "at" to n("9"))
        val leaf = m("caveats" to l(spend, env, env2, hopCv))
        assertEquals(l(spend, env2, hopCv), Caveats.policyCaveats(grant, l(grant, leaf)))
        assertEquals(l(spend, env2), Caveats.policyCaveats(grant, l()))
        assertEquals(l(spend, env2), Caveats.policyCaveats(grant, "chain"))
        assertEquals(l(spend, env2), Caveats.policyCaveats(grant, l(m("caveats" to "x"))))
        assertEquals(l(spend, env2), Caveats.policyCaveats(grant, l("leaf")))
        assertEquals(l(spend, env2), Caveats.policyCaveats(grant, l(m("caveats" to l()))))
        assertEquals("x", Caveats.policyCaveats(m("caveats" to "x"), l(leaf)))
        assertNull(Caveats.policyCaveats("grant", null))
        assertEquals(listOf("<malformed caveats>"), Caveats.evaluateCaveats(Caveats.policyCaveats(m(), null), m()).failed)
        assertEquals(3, (grant["caveats"] as List<*>).size) // the input is not mutated
    }

    // ---- the corpus section, from JUnit (ConformanceRunner runs it too) ----------------------------------

    @Suppress("UNCHECKED_CAST")
    @Test fun corpusCaveatEval() {
        val prim = SnapshotTest.core["primitives"] as Map<String, Any?>
        var ran = 0
        for (x in prim["caveat_eval"] as List<Any?>) {
            val e = x as Map<String, Any?>
            val exp = e["expect"] as Map<String, Any?>
            val r = Caveats.evaluateCaveats(Caveats.policyCaveats(e["grant"], e["chain"]), e["context"])
            assertEquals("${e["name"]}", exp["allow"], r.ok)
            assertEquals("${e["name"]}", exp["failed"], r.failed)
            ran++
        }
        assertTrue("caveat_eval ran $ran", ran >= 40)
    }
}
