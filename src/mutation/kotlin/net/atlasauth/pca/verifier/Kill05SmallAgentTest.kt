package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kill tests for Agent (k05 small group): defaults, setters, every slot member and delegation. */
@Suppress("UNCHECKED_CAST")
class Kill05SmallAgentTest {
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
    private val meEd = Keys.edFromSeed(ByteArray(32) { 11 })
    private val me = Keys.ed25519(meEd)
    private val grant: Map<String, Any?> = Issue.mintGrant(
        principal, me.id()!!, null,
        Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy()), "g",
    ).grant

    private fun nodeId(p: Map<String, Any?>): Any? = (p["plan"] as Map<String, Any?>)["node_id"]

    @Test fun defaultsAndAccessors() {
        val a = Agent(me, "a", grant)
        assertEquals("a", a.aud)
        assertSame(grant, a.grant)
        assertSame(me, a.signer)
        assertEquals(0L, a.counter)
        assertEquals(Issue.DEFAULT_TTL_MS, a.ttlMs)
        assertTrue(a.nonces)
        assertEquals(listOf<Any?>(grant), a.chain)
        val before = System.currentTimeMillis()
        val p = a.act("read", "x")
        val after = System.currentTimeMillis()
        val iat = p["iat"] as Long
        assertTrue(iat in before..after)
        assertEquals(iat + Issue.DEFAULT_TTL_MS, p["exp"])
        assertEquals(1L, p["counter"])
        assertEquals(1L, a.counter)
        assertEquals("n1", nodeId(p))
        assertEquals(22, (p["nonce"] as String).length) // 16 random bytes
        assertNotEquals(p["nonce"], a.act("read", "x")["nonce"])
        assertEquals("Agent: aud (the resource server / instance id) is required", assertThrows(IllegalArgumentException::class.java) { Agent(me, "", grant) }.message)
        assertEquals(listOf<Any?>("c0"), Agent(me, "a", grant, listOf<Any?>("c0")).chain)
    }

    @Test fun constructorValuesAndSetters() {
        assertEquals(5L, Agent(me, "a", grant, counter = 5L).counter)
        val a = Agent(me, "a", grant)
        a.counter = 7L
        a.ttlMs = 1000L
        a.clock = { 42L }
        a.nonces = false
        assertEquals(1000L, a.ttlMs)
        assertFalse(a.nonces)
        val p = a.act("read", "x")
        assertEquals(8L, p["counter"])
        assertEquals("n8", nodeId(p))
        assertEquals(42L, p["iat"])
        assertEquals(1042L, p["exp"])
        assertFalse(p.containsKey("nonce"))
    }

    @Test fun slotsBecomeSignedMembers() {
        val maps = listOf("progress_step", "intent", "intent_session", "fresh_at", "provenance", "attestation", "freshness", "risk_claim")
        val slots = LinkedHashMap<String, Any?>()
        for (k in maps) slots[k] = Issue.obj("slot" to k)
        slots["nonce"] = "fixed-nonce"
        slots["caution"] = "c"
        slots["rationale_commitment"] = "rc"
        slots["tool_binding"] = "tb"
        slots["prohibition_evidence"] = arrayListOf<Any?>("pe")
        val p = Agent(me, "a", grant, clock = { 1L }).act("read", "x", null, slots)
        for (k in maps) assertEquals(k, Issue.obj("slot" to k), p[k])
        assertEquals("fixed-nonce", p["nonce"])
        assertEquals("c", p["caution"])
        assertEquals("rc", p["rationale_commitment"])
        assertEquals("tb", p["tool_binding"])
        assertEquals(arrayListOf<Any?>("pe"), p["prohibition_evidence"])

        // members of the wrong type are dropped (the nonce is then a fresh random one)
        val bad = LinkedHashMap<String, Any?>()
        for (k in maps) bad[k] = "not-a-map"
        bad["nonce"] = 5L
        bad["rationale_commitment"] = 5L
        bad["tool_binding"] = 5L
        val q = Agent(me, "a", grant, clock = { 1L }).act("read", "x", null, bad)
        for (k in listOf("progress_step", "intent", "intent_session", "fresh_at")) assertFalse(k, q.containsKey(k))
        assertEquals(22, (q["nonce"] as String).length)
        assertFalse(q.containsKey("rationale_commitment"))
        assertFalse(q.containsKey("tool_binding"))
        assertFalse(q.containsKey("caution"))
        val r = Agent(me, "a", grant, clock = { 1L }, nonces = false).act("read", "x", null, bad)
        assertFalse(r.containsKey("nonce"))
    }

    @Test fun plansAndDelegation() {
        val a = Agent(me, "a", grant, clock = { 1L })
        assertEquals("commitPlan() first", assertThrows(IllegalStateException::class.java) { a.actNode("s0") }.message)
        val plan = a.commitPlan(listOf(Issue.obj("id" to "s0", "verb" to "step", "resource" to "r")))
        val p = a.actNode("s0")
        assertEquals(plan.root, (p["plan"] as Map<String, Any?>)["root"])

        a.act("read", "x")
        assertEquals(2L, a.counter)
        val child = a.delegate(Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 12 })))
        assertEquals(0L, child.counter)
        assertEquals(2, child.chain.size)
        assertEquals("a", child.aud)
        assertNull((child.chain.last() as Map<String, Any?>)["holder_pq"])

        val hybrid = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(ByteArray(32) { 13 }), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 14 }))
        assertNotNull((a.delegate(hybrid).chain.last() as Map<String, Any?>)["holder_pq"])
        val pureKey = Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 15 }))
        assertEquals("a delegate holder needs an Ed25519 identity", assertThrows(IllegalArgumentException::class.java) { a.delegate(pureKey) }.message)
    }
}
