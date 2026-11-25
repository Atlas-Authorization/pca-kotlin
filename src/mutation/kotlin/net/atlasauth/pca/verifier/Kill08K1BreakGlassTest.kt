package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for BreakGlass.kt (durable Registry over AtomicKv): a store that throws or never runs the update function, a fatal error,
 * a store whose documents are not the expected shape, and the numbered use log.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K1BreakGlassTest {
    private val authority = IntentTestKit.pub("k08k1-bg-authority")
    private val reviewer = IntentTestKit.pub("k08k1-bg-reviewer")
    private val bodyKeys = listOf("v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority")
    private val reviewKeys = listOf("v", "id", "outcome", "notes_digest", "at", "reviewer")
    private val t0 = 1_000_000L
    private val key = "breakglass/holder/agent"

    private fun signed(domain: String, keys: List<String>, label: String, m: LinkedHashMap<String, Any?>): LinkedHashMap<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        for (k in keys) body[k] = m[k]
        m["sig"] = IntentTestKit.sign(label, IntentJs.message(domain, body))
        return m
    }

    private fun grant(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to 1L, "id" to "bg1", "holder" to "agent", "grant_ref" to "g", "reason_digest" to "why",
            "max_uses" to 2L, "issued_at" to t0, "expires_at" to t0 + 3_600_000L, "review_within" to 1_800_000L, "notify_to" to "secops", "authority" to authority)
        for ((k, v) in over) m[k] = v
        return signed(BreakGlass.DOMAIN, bodyKeys, "k08k1-bg-authority", m)
    }

    private fun review(): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to 1L, "id" to "bg1", "outcome" to "justified", "notes_digest" to "n", "at" to t0 + 10, "reviewer" to reviewer)
        return signed(BreakGlass.REVIEW_DOMAIN, reviewKeys, "k08k1-bg-reviewer", m)
    }

    private fun reg(kv: AtomicKv) = BreakGlass.Registry(BreakGlass.Policy(listOf(authority), listOf(reviewer)), kv)

    @Test fun aStoreThatThrowsIsUnreachableAndFailsClosed() {
        val r = reg(Kill08K1ThrowingKv { IllegalStateException("down") })
        val a = r.accept(grant(), t0)
        assertFalse(a.ok)
        assertEquals("store_unreachable", a.code)
        assertFalse(a.replaced)
        val u = r.use("bg1", "agent", "d", t0, true)
        assertEquals("deny", u.decision)
        assertEquals("store_unreachable", u.code)
        assertEquals("bg1", u.id)
        val v = r.review(review(), "agent", t0 + 20)
        assertFalse(v.ok)
        assertEquals("store_unreachable", v.code)
        assertFalse(v.replaced)
        assertTrue(r.frozen("agent", t0))
        assertEquals(0, r.uses("agent", "bg1").size)
    }

    @Test fun aFatalErrorFromTheStoreIsRethrownEverywhere() {
        val r = reg(Kill08K1ThrowingKv { OutOfMemoryError("fatal") })
        assertThrows(OutOfMemoryError::class.java) { r.accept(grant(), t0) }
        assertThrows(OutOfMemoryError::class.java) { r.use("bg1", "agent", "d", t0, true) }
        assertThrows(OutOfMemoryError::class.java) { r.review(review(), "agent", t0 + 20) }
        assertThrows(OutOfMemoryError::class.java) { r.frozen("agent", t0) }
        assertThrows(OutOfMemoryError::class.java) { r.uses("agent", "bg1") }
    }

    @Test fun aStoreThatNeverRunsTheUpdateFunctionLeavesTheUnreachableAnswer() {
        val r = reg(Kill08K1NoopKv)
        val a = r.accept(grant(), t0)
        assertNotNull(a)
        assertFalse(a.ok)
        assertEquals("store_unreachable", a.code)
        val u = r.use("bg1", "agent", "d", t0, true)
        assertNotNull(u)
        assertEquals("deny", u.decision)
        assertEquals("store_unreachable", u.code)
        assertEquals("bg1", u.id)
        val v = r.review(review(), "agent", t0 + 20)
        assertNotNull(v)
        assertFalse(v.ok)
        assertEquals("store_unreachable", v.code)
    }

    @Test fun documentsOfTheWrongShapeAreReadAsEmpty() {
        for (d in listOf<Any?>("junk", linkedMapOf("grants" to "junk"))) {
            val kv = MemoryAtomicKv()
            kv.set(key, d)
            val a = reg(kv).accept(grant(), t0)
            assertTrue("$d ${a.code}", a.ok)
            assertTrue(a.replaced)
        }
        // an entry with no use log, or one that is not a list, is an empty log
        for (e in listOf<Map<String, Any?>>(linkedMapOf("rec" to grant()), linkedMapOf("rec" to grant(), "uses" to "junk"))) {
            val kv = MemoryAtomicKv()
            kv.set(key, linkedMapOf("grants" to linkedMapOf("bg1" to e)))
            val r = reg(kv)
            assertFalse(r.frozen("agent", t0))
            val u = r.use("bg1", "agent", "d", t0, true)
            assertEquals(u.code, "allow", u.decision)
            assertEquals(1L, u.use)
        }
        // a review that is not an object is no review
        val kv = MemoryAtomicKv()
        kv.set(key, linkedMapOf("grants" to linkedMapOf("bg1" to linkedMapOf("rec" to grant(), "uses" to ArrayList<Any?>(), "review" to "junk"))))
        val r = reg(kv)
        assertFalse(r.frozen("agent", t0))
        assertEquals("allow", r.use("bg1", "agent", "d", t0, true).decision)
    }

    @Test fun theUseLogIsNumberedFromOne() {
        val r = reg(MemoryAtomicKv())
        assertTrue(r.accept(grant("max_uses" to 3L), t0).ok)
        for (i in 1..3) {
            val d = r.use("bg1", "agent", "d$i", t0 + i, true)
            assertEquals("allow", d.decision)
            assertEquals(null, d.code)
            assertEquals(i.toLong(), d.use)
            assertEquals(3L - i, d.remaining)
            assertEquals(t0 + 1 + 1_800_000L, d.reviewDue)
        }
        val log = r.uses("agent", "bg1")
        assertEquals(listOf(1L, 2L, 3L), log.map { it.n })
        assertEquals(listOf("d1", "d2", "d3"), log.map { it.actionDigest })
        assertEquals(listOf(t0 + 1, t0 + 2, t0 + 3), log.map { it.at })
        assertEquals("budget_exhausted", r.use("bg1", "agent", "d4", t0 + 4, true).code)
    }
}
