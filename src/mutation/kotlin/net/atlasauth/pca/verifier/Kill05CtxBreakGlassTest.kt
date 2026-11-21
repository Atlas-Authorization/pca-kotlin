package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for BreakGlass.kt, pinned to packages/pca-grants/src/breakglass.ts: every well-formedness bound of a
 * grant and a review (each record is correctly signed, so only the shape check can refuse it), the input guards of
 * use / review / frozen, and the review time window edges.
 */
class Kill05CtxBreakGlassTest {
    private val authority = IntentTestKit.pub("k05-bg-authority")
    private val reviewer = IntentTestKit.pub("k05-bg-reviewer")
    private val bodyKeys = listOf("v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority")
    private val reviewKeys = listOf("v", "id", "outcome", "notes_digest", "at", "reviewer")
    private val t0 = 1_000_000L

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
        return signed(BreakGlass.DOMAIN, bodyKeys, "k05-bg-authority", m)
    }

    private fun review(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to 1L, "id" to "bg1", "outcome" to "justified", "notes_digest" to "n", "at" to t0 + 10, "reviewer" to reviewer)
        for ((k, v) in over) m[k] = v
        return signed(BreakGlass.REVIEW_DOMAIN, reviewKeys, "k05-bg-reviewer", m)
    }

    private fun s(n: Int) = "x".repeat(n)

    @Test
    fun grantShape() {
        assertTrue(BreakGlass.verifyBreakGlass(grant()))
        for (x in listOf(null, "x", 5)) assertFalse("$x", BreakGlass.verifyBreakGlass(x))
        val ok = listOf<Pair<String, Any?>>("id" to s(128), "holder" to s(128), "grant_ref" to s(256), "reason_digest" to s(128), "notify_to" to s(256),
            "max_uses" to 1L, "max_uses" to 16L, "expires_at" to t0 + 1, "expires_at" to t0 + BreakGlass.MAX_WINDOW_MS,
            "review_within" to 1L, "review_within" to BreakGlass.MAX_REVIEW_WITHIN_MS)
        for (o in ok) assertTrue("$o", BreakGlass.verifyBreakGlass(grant(o)))
        val bad = listOf<Pair<String, Any?>>("v" to 2L, "v" to "1", "id" to "", "id" to s(129), "holder" to "", "holder" to s(129),
            "grant_ref" to "", "grant_ref" to s(257), "reason_digest" to "", "reason_digest" to s(129), "notify_to" to "", "notify_to" to s(257),
            "max_uses" to "2", "issued_at" to "5", "expires_at" to "5", "review_within" to "5", "issued_at" to -1L,
            "max_uses" to 0L, "max_uses" to 17L, "expires_at" to t0, "expires_at" to t0 + BreakGlass.MAX_WINDOW_MS + 1,
            "review_within" to 0L, "review_within" to BreakGlass.MAX_REVIEW_WITHIN_MS + 1)
        for (o in bad) assertFalse("$o", BreakGlass.verifyBreakGlass(grant(o)))
    }

    @Test
    fun reviewShape() {
        assertTrue(BreakGlass.verifyBreakGlassReview(review()))
        assertTrue(BreakGlass.verifyBreakGlassReview(review("outcome" to "unjustified", "id" to s(128), "notes_digest" to s(128))))
        for (x in listOf(null, "x", 5)) assertFalse("$x", BreakGlass.verifyBreakGlassReview(x))
        val bad = listOf<Pair<String, Any?>>("v" to 2L, "v" to "1", "id" to "", "id" to s(129), "notes_digest" to "", "notes_digest" to s(129),
            "outcome" to "maybe", "at" to "5", "at" to -1L)
        for (o in bad) assertFalse("$o", BreakGlass.verifyBreakGlassReview(review(o)))
    }

    @Test
    fun useEntryFields() {
        val u = BreakGlass.UseEntry(3, "d", 5)
        assertEquals(3L, u.n)
        assertEquals("d", u.actionDigest)
        assertEquals(5L, u.at)
    }

    private fun registry(): BreakGlass.Registry = BreakGlass.Registry(BreakGlass.Policy(listOf(authority), listOf(reviewer)), MemoryAtomicKv())

    @Test
    fun inputGuards() {
        val reg = registry()
        assertEquals("bad_record", reg.accept(grant(), -1L).code)
        assertEquals("bad_record", reg.accept(grant(), "5").code)
        assertTrue(reg.accept(grant(), t0).ok)
        fun bad(id: Any?, holder: Any?, digest: Any?, now: Any?, notified: Any?) {
            val d = reg.use(id, holder, digest, now, notified)
            assertEquals("deny", d.decision)
            assertEquals("bad_input", d.code)
            assertEquals(null, d.id)
        }
        bad(s(129), "agent", "a", t0, true)
        bad("bg1", s(129), "a", t0, true)
        bad("bg1", "agent", s(129), t0, true)
        bad("bg1", "", "a", t0, true)
        bad("bg1", "agent", "", t0, true)
        bad(5, "agent", "a", t0, true)
        bad("bg1", "agent", "a", -1L, true)
        bad("bg1", "agent", "a", t0, "true")
        // 128-character id / holder / digest pass the input guard (unknown grant)
        assertEquals("unknown_break_glass", reg.use(s(128), s(128), s(128), t0, true).code)
        val ok = reg.use("bg1", "agent", s(128), t0, true)
        assertEquals("allow", ok.decision)
        assertEquals(1L, ok.use)
        // frozen fails closed on malformed input
        for ((h, n) in listOf<Pair<Any?, Any?>>("" to t0, s(129) to t0, 5 to t0, "agent" to -1L, "agent" to "5")) assertTrue("$h/$n", reg.frozen(h, n))
        assertFalse(reg.frozen(s(128), t0))
        assertFalse(reg.frozen("agent", t0))
        // review input guards
        assertEquals("bad_record", reg.review(review(), s(129), t0 + 20).code)
        assertEquals("bad_record", reg.review(review(), "", t0 + 20).code)
        assertEquals("bad_record", reg.review(review(), "agent", -1L).code)
        assertEquals("unknown_break_glass", reg.review(review(), s(128), t0 + 20).code)
    }

    @Test
    fun reviewTimeEdges() {
        // the review may be dated exactly at the first use and exactly at `now`
        var reg = registry()
        assertTrue(reg.accept(grant(), t0).ok)
        assertEquals("allow", reg.use("bg1", "agent", "a", t0 + 10, true).decision)
        var r = reg.review(review("at" to t0 + 10), "agent", t0 + 10)
        assertTrue(r.ok)
        assertTrue(r.replaced)
        reg = registry()
        assertTrue(reg.accept(grant(), t0).ok)
        assertEquals("allow", reg.use("bg1", "agent", "a", t0 + 5, true).decision)
        r = reg.review(review("at" to t0 + 10), "agent", t0 + 9)
        assertFalse(r.ok)
        assertEquals("bad_time", r.code)
        r = reg.review(review("at" to t0 + 4), "agent", t0 + 20)
        assertEquals("bad_time", r.code)
    }
}
