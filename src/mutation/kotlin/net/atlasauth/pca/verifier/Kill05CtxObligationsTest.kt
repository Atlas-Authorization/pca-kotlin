package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for Obligations.kt, pinned to packages/pca/src/obligations.ts: the exact refusal text of every
 * obligation / list check (with its index), the canonical key with and without `due`, the 16-obligation merge limit, the
 * gate and outcome reasons, and the fail-closed catch of merge / gate / outcome (a list whose element read throws).
 */
class Kill05CtxObligationsTest {
    private fun ob(vararg kv: Pair<String, Any?>): Map<String, Any?> = linkedMapOf(*kv)
    private fun log(sink: String) = ob("kind" to "log", "params" to ob("sink" to sink))
    private val rr = ob("kind" to "require_receipt")
    private fun rrDue(d: Long) = ob("kind" to "require_receipt", "due" to d)
    private fun redact(fields: Any?) = ob("kind" to "redact", "params" to ob("fields" to fields))

    /** A list whose element read throws: reaches each function's catch. */
    private val throwing: List<Any?> = object : AbstractList<Any?>() {
        override val size: Int get() = 1
        override fun get(index: Int): Any? = throw IllegalStateException("boom")
        override fun toString() = "<throwing list>" // the assert messages interpolate it; AbstractList.toString would read element 0
    }

    private fun one(o: Any?, msg: String?) =
        assertEquals("$o", msg?.let { "obligations[0]: $it" }, Obligations.obligationsError(listOf(o)))

    @Test
    fun obligationRefusals() {
        assertEquals(listOf("log", "notify", "redact", "watermark", "require_receipt", "undo_window"), Obligations.KINDS)
        one(5L, "an obligation must be an object")
        one(ob("kind" to "log", "x" to 1L), "unknown member 'x'")
        one(ob(), "unknown obligation kind 'undefined'")
        one(ob("kind" to null), "unknown obligation kind 'null'")
        one(ob("kind" to 5L), "unknown obligation kind '5'")
        one(ob("kind" to "shred"), "unknown obligation kind 'shred'")
        one(ob("kind" to "log", "due" to "x"), "due must be a non-negative safe integer")
        one(ob("kind" to "log", "params" to 5L), "params must be an object")
        one(ob("kind" to "log", "params" to ob("x" to 1L)), "unknown parameter 'x' for 'log'")
        one(ob("kind" to "undo_window", "params" to ob("id" to "u")),
            "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)")
        one(ob("kind" to "undo_window", "params" to ob("id" to "u", "window_end" to 5L)), null)
        val fieldsMsg = "redact.fields must be 1..32 dotted field paths"
        for (f in listOf<Any?>("x", emptyList<Any?>(), listOf(5L), List(33) { "f$it" })) one(redact(f), fieldsMsg)
        one(redact(List(32) { "f$it" }), null)
        one(redact(listOf("a", "a")), "redact.fields has a duplicate")
    }

    @Test
    fun listRefusals() {
        assertEquals("obligations must be an array", Obligations.obligationsError(5L))
        assertEquals("more than 16 obligations", Obligations.obligationsError(List(17) { log("s$it") }))
        assertNull(Obligations.obligationsError(List(16) { log("s$it") }))
        assertEquals("obligations[2]: unknown obligation kind 'shred'", Obligations.obligationsError(listOf(log("a"), rr, ob("kind" to "shred"))))
        assertEquals("obligations[1] duplicates an earlier obligation", Obligations.obligationsError(listOf(log("a"), log("a"))))
        assertEquals("obligations[2] duplicates an earlier obligation", Obligations.obligationsError(listOf(log("a"), rr, log("a"))))
        // a lone surrogate passes the shape check but has no canonical key
        assertEquals("obligations[0]: not canonicalizable", Obligations.obligationsError(listOf(ob("kind" to "notify", "params" to ob("to" to "\uD800")))))
        // `due` is part of the identity
        assertNull(Obligations.obligationsError(listOf(rrDue(1), rrDue(2), rr)))
        assertEquals("{\"kind\":\"log\",\"params\":{}}", Obligations.obligationKey(ob("kind" to "log")))
        assertEquals("{\"due\":5,\"kind\":\"require_receipt\",\"params\":{}}", Obligations.obligationKey(rrDue(5)))
    }

    @Test
    fun mergeLimitAndReasons() {
        var m = Obligations.mergeObligations(listOf(listOf(log("a")), listOf(ob("kind" to "shred"))))
        assertFalse(m.ok)
        assertEquals("obligations[0]: unknown obligation kind 'shred'", m.reason)
        assertEquals(emptyList<Any?>(), m.obligations)
        m = Obligations.mergeObligations(listOf(List(8) { log("s$it") }, List(8) { log("s${it + 8}") }))
        assertTrue(m.ok)
        assertEquals(16, m.obligations.size)
        assertNull(m.reason)
        m = Obligations.mergeObligations(listOf(List(9) { log("s$it") }, List(8) { log("s${it + 9}") }))
        assertFalse(m.ok)
        assertEquals("more than 16 obligations after merging", m.reason)
        m = Obligations.mergeObligations(listOf(throwing))
        assertFalse(m.ok)
        assertEquals("evaluation error (fail closed)", m.reason)
    }

    private fun gate(obls: Any?, sup: Any?, decision: String, reason: String?, unsupported: List<String> = emptyList(), perform: List<Any?> = emptyList()) {
        val g = Obligations.pepObligationGate("allow", false, obls, sup)
        assertEquals("$obls/$sup", decision, g.decision)
        assertEquals("$obls/$sup", reason, g.reason)
        assertEquals("$obls/$sup", unsupported, g.unsupported)
        assertEquals("$obls/$sup", perform, g.perform)
    }

    @Test
    fun gateReasons() {
        val malformed = "the supported obligation kinds are malformed"
        gate(null, null, "deny", malformed)
        gate(null, "log", "deny", malformed)
        gate(null, listOf(5L), "deny", malformed)
        gate(listOf(ob("kind" to "shred")), listOf("log"), "deny", "malformed obligations: obligations[0]: unknown obligation kind 'shred'")
        gate(listOf(ob("kind" to "watermark", "params" to ob("id" to "w")), ob("kind" to "notify", "params" to ob("to" to "x")), rr), listOf("log"), "deny",
            "the enforcement point does not support obligation(s) notify, require_receipt, watermark", listOf("notify", "require_receipt", "watermark"))
        gate(throwing, listOf("log"), "deny", "evaluation error (fail closed)")
        gate(listOf(log("a")), listOf("log"), "allow", null, perform = listOf(log("a")))
    }

    private fun outcome(obls: Any?, fulfilled: Any?, now: Any?, outcome: String, overdue: List<Int>) {
        val o = Obligations.obligationOutcome(obls, fulfilled, now)
        assertEquals("$obls/$fulfilled/$now", outcome, o.outcome)
        assertEquals("$obls/$fulfilled/$now", overdue, o.overdue)
        assertEquals("$obls/$fulfilled/$now", if (outcome == "ok") null else "obligation_unmet", o.status)
    }

    @Test
    fun outcomeEdges() {
        outcome(null, emptyList<Any?>(), 5L, "ok", emptyList())
        // a malformed list without any due time is still everything-overdue
        outcome(listOf(ob("kind" to "shred")), emptyList<Any?>(), 5L, "escalate", listOf(0))
        outcome(listOf(rrDue(5)), listOf("x"), 10L, "escalate", listOf(0))
        outcome(listOf(log("a"), rr), "x", 5L, "escalate", listOf(0, 1))
        outcome(listOf(rrDue(5)), listOf(0L), "x", "escalate", listOf(0))
        outcome(throwing, emptyList<Any?>(), 5L, "escalate", emptyList())
    }
}
