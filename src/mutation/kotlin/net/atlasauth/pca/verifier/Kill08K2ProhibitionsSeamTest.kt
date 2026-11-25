package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Direct seams of the prohibition engine that no JSON input reaches: the fail-closed catch blocks (a contained throwable becomes a
 * fail-closed verdict, a fatal error is never swallowed: [Contain.ok]) and the JavaScript-flavoured helpers. A [Spy] map throws on the
 * N-th read of one member, so the throw lands in exactly one guarded region.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K2ProhibitionsSeamTest {
    /** Not contained by [Contain.ok]: must always propagate. */
    private class Boom : Error("boom")

    private class Spy(private val inner: Map<String, Any?>, private val member: String, private val throwAt: Int, private val err: () -> Throwable) : AbstractMap<String, Any?>() {
        var reads = 0
        override val entries: Set<Map.Entry<String, Any?>> get() = inner.entries
        override fun get(key: String): Any? {
            if (key == member && ++reads == throwAt) throw err()
            return inner[key]
        }
        override fun containsKey(key: String): Boolean = inner.containsKey(key)
    }

    /** From the second read of `kind` on, reports an unknown kind (an invariant that changed after validation). */
    private class Flip(private val inner: Map<String, Any?>) : AbstractMap<String, Any?>() {
        var reads = 0
        override val entries: Set<Map.Entry<String, Any?>> get() = inner.entries
        override fun get(key: String): Any? = if (key == "kind" && ++reads >= 2) "bogus" else inner[key]
        override fun containsKey(key: String): Boolean = inner.containsKey(key)
    }

    private val contained: List<() -> Throwable> = listOf(
        { RuntimeException("x") }, { IllegalStateException("x") }, { AssertionError("x") }, { StackOverflowError() }, { NoClassDefFoundError("x") },
    )
    private val fatalErr: () -> Throwable = { Boom() }

    private fun n(d: Double) = Prohibitions.jn(d)
    private fun inv(): LinkedHashMap<String, Any?> = Prohibitions.map("id", "n", "kind", "never", "when", Prohibitions.map("verb", "delete"))
    private fun con(vararg invs: Any?): LinkedHashMap<String, Any?> = Prohibitions.map("version", n(1.0), "principal", "AAAA", "invariants", arrayListOf<Any?>(*invs))
    private fun act(): LinkedHashMap<String, Any?> = Prohibitions.map("action", Prohibitions.map("verb", "delete", "resource", "/x"))
    private fun state(): Map<String, Any?> = Prohibitions.emptyState(n(1000.0))

    private fun expectFatal(what: String, f: () -> Any?) {
        try {
            f()
            fail("$what: a fatal error must propagate")
        } catch (e: Boom) {
            // propagated
        }
    }

    @Test fun jsHelpers() {
        val u = Prohibitions.UNDEF
        assertFalse(Prohibitions.truthy(u))
        assertEquals("undefined", Prohibitions.text(u))
        assertEquals("null", Prohibitions.text(null))
        assertEquals("5", Prohibitions.text(n(5.0)))
        assertTrue(Prohibitions.truthy("x"))
        assertFalse(Prohibitions.truthy(""))
        assertFalse(Prohibitions.truthy(null))
        assertSame(u, Prohibitions.get(LinkedHashMap<String, Any?>(), "k"))
        assertNull(Prohibitions.get(Prohibitions.map("k", null), "k"))
        assertEquals("v", Prohibitions.get(Prohibitions.map("k", "v"), "k"))
        assertSame(u, Prohibitions.prop(null, "k"))
        assertSame(u, Prohibitions.prop("x", "k"))
        assertSame(u, Prohibitions.prop(LinkedHashMap<String, Any?>(), "k"))
        assertNull(Prohibitions.prop(Prohibitions.map("k", null), "k"))
        assertEquals("v", Prohibitions.prop(Prohibitions.map("k", "v"), "k"))
        assertTrue(Prohibitions.isInteger(n(3.0)))
        assertTrue(Prohibitions.isInteger(n(0.0)))
        assertTrue(Prohibitions.isInteger(n(-4.0)))
        assertFalse(Prohibitions.isInteger(n(0.5)))
        assertFalse(Prohibitions.isInteger("3"))
        assertFalse(Prohibitions.isInteger(null))
        assertTrue(Prohibitions.negZero(Json.Num("-0")))
        assertFalse(Prohibitions.negZero(Json.Num("0")))
        assertFalse(Prohibitions.negZero(n(-1.0)))
        assertFalse(Prohibitions.negZero(n(1.0)))
        assertFalse(Prohibitions.negZero("x"))
        assertFalse(Prohibitions.negZero(null))
        assertTrue(Prohibitions.fin(n(1.0)))
        assertFalse(Prohibitions.fin(Json.Num("Infinity")))
        assertFalse(Prohibitions.fin("1"))
        assertEquals(2.5, Prohibitions.dv(Json.Num("2.5")), 0.0)
        assertEquals(Json.Num("3"), Prohibitions.jn(3.0))
        assertEquals("a,b,c", Prohibitions.joinIds(listOf("a", "b", "c")))
        assertEquals("a,undefined", Prohibitions.joinIds(listOf("a", u)))
        assertEquals("null", Prohibitions.joinIds(listOf<Any?>(null)))
    }

    @Test fun safeContainsOnlyContainedThrowables() {
        for (mk in contained) assertEquals(Prohibitions.UNHASHABLE, Prohibitions.safe { throw mk() })
        expectFatal("safe") { Prohibitions.safe { throw Boom() } }
        assertEquals("ok", Prohibitions.safe { "ok" })
    }

    @Test fun verifyConstitutionFailsClosed() {
        for (mk in contained) assertEquals("verification error (fail closed)", Prohibitions.verifyConstitution(Spy(con(inv()), "version", 1, mk), null))
        expectFatal("verifyConstitution") { Prohibitions.verifyConstitution(Spy(con(inv()), "version", 1, fatalErr), null) }
    }

    @Test fun stateProblemFailsClosed() {
        for (mk in contained) assertEquals("malformed monitor state", Prohibitions.stateProblem(Spy(state(), "now", 1, mk)))
        expectFatal("stateProblem") { Prohibitions.stateProblem(Spy(state(), "now", 1, fatalErr)) }
    }

    @Test fun anInvariantThatThrowsWhileEvaluatedIsAViolation() {
        for (mk in contained) {
            val res = Prohibitions.checkProhibitions(act(), con(Spy(inv(), "kind", 2, mk)), state())
            assertEquals(false, res["ok"])
            assertEquals(listOf<Any?>("n"), res["violated"])
            assertEquals(listOf<Any?>("n: evaluation error (fail closed)"), res["reasons"])
            val row = (res["evaluated"] as List<Map<String, Any?>>)[0]
            assertEquals("never", row["kind"])
            assertEquals("violated", row["result"])
            assertEquals("evaluation error (fail closed)", row["reason"])
        }
        expectFatal("evalOne") { Prohibitions.checkProhibitions(act(), con(Spy(inv(), "kind", 2, fatalErr)), state()) }
    }

    @Test fun anInvariantThatChangesKindAfterValidationIsAViolation() {
        val res = Prohibitions.checkProhibitions(act(), con(Flip(inv())), state())
        assertEquals(false, res["ok"])
        assertEquals(listOf<Any?>("n: evaluation error (fail closed)"), res["reasons"])
    }

    @Test fun theMonitorFailsClosed() {
        for (mk in contained) {
            val res = Prohibitions.checkProhibitions(act(), Spy(con(inv()), "invariants", 2, mk), state())
            assertEquals(false, res["ok"])
            assertEquals(listOf<Any?>("<monitor>"), res["violated"])
            assertEquals(listOf<Any?>("monitor error (fail closed)"), res["reasons"])
        }
        expectFatal("checkProhibitions") { Prohibitions.checkProhibitions(act(), Spy(con(inv()), "invariants", 2, fatalErr), state()) }
    }

    @Test fun advanceFailsClosed() {
        for (mk in contained) {
            val res = Prohibitions.advanceStateStrict(act(), Spy(con(inv()), "invariants", 2, mk), state())
            assertEquals(false, res["ok"])
            assertEquals("advance error (fail closed)", res["reason"])
        }
        expectFatal("advanceStateStrict") { Prohibitions.advanceStateStrict(act(), Spy(con(inv()), "invariants", 2, fatalErr), state()) }
    }

    @Test fun whenAffirmativeFailsClosed() {
        val w = Prohibitions.map("verb", "delete")
        assertTrue(Prohibitions.whenAffirmative(w, act()))
        for (mk in contained) assertFalse(Prohibitions.whenAffirmative(Spy(w, "verb", 1, mk), act()))
        expectFatal("whenAffirmative") { Prohibitions.whenAffirmative(Spy(w, "verb", 1, fatalErr), act()) }
    }

    @Test fun verifySafetyEvidenceFailsClosed() {
        val ev = Prohibitions.map("v", n(1.0))
        for (mk in contained) assertEquals("verification error (fail closed)", Prohibitions.verifySafetyEvidence(Spy(ev, "v", 1, mk), act(), con(inv()), state()))
        expectFatal("verifySafetyEvidence") { Prohibitions.verifySafetyEvidence(Spy(ev, "v", 1, fatalErr), act(), con(inv()), state()) }
    }

    @Test fun verifySignedSafetyEvidenceFailsClosed() {
        val signed = Prohibitions.map("evidence", Prohibitions.map("v", n(1.0)))
        val expected = Prohibitions.map("signer", "k")
        for (mk in contained) assertEquals("verification error (fail closed)", Prohibitions.verifySignedSafetyEvidence(Spy(signed, "evidence", 1, mk), expected))
        expectFatal("verifySignedSafetyEvidence") { Prohibitions.verifySignedSafetyEvidence(Spy(signed, "evidence", 1, fatalErr), expected) }
    }

    @Test fun checkAndAdvanceFailsClosedOnTheHeadGuard() {
        // a dry run finds the read of `seq` made by the head guard (the last one before the refusal)
        val dry = Spy(state(), "seq", Int.MAX_VALUE, fatalErr)
        val stale = Prohibitions.checkAndAdvance(true, act(), con(inv()), dry, n(5.0))
        assertEquals("stale state head (seq)", stale["reason"])
        val last = dry.reads
        assertTrue(last > 0)
        for (mk in contained) {
            val res = Prohibitions.checkAndAdvance(true, act(), con(inv()), Spy(state(), "seq", last, mk), n(5.0))
            assertEquals(false, res["allow"])
            assertEquals("state", res["decidedBy"])
            assertEquals("check-and-advance error (fail closed)", res["reason"])
        }
        expectFatal("checkAndAdvance") { Prohibitions.checkAndAdvance(true, act(), con(inv()), Spy(state(), "seq", last, fatalErr), n(5.0)) }
    }
}
