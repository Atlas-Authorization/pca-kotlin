package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kill tests for IntentHistory (k05 small group); outcomes and messages follow packages/pca/src/intent-history.ts. */
class Kill05SmallIntentHistoryTest {
    private fun n(s: String) = Json.Num(s)
    private fun mp(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> { val r = LinkedHashMap<String, Any?>(); for ((k, v) in kv) r[k] = v; return r }
    private val task = mp("kind" to "task")

    private fun acc(agg: String, v: String? = "action.params.total", key: String? = null): LinkedHashMap<String, Any?> {
        val a = mp("id" to "a", "agg" to agg, "sel" to mp("verbs" to arrayListOf<Any?>("send")), "win" to task, "key" to key)
        if (v != null) a["val"] = v
        return a
    }
    private fun ev(id: String, params: Map<String, Any?>, t: Any? = n("100"), verb: Any? = "send", status: String = "committed") =
        mp("id" to id, "verb" to verb, "resource" to "r", "params" to params, "t" to t, "status" to status)

    @Test fun inWindowEdges() {
        assertFalse(IntentHistory.inWindow(mp("kind" to "bogus"), n("5"), n("5")))
        assertFalse(IntentHistory.inWindow(mp("kind" to "bogus"), n("4"), n("5")))
        assertTrue(IntentHistory.inWindow(mp("kind" to "bogus"), n("6"), n("5"))) // stamped after t
        assertFalse(IntentHistory.inWindow(mp("kind" to "sliding", "ms" to n("0")), n("5"), n("5")))
        val period = mp("kind" to "period", "ms" to n("10"), "t0" to n("0"))
        assertTrue(IntentHistory.inWindow(period, n("5"), n("7")))
        assertFalse(IntentHistory.inWindow(period, n("5"), n("12")))
        // a missing ms / t0 makes every period comparison NaN: in no window, even at ti == t
        assertFalse(IntentHistory.inWindow(mp("kind" to "period", "t0" to n("0")), n("5"), n("5")))
        assertFalse(IntentHistory.inWindow(mp("kind" to "period", "ms" to n("10")), n("5"), n("5")))
    }

    @Test fun accKeyOfForms() {
        assertEquals("•", IntentHistory.accKeyOf(mp("key" to n("5")), mp()))
        assertEquals("•", IntentHistory.accKeyOf(mp("key" to null), mp()))
        assertEquals("\"x\"", IntentHistory.accKeyOf(mp("key" to "action.params.p"), mp("p" to "x")))
        assertNull(IntentHistory.accKeyOf(mp("key" to "action.params.p"), mp("q" to "x")))
    }

    @Test fun accPreStateThrowsWhereTheReferenceThrows() {
        val e1 = assertThrows(IllegalStateException::class.java) { IntentHistory.accPreState(acc("sum", key = "action.params.p"), emptyList(), mp(), n("1000"), null) }
        assertEquals("accPreState: the key parameter action.params.p is missing", e1.message)
        val e2 = assertThrows(IllegalStateException::class.java) { IntentHistory.accPreState(acc("sum"), emptyList(), mp(), "x", null) }
        assertEquals("accPreState: the candidate time is not a safe integer", e2.message)
        val e3 = assertThrows(IllegalStateException::class.java) { IntentHistory.accPreState(acc("sum"), listOf(ev("e1", mp("total" to n("1")), t = "x")), mp(), n("1000"), null) }
        assertEquals("accPreState: event e1: the time is not a safe integer", e3.message)
        val e4 = assertThrows(IllegalStateException::class.java) { IntentHistory.accPreState(acc("sum"), listOf(ev("e1", mp())), mp(), n("1000"), null) }
        assertEquals("accPreState: event e1: action.params.total must be a non-negative safe integer", e4.message)
        val two = listOf(ev("e1", mp("total" to n("9007199254740991"))), ev("e2", mp("total" to n("1"))))
        val e5 = assertThrows(IllegalStateException::class.java) { IntentHistory.accPreState(acc("sum"), two, mp(), n("1000"), null) }
        assertEquals("accPreState: sum exceeds 2^53-1", e5.message)
    }

    @Test fun accPreStateValues() {
        val max = listOf(ev("e1", mp("total" to n("9007199254740991"))))
        assertEquals(mp("sum" to n("9007199254740991")), IntentHistory.accPreState(acc("sum"), max, mp(), n("1000"), null))
        // a non-object event and an event whose verb is not a string are skipped, never thrown on
        val odd = listOf<Any?>("x", ev("e1", mp("total" to n("3")), verb = n("5")), ev("e2", mp("total" to n("4"))))
        assertEquals(mp("sum" to n("4")), IntentHistory.accPreState(acc("sum"), odd, mp(), n("1000"), null))
        // an aggregate without distinct keys reports no values
        assertEquals(mp("values" to arrayListOf<Any?>()), IntentHistory.accPreState(acc("foo"), listOf(ev("e1", mp("total" to n("3")))), mp(), n("1000"), null))
    }

    @Test fun accPostPaths() {
        // keyed, candidate without the key: the empty pre-state, then the candidate's own distinct value
        val distinct = acc("distinct", v = "action.params.x", key = "action.params.p")
        assertEquals(1L, IntentHistory.accPost(distinct, listOf(ev("e1", mp("p" to "a", "x" to "v"))), "send", mp("x" to "w"), n("1000"), null))
        val e1 = assertThrows(IllegalStateException::class.java) { IntentHistory.accPost(acc("sum"), emptyList(), "send", mp(), n("1000"), null) }
        assertEquals("accPost: action.params.total must be a non-negative safe integer", e1.message)
        val full = listOf(ev("e1", mp("total" to n("9007199254740991"))))
        val e2 = assertThrows(IllegalStateException::class.java) { IntentHistory.accPost(acc("sum"), full, "send", mp("total" to n("1")), n("1000"), null) }
        assertEquals("accPost: overflow", e2.message)
        assertEquals(9007199254740991L, IntentHistory.accPost(acc("sum"), full, "send", mp("total" to n("0")), n("1000"), null))
    }

    private val within = mp("id" to "m", "kind" to "responds_within", "p" to mp("verb" to "a", "resource" to "*"), "q" to mp("verb" to "b", "resource" to "*"), "within" to n("3"))
    private fun mev(verb: String, resource: String = "r", params: Map<String, Any?> = mp()) =
        mp("verb" to verb, "resource" to resource, "params" to params, "status" to "committed")

    @Test fun monitorSteps() {
        val exact = mp("kind" to "never", "p" to mp("verb" to "a", "resource" to "r1"))
        assertEquals("seen", IntentHistory.monitorStep(exact, "clean", mev("a", "r1")))
        assertEquals("clean", IntentHistory.monitorStep(exact, "clean", mev("a", "r2")))
        val where = mp("kind" to "never", "p" to mp("verb" to "a", "resource" to "*", "where" to arrayListOf<Any?>(mp("field" to "action.params.k", "op" to "eq", "value" to "z"))))
        assertEquals("seen", IntentHistory.monitorStep(where, "clean", mev("a", params = mp("k" to "z"))))
        assertEquals("clean", IntentHistory.monitorStep(where, "clean", mev("a", params = mp("k" to "y"))))
        assertEquals("pending:3", IntentHistory.monitorStep(within, "idle", mev("a")))
        assertEquals("pending:2", IntentHistory.monitorStep(within, "pending:3", mev("x")))
        // an unreadable pending count stays NaN, as Number('abc') does in the reference
        assertEquals("pending:NaN", IntentHistory.monitorStep(within, "pending:abc", mev("x")))
        val noDeadline = LinkedHashMap(within).also { it.remove("within") }
        assertEquals("missed", IntentHistory.monitorStep(noDeadline, "idle", mev("a")))
        assertEquals("zzz", IntentHistory.monitorStep(mp("kind" to "bogus"), "zzz", mev("a")))
    }
}
