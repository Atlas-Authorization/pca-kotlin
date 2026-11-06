package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * 0.5 mutation kills for MissingContext.kt, pinned to packages/pca/src/missing-context.ts: the supplier table's forbidden
 * segments, deep copies, the 16-level flatten cut-off, the action/params defaults of bindContext, and every collect() branch
 * (groups, ill-typed leaves, params availability, the 64-level depth cap, the regex budget) of decideWithMissing.
 */
class Kill05CtxMissingContextTest {
    private val act = mapOf("verb" to "refund", "resource" to "/acct/a1", "params" to mapOf("amount" to 50))
    private fun bound(vararg extra: Pair<String, Any?>): Map<String, Any?> =
        linkedMapOf<String, Any?>("action" to act, "env" to mapOf("tier" to "gold")).apply { putAll(extra) }
    private fun leaf(field: Any?, op: String, value: Any?): Map<String, Any?> = mapOf("field" to field, "op" to op, "value" to value)
    private val approved = leaf("env.approved", "eq", true)

    private fun check(name: String, decision: String, reason: String?, missing: List<Pair<String, String>>, got: MissingContext.Typed) {
        assertEquals("$name: decision", decision, got.decision)
        assertEquals("$name: reason", reason, got.reason)
        assertEquals("$name: missing", missing, got.missing.map { it.path to it.supplier })
    }

    private fun deny(name: String, reason: String, where: Any?, b: Any? = bound(), supplied: Any? = null, suppliers: Any? = null) =
        check(name, "deny", reason, emptyList(), MissingContext.decideWithMissing(where, b, supplied, suppliers))

    private fun escalate(name: String, where: Any?, b: Any? = bound(), vararg paths: String) =
        check(name, "escalate", "escalate: missing_context " + paths.joinToString(",") { "principal:$it" }, paths.map { it to "principal" },
            MissingContext.decideWithMissing(where, b, null, null))

    @Test
    fun suppliersAndTable() {
        assertEquals(listOf("principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted"), MissingContext.SUPPLIERS)
        for (t in listOf(null, 5, listOf<Any?>())) assertEquals("$t", "the supplier table must be an object", MissingContext.supplierTableError(t))
        for (k in listOf("env.constructor", "subject.__proto__", "action.params.a.prototype", "foo"))
            assertEquals(k, "bad supplier path '$k'", MissingContext.supplierTableError(mapOf(k to "principal")))
        assertEquals("bad supplier for 'env.x'", MissingContext.supplierTableError(mapOf("env.x" to "everyone")))
        assertNull(MissingContext.supplierTableError(mapOf("env" to "principal", "env.obs" to "rs_observation",
            "subject.kyc" to "discharge_issuer", "action.params.note" to "agent_declared_untrusted")))
        val tier = listOf(leaf("env.tier", "eq", "gold"))
        deny("non-object table", "bad supplier table: the supplier table must be an object", tier, suppliers = 5)
        deny("forbidden segment", "bad supplier table: bad supplier path 'env.constructor'", tier, suppliers = mapOf("env.constructor" to "principal"))
    }

    @Test
    fun bindCopiesDeeply() {
        val inner = linkedMapOf<String, Any?>("a" to 1)
        val list = arrayListOf<Any?>(inner)
        val supList = arrayListOf<Any?>(1)
        val b = linkedMapOf<String, Any?>("action" to mapOf("verb" to "v", "resource" to "r"), "env" to linkedMapOf<String, Any?>("l" to list))
        val got = MissingContext.bindContext(b, mapOf("env" to mapOf("k" to supList)))
        inner["a"] = 2
        list.add(3)
        supList.add(2)
        assertEquals(mapOf("action" to mapOf("verb" to "v", "resource" to "r"), "env" to mapOf("l" to listOf(mapOf("a" to 1)), "k" to listOf(1))), got.context)
        assertEquals(emptyList<String>(), got.conflicts)
    }

    @Test
    fun flattenStopsBelowSixteenLevels() {
        var v: Any? = mapOf("x" to 1)
        for (i in 17 downTo 1) v = mapOf("a$i" to v)
        val got = MissingContext.bindContext(bound(), mapOf("env" to v), mapOf("env" to "agent_declared_untrusted"))
        assertEquals(listOf("env." + (1..17).joinToString(".") { "a$it" }), got.dropped)
        assertEquals(emptyList<String>(), got.conflicts)
        assertEquals(bound(), got.context)
    }

    @Test
    fun bindDefaults() {
        val vr = mapOf("verb" to "v", "resource" to "r")
        // an empty supplied object is a leaf; an env-only supply never touches the action
        var got = MissingContext.bindContext(mapOf("action" to vr), mapOf("env" to mapOf("e" to emptyMap<String, Any?>())))
        assertEquals(mapOf("action" to vr, "env" to mapOf("e" to emptyMap<String, Any?>())), got.context)
        got = MissingContext.bindContext(mapOf("subject" to mapOf("id" to "u1")), mapOf("env" to mapOf("k" to 1)))
        assertEquals(mapOf("subject" to mapOf("id" to "u1"), "env" to mapOf("k" to 1)), got.context)
        // params under a missing or null action get an empty verb and resource
        val made = mapOf("verb" to "", "resource" to "", "params" to mapOf("a" to 1))
        got = MissingContext.bindContext(mapOf("subject" to mapOf("id" to "u1")), mapOf("action" to mapOf("params" to mapOf("a" to 1))))
        assertEquals(mapOf("subject" to mapOf("id" to "u1"), "action" to made), got.context)
        got = MissingContext.bindContext(mapOf("action" to null), mapOf("action" to mapOf("params" to mapOf("a" to 1))))
        assertEquals(mapOf("action" to made), got.context)
        assertEquals(emptyList<String>(), got.conflicts)
        // a non-object bound action cannot take params (decideWithMissing never gets here: it needs an action object)
        try {
            MissingContext.bindContext(mapOf("action" to "x"), mapOf("action" to mapOf("params" to mapOf("a" to 1))))
            fail("a string action took params")
        } catch (e: IllegalStateException) {
            assertEquals("action is not an object", e.message)
        }
        // a bound non-object root is replaced (only prefixes of two or more segments block)
        got = MissingContext.bindContext(mapOf("action" to vr, "env" to 5), mapOf("env" to mapOf("kyc" to "ok")))
        assertEquals(mapOf("action" to vr, "env" to mapOf("kyc" to "ok")), got.context)
        assertEquals(emptyList<String>(), got.conflicts)
        // a supplied value under a bound object merges beside it
        got = MissingContext.bindContext(mapOf("action" to vr, "env" to mapOf("o" to mapOf("x" to 1))), mapOf("env" to mapOf("o" to mapOf("y" to 2))))
        assertEquals(mapOf("action" to vr, "env" to mapOf("o" to mapOf("x" to 1, "y" to 2))), got.context)
        assertEquals(emptyList<String>(), got.conflicts)
    }

    @Test
    fun collectGroupsAndLeaves() {
        escalate("all_of group", listOf(mapOf("all_of" to listOf(approved))), bound(), "env.approved")
        escalate("any_of group", listOf(mapOf("any_of" to listOf(leaf("env.a", "eq", 1), leaf("env.b", "eq", 2)))), bound(), "env.a", "env.b")
        escalate("a decided sibling names nothing", listOf(leaf("env.tier", "eq", "gold"), approved), bound(), "env.approved")
        escalate("an unknown root is missing", listOf(leaf("x", "eq", 1)), bound(), "x")
        deny("list condition", "ill_typed_context", listOf(listOf(1)))
        deny("string condition", "ill_typed_context", listOf("x"))
        deny("empty group", "ill_typed_context", listOf(mapOf("all_of" to emptyList<Any?>()), approved))
        deny("non-list group", "ill_typed_context", listOf(mapOf("any_of" to 5), approved))
        deny("ill-typed beside missing", "ill_typed_context", listOf(leaf("env.tier", "lt", 5), approved))
        deny("empty field", "ill_typed_context", listOf(leaf("", "eq", 1)))
        deny("non-string field", "ill_typed_context", listOf(leaf(5, "eq", 1)))
    }

    @Test
    fun collectParams() {
        val nullParams = mapOf("action" to mapOf("verb" to "v", "resource" to "r", "params" to null), "env" to emptyMap<String, Any?>())
        escalate("null params", listOf(leaf("action.params", "eq", 1)), nullParams, "action.params")
        val mapParams = mapOf("action" to mapOf("verb" to "v", "resource" to "r", "params" to mapOf("amount" to "x")))
        deny("ill-typed param", "ill_typed_context", listOf(leaf("action.params.amount", "lt", 5)), mapParams)
        val listParams = mapOf("action" to mapOf("verb" to "v", "resource" to "r", "params" to listOf("x")))
        deny("ill-typed list param", "ill_typed_context", listOf(leaf("action.params.0", "lt", 5)), listParams)
    }

    @Test
    fun collectDepthBudgetAndErrors() {
        fun nots(n: Int, inner: Any?): Any? {
            var c = inner
            repeat(n) { c = mapOf("not" to c) }
            return c
        }
        escalate("64 nots", listOf(nots(64, approved)), bound(), "env.approved")
        deny("65 nots", "ill_typed_context", listOf(nots(65, approved), leaf("env.k", "eq", 1)))
        // the 65th regex evaluation exhausts the document budget: undecided overall, yet each condition alone is true
        deny("regex budget", "ill_typed_context", List(65) { leaf("env.tier", "matches", "gold") })
        val two = listOf(leaf("action.params.a", "eq", 1), leaf("action.params.b", "eq", 1))
        check("two untrusted", "deny", "missing_context_untrusted: action.params.a,action.params.b",
            listOf("action.params.a" to "agent_declared_untrusted", "action.params.b" to "agent_declared_untrusted"),
            MissingContext.decideWithMissing(two, bound(), null, mapOf("action.params" to "agent_declared_untrusted")))
        deny("non-string supplied key", "evaluation error (fail closed)", listOf(approved), supplied = mapOf("env" to mapOf<Any?, Any?>(1 to "x")))
    }
}
