package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Authorize.kt k05 survivors, the semantic-firewall helpers: the number / scalar primitives (fin, isInt, jsEq, jsString, classRank),
 * the schema and value budgets at their exact boundaries (called directly with a Budget, so the guards are exercised alone), show()'s
 * surrogate handling, the tool_schema / agent-caveat fail-closed handlers (a throwing Map / List reaches them), and the default-deny
 * of an empty `predicates` allow list.
 */
@Suppress("UNCHECKED_CAST")
class Kill05AuthorizeSchemaTest {
    private val budgetCls = Class.forName("net.atlasauth.pca.verifier.Authorize\$Budget")

    private fun budget(n: Int): Any = budgetCls.getDeclaredConstructor(Int::class.javaPrimitiveType).also { it.isAccessible = true }.newInstance(n)
    private fun budgetN(b: Any): Int = budgetCls.getDeclaredMethod("getN").also { it.isAccessible = true }.invoke(b) as Int

    private fun eq(want: Any?, got: Any?) = assertEquals(want, got)

    private fun fin(x: Any?): Double? = KUtil.priv(Authorize, "fin", x)
    private fun isInt(x: Any?): Boolean = KUtil.priv(Authorize, "isInt", x)
    private fun jsEq(a: Any?, b: Any?): Boolean = KUtil.priv(Authorize, "jsEq", a, b)
    private fun show(s: String): String = KUtil.priv(Authorize, "show", s)
    private fun checkValue(spec: Map<String, Any?>, v: Any?, depth: Int, b: Any): String? = KUtil.priv(Authorize, "checkValue", spec, v, "p", depth, b)
    private fun objectSchemaError(depth: Int, b: Any): String? = KUtil.priv(Authorize, "objectSchemaError", emptyMap<String, Any?>(), false, null, depth, b)

    @Test fun finIsAFiniteJsonNumberOnly() {
        eq(2.5, fin(Json.Num("2.5")))
        eq(3.0, fin(Json.Num("3")))
        assertNull(fin(Json.Num("abc")))
        assertNull(fin(Json.Num("1e400")))
        eq(1.5, fin(1.5))
        eq(7.0, fin(7L))
        for (bad in listOf<Any?>(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Float.NaN, Float.POSITIVE_INFINITY, "1", true, null))
            assertNull("$bad", fin(bad))
    }

    @Test fun isIntRefusesFractionsNegativeZeroAndNonNumbers() {
        assertTrue(isInt(2L))
        assertTrue(isInt(Json.Num("3")))
        assertTrue(isInt(0.0))
        assertFalse(isInt(2.5))
        assertFalse(isInt(-0.0))
        assertFalse(isInt("2"))
        assertFalse(isInt(null))
        assertFalse(isInt(Double.NaN))
    }

    @Test fun jsEqNeverEquatesNonScalars() {
        assertTrue(jsEq("a", "a"))
        assertTrue(jsEq(1L, Json.Num("1")))
        assertTrue(jsEq(true, true))
        assertFalse(jsEq("a", null))
        assertFalse(jsEq(null, null))
        assertFalse(jsEq(listOf<Any?>(), listOf<Any?>()))
        assertFalse(jsEq(true, 1L))
    }

    @Test fun jsStringNormalizesNumbersFirst() {
        eq("1", KUtil.priv<String>(Authorize, "jsString", 1.0, true))
        eq("1.5", KUtil.priv<String>(Authorize, "jsString", Json.Num("1.50"), true))
        eq("undefined", KUtil.priv<String>(Authorize, "jsString", "x", false))
    }

    @Test fun classRankUnknownAndNonStringAreIrreversible() {
        eq(0, Revocation.classRank("reversible"))
        eq(1, Revocation.classRank("costly"))
        eq(1, Revocation.classRank("rate_limited"))
        eq(2, Revocation.classRank("irreversible"))
        eq(2, Revocation.classRank("weird"))
        eq(2, Revocation.classRank(5L))
        eq(2, Revocation.classRank(null))
    }

    @Test fun showEscapesLoneSurrogatesAndKeepsPairs() {
        eq("\"a\uD83D\uDE00b\"", show("a\uD83D\uDE00b"))
        eq("\"\\ud83d\"", show("\uD83D"))
        eq("\"\\ud83dx\"", show("\uD83Dx"))
        eq("\"\\ude00\"", show("\uDE00"))
        eq("\"\\ud83d\uD83D\uDE00\"", show("\uD83D\uD83D\uDE00"))
        eq("\"x\\ude00\\ud83d\"", show("x\uDE00\uD83D"))
        eq("\"\uD83D\uDE00\uD83D\uDE00\"", show("\uD83D\uDE00\uD83D\uDE00"))
    }

    @Test fun objectSchemaDepthAndNodeBudget() {
        assertNull(objectSchemaError(8, budget(0)))
        eq("schema too deep", objectSchemaError(9, budget(0)))
        val b = budget(255)
        assertNull(objectSchemaError(1, b))
        eq(256, budgetN(b))
        eq("schema too large", objectSchemaError(1, budget(256)))
    }

    @Test fun valueDepthNodeBudgetAndUnknownType() {
        val bool = mapOf<String, Any?>("type" to "boolean")
        assertNull(checkValue(bool, true, 9, budget(0)))
        eq("p: too deep", checkValue(bool, true, 10, budget(0)))
        val b = budget(9_999)
        assertNull(checkValue(bool, true, 2, b))
        eq(10_000, budgetN(b))
        eq("p: too many values", checkValue(bool, true, 2, budget(10_000)))
        eq("p: unknown type", checkValue(mapOf<String, Any?>("type" to "weird"), true, 2, budget(0)))
    }

    @Test fun aNullSchemaKeyIsUnknown() {
        val schema = HashMap<Any?, Any?>()
        schema[null] = 1L
        schema["props"] = LinkedHashMap<String, Any?>()
        eq("unknown schema key", Authorize.validateArgSchema(schema))
    }

    @Test fun enumMembersAreEachChecked() {
        fun s(spec: Map<String, Any?>) = Authorize.validateArgSchema(mapOf("props" to mapOf("a" to spec)))
        assertNull(s(mapOf("type" to "string", "enum" to listOf("x", "y"))))
        eq("a: bad enum", s(mapOf("type" to "string", "enum" to listOf("x", 5L))))
        eq("a: bad enum", s(mapOf("type" to "integer", "enum" to listOf(1L, Json.Num("1.5")))))
    }

    // ---- tool_schema evaluation

    private fun caveat(schema: Map<String, Any?>, tool: String = "t"): Map<String, Any?> = KUtil.m(
        "type" to "tool_schema", "tool" to tool, "schema" to schema, "schema_digest" to Pca.hashCanonical(schema), "signature_digest" to "sd",
        "binding_digest" to Pca.hashCanonical(linkedMapOf<String, Any?>("tool" to tool, "signature_digest" to "sd", "schema" to schema)),
    )

    private val schema: Map<String, Any?> = KUtil.m(
        "props" to KUtil.m("a" to KUtil.m("type" to "integer"), "e" to KUtil.m("type" to "string", "enum" to KUtil.l("x", "y"))),
        "required" to KUtil.l("a"),
    )

    @Test fun toolSchemaCallsAndEnums() {
        val cv = caveat(schema)
        eq(Authorize.ToolSchemaResult(true, null), Authorize.evaluateToolSchema(cv, KUtil.m("tool" to "t", "args" to KUtil.m("a" to 1L, "e" to "y"))))
        eq(Authorize.ToolSchemaResult(false, "args.e: violates enum"), Authorize.evaluateToolSchema(cv, KUtil.m("tool" to "t", "args" to KUtil.m("a" to 1L, "e" to "z"))))
        eq(Authorize.ToolSchemaResult(false, "args: missing required argument 'a'"), Authorize.evaluateToolSchema(cv, KUtil.m("tool" to "t", "args" to KUtil.m("e" to "x"))))
        eq(Authorize.ToolSchemaResult(false, "malformed call"), Authorize.evaluateToolSchema(cv, KUtil.m("tool" to 5L, "args" to KUtil.m("a" to 1L))))
        eq(Authorize.ToolSchemaResult(false, "malformed call"), Authorize.evaluateToolSchema(cv, KUtil.m("tool" to "t", "args" to 5L)))
        eq(Authorize.ToolSchemaResult(false, "malformed call"), Authorize.evaluateToolSchema(cv, 5L))
    }

    /** A Map / List whose reads throw [t] the first [n] times, then behave as [real]. */
    private class Flaky(val t: Throwable, var n: Int, val real: Map<String, Any?>) : AbstractMap<String, Any?>() {
        override val entries: Set<Map.Entry<String, Any?>>
            get() { if (n > 0) { n--; throw t }; return real.entries }
    }

    @Test fun toolSchemaEvaluationErrorsFailClosed() {
        val err = Authorize.ToolSchemaResult(false, "evaluation error (fail closed)")
        eq(err, Authorize.evaluateToolSchema(Flaky(IllegalStateException("x"), 1000, emptyMap()), KUtil.m("tool" to "t", "args" to KUtil.m())))
        eq(err, Authorize.evaluateToolSchema(Flaky(StackOverflowError(), 1000, emptyMap()), KUtil.m("tool" to "t", "args" to KUtil.m())))
    }

    // ---- agent-native caveats

    private val ctx: Map<String, Any?> = KUtil.m("now" to 1L)
    private val actionCtx: Map<String, Any?> = KUtil.m("action" to KUtil.m("verb" to "x", "resource" to "r"))

    private fun agent(vararg cvs: Any?) = Authorize.evaluateAgentCaveats(listOf(*cvs), ctx, actionCtx, null)

    @Test fun predicatesCaveatDefaultDeny() {
        eq(Caveats.Result(true, emptyList()), agent(KUtil.m("type" to "predicates", "allow" to KUtil.l(KUtil.m("verb" to "y"), KUtil.m("verb" to "x")))))
        eq(Caveats.Result(false, listOf("predicates")), agent(KUtil.m("type" to "predicates", "allow" to KUtil.l(KUtil.m("verb" to "y")))))
        eq(Caveats.Result(false, listOf("predicates")), agent(KUtil.m("type" to "predicates", "allow" to KUtil.l())))
        eq(Caveats.Result(false, listOf("predicates")), agent(KUtil.m("type" to "predicates", "allow" to "x")))
    }

    @Test fun anUnreadableCaveatFailsClosedUnderItsName() {
        // the first read of `type` throws inside the evaluator (fail closed), the second names the failing caveat
        eq(Caveats.Result(false, listOf("flaky")), agent(Flaky(IllegalStateException("x"), 1, mapOf("type" to "flaky"))))
        eq(Caveats.Result(false, listOf("flaky")), agent(Flaky(StackOverflowError(), 1, mapOf("type" to "flaky"))))
    }

    @Test fun malformedCaveatNames() {
        eq(Caveats.Result(false, listOf("<malformed>")), agent(5L))
        eq(Caveats.Result(false, listOf("<malformed>")), agent(KUtil.m("type" to 5L)))
        eq(Caveats.Result(false, listOf("<malformed caveats>")), Authorize.evaluateAgentCaveats("x", ctx))
    }

    @Test fun aThrowingCaveatListIsAnEvaluationError() {
        val bad = object : AbstractList<Any?>() {
            override val size: Int get() = 1
            override fun get(index: Int): Any? = throw IllegalStateException("x")
        }
        eq(Caveats.Result(false, listOf("<evaluation error>")), Authorize.evaluateAgentCaveats(bad, ctx))
    }
}
