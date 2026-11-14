package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kill tests for PcaDecision (k05 small group); outcomes and reasons follow packages/pca/src/decision.ts. */
class Kill05SmallPcaDecisionTest {
    private fun n(s: String) = Json.Num(s)
    private fun mp(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> { val r = LinkedHashMap<String, Any?>(); for ((k, v) in kv) r[k] = v; return r }

    @Test fun meetAndPrefixes() {
        assertEquals("deny", PcaDecision.meet("bogus", "allow"))
        assertEquals("deny", PcaDecision.meet("allow", "bogus"))
        assertEquals("escalate", PcaDecision.meet("escalate", "allow"))
        assertEquals("escalate", PcaDecision.meet("allow", "escalate"))
        assertEquals(listOf("intent_required:", "escalate:"), PcaDecision.ESCALATE_REASON_PREFIXES)
    }

    @Test fun decisionOfTable() {
        val fail = mapOf("a" to "fail")
        assertEquals("allow", PcaDecision.decisionOf(true, fail, emptyList()))
        assertEquals("escalate", PcaDecision.decisionOf(false, fail, listOf("a: escalate: x")))
        assertEquals("escalate", PcaDecision.decisionOf(false, fail, listOf("a: intent_required: y", "a: escalate: z", "b: other")))
        assertEquals("deny", PcaDecision.decisionOf(false, fail, listOf("a: ESCALATE: x"))) // prefixes are case-sensitive
        assertEquals("deny", PcaDecision.decisionOf(false, fail, listOf("A: escalate: x"))) // so is the check name
        assertEquals("deny", PcaDecision.decisionOf(false, fail, listOf("a: escalate: x", "a: other")))
        assertEquals("deny", PcaDecision.decisionOf(false, fail, listOf("a: other", "a: escalate: x")))
        assertEquals("deny", PcaDecision.decisionOf(false, fail, emptyList()))
        assertEquals("deny", PcaDecision.decisionOf(false, mapOf("a" to "pass"), listOf("a: escalate: x")))
        assertEquals("escalate", PcaDecision.decisionOf(false, mapOf("a" to "fail", "b" to "fail"), listOf("a: escalate: x", "b: intent_required: y")))
        assertEquals("deny", PcaDecision.decisionOf(false, mapOf("a" to "fail", "b" to "fail"), listOf("a: escalate: x")))
    }

    @Test fun decisionOfJson() {
        assertEquals("deny", PcaDecision.decisionOf("x"))
        assertEquals("deny", PcaDecision.decisionOf(mp()))
        assertEquals("deny", PcaDecision.decisionOf(mp("checks" to "x", "reasons" to arrayListOf<Any?>("a: escalate: x"))))
        assertEquals("allow", PcaDecision.decisionOf(mp("allow" to true)))
        assertEquals("escalate", PcaDecision.decisionOf(mp("checks" to mp("a" to "fail"), "reasons" to arrayListOf<Any?>(n("5"), "a: escalate: x"))))
        assertEquals("deny", PcaDecision.decisionOf(mp("checks" to mp("a" to "fail"))))
        assertEquals("deny", PcaDecision.decisionOf(mp("checks" to mp("a" to "fail"), "reasons" to "a: escalate: x")))
        assertEquals("deny", PcaDecision.decisionOf(mp("checks" to mp("a" to n("5")), "reasons" to arrayListOf<Any?>("a: escalate: x"))))
        val intKeyed = HashMap<Any?, Any?>(); intKeyed[1] = "fail"
        assertEquals("deny", PcaDecision.decisionOf(mp("checks" to intKeyed, "reasons" to arrayListOf<Any?>("1: escalate: x"))))
    }

    @Test fun foldV2() {
        val ok = PcaDecision.V2Check("a", true, "r")
        assertTrue(ok.ok)
        val got = PcaDecision.foldV2Reasons(listOf("x"), listOf(ok, PcaDecision.V2Check("b", false, null), PcaDecision.V2Check("c", false, "r"), PcaDecision.V2Check("c", false, "r")))
        assertEquals(listOf("x", "c: r"), got)
    }

    @Test fun unitTagCountAndModelPaths() {
        fun tagTable(k: Int): LinkedHashMap<String, Any?> { val u = LinkedHashMap<String, Any?>(); for (i in 0 until k) u["action.params.p$i"] = mp("kind" to "m"); return u }
        assertNull(PcaDecision.unitTagsError(tagTable(64)))
        assertEquals("units has more than 64 entries", PcaDecision.unitTagsError(tagTable(65)))
        assertFalse(PcaDecision.isModelDerivedPath(n("5")))
        assertTrue(PcaDecision.isModelDerivedPath("env.class.x"))
    }

    private fun nest(levels: Int): Any? {
        var c: Any? = mp("field" to "env.class.x", "op" to "exists")
        repeat(levels) { c = mp("all_of" to arrayListOf(c)) }
        return c
    }
    private fun predsWhere(vararg conds: Any?) = arrayListOf<Any?>(arrayListOf<Any?>(mp("verb" to "*", "where" to arrayListOf(*conds))))

    @Test fun collectPathsDepthLimit() {
        assertEquals(listOf("env.class.x"), PcaDecision.modelPathsRead(predsWhere(nest(64))))
        assertEquals(emptyList<String>(), PcaDecision.modelPathsRead(predsWhere(nest(65))))
    }

    @Test fun tightenResults() {
        val r = PcaDecision.TightenResult("deny", false, listOf("p"), "why")
        assertEquals("TightenResult(outcome=deny, legacy=false, offending=[p], reason=why)", r.toString())
        assertEquals("UnitsResult(ok=false, reason=m)", PcaDecision.UnitsResult(false, "m").toString())

        val world = predsWhere(mp("field" to "env.world", "op" to "exists"))
        assertEquals("ok", PcaDecision.decideTighten(mp("predicates" to world, "single_source" to arrayListOf<Any?>(n("5")))).outcome)
        val single = PcaDecision.decideTighten(mp("predicates" to world, "single_source" to arrayListOf<Any?>("w")))
        assertEquals("deny", single.outcome)
        assertEquals(listOf("env.world"), single.offending)

        val rule = arrayListOf<Any?>(mp("id" to "r1", "when" to mp("field" to "env.x", "op" to "eq", "value" to n("1")), "signal" to "deny"))
        val unknown = PcaDecision.decideTighten(mp("tighten" to rule, "context" to "x"))
        assertEquals("escalate", unknown.outcome)
        assertEquals("escalate: rule 'r1' could not be decided (a value it reads is missing or ill-typed)", unknown.reason)
        val hit = PcaDecision.decideTighten(mp("tighten" to rule, "context" to mp("env" to mp("x" to n("1")))))
        assertEquals("deny", hit.outcome)
        assertEquals("denied by tighten rule 'r1'", hit.reason)
        val none = PcaDecision.decideTighten(mp())
        assertEquals("ok", none.outcome)
        assertNull(none.reason)
    }

    private class Throwing(val t: Throwable) : LinkedHashMap<String, Any?>() {
        override fun get(key: String): Any? = throw t
    }

    @Test fun evaluationErrorsFailClosed() {
        val t = PcaDecision.decideTighten(Throwing(IllegalStateException("boom")))
        assertEquals("deny", t.outcome)
        assertFalse(t.legacy)
        assertEquals(emptyList<String>(), t.offending)
        assertEquals("evaluation error (fail closed): boom", t.reason)
        assertEquals("evaluation error (fail closed): unknown", PcaDecision.decideTighten(Throwing(IllegalStateException())).reason)
        val so = PcaDecision.decideTighten(Throwing(StackOverflowError()))
        assertEquals("evaluation error (fail closed): unknown", so.reason)
        assertEquals(emptyList<String>(), so.offending)
        val u = PcaDecision.decideUnits(Throwing(IllegalStateException("boom")))
        assertFalse(u.ok)
        assertEquals("evaluation error (fail closed): boom", u.reason)
        assertEquals("evaluation error (fail closed): unknown", PcaDecision.decideUnits(Throwing(IllegalStateException())).reason)
        assertEquals("evaluation error (fail closed): unknown", PcaDecision.decideUnits(Throwing(StackOverflowError())).reason)
    }

    private val money = mp("kind" to "money", "currency" to "usd")
    private fun units(schemaTag: Any?, policyTag: Map<String, Any?> = money, unitId: Any? = "u1", preds: Any? = null, extraParams: Map<String, Any?> = mp()): PcaDecision.UnitsResult {
        val params = mp("action.params.amt" to mp("unit" to unitId)); params.putAll(extraParams)
        val input = mp("units" to mp("action.params.amt" to policyTag), "verb" to "pay", "verb_params" to params, "schema_units" to mp("u1" to schemaTag))
        if (preds != null) input["predicates"] = preds
        return PcaDecision.decideUnits(input)
    }
    private fun confusion(declared: String, tagged: String) =
        "'action.params.amt' is declared as $declared by the action schema but the policy term is tagged $tagged (unit confusion)"

    @Test fun unitsComparisonAndText() {
        assertTrue(units(money).ok)
        assertEquals(confusion("?/usd", "money/usd"), units(mp("currency" to "usd")).reason)
        assertEquals(confusion("?/usd", "money/usd"), units(mp("kind" to null, "currency" to "usd")).reason)
        assertEquals(confusion("money/null", "money"), units(mp("kind" to "money", "currency" to null), mp("kind" to "money")).reason)
        assertEquals(confusion("time/usd", "money/usd"), units(mp("kind" to "time", "currency" to "usd")).reason)
        assertEquals(confusion("money/eur", "money/usd"), units(mp("kind" to "money", "currency" to "eur")).reason)
        assertEquals(confusion("money/usd/e2", "money/usd/e3"),
            units(mp("kind" to "money", "currency" to "usd", "exponent" to n("2")), mp("kind" to "money", "currency" to "usd", "exponent" to n("3"))).reason)
        assertTrue(units(mp("kind" to "money", "currency" to "usd", "exponent" to n("2")), mp("kind" to "money", "currency" to "usd", "exponent" to n("2"))).ok)
        assertEquals(confusion("no unit", "money/usd"), units(money, unitId = n("5")).reason)
    }

    @Test fun untaggedReads() {
        val readsQ = predsWhere(mp("field" to "action.params.q", "op" to "exists"))
        assertEquals("a policy term reads 'action.params.q' (money/usd) without a unit tag",
            units(money, preds = readsQ, extraParams = mp("action.params.q" to mp("unit" to "u1"))).reason)
        // a declared parameter whose unit id is unknown carries no unit: reading it untagged is fine
        assertTrue(units(money, preds = readsQ, extraParams = mp("action.params.q" to mp("unit" to "nope"))).ok)
        // a path that is not action.params.<name> is never unit-checked, even when the verb's table names it
        val readsEnv = predsWhere(mp("field" to "env.x", "op" to "exists"))
        assertTrue(units(money, preds = readsEnv, extraParams = mp("env.x" to mp("unit" to "u1"))).ok)
    }
}
