package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** The policy debugger against the reference corpus (ref-policy-debug, 553 cases): explainRisk, explainDecision, applyDelta, counterfactual, auditPCActn. */
@Suppress("UNCHECKED_CAST")
class PolicyDebugRefDiffTest {
    private val mod = "ref-policy-debug"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    /** The inverse of the corpus's non-finite spelling for a result: a non-finite number becomes `{"$num": text}`. */
    private fun enc(v: Any?): Any? = when (v) {
        is Json.Num -> if (v.raw == "NaN" || v.raw == "Infinity" || v.raw == "-Infinity") linkedMapOf<String, Any?>("\$num" to v.raw) else v
        is List<*> -> v.map { enc(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = enc(x) }
        else -> v
    }

    @Test fun everyFunction() {
        val verifyOptions = CoreVerifyDiffTest()
        OracleCases.each(mod, "explainRisk") { x -> enc(PolicyDebug.explainRisk(OracleCases.decNum(x[0]), OracleCases.decNum(x[1]), OracleCases.decNum(x[2]))) }
        OracleCases.each(mod, "explainDecision") { x -> enc(PolicyDebug.explainDecision(map(OracleCases.decNum(x[0])))) }
        OracleCases.each(mod, "applyDelta") { x -> enc(PolicyDebug.applyDelta(map(OracleCases.decNum(x[0])), map(OracleCases.decNum(x[1])))) }
        OracleCases.each(mod, "counterfactual") { x -> enc(PolicyDebug.counterfactual(map(OracleCases.decNum(x[0])), OracleCases.decNum(x[1]) as List<Any?>)) }
        OracleCases.each(mod, "auditPCActn") { x -> enc(PolicyDebug.auditPCActn(x[0], map(OracleCases.decNum(x[1])), verifyOptions.options(map(x[2])))) }
        val fns = setOf("explainRisk", "explainDecision", "applyDelta", "counterfactual", "auditPCActn")
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(553, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
