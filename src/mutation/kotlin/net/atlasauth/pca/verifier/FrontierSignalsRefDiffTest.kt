package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** The frontier signal typing and the risk-input tightening against the reference corpus (ref-frontier-signals, 690 cases). */
@Suppress("UNCHECKED_CAST")
class FrontierSignalsRefDiffTest {
    private val mod = "ref-frontier-signals"

    private fun a(x: List<Any?>, i: Int): Any? = OracleCases.decNum(x[i])

    /** Members of a number, string or array read as undefined in the reference; null and undefined throw. */
    @Suppress("UNCHECKED_CAST")
    private fun members(v: Any?): Map<String, Any?> = if (v is Map<*, *>) v as Map<String, Any?> else if (v == null) throw NullPointerException("cannot read properties of null") else emptyMap()

    @Test fun everyFunction() {
        OracleCases.each(mod, "semanticSignal") { x -> FrontierSignals.semanticSignal(a(x, 0)) }
        OracleCases.each(mod, "progressSignal") { x -> FrontierSignals.progressSignal(a(x, 0)) }
        OracleCases.each(mod, "objectiveSignal") { x -> FrontierSignals.objectiveSignal(a(x, 0)) }
        OracleCases.each(mod, "tightenRiskInputs") { x -> FrontierSignals.tightenRiskInputs(members(a(x, 0)), members(a(x, 1))) }
        val fns = setOf("semanticSignal", "progressSignal", "objectiveSignal", "tightenRiskInputs")
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(690, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
