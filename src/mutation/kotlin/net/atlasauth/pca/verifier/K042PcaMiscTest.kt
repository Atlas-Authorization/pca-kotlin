package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Intent-policy threshold parsing / validity, the fail-closed intent binding fault, the suite registry and the JavaScript string of a list. */
class K042PcaMiscTest {
    private val MAX_SAFE = 9007199254740991.0

    @Test fun thresholdParse() {
        val p = Pca.IntentPolicy.fromJson(mapOf("min_fidelity_ppm" to Json.Num("950000.0"), "max_residual_risk_ppm" to Json.Num("1e3")))!!
        assertEquals(950000.0, p.minFidelityPpm!!, 0.0)
        assertEquals(1000.0, p.maxResidualRiskPpm!!, 0.0)
        assertTrue(p.isActive); assertFalse(p.require)
        val bad = Pca.IntentPolicy.fromJson(mapOf("min_fidelity_ppm" to Json.Num("abc")))!!
        assertNotNull(bad.minFidelityPpm); assertTrue(bad.minFidelityPpm!!.isNaN()); assertNull(bad.maxResidualRiskPpm)
        assertEquals("intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)", Pca.decideIntent(null, false, mapOf(), bad))
        assertTrue(Pca.IntentPolicy.fromJson(mapOf("max_residual_risk_ppm" to Json.Num("--1")))!!.maxResidualRiskPpm!!.isNaN())
        assertEquals(5.0, Pca.IntentPolicy.fromJson(mapOf("min_fidelity_ppm" to 5L))!!.minFidelityPpm!!, 0.0)
        assertTrue(Pca.IntentPolicy.fromJson(mapOf("min_fidelity_ppm" to "5"))!!.minFidelityPpm!!.isNaN())
        assertTrue(Pca.IntentPolicy.fromJson(mapOf("min_fidelity_ppm" to null))!!.minFidelityPpm!!.isNaN())
        assertEquals(0.0, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\": 0}")!!.minFidelityPpm!!, 0.0)
        assertEquals(7.0, Pca.IntentPolicy.fromJsonText("{\"max_residual_risk_ppm\": 7}")!!.maxResidualRiskPpm!!, 0.0)
        assertNull(Pca.IntentPolicy.fromJson("x")); assertNull(Pca.IntentPolicy.fromJson(null))
        assertTrue(Pca.IntentPolicy.fromJson(mapOf("require" to true))!!.require)
        assertFalse(Pca.IntentPolicy.fromJson(mapOf("require" to "true"))!!.require)
    }

    @Test fun okThresholdEveryBound() {
        assertTrue(Pca.okThreshold(null)); assertTrue(Pca.okThreshold(0.0)); assertTrue(Pca.okThreshold(1.0)); assertTrue(Pca.okThreshold(950000.0)); assertTrue(Pca.okThreshold(MAX_SAFE))
        for (v in listOf(MAX_SAFE + 1, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, 1.5, 0.5, -1.0, -0.0, Double.MAX_VALUE)) assertFalse("$v", Pca.okThreshold(v))
    }

    @Test fun intentBindingFaultIsFailClosedWithTheExceptionClass() {
        val envelope = linkedMapOf<String, Any?>("type" to "envelope", "goal_commit" to "x")
        val grant = linkedMapOf<String, Any?>("caveats" to arrayListOf<Any?>(envelope))
        assertEquals("intent binding error (fail closed): ClassCastException", Pca.decideIntent("not-an-object", true, grant, null))
        assertEquals("intent binding error (fail closed): ClassCastException", Pca.decideIntent(7L, true, grant, Pca.IntentPolicy(require = true)))
    }

    @Test fun suiteRegistry() {
        val reg = Pq.REGISTERED_SUITES
        assertEquals(14, reg.size)
        assertEquals("ed25519", reg[0]); assertEquals("hybrid-ed25519-less-cat1", reg[13]); assertTrue(reg.contains("fn-dsa-512"))
        val sup = Pq.supportedSuites()
        assertTrue(sup.isNotEmpty()); assertEquals("ed25519", sup[0])
        assertEquals(reg.filter { it in sup }, sup)
        assertTrue(sup.containsAll(listOf("ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f")))
        assertFalse(sup.contains("fn-dsa-512"))
    }

    @Test fun jsStringOfLists() {
        val js = { v: Any? -> KUtil.priv<String>(ParamProvenance, "jsString", v) }
        assertEquals("a,b", js(arrayListOf<Any?>("a", "b")))
        assertEquals("1,,x", js(arrayListOf<Any?>(Json.Num("1"), null, "x")))
        assertEquals("a,b,c", js(arrayListOf<Any?>("a", arrayListOf<Any?>("b", "c"))))
        assertEquals("", js(arrayListOf<Any?>()))
        assertEquals("[object Object]", js(linkedMapOf<String, Any?>()))
        assertEquals("null", js(null))
        assertEquals("5", js(Json.Num("5")))
    }
}
