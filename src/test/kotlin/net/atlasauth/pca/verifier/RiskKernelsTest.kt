package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The numeric kernels of the risk plane: score, threshold, escalation, budget leak / debit / age, admission, rounding, merge, geodesic. */
class RiskKernelsTest {
    private val weights: Map<String, Any?> = linkedMapOf("alpha" to 0.25, "beta" to 0.2, "gamma" to 0.2, "delta" to 0.2, "epsilon" to 0.1, "zeta" to 0.05)
    private val calm: Map<String, Any?> = linkedMapOf("semanticDistance" to 0.0, "reversibility" to 1.0, "blastRadius" to 0.0, "taint" to 0.0, "confidence" to 1.0, "age" to 0.0)

    @Test fun theScoreIsTheWeightedSumClampedAndAMissingInputIsItsWorstCase() {
        assertEquals(0.0, Risk.riskScore(calm, weights), 0.0)
        assertEquals(1.0, Risk.riskScore(emptyMap(), weights), 1e-9)
        assertEquals(1.0, Risk.riskScore(linkedMapOf("semanticDistance" to Double.NaN, "reversibility" to "x"), weights), 1e-9)
        assertEquals(0.25, Risk.riskScore(calm + mapOf("semanticDistance" to 1.0), weights), 1e-9)
        assertEquals(0.25, Risk.riskScore(calm + mapOf("semanticDistance" to 7.0), weights), 1e-9) // an input above 1 is clamped to 1
        assertEquals(0.0, Risk.riskScore(calm + mapOf("semanticDistance" to -3.0), weights), 1e-9)
        assertEquals(0.2, Risk.riskScore(calm + mapOf("reversibility" to 0.0), weights), 1e-9)
        assertEquals(0.1, Risk.riskScore(calm + mapOf("confidence" to 0.0), weights), 1e-9)
        assertEquals(0.05, Risk.riskScore(calm + mapOf("age" to 1.0), weights), 1e-9)
        // a negative or non-numeric weight counts as 0
        assertEquals(0.0, Risk.riskScore(calm + mapOf("semanticDistance" to 1.0), weights + mapOf("alpha" to -1.0)), 0.0)
        assertEquals(0.0, Risk.riskScore(calm + mapOf("semanticDistance" to 1.0), weights + mapOf("alpha" to "x")), 0.0)
        assertEquals(1.0, Risk.riskScore(emptyMap(), mapOf("alpha" to 5.0)), 0.0) // the sum is clamped to 1
    }

    private val policy = Risk.Policy.of(linkedMapOf("weights" to weights, "theta1" to 0.25, "theta2" to 0.6, "kappa" to 1.0, "lambda" to 0.0005, "rho" to 0.5, "bMax" to 1.0))!!

    @Test fun thePolicyReadsOnlyFiniteNumbers() {
        assertEquals(0.25, policy.theta1, 0.0)
        assertEquals(1.0, policy.bMax, 0.0)
        assertNull(Risk.Policy.of(null))
        assertNull(Risk.Policy.of(linkedMapOf("weights" to weights, "theta1" to "x", "theta2" to 0.6, "kappa" to 1.0, "lambda" to 0.0, "rho" to 0.5, "bMax" to 1.0)))
        assertNull(Risk.Policy.of(linkedMapOf("theta1" to 0.25, "theta2" to 0.6, "kappa" to 1.0, "lambda" to 0.0, "rho" to 0.5, "bMax" to 1.0)))
    }

    @Test fun theThresholdMapAndItsEscalation() {
        fun t(r: Double, irr: Boolean = false) = Risk.requiredThreshold(r, policy, irr)
        assertEquals(1, t(0.25).t)
        assertEquals("claim", t(0.25).proof)
        assertTrue(t(0.25).optimisticAllowed)
        assertFalse(t(0.25, true).optimisticAllowed) // never optimistic for an irreversible action
        assertEquals(2, t(0.26).t)
        assertEquals("standard", t(0.26).proof)
        assertFalse(t(0.26).optimisticAllowed)
        assertEquals(2, t(0.6).t)
        assertEquals(3, t(0.61).t)
        assertEquals("strong", t(0.61).proof)
        assertEquals(3, t(Double.NaN).t)
        assertEquals(3, t(Double.POSITIVE_INFINITY).t)
        val e = Risk.escalateThreshold(Risk.Threshold(1, "claim", true), 2)
        assertEquals(2, e.t)
        assertEquals("standard", e.proof)
        assertFalse(e.optimisticAllowed)
        val keep = Risk.escalateThreshold(Risk.Threshold(1, "claim", true), 0)
        assertEquals(1, keep.t)
        assertTrue(keep.optimisticAllowed)
        val never = Risk.escalateThreshold(Risk.Threshold(3, "strong", false), 2) // never lowered
        assertEquals(3, never.t)
        assertEquals("strong", never.proof)
        assertEquals("strong", Risk.escalateThreshold(Risk.Threshold(2, "strong", false), 2).proof) // a stronger proof is kept
        assertEquals("strong", Risk.escalateThreshold(Risk.Threshold(1, "claim", true), 3).proof)
    }

    @Test fun theBudgetLeaksDebitsAndAges() {
        assertEquals(1.0, Risk.cost(0.5, 2.0), 0.0)
        assertEquals(2.0, Risk.cost(Double.NaN, 2.0), 0.0)
        assertEquals(1.0, Risk.cost(2.0, 1.0), 0.0)
        assertEquals(0.0, Risk.cost(0.5, -1.0), 0.0)
        val b = Risk.Budget(10.0, 0.0)
        val leaked = Risk.leak(b, 10_000.0, 0.5)
        assertEquals(5.0, leaked.B, 1e-12)
        assertEquals(0.0, leaked.tau, 0.0)
        assertEquals(10_000.0, leaked.asOf!!, 0.0)
        assertEquals(5.0, Risk.leak(leaked, 10_000.0, 0.5).B, 1e-12) // idempotent at the same now
        assertEquals(0.0, Risk.leak(b, 10_000.0, 10.0).B, 0.0) // floored at 0
        val back = Risk.leak(Risk.Budget(10.0, 0.0, 5_000.0), 1_000.0, 0.5) // a clock that went back leaks nothing and keeps asOf
        assertEquals(10.0, back.B, 0.0)
        assertEquals(5_000.0, back.asOf!!, 0.0)
        assertEquals(10.0, Risk.leak(b, Double.NaN, 0.5).B, 0.0)
        assertEquals(10.0, Risk.leak(b, 10_000.0, -1.0).B, 0.0)
        assertEquals(3.0, Risk.debit(Risk.Budget(5.0, 0.0), 2.0).B, 0.0)
        assertEquals(0.0, Risk.debit(Risk.Budget(5.0, 0.0), 9.0).B, 0.0)
        assertEquals(5.0, Risk.debit(Risk.Budget(5.0, 0.0), -1.0).B, 0.0)
        val bt = Risk.Budget(1.0, 0.0)
        assertEquals(0.5, Risk.ageSinceTouch(bt, 1_800_000.0), 0.0)
        assertEquals(1.0, Risk.ageSinceTouch(bt, 7_200_000.0), 0.0)
        assertEquals(0.0, Risk.ageSinceTouch(Risk.Budget(1.0, 5.0), 1.0), 0.0)
        assertEquals(1.0, Risk.ageSinceTouch(bt, 1.0, 0.0), 0.0)
        assertEquals(1.0, Risk.ageSinceTouch(bt, Double.NaN), 0.0)
        assertEquals(0.5, Risk.ageSinceTouch(bt, 500.0, 1000.0), 0.0)
    }

    @Test fun admissionAndRounding() {
        Risk.admitOf(1, true).let { assertTrue(it.admit); assertFalse(it.needStepUp); assertEquals(1, it.t); assertTrue(it.metered) }
        Risk.admitOf(1, false).let { assertFalse(it.admit); assertTrue(it.needStepUp); assertEquals(3, it.t); assertFalse(it.metered) }
        Risk.admitOf(2, true).let { assertFalse(it.admit); assertTrue(it.needStepUp); assertEquals(2, it.t); assertTrue(it.metered) }
        Risk.admitOf(2, false).let { assertEquals(3, it.t); assertFalse(it.metered) }
        Risk.admitOf(3, true).let { assertFalse(it.admit); assertTrue(it.needStepUp); assertEquals(3, it.t); assertFalse(it.metered) }
        assertEquals("0.063", Risk.toFixed3(0.0625))
        assertEquals("0.500", Risk.toFixed3(0.5))
        assertEquals("1.000", Risk.toFixed3(1.0))
        assertEquals("0.000", Risk.toFixed3(0.0))
        assertEquals("0.000", Risk.toFixed3(0.0004))
        assertEquals("0.001", Risk.toFixed3(0.0005))
    }

    @Test fun theRiskierOfTwoInputSets() {
        assertNull(Risk.riskier(null, null))
        val a = mapOf<String, Any?>("semanticDistance" to 0.2, "reversibility" to 0.5)
        assertSame(a, Risk.riskier(a, null))
        assertSame(a, Risk.riskier(null, a))
        val m = Risk.riskier(a, mapOf("semanticDistance" to 0.4, "reversibility" to 0.3, "taint" to 0.9))!!
        assertEquals(0.4, m["semanticDistance"])
        assertEquals(0.3, m["reversibility"]) // lower reversibility is riskier
        assertEquals(0.9, m["taint"]) // an input only the second side has stands
        val keep = Risk.riskier(a, mapOf("semanticDistance" to 0.1, "reversibility" to 0.9, "blastRadius" to Double.NaN, "age" to "x"))!!
        assertEquals(0.2, keep["semanticDistance"])
        assertEquals(0.5, keep["reversibility"])
        assertFalse(keep.containsKey("blastRadius")) // a non-finite value never enters
        assertFalse(keep.containsKey("age"))
        assertEquals(0.7, Risk.riskier(mapOf("confidence" to 0.8), mapOf("confidence" to 0.7))!!["confidence"])
    }

    @Test fun thePlanGeodesic() {
        val flat = listOf(mapOf("id" to "a"), mapOf("id" to "b"), mapOf("id" to "c"))
        assertEquals(1.0, Risk.planGeodesic(flat, "a", "c"), 1e-12)
        assertEquals(0.5, Risk.planGeodesic(flat, "a", "b"), 1e-12)
        assertEquals(0.0, Risk.planGeodesic(flat, "b", "b"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(flat, "a", "zzz"), 0.0)
        assertEquals(1.0, Risk.planGeodesic("x", "a", "b"), 0.0)
        val dag = listOf(mapOf("id" to "a"), mapOf("id" to "b", "pre" to "a"), mapOf("id" to "c", "pre" to listOf("b")), mapOf("id" to "d"))
        assertEquals(1.0 / 3, Risk.planGeodesic(dag, "a", "b"), 1e-12)
        assertEquals(2.0 / 3, Risk.planGeodesic(dag, "a", "c"), 1e-12)
        assertEquals(2.0 / 3, Risk.planGeodesic(dag, "c", "a"), 1e-12) // undirected
        assertEquals(1.0, Risk.planGeodesic(dag, "a", "d"), 0.0) // unreachable
        val post = listOf(mapOf("id" to "a", "post" to mapOf("then" to "b")), mapOf("id" to "b"), mapOf("id" to "c", "pre" to mapOf("after" to "b")))
        assertEquals(1.0, Risk.planGeodesic(post, "a", "c"), 1e-12)
    }
}
