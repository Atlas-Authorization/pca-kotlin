package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kotlin 0.5 mutation kills for [Risk] (group k5), from packages/pca/src/risk.ts: the risk functional per term (the worst case of every
 * missing input, the clamps, the non-negative weights), the threshold map and its escalation, the budget kernels (cost, leak, debit, age)
 * with every non-finite input, the admission table, `toFixed3`, the policy reader, and the plan geodesic with every reference key of the
 * reference (`after` / `depends_on` / `requires` / `nodes` and `before` / `enables` / `then` / `next`).
 */
@Suppress("UNCHECKED_CAST")
class Kill08K5RiskTest {
    private fun raw(d: Double) = java.lang.Double.doubleToRawLongBits(d)
    private fun near(want: Double, got: Double) = assertEquals(want, got, 1e-12)

    // ---- the policy reader and the constants ----

    @Test fun constants() {
        assertEquals(listOf("alpha", "beta", "gamma", "delta", "epsilon", "zeta"), Risk.WEIGHT_KEYS)
        assertEquals(listOf("semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"), Risk.INPUT_KEYS)
        assertEquals(mapOf("semanticDistance" to 1.0, "reversibility" to 0.0, "blastRadius" to 1.0, "taint" to 1.0, "confidence" to 0.0, "age" to 1.0), Risk.WORST)
    }

    private fun pol(over: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>(
            "weights" to mapOf<String, Any?>("alpha" to 0.5), "theta1" to 0.1, "theta2" to 0.2, "kappa" to 0.3, "lambda" to 0.4, "rho" to 0.5, "bMax" to 0.6,
        )
        for ((k, v) in over) if (v == null) m.remove(k) else m[k] = v
        return m
    }

    @Test fun thePolicyReaderMapsEveryMember() {
        val w = mapOf<String, Any?>("alpha" to 0.5)
        val p = Risk.Policy.of(pol(mapOf("weights" to w)))!!
        assertSame(w, p.weights)
        assertEquals(0.1, p.theta1, 0.0)
        assertEquals(0.2, p.theta2, 0.0)
        assertEquals(0.3, p.kappa, 0.0)
        assertEquals(0.4, p.lambda, 0.0)
        assertEquals(0.5, p.rho, 0.0)
        assertEquals(0.6, p.bMax, 0.0)
        // number lexemes read like numbers
        val q = Risk.Policy.of(pol(mapOf("lambda" to Json.Num("7"), "rho" to Json.Num("8"), "bMax" to Json.Num("9"))))!!
        assertEquals(7.0, q.lambda, 0.0)
        assertEquals(8.0, q.rho, 0.0)
        assertEquals(9.0, q.bMax, 0.0)
    }

    @Test fun thePolicyReaderRefusesEachMalformedMember() {
        assertNull(Risk.Policy.of(null))
        for (bad in listOf<Any?>(null, "x", 5L, listOf<Any?>())) assertNull("weights $bad", Risk.Policy.of(pol(mapOf("weights" to bad))))
        for (key in listOf("theta1", "theta2", "kappa", "lambda", "rho", "bMax")) {
            for (bad in listOf<Any?>(null, "1", true, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, listOf<Any?>())) {
                assertNull("$key=$bad", Risk.Policy.of(pol(mapOf(key to bad))))
            }
            assertNotNull(key, Risk.Policy.of(pol(mapOf(key to 0.0))))
        }
    }

    // ---- fin / clamp01 ----

    @Test fun finIsAFiniteJavaScriptNumberOnly() {
        assertEquals(1.5, Risk.fin(1.5)!!, 0.0)
        assertEquals(0.0, Risk.fin(0L)!!, 0.0)
        assertEquals(-3.0, Risk.fin(Json.Num("-3"))!!, 0.0)
        for (bad in listOf<Any?>(null, "1", true, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, listOf<Any?>(), mapOf<String, Any?>())) assertNull("$bad", Risk.fin(bad))
    }

    @Test fun clamp01KeepsItsFixedPoints() {
        assertEquals(0.0, Risk.clamp01(-1.0), 0.0)
        assertEquals(0.0, Risk.clamp01(0.0), 0.0)
        assertEquals(0.5, Risk.clamp01(0.5), 0.0)
        assertEquals(1.0, Risk.clamp01(1.0), 0.0)
        assertEquals(1.0, Risk.clamp01(2.0), 0.0)
        // negative zero is not below zero: it is returned as is
        assertEquals(raw(-0.0), raw(Risk.clamp01(-0.0)))
        assertEquals(raw(0.0), raw(Risk.clamp01(0.0)))
        assertEquals(raw(1.0), raw(Risk.clamp01(1.0)))
    }

    // ---- riskScore ----

    private fun w(vararg kv: Pair<String, Any?>): Map<String, Any?> = mapOf(*kv)

    @Test fun eachTermUsesTheWorstCaseOfItsMissingInput() {
        for (key in Risk.WEIGHT_KEYS) near(0.1, Risk.riskScore(emptyMap(), w(key to 0.1)))
        // non-finite and non-number inputs are the worst case too
        for (bad in listOf<Any?>(Double.NaN, Double.POSITIVE_INFINITY, "0.5", null, true)) {
            val inputs = Risk.INPUT_KEYS.associateWith { bad }
            for (key in Risk.WEIGHT_KEYS) near(0.1, Risk.riskScore(inputs, w(key to 0.1)))
        }
    }

    @Test fun theFunctionalIsTheWeightedSumClampedToTheUnitInterval() {
        val i = mapOf<String, Any?>("semanticDistance" to 0.2, "reversibility" to 0.4, "blastRadius" to 0.6, "taint" to 0.8, "confidence" to 0.5, "age" to 0.25)
        val ws = w("alpha" to 0.5, "beta" to 0.3, "gamma" to 0.1, "delta" to 0.05, "epsilon" to 0.02, "zeta" to 0.01)
        near(0.1 + 0.18 + 0.06 + 0.04 + 0.01 + 0.0025, Risk.riskScore(i, ws))
        // each input moves exactly its own term
        near(0.5 * 1.0 + 0.3 * 0.6 + 0.1 * 0.6 + 0.05 * 0.8 + 0.02 * 0.5 + 0.01 * 0.25, Risk.riskScore(i + ("semanticDistance" to 7.0), ws))
        near(0.5 * 0.2 + 0.3 * 1.0 + 0.1 * 0.6 + 0.05 * 0.8 + 0.02 * 0.5 + 0.01 * 0.25, Risk.riskScore(i + ("reversibility" to -3.0), ws))
        near(0.5 * 0.2 + 0.3 * 0.6 + 0.1 * 1.0 + 0.05 * 0.8 + 0.02 * 0.5 + 0.01 * 0.25, Risk.riskScore(i + ("blastRadius" to 1.5), ws))
        near(0.5 * 0.2 + 0.3 * 0.6 + 0.1 * 0.6 + 0.05 * 0.0 + 0.02 * 0.5 + 0.01 * 0.25, Risk.riskScore(i + ("taint" to -0.1), ws))
        near(0.5 * 0.2 + 0.3 * 0.6 + 0.1 * 0.6 + 0.05 * 0.8 + 0.02 * 1.0 + 0.01 * 0.25, Risk.riskScore(i + ("confidence" to -9.0), ws))
        near(0.5 * 0.2 + 0.3 * 0.6 + 0.1 * 0.6 + 0.05 * 0.8 + 0.02 * 0.5 + 0.01 * 1.0, Risk.riskScore(i + ("age" to 100.0), ws))
        // the sum is clamped
        assertEquals(1.0, Risk.riskScore(emptyMap(), w("alpha" to 2.0, "beta" to 2.0)), 0.0)
        assertEquals(1.0, Risk.riskScore(emptyMap(), w("alpha" to 1.0)), 0.0)
        assertEquals(0.0, Risk.riskScore(i, emptyMap()), 0.0)
    }

    @Test fun weightsAreClampedToNonNegativeAndNonFiniteWeightsCountNothing() {
        near(0.0, Risk.riskScore(emptyMap(), w("alpha" to -1.0)))
        near(0.1, Risk.riskScore(emptyMap(), w("alpha" to -1.0, "beta" to 0.1)))
        near(0.1, Risk.riskScore(emptyMap(), w("alpha" to Double.NaN, "beta" to 0.1, "gamma" to Double.POSITIVE_INFINITY, "delta" to "0.4")))
        // an all-negative-zero weight set scores positive zero
        val negZero = Risk.WEIGHT_KEYS.associateWith { -0.0 }
        assertEquals(raw(0.0), raw(Risk.riskScore(emptyMap(), negZero)))
        assertEquals(raw(0.0), raw(Risk.riskScore(emptyMap(), emptyMap())))
    }

    // ---- thresholds ----

    private fun p(t1: Double, t2: Double) = Risk.Policy(emptyMap(), t1, t2, 1.0, 1.0, 1.0, 1.0)

    private fun thr(t: Risk.Threshold, tt: Int, proof: String, opt: Boolean) {
        assertEquals(tt, t.t)
        assertEquals(proof, t.proof)
        assertEquals(opt, t.optimisticAllowed)
    }

    @Test fun theThresholdMapIsPiecewiseWithInclusiveUpperBounds() {
        val pp = p(0.3, 0.6)
        thr(Risk.requiredThreshold(0.0, pp), 1, "claim", true)
        thr(Risk.requiredThreshold(0.3, pp), 1, "claim", true)
        thr(Risk.requiredThreshold(0.3000001, pp), 2, "standard", false)
        thr(Risk.requiredThreshold(0.6, pp), 2, "standard", false)
        thr(Risk.requiredThreshold(0.6000001, pp), 3, "strong", false)
        thr(Risk.requiredThreshold(1.0, pp), 3, "strong", false)
        // optimistic acceptance is never allowed for an irreversible action, nor above t=1
        thr(Risk.requiredThreshold(0.1, pp, true), 1, "claim", false)
        thr(Risk.requiredThreshold(0.1, pp, false), 1, "claim", true)
        thr(Risk.requiredThreshold(0.5, pp, false), 2, "standard", false)
        thr(Risk.requiredThreshold(0.9, pp, false), 3, "strong", false)
    }

    @Test fun aNonFiniteRiskIsTheWorstCaseOfOne() {
        val pp = p(0.3, 1.0) // theta2 = 1: the worst case lands on t=2, not t=3
        for (r in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) thr(Risk.requiredThreshold(r, pp), 2, "standard", false)
        thr(Risk.requiredThreshold(1.0, pp), 2, "standard", false)
        thr(Risk.requiredThreshold(1.0000001, pp), 3, "strong", false)
        val tight = p(0.3, 0.6)
        for (r in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) thr(Risk.requiredThreshold(r, tight), 3, "strong", false)
    }

    @Test fun escalationNeverLowersAnything() {
        thr(Risk.escalateThreshold(Risk.Threshold(1, "claim", true), 1), 1, "claim", true)
        thr(Risk.escalateThreshold(Risk.Threshold(1, "claim", true), 2), 2, "standard", false)
        thr(Risk.escalateThreshold(Risk.Threshold(1, "claim", true), 3), 3, "strong", false)
        thr(Risk.escalateThreshold(Risk.Threshold(2, "standard", false), 1), 2, "standard", false)
        thr(Risk.escalateThreshold(Risk.Threshold(2, "standard", false), 2), 2, "standard", false)
        thr(Risk.escalateThreshold(Risk.Threshold(2, "standard", false), 3), 3, "strong", false)
        thr(Risk.escalateThreshold(Risk.Threshold(3, "strong", false), 2), 3, "strong", false)
        // the proof is raised to the floor of the new t, and kept when already at least that strong
        thr(Risk.escalateThreshold(Risk.Threshold(2, "claim", false), 2), 2, "standard", false)
        thr(Risk.escalateThreshold(Risk.Threshold(1, "strong", true), 2), 2, "strong", false)
        thr(Risk.escalateThreshold(Risk.Threshold(1, "strong", true), 1), 1, "strong", true)
        thr(Risk.escalateThreshold(Risk.Threshold(1, "standard", true), 1), 1, "standard", true)
    }

    // ---- the budget ----

    @Test fun costIsKappaTimesTheClampedRisk() {
        near(1.0, Risk.cost(0.5, 2.0))
        near(2.0, Risk.cost(1.0, 2.0))
        near(2.0, Risk.cost(2.0, 2.0))
        near(0.0, Risk.cost(-1.0, 2.0))
        near(0.0, Risk.cost(0.0, 2.0))
        // a non-finite risk is the cost of r = 1 (-Infinity included, it is not clamped to 0)
        for (r in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) near(2.0, Risk.cost(r, 2.0))
        // a non-positive or non-finite kappa costs nothing
        for (kappa in listOf(-1.0, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, 0.0)) near(0.0, Risk.cost(0.5, kappa))
        assertEquals(raw(0.0), raw(Risk.cost(0.5, -0.0)))
    }

    @Test fun nzKeepsOnlyPositiveFiniteNumbers() {
        fun nz(x: Double?): Double = KUtil.priv(Risk, "nz", x)
        assertEquals(2.5, nz(2.5), 0.0)
        assertEquals(Double.MIN_VALUE, nz(Double.MIN_VALUE), 0.0)
        for (bad in listOf(null, -1.0, 0.0, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) assertEquals("$bad", raw(0.0), raw(nz(bad)))
        assertEquals(raw(0.0), raw(nz(-0.0)))
    }

    private fun b(B: Double, tau: Double = 1000.0, asOf: Double? = null) = Risk.Budget(B, tau, asOf)

    @Test fun leakDrainsLambdaPerSecondSinceTheLastUpdate() {
        assertEquals(Risk.Budget(5.0, 1000.0, 6000.0), Risk.leak(b(10.0), 6000.0, 1.0))
        assertEquals(Risk.Budget(8.0, 1000.0, 6000.0), Risk.leak(b(10.0, asOf = 4000.0), 6000.0, 1.0))
        assertEquals(Risk.Budget(9.0, 1000.0, 6000.0), Risk.leak(b(10.0), 6000.0, 0.2))
        // the budget floors at zero, and a clock behind the last update leaks nothing and keeps the later time
        assertEquals(Risk.Budget(0.0, 1000.0, 6000.0), Risk.leak(b(10.0), 6000.0, 10.0))
        assertEquals(Risk.Budget(10.0, 1000.0, 1000.0), Risk.leak(b(10.0), 500.0, 1.0))
        assertEquals(Risk.Budget(10.0, 1000.0, 1000.0), Risk.leak(b(10.0), 1000.0, 1.0))
        // a lambda that is not positive and finite drains nothing
        for (l in listOf(0.0, -1.0, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) assertEquals("$l", Risk.Budget(10.0, 1000.0, 6000.0), Risk.leak(b(10.0), 6000.0, l))
        // the tau is carried over unchanged
        assertEquals(123.0, Risk.leak(b(10.0, tau = 123.0, asOf = 123.0), 6000.0, 1.0).tau, 0.0)
    }

    @Test fun leakWithANonFiniteClockOrStartLeaksNothing() {
        for (now in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            assertEquals("$now", Risk.Budget(10.0, 1000.0, 1000.0), Risk.leak(b(10.0), now, 1.0))
            assertEquals("$now", Risk.Budget(10.0, 1000.0, 4000.0), Risk.leak(b(10.0, asOf = 4000.0), now, 1.0))
        }
        val nanFrom = Risk.leak(b(10.0, tau = Double.NaN), 5000.0, 1.0)
        assertEquals(10.0, nanFrom.B, 0.0)
        assertTrue(nanFrom.asOf!!.isNaN())
        val nanFromNanNow = Risk.leak(b(10.0, tau = Double.NaN), Double.NaN, 1.0)
        assertEquals(10.0, nanFromNanNow.B, 0.0)
        assertTrue(nanFromNanNow.asOf!!.isNaN())
        val negInfFrom = Risk.leak(b(10.0, tau = Double.NEGATIVE_INFINITY), 5000.0, 1.0)
        assertEquals(10.0, negInfFrom.B, 0.0)
        assertEquals(5000.0, negInfFrom.asOf!!, 0.0)
        val posInfFrom = Risk.leak(b(10.0, asOf = Double.POSITIVE_INFINITY), 5000.0, 1.0)
        assertEquals(10.0, posInfFrom.B, 0.0)
        assertEquals(Double.POSITIVE_INFINITY, posInfFrom.asOf!!, 0.0)
        assertEquals(Double.NEGATIVE_INFINITY, negInfFrom.tau, 0.0)
        assertEquals(1000.0, Risk.leak(b(10.0), Double.NaN, 1.0).tau, 0.0)
    }

    @Test fun debitFloorsAtZeroAndIgnoresNonPositiveCosts() {
        assertEquals(Risk.Budget(7.0, 1000.0, 500.0), Risk.debit(b(10.0, asOf = 500.0), 3.0))
        assertEquals(Risk.Budget(0.0, 1000.0, null), Risk.debit(b(1.0), 3.0))
        assertEquals(Risk.Budget(0.0, 1000.0, null), Risk.debit(b(3.0), 3.0))
        for (c in listOf(-2.0, 0.0, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) assertEquals("$c", Risk.Budget(10.0, 1000.0, null), Risk.debit(b(10.0), c))
        assertEquals(raw(0.0), raw(Risk.debit(b(1.0), 5.0).B))
    }

    @Test fun ageIsTheClampedFractionOfTheHorizonAndTheWorstCaseWhenAnythingIsBad() {
        val bud = b(1.0, tau = 0.0)
        near(0.5, Risk.ageSinceTouch(bud, 1_800_000.0))
        near(0.0, Risk.ageSinceTouch(bud, 0.0))
        near(0.0, Risk.ageSinceTouch(bud, -5.0))
        near(1.0, Risk.ageSinceTouch(bud, 3_600_000.0))
        near(1.0, Risk.ageSinceTouch(bud, 9_000_000.0))
        near(0.5, Risk.ageSinceTouch(bud, 0.5, 1.0))
        near(0.25, Risk.ageSinceTouch(b(1.0, tau = 1000.0), 1500.0, 2000.0))
        // every non-finite input, and a horizon that is not positive, is the worst case
        for (bad in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            near(1.0, Risk.ageSinceTouch(bud, bad))
            near(1.0, Risk.ageSinceTouch(b(1.0, tau = bad), 1000.0))
            near(1.0, Risk.ageSinceTouch(bud, 1000.0, bad))
        }
        near(1.0, Risk.ageSinceTouch(bud, 1000.0, 0.0))
        near(1.0, Risk.ageSinceTouch(b(1.0, tau = 5.0), 5.0, 0.0))
        near(1.0, Risk.ageSinceTouch(bud, 1000.0, -1.0))
    }

    @Test fun admissionTable() {
        fun a(t: Int, covers: Boolean, admit: Boolean, step: Boolean, tt: Int, metered: Boolean) {
            val r = Risk.admitOf(t, covers)
            assertEquals("$t/$covers admit", admit, r.admit)
            assertEquals("$t/$covers step-up", step, r.needStepUp)
            assertEquals("$t/$covers t", tt, r.t)
            assertEquals("$t/$covers metered", metered, r.metered)
        }
        a(1, true, true, false, 1, true)
        a(1, false, false, true, 3, false)
        a(2, true, false, true, 2, true)
        a(2, false, false, true, 3, false)
        a(3, true, false, true, 3, false)
        a(3, false, false, true, 3, false)
        a(4, true, false, true, 3, false)
        a(0, true, false, true, 3, false)
    }

    @Test fun toFixed3RoundsATieUp() {
        assertEquals("0.000", Risk.toFixed3(0.0))
        assertEquals("1.000", Risk.toFixed3(1.0))
        assertEquals("0.500", Risk.toFixed3(0.5))
        assertEquals("0.063", Risk.toFixed3(0.0625))
        assertEquals("0.001", Risk.toFixed3(0.0005))
        assertEquals("0.000", Risk.toFixed3(0.0004))
        assertEquals("0.123", Risk.toFixed3(0.12345))
        assertEquals("0.200", Risk.toFixed3(0.2))
        assertEquals("0.999", Risk.toFixed3(0.9994))
        assertEquals("1.000", Risk.toFixed3(0.9996))
    }

    // ---- the plan geodesic ----

    private fun node(id: String, pre: Any? = null, post: Any? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("id" to id)
        if (pre != null) m["pre"] = pre
        if (post != null) m["post"] = post
        return m
    }

    @Test fun theGeodesicFailsClosedOnAnUnknownPlanOrNode() {
        val plan = listOf(node("a"), node("b"))
        for (notAPlan in listOf<Any?>(null, "x", 5L, mapOf("a" to 1L))) assertEquals("$notAPlan", 1.0, Risk.planGeodesic(notAPlan, "a", "b"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(plan, "zz", "b"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(plan, "a", "zz"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(plan, "zz", "yy"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(plan, null, "b"), 0.0)
        assertEquals(0.0, Risk.planGeodesic(plan, "a", "a"), 0.0)
        assertEquals(0.0, Risk.planGeodesic(plan, "b", "b"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(plan, "a", "b"), 0.0)
    }

    @Test fun withNoEdgesTheDistanceIsTheIndexDistance() {
        val plan = listOf(node("a"), node("b"), node("c"), node("d"), node("e"))
        near(0.75, Risk.planGeodesic(plan, "a", "d"))
        near(0.75, Risk.planGeodesic(plan, "d", "a"))
        near(0.5, Risk.planGeodesic(plan, "b", "d"))
        near(0.5, Risk.planGeodesic(plan, "d", "b"))
        near(0.25, Risk.planGeodesic(plan, "c", "d"))
        near(1.0, Risk.planGeodesic(plan, "a", "e"))
        // a node that is not an object is skipped, never fails
        val mixed = listOf<Any?>("x", node("a"), 5L, node("b"))
        near(2.0 / 3.0, Risk.planGeodesic(mixed, "a", "b"))
    }

    private fun linked(pre: Any? = null, post: Any? = null): Double {
        // a at 0, x at 1, b at 2: a declared link between a and b is 1 hop = 0.5; no recognised link falls back to the index distance 1
        val plan = listOf(node("a", post = post), node("x"), node("b", pre = pre))
        val ab = Risk.planGeodesic(plan, "a", "b")
        val ba = Risk.planGeodesic(plan, "b", "a")
        assertEquals("symmetric", ab, ba, 0.0)
        return ab
    }

    @Test fun everyPredecessorFormLinksTheNodes() {
        for (pre in listOf<Any?>(
            "a", listOf("a"), mapOf("after" to "a"), mapOf("after" to listOf("a")), mapOf("depends_on" to "a"), mapOf("depends_on" to listOf("a")),
            mapOf("requires" to "a"), mapOf("requires" to listOf("a")), mapOf("nodes" to "a"), mapOf("nodes" to listOf("a")),
            listOf(5L, "a", null), listOf("zzz", "a"), mapOf("after" to listOf(5L, "a")),
        )) assertEquals("pre $pre", 0.5, linked(pre = pre), 0.0)
    }

    @Test fun everySuccessorFormLinksTheNodes() {
        for (post in listOf<Any?>(
            "b", listOf("b"), mapOf("before" to "b"), mapOf("before" to listOf("b")), mapOf("enables" to "b"), mapOf("enables" to listOf("b")),
            mapOf("then" to "b"), mapOf("then" to listOf("b")), mapOf("next" to "b"), mapOf("next" to listOf("b")),
            listOf(5L, "b", null), listOf("zzz", "b"), mapOf("next" to listOf(5L, "b")),
        )) assertEquals("post $post", 0.5, linked(post = post), 0.0)
    }

    @Test fun referencesThatAreNotRecognisedLinkNothing() {
        // successor keys under pre, predecessor keys under post, unknown keys, non-strings, unknown ids, other structures
        for (pre in listOf<Any?>(mapOf("before" to "a"), mapOf("enables" to "a"), mapOf("then" to "a"), mapOf("next" to "a"), mapOf("other" to "a"), 5L, true, "zzz", listOf("zzz"), emptyList<Any?>(), mapOf("after" to 5L), mapOf("after" to mapOf("x" to "a"))))
            assertEquals("pre $pre", 1.0, linked(pre = pre), 0.0)
        for (post in listOf<Any?>(mapOf("after" to "b"), mapOf("depends_on" to "b"), mapOf("requires" to "b"), mapOf("nodes" to "b"), mapOf("other" to "b"), 5L, "zzz", listOf("zzz"), emptyList<Any?>(), mapOf("next" to 5L)))
            assertEquals("post $post", 1.0, linked(post = post), 0.0)
        // a list is not searched for keys: a map inside a list is not a reference
        assertEquals(1.0, linked(pre = listOf(mapOf("after" to "a"))), 0.0)
    }

    @Test fun aDeclaredLinkIsCountedOnceWhicheverSideDeclaresIt() {
        val plan = listOf(node("a", post = "b"), node("x"), node("b", pre = "a"))
        near(0.5, Risk.planGeodesic(plan, "a", "b"))
        near(0.5, Risk.planGeodesic(plan, "b", "a"))
    }

    @Test fun aSelfReferenceIsNoEdge() {
        val plan = listOf(node("a"), node("b"), node("c", pre = "c", post = "c"), node("d"))
        near(1.0 / 3.0, Risk.planGeodesic(plan, "a", "b"))
        near(1.0, Risk.planGeodesic(plan, "a", "d"))
    }

    @Test fun theDistanceIsTheHopCountOverTheUndirectedGraph() {
        // a - b - c - d chain through pre references, e isolated; plan order a, c, e, b, d (n = 5)
        val plan = listOf(node("a"), node("c", pre = "b"), node("e"), node("b", pre = "a"), node("d", pre = "c"))
        near(0.75, Risk.planGeodesic(plan, "a", "d"))
        near(0.75, Risk.planGeodesic(plan, "d", "a"))
        near(0.5, Risk.planGeodesic(plan, "a", "c"))
        near(0.5, Risk.planGeodesic(plan, "c", "a"))
        near(0.25, Risk.planGeodesic(plan, "a", "b"))
        near(0.25, Risk.planGeodesic(plan, "b", "a"))
        near(0.25, Risk.planGeodesic(plan, "c", "d"))
        near(0.5, Risk.planGeodesic(plan, "b", "d"))
        near(0.5, Risk.planGeodesic(plan, "d", "b"))
        // unreachable (an isolated node while other edges exist) is 1, not the index distance
        assertEquals(1.0, Risk.planGeodesic(plan, "a", "e"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(plan, "e", "a"), 0.0)
        assertEquals(1.0, Risk.planGeodesic(plan, "e", "d"), 0.0)
        // successor references build the same graph
        val fwd = listOf(node("a", post = "b"), node("b", post = listOf("c")), node("c", post = mapOf("next" to "d")), node("d"))
        near(1.0, Risk.planGeodesic(fwd, "a", "d"))
        near(2.0 / 3.0, Risk.planGeodesic(fwd, "a", "c"))
        near(2.0 / 3.0, Risk.planGeodesic(fwd, "d", "b"))
        // a non-object node in the plan is skipped while edges are read
        val mixed = listOf<Any?>("junk", node("a"), node("b", pre = "a"), 7L)
        near(1.0 / 3.0, Risk.planGeodesic(mixed, "a", "b"))
    }
}
