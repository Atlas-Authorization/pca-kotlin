package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Outcome

/** Checking an executed action's effect against its postconditions and feeding a violation back, and the Monte Carlo form of the residual-risk estimate. */
object IntentOutcome {
    /**
     * Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes the action's cell; ok and
     * pending change nothing. [pcs] null = the default postconditions. Returns {report, divergence?}.
     */
    @JvmStatic
    fun verifyOutcome(l: IntentLearner, o: Outcome, effect: Map<String, Any?>?, pcs: List<*>?): Map<String, Any?> {
        val vs = l.omega.verbs.firstOrNull { it.verb == o.verb } ?: throw IllegalArgumentException("verifyOutcome: no verb ${o.verb} in Omega")
        val report = if (pcs == null) IntentEffects.checkPostconditions(vs, o, effect) else IntentEffects.checkPostconditions(vs, o, effect, pcs)
        val r = LinkedHashMap<String, Any?>()
        r["report"] = report
        if ("violated" == report["status"]) r["divergence"] = IntentMapKit.applyDivergence(l, o, 0)
        return r
    }

    /** The Monte Carlo residual-risk estimate of the learner's grant over [samples] draws (default 20000) with the seeded generator (default 7). */
    @JvmStatic
    fun estimateResidualRiskMC(l: IntentLearner, samples: Int?, seed: Double?): Double {
        val m = samples ?: 20000
        val rand = IntentOmega.rng(seed ?: 7.0)
        val syn = l.synthesize()
        val grant = LinkedHashMap<String, Any?>()
        grant["predicates"] = syn.predicates
        grant["caveats"] = syn.caveats
        val g = IntentPolicy.admitter(grant)
        var r = 0.0
        for (i in 0 until m) {
            val s = IntentOmega.sampleOutcome(l.omega, rand)
            if (g.admits(s.vs, s.o)) r += (1 - l.acceptance(s.o)) * IntentOmega.harmOf(s.vs, s.o, l.harm)
        }
        return r / m
    }
}
