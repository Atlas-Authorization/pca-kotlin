package net.atlasauth.pca.wallet

import java.util.IdentityHashMap
import net.atlasauth.pca.intent.IntentLearner
import net.atlasauth.pca.intent.IntentOmega
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.VerbSpace

/** The wallet's default views over the intent learner: the grant view the question channel consults, and the population-prior mass. */
@Suppress("UNCHECKED_CAST")
object WalletLearner {
    /**
     * A [WalletView] over an intent learner, with an optional ceiling predicate ([insideCeiling]: true = inside every ceiling;
     * null = no ceiling). `p` and `vetoed` read the learner at the cell's representative outcome; an unknown verb throws, as in
     * the reference.
     */
    fun learnerView(l: IntentLearner, insideCeiling: ((String, IntArray) -> Boolean)? = null): WalletView = object : WalletView {
        private fun vsOf(verb: String): VerbSpace {
            for (v in l.omega.verbs) if (v.verb == verb) return v
            throw IllegalArgumentException("learnerView: unknown verb $verb")
        }

        override fun p(verb: String, idx: IntArray): Double = l.acceptance(IntentOmega.cellRep(vsOf(verb), idx))

        override fun vetoed(verb: String, idx: IntArray): Boolean = l.isVetoed(IntentOmega.cellRep(vsOf(verb), idx))

        override fun outsideCeiling(verb: String, idx: IntArray): Boolean = insideCeiling != null && !insideCeiling(verb, idx)

        override fun confirmed(): List<Map<String, Any?>> {
            val out = ArrayList<Map<String, Any?>>()
            for (c in l.cells()) {
                if (!c.inGrant) continue
                val m = LinkedHashMap<String, Any?>()
                m["verb"] = c.verb
                m["idx"] = WalletNoise.idxList(c.cell)
                out.add(m)
            }
            return out
        }
    }

    /**
     * mu-mass (ppm) of cells admitted only because of the population prior: in the grant with the prior, not in it without, after
     * the same observations. Zero at tau = 1 under noise-free answers; the map reports it as `metrics.prior_admitted_ppm`.
     */
    fun priorAdmittedPpm(omega: Omega, base: IntentLearner.LearnerOptions?, observations: Collection<IntentLearner.Observation>, mix: WalletPopulation.PriorMix): Long {
        val without = copyOf(base)
        without.priorMix = null
        val with = copyOf(base)
        val asMap = IdentityHashMap<VerbSpace, Map<String, Any?>>()
        with.priorMix = IntentLearner.PriorMix(mix.beta, IntentLearner.PriorWeight { vs, contains ->
            mix.weight(asMap.getOrPut(vs) { verbMap(vs) }, contains)
        })
        val a = IntentLearner.replay(omega, without, observations).cells()
        val b = IntentLearner.replay(omega, with, observations).cells()
        var mass = 0.0
        for (i in b.indices) if (b[i].inGrant && !a[i].inGrant) mass += b[i].mass
        return Math.round(mass * 1_000_000)
    }

    private fun verbMap(vs: VerbSpace): Map<String, Any?> =
        (IntentOmega.omegaToJson(Omega(listOf(vs), listOf()))["verbs"] as List<Any?>)[0] as Map<String, Any?>

    private fun copyOf(o: IntentLearner.LearnerOptions?): IntentLearner.LearnerOptions {
        val c = IntentLearner.LearnerOptions()
        if (o == null) return c
        c.eta = o.eta; c.etaPos = o.etaPos; c.etaNeg = o.etaNeg; c.tau = o.tau; c.priorMix = o.priorMix; c.nullMass = o.nullMass; c.nullMassFn = o.nullMassFn
        c.anchor = o.anchor; c.anchors = o.anchors; c.harm = o.harm; c.maxHypotheses = o.maxHypotheses; c.maxEnumeration = o.maxEnumeration
        c.strategy = o.strategy; c.hypothesisClass = o.hypothesisClass; c.agnosticSlack = o.agnosticSlack; c.monotone = o.monotone
        return c
    }
}
